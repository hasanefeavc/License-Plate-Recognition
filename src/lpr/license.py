"""Offline, time-limited licensing.

The deployment model this exists for: the software is installed on a customer
site that has no outbound internet access, runs for a paid period and must
stop working by itself when that period ends. There is no activation server
to call, so the licence has to carry its own proof -- a signed JWT whose
``exp`` claim *is* the expiry date. Anyone can read it; only the holder of
the vendor's **private** key can mint one.

Asymmetric on purpose. This module previously verified HS256 tokens with a
shared secret, which meant every customer install carried the key needed to
*forge* a licence -- one leaked config file and the whole scheme was over.
Under RS256 a site holds ``public_key.pem`` and nothing else: it can check a
signature and can never produce one. There is deliberately no secret, no
environment variable and no ``.env`` fallback left in this module; if the
public key is missing, verification fails closed rather than reaching for
something weaker.

Three defences, in the order an attacker meets them:

1. **Signature.** RS256 over the vendor's private key, verified here with
   ``public_key.pem``. Editing ``exp`` in the token invalidates it, and
   re-signing needs a key that never leaves the vendor's machine. The
   algorithm list passed to PyJWT is pinned to RS256, so a token that asks to
   be verified as HS256 (the classic algorithm-confusion attack, where the
   public key is submitted as an HMAC secret) is rejected before any
   signature check happens. See :func:`validate_token`.
2. **Anti-rollback.** The obvious attack on an offline expiry date is to set
   the machine clock back. Every check records the current wall clock in
   ``system_meta.last_run_time`` and refuses to run when it sees time move
   *backwards* by more than :data:`ROLLBACK_TOLERANCE_S`. A rolled-back clock
   therefore buys nothing: the licence stays invalid until the clock catches
   up with the furthest point the system has already seen.
3. **Storage.** The active token lives in the database
   (``system_meta.license_token``) *and* in a ``.license`` file, so restoring
   an old database copy or deleting the file alone does not clear the
   recorded ``last_run_time``.

Nothing here raises on an invalid licence. Every entry point gets a
:class:`LicenseStatus` describing *why* it is invalid, because the contract
with the rest of the system is "halt the ML pipeline and wait for a new key",
never "crash the service".

Typical use::

    from lpr.license import LicenseGuard

    guard = LicenseGuard()
    status = guard.refresh()
    if not status.valid:
        ...          # pause the pipeline, show status.detail to the operator
    guard.activate(token_from_the_operator)   # raises LicenseError if bad
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import jwt

logger = logging.getLogger(__name__)

__all__ = [
    "ALGORITHM",
    "ISSUER",
    "LAST_RUN_KEY",
    "LICENSE_FILE_NAME",
    "LICENSE_TOKEN_KEY",
    "PUBLIC_KEY_ENV_VAR",
    "PUBLIC_KEY_NAME",
    "LicenseError",
    "LicenseGuard",
    "LicenseStatus",
    "activate_license",
    "check_license",
    "license_file_candidates",
    "load_public_key",
    "public_key_candidates",
    "read_license_token",
    "validate_token",
]

#: Signature algorithm. Asymmetric: sites verify, only the vendor signs.
#: Pinned as the *only* accepted algorithm on every ``jwt.decode`` call.
ALGORITHM: Final[str] = "RS256"

#: ``iss`` claim every licence carries. Checked on validation. Licences and
#: API session tokens are now signed with different keys *and* different
#: algorithms, so this is belt and braces rather than the load-bearing check
#: it was under the shared-secret scheme.
ISSUER: Final[str] = "lpr-license"

#: ``system_meta`` keys.
LICENSE_TOKEN_KEY: Final[str] = "license_token"
LICENSE_ACTIVATED_KEY: Final[str] = "license_activated_at"
LAST_RUN_KEY: Final[str] = "last_run_time"

#: Filename used for the on-disk copy of the active token.
LICENSE_FILE_NAME: Final[str] = ".license"

#: How far the clock may legitimately jump backwards (NTP correction, a
#: daylight-saving misconfiguration being fixed) before it is read as
#: tampering. Five minutes is far more than a real correction needs and far
#: less than any useful amount of stolen runtime.
ROLLBACK_TOLERANCE_S: Final[float] = 300.0

#: Filename of the verifying key installed on each site.
PUBLIC_KEY_NAME: Final[str] = "public_key.pem"

#: Absolute path to ``public_key.pem``, when it lives somewhere unusual.
#: This is a *path*, never key material: nothing secret is ever read from the
#: environment by this module.
PUBLIC_KEY_ENV_VAR: Final[str] = "LPR_LICENSE_PUBLIC_KEY"

#: Reason codes. Stable strings: the GUI switches on them, humans read
#: ``LicenseStatus.detail`` instead.
REASON_OK: Final[str] = "ok"
REASON_MISSING: Final[str] = "missing"
REASON_EXPIRED: Final[str] = "expired"
REASON_INVALID: Final[str] = "invalid"
REASON_NOT_YET_VALID: Final[str] = "not_yet_valid"
REASON_CLOCK_ROLLBACK: Final[str] = "clock_rollback"
#: Wire value kept as ``no_secret`` across the RS256 migration: the desktop
#: client and the ``/api/license`` contract switch on these strings, and the
#: operator-facing meaning ("this install cannot verify licences") did not
#: change with the key type.
REASON_NO_KEY: Final[str] = "no_secret"
#: The signature is good and the licence is in date, but it was issued for a
#: different machine. Distinct from ``invalid`` on purpose: this is the one
#: refusal with a remedy the customer can act on, and telling them "geçersiz"
#: sends them looking for a typo in a key that is perfectly well-formed.
REASON_MACHINE_MISMATCH: Final[str] = "machine_mismatch"

_DETAILS: Final[dict[str, str]] = {
    REASON_OK: "Lisans geçerli.",
    REASON_MISSING: "Lisans anahtarı bulunamadı. Lütfen bir lisans anahtarı girin.",
    REASON_EXPIRED: "Lisans süresi doldu. Lütfen yeni bir lisans anahtarı girin.",
    REASON_INVALID: "Lisans anahtarı geçersiz.",
    REASON_NOT_YET_VALID: "Lisans anahtarı henüz geçerli değil (başlangıç tarihi ileride).",
    REASON_CLOCK_ROLLBACK: ("Sistem saati geriye alınmış. Lisans doğrulanamıyor; saati düzeltin."),
    REASON_NO_KEY: ("Lisans doğrulama anahtarı (public_key.pem) bulunamadı veya okunamadı."),
    REASON_MACHINE_MISMATCH: (
        "Bu lisans anahtarı başka bir makine için verilmiş. Donanım değiştiyse "
        "yeni makine kimliğinizle (hwid) yeniden bağlama talep edin."
    ),
}


class LicenseError(Exception):
    """Raised only by :func:`activate_license` when a submitted key is bad.

    Checks never raise -- they return a :class:`LicenseStatus`. Submitting a
    key is different: the operator is standing there waiting to be told what
    is wrong with what they just typed.
    """

    def __init__(self, message: str, reason: str = REASON_INVALID) -> None:
        super().__init__(message)
        self.reason = reason


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LicenseStatus:
    """The outcome of one licence check. Never an exception, always this."""

    valid: bool
    reason: str
    detail: str
    client: str | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    seconds_remaining: float | None = None
    #: This machine's id, so an operator can quote it in a rebind request
    #: without running a separate tool. Present on every status, not only on a
    #: mismatch: the moment somebody needs it is the moment the gate is down.
    hwid: str | None = None
    #: Components the licence names that do not match this machine. Empty for
    #: an unbound licence and for one that matches.
    machine_mismatch: tuple[str, ...] = ()

    @property
    def days_remaining(self) -> float | None:
        if self.seconds_remaining is None:
            return None
        return round(self.seconds_remaining / 86400.0, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "detail": self.detail,
            "client": self.client,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "seconds_remaining": self.seconds_remaining,
            "days_remaining": self.days_remaining,
            "hwid": self.hwid,
            "machine_mismatch": list(self.machine_mismatch),
        }

    @classmethod
    def failure(cls, reason: str, detail: str | None = None, **fields: Any) -> LicenseStatus:
        return cls(
            valid=False,
            reason=reason,
            detail=detail or _DETAILS.get(reason, _DETAILS[REASON_INVALID]),
            **fields,
        )


# ---------------------------------------------------------------------------
# Public key
# ---------------------------------------------------------------------------


def _project_root() -> Path:
    """Repo root (``<root>/src/lpr/license.py``), or the image's ``/app``."""
    return Path(__file__).resolve().parents[2]


def public_key_candidates() -> list[Path]:
    """Where ``public_key.pem`` may live, most specific first.

    An explicit path wins; then the writable data directory (the container's
    volume, which is what an installer copies into); then ``keys/`` and the
    install root, which is where a bare checkout finds the file that
    ``scripts/generate_keys.py`` wrote.
    """
    paths: list[Path] = []

    explicit = os.environ.get(PUBLIC_KEY_ENV_VAR, "").strip()
    if explicit:
        paths.append(Path(explicit).expanduser())

    try:
        from lpr.config import get_settings

        paths.append(get_settings().paths.data_dir / PUBLIC_KEY_NAME)
    except Exception:  # pragma: no cover - settings unavailable (CLI use)
        logger.debug("Ayarlar okunamadı, açık anahtar veri dizininde aranmayacak")

    root = _project_root()
    paths.append(root / "keys" / PUBLIC_KEY_NAME)
    paths.append(root / PUBLIC_KEY_NAME)
    paths.append(Path.cwd() / "keys" / PUBLIC_KEY_NAME)
    paths.append(Path.cwd() / PUBLIC_KEY_NAME)

    unique: list[Path] = []
    for path in paths:
        if path not in unique:
            unique.append(path)
    return unique


#: (path, mtime, size) -> PEM bytes. Verification runs on a timer, so the key
#: is not re-read from disk every minute; the stat tuple means replacing the
#: file (a re-keyed site) is still picked up without a restart.
_key_cache: dict[tuple[str, float, int], bytes] = {}
_key_cache_lock = threading.Lock()


def load_public_key(source: str | bytes | Path | None = None) -> bytes | None:
    """The PEM verifying key, or ``None`` when it cannot be found or read.

    ``source`` may be PEM material itself (handed in by a test or a caller
    that already has it), a path to a key file, or ``None`` to search
    :func:`public_key_candidates`. Never returns a private key: a PEM that
    contains one is refused, because verifying with a private key would mean
    the signing key had been shipped to a site, which is exactly the mistake
    this migration exists to make impossible.
    """
    if isinstance(source, bytes):
        return _validated_pem(source, "<memory>")
    if isinstance(source, str) and "BEGIN" in source:
        return _validated_pem(source.encode("utf-8"), "<memory>")

    candidates = [Path(source).expanduser()] if source is not None else public_key_candidates()

    for path in candidates:
        try:
            stat_result = path.stat()
        except OSError:
            continue

        cache_key = (str(path), stat_result.st_mtime, stat_result.st_size)
        with _key_cache_lock:
            cached = _key_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            pem = path.read_bytes()
        except OSError as exc:
            logger.warning("Açık anahtar okunamadı (%s): %s", path, exc)
            continue

        validated = _validated_pem(pem, str(path))
        if validated is None:
            continue

        with _key_cache_lock:
            _key_cache.clear()  # only ever one active key; keep this bounded
            _key_cache[cache_key] = validated
        logger.debug("Lisans açık anahtarı yüklendi: %s", path)
        return validated

    logger.error(
        "Lisans doğrulama anahtarı bulunamadı. Aranan konumlar: %s",
        ", ".join(str(path) for path in candidates),
    )
    return None


def _validated_pem(pem: bytes, origin: str) -> bytes | None:
    """Reject anything that is not a PEM *public* key."""
    if b"PRIVATE KEY" in pem:
        logger.error(
            "%s bir ÖZEL anahtar içeriyor. Sitelere yalnızca public_key.pem "
            "dağıtılmalıdır; bu dosya doğrulama için kullanılmayacak.",
            origin,
        )
        return None
    if b"BEGIN PUBLIC KEY" not in pem and b"BEGIN RSA PUBLIC KEY" not in pem:
        logger.error("%s geçerli bir PEM açık anahtarı değil.", origin)
        return None
    return pem


# ---------------------------------------------------------------------------
# Token validation (pure: no database, no filesystem)
# ---------------------------------------------------------------------------


def _iso(timestamp: Any) -> str | None:
    try:
        return datetime.fromtimestamp(float(timestamp), tz=UTC).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _unverified_claims(token: str) -> dict[str, Any]:
    """Claims without signature or expiry checks. Display purposes only.

    Used so an expired licence can still show *when* it expired and for whom,
    which is the first thing the operator on the phone is asked.
    """
    try:
        claims = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False, "verify_iss": False},
            algorithms=[ALGORITHM],
        )
    except Exception:  # pragma: no cover - unparseable token
        return {}
    return claims if isinstance(claims, dict) else {}


def validate_token(
    token: str,
    *,
    public_key: str | bytes | Path | None = None,
    now: float | None = None,
) -> LicenseStatus:
    """Verify signature, issuer and expiry of one licence token.

    Knows nothing about the database or the clock history -- that is
    :func:`check_license`'s job. Kept pure so the generator can verify what it
    just signed and the tests can drive it with an arbitrary ``now``.

    ``public_key`` overrides the search in :func:`public_key_candidates`; it
    accepts PEM material or a path. Without a readable public key nothing
    validates -- there is no fallback to a shared secret any more, by design.
    """
    raw = (token or "").strip()
    if not raw:
        return LicenseStatus.failure(REASON_MISSING)

    key = load_public_key(public_key)
    if not key:
        return LicenseStatus.failure(REASON_NO_KEY)

    claims = _unverified_claims(raw)
    client = claims.get("client") or claims.get("sub")
    display = {
        "client": str(client) if client else None,
        "issued_at": _iso(claims.get("iat")),
        "expires_at": _iso(claims.get("exp")),
    }

    try:
        verified: dict[str, Any] = jwt.decode(
            raw,
            key,
            # One algorithm, never a list that includes an HMAC variant: this
            # is what stops a forged token from asking to be verified with the
            # public key treated as an HMAC secret.
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["exp", "iat", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        return LicenseStatus.failure(REASON_EXPIRED, seconds_remaining=0.0, **display)
    except jwt.ImmatureSignatureError:
        return LicenseStatus.failure(REASON_NOT_YET_VALID, **display)
    except jwt.InvalidTokenError as exc:
        # Bad signature, wrong issuer, malformed, missing claims. The reason
        # is logged but never shown: telling a forger *which* check failed is
        # free help.
        logger.warning("Lisans anahtarı reddedildi: %s", exc)
        return LicenseStatus.failure(REASON_INVALID)

    expires = verified.get("exp")
    reference = time.time() if now is None else float(now)
    remaining: float | None = None
    if expires is not None:
        remaining = max(0.0, float(expires) - reference)
        if remaining <= 0.0:
            # ``now`` was supplied and is past exp; PyJWT compared against the
            # real clock, so re-check against the caller's reference.
            return LicenseStatus.failure(REASON_EXPIRED, seconds_remaining=0.0, **display)

    subject = verified.get("client") or verified.get("sub")
    display = {
        "client": str(subject) if subject else None,
        "issued_at": _iso(verified.get("iat")),
        "expires_at": _iso(expires),
    }

    # The binding is checked last, and only on a token that is otherwise good.
    # A forged or expired key must not be told which machine it would have had
    # to come from, and an operator must not be sent chasing a hardware
    # problem when the real fault is an expired licence.
    fingerprint = _machine_fingerprint()
    claimed = {name: str(verified[name]) for name in _BINDING_CLAIMS if verified.get(name)}
    matched, agreeing, mismatched = _machine_matches(claimed, fingerprint)
    if not matched:
        logger.warning(
            "Lisans bu makine için değil: %d bileşen eşleşti, uyuşmayan: %s",
            agreeing,
            ", ".join(mismatched) or "-",
        )
        return LicenseStatus.failure(
            REASON_MACHINE_MISMATCH,
            seconds_remaining=remaining,
            hwid=fingerprint.hwid if fingerprint else None,
            machine_mismatch=tuple(mismatched),
            **display,
        )

    return LicenseStatus(
        valid=True,
        reason=REASON_OK,
        detail=_DETAILS[REASON_OK],
        seconds_remaining=remaining,
        hwid=fingerprint.hwid if fingerprint else None,
        **display,
    )


#: Claim names carrying the hardware binding. Mirrors
#: :data:`lpr.machine.COMPONENTS`; imported lazily so this module keeps
#: importing on a host where the fingerprint readers cannot run at all.
_BINDING_CLAIMS: Final[tuple[str, ...]] = ("machine_id", "mac", "board")


def _machine_fingerprint() -> Any:
    """This machine's fingerprint, or ``None`` when it cannot be read.

    Never raises. Fingerprinting is a *refusal* mechanism, and one that could
    take the service down by failing to read a sysfs file would be a worse
    liability than the copying it prevents.
    """
    try:
        from lpr.machine import current_fingerprint

        return current_fingerprint()
    except Exception:  # pragma: no cover - defensive
        logger.debug("Makine parmak izi okunamadı", exc_info=True)
        return None


def _machine_matches(claimed: dict[str, str], fingerprint: Any) -> tuple[bool, int, list[str]]:
    """Whether a licence's binding names this machine.

    An unbound licence (no binding claims) matches everything -- the vendor
    chose to issue it that way, and that decision belongs at issue time.

    A bound licence on a host whose fingerprint cannot be read at all is
    **accepted**, deliberately. The alternative is that an unreadable sysfs
    after a kernel upgrade closes a customer's gate, and a fingerprint that
    cannot be read is not evidence of a copy.
    """
    if not claimed:
        return True, 0, []
    if fingerprint is None:
        logger.warning("Lisans makineye bağlı ama parmak izi okunamadı; bağ denetimi atlanıyor.")
        return True, 0, []
    try:
        from lpr.machine import fingerprint_matches

        return fingerprint_matches(claimed, fingerprint)
    except Exception:  # pragma: no cover - defensive
        logger.debug("Makine bağı denetlenemedi", exc_info=True)
        return True, 0, []


# ---------------------------------------------------------------------------
# Storage: system_meta + .license file
# ---------------------------------------------------------------------------


def _meta() -> Any:
    """The ``system_meta`` repository, imported lazily.

    Lazy so that importing this module (which the licence *generator* does)
    never drags in sqlite, argon2 or the settings machinery.
    """
    from lpr.db import SystemMetaRepository

    return SystemMetaRepository()


def license_file_candidates() -> list[Path]:
    """Where a ``.license`` file may live, most specific first.

    The data directory is the container's writable volume, so that is the
    canonical location; the repo/install root is supported because dropping a
    file next to the executable is what a site engineer does without being
    told.
    """
    paths: list[Path] = []
    try:
        from lpr.config import get_settings

        paths.append(get_settings().paths.data_dir / LICENSE_FILE_NAME)
    except Exception:  # pragma: no cover - settings unavailable
        logger.debug("Ayarlar okunamadı, lisans dosyası veri dizininde aranmayacak")
    paths.append(_project_root() / LICENSE_FILE_NAME)
    paths.append(Path.cwd() / LICENSE_FILE_NAME)

    unique: list[Path] = []
    for path in paths:
        if path not in unique:
            unique.append(path)
    return unique


def _read_license_file() -> str | None:
    for path in license_file_candidates():
        try:
            if not path.is_file():
                continue
            content = path.read_text(encoding="utf-8").strip()
        except OSError as exc:  # pragma: no cover - permissions
            logger.warning("Lisans dosyası okunamadı (%s): %s", path, exc)
            continue
        if content:
            # Tolerate a file that has a comment header or a trailing newline:
            # the token is the first non-comment line.
            for line in content.splitlines():
                candidate = line.strip()
                if candidate and not candidate.startswith("#"):
                    return candidate
    return None


def _write_license_file(token: str) -> None:
    """Best-effort mirror of the active token onto disk."""
    for path in license_file_candidates()[:1]:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(token.strip() + "\n", encoding="utf-8")
        except OSError as exc:  # pragma: no cover - read-only volume
            logger.warning("Lisans dosyası yazılamadı (%s): %s", path, exc)


def read_license_token() -> str | None:
    """The active token: database first, ``.license`` file as a fallback.

    The file is the recovery path -- it is how a licence survives a wiped
    database, and how an engineer installs one without the GUI. When only the
    file has a token it is copied into the database on the way out, so the
    next check is a single indexed read.
    """
    stored: str | None = None
    try:
        stored = _meta().get(LICENSE_TOKEN_KEY)
    except Exception:  # pragma: no cover - database unavailable
        logger.debug("Lisans anahtarı veritabanından okunamadı", exc_info=True)

    if stored and stored.strip():
        return stored.strip()

    from_file = _read_license_file()
    if from_file:
        try:
            _meta().set(LICENSE_TOKEN_KEY, from_file)
        except Exception:  # pragma: no cover - database unavailable
            logger.debug("Dosyadaki lisans veritabanına yazılamadı", exc_info=True)
    return from_file


# ---------------------------------------------------------------------------
# Anti-rollback clock
# ---------------------------------------------------------------------------


def _last_run_time() -> float:
    try:
        raw = _meta().get(LAST_RUN_KEY)
    except Exception:  # pragma: no cover - database unavailable
        return 0.0
    try:
        return float(raw) if raw else 0.0
    except (TypeError, ValueError):
        return 0.0


def _record_run_time(now: float) -> None:
    """Advance the high-water mark. Never moves backwards, by construction."""
    try:
        if now > _last_run_time():
            _meta().set(LAST_RUN_KEY, f"{now:.3f}")
    except Exception:  # pragma: no cover - database unavailable
        logger.debug("Son çalışma zamanı kaydedilemedi", exc_info=True)


def clock_rolled_back(now: float | None = None) -> bool:
    """True when the wall clock is behind the furthest point already seen."""
    reference = time.time() if now is None else float(now)
    return reference < (_last_run_time() - ROLLBACK_TOLERANCE_S)


# ---------------------------------------------------------------------------
# The checks the rest of the system calls
# ---------------------------------------------------------------------------


def check_license(
    *,
    token: str | None = None,
    public_key: str | bytes | Path | None = None,
    now: float | None = None,
    record: bool = True,
) -> LicenseStatus:
    """Full check: stored token + signature + expiry + anti-rollback.

    ``record=False`` inspects without advancing the anti-rollback clock, which
    is what the "is this key any good?" path on key submission wants.
    """
    reference = time.time() if now is None else float(now)

    if clock_rolled_back(reference):
        logger.error(
            "Sistem saati geriye alınmış (şimdi=%s, son çalışma=%s)",
            _iso(reference),
            _iso(_last_run_time()),
        )
        return LicenseStatus.failure(REASON_CLOCK_ROLLBACK)

    raw = token if token is not None else read_license_token()
    if not raw:
        if record:
            _record_run_time(reference)
        return LicenseStatus.failure(REASON_MISSING)

    status = validate_token(raw, public_key=public_key, now=reference)
    if record:
        # Recorded even for an invalid licence: an expired site that is left
        # running must not be able to gain anything by being restarted with
        # the clock moved back.
        _record_run_time(reference)
    return status


def activate_license(token: str, *, public_key: str | bytes | Path | None = None) -> LicenseStatus:
    """Validate and persist a new licence key.

    Raises :class:`LicenseError` when the key is not usable, so nothing that
    fails validation ever reaches storage and the operator gets told why.
    """
    raw = (token or "").strip()
    if not raw:
        raise LicenseError(_DETAILS[REASON_MISSING], REASON_MISSING)

    if clock_rolled_back():
        raise LicenseError(_DETAILS[REASON_CLOCK_ROLLBACK], REASON_CLOCK_ROLLBACK)

    status = validate_token(raw, public_key=public_key)
    if not status.valid:
        raise LicenseError(status.detail, status.reason)

    meta = _meta()
    meta.set(LICENSE_TOKEN_KEY, raw)
    meta.set(LICENSE_ACTIVATED_KEY, datetime.now(UTC).isoformat())
    _write_license_file(raw)
    logger.info(
        "Yeni lisans etkinleştirildi (müşteri=%s, bitiş=%s)",
        status.client,
        status.expires_at,
    )
    return status


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


class LicenseGuard:
    """Caches the last licence check so hot paths need not re-verify.

    The API keeps one of these on ``app.state``: a background task calls
    :meth:`refresh` on an interval, and request handlers read :attr:`status`,
    which costs nothing. Thread-safe because the refresher, the request
    handlers and the pipeline threads all touch it.
    """

    def __init__(self, public_key: str | bytes | Path | None = None) -> None:
        #: Optional override; ``None`` means "search the usual locations on
        #: every check", which is what lets an installer drop a new
        #: public_key.pem in without restarting the service.
        self._public_key = public_key
        self._lock = threading.Lock()
        self._status = LicenseStatus.failure(REASON_MISSING)
        self._checked_at = 0.0

    @property
    def status(self) -> LicenseStatus:
        with self._lock:
            return self._status

    @property
    def valid(self) -> bool:
        return self.status.valid

    @property
    def checked_at(self) -> float:
        with self._lock:
            return self._checked_at

    def refresh(self, *, now: float | None = None) -> LicenseStatus:
        """Re-run the full check and cache the result."""
        status = check_license(public_key=self._public_key, now=now)
        with self._lock:
            previous = self._status
            self._status = status
            self._checked_at = time.time()
        if previous.valid != status.valid:
            level = logging.INFO if status.valid else logging.ERROR
            logger.log(level, "Lisans durumu değişti: %s", status.detail)
        return status

    def activate(self, token: str) -> LicenseStatus:
        """Persist a new key and adopt its status. Raises on a bad key."""
        status = activate_license(token, public_key=self._public_key)
        with self._lock:
            self._status = status
            self._checked_at = time.time()
        return status
