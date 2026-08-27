"""Per-operator licence keys.

Not to be confused with :mod:`lpr.license`, which is the *deployment* licence:
RS256 against a vendor public key, issued offline, and it gates whether the
pipeline runs at all. This module is a different thing at a different scope --
HS256 keys this server issues to its own operators, gating whether a given
account may drive the API.

They cannot be mistaken for one another. Different algorithm, different key
material, and a ``typ`` claim checked on the way in, so neither a deployment
licence nor an API session token validates here and a key issued here validates
nowhere else.

Generation and activation are separate events
--------------------------------------------
A key encodes a **duration**, not a deadline: ``duration_days`` plus the
username it was issued to. Nothing about the account changes when one is
generated -- an admin can cut a 365-day key on Monday and hand it over in
March, and the operator still gets a full year.

The countdown starts at :func:`activate`, which is the only place
``license_expires_at`` is ever computed. That is what makes the two halves
honest: generation produces a bearer artefact, activation binds it to a clock.

The consequence worth knowing is that an un-activated key does not go stale. It
is a credential for exactly one account and grants exactly the span written into
it, but it stays usable until somebody uses it -- treat a generated key like the
password it effectively is until the operator has activated it.

Who needs one
-------------
Only operators. An administrator is exempt by construction: the account that
*issues* keys cannot sensibly be locked out by one, and an installation whose
sole admin is holding an expired key has no recovery path short of editing the
database. :func:`requires_license` is the single place that decision lives.

Disabled by default
-------------------
With ``LPR_LICENSE_SECRET`` unset there is nothing to sign with, and
:func:`enforcement_enabled` reports ``False`` -- every operator passes. That is
deliberate rather than fail-closed: an upgrade that silently locked every
operator out of a working barrier, at a site that had never been told to set a
new secret, would be a worse outcome than the feature simply not being on yet.
Setting the secret turns enforcement on.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import jwt

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lpr.config import Settings

logger = logging.getLogger(__name__)

__all__ = [
    "ALGORITHM",
    "LICENSE_TYP",
    "STATUS_ACTIVE",
    "STATUS_EXPIRED",
    "STATUS_PENDING",
    "STATUS_REVOKED",
    "STATUS_UNLIMITED",
    "UserLicense",
    "KeyInfo",
    "activate",
    "enforcement_enabled",
    "inspect_key",
    "issue_key",
    "license_for",
    "requires_license",
]

ALGORITHM = "HS256"

#: ``typ`` claim. Present so a token from any other subsystem signed with the
#: same secret could never be replayed as a licence.
LICENSE_TYP = "lpr-user-license"

STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"
#: A fresh operator account, or one whose key has not been entered yet. Named
#: for what it is waiting on rather than for what it lacks: "missing" reads as
#: an error, and a new hire on their first morning is not an error.
STATUS_PENDING = "pending_activation"
STATUS_REVOKED = "revoked"
#: Administrators. Not a licence -- the absence of one.
STATUS_UNLIMITED = "unlimited"

#: Validity bounds for a generated key, in days.
MIN_DAYS = 1
MAX_DAYS = 3650


@dataclass(frozen=True, slots=True)
class KeyInfo:
    """What one licence key says, before it has been bound to a clock."""

    valid: bool = False
    username: str | None = None
    duration_days: int = 0
    detail: str = ""


@dataclass(frozen=True, slots=True)
class UserLicense:
    """The result of checking one account's licence."""

    status: str = STATUS_PENDING
    username: str | None = None
    expires_at: str | None = None
    days_remaining: float | None = None
    detail: str = ""
    #: When the operator entered their key. ``None`` until they do.
    activated_at: str | None = None
    duration_days: int | None = None

    @property
    def valid(self) -> bool:
        return self.status in (STATUS_ACTIVE, STATUS_UNLIMITED)

    @property
    def unlimited(self) -> bool:
        return self.status == STATUS_UNLIMITED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "username": self.username,
            "expires_at": self.expires_at,
            "days_remaining": (
                None if self.days_remaining is None else round(self.days_remaining, 2)
            ),
            "valid": self.valid,
            "unlimited": self.unlimited,
            "detail": self.detail,
            "activated_at": self.activated_at,
            "duration_days": self.duration_days,
        }


def _secret(settings: "Settings | None" = None) -> str:
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()
    return str(getattr(settings, "license_secret", "") or "").strip()


def enforcement_enabled(settings: "Settings | None" = None) -> bool:
    """True when a signing secret is configured, i.e. licences are in force."""
    return bool(_secret(settings))


def requires_license(role: str) -> bool:
    """Whether an account in ``role`` needs a licence at all.

    Administrators never do. They issue the keys, and an admin locked out by an
    expired key of their own could not issue a replacement -- the installation
    would need its database edited by hand to recover.
    """
    from lpr.api.security import ADMIN_ROLE

    return role != ADMIN_ROLE


def issue_key(
    username: str,
    days: int,
    settings: "Settings | None" = None,
    now: datetime | None = None,
) -> str:
    """Sign a licence key granting ``days`` of access to ``username``.

    Returns the key alone. Nothing else happens: no row is written, no
    countdown starts, the operator's status does not change. The key is an
    artefact the admin hands over, and it is worth exactly ``days`` from
    whenever it is activated.

    Deliberately carries no ``exp``. An expiry here would be a deadline for
    *collecting* the key rather than for using the access, and an admin who
    generated one on Friday for a Monday start would find it dead on arrival.

    Raises ``RuntimeError`` when no secret is configured -- a key nothing can
    verify would look like success and fail at activation.
    """
    secret = _secret(settings)
    if not secret:
        raise RuntimeError("LPR_LICENSE_SECRET tanımlı değil; lisans anahtarı üretilemez.")

    name = (username or "").strip()
    if not name:
        raise ValueError("Lisans anahtarı için kullanıcı adı gerekli")
    span = max(MIN_DAYS, min(MAX_DAYS, int(days)))

    issued = now or datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "typ": LICENSE_TYP,
            "sub": name,
            "duration_days": span,
            "iat": int(issued.timestamp()),
        },
        secret,
        algorithm=ALGORITHM,
    )
    if isinstance(token, bytes):  # pragma: no cover - PyJWT 1.x
        token = token.decode("utf-8")
    logger.info("Lisans anahtarı üretildi: %s (%d gün, henüz etkinleştirilmedi)", name, span)
    return token


def inspect_key(
    key: str,
    username: str | None = None,
    settings: "Settings | None" = None,
) -> KeyInfo:
    """Read one key without activating it. Never raises.

    ``username`` binds the key to an account. A key is issued *to* somebody,
    and without this check any operator could enter a colleague's key and help
    themselves to its duration.
    """
    secret = _secret(settings)
    if not secret:
        return KeyInfo(detail="Lisans doğrulaması yapılandırılmamış")

    raw = (key or "").strip()
    if not raw:
        return KeyInfo(detail="Lisans anahtarı girilmedi")

    try:
        claims: dict[str, Any] = jwt.decode(
            raw,
            secret,
            # One algorithm, never a list: accepting several is how a verifier
            # gets talked into checking a signature it should not.
            algorithms=[ALGORITHM],
            options={"require": ["sub"]},
        )
    except jwt.InvalidTokenError:
        return KeyInfo(detail="Lisans anahtarı geçersiz")

    if str(claims.get("typ")) != LICENSE_TYP:
        # Something else signed with this secret. Not a licence key.
        return KeyInfo(detail="Lisans anahtarı geçersiz")

    subject = str(claims.get("sub") or "")
    if username is not None and subject != (username or "").strip():
        logger.warning(
            "Lisans anahtarı başka bir kullanıcıya ait: %s (sunulan: %s)", subject, username
        )
        return KeyInfo(username=subject or None, detail="Lisans anahtarı bu kullanıcıya ait değil")

    try:
        duration = int(claims.get("duration_days") or 0)
    except (TypeError, ValueError):
        duration = 0
    if duration < MIN_DAYS:
        return KeyInfo(username=subject or None, detail="Lisans anahtarı geçersiz süre taşıyor")

    return KeyInfo(
        valid=True,
        username=subject or None,
        duration_days=min(MAX_DAYS, duration),
        detail=f"{duration} günlük lisans anahtarı",
    )


def activate(
    key: str,
    username: str,
    settings: "Settings | None" = None,
    now: datetime | None = None,
) -> UserLicense:
    """Bind a key to the clock. This is where the countdown starts.

    The single place ``license_expires_at`` is ever computed: ``now`` plus the
    duration the key carries. Returns an invalid :class:`UserLicense` (status
    unchanged, no expiry) when the key does not check out, so the caller can
    report the reason without having written anything.
    """
    info = inspect_key(key, username, settings)
    if not info.valid:
        return UserLicense(status=STATUS_PENDING, username=username, detail=info.detail)

    moment = now or datetime.now(timezone.utc)
    expires = moment + timedelta(days=info.duration_days)
    return UserLicense(
        status=STATUS_ACTIVE,
        username=username,
        expires_at=expires.replace(microsecond=0).isoformat(),
        days_remaining=float(info.duration_days),
        detail="Lisans etkinleştirildi",
        activated_at=moment.replace(microsecond=0).isoformat(),
        duration_days=info.duration_days,
    )


def license_for(
    role: str,
    row: dict[str, Any] | None,
    settings: "Settings | None" = None,
    now: datetime | None = None,
) -> UserLicense:
    """The licence state of one account, as the API reports and enforces it.

    Read entirely from the stored row rather than from the key. Once activated,
    the *database* holds the expiry; re-deriving it from the key would restart
    the countdown on every request and the licence would never run out.

    The order of these checks is the policy:

    1. **Administrator** -> unlimited, before anything on the row is read.
    2. **Enforcement off** (no secret) -> unlimited, so an unconfigured site
       keeps working.
    3. **Explicitly revoked** -> revoked, whatever the dates say. Revocation is
       a database fact; a signed key cannot be un-signed.
    4. **No expiry recorded** -> waiting for the operator to enter their key.
    5. Otherwise the recorded expiry decides.
    """
    if not requires_license(role):
        return UserLicense(status=STATUS_UNLIMITED, detail="Sınırsız yönetici lisansı")
    if not enforcement_enabled(settings):
        return UserLicense(status=STATUS_UNLIMITED, detail="Lisans denetimi kapalı")

    record = row or {}
    name = str(record.get("username") or "") or None
    duration = record.get("license_duration_days")
    duration_days = int(duration) if duration else None

    if str(record.get("license_status") or "") == STATUS_REVOKED:
        return UserLicense(
            status=STATUS_REVOKED,
            username=name,
            detail="Lisans iptal edildi",
            activated_at=str(record.get("license_activated_at") or "") or None,
            duration_days=duration_days,
        )

    expires_at = str(record.get("license_expires_at") or "").strip()
    if not expires_at:
        return UserLicense(
            status=STATUS_PENDING,
            username=name,
            detail="Lisans anahtarı bekleniyor",
            duration_days=duration_days,
        )

    moment = now or datetime.now(timezone.utc)
    remaining = _days_until(expires_at, moment)
    if remaining is None:
        # An unparseable date is not an active licence; treat it as unentered
        # rather than granting access on a value nothing can read.
        return UserLicense(
            status=STATUS_PENDING, username=name, detail="Lisans bitiş tarihi okunamadı"
        )

    activated_at = str(record.get("license_activated_at") or "") or None
    if remaining <= 0:
        return UserLicense(
            status=STATUS_EXPIRED,
            username=name,
            expires_at=expires_at,
            days_remaining=0.0,
            detail="Lisans süresi doldu",
            activated_at=activated_at,
            duration_days=duration_days,
        )

    return UserLicense(
        status=STATUS_ACTIVE,
        username=name,
        expires_at=expires_at,
        days_remaining=remaining,
        detail="Lisans geçerli",
        activated_at=activated_at,
        duration_days=duration_days,
    )


def _days_until(expires_at: str, now: datetime) -> float | None:
    """Days from ``now`` to an ISO-8601 instant, or ``None`` if unreadable."""
    try:
        moment = datetime.fromisoformat(expires_at)
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:  # pragma: no cover - stored values carry an offset
        moment = moment.replace(tzinfo=timezone.utc)
    return (moment - now).total_seconds() / 86400.0


def _iso(timestamp: Any) -> str | None:
    try:
        return (
            datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )
    except (TypeError, ValueError, OSError, OverflowError):
        return None
