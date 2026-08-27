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
    "STATUS_MISSING",
    "STATUS_REVOKED",
    "STATUS_UNLIMITED",
    "UserLicense",
    "enforcement_enabled",
    "issue_key",
    "requires_license",
    "verify_key",
]

ALGORITHM = "HS256"

#: ``typ`` claim. Present so a token from any other subsystem signed with the
#: same secret could never be replayed as a licence.
LICENSE_TYP = "lpr-user-license"

STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"
STATUS_MISSING = "missing"
STATUS_REVOKED = "revoked"
#: Administrators. Not a licence -- the absence of one.
STATUS_UNLIMITED = "unlimited"

#: Validity bounds for a generated key, in days.
MIN_DAYS = 1
MAX_DAYS = 3650


@dataclass(frozen=True, slots=True)
class UserLicense:
    """The result of checking one account's licence."""

    status: str = STATUS_MISSING
    username: str | None = None
    expires_at: str | None = None
    days_remaining: float | None = None
    detail: str = ""

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
) -> tuple[str, str]:
    """Sign a licence key for ``username``. Returns ``(key, expires_at)``.

    Raises ``RuntimeError`` when no secret is configured -- generating a key
    that nothing can verify would look like success and fail at activation.
    """
    secret = _secret(settings)
    if not secret:
        raise RuntimeError("LPR_LICENSE_SECRET tanımlı değil; lisans anahtarı üretilemez.")

    name = (username or "").strip()
    if not name:
        raise ValueError("Lisans anahtarı için kullanıcı adı gerekli")
    span = max(MIN_DAYS, min(MAX_DAYS, int(days)))

    issued = now or datetime.now(timezone.utc)
    expires = issued + timedelta(days=span)
    token = jwt.encode(
        {
            "typ": LICENSE_TYP,
            "sub": name,
            "iat": int(issued.timestamp()),
            "exp": int(expires.timestamp()),
        },
        secret,
        algorithm=ALGORITHM,
    )
    if isinstance(token, bytes):  # pragma: no cover - PyJWT 1.x
        token = token.decode("utf-8")
    logger.info("Lisans anahtarı üretildi: %s (%d gün)", name, span)
    return token, expires.replace(microsecond=0).isoformat()


def verify_key(
    key: str,
    username: str | None = None,
    settings: "Settings | None" = None,
    now: datetime | None = None,
) -> UserLicense:
    """Check one licence key. Never raises.

    ``username`` binds the key to an account: a key is issued *to* somebody,
    and without this check any operator could activate a colleague's key and
    inherit its validity.
    """
    secret = _secret(settings)
    if not secret:
        return UserLicense(status=STATUS_MISSING, detail="Lisans doğrulaması yapılandırılmamış")

    raw = (key or "").strip()
    if not raw:
        return UserLicense(status=STATUS_MISSING, detail="Lisans anahtarı girilmedi")

    try:
        claims: dict[str, Any] = jwt.decode(
            raw,
            secret,
            # A single algorithm, never a list: accepting more than one is how
            # a verifier gets talked into checking a signature it should not.
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        stale = _unverified(raw)
        return UserLicense(
            status=STATUS_EXPIRED,
            username=str(stale.get("sub") or "") or None,
            expires_at=_iso(stale.get("exp")),
            days_remaining=0.0,
            detail="Lisans süresi doldu",
        )
    except jwt.InvalidTokenError:
        return UserLicense(status=STATUS_MISSING, detail="Lisans anahtarı geçersiz")

    if str(claims.get("typ")) != LICENSE_TYP:
        # Something else signed with this secret. Not a licence.
        return UserLicense(status=STATUS_MISSING, detail="Lisans anahtarı geçersiz")

    subject = str(claims.get("sub") or "")
    if username is not None and subject != (username or "").strip():
        logger.warning(
            "Lisans anahtarı başka bir kullanıcıya ait: %s (sunulan: %s)", subject, username
        )
        return UserLicense(
            status=STATUS_MISSING,
            username=subject or None,
            detail="Lisans anahtarı bu kullanıcıya ait değil",
        )

    moment = now or datetime.now(timezone.utc)
    expires_ts = float(claims["exp"])
    remaining = (expires_ts - moment.timestamp()) / 86400.0
    return UserLicense(
        status=STATUS_ACTIVE,
        username=subject or None,
        expires_at=_iso(expires_ts),
        days_remaining=max(0.0, remaining),
        detail="Lisans geçerli",
    )


def license_for(
    role: str,
    row: dict[str, Any] | None,
    settings: "Settings | None" = None,
    now: datetime | None = None,
) -> UserLicense:
    """The licence state of one account, as the API reports and enforces it.

    The order of these checks is the policy:

    1. **Administrator** -> unlimited, always, before anything else is read.
    2. **Enforcement off** (no secret) -> unlimited, so an unconfigured site
       keeps working.
    3. **Explicitly revoked** -> revoked, even if the key it holds still
       verifies. Revocation is a database fact; the key cannot be un-signed.
    4. Otherwise the stored key is verified.
    """
    if not requires_license(role):
        return UserLicense(status=STATUS_UNLIMITED, detail="Sınırsız yönetici lisansı")
    if not enforcement_enabled(settings):
        return UserLicense(status=STATUS_UNLIMITED, detail="Lisans denetimi kapalı")

    record = row or {}
    stored_status = str(record.get("license_status") or "")
    if stored_status == STATUS_REVOKED:
        return UserLicense(
            status=STATUS_REVOKED,
            username=str(record.get("username") or "") or None,
            detail="Lisans iptal edildi",
        )

    key = str(record.get("license_key") or "")
    if not key:
        return UserLicense(status=STATUS_MISSING, detail="Lisans anahtarı yok")
    return verify_key(key, str(record.get("username") or "") or None, settings, now)


def _iso(timestamp: Any) -> str | None:
    try:
        return (
            datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _unverified(token: str) -> dict[str, Any]:
    """Claims without signature verification, for reporting on a dead key."""
    try:
        return dict(jwt.decode(token, options={"verify_signature": False}))
    except Exception:  # pragma: no cover - malformed token
        return {}
