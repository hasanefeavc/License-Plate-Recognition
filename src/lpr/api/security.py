"""Authentication and authorisation for the LPR API.

Stateless HS256 JWT bearer tokens: the token carries the username, the role and
an expiry, signed with ``settings.api.secret_key``. There is no session store.

One thing is checked against the database on every request, and it is worth
being explicit about why. Sessions are role-scoped -- a year for an
administrator, one shift for an operator (see
:class:`lpr.config.ApiConfig`) -- and over a year a signed claim goes stale in
two ways that matter: the account may have been deleted, or demoted. Neither
can wait for the expiry, so :func:`resolve_live_user` re-reads the account
behind each token. That is one indexed primary-key lookup, and it is what makes
"delete user" and "change role" take effect rather than being advisory.

Password *verification* is deliberately not implemented here -- it belongs to
:class:`lpr.db.UserRepository`, which owns the hashing scheme (argon2). This
module only ever asks the repository "is this password correct?" and turns a
``True`` into a token.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lpr.config import get_settings

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
ADMIN_ROLE = "admin"
OPERATOR_ROLE = "operator"

# auto_error=False so a missing header reaches our own handler and produces the
# same JSON error envelope as everything else instead of FastAPI's default.
_bearer_scheme = HTTPBearer(auto_error=False, scheme_name="BearerToken")

__all__ = [
    "ADMIN_ROLE",
    "ALGORITHM",
    "AuthError",
    "AuthUser",
    "OPERATOR_ROLE",
    "authenticate_user",
    "create_token",
    "current_user",
    "decode_token",
    "require_admin",
    "resolve_live_user",
    "token_ttl_seconds",
    "user_from_token",
]


class AuthError(Exception):
    """Raised by the non-HTTP helpers (used by the WebSocket handshake).

    The HTTP dependencies translate this into a 401; the WebSocket endpoint
    translates it into a 1008 policy-violation close.
    """


@dataclass(frozen=True, slots=True)
class AuthUser:
    """The authenticated caller, as reconstructed from a valid token."""

    username: str
    role: str = OPERATOR_ROLE

    @property
    def is_admin(self) -> bool:
        return self.role == ADMIN_ROLE


def token_ttl_seconds(role: str | None = None, override_min: int | None = None) -> int:
    """How long a session for ``role`` should last, in seconds.

    Resolution order, most specific first: an ``override_min`` stored on the
    account, then the policy for the role, then ``api.token_ttl_min`` as the
    fallback for anything unrecognised. Floored at a minute so a
    misconfiguration cannot mint a token that has already expired.
    """
    api = get_settings().api
    if override_min:
        minutes = int(override_min)
    elif role == ADMIN_ROLE:
        minutes = int(getattr(api, "admin_token_ttl_min", api.token_ttl_min))
    elif role == OPERATOR_ROLE:
        minutes = int(getattr(api, "operator_token_ttl_min", api.token_ttl_min))
    else:
        minutes = int(api.token_ttl_min)
    return max(60, minutes * 60)


def _secret_key() -> str:
    return get_settings().api.secret_key


def create_token(username: str, role: str = OPERATOR_ROLE, ttl_minutes: int | None = None) -> str:
    """Sign a bearer token for ``username`` with ``role``.

    Claims: ``sub`` (username), ``role``, ``iat``, ``exp``. The lifetime comes
    from :func:`token_ttl_seconds`, so an admin gets a long session and an
    operator a shift-length one without the caller having to know the policy.
    """
    now = datetime.now(timezone.utc)
    lifetime = token_ttl_seconds(role, ttl_minutes)
    payload: dict[str, Any] = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=lifetime)).timestamp()),
    }
    token = jwt.encode(payload, _secret_key(), algorithm=ALGORITHM)
    # PyJWT >= 2 returns str; older builds returned bytes. Normalise.
    if isinstance(token, bytes):  # pragma: no cover - defensive
        token = token.decode("utf-8")
    return token


def decode_token(token: str) -> dict[str, Any]:
    """Verify signature + expiry and return the claim set.

    Raises :class:`AuthError` for anything wrong: bad signature, expired,
    malformed, or missing the ``sub`` claim.
    """
    if not token or not token.strip():
        raise AuthError("Token eksik")
    try:
        claims: dict[str, Any] = jwt.decode(
            token.strip(),
            _secret_key(),
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Oturum süresi doldu") from exc
    except jwt.InvalidTokenError as exc:
        # Covers bad signature, malformed token and missing required claims.
        raise AuthError("Geçersiz oturum anahtarı") from exc

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise AuthError("Geçersiz oturum anahtarı")
    return claims


def user_from_token(token: str) -> AuthUser:
    """Transport-agnostic token -> user. Used by HTTP deps and the WebSocket."""
    claims = decode_token(token)
    role = claims.get("role")
    return AuthUser(
        username=str(claims["sub"]),
        role=role if isinstance(role, str) and role else OPERATOR_ROLE,
    )


def authenticate_user(user_repo: Any, username: str, password: str) -> AuthUser | None:
    """Check credentials through the repository. ``None`` when they are wrong.

    ``user_repo`` is a ``lpr.db.UserRepository`` (duck-typed here so tests can
    pass a fake without importing the db package).
    """
    try:
        if not user_repo.verify(username, password):
            return None
    except Exception:  # pragma: no cover - repository/database failure
        logger.exception("Kullanıcı doğrulaması başarısız: %s", username)
        return None

    role = OPERATOR_ROLE
    try:
        for row in user_repo.list_users():
            if str(row.get("username")) == username:
                role = str(row.get("role") or OPERATOR_ROLE)
                break
    except Exception:  # pragma: no cover - list_users is best-effort
        logger.warning("Kullanıcı rolü okunamadı, 'operator' varsayılıyor", exc_info=True)
    return AuthUser(username=username, role=role)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def resolve_live_user(user: AuthUser, user_repo: Any = None) -> AuthUser:
    """Re-check a token's account against the database.

    A JWT is a claim frozen at sign time, and with ``admin_token_ttl_min`` at a
    year that claim can be very stale. Two things must not wait a year:

    * **Deletion.** Removing an account has to end its sessions, or "delete
      user" is theatre. This is what makes it real.
    * **Demotion.** An account moved from admin to operator carries a token
      that still says ``admin``; the database role is the authoritative one.

    Raises :class:`AuthError` when the account is gone. A *lookup failure* is
    not the same as a deleted account, so it is logged and the token is
    honoured: this check is a revocation layer on top of a signature that is
    still valid, and a transient database error should not lock every operator
    out of a running gate.
    """
    try:
        if user_repo is None:
            from lpr.db import UserRepository

            user_repo = UserRepository()
        row = user_repo.get(user.username)
    except Exception:
        logger.warning(
            "Kullanıcı doğrulanamadı, jeton kabul ediliyor: %s", user.username, exc_info=True
        )
        return user

    if row is None:
        logger.info("Silinmiş hesabın jetonu reddedildi: %s", user.username)
        raise AuthError("Hesap artık mevcut değil")

    role = str(row.get("role") or OPERATOR_ROLE)
    return user if role == user.role else AuthUser(username=user.username, role=role)


async def current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ] = None,
) -> AuthUser:
    """FastAPI dependency: the authenticated caller, or HTTP 401."""
    if credentials is None or not credentials.credentials:
        raise _unauthorized("Kimlik doğrulama gerekli")
    if (credentials.scheme or "").lower() != "bearer":
        raise _unauthorized("Kimlik doğrulama gerekli")
    try:
        return resolve_live_user(user_from_token(credentials.credentials))
    except AuthError as exc:
        raise _unauthorized(str(exc)) from exc


async def require_admin(
    user: Annotated[AuthUser, Depends(current_user)],
) -> AuthUser:
    """FastAPI dependency: like :func:`current_user` but 403 for non-admins."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu işlem için yönetici yetkisi gerekli",
        )
    return user


CurrentUser = Annotated[AuthUser, Depends(current_user)]
AdminUser = Annotated[AuthUser, Depends(require_admin)]
