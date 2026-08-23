"""Authentication and authorisation for the LPR API.

Stateless HS256 JWT bearer tokens. There is no server-side session store: the
token itself carries the username, the role and an expiry, signed with
``settings.api.secret_key``.

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


def token_ttl_seconds() -> int:
    """Configured token lifetime, in seconds."""
    return max(60, int(get_settings().api.token_ttl_min) * 60)


def _secret_key() -> str:
    return get_settings().api.secret_key


def create_token(username: str, role: str = OPERATOR_ROLE) -> str:
    """Sign a bearer token for ``username`` with ``role``.

    Claims: ``sub`` (username), ``role``, ``iat``, ``exp``.
    """
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=token_ttl_seconds())).timestamp()),
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
        return user_from_token(credentials.credentials)
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
