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

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lpr.api.deps import get_user_repository
from lpr.config import get_settings

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
ADMIN_ROLE = "admin"
OPERATOR_ROLE = "operator"
#: Read-only. Sees the live view, the pass log and the occupancy count; may
#: not touch the barrier, the plate list, the configuration or other accounts.
#:
#: This role exists because the alternative was worse. A gatehouse attendant
#: who needs to watch the feed and look up "did that van come through" had no
#: option but ``operator``, which also carries the manual gate-open button --
#: so every site ended up handing barrier control to whoever needed to read a
#: log.
VIEWER_ROLE = "viewer"

#: Every role the system knows, weakest first. Order is meaningful: it is what
#: :func:`role_at_least` compares.
ROLES: tuple[str, ...] = (VIEWER_ROLE, OPERATOR_ROLE, ADMIN_ROLE)

#: Rank per role, for the comparison above.
_ROLE_RANK = {name: index for index, name in enumerate(ROLES)}

# auto_error=False so a missing header reaches our own handler and produces the
# same JSON error envelope as everything else instead of FastAPI's default.
_bearer_scheme = HTTPBearer(auto_error=False, scheme_name="BearerToken")

__all__ = [
    "ADMIN_ROLE",
    "ALGORITHM",
    "AuthError",
    "AuthUser",
    "LICENSE_LAPSED_DETAIL",
    "OPERATOR_ROLE",
    "ROLES",
    "VIEWER_ROLE",
    "require_licensed_operator",
    "require_operator",
    "role_at_least",
    "authenticate_user",
    "create_token",
    "current_user",
    "decode_token",
    "license_forbidden",
    "license_refusal",
    "require_admin",
    "require_license",
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

    @property
    def is_viewer(self) -> bool:
        """Read-only. True only for the viewer role, never for admin.

        Asked as "is this account restricted", not as "what rank is it", so it
        stays correct if a role is ever inserted between viewer and operator.
        """
        return self.role == VIEWER_ROLE

    @property
    def can_write(self) -> bool:
        """Whether this account may change anything at all."""
        return role_at_least(self.role, OPERATOR_ROLE)


def role_at_least(role: str | None, minimum: str) -> bool:
    """Whether ``role`` is at least as privileged as ``minimum``.

    An unknown role ranks below everything. That is the safe direction: a
    token carrying a role this build has never heard of -- a downgrade, a
    typo in a database row, a forged claim -- gets the least authority, not
    the most.
    """
    return _ROLE_RANK.get(str(role or ""), -1) >= _ROLE_RANK.get(minimum, len(ROLES))


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
    now = datetime.now(UTC)
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
    if user_repo is None:
        # No repository to consult (no request context). The signature is still
        # valid, so the token stands -- see the fail-open note above.
        return user
    try:
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


#: The user repository, resolved the way FastAPI resolves everything else.
#:
#: Declared as a real dependency rather than fetched with
#: ``deps.get_user_repository(request)``. Calling a provider directly bypasses
#: ``app.dependency_overrides`` entirely -- the auth path would then reach past
#: any override and talk to the process's real database, which is both wrong in
#: a test and surprising in an app that swaps the repository for any reason.
#: Names ``deps.get_user_repository`` itself, not a wrapper around it.
#: ``app.dependency_overrides`` is keyed on the callable's *identity*, so a
#: local indirection -- however thin -- would never be substituted, and the
#: auth path would quietly keep talking to the real database.
UserRepo = Annotated[Any, Depends(get_user_repository)]


async def current_user(
    user_repo: UserRepo,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)] = None,
) -> AuthUser:
    """FastAPI dependency: the authenticated caller, or HTTP 401."""
    if credentials is None or not credentials.credentials:
        raise _unauthorized("Kimlik doğrulama gerekli")
    if (credentials.scheme or "").lower() != "bearer":
        raise _unauthorized("Kimlik doğrulama gerekli")
    try:
        user = user_from_token(credentials.credentials)
        # The revocation check reads SQLite, and this dependency runs on every
        # authenticated request. Left inline it would be a synchronous read on
        # the event loop -- normally a millisecond, but under write contention
        # it waits on the busy-timeout and stalls *every* concurrent request,
        # not just its own. Off the loop it can only ever delay itself.
        return await asyncio.to_thread(resolve_live_user, user, user_repo)
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


async def require_licensed_operator(
    user: Annotated[AuthUser, Depends(require_license)],
) -> AuthUser:
    """Holds a live licence **and** may write. The guard for every mutation.

    Composed rather than duplicated: it depends on :func:`require_license`,
    which depends on :func:`current_user`, so the licence check, the
    revocation check and the role check happen in that order and each is
    written once.

    Order matters for the message the operator sees. A lapsed licence is
    reported as a lapsed licence even for a viewer, because the dashboard
    opens the licence dialog on that specific detail string -- telling a
    viewer "you are read-only" when the real problem is an expired licence
    would send them to the wrong place.
    """
    if not user.can_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu hesap salt okunur (viewer); bu işlem için yetkisi yok",
        )
    return user


async def require_operator(
    user: Annotated[AuthUser, Depends(current_user)],
) -> AuthUser:
    """FastAPI dependency: 403 for a read-only viewer.

    The guard on everything that *changes* something short of administration:
    the plate list, the barrier, the pipeline's paused state. Admins pass it
    too -- it is a floor, not an exact match.

    Kept separate from :func:`require_admin` rather than folded into it,
    because the two answer different questions. "May this account write" and
    "may this account manage the installation" are the same for two roles out
    of three and different for the one this exists for.
    """
    if not user.can_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu hesap salt okunur (viewer); bu işlem için yetkisi yok",
        )
    return user


async def license_refusal(user: AuthUser, user_repo: Any) -> str | None:
    """``None`` when ``user`` may use the application, or the refusal detail.

    The single place the application-access rule is evaluated. Four callers
    share it -- the HTTP dependency below, the MJPEG endpoint, the WebSocket
    handshake and the login route -- and they must agree, because an account
    refused at login that could still open a socket would not be refused at
    all.

    Administrators pass unconditionally -- see
    :func:`lpr.user_license.requires_license` for why the account that issues
    keys cannot be gated by one.

    A failure to *read* the licence lets the caller through, for the same
    reason the revocation check does: this sits on top of an already-valid
    credential, and a database hiccup must not lock an operator out of a
    working installation.

    Note what this does **not** touch: the barrier. A licence governs one
    person's access to the dashboard and the API, and a resident's car is not
    party to that contract -- see
    :meth:`lpr.db.repository.PlateRepository.authorization`.
    """
    from lpr.user_license import license_for, requires_license

    if not requires_license(user.role):
        return None
    if user_repo is None:  # pragma: no cover - provider always returns one
        return None
    try:
        # Off the event loop, for the same reason as the revocation check.
        row = await asyncio.to_thread(user_repo.get, user.username)
    except Exception:
        logger.warning("Lisans okunamadı, istek kabul ediliyor: %s", user.username, exc_info=True)
        return None

    state = license_for(user.role, row)
    if state.valid:
        return None
    logger.info("Lisans engeli: %s (%s)", user.username, state.status)
    return LICENSE_LAPSED_DETAIL


def license_forbidden(detail: str) -> HTTPException:
    """The one refusal an unlicensed account ever sees: **403 Forbidden**."""
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


async def require_license(
    user: Annotated[AuthUser, Depends(current_user)],
    user_repo: UserRepo,
) -> AuthUser:
    """Like :func:`current_user`, but the account must hold a live licence.

    Refuses with **403 Forbidden** and :data:`LICENSE_LAPSED_DETAIL`. The
    dashboard tells this apart from an ordinary role refusal by that exact
    detail string, and opens the licence dialog on it -- so the two must stay
    in step; ``test_web_ui`` asserts the page carries the same text.

    This is the dependency for everything an authenticated caller does with
    the site: operating it, and reading it. The only endpoints deliberately
    left on :func:`current_user` are the ones an unlicensed operator needs in
    order to *stop* being unlicensed -- ``/api/auth/me``, ``/api/license``,
    ``/api/license/me`` and ``/api/license/activate``. Gating those would
    leave the dashboard unable to explain why everything else refuses, and
    would remove the way back in.
    """
    detail = await license_refusal(user, user_repo)
    if detail is None:
        return user
    raise license_forbidden(detail)


#: What an expired account is told, at login and on every authenticated
#: request. One constant because four places have to agree on it: this module
#: raises it, the login route raises it, the WebSocket closes with it, and
#: ``web/app.js`` matches on it to tell a lapsed licence apart from an ordinary
#: role refusal (both are 403).
LICENSE_LAPSED_DETAIL = "Kullanıcı lisans süresi dolmuştur"


CurrentUser = Annotated[AuthUser, Depends(current_user)]
AdminUser = Annotated[AuthUser, Depends(require_admin)]
#: Authenticated *and* licensed. This is the dependency for anything that
#: operates the site, as opposed to reading it or managing accounts.
LicensedUser = Annotated[AuthUser, Depends(require_license)]
