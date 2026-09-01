"""HTTP endpoints for the LPR service.

All handlers are ``async``. Anything that can block (JPEG grabbing, sqlite
access through the repositories) is either fast enough to be negligible or is
pushed onto the default thread-pool executor -- the event loop is never held
hostage by camera or database work.

Errors are raised as :class:`fastapi.HTTPException` and rendered into a uniform
JSON envelope by the handlers installed in :mod:`lpr.api.main`; no handler here
ever formats an error body or leaks a traceback itself.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Any, Literal

from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    HTTPException,
    Path,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError

from lpr.api import deps
from lpr.api.ratelimit import client_address
from lpr.api.schemas import (
    CameraIssueOut,
    CameraSourceIn,
    CameraStatusOut,
    HealthOut,
    LicenseIn,
    LicenseOut,
    LoginIn,
    LogOut,
    LogQuery,
    MetricsOut,
    ModelAssetsOut,
    ParkingIn,
    ParkingOut,
    PipelineStateOut,
    PlateIn,
    PlateListOut,
    PlateDetailOut,
    PlateImportOut,
    PlateOut,
    PlateUpdateIn,
    RegisterIn,
    RelayTriggerOut,
    StatsOut,
    SystemEventOut,
    SystemUpdateIn,
    SystemUpdateOut,
    TokenOut,
    LicenseKeyIn,
    UserCreateIn,
    UserLicenseIn,
    UserLicenseOut,
    UserOut,
    VersionOut,
    normalize_plate,
    plate_status,
)
from lpr.api.security import (
    ADMIN_ROLE,
    AuthError,
    AuthUser,
    authenticate_user,
    create_token,
    current_user,
    license_forbidden,
    license_refusal,
    require_admin,
    require_licensed_operator,
    require_license,
    token_ttl_seconds,
    user_from_token,
)
from lpr.contracts import CameraRole, LprEvent, utc_now_iso
from lpr.user_license import license_for

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lpr.config import Settings

logger = logging.getLogger(__name__)

router = APIRouter()

_optional_bearer = HTTPBearer(auto_error=False, scheme_name="BearerToken")

#: Upper bound on MJPEG frames pushed to a single client.
#:
#: The stream reads the capture worker's latest buffer, which is refreshed at
#: the camera's own rate and never waits on detection or OCR, so this is a
#: bandwidth-and-JPEG-encoding budget rather than a property of the pipeline.
#: Set to the capture rate: the previous 10 made a 30 FPS webcam look stuttery
#: for no saving that mattered, since a frame nobody is watching is never
#: encoded at all.
STREAM_MAX_FPS = 30.0
STREAM_BOUNDARY = "lprframe"
#: How long a stream may go without a frame before it gives up (seconds).
_STREAM_IDLE_TIMEOUT_S = 30.0

#: How often to look again once a camera has stopped producing frames.
#:
#: Polling a silent camera at :data:`STREAM_MAX_FPS` was 30 thread-pool hops a
#: second returning ``None`` every time, and the pool it borrows is the same one
#: serving every other request -- so one dark camera made the whole dashboard
#: feel slow. Half a second still notices a camera coming back well inside the
#: reconnect the browser would attempt anyway.
_STREAM_IDLE_POLL_S = 0.5

CurrentUser = Annotated[AuthUser, Depends(current_user)]
AdminUser = Annotated[AuthUser, Depends(require_admin)]
#: Authenticated, and licensed if the role needs one. Everything that *operates*
#: the site uses this; only account management stays admin-only.
LicensedUser = Annotated[AuthUser, Depends(require_license)]
#: A licensed account that may also *change* something. Everything that writes
#: -- the plate list, the barrier, the pipeline's paused state, the site
#: configuration -- takes this instead of LicensedUser, so a read-only viewer
#: is refused at the dependency rather than at each handler's own discretion.
WritingUser = Annotated[AuthUser, Depends(require_licensed_operator)]


def app_version() -> str:
    """Installed package version, with a sane fallback for a source checkout."""
    try:
        from importlib.metadata import version

        return version("lpr")
    except Exception:  # pragma: no cover - not installed / metadata missing
        return "0.1.0"


def _camera_role(camera: str) -> str:
    """Validate a camera role from the path, 404 when it is not one of ours."""
    try:
        return CameraRole(camera.strip().lower()).value
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Bilinmeyen kamera: {camera}",
        ) from None


def _streamable_roles(pipeline: Any) -> set[str] | None:
    """Roles with a live capture worker, or ``None`` when that is unknowable.

    A camera turned off in the config -- the usual reason being two roles
    contending for one physical device -- never gets a worker, so it has no
    frames now and will have none later. Streaming it is a request that can
    only end in the idle timeout.

    ``None`` means "this pipeline cannot say", and the caller then allows the
    stream rather than inventing a 404: guessing wrong in that direction breaks
    a working camera, which is far worse than the hang this check avoids.
    """
    roles = getattr(pipeline, "camera_roles", None)
    if callable(roles):
        try:
            return {str(role) for role in roles()}
        except Exception:  # pragma: no cover - defensive
            logger.debug("camera_roles() failed", exc_info=True)

    # Older pipelines and test doubles expose the same fact through stats().
    try:
        cameras = getattr(pipeline.stats(), "cameras", None)
        if isinstance(cameras, dict):
            return {str(role) for role in cameras}
    except Exception:  # pragma: no cover - defensive
        logger.debug("stats().cameras unavailable", exc_info=True)
    return None


def _camera_status_dicts(pipeline: Any) -> list[dict[str, Any]]:
    """Normalise ``stats().cameras`` into plain dicts, whatever it holds."""
    stats = pipeline.stats()
    cameras = getattr(stats, "cameras", None) or {}
    items = cameras.values() if isinstance(cameras, dict) else cameras
    out: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            out.append(dict(item))
            continue
        out.append(
            {
                "role": getattr(item, "role", ""),
                "source": getattr(item, "source", ""),
                "connected": bool(getattr(item, "connected", False)),
                "fps": float(getattr(item, "fps", 0.0)),
                "frames_read": int(getattr(item, "frames_read", 0)),
                "frames_dropped": int(getattr(item, "frames_dropped", 0)),
                "motion_skipped": int(getattr(item, "motion_skipped", 0)),
                "last_error": getattr(item, "last_error", None),
                "last_frame_ts": float(getattr(item, "last_frame_ts", 0.0)),
            }
        )
    return out


async def _in_thread(func: Any, *args: Any) -> Any:
    """Run a blocking repository/pipeline call off the event loop."""
    return await asyncio.get_running_loop().run_in_executor(None, func, *args)


async def _in_thread_kw(func: Any, *args: Any, **kwargs: Any) -> Any:
    """As :func:`_in_thread`, for calls that need keyword arguments.

    ``run_in_executor`` takes positional arguments only, so the call is closed
    over instead. Separate from ``_in_thread`` rather than replacing it: the
    positional form is used on nearly every route and does not need the extra
    lambda.
    """
    return await asyncio.get_running_loop().run_in_executor(None, lambda: func(*args, **kwargs))


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def _setup_required(user_repo: Any) -> bool:
    """True while the installation has no accounts at all.

    Read on the unauthenticated health probe, so it must never raise: a
    database that cannot be reached reports ``False``, which makes the login
    screen offer sign-in rather than advertising public registration on a
    system whose user table it simply could not read.
    """
    try:
        return bool(user_repo.is_first_user())
    except Exception:
        logger.debug("Kurulum durumu okunamadı", exc_info=True)
        return False


@router.get("/health", response_model=HealthOut, tags=["health"], summary="Servis sağlığı")
async def health(request: Request, user_repo: deps.UserRepo) -> HealthOut:
    """Unauthenticated liveness/readiness probe.

    Answers 200 even when the pipeline never started -- the Docker HEALTHCHECK
    hits this endpoint, and a degraded-but-serving API must not be restarted in
    a loop. ``status`` is ``"degraded"`` in that case.
    """
    version = app_version()
    pipeline = deps.get_pipeline_optional(request)
    if pipeline is None:
        # `pipeline_unavailable_detail` folds in the recorded start-up error
        # *and* the model-asset status, so the probe names the missing file
        # rather than only the fact that something is missing. A fresh clone's
        # first boot is the common case here, and "models/plate_yolov8n.pt is
        # not there" is the whole answer.
        return HealthOut(
            status="degraded",
            version=version,
            pipeline_running=False,
            cameras={role.value: False for role in CameraRole},
            detail=deps.pipeline_unavailable_detail(request.app),
            setup_required=_setup_required(user_repo),
        )

    setup_required = _setup_required(user_repo)
    try:
        running = bool(getattr(pipeline, "running", False))
        cameras = {
            str(cam.get("role") or ""): bool(cam.get("connected"))
            for cam in _camera_status_dicts(pipeline)
        }
        cameras.pop("", None)
        for role in CameraRole:
            cameras.setdefault(role.value, False)
    except Exception as exc:  # pragma: no cover - orchestrator misbehaving
        logger.warning("Sağlık kontrolü istatistikleri okunamadı: %s", exc)
        return HealthOut(
            status="degraded",
            version=version,
            pipeline_running=False,
            cameras={role.value: False for role in CameraRole},
            detail="İstatistikler okunamadı",
            setup_required=setup_required,
        )

    healthy = running and any(cameras.values())
    detail: str | None = None
    if not healthy:
        # A role that configuration validation switched off (duplicate device,
        # unopenable source) looks exactly like an unplugged camera from here.
        # It is not, and the difference is the difference between checking a
        # cable and editing one line of .env -- so say which it is.
        issues = deps.get_settings_dep().cameras.issues
        detail = "; ".join(issue.message for issue in issues) or "Kamera bağlantısı yok"
    return HealthOut(
        status="ok" if healthy else "degraded",
        version=version,
        pipeline_running=running,
        cameras=cameras,
        detail=detail,
        setup_required=setup_required,
    )


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@router.post(
    "/api/auth/login",
    response_model=TokenOut,
    tags=["auth"],
    summary="Giriş yap",
)
async def login(request: Request, payload: LoginIn, user_repo: deps.UserRepo) -> TokenOut:
    """Exchange credentials for a bearer token.

    Two things have to be true, and they are different questions. The password
    says *who* this is; the licence says whether that person may use the
    application at all. A lapsed licence is refused here with **403** and
    :data:`LICENSE_LAPSED_DETAIL` rather than at the first API call, so an
    expired account never holds a token in the first place.

    ``license_key`` on the body is the way back in. Activation normally needs a
    session, and refusing the session would otherwise strand an operator
    holding a perfectly good key: locked out of the dashboard, and locked out
    of the endpoint that would unlock it. Sending the key with the credentials
    activates it first and lets the same request through -- the login screen
    offers the field once the server has answered with the lapse.

    None of this touches the barrier: a resident's plate keeps working while
    the account it is recorded against cannot log in. See
    :meth:`lpr.db.repository.PlateRepository.authorization`.

    Rate limited by address and locked out progressively by username -- see
    :mod:`lpr.api.ratelimit`. The check happens *before* the password is
    verified, so a locked account costs no argon2 hash: argon2 is expensive by
    design, and making an attacker pay for it only helps while we are not
    paying it too.
    """
    limiter = deps.get_login_limiter(request)
    address = client_address(request)

    decision = limiter.check(address, payload.username)
    if not decision.allowed:
        _record_auth_event(
            "login_throttled",
            f"Giriş engellendi ({decision.reason}): {payload.username} / {address}",
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Çok fazla başarısız giriş denemesi. "
                f"{decision.retry_after_header} saniye sonra tekrar deneyin."
            ),
            headers={"Retry-After": decision.retry_after_header},
        )

    limiter.record_attempt(address)
    user = await _in_thread(authenticate_user, user_repo, payload.username, payload.password)
    if user is None:
        locked = limiter.record_failure(address, payload.username)
        if not locked.allowed:
            _record_auth_event(
                "login_lockout",
                f"Hesap kilitlendi: {payload.username} "
                f"({locked.retry_after_header} sn, kaynak {address})",
                level="warning",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanıcı adı veya parola hatalı",
            headers={"WWW-Authenticate": "Bearer"},
        )

    limiter.record_success(address, payload.username)

    # Only after the password checked out. Activating on an unauthenticated
    # request would let anyone holding a key burn it against any username.
    if payload.license_key:
        await _activate_license_key(user_repo, user.username, payload.license_key)

    lapsed = await license_refusal(user, user_repo)
    if lapsed is not None:
        raise license_forbidden(lapsed)

    # Session length follows the account: an admin stays signed in, an operator
    # gets a shift. A per-account override on the row beats both.
    ttl_min = await _account_ttl(user_repo, user.username)
    return TokenOut(
        access_token=create_token(user.username, user.role, ttl_min),
        expires_in=token_ttl_seconds(user.role, ttl_min),
        username=user.username,
        role=user.role,
    )


def _record_auth_event(source: str, message: str, level: str = "info") -> None:
    """Write one authentication event to the admin trail. Never raises.

    A brute-force attempt nobody can see afterwards is only half-defended, so
    throttles and lockouts land in ``system_events`` where an admin reviews
    them -- but the audit trail is not on the control path, and a database
    hiccup must not turn a refused login into a 500.
    """
    try:
        from lpr.db import SystemEventRepository

        SystemEventRepository().write(source=source, message=message, level=level)
    except Exception:  # pragma: no cover - the trail is never load-bearing
        logger.debug("Kimlik doğrulama olayı kaydedilemedi", exc_info=True)


async def _account_ttl(user_repo: Any, username: str) -> int | None:
    """The per-account session override, or ``None`` to use the role policy."""
    getter = getattr(user_repo, "get", None)
    if not callable(getter):
        return None
    try:
        row = await _in_thread(getter, username)
    except Exception:  # pragma: no cover - repository failure
        logger.debug("Oturum süresi okunamadı: %s", username, exc_info=True)
        return None
    value = (row or {}).get("token_ttl_min")
    return int(value) if value else None


@router.post(
    "/api/auth/register",
    response_model=TokenOut,
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
    summary="Kullanıcı oluştur",
)
async def register(
    payload: RegisterIn,
    user_repo: deps.UserRepo,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_optional_bearer)] = None,
) -> TokenOut:
    """Create an account.

    The very first account on a fresh installation may be created without any
    credentials and is always given the ``admin`` role -- this is the bootstrap
    path the desktop client's login screen uses. Once that account exists,
    every further registration needs an admin bearer token.
    """
    first_user = bool(await _in_thread(user_repo.is_first_user))

    if first_user:
        role = ADMIN_ROLE
    else:
        if credentials is None or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Kimlik doğrulama gerekli",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            requester = user_from_token(credentials.credentials)
        except AuthError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        if not requester.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Bu işlem için yönetici yetkisi gerekli",
            )
        role = payload.role

    created = await _in_thread(user_repo.register, payload.username, payload.password, role)
    if not created:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Kullanıcı zaten mevcut: {payload.username}",
        )

    logger.info("Yeni kullanıcı oluşturuldu: %s (%s)", payload.username, role)
    return TokenOut(
        access_token=create_token(payload.username, role),
        expires_in=token_ttl_seconds(role),
        username=payload.username,
        role=role,
    )


@router.get("/api/auth/me", response_model=UserOut, tags=["auth"], summary="Oturum bilgisi")
async def whoami(user: CurrentUser) -> UserOut:
    return UserOut(username=user.username, role=user.role)


@router.get(
    "/api/users",
    response_model=list[UserOut],
    tags=["auth"],
    summary="Kullanıcıları listele",
)
async def list_users(_: AdminUser, user_repo: deps.UserRepo) -> list[UserOut]:
    """Every account. Admin only, and never carries password material."""
    rows = await _in_thread(user_repo.list_users)
    return [_user_out(row) for row in rows]


def _user_out(row: dict[str, Any]) -> UserOut:
    """Map one user row onto the wire model, with its live licence state.

    ``license_status`` is recomputed rather than read straight off the row: the
    stored value is what was true when the key was issued, and a key that has
    since expired should show as expired without anybody having to run a
    sweep.
    """
    ttl = row.get("token_ttl_min")
    role = str(row.get("role") or "operator")
    state = license_for(role, row)
    return UserOut(
        username=str(row.get("username", "")),
        role=role,
        created_at=(str(row["created_at"]) if row.get("created_at") else None),
        token_ttl_min=int(ttl) if ttl else None,
        license_status=state.status,
        license_expires_at=state.expires_at or (row.get("license_expires_at") or None),
        license_key=(row.get("license_key") or None),
        license_activated_at=state.activated_at,
        license_duration_days=state.duration_days,
    )


@router.post(
    "/api/users",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
    summary="Kullanıcı oluştur",
)
async def create_user(payload: UserCreateIn, _: AdminUser, user_repo: deps.UserRepo) -> UserOut:
    """Create an account. Admin only.

    Separate from ``POST /api/auth/register``, which exists for the one
    unauthenticated case: the very first account on a fresh installation. This
    endpoint is the ordinary path and always requires an admin token, so the
    bootstrap hole stays exactly one account wide.

    ``token_ttl_min`` sets how long this account's sessions last; leaving it
    unset inherits the policy for the role.
    """
    created = await _in_thread_kw(
        user_repo.register,
        payload.username,
        payload.password,
        payload.role,
        token_ttl_min=payload.token_ttl_min,
    )
    if not created:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Kullanıcı adı zaten kayıtlı: {payload.username}",
        )

    logger.info(
        "Kullanıcı oluşturuldu: %s (rol=%s, oturum=%s dk)",
        payload.username,
        payload.role,
        payload.token_ttl_min or "rol varsayılanı",
    )
    row = await _in_thread(user_repo.get, payload.username) if hasattr(user_repo, "get") else None
    return _user_out(
        row
        or {
            "username": payload.username,
            "role": payload.role,
            "token_ttl_min": payload.token_ttl_min,
        }
    )


@router.delete(
    "/api/users/{username}",
    response_model=UserOut,
    tags=["auth"],
    summary="Kullanıcı sil",
)
async def delete_user(
    user: AdminUser,
    user_repo: deps.UserRepo,
    username: Annotated[str, Path(min_length=1, max_length=40, examples=["bekci"])],
) -> UserOut:
    """Delete an account. Admin only, with two refusals, checked in this order.

    **You cannot delete the last admin.** There is no recovery path: with no
    admin account left nobody can create one, and the installation needs its
    database edited by hand. ``POST /api/auth/register`` will not help --
    it only bootstraps when the user table is *entirely* empty.

    **You cannot delete yourself.** The request would succeed and then
    immediately invalidate the token that made it, which reads as the dashboard
    breaking. Ask another admin.

    Any plates recorded against the account keep working: ``plates.username``
    is ownership metadata, not a gate permit, so the cars are unaffected.

    The last-admin check comes first because when both apply -- the sole
    administrator deleting their own account -- it is the one that says what to
    do next.

    Deletion takes effect immediately rather than at token expiry: every
    request re-checks the account behind its token (see
    :func:`lpr.api.security.resolve_live_user`), which is what makes this
    meaningful against an admin session that lasts a year.
    """
    name = username.strip()
    existing = await _in_thread(user_repo.get, name) if hasattr(user_repo, "get") else None
    if existing is None:
        # Fall back to the list for a repository without get(), so the 404
        # below is still accurate rather than a blind delete.
        rows = await _in_thread(user_repo.list_users)
        existing = next((r for r in rows if str(r.get("username")) == name), None)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Kullanıcı bulunamadı: {name}",
        )

    # Order matters. When the last admin tries to delete themselves both rules
    # apply, and "you cannot remove the last administrator" is the one that
    # tells them what to do about it -- create another admin first. Checking
    # self-deletion first would answer with "ask another admin" on an
    # installation where there is no other admin to ask.
    if str(existing.get("role")) == ADMIN_ROLE and await _last_admin(user_repo):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Son yönetici hesabı silinemez. Önce başka bir yönetici oluşturun.",
        )

    if name == user.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Kendi hesabınızı silemezsiniz. Başka bir yöneticiden isteyin.",
        )

    removed = await _in_thread(user_repo.delete, name)
    if not removed:  # pragma: no cover - raced with another delete
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Kullanıcı bulunamadı: {name}",
        )

    logger.warning("Kullanıcı silindi: %s (silen: %s)", name, user.username)
    return _user_out(existing)


async def _last_admin(user_repo: Any) -> bool:
    """True when exactly one admin account remains."""
    counter = getattr(user_repo, "count_by_role", None)
    if callable(counter):
        return int(await _in_thread(counter, ADMIN_ROLE)) <= 1
    rows = await _in_thread(user_repo.list_users)
    return sum(1 for row in rows if str(row.get("role")) == ADMIN_ROLE) <= 1


# ---------------------------------------------------------------------------
# Plates
# ---------------------------------------------------------------------------


@router.get(
    "/api/plates",
    response_model=PlateListOut,
    tags=["plates"],
    summary="Kayıtlı plakalar",
)
async def list_plates(_: LicensedUser, plate_repo: deps.PlateRepo) -> PlateListOut:
    """Every registered plate, as bare strings *and* as resident records.

    Both shapes come back from one request. ``plates`` is what the desktop
    client has always consumed and stays a list of strings; ``records`` carries
    the owner, apartment, expiry and derived status the management screen
    renders. Serving them together keeps the screen to a single round trip and
    guarantees the two views cannot disagree.
    """
    rows = await _in_thread(_plate_records, plate_repo)
    return PlateListOut(
        plates=[row["plate"] for row in rows],
        records=[PlateDetailOut.model_validate(row) for row in rows],
        count=len(rows),
    )


def _plate_records(plate_repo: Any) -> list[dict[str, Any]]:
    """Detailed rows with ``status`` attached, or bare plates on an old repo.

    ``all_detailed`` is the richer call; a repository that predates it (or a
    test double standing in for one) still yields a usable list rather than an
    error, because the plate list is the screen an operator opens first.
    """
    detailed = getattr(plate_repo, "all_detailed", None)
    if not callable(detailed):
        return [{"plate": plate} for plate in plate_repo.all()]

    now = utc_now_iso()
    rows: list[dict[str, Any]] = []
    for row in detailed():
        record = dict(row)
        record["blocked"] = bool(record.get("blocked"))
        record["status"] = plate_status(record, now)
        rows.append(record)
    return rows


@router.post(
    "/api/plates",
    response_model=PlateOut,
    status_code=status.HTTP_201_CREATED,
    tags=["plates"],
    summary="Plaka ekle",
)
async def add_plate(payload: PlateIn, _: WritingUser, plate_repo: deps.PlateRepo) -> PlateOut:
    """Register one plate, with resident details when the caller supplied them.

    Still a 409 on a duplicate rather than a silent overwrite: adding a plate
    that is already there is a mistake worth telling the operator about. Bulk
    replacement is what ``POST /api/plates/import?overwrite=true`` is for.
    """
    upsert = getattr(plate_repo, "upsert", None)
    if callable(upsert):
        fields: dict[str, Any] = {
            "owner": payload.owner,
            "apartment": payload.apartment,
            "note": payload.note,
            "expires_at": payload.expires_at,
            "blocked": payload.blocked,
            "overwrite": False,
        }
        # Sent only when the caller named a subscriber, so a repository that
        # predates the column still serves the common case. When one *is*
        # named it is passed regardless: failing loudly beats registering the
        # car with its subscriber silently dropped, which would leave it
        # governed by no licence at all.
        if payload.username is not None:
            fields["username"] = payload.username
        outcome = await _in_thread_kw(upsert, payload.plate, **fields)
        added = outcome == "added"
    else:  # pragma: no cover - repository predating the resident columns
        added = await _in_thread(plate_repo.add, payload.plate, payload.note)

    if not added:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Plaka zaten kayıtlı: {payload.plate}",
        )
    logger.info("Plaka eklendi: %s", payload.plate)
    return PlateOut(plate=payload.plate, registered=True)


@router.patch(
    "/api/plates/{plate}",
    response_model=PlateDetailOut,
    tags=["plates"],
    summary="Plaka kaydını güncelle",
)
async def update_plate(
    payload: PlateUpdateIn,
    _: WritingUser,
    plate_repo: deps.PlateRepo,
    plate: Annotated[str, Path(min_length=1, max_length=32, examples=["34ABC123"])],
) -> PlateDetailOut:
    """Patch one resident record. Only the fields sent are written.

    This is what the dashboard's block toggle uses: ``{"blocked": true}``
    changes the flag and leaves owner, apartment, note and expiry exactly as
    they were. A full-overwrite PUT would make the toggle destructive.
    """
    normalized = normalize_plate(plate)
    changes = payload.changes()
    if not changes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Güncellenecek alan belirtilmedi",
        )

    updater = getattr(plate_repo, "update", None)
    if not callable(updater):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Plaka güncelleme desteklenmiyor",
        )

    changed = await _in_thread_kw(updater, normalized, **changes)
    if not changed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Plaka bulunamadı: {normalized}",
        )

    row = await _in_thread(plate_repo.get, normalized) or {"plate": normalized}
    record = dict(row)
    record["blocked"] = bool(record.get("blocked"))
    record["status"] = plate_status(record)
    logger.info("Plaka güncellendi: %s (%s)", normalized, ", ".join(changes))
    return PlateDetailOut.model_validate(record)


@router.delete(
    "/api/plates/{plate}",
    response_model=PlateOut,
    tags=["plates"],
    summary="Plaka sil",
)
async def delete_plate(
    _: WritingUser,
    plate_repo: deps.PlateRepo,
    plate: Annotated[str, Path(min_length=1, max_length=32, examples=["34ABC123"])],
) -> PlateOut:
    normalized = normalize_plate(plate)
    removed = await _in_thread(plate_repo.remove, normalized)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Plaka bulunamadı: {normalized}",
        )
    logger.info("Plaka silindi: %s", normalized)
    return PlateOut(plate=normalized, registered=False)


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


@router.get("/api/logs", response_model=list[LogOut], tags=["logs"], summary="Kayıtlar")
async def list_logs(
    _: LicensedUser,
    log_repo: deps.LogRepo,
    since: Annotated[str | None, Query(examples=["2026-05-01"])] = None,
    until: Annotated[str | None, Query(examples=["2026-05-02"])] = None,
    camera: Annotated[Literal["entry", "exit"] | None, Query(examples=["entry"])] = None,
    plate: Annotated[str | None, Query(examples=["34ABC123"])] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[LogOut]:
    # The individual Query(...) constraints above already rejected the obvious
    # nonsense; LogQuery re-runs the whole rule set (plate normalisation, date
    # stripping) so the repository always sees canonical values.
    try:
        query = LogQuery(
            since=since,
            until=until,
            camera=camera,
            plate=plate,
            limit=limit,
            offset=offset,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_url=False)) from exc
    events = await _in_thread(
        lambda: log_repo.query(
            since=query.since,
            until=query.until,
            camera=query.camera,
            plate=query.plate,
            limit=query.limit,
            offset=query.offset,
        )
    )
    return [LogOut.from_event(event) for event in events]


@router.get(
    "/api/logs/dates",
    response_model=list[str],
    tags=["logs"],
    summary="Kayıt bulunan günler",
)
async def log_dates(
    _: LicensedUser,
    log_repo: deps.LogRepo,
    tz_offset: Annotated[int, Query(ge=-840, le=840, examples=[180])] = 0,
) -> list[str]:
    """Days that have log rows, newest first, as ``YYYY-MM-DD``.

    ``tz_offset`` is minutes **east of UTC** (180 for Turkey), and decides
    whose calendar day the rows are bucketed into. The browser passes its own
    offset so the picker offers the operator *their* days: a read at 01:30 in
    Istanbul is stored as 22:30 the day before in UTC, and without this it
    would be offered under a date the operator never worked.

    The bounds are the real ones -- UTC-12:00 to UTC+14:00 -- so a nonsense
    offset is a 422 rather than a silently skewed day list.

    Whatever this returns, the client must filter with the matching day
    boundaries; a list bucketed one way and a range computed another is how
    a day that plainly has rows comes back empty.
    """
    days = await _in_thread(log_repo.dates, int(tz_offset))
    return [str(day) for day in days]


# ---------------------------------------------------------------------------
# Parking occupancy
# ---------------------------------------------------------------------------

#: ``system_meta`` key holding the operator-set capacity. Stored in the
#: database rather than config.yaml so an admin can change it from the browser
#: without a redeploy, and so every tablet on the site reads one value.
CAPACITY_KEY = "parking.capacity"


def _day_start_iso() -> str:
    """Midnight UTC today -- the window the occupancy counter works over.

    Occupancy is a same-day tally: it resets at 00:00 UTC rather than trying
    to reconcile a car that was parked overnight. A gate log is not a parking
    contract, and a counter that silently drifts for weeks is worse than one
    that is honest about its window.
    """
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


def _read_capacity(meta_repo: Any, settings: Settings) -> int:
    """Operator-set capacity, falling back to the configured default."""
    try:
        stored = meta_repo.get(CAPACITY_KEY)
    except Exception:  # pragma: no cover - a missing table reads as "unset"
        logger.debug("Kapasite okunamadı", exc_info=True)
        stored = None
    if stored is not None:
        try:
            return max(0, int(stored))
        except (TypeError, ValueError):
            logger.warning("Geçersiz kapasite değeri saklanmış: %r", stored)
    return max(0, int(settings.parking.capacity))


async def _parking_state(log_repo: Any, meta_repo: Any, settings: Settings) -> ParkingOut:
    since = _day_start_iso()
    capacity = _read_capacity(meta_repo, settings)
    counts = await _in_thread(log_repo.occupancy_since, since)
    inside = int(counts.get("inside", 0))
    return ParkingOut(
        inside=inside,
        capacity=capacity,
        # A capacity of 0 means "not configured", not "permanently full".
        full=capacity > 0 and inside >= capacity,
        entries=int(counts.get("entries", 0)),
        exits=int(counts.get("exits", 0)),
        since=since,
    )


@router.get(
    "/api/parking",
    response_model=ParkingOut,
    tags=["parking"],
    summary="Doluluk ve kapasite",
)
async def parking_state(
    _: LicensedUser,
    log_repo: deps.LogRepo,
    meta_repo: deps.MetaRepo,
    settings: deps.AdminSettings,
) -> ParkingOut:
    return await _parking_state(log_repo, meta_repo, settings)


@router.put(
    "/api/parking",
    response_model=ParkingOut,
    tags=["parking"],
    summary="Kapasiteyi ayarla",
)
async def set_parking_capacity(
    payload: ParkingIn,
    user: WritingUser,
    log_repo: deps.LogRepo,
    meta_repo: deps.MetaRepo,
    settings: deps.AdminSettings,
) -> ParkingOut:
    await _in_thread(meta_repo.set, CAPACITY_KEY, str(int(payload.capacity)))
    logger.info(
        "Otopark kapasitesi %d olarak ayarlandı (kullanıcı: %s)",
        payload.capacity,
        user.username,
    )
    return await _parking_state(log_repo, meta_repo, settings)


# ---------------------------------------------------------------------------
# Pipeline / cameras
# ---------------------------------------------------------------------------


@router.get("/api/stats", response_model=StatsOut, tags=["pipeline"], summary="İstatistikler")
async def stats(request: Request, _: LicensedUser) -> StatsOut:
    pipeline = deps.get_pipeline(request)
    raw = pipeline.stats()
    started_at = float(getattr(raw, "started_at", 0.0) or 0.0)
    uptime = max(0.0, time.time() - started_at) if started_at else 0.0
    return StatsOut(
        running=bool(getattr(pipeline, "running", False)),
        started_at=started_at,
        uptime_s=uptime,
        plates_read=int(getattr(raw, "plates_read", 0)),
        grants=int(getattr(raw, "grants", 0)),
        denials=int(getattr(raw, "denials", 0)),
        ocr_skipped=int(getattr(raw, "ocr_skipped", 0)),
        fast_path_hits=int(getattr(raw, "fast_path_hits", 0)),
        cameras=[CameraStatusOut.model_validate(cam) for cam in _camera_status_dicts(pipeline)],
    )


@router.get(
    "/api/metrics",
    response_model=MetricsOut,
    tags=["pipeline"],
    summary="Sistem metrikleri",
)
async def metrics(request: Request, _: LicensedUser) -> MetricsOut:
    """Flat operational counters for a dashboard or a scrape job.

    Deliberately a superset of ``/api/stats`` minus the per-camera detail:
    the frame counters are summed across cameras so the caller gets the whole
    system in one line. Reads the same snapshot ``/api/stats`` does, so the
    two can never disagree.
    """
    pipeline = deps.get_pipeline(request)
    raw = pipeline.stats()
    started_at = float(getattr(raw, "started_at", 0.0) or 0.0)
    cameras = _camera_status_dicts(pipeline)

    try:
        from lpr.api.ws import manager as ws_manager

        clients = int(ws_manager.count)
    except Exception:  # pragma: no cover - the socket layer is optional
        clients = 0

    # The cached status, not a fresh verify: the watchdog refreshes it on its
    # own interval, and a scrape job must never make this endpoint do crypto.
    license_status = deps.get_license_guard(request.app).status

    return MetricsOut(
        running=bool(getattr(pipeline, "running", False)),
        uptime_s=max(0.0, time.time() - started_at) if started_at else 0.0,
        plates_read=int(getattr(raw, "plates_read", 0)),
        grants=int(getattr(raw, "grants", 0)),
        denials=int(getattr(raw, "denials", 0)),
        ocr_skipped=int(getattr(raw, "ocr_skipped", 0)),
        fast_path_hits=int(getattr(raw, "fast_path_hits", 0)),
        motion_skipped=sum(int(cam.get("motion_skipped", 0)) for cam in cameras),
        frames_read=sum(int(cam.get("frames_read", 0)) for cam in cameras),
        frames_dropped=sum(int(cam.get("frames_dropped", 0)) for cam in cameras),
        cameras_connected=sum(1 for cam in cameras if cam.get("connected")),
        cameras_total=len(cameras),
        websocket_clients=clients,
        license_valid=license_status.valid,
        license_reason=license_status.reason,
        license_client=license_status.client,
        license_expires_at=license_status.expires_at,
        license_days_remaining=license_status.days_remaining,
    )


@router.get(
    "/api/cameras",
    response_model=list[CameraStatusOut],
    tags=["pipeline"],
    summary="Kamera durumları",
)
async def cameras(request: Request, _: LicensedUser) -> list[CameraStatusOut]:
    pipeline = deps.get_pipeline_optional(request)
    if pipeline is None:
        settings = deps.get_settings_dep()
        return [
            CameraStatusOut(
                role=CameraRole.ENTRY.value,
                source=settings.cameras.entry.source,
                connected=False,
                last_error="İşlem hattı çalışmıyor",
            ),
            CameraStatusOut(
                role=CameraRole.EXIT.value,
                source=settings.cameras.exit.source,
                connected=False,
                last_error="İşlem hattı çalışmıyor",
            ),
        ]
    return [CameraStatusOut.model_validate(cam) for cam in _camera_status_dicts(pipeline)]


@router.post(
    "/api/cameras/{camera}/source",
    response_model=CameraStatusOut,
    tags=["pipeline"],
    summary="Kamera kaynağını değiştir",
)
async def set_camera_source(
    request: Request,
    _: WritingUser,
    camera: Annotated[str, Path(examples=["entry"])],
    payload: Annotated[CameraSourceIn, Body()],
) -> CameraStatusOut:
    role = _camera_role(camera)
    pipeline = deps.get_pipeline(request)
    setter = getattr(pipeline, "set_camera_source", None)
    if not callable(setter):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Çalışma anında kamera kaynağı değiştirme desteklenmiyor",
        )
    await _in_thread(setter, role, payload.source)
    logger.info("Kamera kaynağı güncellendi: %s -> %s", role, payload.source)
    for cam in _camera_status_dicts(pipeline):
        if str(cam.get("role")) == role:
            return CameraStatusOut.model_validate(cam)
    return CameraStatusOut(role=role, source=payload.source, connected=False)


@router.post(
    "/api/pipeline/pause",
    response_model=PipelineStateOut,
    tags=["pipeline"],
    summary="İşlemeyi duraklat",
)
async def pause_pipeline(request: Request, _: WritingUser) -> PipelineStateOut:
    # Remembered so releasing a licence hold does not undo a deliberate pause.
    request.app.state.manual_paused = True
    paused = deps.set_paused(request.app, True)
    pipeline = deps.get_pipeline_optional(request)
    return PipelineStateOut(paused=paused, running=bool(getattr(pipeline, "running", False)))


@router.post(
    "/api/pipeline/resume",
    response_model=PipelineStateOut,
    tags=["pipeline"],
    summary="İşlemeye devam et",
)
async def resume_pipeline(request: Request, _: WritingUser) -> PipelineStateOut:
    request.app.state.manual_paused = False
    # Deliberately not gated on the deployment licence any more: access control
    # is the per-user model, and an installation-wide expiry that leaves an
    # administrator unable to restart their own gate is an outage, not a
    # commercial control.
    paused = deps.set_paused(request.app, False)
    pipeline = deps.get_pipeline_optional(request)
    return PipelineStateOut(paused=paused, running=bool(getattr(pipeline, "running", False)))


# ---------------------------------------------------------------------------
# Licence
# ---------------------------------------------------------------------------


def _license_out(request: Request, status_obj: Any) -> LicenseOut:
    return LicenseOut(
        **status_obj.to_dict(),
        pipeline_halted=deps.is_license_halted(request.app),
    )


@router.get(
    "/api/license",
    response_model=LicenseOut,
    tags=["license"],
    summary="Lisans durumu",
)
async def license_status(request: Request, _: CurrentUser) -> LicenseOut:
    """Current licence state, as last checked by the watchdog.

    Any authenticated user may read it -- the desktop client polls this to
    decide whether to lock its own UI, and an operator who cannot see *why*
    the system stopped just phones the installer.
    """
    guard = deps.get_license_guard(request.app)
    return _license_out(request, guard.status)


@router.post(
    "/api/license",
    response_model=LicenseOut,
    tags=["license"],
    summary="Lisans anahtarı gir",
)
async def submit_license(
    request: Request,
    payload: LicenseIn,
    user: AdminUser,
) -> LicenseOut:
    """Install a new licence key and, if it is good, release the halt.

    Verification and storage happen off the event loop (signature check plus
    two SQLite writes). A rejected key is a 400 carrying the reason the
    operator needs -- expired, invalid, or a rolled-back system clock.
    """
    from lpr.license import LicenseError

    guard = deps.get_license_guard(request.app)
    try:
        activated = await _in_thread(guard.activate, payload.key)
    except LicenseError as exc:
        logger.warning("Lisans anahtarı reddedildi (kullanıcı: %s): %s", user.username, exc)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    deps.apply_license_state(request.app, activated.valid)
    logger.info(
        "Lisans güncellendi (kullanıcı: %s, müşteri: %s, bitiş: %s)",
        user.username,
        activated.client,
        activated.expires_at,
    )
    return _license_out(request, activated)


# ---------------------------------------------------------------------------
# Relay
# ---------------------------------------------------------------------------


@router.post(
    "/api/relay/trigger",
    response_model=RelayTriggerOut,
    tags=["relay"],
    summary="Kapıyı elle aç",
)
async def trigger_relay(
    request: Request,
    user: WritingUser,
    log_repo: deps.LogRepo,
) -> RelayTriggerOut:
    """Open the gate by hand and record it as a ``granted`` event for plate
    ``MANUAL`` so the audit trail shows who opened the barrier and when.
    """
    pipeline = deps.get_pipeline(request)
    trigger = getattr(pipeline, "trigger_relay", None)
    if not callable(trigger):
        relay = getattr(pipeline, "relay", None)
        trigger = getattr(relay, "trigger", None)
    if not callable(trigger):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Röle donanımı kullanılamıyor",
        )

    try:
        await _in_thread(trigger)
    except Exception as exc:
        logger.exception("Elle bariyer açma başarısız")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Röle tetiklenemedi: {exc}",
        ) from exc

    event = LprEvent(
        ts=utc_now_iso(),
        camera=CameraRole.ENTRY.value,
        plate="MANUAL",
        action="granted",
        confidence=1.0,
    )
    try:
        await _in_thread(log_repo.write, event)
    except Exception:  # pragma: no cover - logging must not fail the action
        logger.exception("Elle açma kaydı yazılamadı")

    logger.info("Kapı elle açıldı (kullanıcı: %s)", user.username)
    return RelayTriggerOut(triggered=True, plate=event.plate, ts=event.ts, detail=None)


# ---------------------------------------------------------------------------
# MJPEG stream
# ---------------------------------------------------------------------------


async def stream_user(
    user_repo: deps.UserRepo,
    token: Annotated[str | None, Query(description="Bearer token (tarayıcı <img> için)")] = None,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_optional_bearer)] = None,
) -> AuthUser:
    """Auth *and* licence for the MJPEG endpoint.

    An ``<img src=...>`` tag cannot set an ``Authorization`` header, so the
    token may also arrive as a query parameter here. The desktop client uses
    the header.

    The licence is checked here rather than through :data:`LicensedUser`
    because this endpoint takes its credential differently -- and a live camera
    feed is exactly the kind of access a lapsed account must not keep. Skipping
    it would leave the one screen an unlicensed operator most wants still
    working.
    """
    raw = credentials.credentials if credentials and credentials.credentials else token
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kimlik doğrulama gerekli",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        user = user_from_token(raw)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    lapsed = await license_refusal(user, user_repo)
    if lapsed is not None:
        raise license_forbidden(lapsed)
    return user


async def _mjpeg_iterator(
    request: Request,
    pipeline: Any,
    camera: str,
    quality: int,
) -> AsyncIterator[bytes]:
    """Yield ``multipart/x-mixed-replace`` parts until the client goes away."""
    frame_budget = 1.0 / STREAM_MAX_FPS
    header = f"--{STREAM_BOUNDARY}\r\nContent-Type: image/jpeg\r\n".encode("ascii")
    idle_for = 0.0
    try:
        while True:
            if await request.is_disconnected():
                break
            try:
                frame = await _in_thread(pipeline.latest_frame_jpeg, camera, quality)
            except Exception:  # pragma: no cover - capture side failure
                logger.exception("Kare alınamadı: %s", camera)
                break

            if frame:
                idle_for = 0.0
                yield header + f"Content-Length: {len(frame)}\r\n\r\n".encode("ascii")
                yield frame
                yield b"\r\n"
                delay = frame_budget
            else:
                # Back off while there is nothing to send. The camera is
                # configured (the endpoint refused it otherwise), so this is a
                # live camera gone quiet -- worth waiting for, not worth
                # asking about thirty times a second.
                idle_for += _STREAM_IDLE_POLL_S
                if idle_for >= _STREAM_IDLE_TIMEOUT_S:
                    logger.info("Kare gelmediği için akış kapatıldı: %s", camera)
                    break
                delay = _STREAM_IDLE_POLL_S
            await asyncio.sleep(delay)
    except asyncio.CancelledError:  # pragma: no cover - normal disconnect path
        raise
    except (ConnectionResetError, BrokenPipeError):  # pragma: no cover
        logger.debug("İstemci akıştan ayrıldı: %s", camera)
    finally:
        logger.debug("MJPEG akışı sonlandı: %s", camera)


@router.get(
    "/api/stream/{camera}",
    tags=["stream"],
    summary="Canlı MJPEG görüntü",
    response_class=StreamingResponse,
    responses={200: {"content": {"multipart/x-mixed-replace": {}}}},
)
async def stream(
    request: Request,
    _: Annotated[AuthUser, Depends(stream_user)],
    camera: Annotated[str, Path(examples=["entry"])],
    quality: Annotated[int, Query(ge=10, le=95)] = 80,
) -> StreamingResponse:
    role = _camera_role(camera)
    pipeline = deps.get_pipeline(request)

    # A disabled camera is refused here rather than in the generator. Entering
    # the loop for one costs a held connection for the full idle timeout, and a
    # browser only allows a handful of connections per host -- so the dead
    # stream is paid for by every *other* request on the page, which is what
    # made the dashboard load slowly rather than merely show one blank tile.
    available = _streamable_roles(pipeline)
    if available is not None and role not in available:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Kamera etkin değil: {role}",
        )

    return StreamingResponse(
        _mjpeg_iterator(request, pipeline, role, quality),
        media_type=f"multipart/x-mixed-replace; boundary={STREAM_BOUNDARY}",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
            "Connection": "close",
        },
    )


# ---------------------------------------------------------------------------
# System / OTA update
#
# The dangerous half of this feature lives in :mod:`lpr.updater`, not here.
# These handlers authenticate, translate the updater's two refusal modes into
# status codes, and get out of the way -- there is no command construction, no
# subprocess call and nothing from the request body anywhere in this section.
# ---------------------------------------------------------------------------


def _update_out(status_obj: Any, accepted: bool = False) -> SystemUpdateOut:
    return SystemUpdateOut(**status_obj.to_dict(), accepted=accepted)


@router.get(
    "/api/system/version",
    response_model=VersionOut,
    tags=["system"],
    summary="Sistem sürümü",
)
async def system_version(request: Request, _: LicensedUser) -> VersionOut:
    """The deployed version and git revision.

    Readable by any authenticated user: an operator who can see that the site
    is three commits behind can say so on the phone instead of guessing. It
    shells out to git, so it runs off the event loop.
    """
    updater = deps.get_system_updater(request)
    info = await _in_thread(updater.version)
    return VersionOut(**info.to_dict(), update_enabled=bool(updater.enabled))


@router.get(
    "/api/system/assets",
    response_model=ModelAssetsOut,
    tags=["system"],
    summary="Model dosyaları ve kamera yapılandırması",
)
async def system_assets(request: Request, _: LicensedUser) -> ModelAssetsOut:
    """What this installation is missing, named file by file.

    A fresh clone has an empty ``models/`` -- every ``.pt`` is gitignored -- so
    the very first run of a new checkout is also the run most likely to be
    degraded. ``/health`` says *that* the service is degraded; this says
    *which file* to put where, and repeats the camera roles the configuration
    refused to start.

    Readable by any authenticated user, and cheap: it stats a handful of paths
    and imports nothing from the ML stack, which is what lets it answer on a
    box where that stack is what is missing.
    """
    assets = await _in_thread(deps.get_model_assets, request.app)
    settings = deps.get_settings_dep()
    return ModelAssetsOut(
        **assets.to_dict(),
        cameras=[
            CameraIssueOut(**issue.model_dump()) for issue in settings.cameras.issues
        ],
    )


@router.get(
    "/api/system/update",
    response_model=SystemUpdateOut,
    tags=["system"],
    summary="Güncelleme durumu",
)
async def system_update_status(request: Request, _: LicensedUser) -> SystemUpdateOut:
    """Progress of the current or last update.

    This is what the UI polls after the POST. Note that a *successful* update
    kills the container serving it, so the reply that reports success normally
    comes from the freshly started container reading the state file the old one
    left behind.
    """
    return _update_out(deps.get_system_updater(request).status)


@router.post(
    "/api/system/update",
    response_model=SystemUpdateOut,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["system"],
    summary="Sistemi güncelle",
    responses={
        409: {"description": "Zaten devam eden bir güncelleme var"},
        503: {"description": "Sistem güncellemesi devre dışı"},
    },
)
async def system_update(
    request: Request,
    user: WritingUser,
    payload: SystemUpdateIn | None = None,
) -> SystemUpdateOut:
    """Pull from the configured remote and rebuild the stack. Admin only.

    Returns **202 Accepted**, not 200: the work is detached onto its own thread
    and the response is sent before ``docker compose`` starts, because the
    rebuild terminates this process. A 202 that arrives is the strongest
    promise this endpoint can honestly make -- the client must poll
    ``GET /api/system/update`` and ``GET /api/system/version`` for the outcome.

    The body is optional and carries at most ``force``, which asks for the
    rebuild to happen even when the pull brings nothing new. Nothing about
    *what* is pulled or built comes from the caller either way; see
    :class:`lpr.config.SystemUpdateConfig`.
    """
    force = bool(payload.force) if payload is not None else False
    updater = deps.get_system_updater(request)
    try:
        state = updater.start(force=force)
    except RuntimeError as exc:
        detail = str(exc)
        # Disabled is a deployment state (503); already-running is a conflict
        # (409). Both are expected, neither is a server fault.
        code = (
            status.HTTP_409_CONFLICT
            if "devam eden" in detail
            else status.HTTP_503_SERVICE_UNAVAILABLE
        )
        raise HTTPException(status_code=code, detail=detail) from exc

    logger.warning(
        "Sistem %s '%s' tarafından tetiklendi",
        "yeniden derlemesi (zorla)" if force else "güncellemesi",
        user.username,
    )
    return _update_out(state, accepted=True)


@router.get(
    "/api/system/events",
    response_model=list[SystemEventOut],
    tags=["system"],
    summary="Sistem olayları",
)
async def system_events(
    request: Request,
    _: LicensedUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    source: Annotated[str | None, Query(max_length=64)] = None,
) -> list[SystemEventOut]:
    """Operational audit trail, newest first. Admin only.

    This is where the nightly updater reports what it did at 03:00 -- checked,
    found nothing, found something and installed it, or failed and why. It is
    *not* the plate log: those live in different tables precisely so an
    unattended update cannot appear in an operator's vehicle history.
    """
    repo = deps.get_system_event_repository(request)
    rows = await _in_thread(repo.recent, limit, source)
    return [SystemEventOut.model_validate(row) for row in rows]


# ---------------------------------------------------------------------------
# CSV import / export
#
# Exports are returned as a whole body rather than streamed: a resident list is
# a few hundred rows and a filtered log page is capped at EXPORT_MAX_ROWS, so
# the largest response here is a couple of megabytes -- well inside what a
# single Response can carry, and it keeps the Content-Length header that makes
# a browser show a real download progress bar.
# ---------------------------------------------------------------------------

#: Upper bound on rows in one log export. Higher than the UI's page size on
#: purpose (an export is meant to cover a shift, not a screen), but bounded so
#: one request cannot pull a year of history into memory.
EXPORT_MAX_ROWS = 50_000


def _csv_response(payload: bytes, filename: str) -> Response:
    """A CSV body with the headers that make a browser save it as a file."""
    return Response(
        content=payload,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


def _export_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")


@router.post(
    "/api/plates/import",
    response_model=PlateImportOut,
    tags=["plates"],
    summary="Plakaları CSV ile içe aktar",
)
async def import_plates(
    _: WritingUser,
    plate_repo: deps.PlateRepo,
    file: Annotated[
        UploadFile,
        File(description="CSV sütunları: plate, owner, apartment, notes, expires_at"),
    ],
    overwrite: Annotated[bool, Query()] = False,
) -> PlateImportOut:
    """Bulk-load a resident list from a spreadsheet export.

    ``overwrite=false`` (the default) **skips** plates that already exist;
    ``overwrite=true`` updates them in place. Skipping is the default because
    re-uploading last month's list is a normal thing for a site manager to do,
    and it should not silently overwrite owner and expiry data that has been
    corrected in the meantime.

    Excel's habits are handled rather than rejected: a UTF-8 BOM, a semicolon
    delimiter on a Turkish locale, cp1254 encoding, and Turkish column headers
    (``plaka``, ``sahibi``, ``daire``) all parse. Only ``plate`` is required.
    """
    from lpr.csvio import MAX_IMPORT_BYTES, parse_plate_csv

    raw = await file.read()
    if len(raw) > MAX_IMPORT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Dosya çok büyük (en fazla {MAX_IMPORT_BYTES // (1024 * 1024)} MB)",
        )

    report = await _in_thread(parse_plate_csv, raw, overwrite, plate_repo)
    logger.info(
        "CSV içe aktarma (%s): %d eklendi, %d güncellendi, %d atlandı, %d geçersiz",
        file.filename,
        report.added,
        report.updated,
        report.skipped,
        report.invalid,
    )
    return PlateImportOut(**report.to_dict())


@router.get(
    "/api/plates/export",
    tags=["plates"],
    summary="Plakaları CSV olarak indir",
    response_class=Response,
    responses={200: {"content": {"text/csv": {}}}},
)
async def export_plates(_: LicensedUser, plate_repo: deps.PlateRepo) -> Response:
    """The whole plate list as CSV, in the same column order the importer reads.

    Round-trips: downloading, editing in Excel and re-uploading with
    ``overwrite=true`` is a supported way to bulk-edit residents.
    """
    from lpr.csvio import export_plates_csv

    rows = await _in_thread(plate_repo.all_detailed)
    payload = await _in_thread(export_plates_csv, rows)
    return _csv_response(payload, f"plakalar-{_export_stamp()}.csv")


@router.get(
    "/api/events/export",
    tags=["logs"],
    summary="Kayıtları CSV olarak indir",
    response_class=Response,
    responses={200: {"content": {"text/csv": {}}}},
)
async def export_events(
    _: LicensedUser,
    log_repo: deps.LogRepo,
    since: Annotated[str | None, Query(max_length=32)] = None,
    until: Annotated[str | None, Query(max_length=32)] = None,
    camera: Annotated[str | None, Query(max_length=16)] = None,
    plate: Annotated[str | None, Query(max_length=16)] = None,
    limit: Annotated[int, Query(ge=1, le=EXPORT_MAX_ROWS)] = 10_000,
) -> Response:
    """Filtered access history as CSV.

    Takes the same filters as ``GET /api/logs`` so the download matches what
    the operator is looking at on screen, rather than being a second query with
    its own idea of the date range.
    """
    from lpr.csvio import export_events_csv

    # Deliberately not routed through LogQuery: that model caps `limit` at the
    # UI's page size (1000), whereas an export is meant to cover a shift rather
    # than a screen. The bounds that apply here are on the parameters above.
    events = await _in_thread(
        log_repo.query,
        since or None,
        until or None,
        _camera_role(camera) if camera else None,
        normalize_plate(plate) if plate else None,
        limit,
        0,
    )
    rows = [
        {
            "id": event.id,
            "ts": event.ts,
            "camera": event.camera,
            "plate": event.plate,
            "action": event.action,
            "confidence": round(float(event.confidence), 4),
        }
        for event in events
    ]
    payload = await _in_thread(export_events_csv, rows)
    return _csv_response(payload, f"kayitlar-{_export_stamp()}.csv")


# ---------------------------------------------------------------------------
# Per-operator licences
#
# Distinct from the deployment licence above: that one is RS256 from the vendor
# and decides whether this installation may run at all; these are HS256 keys
# this server issues to its own operators and decide who may drive it.
# ---------------------------------------------------------------------------


def _user_license_out(state: Any, key: str | None = None) -> UserLicenseOut:
    """Wire model for a *per-operator* licence.

    Named apart from ``_license_out`` above, which renders the deployment
    licence. Two licences at two scopes; one name for both would shadow.
    """
    return UserLicenseOut(**state.to_dict(), key=key)


@router.get(
    "/api/license/me",
    response_model=UserLicenseOut,
    tags=["license"],
    summary="Kendi lisans durumum",
)
async def my_license(user: CurrentUser, user_repo: deps.UserRepo) -> UserLicenseOut:
    """The caller's own licence state, for the navbar badge.

    Deliberately *not* licence-gated: an operator whose licence has lapsed is
    exactly who needs to read this, and gating it would leave the dashboard
    unable to explain why everything else is refusing.
    """
    row = await _in_thread(user_repo.get, user.username) if hasattr(user_repo, "get") else None
    return _user_license_out(license_for(user.role, row or {"username": user.username}))


@router.post(
    "/api/license/activate",
    response_model=UserLicenseOut,
    tags=["license"],
    summary="Lisans anahtarı etkinleştir",
)
async def activate_user_license(
    payload: LicenseKeyIn, user: CurrentUser, user_repo: deps.UserRepo
) -> UserLicenseOut:
    """Activate a licence key issued to the calling account.

    Not licence-gated, for the obvious reason: this is the way *out* of being
    unlicensed. It is still authenticated, and the key is checked against the
    caller's own username -- a key is issued to a person, and without that
    binding an operator could activate a colleague's key and inherit its
    validity.
    """
    return _user_license_out(
        await _activate_license_key(user_repo, user.username, payload.key)
    )


async def _activate_license_key(user_repo: Any, username: str, key: str) -> Any:
    """Bind one key to ``username`` and store the resulting expiry.

    Shared by ``POST /api/license/activate`` and the login route, which is the
    point: an operator activating from the login screen and one activating from
    the dashboard must get the same validation, the same countdown and the same
    error, or the recovery path would be a second implementation of the rule.

    Raises 400 for a key that does not check out -- including one issued to
    somebody else, because a key is issued to a person and without that binding
    an operator could inherit a colleague's validity.
    """
    from lpr.user_license import activate

    state = await _in_thread(activate, key, username)
    if not state.valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=state.detail or "Lisans anahtarı geçersiz",
        )

    # This is where the countdown starts -- the expiry is computed here, from
    # now plus the duration the key carries, and written once.
    stored = await _in_thread_kw(
        user_repo.set_license,
        username,
        key,
        state.expires_at,
        state.status,
        duration_days=state.duration_days,
        activated_at=state.activated_at,
    )
    if not stored:  # pragma: no cover - account deleted mid-request
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Kullanıcı bulunamadı: {username}",
        )

    logger.info(
        "Lisans etkinleştirildi: %s (%s gün, bitiş %s)",
        username,
        state.duration_days,
        state.expires_at,
    )
    return state


@router.post(
    "/api/users/{username}/license",
    response_model=UserLicenseOut,
    status_code=status.HTTP_201_CREATED,
    tags=["license"],
    summary="Kullanıcıya lisans anahtarı üret",
)
async def generate_user_license(
    payload: UserLicenseIn,
    _: AdminUser,
    user_repo: deps.UserRepo,
    username: Annotated[str, Path(min_length=1, max_length=40, examples=["bekci"])],
) -> UserLicenseOut:
    """Issue a licence key for one operator. Admin only.

    The key is both stored on the account *and* returned once, so the admin can
    pass it on. Issuing activates immediately -- an admin generating a key for
    somebody has already decided they should be working.

    Refuses for an administrator: they are exempt by construction, and a key
    that would never be checked is a misleading thing to hand somebody.
    """
    from lpr.user_license import issue_key, requires_license

    name = username.strip()
    row = await _in_thread(user_repo.get, name) if hasattr(user_repo, "get") else None
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Kullanıcı bulunamadı: {name}"
        )
    if not requires_license(str(row.get("role") or "operator")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Yönetici hesapları sınırsızdır; lisans anahtarı gerekmez",
        )

    try:
        key = await _in_thread(issue_key, name, payload.days)
    except RuntimeError as exc:
        # No signing secret: say so rather than handing over a key that will
        # fail at activation.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    # Nothing is written. Generating a key says what an operator *may* have;
    # it is their activation that says what they now have, and starting the
    # countdown here would burn the days between handing the key over and the
    # operator's first shift.
    logger.info("Lisans anahtarı üretildi: %s (%d gün)", name, payload.days)
    current = license_for(str(row.get("role") or "operator"), row)
    return _user_license_out(current, key=key)


@router.delete(
    "/api/users/{username}/license",
    response_model=UserLicenseOut,
    tags=["license"],
    summary="Kullanıcının lisansını iptal et",
)
async def revoke_user_license(
    _: AdminUser,
    user_repo: deps.UserRepo,
    username: Annotated[str, Path(min_length=1, max_length=40, examples=["bekci"])],
) -> UserLicenseOut:
    """Revoke an operator's licence. Admin only, and effective immediately.

    The key stays on the row and the *status* is what changes. A signed key
    cannot be un-signed, so a status flag is the only thing that can actually
    withdraw it -- and keeping the key lets an admin see what was revoked.
    """
    from lpr.user_license import STATUS_REVOKED, UserLicense

    name = username.strip()
    row = await _in_thread(user_repo.get, name) if hasattr(user_repo, "get") else None
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Kullanıcı bulunamadı: {name}"
        )

    await _in_thread_kw(
        user_repo.set_license,
        name,
        row.get("license_key"),
        row.get("license_expires_at"),
        STATUS_REVOKED,
        duration_days=row.get("license_duration_days"),
        activated_at=row.get("license_activated_at"),
    )
    logger.warning("Lisans iptal edildi: %s", name)
    return _user_license_out(
        UserLicense(status=STATUS_REVOKED, username=name, detail="Lisans iptal edildi")
    )
