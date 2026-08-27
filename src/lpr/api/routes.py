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
from lpr.api.schemas import (
    CameraSourceIn,
    CameraStatusOut,
    HealthOut,
    LicenseIn,
    LicenseOut,
    LoginIn,
    LogOut,
    LogQuery,
    MetricsOut,
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
    SystemUpdateOut,
    TokenOut,
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
    require_admin,
    token_ttl_seconds,
    user_from_token,
)
from lpr.contracts import CameraRole, LprEvent, utc_now_iso

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lpr.config import Settings

logger = logging.getLogger(__name__)

router = APIRouter()

_optional_bearer = HTTPBearer(auto_error=False, scheme_name="BearerToken")

#: Upper bound on MJPEG frames pushed to a single client.
STREAM_MAX_FPS = 10.0
STREAM_BOUNDARY = "lprframe"
#: How long a stream may go without a frame before it gives up (seconds).
_STREAM_IDLE_TIMEOUT_S = 30.0

CurrentUser = Annotated[AuthUser, Depends(current_user)]
AdminUser = Annotated[AuthUser, Depends(require_admin)]


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


@router.get("/health", response_model=HealthOut, tags=["health"], summary="Servis sağlığı")
async def health(request: Request) -> HealthOut:
    """Unauthenticated liveness/readiness probe.

    Answers 200 even when the pipeline never started -- the Docker HEALTHCHECK
    hits this endpoint, and a degraded-but-serving API must not be restarted in
    a loop. ``status`` is ``"degraded"`` in that case.
    """
    version = app_version()
    pipeline = deps.get_pipeline_optional(request)
    if pipeline is None:
        detail = getattr(request.app.state, "pipeline_error", None)
        return HealthOut(
            status="degraded",
            version=version,
            pipeline_running=False,
            cameras={role.value: False for role in CameraRole},
            detail=str(detail) if detail else "İşlem hattı başlatılamadı",
        )

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
        )

    healthy = running and any(cameras.values())
    return HealthOut(
        status="ok" if healthy else "degraded",
        version=version,
        pipeline_running=running,
        cameras=cameras,
        detail=None if healthy else "Kamera bağlantısı yok",
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
async def login(payload: LoginIn, user_repo: deps.UserRepo) -> TokenOut:
    user = await _in_thread(authenticate_user, user_repo, payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanıcı adı veya parola hatalı",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenOut(
        access_token=create_token(user.username, user.role),
        expires_in=token_ttl_seconds(),
        username=user.username,
        role=user.role,
    )


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
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_optional_bearer)
    ] = None,
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
        expires_in=token_ttl_seconds(),
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
    rows = await _in_thread(user_repo.list_users)
    return [
        UserOut(
            username=str(row.get("username", "")),
            role=str(row.get("role") or "operator"),
            created_at=(str(row["created_at"]) if row.get("created_at") else None),
        )
        for row in rows
    ]


# ---------------------------------------------------------------------------
# Plates
# ---------------------------------------------------------------------------


@router.get(
    "/api/plates",
    response_model=PlateListOut,
    tags=["plates"],
    summary="Kayıtlı plakalar",
)
async def list_plates(_: CurrentUser, plate_repo: deps.PlateRepo) -> PlateListOut:
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
async def add_plate(payload: PlateIn, _: AdminUser, plate_repo: deps.PlateRepo) -> PlateOut:
    """Register one plate, with resident details when the caller supplied them.

    Still a 409 on a duplicate rather than a silent overwrite: adding a plate
    that is already there is a mistake worth telling the operator about. Bulk
    replacement is what ``POST /api/plates/import?overwrite=true`` is for.
    """
    upsert = getattr(plate_repo, "upsert", None)
    if callable(upsert):
        outcome = await _in_thread_kw(
            upsert,
            payload.plate,
            owner=payload.owner,
            apartment=payload.apartment,
            note=payload.note,
            expires_at=payload.expires_at,
            blocked=payload.blocked,
            overwrite=False,
        )
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
    _: AdminUser,
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
    _: AdminUser,
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
    _: CurrentUser,
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
async def log_dates(_: CurrentUser, log_repo: deps.LogRepo) -> list[str]:
    return [str(day) for day in await _in_thread(log_repo.dates)]


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
    _: CurrentUser,
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
    user: AdminUser,
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
async def stats(request: Request, _: CurrentUser) -> StatsOut:
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
        cameras=[CameraStatusOut.model_validate(cam) for cam in _camera_status_dicts(pipeline)],
    )


@router.get(
    "/api/metrics",
    response_model=MetricsOut,
    tags=["pipeline"],
    summary="Sistem metrikleri",
)
async def metrics(request: Request, _: CurrentUser) -> MetricsOut:
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
async def cameras(request: Request, _: CurrentUser) -> list[CameraStatusOut]:
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
    _: AdminUser,
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
async def pause_pipeline(request: Request, _: AdminUser) -> PipelineStateOut:
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
async def resume_pipeline(request: Request, _: AdminUser) -> PipelineStateOut:
    request.app.state.manual_paused = False
    # An expired site must not be able to resume itself through this endpoint;
    # the only way out is a valid key via POST /api/license.
    guard = deps.get_license_guard(request.app)
    if deps.is_license_halted(request.app) or not guard.status.valid:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=guard.status.detail,
        )
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

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
    user: AdminUser,
    log_repo: deps.LogRepo,
) -> RelayTriggerOut:
    """Open the gate by hand and record it as a ``granted`` event for plate
    ``MANUAL`` so the audit trail shows who opened the barrier and when.
    """
    guard = deps.get_license_guard(request.app)
    if not guard.status.valid:
        # The gate is the licensed function. Refusing here closes the obvious
        # hole in halting only the ML half of the pipeline.
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=guard.status.detail,
        )

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
    token: Annotated[str | None, Query(description="Bearer token (tarayıcı <img> için)")] = None,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_optional_bearer)
    ] = None,
) -> AuthUser:
    """Auth for the MJPEG endpoint.

    An ``<img src=...>`` tag cannot set an ``Authorization`` header, so the
    token may also arrive as a query parameter here. The desktop client uses
    the header.
    """
    raw = credentials.credentials if credentials and credentials.credentials else token
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kimlik doğrulama gerekli",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return user_from_token(raw)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


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
            else:
                idle_for += frame_budget
                if idle_for >= _STREAM_IDLE_TIMEOUT_S:
                    logger.info("Kare gelmediği için akış kapatıldı: %s", camera)
                    break
            await asyncio.sleep(frame_budget)
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
async def system_version(request: Request, _: CurrentUser) -> VersionOut:
    """The deployed version and git revision.

    Readable by any authenticated user: an operator who can see that the site
    is three commits behind can say so on the phone instead of guessing. It
    shells out to git, so it runs off the event loop.
    """
    updater = deps.get_system_updater(request)
    info = await _in_thread(updater.version)
    return VersionOut(**info.to_dict(), update_enabled=bool(updater.enabled))


@router.get(
    "/api/system/update",
    response_model=SystemUpdateOut,
    tags=["system"],
    summary="Güncelleme durumu",
)
async def system_update_status(request: Request, _: AdminUser) -> SystemUpdateOut:
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
async def system_update(request: Request, user: AdminUser) -> SystemUpdateOut:
    """Pull from the configured remote and rebuild the stack. Admin only.

    Returns **202 Accepted**, not 200: the work is detached onto its own thread
    and the response is sent before ``docker compose`` starts, because the
    rebuild terminates this process. A 202 that arrives is the strongest
    promise this endpoint can honestly make -- the client must poll
    ``GET /api/system/update`` and ``GET /api/system/version`` for the outcome.

    Nothing about *what* is pulled comes from the caller; see
    :class:`lpr.config.SystemUpdateConfig`.
    """
    updater = deps.get_system_updater(request)
    try:
        state = updater.start()
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

    logger.warning("Sistem güncellemesi '%s' tarafından tetiklendi", user.username)
    return _update_out(state, accepted=True)


@router.get(
    "/api/system/events",
    response_model=list[SystemEventOut],
    tags=["system"],
    summary="Sistem olayları",
)
async def system_events(
    request: Request,
    _: AdminUser,
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
    _: AdminUser,
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
async def export_plates(_: AdminUser, plate_repo: deps.PlateRepo) -> Response:
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
    _: CurrentUser,
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
