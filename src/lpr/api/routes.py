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
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError

from lpr.api import deps
from lpr.api.schemas import (
    CameraSourceIn,
    CameraStatusOut,
    HealthOut,
    LogOut,
    LogQuery,
    LoginIn,
    MetricsOut,
    PipelineStateOut,
    PlateIn,
    PlateListOut,
    PlateOut,
    RegisterIn,
    RelayTriggerOut,
    StatsOut,
    TokenOut,
    UserOut,
    normalize_plate,
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
    plates = await _in_thread(plate_repo.all)
    return PlateListOut(plates=list(plates), count=len(plates))


@router.post(
    "/api/plates",
    response_model=PlateOut,
    status_code=status.HTTP_201_CREATED,
    tags=["plates"],
    summary="Plaka ekle",
)
async def add_plate(payload: PlateIn, _: AdminUser, plate_repo: deps.PlateRepo) -> PlateOut:
    added = await _in_thread(plate_repo.add, payload.plate, payload.note)
    if not added:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Plaka zaten kayıtlı: {payload.plate}",
        )
    logger.info("Plaka eklendi: %s", payload.plate)
    return PlateOut(plate=payload.plate, registered=True)


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
    paused = deps.set_paused(request.app, False)
    pipeline = deps.get_pipeline_optional(request)
    return PipelineStateOut(paused=paused, running=bool(getattr(pipeline, "running", False)))


# ---------------------------------------------------------------------------
# Relay
# ---------------------------------------------------------------------------


@router.post(
    "/api/relay/trigger",
    response_model=RelayTriggerOut,
    tags=["relay"],
    summary="Bariyeri elle aç",
)
async def trigger_relay(
    request: Request,
    user: AdminUser,
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

    logger.info("Bariyer elle açıldı (kullanıcı: %s)", user.username)
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
