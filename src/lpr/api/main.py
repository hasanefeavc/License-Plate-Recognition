"""Application factory and console entry point for ``lpr-api``.

``create_app()`` builds the FastAPI application; the module-level ``app`` is
what ``uvicorn lpr.api.main:app`` imports, and ``run()`` is the
``lpr-api`` console script declared in ``pyproject.toml``.

Degraded-mode contract: if the pipeline cannot be built (missing YOLO weights,
no torch, no camera), the error is logged, ``app.state.pipeline`` stays
``None`` and the API keeps serving. ``/health`` then answers 200 with
``status="degraded"``. A container that crash-loops on a missing model file is
strictly worse than one that stays up and says what is wrong.

The same contract covers the licence (:mod:`lpr.license`): an expired or
missing key never stops the process. A background task re-checks it on an
interval and pauses the orchestrator -- no detection, no OCR, no relay --
while leaving the HTTP API up, so the operator can read *why* it stopped and
``POST /api/license`` a new key to bring it straight back.

The browser dashboard in ``web/`` is mounted at ``/web`` and is a *client* of
this API exactly like the Tkinter one -- it adds no endpoints and gets no
privileges of its own. A missing ``web/`` directory follows the same
degraded-mode contract as everything else: it is logged and the API keeps
serving, because a headless deployment that never opens a browser should not
fail to start over a missing HTML file.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from lpr.api import deps
from lpr.api.routes import app_version, router
from lpr.api.ws import ws_router
from lpr.config import Settings, get_settings
from lpr.logging_conf import setup_logging

logger = logging.getLogger(__name__)

__all__ = ["LICENSE_CHECK_INTERVAL_S", "WEB_MOUNT_PATH", "app", "create_app", "run"]

#: How often the licence is re-verified while the service runs. A licence is
#: a date, not a revocation list, so this only has to be fine-grained enough
#: that a site does not keep processing for long after midnight of its expiry
#: -- and coarse enough to be free.
LICENSE_CHECK_INTERVAL_S = 60.0

#: Where the browser dashboard is served from. ``/`` redirects here.
WEB_MOUNT_PATH = "/web"

_TITLES: dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    409: "Conflict",
    422: "Unprocessable Entity",
    500: "Internal Server Error",
    501: "Not Implemented",
    503: "Service Unavailable",
}


def _error_response(
    status_code: int,
    detail: Any,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Uniform error envelope: ``{"error": {"status", "title", "detail"}}``."""
    body = {
        "error": {
            "status": status_code,
            "title": _TITLES.get(status_code, "Error"),
            "detail": detail,
        }
    }
    return JSONResponse(status_code=status_code, content=body, headers=headers)


def _install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        headers = getattr(exc, "headers", None)
        return _error_response(exc.status_code, exc.detail, headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Pydantic's error list is safe to echo (field names + messages) but is
        # normalised to strings so no exception objects reach the wire.
        problems = [
            {
                "loc": [str(part) for part in err.get("loc", ())],
                "msg": str(err.get("msg", "")),
                "type": str(err.get("type", "")),
            }
            for err in exc.errors()
        ]
        return _error_response(422, problems)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Log the traceback server-side; the client only ever sees a generic
        # message. Stack traces are an information leak.
        logger.exception("İşlenmeyen hata: %s %s", request.method, request.url.path)
        return _error_response(500, "Beklenmeyen bir sunucu hatası oluştu")


def _resolve_web_dir(settings: Settings) -> Path | None:
    """Locate the ``web/`` directory, or None if this build has no web UI.

    Tried in order: the configured path as given (absolute, or relative to the
    working directory -- ``/app`` in the container), then relative to the repo
    root inferred from this file. The second candidate is what makes
    ``uvicorn lpr.api.main:app`` work from any directory during development.
    """
    configured = str(settings.app.web_dir or "").strip()
    if not configured:
        return None

    candidates = [Path(configured).expanduser()]
    if not candidates[0].is_absolute():
        # src/lpr/api/main.py -> parents[3] is the repo (or image) root.
        candidates.append(Path(__file__).resolve().parents[3] / configured)

    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    return None


def _mount_web_ui(app: FastAPI, settings: Settings) -> None:
    """Serve the browser dashboard at ``/web``, with ``/`` redirecting to it.

    Mounted *after* the API routers so it can never shadow them: Starlette
    matches routes in registration order, and this mount only ever sees paths
    the API did not claim.
    """
    directory = _resolve_web_dir(settings)
    if directory is None:
        logger.info(
            "Web arayüzü bulunamadı (app.web_dir=%r); yalnızca API sunuluyor",
            settings.app.web_dir,
        )
        return

    app.mount(
        WEB_MOUNT_PATH,
        StaticFiles(directory=directory, html=True),
        name="web",
    )

    @app.get("/", include_in_schema=False)
    async def _web_root() -> RedirectResponse:
        """Send a bare host visit to the dashboard."""
        return RedirectResponse(url=f"{WEB_MOUNT_PATH}/")

    app.state.web_dir = directory
    logger.info("Web arayüzü sunuluyor: %s -> %s", WEB_MOUNT_PATH, directory)


def _start_pipeline(app: FastAPI, settings: Settings) -> None:
    """Build and start the orchestrator, tolerating a total failure."""
    try:
        from lpr.pipeline.factory import build_pipeline

        pipeline = build_pipeline(settings=settings)
        pipeline.start()
    except Exception as exc:
        # ImportError (no torch), FileNotFoundError (no weights), RuntimeError
        # (no camera) -- all of them land here and all of them are survivable.
        logger.error("Görüntü işleme hattı başlatılamadı: %s", exc, exc_info=True)
        app.state.pipeline = None
        app.state.pipeline_error = str(exc)
        return

    app.state.pipeline = pipeline
    app.state.pipeline_error = None
    logger.info("Görüntü işleme hattı başlatıldı")


def _stop_pipeline(app: FastAPI) -> None:
    pipeline = getattr(app.state, "pipeline", None)
    if pipeline is None:
        return
    try:
        pipeline.stop(timeout=5.0)
        logger.info("Görüntü işleme hattı durduruldu")
    except Exception:
        logger.exception("Görüntü işleme hattı durdurulurken hata")
    finally:
        app.state.pipeline = None


async def _broadcast_license(status: Any, halted: bool) -> None:
    """Push the licence state to every connected client immediately.

    The desktop client also polls, but a site that expires while somebody is
    watching the screen should lock right then, not up to a poll interval
    later.
    """
    try:
        from lpr.api.ws import manager as ws_manager

        await ws_manager.broadcast(
            {"type": "license", "license": {**status.to_dict(), "pipeline_halted": halted}}
        )
    except Exception:  # pragma: no cover - the socket layer is optional
        logger.debug("Lisans durumu yayınlanamadı", exc_info=True)


async def _check_license(app: FastAPI, *, announce: bool = True) -> Any:
    """Re-verify the licence and align the pipeline with the result.

    The verification itself (signature + two SQLite reads) runs in a worker
    thread so the event loop is never blocked, and every failure mode is
    swallowed: a licence check that throws must not take the API down.
    """
    guard = deps.get_license_guard(app)
    previous = guard.status.valid
    status = await asyncio.to_thread(guard.refresh)
    halted = deps.apply_license_state(app, status.valid)
    if announce and previous != status.valid:
        await _broadcast_license(status, halted)
    return status


async def _license_watchdog(app: FastAPI, interval: float) -> None:
    """Re-check the licence forever, on ``interval``. Never raises out."""
    while True:
        try:
            await asyncio.sleep(interval)
            await _check_license(app)
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            raise
        except Exception:  # pragma: no cover - defensive
            logger.exception("Lisans denetimi başarısız")


def _start_nightly_update(app: FastAPI, settings: Settings) -> "asyncio.Task[None] | None":
    """Start the nightly OTA check, or return None when it is switched off.

    Returning ``None`` rather than starting a task that immediately does
    nothing keeps the "no scheduler is running" case visible in a task dump,
    which is what you want to check first when an update did not happen
    overnight.
    """
    cfg = getattr(settings, "system_update", None)
    if not bool(getattr(cfg, "nightly_check", False)):
        return None
    if not bool(getattr(cfg, "enabled", False)):
        # The job would refuse every night anyway; say so once at startup
        # instead of writing an audit row about it every day.
        logger.info("Gecelik güncelleme denetimi atlandı: system_update.enabled kapalı")
        return None

    try:
        from lpr.db import SystemEventRepository
        from lpr.scheduler import NightlyUpdateJob, nightly_update_loop

        job = NightlyUpdateJob(
            updater=deps.get_system_updater_for(app),
            events=SystemEventRepository(),
            auto_update=bool(getattr(cfg, "auto_update", False)),
        )
        hour = int(getattr(cfg, "check_hour", 3))
        minute = int(getattr(cfg, "check_minute", 0))
    except Exception:
        logger.exception("Gecelik güncelleme görevi kurulamadı")
        return None

    logger.info(
        "Gecelik güncelleme denetimi %02d:%02d için planlandı (otomatik kurulum=%s)",
        hour,
        minute,
        job.auto_update,
    )
    return asyncio.create_task(
        nightly_update_loop(job, hour, minute), name="nightly-update"
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start/stop everything the request handlers depend on."""
    settings: Settings = app.state.settings
    setup_logging(
        level=settings.app.log_level,
        json=settings.app.headless,
        data_dir=settings.paths.data_dir,
    )
    logger.info("lpr-api %s başlatılıyor", app_version())

    try:
        from lpr.db import init_db

        init_db()
        logger.info("Veritabanı hazır: %s", settings.paths.database)
    except Exception:
        # A broken database is fatal for the useful endpoints but /health must
        # still answer, so this is logged rather than raised.
        logger.exception("Veritabanı başlatılamadı")

    _start_pipeline(app, settings)

    # Checked *after* the pipeline is built so an unlicensed site starts up
    # fully -- cameras connected, live view working -- and is then held
    # paused, which is what makes entering a new key an instant recovery.
    try:
        status = await _check_license(app, announce=False)
        logger.info("Lisans durumu: %s", status.detail)
    except Exception:  # pragma: no cover - defensive
        logger.exception("Başlangıç lisans denetimi başarısız")
        deps.apply_license_state(app, False)

    watchdog = asyncio.create_task(
        _license_watchdog(app, LICENSE_CHECK_INTERVAL_S), name="license-watchdog"
    )
    nightly = _start_nightly_update(app, settings)
    try:
        yield
    finally:
        for task in (watchdog, nightly):
            if task is None:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        _stop_pipeline(app)
        logger.info("lpr-api kapatıldı")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application.

    Nothing expensive happens here -- database and pipeline start-up live in
    the lifespan handler, so importing this module (as the test-suite and
    ``uvicorn --reload`` both do) stays cheap and side-effect free.
    """
    resolved = settings or get_settings()

    app = FastAPI(
        title="LPR API",
        description=(
            "Plaka tanıma servisi: canlı görüntü, olay akışı, plaka yönetimi "
            "ve bariyer kontrolü."
        ),
        version=app_version(),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Everything shared lives on app.state -- see lpr.api.deps.
    app.state.settings = resolved
    app.state.pipeline = None
    app.state.pipeline_error = None
    app.state.paused = False
    #: Set by the operator's pause button; kept apart from the licence hold so
    #: neither can silently undo the other. See ``deps.apply_license_state``.
    app.state.manual_paused = False
    app.state.license_halted = False
    app.state.license_guard = None
    app.state.web_dir = None

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(resolved.api.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _install_exception_handlers(app)
    app.include_router(router)
    app.include_router(ws_router)
    _mount_web_ui(app, resolved)
    return app


app = create_app()


def run() -> None:
    """``lpr-api`` console-script entry point."""
    import uvicorn

    settings = get_settings()
    setup_logging(
        level=settings.app.log_level,
        json=settings.app.headless,
        data_dir=settings.paths.data_dir,
    )
    logger.info("HTTP sunucusu dinliyor: %s:%s", settings.api.host, settings.api.port)
    uvicorn.run(
        "lpr.api.main:app",
        host=settings.api.host,
        port=settings.api.port,
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":  # pragma: no cover
    run()
