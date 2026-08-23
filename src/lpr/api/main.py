"""Application factory and console entry point for ``lpr-api``.

``create_app()`` builds the FastAPI application; the module-level ``app`` is
what ``uvicorn lpr.api.main:app`` imports, and ``run()`` is the
``lpr-api`` console script declared in ``pyproject.toml``.

Degraded-mode contract: if the pipeline cannot be built (missing YOLO weights,
no torch, no camera), the error is logged, ``app.state.pipeline`` stays
``None`` and the API keeps serving. ``/health`` then answers 200 with
``status="degraded"``. A container that crash-loops on a missing model file is
strictly worse than one that stays up and says what is wrong.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

from lpr.api.routes import app_version, router
from lpr.api.ws import ws_router
from lpr.config import Settings, get_settings
from lpr.logging_conf import setup_logging

logger = logging.getLogger(__name__)

__all__ = ["app", "create_app", "run"]

_TITLES: dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
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
    try:
        yield
    finally:
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
