"""FastAPI dependency providers.

Everything shared between requests (the pipeline orchestrator, the repository
objects, the pause flag) lives on ``app.state`` and is reached through these
providers. There is no module-level mutable state, which is what makes the
test-suite able to spin up several apps in one process and override any single
dependency without leaking into the next test.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import Depends, HTTPException, Request, status

from lpr.config import Settings, get_settings

if TYPE_CHECKING:  # pragma: no cover - typing only
    from starlette.applications import Starlette

logger = logging.getLogger(__name__)

__all__ = [
    "AdminSettings",
    "LogRepo",
    "PlateRepo",
    "UserRepo",
    "get_log_repository",
    "get_pipeline",
    "get_pipeline_optional",
    "get_plate_repository",
    "get_settings_dep",
    "get_user_repository",
    "is_paused",
    "set_paused",
]


def _cached_on_state(app: "Starlette", attr: str, factory: Any) -> Any:
    """Return ``app.state.<attr>``, building it once on first use."""
    existing = getattr(app.state, attr, None)
    if existing is None:
        existing = factory()
        setattr(app.state, attr, existing)
    return existing


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def get_pipeline_optional(request: Request) -> Any | None:
    """The orchestrator, or ``None`` when it could not be built/started.

    ``/health`` uses this: the container must stay up and report *degraded*
    rather than crash-loop when the ML weights or torch are unavailable.
    """
    return getattr(request.app.state, "pipeline", None)


def get_pipeline(request: Request) -> Any:
    """The orchestrator, or HTTP 503 when the service is running degraded."""
    pipeline = get_pipeline_optional(request)
    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Görüntü işleme hattı kullanılamıyor",
        )
    return pipeline


def is_paused(app: "Starlette") -> bool:
    return bool(getattr(app.state, "paused", False))


def set_paused(app: "Starlette", value: bool) -> bool:
    """Flip the pause flag, forwarding to the orchestrator when it supports it.

    ``PipelineOrchestrator`` is not required to expose pause/resume; when it
    does not, the flag on ``app.state`` is still authoritative for the UI and
    is honoured by the event fan-out.
    """
    app.state.paused = bool(value)
    pipeline = getattr(app.state, "pipeline", None)
    method = getattr(pipeline, "pause" if value else "resume", None)
    if callable(method):
        try:
            method()
        except Exception:  # pragma: no cover - orchestrator-side failure
            logger.exception("İşlem hattı duraklatma/devam ettirme başarısız")
    return app.state.paused


# ---------------------------------------------------------------------------
# Repositories
# ---------------------------------------------------------------------------


def get_plate_repository(request: Request) -> Any:
    def factory() -> Any:
        from lpr.db import PlateRepository

        return PlateRepository()

    return _cached_on_state(request.app, "plate_repository", factory)


def get_log_repository(request: Request) -> Any:
    def factory() -> Any:
        from lpr.db import LogRepository

        return LogRepository()

    return _cached_on_state(request.app, "log_repository", factory)


def get_user_repository(request: Request) -> Any:
    def factory() -> Any:
        from lpr.db import UserRepository

        return UserRepository()

    return _cached_on_state(request.app, "user_repository", factory)


def get_settings_dep() -> Settings:
    return get_settings()


PlateRepo = Annotated[Any, Depends(get_plate_repository)]
LogRepo = Annotated[Any, Depends(get_log_repository)]
UserRepo = Annotated[Any, Depends(get_user_repository)]
AdminSettings = Annotated[Settings, Depends(get_settings_dep)]
Pipeline = Annotated[Any, Depends(get_pipeline)]
OptionalPipeline = Annotated[Any, Depends(get_pipeline_optional)]
