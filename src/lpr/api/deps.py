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
    "LicenseGuardDep",
    "LogRepo",
    "MetaRepo",
    "PlateRepo",
    "UserRepo",
    "apply_license_state",
    "get_license_guard",
    "get_license_guard_dep",
    "get_log_repository",
    "get_pipeline",
    "get_pipeline_optional",
    "get_plate_repository",
    "get_settings_dep",
    "get_user_repository",
    "is_license_halted",
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
# Licence
# ---------------------------------------------------------------------------


def get_license_guard(app: "Starlette") -> Any:
    """The app's :class:`lpr.license.LicenseGuard`, built on first use."""

    def factory() -> Any:
        from lpr.license import LicenseGuard

        return LicenseGuard()

    return _cached_on_state(app, "license_guard", factory)


def get_license_guard_dep(request: Request) -> Any:
    return get_license_guard(request.app)


def is_license_halted(app: "Starlette") -> bool:
    """True while the pipeline is paused *because of* the licence.

    Tracked separately from ``app.state.paused`` so an operator's manual
    pause and a licence halt cannot cancel each other out: releasing the
    licence hold must not resume a pipeline the operator deliberately paused,
    and resuming by hand must not clear a licence hold.
    """
    return bool(getattr(app.state, "license_halted", False))


def apply_license_state(app: "Starlette", valid: bool) -> bool:
    """Halt or release the pipeline to match the licence state.

    Returns whether the pipeline is currently held for licence reasons. Safe
    to call on every check: the transitions are idempotent, and it never
    resumes a pipeline that an operator paused by hand.
    """
    halted = is_license_halted(app)

    if not valid:
        app.state.license_halted = True
        if not halted:
            logger.error("Lisans geçersiz: görüntü işleme durduruluyor")
        set_paused(app, True)
        return True

    app.state.license_halted = False
    if halted:
        logger.info("Lisans geçerli: görüntü işleme devam ediyor")
        # Only the licence hold is released here. If the operator had also
        # pressed pause, ``manual_paused`` keeps the pipeline down.
        if not bool(getattr(app.state, "manual_paused", False)):
            set_paused(app, False)
    return False


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


def get_meta_repository(request: Request) -> Any:
    """Key/value store for runtime settings an admin can change (capacity)."""

    def factory() -> Any:
        from lpr.db import SystemMetaRepository

        return SystemMetaRepository()

    return _cached_on_state(request.app, "meta_repository", factory)


def get_settings_dep() -> Settings:
    return get_settings()


LicenseGuardDep = Annotated[Any, Depends(get_license_guard_dep)]
PlateRepo = Annotated[Any, Depends(get_plate_repository)]
LogRepo = Annotated[Any, Depends(get_log_repository)]
UserRepo = Annotated[Any, Depends(get_user_repository)]
MetaRepo = Annotated[Any, Depends(get_meta_repository)]
AdminSettings = Annotated[Settings, Depends(get_settings_dep)]
Pipeline = Annotated[Any, Depends(get_pipeline)]
OptionalPipeline = Annotated[Any, Depends(get_pipeline_optional)]
