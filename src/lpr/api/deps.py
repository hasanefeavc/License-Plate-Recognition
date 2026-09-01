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
    "get_model_assets",
    "get_pipeline",
    "get_pipeline_optional",
    "get_plate_repository",
    "get_settings_dep",
    "get_system_event_repository",
    "get_system_updater",
    "get_system_updater_for",
    "get_user_repository",
    "is_license_halted",
    "is_paused",
    "set_paused",
]


def _cached_on_state(app: Starlette, attr: str, factory: Any) -> Any:
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


def get_model_assets(app: Starlette) -> Any:
    """What the model files on this box are, cached on ``app.state``.

    Computed at start-up by the lifespan handler; recomputed here if something
    asks before then (a ``TestClient`` built without ``with``, for instance).
    Reading the filesystem is cheap, and answering "which file is missing?"
    with "I do not know" would defeat the purpose of the endpoint.
    """

    def factory() -> Any:
        from lpr.model_assets import describe_assets

        return describe_assets(get_settings())

    return _cached_on_state(app, "model_assets", factory)


def pipeline_unavailable_detail(app: Starlette) -> str:
    """Why the pipeline is not there, in one sentence an operator can act on.

    "Görüntü işleme hattı kullanılamıyor" is true and useless: it is the same
    message whether torch is missing, a model file is absent or a camera is
    unplugged. The recorded start-up error and the model-asset status are both
    already on ``app.state``, so the 503 can name the actual gap instead of
    sending the operator to the container logs.
    """
    parts = ["Görüntü işleme hattı kullanılamıyor"]
    error = getattr(app.state, "pipeline_error", None)
    if error:
        parts.append(str(error))
    try:
        assets = get_model_assets(app)
        if not assets.ready:
            parts.append(assets.detail)
    except Exception:  # pragma: no cover - defensive; a 503 must not 500
        logger.debug("Model varlık durumu okunamadı", exc_info=True)
    return " -- ".join(parts)


def get_pipeline(request: Request) -> Any:
    """The orchestrator, or HTTP 503 when the service is running degraded."""
    pipeline = get_pipeline_optional(request)
    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=pipeline_unavailable_detail(request.app),
        )
    return pipeline


def is_paused(app: Starlette) -> bool:
    return bool(getattr(app.state, "paused", False))


def set_paused(app: Starlette, value: bool) -> bool:
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


def get_license_guard(app: Starlette) -> Any:
    """The app's :class:`lpr.license.LicenseGuard`, built on first use."""

    def factory() -> Any:
        from lpr.license import LicenseGuard

        return LicenseGuard()

    return _cached_on_state(app, "license_guard", factory)


def get_license_guard_dep(request: Request) -> Any:
    return get_license_guard(request.app)


def is_license_halted(app: Starlette) -> bool:
    """True while the pipeline is paused *because of* the licence.

    Tracked separately from ``app.state.paused`` so an operator's manual
    pause and a licence halt cannot cancel each other out: releasing the
    licence hold must not resume a pipeline the operator deliberately paused,
    and resuming by hand must not clear a licence hold.
    """
    return bool(getattr(app.state, "license_halted", False))


def apply_license_state(app: Starlette, valid: bool) -> bool:
    """Record the deployment licence state. **No longer halts the pipeline.**

    The deployment licence used to pause recognition and refuse the gate when
    it lapsed. Access control now lives entirely in the per-user model
    (:mod:`lpr.user_license`): administrators are unlimited, operators hold
    their own keys, and neither is affected by the installation-wide licence.

    The state is still tracked and still reported by ``GET /api/license``,
    because the desktop client polls it and an installer wants to see it. What
    it no longer does is stop a working barrier -- an expiry that locks an
    administrator out of their own site is not a commercial control, it is an
    outage.

    Always returns ``False`` (never held for licence reasons); kept as a
    function, and still called, so re-enabling the hold is one edit here rather
    than a hunt through the lifespan and the routes.
    """
    app.state.license_halted = False
    if not valid:
        logger.warning(
            "Dağıtım lisansı geçersiz (görüntü işleme etkilenmiyor; "
            "erişim kontrolü kullanıcı lisanslarında)"
        )
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


def get_system_updater_for(app: Starlette) -> Any:
    """The app's :class:`lpr.updater.SystemUpdater`, built on first use.

    One instance per app, because it owns the single-flight lock that keeps two
    admins from racing a rebuild against a checkout. Building it per-request
    would give every caller its own lock and defeat the point -- and the
    nightly scheduler has to share that same lock with the HTTP handlers, which
    is why this takes an ``app`` rather than a ``Request``.
    """

    def factory() -> Any:
        from lpr.updater import SystemUpdater

        return SystemUpdater(get_settings())

    return _cached_on_state(app, "system_updater", factory)


def get_system_updater(request: Request) -> Any:
    return get_system_updater_for(request.app)


def get_system_event_repository(request: Request) -> Any:
    """Operational audit trail (OTA updates), separate from the plate log."""

    def factory() -> Any:
        from lpr.db import SystemEventRepository

        return SystemEventRepository()

    return _cached_on_state(request.app, "system_event_repository", factory)


def get_model_assets_dep(request: Request) -> Any:
    return get_model_assets(request.app)


def get_settings_dep() -> Settings:
    return get_settings()


LicenseGuardDep = Annotated[Any, Depends(get_license_guard_dep)]
PlateRepo = Annotated[Any, Depends(get_plate_repository)]
LogRepo = Annotated[Any, Depends(get_log_repository)]
UserRepo = Annotated[Any, Depends(get_user_repository)]
MetaRepo = Annotated[Any, Depends(get_meta_repository)]
AdminSettings = Annotated[Settings, Depends(get_settings_dep)]
ModelAssetsDep = Annotated[Any, Depends(get_model_assets_dep)]
SystemUpdaterDep = Annotated[Any, Depends(get_system_updater)]
SystemEventRepo = Annotated[Any, Depends(get_system_event_repository)]
Pipeline = Annotated[Any, Depends(get_pipeline)]
OptionalPipeline = Annotated[Any, Depends(get_pipeline_optional)]


def get_login_limiter(request: Any) -> Any:
    """The process-wide login rate limiter, created on first use.

    Held on ``app.state`` rather than as a module global so a test app and the
    real one never share lockout state -- one test locking an account would
    otherwise leak into every test after it.
    """
    from lpr.api.ratelimit import LoginLimiter

    app = request.app
    limiter = getattr(app.state, "login_limiter", None)
    if limiter is None:
        limiter = LoginLimiter()
        app.state.login_limiter = limiter
    return limiter
