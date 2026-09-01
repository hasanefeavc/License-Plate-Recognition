"""HTTP/WebSocket layer of the LPR service.

Attributes are resolved lazily so that merely importing ``lpr.api`` -- which
``lpr.api.routes`` itself does, to reach ``lpr.api.deps`` -- does not pull in
FastAPI or build the application as a side effect.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastapi import FastAPI

    from lpr.api.main import create_app, run

__all__ = ["create_app", "get_app", "run"]


def get_app() -> FastAPI:
    """Return the module-level application instance."""
    from lpr.api.main import app

    return app


def __getattr__(name: str) -> Any:
    if name in {"create_app", "run"}:
        from lpr.api import main as _main

        return getattr(_main, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
