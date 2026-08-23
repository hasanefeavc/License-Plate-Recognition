"""Desktop client package.

Only the transport layer (:mod:`lpr.ui.client`) is re-exported eagerly; it has
no Tkinter dependency. ``LprApp``/``main`` are resolved lazily so that
importing ``lpr.ui`` on a headless machine -- or in the test-suite -- does not
drag in Tkinter, Pillow or ttkbootstrap.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from lpr.ui.client import EventStream, LprApiError, LprClient

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lpr.ui.app import LprApp, main

__all__ = ["EventStream", "LprApiError", "LprApp", "LprClient", "main"]


def __getattr__(name: str) -> Any:
    if name in {"LprApp", "main"}:
        from lpr.ui import app as _app

        return getattr(_app, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
