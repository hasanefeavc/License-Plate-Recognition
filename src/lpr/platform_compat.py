"""All ``sys.platform`` / OS-specific branching lives in this module.

No other module in this package should import ``ctypes.windll``, branch on
``sys.platform``, or otherwise special-case Windows vs. Linux vs. macOS.
Centralising it here means the rest of the codebase can stay portable and
this is the only file that needs review when a new OS quirk shows up.

Every function here is defensive: nothing raises just because a platform
feature is unavailable (missing pyserial, no DISPLAY, non-Windows ctypes,
...). Callers get a safe fallback value instead of an exception.
"""

from __future__ import annotations

import os
import sys

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"


def hide_file(path: str) -> bool:
    """Best-effort hide a file from casual view.

    On Windows this sets the FILE_ATTRIBUTE_HIDDEN flag via the Win32 API.
    On POSIX platforms hiding a file conventionally just means prefixing its
    name with a dot, which is a naming decision for the caller to make, not
    something this function can do to an already-named path -- so this is a
    documented no-op that always returns False there.

    Never raises. Returns True only on a confirmed successful Windows call.
    """
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        FILE_ATTRIBUTE_HIDDEN = 0x02
        result = ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)  # type: ignore[attr-defined]
        return bool(result)
    except Exception:
        return False


def default_serial_port() -> str | None:
    """Return a plausible default serial device path for this OS.

    This is a guess used only as a starting point (e.g. for a config
    default); callers that need certainty should use ``list_serial_ports``
    and let the user or a probe confirm connectivity.
    """
    if IS_WINDOWS:
        return "COM3"
    if IS_LINUX:
        for candidate in ("/dev/ttyUSB0", "/dev/ttyACM0", "/dev/serial0"):
            if os.path.exists(candidate):
                return candidate
        return None
    return None


def list_serial_ports() -> list[str]:
    """Enumerate available serial ports, or [] if pyserial is unavailable."""
    try:
        from serial.tools import list_ports
    except Exception:
        return []
    try:
        return [p.device for p in list_ports.comports()]
    except Exception:
        return []


def default_camera_backend() -> int:
    """Return the preferred OpenCV VideoCapture backend for this OS.

    ``cv2`` is imported lazily inside this function so that importing
    ``platform_compat`` (or anything that transitively imports it, like
    ``config``) never pulls in OpenCV as a side effect.
    """
    import cv2

    if IS_WINDOWS:
        return cv2.CAP_DSHOW
    if IS_LINUX:
        return cv2.CAP_V4L2
    return cv2.CAP_ANY


def in_container() -> bool:
    """True when running inside a Docker/Kubernetes container."""
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return "docker" in content or "kubepods" in content
    except OSError:
        return False


def supports_gui() -> bool:
    """Best-effort check for whether a display is available for Tkinter/cv2 GUI."""
    if in_container() and not os.environ.get("DISPLAY"):
        return False
    if IS_WINDOWS:
        return True
    if IS_MACOS:
        return True
    if IS_LINUX:
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return False
