"""Hardware drivers (gate relay).

    from lpr.hardware import build_relay

    relay = build_relay()   # SerialRelay or MockRelay, never raises
    relay.trigger()         # returns immediately, pulse runs on a worker thread
"""

from __future__ import annotations

from lpr.hardware.relay import MockRelay, SerialRelay, build_relay

__all__ = ["MockRelay", "SerialRelay", "build_relay"]
