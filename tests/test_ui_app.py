"""Tests for the desktop client's event routing.

No real Tk widgets and no display: the window, the views and the event stream
are all stubs. What is under test is the *discipline* -- that stream events
reach widgets only through ``root.after``, on the Tk thread, and that one bad
event cannot take the pump down with it.
"""

from __future__ import annotations

import queue
from typing import Any

import pytest

pytest.importorskip("tkinter")

from lpr.ui.app import LprApp, _activity_text  # noqa: E402


class StubRoot:
    """Records ``after`` calls instead of scheduling them."""

    def __init__(self) -> None:
        self.scheduled: list[tuple[int, Any, tuple[Any, ...]]] = []

    def after(self, delay: int, callback: Any = None, *args: Any) -> str:
        self.scheduled.append((delay, callback, args))
        return "id"

    def run_scheduled(self) -> None:
        """Run every zero-delay callback, as the Tk main loop would."""
        for delay, callback, args in list(self.scheduled):
            if delay == 0 and callback is not None:
                callback(*args)


class StubLogPane:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def add_event(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class StubPane:
    def __init__(self) -> None:
        self.images: list[Any] = []
        self.connected: list[bool] = []

    def set_image(self, image: Any) -> None:
        self.images.append(image)

    def set_connected(self, connected: bool, fps: float = 0.0) -> None:
        self.connected.append(connected)

    def clear_image(self) -> None:
        self.images.clear()


class StubView:
    def __init__(self) -> None:
        self.log_pane = StubLogPane()
        self.activity: list[str] = []
        self.cameras: list[Any] = []
        self.banners: list[tuple[bool, str]] = []
        self.uptime: list[str] = []
        self.panes: dict[str, StubPane] = {"entry": StubPane(), "exit": StubPane()}
        self.license_texts: list[tuple[str, bool]] = []
        self.license_locks: list[tuple[bool, str]] = []

    def set_license_text(self, text: str, ok: bool = True) -> None:
        self.license_texts.append((text, ok))

    def set_license_locked(self, locked: bool, message: str = "") -> None:
        self.license_locks.append((locked, message))

    def set_activity(self, text: str) -> None:
        self.activity.append(text)

    def set_cameras(self, cameras: Any) -> None:
        self.cameras.append(cameras)

    def set_banner(self, visible: bool, message: str = "") -> None:
        self.banners.append((visible, message))

    def set_uptime(self, text: str) -> None:
        self.uptime.append(text)


class StubStream:
    def __init__(self, messages: list[dict[str, Any]]) -> None:
        self._messages = list(messages)

    def poll(self, max_items: int = 500) -> list[dict[str, Any]]:
        drained, self._messages = self._messages, []
        return drained


def make_app(messages: list[dict[str, Any]] | None = None) -> tuple[LprApp, StubRoot, StubView]:
    """An LprApp with only the attributes the drain path touches."""
    app = object.__new__(LprApp)
    root = StubRoot()
    view = StubView()
    app.root = root  # type: ignore[attr-defined]
    app.main_view = view  # type: ignore[attr-defined]
    app._ui_queue = queue.Queue()  # type: ignore[attr-defined]
    app._events = StubStream(messages or [])  # type: ignore[attr-defined]
    app._started_at = 0.0  # type: ignore[attr-defined]
    app._last_uptime_second = -1  # type: ignore[attr-defined]
    app._license = {}  # type: ignore[attr-defined]
    app._license_locked = False  # type: ignore[attr-defined]
    app._license_dialog = None  # type: ignore[attr-defined]
    return app, root, view


# ---------------------------------------------------------------------------
# Thread discipline
# ---------------------------------------------------------------------------


def test_stream_events_are_dispatched_through_after_zero() -> None:
    """Widgets are never written to inline: every event is its own Tk task."""
    messages = [
        {"type": "event", "data": {"plate": "34ABC123", "action": "granted"}},
        {"type": "event", "data": {"plate": "06XYZ42", "action": "denied"}},
    ]
    app, root, view = make_app(messages)

    app._drain()

    zero_delay = [call for call in root.scheduled if call[0] == 0]
    assert len(zero_delay) == 2, "one after(0, ...) per event"
    assert all(call[1] == app._dispatch_event for call in zero_delay)
    # Nothing has touched a widget yet -- the callbacks have only been queued.
    assert view.log_pane.events == []

    root.run_scheduled()
    assert [e["plate"] for e in view.log_pane.events] == ["34ABC123", "06XYZ42"]


def test_drain_reschedules_itself() -> None:
    app, root, _view = make_app()
    app._drain()
    assert any(delay > 0 for delay, _cb, _args in root.scheduled), "pump must keep running"


def test_a_failing_event_does_not_kill_the_pump() -> None:
    class Exploding(StubView):
        def set_activity(self, text: str) -> None:
            raise RuntimeError("widget is gone")

    app, root, _ = make_app()
    app.main_view = Exploding()  # type: ignore[attr-defined]
    app._dispatch_event({"type": "telemetry", "data": {"kind": "read", "plate": "34ABC123"}})
    # Swallowed: the next event is still processed.
    app.main_view = StubView()  # type: ignore[attr-defined]
    app._dispatch_event({"type": "event", "data": {"plate": "34ABC123"}})
    assert app.main_view.log_pane.events  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Routing by message type
# ---------------------------------------------------------------------------


def test_decisions_go_to_the_log_table() -> None:
    app, _root, view = make_app()
    app._handle_event({"type": "event", "data": {"plate": "34ABC123", "action": "granted"}})
    assert view.log_pane.events == [{"plate": "34ABC123", "action": "granted"}]


def test_telemetry_never_reaches_the_log_table() -> None:
    """Reads and votes are live activity, not recorded decisions."""
    app, _root, view = make_app()
    app._handle_event({"type": "telemetry", "data": {"kind": "read", "plate": "34ABC123"}})
    assert view.log_pane.events == []
    assert view.activity and "34ABC123" in view.activity[0]


def test_camera_status_updates_the_panes() -> None:
    app, _root, view = make_app()
    cameras = [{"role": "entry", "connected": True, "fps": 12.5}]
    app._handle_event({"type": "camera_status", "cameras": cameras})
    assert view.cameras == [cameras]


def test_disconnect_and_reconnect_toggle_the_banner() -> None:
    app, _root, view = make_app()
    app._handle_event({"type": "status", "connected": False})
    app._handle_event({"type": "status", "connected": True})
    assert [visible for visible, _ in view.banners] == [True, False]


def test_malformed_payloads_are_ignored() -> None:
    app, _root, view = make_app()
    for message in (
        {"type": "event"},
        {"type": "event", "data": "not-a-dict"},
        {"type": "telemetry", "data": None},
        {"type": "camera_status", "cameras": "nope"},
        {"type": "unknown-to-this-build"},
        {},
    ):
        app._handle_event(message)
    assert view.log_pane.events == []
    assert view.cameras == []


def test_events_are_dropped_when_no_view_is_mounted() -> None:
    """Messages can arrive before login completes; they must not crash."""
    app, _root, _view = make_app()
    app.main_view = None  # type: ignore[attr-defined]
    app._handle_event({"type": "event", "data": {"plate": "34ABC123"}})


# ---------------------------------------------------------------------------
# Licence lockdown
# ---------------------------------------------------------------------------


def _watch_license_dialog(app: LprApp) -> list[int]:
    """Replace ``open_license`` so no real Toplevel is built."""
    opened: list[int] = []
    app.open_license = lambda: opened.append(1)  # type: ignore[method-assign]
    return opened


def test_an_invalid_licence_freezes_the_view_and_asks_for_a_key() -> None:
    app, _root, view = make_app()
    opened = _watch_license_dialog(app)

    app._apply_license({"valid": False, "reason": "expired", "detail": "Lisans süresi doldu."})

    assert app._license_locked is True
    assert view.license_locks == [(True, "Lisans süresi doldu.")]
    assert opened == [1], "the operator must be prompted for a new key"


def test_a_frozen_view_renders_no_further_frames() -> None:
    app, _root, view = make_app()
    _watch_license_dialog(app)
    app._apply_license({"valid": False, "reason": "expired", "detail": "bitti"})

    app._handle("frame", ("entry", object()))

    assert view.panes["entry"].images == []


def test_a_valid_licence_thaws_the_view() -> None:
    app, _root, view = make_app()
    _watch_license_dialog(app)
    app._apply_license({"valid": False, "reason": "expired", "detail": "bitti"})
    view.license_locks.clear()

    app._apply_license(
        {"valid": True, "reason": "ok", "detail": "Lisans geçerli.", "days_remaining": 12.0}
    )

    assert app._license_locked is False
    assert view.license_locks == [(False, "Lisans geçerli.")]
    assert view.license_texts[-1][1] is True

    marker = object()
    app._handle("frame", ("entry", marker))
    assert view.panes["entry"].images == [marker]


def test_the_lock_state_is_not_reapplied_on_every_poll() -> None:
    """Two identical polls must not re-open the dialog."""
    app, _root, view = make_app()
    opened = _watch_license_dialog(app)
    payload = {"valid": False, "reason": "expired", "detail": "bitti"}

    app._apply_license(dict(payload))
    app._apply_license(dict(payload))

    assert opened == [1]
    assert len(view.license_locks) == 1


def test_a_pushed_licence_event_locks_immediately() -> None:
    """The WebSocket path, so a site locks without waiting for a poll."""
    app, _root, view = make_app()
    _watch_license_dialog(app)

    app._handle_event(
        {"type": "license", "license": {"valid": False, "reason": "expired", "detail": "bitti"}}
    )

    assert view.license_locks == [(True, "bitti")]


def test_a_rejected_key_leaves_the_view_locked() -> None:
    app, _root, view = make_app()
    _watch_license_dialog(app)
    app._apply_license({"valid": False, "reason": "expired", "detail": "bitti"})
    view.license_locks.clear()

    app._handle("license_result", (False, "[400] Lisans anahtarı geçersiz.", None))

    assert app._license_locked is True
    assert view.license_locks == []


def test_an_accepted_key_unlocks_the_view() -> None:
    app, _root, view = make_app()
    _watch_license_dialog(app)
    app._apply_license({"valid": False, "reason": "expired", "detail": "bitti"})

    app._handle(
        "license_result",
        (True, "", {"valid": True, "reason": "ok", "detail": "Lisans geçerli."}),
    )

    assert app._license_locked is False
    assert view.license_locks[-1][0] is False


# ---------------------------------------------------------------------------
# Activity formatting
# ---------------------------------------------------------------------------


def test_activity_text_for_a_read() -> None:
    text = _activity_text(
        {"kind": "read", "camera": "entry", "plate": "34ABC123", "confidence": 0.91}
    )
    assert "entry" in text and "34ABC123" in text and "91%" in text


def test_activity_text_for_vote_progress_and_confirmation() -> None:
    progress = _activity_text(
        {"kind": "vote", "camera": "exit", "plate": "34ABC123", "votes": 2, "needed": 3}
    )
    assert "2/3" in progress and "exit" in progress

    confirmed = _activity_text(
        {
            "kind": "vote",
            "camera": "exit",
            "plate": "34ABC123",
            "votes": 3,
            "needed": 3,
            "confirmed": True,
        }
    )
    assert "onaylandı" in confirmed


def test_activity_text_tolerates_missing_fields() -> None:
    assert _activity_text({})
    assert _activity_text({"kind": "vote"})
