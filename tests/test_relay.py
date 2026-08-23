"""Tests for the gate relay.

The headline property: :meth:`SerialRelay.trigger` must return in far less
time than the pulse it requests. The legacy app slept for the whole pulse on
the capture thread, blinding both cameras for a second every time the barrier
opened.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from lpr.contracts import Relay
from lpr.hardware.relay import MockRelay, SerialRelay, build_relay


class FakeSerial:
    """Minimal pyserial stand-in that records the bytes written."""

    def __init__(self, port: str, baud: int, timeout: int = 1, write_timeout: int = 2) -> None:
        self.port = port
        self.baud = baud
        self.is_open = True
        self.written: list[bytes] = []
        self._lock = threading.Lock()

    def write(self, payload: bytes) -> int:
        with self._lock:
            self.written.append(payload)
        return len(payload)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.is_open = False


class FakeSerialModule:
    """Stands in for the ``serial`` module inside ``lpr.hardware.relay``."""

    class SerialException(Exception):
        pass

    def __init__(self, fail_times: int = 0) -> None:
        self.fail_times = fail_times
        self.opened: list[FakeSerial] = []

    def Serial(  # noqa: N802 - mirrors pyserial's own capitalised name
        self, port: str, baud: int, timeout: int = 1, write_timeout: int = 2
    ) -> FakeSerial:
        if self.fail_times > 0:
            self.fail_times -= 1
            raise self.SerialException(f"cannot open {port}")
        instance = FakeSerial(port, baud, timeout, write_timeout)
        self.opened.append(instance)
        return instance


@pytest.fixture
def fake_serial(monkeypatch: pytest.MonkeyPatch) -> FakeSerialModule:
    module = FakeSerialModule()
    monkeypatch.setattr("lpr.hardware.relay._import_serial", lambda: module)
    return module


def _wait_for(predicate: Any, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


# ---------------------------------------------------------------------------
# The non-blocking property
# ---------------------------------------------------------------------------


def test_trigger_returns_far_faster_than_the_pulse(fake_serial) -> None:
    pulse_ms = 500
    relay = SerialRelay("/dev/fake", 9600, "A", "a", pulse_ms=pulse_ms)
    try:
        started = time.monotonic()
        relay.trigger()
        elapsed = time.monotonic() - started

        assert elapsed < pulse_ms / 1000.0 / 5, (
            f"trigger() took {elapsed * 1000:.1f}ms; it must not wait for the "
            f"{pulse_ms}ms pulse (that was the legacy bug)"
        )

        assert _wait_for(lambda: relay.pulses_sent == 1)
        assert fake_serial.opened[0].written == [b"A", b"a"]
    finally:
        relay.close()


def test_many_triggers_return_immediately(fake_serial) -> None:
    relay = SerialRelay("/dev/fake", 9600, pulse_ms=200)
    try:
        started = time.monotonic()
        for _ in range(50):
            relay.trigger()
        elapsed = time.monotonic() - started
        assert elapsed < 0.2, "50 triggers must not add up to any real time"
    finally:
        relay.close()


def test_in_flight_requests_are_coalesced(fake_serial) -> None:
    """A second request while the gate is opening is dropped, not queued."""
    relay = SerialRelay("/dev/fake", 9600, pulse_ms=300)
    try:
        relay.trigger()
        time.sleep(0.05)  # the worker is now mid-pulse
        for _ in range(9):
            relay.trigger()

        assert relay.pulses_dropped == 9
        assert _wait_for(lambda: relay.pulses_sent == 1)
        time.sleep(0.3)
        assert relay.pulses_sent == 1, "coalesced requests must not fire extra pulses"
        assert len(fake_serial.opened) == 1
        assert fake_serial.opened[0].written == [b"A", b"a"]
    finally:
        relay.close()


def test_a_new_pulse_is_accepted_after_the_previous_one_finishes(fake_serial) -> None:
    relay = SerialRelay("/dev/fake", 9600, pulse_ms=20)
    try:
        relay.trigger()
        assert _wait_for(lambda: relay.pulses_sent == 1)
        relay.trigger()
        assert _wait_for(lambda: relay.pulses_sent == 2)
        assert fake_serial.opened[0].written == [b"A", b"a", b"A", b"a"]
    finally:
        relay.close()


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


def test_open_failure_does_not_raise_and_is_retried(monkeypatch) -> None:
    module = FakeSerialModule(fail_times=1)
    monkeypatch.setattr("lpr.hardware.relay._import_serial", lambda: module)

    relay = SerialRelay("/dev/fake", 9600, pulse_ms=10)
    try:
        relay.trigger()  # must not raise even though the open fails
        assert _wait_for(lambda: relay.last_error is not None)
        assert relay.pulses_sent == 0
        assert relay.available is False

        # Backoff is in effect, so force the next attempt to be allowed.
        relay._next_open_attempt = 0.0
        relay.trigger()
        assert _wait_for(lambda: relay.pulses_sent == 1)
        assert relay.available is True
    finally:
        relay.close()


def test_write_failure_closes_and_reopens_the_port(fake_serial) -> None:
    relay = SerialRelay("/dev/fake", 9600, pulse_ms=10)
    try:
        relay.trigger()
        assert _wait_for(lambda: relay.pulses_sent == 1)
        first = fake_serial.opened[0]

        def explode(payload: bytes) -> int:
            raise FakeSerialModule.SerialException("device disappeared")

        first.write = explode  # type: ignore[method-assign]

        relay.trigger()
        assert _wait_for(lambda: relay.last_error is not None)
        assert first.is_open is False, "a failed write must close the port"

        relay._next_open_attempt = 0.0
        relay.trigger()
        assert _wait_for(lambda: relay.pulses_sent == 2)
        assert len(fake_serial.opened) == 2, "the port must be reopened"
    finally:
        relay.close()


def test_close_is_idempotent_and_stops_the_worker(fake_serial) -> None:
    relay = SerialRelay("/dev/fake", 9600, pulse_ms=10)
    relay.trigger()
    assert _wait_for(lambda: relay.pulses_sent == 1)

    relay.close()
    relay.close()

    assert relay._thread.is_alive() is False
    assert relay.available is False
    # Triggering a closed relay is a silent no-op, never an exception.
    relay.trigger()
    assert relay.pulses_sent == 1


# ---------------------------------------------------------------------------
# MockRelay and the factory
# ---------------------------------------------------------------------------


def test_mock_relay_satisfies_the_protocol() -> None:
    relay = MockRelay("test")
    assert isinstance(relay, Relay)
    relay.trigger()
    relay.trigger()
    assert relay.triggers == 2
    assert relay.available is True
    relay.close()
    assert relay.available is False
    relay.trigger()
    assert relay.triggers == 2


def test_serial_relay_satisfies_the_protocol(fake_serial) -> None:
    relay = SerialRelay("/dev/fake", 9600, pulse_ms=10)
    try:
        assert isinstance(relay, Relay)
    finally:
        relay.close()


def test_build_relay_falls_back_when_disabled(tmp_settings) -> None:
    # tmp_settings ships relay.enabled=False.
    relay = build_relay(tmp_settings)
    assert isinstance(relay, MockRelay)
    relay.close()


def test_build_relay_falls_back_when_mocked(tmp_settings) -> None:
    tmp_settings.relay.enabled = True
    tmp_settings.relay.mock = True
    relay = build_relay(tmp_settings)
    assert isinstance(relay, MockRelay)
    relay.close()


def test_build_relay_falls_back_when_no_port(tmp_settings, monkeypatch) -> None:
    tmp_settings.relay.enabled = True
    tmp_settings.relay.mock = False
    monkeypatch.setattr("lpr.config.default_serial_port", lambda: None)
    tmp_settings.relay.port = "auto"

    relay = build_relay(tmp_settings)
    assert isinstance(relay, MockRelay), "no serial device must degrade, not crash"
    relay.close()


def test_build_relay_falls_back_without_pyserial(tmp_settings, monkeypatch) -> None:
    tmp_settings.relay.enabled = True
    tmp_settings.relay.mock = False
    tmp_settings.relay.port = "/dev/ttyUSB9"
    monkeypatch.setattr("lpr.hardware.relay._import_serial", lambda: None)

    relay = build_relay(tmp_settings)
    assert isinstance(relay, MockRelay)
    relay.close()


def test_build_relay_returns_serial_relay_when_configured(tmp_settings, fake_serial) -> None:
    tmp_settings.relay.enabled = True
    tmp_settings.relay.mock = False
    tmp_settings.relay.port = "/dev/fake"
    tmp_settings.relay.pulse_ms = 10

    relay = build_relay(tmp_settings)
    try:
        assert isinstance(relay, SerialRelay)
        relay.trigger()
        assert _wait_for(lambda: relay.pulses_sent == 1)
    finally:
        relay.close()
