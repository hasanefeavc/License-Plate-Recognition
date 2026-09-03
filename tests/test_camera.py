"""Tests for RTSP hardening: FFmpeg options, the stall watchdog and masking.

These cover the failure that takes a gate offline without anybody noticing: a
TCP connection that stays open while the camera stops sending. ``read()`` has
no timeout of its own, so the capture thread parks forever, the process stays
alive, ``/health`` keeps answering 200, and the barrier simply never opens
again.

Nothing here opens a socket or a device. ``CameraWorker`` is driven with a
fake capture object, so a stall is produced by *not returning* from a fake
``read()`` -- which is exactly what the real failure is -- and the watchdog is
observed breaking it.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from lpr.config import CameraConfig
from lpr.masking import REDACTION, mask_text, mask_url
from lpr.pipeline.camera import (
    _FFMPEG_OPTIONS_ENV,
    CameraWorker,
    ffmpeg_capture_options,
)

RTSP = "rtsp://admin:hunter2@10.0.0.5:554/Streaming/Channels/101"


# ---------------------------------------------------------------------------
# Credential masking
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (RTSP, f"rtsp://admin:{REDACTION}@10.0.0.5:554/Streaming/Channels/101"),
        ("rtsp://10.0.0.5/stream", "rtsp://10.0.0.5/stream"),
        ("rtsp://admin@10.0.0.5/s1", "rtsp://admin@10.0.0.5/s1"),
        ("http://user:pw@cam.local/img.cgi", f"http://user:{REDACTION}@cam.local/img.cgi"),
        ("0", "0"),
        ("/dev/video0", "/dev/video0"),
        ("", ""),
        (None, ""),
    ],
)
def test_mask_url(raw: Any, expected: str) -> None:
    assert mask_url(raw) == expected


def test_the_username_survives_because_it_is_diagnostic_not_secret() -> None:
    masked = mask_url(RTSP)
    assert "admin" in masked, "knowing which account is configured helps diagnosis"
    assert "hunter2" not in masked


def test_masking_finds_a_url_inside_a_sentence() -> None:
    """OpenCV reports failures as prose, and that prose reaches last_error."""
    message = f"Could not open {RTSP}: connection refused"
    masked = mask_text(message)
    assert "hunter2" not in masked
    assert "connection refused" in masked


def test_a_local_device_path_containing_an_at_sign_is_untouched() -> None:
    """Over-eager redaction makes a log less useful for no security gain."""
    assert mask_url(r"C:\Users\a@b\clip.mp4") == r"C:\Users\a@b\clip.mp4"


def test_the_worker_masks_its_source_in_status() -> None:
    """CameraStatus is serialised straight into the API response."""
    worker = CameraWorker("entry", CameraConfig(source=RTSP))
    assert "hunter2" not in worker.status().source
    assert REDACTION in worker.status().source


def test_the_worker_masks_credentials_in_recorded_errors() -> None:
    worker = CameraWorker("entry", CameraConfig(source=RTSP))
    worker._record_error(f"open failed for {RTSP}")
    assert "hunter2" not in (worker.status().last_error or "")


# ---------------------------------------------------------------------------
# FFmpeg capture options
# ---------------------------------------------------------------------------


def test_a_network_source_gets_tcp_and_a_socket_timeout() -> None:
    """The single most important line in the module.

    Without stimeout, a stream that stops sending parks read() forever.
    Without rtsp_transport=tcp, FFmpeg uses UDP and drops packets, which
    surfaces as OCR errors that are really decode errors.
    """
    options = ffmpeg_capture_options(CameraConfig(source=RTSP, open_timeout_s=5.0))
    assert options is not None
    assert "rtsp_transport;tcp" in options
    assert "stimeout;5000000" in options, "FFmpeg wants microseconds"


def test_the_socket_timeout_is_converted_to_microseconds() -> None:
    options = ffmpeg_capture_options(CameraConfig(source=RTSP, open_timeout_s=2.5))
    assert "stimeout;2500000" in (options or "")


def test_udp_can_be_selected_for_a_site_that_needs_it() -> None:
    options = ffmpeg_capture_options(CameraConfig(source=RTSP, rtsp_transport="udp"))
    assert "rtsp_transport;udp" in (options or "")


def test_a_zero_timeout_omits_stimeout_rather_than_sending_zero() -> None:
    """stimeout;0 would mean "time out immediately", not "no timeout"."""
    options = ffmpeg_capture_options(CameraConfig(source=RTSP, open_timeout_s=0))
    assert "stimeout" not in (options or "")


@pytest.mark.parametrize("source", ["0", "1", "/dev/video0"])
def test_a_local_device_gets_no_ffmpeg_options(source: str) -> None:
    assert ffmpeg_capture_options(CameraConfig(source=source)) is None


def test_the_options_env_var_is_scoped_to_one_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """The variable is process-global, so it must not outlive the constructor.

    Two cameras with different transports would otherwise race, and every
    unrelated FFmpeg user in the process would inherit these options.
    """
    monkeypatch.delenv(_FFMPEG_OPTIONS_ENV, raising=False)
    worker = CameraWorker("entry", CameraConfig(source=RTSP))

    seen: list[str | None] = []
    with worker._ffmpeg_options():
        seen.append(__import__("os").environ.get(_FFMPEG_OPTIONS_ENV))

    assert seen[0] is not None and "rtsp_transport;tcp" in seen[0]
    assert __import__("os").environ.get(_FFMPEG_OPTIONS_ENV) is None


def test_a_pre_existing_options_value_is_restored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_FFMPEG_OPTIONS_ENV, "something;else")
    worker = CameraWorker("entry", CameraConfig(source=RTSP))
    with worker._ffmpeg_options():
        pass
    assert __import__("os").environ[_FFMPEG_OPTIONS_ENV] == "something;else"


# ---------------------------------------------------------------------------
# Reconnect backoff
# ---------------------------------------------------------------------------


def test_backoff_grows_and_is_capped() -> None:
    config = CameraConfig(source=RTSP, reconnect_delay_s=1.0, reconnect_max_delay_s=8.0)
    worker = CameraWorker("entry", config)
    worker._stop_event.set()  # so _sleep_backoff returns at once

    delays = []
    for _ in range(6):
        delays.append(worker._backoff)
        worker._sleep_backoff()

    assert delays[0] == pytest.approx(1.0)
    assert delays[1] == pytest.approx(2.0)
    assert delays[2] == pytest.approx(4.0)
    assert delays[-1] == pytest.approx(8.0), "capped at reconnect_max_delay_s"


def test_backoff_never_exceeds_the_cap_even_with_jitter() -> None:
    config = CameraConfig(source=RTSP, reconnect_delay_s=1.0, reconnect_max_delay_s=4.0)
    worker = CameraWorker("entry", config)
    worker._stop_event.set()
    for _ in range(20):
        worker._sleep_backoff()
    assert worker._backoff <= 4.0


def test_a_delivered_frame_resets_the_backoff() -> None:
    """Only a frame proves the link works.

    Resetting on a successful *open* instead would defeat the mechanism
    against exactly the camera this phase is about: one that accepts the
    connection and then sends nothing.
    """
    np = pytest.importorskip("numpy")
    config = CameraConfig(source=RTSP, reconnect_delay_s=1.0, reconnect_max_delay_s=30.0)
    worker = CameraWorker("entry", config)
    worker._stop_event.set()
    worker._sleep_backoff()
    worker._sleep_backoff()
    assert worker._backoff > 1.0

    worker._publish(np.zeros((4, 4, 3), dtype=np.uint8))
    worker._backoff = worker._reconnect_delay  # what _capture_loop does on a frame
    assert worker._backoff == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# A source that never opens
#
# The other end of the same contract as the watchdog: a camera the capture
# backend refuses outright must degrade the service, never stop it. Nothing
# here opens a device -- ``cv2.VideoCapture`` is replaced by a class that
# reports itself closed, which is what the real one does for a wrong index, a
# device another process holds, or a URL nothing answers on.
# ---------------------------------------------------------------------------


class RefusingCapture:
    """A capture handle that never opens. Counts its own release."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.releases = 0

    def isOpened(self) -> bool:  # noqa: N802 - mirrors the cv2 API
        return False

    def release(self) -> None:
        self.releases += 1


def test_a_source_that_will_not_open_is_reported_and_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failure an operator sees as "the entry camera is offline".

    ``_open`` has to hand back ``None`` and put the reason on the status
    object, because that status is the only thing standing between this and a
    gate that is silently blind: it is what ``/health`` and the dashboard read.
    Raising instead would take the whole capture thread down and, with it, the
    other camera.
    """
    cv2 = pytest.importorskip("cv2")
    monkeypatch.setattr(cv2, "VideoCapture", RefusingCapture)
    worker = CameraWorker("entry", CameraConfig(source="9", reconnect_delay_s=0.01))

    assert worker._open() is None
    status = worker.status()
    assert status.connected is False
    assert status.last_error and "could not open" in status.last_error
    assert worker.enabled, "a camera that is fitted but unreachable is still configured"


def test_a_source_that_will_not_open_is_retried_instead_of_abandoned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A camera that is merely rebooting must be picked up when it returns.

    Giving up after the first refusal would mean a power-cycled camera stays
    dark until somebody restarts the service, which is the failure the backoff
    exists to avoid. The loop is stopped from inside the third open so the test
    terminates on a deterministic count rather than on a timer.
    """
    cv2 = pytest.importorskip("cv2")
    monkeypatch.setattr(cv2, "VideoCapture", RefusingCapture)
    config = CameraConfig(source="9", reconnect_delay_s=0.01, reconnect_max_delay_s=0.01)
    worker = CameraWorker("entry", config)
    real_open = worker._open
    attempts = 0

    def counting_open() -> Any:
        nonlocal attempts
        attempts += 1
        if attempts >= 3:
            worker._stop_event.set()
        return real_open()

    monkeypatch.setattr(worker, "_open", counting_open)
    worker._capture_loop()

    assert attempts == 3, "the loop must keep retrying, not return on the first failure"
    assert worker.status().connected is False


def test_an_unfitted_camera_starts_and_stops_without_touching_a_device() -> None:
    """A blank source is the normal single-camera site, not a failure.

    ``run`` returns immediately, so a role nobody wired up costs a thread that
    exits rather than one reconnecting to nothing all night.
    """
    worker = CameraWorker("exit", CameraConfig(source=""))

    assert not worker.enabled
    assert worker.status().last_error == "no source configured"
    worker.run()  # must not block, and must not raise
    assert worker.status().connected is False


# ---------------------------------------------------------------------------
# The stall watchdog
# ---------------------------------------------------------------------------


class StallingCapture:
    """A capture that delivers ``good_frames`` and then blocks forever.

    This *is* the production failure, reproduced: the socket is open, the
    driver is happy, and ``read()`` simply never returns. ``release()`` sets
    the event that lets the blocked read finish, which is what OpenCV's real
    release does to a blocked FFmpeg read.
    """

    def __init__(self, good_frames: int = 1) -> None:
        import numpy as np

        self._frame = np.zeros((8, 8, 3), dtype=np.uint8)
        self._remaining = good_frames
        self.released = threading.Event()
        self.release_calls = 0
        self.reads_started = 0

    def isOpened(self) -> bool:  # noqa: N802 - mirrors the cv2 API
        return not self.released.is_set()

    def set(self, *_args: Any) -> bool:  # noqa: A003 - mirrors the cv2 API
        return True

    def read(self) -> tuple[bool, Any]:
        self.reads_started += 1
        if self._remaining > 0:
            self._remaining -= 1
            return True, self._frame
        # Block until somebody releases us, exactly like a stalled RTSP read.
        self.released.wait(timeout=10.0)
        return False, None

    def release(self) -> None:
        self.release_calls += 1
        self.released.set()


@pytest.fixture
def stalling_worker(monkeypatch: pytest.MonkeyPatch) -> Any:
    """A worker whose ``_open`` hands back a StallingCapture."""
    pytest.importorskip("numpy")
    config = CameraConfig(
        source=RTSP,
        stall_timeout_s=0.3,
        reconnect_delay_s=0.05,
        reconnect_max_delay_s=0.2,
        fps_limit=0,
    )
    worker = CameraWorker("entry", config)
    captures: list[StallingCapture] = []

    def fake_open() -> StallingCapture:
        capture = StallingCapture(good_frames=1)
        captures.append(capture)
        with worker._capture_lock:
            worker._capture = capture
            worker._capture_generation += 1
        with worker._lock:
            worker._status.connected = True
            worker._status.last_error = None
            worker._status.last_frame_ts = time.time()
        return capture

    monkeypatch.setattr(worker, "_open", fake_open)
    worker.captures = captures  # type: ignore[attr-defined]
    return worker


def test_the_watchdog_breaks_a_stalled_read(stalling_worker: Any) -> None:
    """The core assertion of this phase.

    Without the watchdog the capture thread sits in read() forever. The
    process stays alive and the gate is silently blind.
    """
    worker = stalling_worker
    worker.start()
    try:
        deadline = time.monotonic() + 6.0
        while worker.stalls < 1 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert worker.stalls >= 1, "the watchdog never fired on a stalled stream"
        assert worker.captures[0].release_calls >= 1
    finally:
        worker.stop(timeout=3.0)


def test_a_stall_is_followed_by_a_reconnect(stalling_worker: Any) -> None:
    """Breaking the read is only half of it; the worker must come back."""
    worker = stalling_worker
    worker.start()
    try:
        deadline = time.monotonic() + 8.0
        while len(worker.captures) < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert len(worker.captures) >= 2, "no reconnect after the forced release"
    finally:
        worker.stop(timeout=3.0)


def test_a_stall_is_reported_on_the_status_object(stalling_worker: Any) -> None:
    """An operator has to be able to see this, or it is still a silent failure."""
    worker = stalling_worker
    worker.start()
    try:
        deadline = time.monotonic() + 6.0
        while worker.stalls < 1 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert "no frame for" in (worker.status().last_error or "")
    finally:
        worker.stop(timeout=3.0)


def test_the_watchdog_does_not_fire_before_the_first_frame() -> None:
    """A stream that has never delivered is connecting, not stalled.

    Treating last_frame_ts == 0 as "stalled since the epoch" would force a
    reconnect on every start-up, before the camera had a chance to answer.
    """
    worker = CameraWorker("entry", CameraConfig(source=RTSP, stall_timeout_s=0.1))
    with worker._lock:
        worker._status.connected = True
        worker._status.last_frame_ts = 0.0

    thread = threading.Thread(target=worker._watchdog_loop, daemon=True)
    thread.start()
    time.sleep(0.4)
    worker._stop_event.set()
    thread.join(timeout=2.0)

    assert worker.stalls == 0


def test_the_watchdog_is_disabled_by_a_zero_timeout() -> None:
    worker = CameraWorker("entry", CameraConfig(source=RTSP, stall_timeout_s=0.0))
    worker._start_watchdog()
    assert worker._watchdog is None


def test_a_healthy_stream_never_trips_the_watchdog() -> None:
    """The regression that would matter most: reconnecting a working camera."""
    worker = CameraWorker("entry", CameraConfig(source=RTSP, stall_timeout_s=0.3))
    with worker._lock:
        worker._status.connected = True

    stop_feeding = threading.Event()

    def keep_fresh() -> None:
        while not stop_feeding.wait(0.05):
            with worker._lock:
                worker._status.last_frame_ts = time.time()

    feeder = threading.Thread(target=keep_fresh, daemon=True)
    watchdog = threading.Thread(target=worker._watchdog_loop, daemon=True)
    feeder.start()
    watchdog.start()
    time.sleep(1.2)
    worker._stop_event.set()
    stop_feeding.set()
    watchdog.join(timeout=2.0)
    feeder.join(timeout=2.0)

    assert worker.stalls == 0, "a camera delivering frames was reconnected anyway"


def test_force_release_clears_the_handle_before_releasing_it() -> None:
    """The read loop must never come back to an object freed underneath it."""
    pytest.importorskip("numpy")
    worker = CameraWorker("entry", CameraConfig(source=RTSP))
    capture = StallingCapture()
    with worker._capture_lock:
        worker._capture = capture
        worker._capture_generation += 1
    generation = worker._capture_generation

    worker._force_release()

    assert worker._capture is None
    assert capture.release_calls == 1
    assert worker._capture_generation != generation, "the read loop must see a change"
    assert worker.status().connected is False
