"""Camera selection and live-view decoupling.

Three properties, all of which were broken and all of which fail silently --
as a frozen preview or a log full of reconnect warnings -- rather than as an
exception somebody notices:

* a camera role with no source is skipped, not opened;
* two roles never open the same physical device;
* the MJPEG live view reads the capture buffer, so it keeps running at
  capture rate while detection and OCR are slow, stalled or switched off.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from lpr.config import CameraConfig, CamerasConfig, MotionConfig
from lpr.pipeline.camera import CameraWorker
from lpr.pipeline.orchestrator import PipelineOrchestrator

from .conftest import FakeDetector, FakeRecognizer, FakeRelay, FakeVoter


def _pipeline(settings: Any, **overrides: Any) -> PipelineOrchestrator:
    return PipelineOrchestrator(
        settings=settings,
        detector=overrides.get("detector") or FakeDetector(),
        recognizer=overrides.get("recognizer") or FakeRecognizer(),
        voter=overrides.get("voter") or FakeVoter(),
        relay=overrides.get("relay") or FakeRelay(),
    )


def _with_cameras(settings: Any, entry: str, exit_: str) -> Any:
    """Copy of ``settings`` with the two camera sources replaced."""
    return settings.model_copy(
        update={
            "cameras": CamerasConfig(
                entry=CameraConfig(source=entry, queue_size=2, fps_limit=0),
                exit=CameraConfig(source=exit_, queue_size=2, fps_limit=0),
                motion=MotionConfig(enabled=False),
            )
        }
    )


# ---------------------------------------------------------------------------
# Empty sources
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_source_is_not_a_camera(blank: str) -> None:
    config = CameraConfig(source=blank)
    assert config.enabled is False
    assert config.resolved_source is None
    assert config.device_key is None


def test_orchestrator_skips_a_camera_with_no_source(db) -> None:
    """The single-camera setup: exit is blank, so only entry is selected."""
    pipeline = _pipeline(_with_cameras(db, entry="0", exit_=""))

    assert [role for role, _ in pipeline._camera_configs()] == ["entry"]


def test_a_blank_source_never_opens_a_device(monkeypatch: pytest.MonkeyPatch) -> None:
    """Not merely 'fails to open' -- OpenCV is never called at all.

    The old behaviour was a VideoCapture("") every reconnect_delay_s for the
    life of the process, each one logging a warning.
    """
    import cv2

    def explode(*args: Any, **kwargs: Any) -> Any:  # pragma: no cover - must not run
        raise AssertionError("VideoCapture must not be constructed for a blank source")

    monkeypatch.setattr(cv2, "VideoCapture", explode)

    worker = CameraWorker("exit", CameraConfig(source=""))
    assert worker.enabled is False

    worker.run()  # returns immediately rather than entering the reconnect loop

    status = worker.status()
    assert status.connected is False
    assert status.frames_read == 0
    assert status.last_error == "no source configured"


def test_starting_a_pipeline_with_no_cameras_is_not_an_error(db) -> None:
    pipeline = _pipeline(_with_cameras(db, entry="", exit_=""))
    assert pipeline._camera_configs() == []

    pipeline.start()
    try:
        assert pipeline.running is True
        assert pipeline.camera_roles() == []
    finally:
        pipeline.stop(timeout=2.0)


# ---------------------------------------------------------------------------
# Device collisions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "exit_"),
    [
        ("0", "0"),  # the same index twice
        ("/dev/video0", "0"),  # the reported failure: path vs index
        ("0", "/dev/video0"),  # and the other way round
        ("/dev/video0", "/dev/video0"),
    ],
)
def test_two_roles_never_open_the_same_device(db, entry: str, exit_: str) -> None:
    """V4L2 gives exclusive access; the loser would reconnect forever.

    Skipping is decided before anything is opened, and entry wins because it
    is offered the device first -- so which camera survives is deterministic
    rather than a race between two capture threads.
    """
    pipeline = _pipeline(_with_cameras(db, entry=entry, exit_=exit_))

    assert [role for role, _ in pipeline._camera_configs()] == ["entry"]


def test_distinct_devices_both_survive(db) -> None:
    pipeline = _pipeline(_with_cameras(db, entry="/dev/video0", exit_="1"))

    assert [role for role, _ in pipeline._camera_configs()] == ["entry", "exit"]


def test_device_key_normalises_index_and_path() -> None:
    assert CameraConfig(source="0").device_key == CameraConfig(source="/dev/video0").device_key
    assert CameraConfig(source="1").device_key != CameraConfig(source="/dev/video0").device_key
    # A URL is not a V4L2 device and keeps its own identity.
    assert CameraConfig(source="rtsp://cam/1").device_key == "rtsp://cam/1"


# ---------------------------------------------------------------------------
# The live view must not wait on inference
# ---------------------------------------------------------------------------


class _StallingDetector:
    """A detector that blocks until released -- a slow CPU OCR/YOLO pass."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def detect(self, frame: Any) -> list[Any]:
        self.entered.set()
        self.release.wait(timeout=5.0)
        return []


def test_the_live_view_reads_the_capture_buffer_not_the_inference_thread(db, frame) -> None:
    """latest_frame() must come from capture, which never waits on detection.

    Reading the processing thread's buffer instead -- which is what this used
    to do -- pinned the preview to the motion gate: on a still scene that is
    one frame every motion.heartbeat_s, and any stall in detection froze the
    preview outright.
    """
    import numpy as np

    pipeline = _pipeline(db)

    captured = np.full_like(frame, 7)
    stale = np.zeros_like(frame)

    class OnlyLatest:
        """Capture is producing frames; the processing thread is behind."""

        role = "entry"

        def latest(self) -> Any:
            return captured

        def read(self, timeout: float = 1.0) -> Any | None:
            return None

    pipeline._cameras["entry"] = OnlyLatest()  # type: ignore[assignment]
    with pipeline._frame_lock:
        pipeline._latest_frames["entry"] = stale

    assert pipeline.latest_frame("entry") is captured


def test_the_stream_keeps_serving_while_detection_is_stalled(db, frame) -> None:
    """The end-to-end property: a wedged detector must not freeze the preview."""
    pytest.importorskip("cv2")

    detector = _StallingDetector()
    settings = _with_cameras(db, entry="0", exit_="")
    pipeline = _pipeline(settings, detector=detector)

    from .test_pipeline import ScriptedCamera

    camera = ScriptedCamera("entry", [frame] * 8)
    pipeline._cameras["entry"] = camera  # type: ignore[assignment]

    loop = threading.Thread(target=pipeline._process_camera, args=("entry",), daemon=True)
    loop.start()
    try:
        assert detector.entered.wait(timeout=5.0), "detector never ran"

        # The processing thread is now parked inside detect(). The stream must
        # still get a frame, and must get it promptly.
        started = time.monotonic()
        encoded = pipeline.latest_frame_jpeg("entry", quality=60)
        elapsed = time.monotonic() - started

        assert encoded is not None and encoded[:2] == b"\xff\xd8"
        assert elapsed < 1.0, f"the stream waited {elapsed:.2f}s on the stalled detector"
    finally:
        detector.release.set()
        pipeline._stop_event.set()
        loop.join(timeout=5.0)


def test_stream_fps_budget_is_not_throttled_below_capture_rate() -> None:
    """A 30 FPS camera should not be shown as a 10 FPS slideshow."""
    from lpr.api.routes import STREAM_MAX_FPS

    assert STREAM_MAX_FPS >= 30.0
