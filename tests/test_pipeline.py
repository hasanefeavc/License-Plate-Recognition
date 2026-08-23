"""Tests for the capture / orchestration layer.

The properties under test are the ones that were broken in the legacy app:
a slow consumer must not stall capture, the detector must not run on every
frame, a car idling at the gate must not spam the log, and a slow event
subscriber must not stall the pipeline.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Any

import pytest

from lpr.contracts import Action, CameraStatus, PlateRead
from lpr.db import LogRepository, PlateRepository, init_db
from lpr.pipeline.camera import CameraWorker
from lpr.pipeline.orchestrator import SUBSCRIBER_QUEUE_SIZE, PipelineOrchestrator

from .conftest import (
    FakeDetector,
    FakeRecognizer,
    FakeRelay,
    FakeTrackingDetector,
    FakeVoter,
)


# ---------------------------------------------------------------------------
# Test doubles for the capture layer
# ---------------------------------------------------------------------------


class ScriptedCamera:
    """A CameraWorker stand-in that replays a fixed list of frames."""

    def __init__(self, role: str, frames: list[Any]) -> None:
        self.role = role
        self._frames = list(frames)
        self._queue: queue.Queue[Any] = queue.Queue()
        for item in self._frames:
            self._queue.put(item)
        self.started = False
        self.stopped = False

    def start(self) -> None:
        self.started = True

    def stop(self, timeout: float = 5.0) -> None:
        self.stopped = True

    def is_alive(self) -> bool:
        return self.started and not self.stopped

    def join(self, timeout: float | None = None) -> None:
        return None

    def read(self, timeout: float = 1.0) -> Any | None:
        try:
            return self._queue.get(timeout=min(timeout, 0.05))
        except queue.Empty:
            return None

    def latest(self) -> Any | None:
        return self._frames[-1] if self._frames else None

    def status(self) -> CameraStatus:
        return CameraStatus(role=self.role, source="scripted", connected=True)


class FakeClock:
    """A monotonic clock the test drives by hand."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _build_pipeline(
    settings: Any,
    detector: Any = None,
    recognizer: Any = None,
    voter: Any = None,
    relay: Any = None,
) -> PipelineOrchestrator:
    return PipelineOrchestrator(
        settings=settings,
        detector=detector or FakeDetector(),
        recognizer=recognizer or FakeRecognizer(),
        voter=voter or FakeVoter(),
        relay=relay or FakeRelay(),
    )


# ---------------------------------------------------------------------------
# CameraWorker queue semantics
# ---------------------------------------------------------------------------


def test_camera_queue_drops_oldest_never_blocks(tmp_settings) -> None:
    """A full queue evicts the oldest frame instead of stalling capture."""
    worker = CameraWorker("entry", tmp_settings.cameras.entry)  # queue_size=2
    assert worker._queue.maxsize == 2

    for n in range(5):
        started = time.monotonic()
        worker._publish(f"frame-{n}")
        # Publishing must be effectively instantaneous even when full.
        assert time.monotonic() - started < 0.5

    status = worker.status()
    assert status.frames_read == 5
    assert status.frames_dropped == 3
    # Only the two newest frames survived, oldest first out of the queue.
    assert worker.read(timeout=0.1) == "frame-3"
    assert worker.read(timeout=0.1) == "frame-4"
    assert worker.read(timeout=0.01) is None
    # latest() always tracks the newest frame regardless of the queue.
    assert worker.latest() == "frame-4"


def test_camera_status_tracks_errors_and_fps(tmp_settings) -> None:
    worker = CameraWorker("entry", tmp_settings.cameras.entry)
    worker._publish("a")
    time.sleep(0.02)
    worker._publish("b")
    status = worker.status()
    assert status.connected is True
    assert status.fps > 0
    assert status.last_frame_ts > 0

    worker._record_error("camera unplugged")
    status = worker.status()
    assert status.connected is False
    assert status.last_error == "camera unplugged"
    assert status.fps == 0.0


def test_camera_status_returns_a_copy(tmp_settings) -> None:
    worker = CameraWorker("entry", tmp_settings.cameras.entry)
    snapshot = worker.status()
    worker._publish("a")
    assert snapshot.frames_read == 0
    assert worker.status().frames_read == 1


def test_camera_stop_is_safe_before_start(tmp_settings) -> None:
    worker = CameraWorker("exit", tmp_settings.cameras.exit)
    worker.stop(timeout=0.1)
    assert worker.stopping is True


# ---------------------------------------------------------------------------
# Motion gating
# ---------------------------------------------------------------------------


def _scene(shift: int = 0, car: bool = False) -> Any:
    """A 720p frame: static background, optionally with a car-sized object."""
    np = pytest.importorskip("numpy")
    frame = np.zeros((720, 1280, 3), dtype=np.uint8)
    frame[:, :, 1] = np.linspace(40, 100, 1280).astype(np.uint8)
    frame[500:720, :, :] = 70
    if car:
        frame[380:560, 300 + shift : 560 + shift] = 220
    return frame


def test_motion_gate_drops_a_still_scene(tmp_settings) -> None:
    pytest.importorskip("cv2")
    from lpr.pipeline.camera import MotionGate

    gate = MotionGate(threshold=5000, heartbeat_s=0.0)
    assert gate.should_process(_scene()) is True, "the first frame seeds the background"
    for _ in range(5):
        assert gate.should_process(_scene()) is False
    assert gate.last_area == 0.0


def test_motion_gate_passes_a_moving_car(tmp_settings) -> None:
    pytest.importorskip("cv2")
    from lpr.pipeline.camera import MotionGate

    gate = MotionGate(threshold=5000, heartbeat_s=0.0)
    gate.should_process(_scene())
    gate.should_process(_scene())
    assert gate.should_process(_scene(car=True)) is True
    # Areas are reported in full-frame pixels, not downscaled ones: the car is
    # 260x180 = 46800 px, so the measurement must be of that order.
    assert gate.last_area > 20000, gate.last_area


def test_motion_gate_heartbeat_passes_a_still_scene(tmp_settings) -> None:
    pytest.importorskip("cv2")
    from lpr.pipeline.camera import MotionGate

    clock = FakeClock()
    gate = MotionGate(threshold=5000, heartbeat_s=3.0, clock=clock)
    gate.should_process(_scene())
    assert gate.should_process(_scene()) is False

    clock.advance(3.5)
    assert gate.should_process(_scene()) is True, "heartbeat must force a frame through"
    clock.advance(0.5)
    assert gate.should_process(_scene()) is False, "and then reset the interval"


def test_motion_gate_fails_open(tmp_settings) -> None:
    """Anything the gate cannot measure is passed through, never dropped."""
    from lpr.pipeline.camera import MotionGate

    gate = MotionGate(threshold=5000, heartbeat_s=0.0)
    for _ in range(5):
        assert gate.should_process("not-a-frame") is True
        assert gate.should_process(None) is True


def test_motion_gate_disables_itself_after_repeated_failures(tmp_settings) -> None:
    from lpr.pipeline.camera import MOTION_MAX_FAILURES, MotionGate

    class Exploding:
        shape = (720, 1280, 3)
        ndim = 3

        def __getitem__(self, item: Any) -> Any:
            raise RuntimeError("boom")

    gate = MotionGate(threshold=5000, heartbeat_s=0.0)
    for _ in range(MOTION_MAX_FAILURES):
        assert gate.should_process(Exploding()) is True
    assert gate._available is False
    assert gate.should_process(_scene()) is True, "a disabled gate passes everything"


def test_motion_gate_reset_reseeds_the_background(tmp_settings) -> None:
    pytest.importorskip("cv2")
    from lpr.pipeline.camera import MotionGate

    gate = MotionGate(threshold=5000, heartbeat_s=0.0)
    gate.should_process(_scene())
    assert gate.should_process(_scene()) is False

    gate.reset()
    # First frame after a reconnect seeds a fresh background instead of
    # reading the whole new scene as movement.
    assert gate.should_process(_scene(car=True)) is True
    assert gate.should_process(_scene(car=True)) is False


def test_camera_worker_skips_still_frames(tmp_settings) -> None:
    """The queue only gets frames worth an inference pass; preview still moves."""
    pytest.importorskip("cv2")
    from lpr.config import MotionConfig

    worker = CameraWorker(
        "entry",
        tmp_settings.cameras.entry,
        motion=MotionConfig(enabled=True, threshold=5000, heartbeat_s=0.0),
    )

    worker._publish(_scene())  # seeds the background, goes through
    still = _scene()
    for _ in range(4):
        worker._publish(still)

    status = worker.status()
    assert status.frames_read == 5, "every captured frame is still counted"
    assert status.motion_skipped == 4
    assert worker.latest() is still, "the preview must keep updating while gated"
    assert worker.read(timeout=0.05) is not None
    assert worker.read(timeout=0.01) is None, "the still frames never reached the queue"

    worker._publish(_scene(car=True))
    assert worker.read(timeout=0.05) is not None


def test_camera_worker_without_motion_queues_everything(tmp_settings) -> None:
    from lpr.config import MotionConfig

    worker = CameraWorker(
        "entry",
        tmp_settings.cameras.entry,
        motion=MotionConfig(enabled=False),
    )
    assert worker._motion is None
    for _ in range(3):
        worker._publish(_scene())
    assert worker.status().motion_skipped == 0
    assert worker.status().frames_read == 3


# ---------------------------------------------------------------------------
# frame_stride
# ---------------------------------------------------------------------------


def test_frame_stride_is_honoured(db, monkeypatch, frame) -> None:
    """The detector must only see every Nth frame -- the main CPU saving."""
    settings = db
    monkeypatch.setattr(settings.detection, "frame_stride", 3)

    detector = FakeDetector()
    pipeline = _build_pipeline(settings, detector=detector, voter=FakeVoter(confirm=False))

    frames = [frame] * 9
    camera = ScriptedCamera("entry", frames)
    pipeline._cameras["entry"] = camera

    # Drive the loop directly, then let it stop once the frames run out.
    stopper = threading.Thread(
        target=lambda: (time.sleep(0.4), pipeline._stop_event.set())
    )
    stopper.start()
    pipeline._process_camera("entry")
    stopper.join()

    assert detector.calls == 3, f"expected 9//3 detector calls, got {detector.calls}"


def test_frame_stride_of_one_runs_every_frame(db, monkeypatch, frame) -> None:
    settings = db
    monkeypatch.setattr(settings.detection, "frame_stride", 1)

    detector = FakeDetector()
    pipeline = _build_pipeline(settings, detector=detector, voter=FakeVoter(confirm=False))
    pipeline._cameras["entry"] = ScriptedCamera("entry", [frame] * 4)

    stopper = threading.Thread(
        target=lambda: (time.sleep(0.4), pipeline._stop_event.set())
    )
    stopper.start()
    pipeline._process_camera("entry")
    stopper.join()

    assert detector.calls == 4


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


def test_granted_path(db, frame) -> None:
    PlateRepository().add("34ABC123")
    relay = FakeRelay()
    pipeline = _build_pipeline(db, relay=relay)

    events = pipeline.process_frame("entry", frame)

    assert [e.action for e in events] == [str(Action.GRANTED)]
    assert relay.triggers == 1
    assert events[0].id is not None, "the event must carry its database rowid"

    logged = LogRepository().recent(10)
    assert [e.action for e in logged] == [str(Action.GRANTED)]
    assert logged[0].plate == "34ABC123"

    stats = pipeline.stats()
    assert stats.grants == 1
    assert stats.denials == 0
    assert stats.plates_read == 1


def test_denied_path_does_not_trigger_the_relay(db, frame) -> None:
    relay = FakeRelay()
    pipeline = _build_pipeline(db, relay=relay)

    events = pipeline.process_frame("entry", frame)

    assert [e.action for e in events] == [str(Action.DENIED)]
    assert relay.triggers == 0
    assert pipeline.stats().denials == 1
    assert LogRepository().recent(10)[0].action == str(Action.DENIED)


def test_unusable_and_low_confidence_reads_are_skipped(db, frame) -> None:
    pipeline = _build_pipeline(
        db, recognizer=FakeRecognizer(text="", valid=False), voter=FakeVoter()
    )
    assert pipeline.process_frame("entry", frame) == []

    low = FakeRecognizer(
        reads=[PlateRead(text="34ABC123", confidence=0.1, raw_text="34ABC123", valid=True)]
    )
    pipeline2 = _build_pipeline(db, recognizer=low)
    assert pipeline2.process_frame("entry", frame) == []
    assert LogRepository().count_matching() == 0


def test_unconfirmed_votes_never_reach_the_database(db, frame) -> None:
    voter = FakeVoter(confirm=False)
    pipeline = _build_pipeline(db, voter=voter)

    assert pipeline.process_frame("entry", frame) == []
    assert len(voter.submissions) == 1
    assert LogRepository().count_matching() == 0
    assert pipeline.stats().plates_read == 1


def test_cooldown_suppresses_repeat_decisions(db, monkeypatch, frame) -> None:
    """An idling car re-confirms constantly; only the first decision is logged."""
    settings = db
    monkeypatch.setattr(settings.voting, "cooldown_s", 60.0)
    PlateRepository().add("34ABC123")

    relay = FakeRelay()
    pipeline = _build_pipeline(settings, relay=relay)

    first = pipeline.process_frame("entry", frame)
    repeats = [pipeline.process_frame("entry", frame) for _ in range(4)]

    assert [e.action for e in first] == [str(Action.GRANTED)]
    assert all(e.action == str(Action.COOLDOWN) for batch in repeats for e in batch)

    assert relay.triggers == 1, "the gate must not re-fire while in cooldown"
    assert LogRepository().count_matching() == 1, "cooldown must not spam the logs table"


def test_cooldown_is_per_camera_and_plate(db, monkeypatch) -> None:
    settings = db
    monkeypatch.setattr(settings.voting, "cooldown_s", 60.0)
    pipeline = _build_pipeline(settings)

    assert pipeline.decide("entry", "34ABC123").action == str(Action.DENIED)
    assert pipeline.decide("entry", "34ABC123").action == str(Action.COOLDOWN)
    # A different camera and a different plate each have their own window.
    assert pipeline.decide("exit", "34ABC123").action == str(Action.DENIED)
    assert pipeline.decide("entry", "06XYZ99").action == str(Action.DENIED)


def test_cooldown_expires(db, monkeypatch) -> None:
    settings = db
    monkeypatch.setattr(settings.voting, "cooldown_s", 0.05)
    pipeline = _build_pipeline(settings)

    assert pipeline.decide("entry", "34ABC123").action == str(Action.DENIED)
    assert pipeline.decide("entry", "34ABC123").action == str(Action.COOLDOWN)
    time.sleep(0.08)
    assert pipeline.decide("entry", "34ABC123").action == str(Action.DENIED)
    assert LogRepository().count_matching() == 2


# ---------------------------------------------------------------------------
# Tracking
# ---------------------------------------------------------------------------


def _tracking_voter(db: Any, **kwargs: Any) -> Any:
    from lpr.ocr.voting import MultiFrameVoter

    params: dict[str, Any] = {"window": 5, "min_votes": 1, "ttl_s": 100.0}
    params.update(kwargs)
    return MultiFrameVoter(**params)


def test_a_decided_track_stops_costing_ocr(db, frame) -> None:
    """The point of tracking: one car, one OCR pass -- not one per frame."""
    PlateRepository().add("34ABC123")
    recognizer = FakeRecognizer()
    relay = FakeRelay()
    pipeline = _build_pipeline(
        db,
        detector=FakeTrackingDetector(track_ids=[7]),
        recognizer=recognizer,
        voter=_tracking_voter(db, cooldown_s=60.0),
        relay=relay,
    )

    first = pipeline.process_frame("entry", frame)
    for _ in range(9):
        assert pipeline.process_frame("entry", frame) == []

    assert [e.action for e in first] == [str(Action.GRANTED)]
    assert recognizer.calls == 1, "the same tracked plate must not be re-read"
    assert relay.triggers == 1
    assert pipeline.stats().ocr_skipped == 9


def test_a_new_track_is_recognised_again(db, frame) -> None:
    """A second car must not inherit the first one's OCR suppression."""
    recognizer = FakeRecognizer(
        reads=[
            PlateRead(text="34ABC123", confidence=0.95, raw_text="34ABC123", valid=True),
            PlateRead(text="06XYZ99", confidence=0.95, raw_text="06XYZ99", valid=True),
        ]
    )
    detector = FakeTrackingDetector(track_ids=[7, 7, 8, 8])
    pipeline = _build_pipeline(
        db,
        detector=detector,
        recognizer=recognizer,
        voter=_tracking_voter(db, cooldown_s=60.0),
    )

    for _ in range(4):
        pipeline.process_frame("entry", frame)

    assert recognizer.calls == 2, "one read for track 7, one for track 8"


def test_each_camera_gets_its_own_tracker_stream(db, frame) -> None:
    detector = FakeTrackingDetector(track_ids=[7])
    pipeline = _build_pipeline(
        db, detector=detector, voter=_tracking_voter(db, cooldown_s=60.0)
    )

    pipeline.process_frame("entry", frame)
    pipeline.process_frame("exit", frame)

    assert detector.streams == ["entry", "exit"]


def test_an_untracked_detector_still_runs_ocr_every_frame(db, frame) -> None:
    """Backwards compatibility: no track ids means the old behaviour."""
    recognizer = FakeRecognizer()
    pipeline = _build_pipeline(
        db,
        detector=FakeDetector(),
        recognizer=recognizer,
        voter=_tracking_voter(db, cooldown_s=60.0),
    )

    for _ in range(5):
        pipeline.process_frame("entry", frame)

    assert recognizer.calls == 5
    assert pipeline.stats().ocr_skipped == 0


def test_a_track_unaware_voter_is_driven_the_old_way(db, frame) -> None:
    """A voter without the tracking hooks keeps its two-argument submit."""
    voter = FakeVoter(confirm=False)
    recognizer = FakeRecognizer()
    pipeline = _build_pipeline(
        db,
        detector=FakeTrackingDetector(track_ids=[7]),
        recognizer=recognizer,
        voter=voter,
    )

    for _ in range(3):
        pipeline.process_frame("entry", frame)

    assert len(voter.submissions) == 3
    assert recognizer.calls == 3


# ---------------------------------------------------------------------------
# Subscribers
# ---------------------------------------------------------------------------


def test_subscribe_fan_out(db, frame) -> None:
    pipeline = _build_pipeline(db)
    a = pipeline.subscribe()
    b = pipeline.subscribe()

    pipeline.process_frame("entry", frame)

    assert a.get_nowait().plate == "34ABC123"
    assert b.get_nowait().plate == "34ABC123"

    pipeline.unsubscribe(a)
    pipeline.unsubscribe(a)  # idempotent
    pipeline.decide("exit", "06XYZ99")
    assert a.empty()
    assert b.get_nowait().plate == "06XYZ99"


def test_full_subscriber_queue_never_stalls_the_pipeline(db) -> None:
    """A dead WebSocket client loses history; the pipeline keeps running."""
    pipeline = _build_pipeline(db)
    q = pipeline.subscribe()
    assert q.maxsize == SUBSCRIBER_QUEUE_SIZE

    started = time.monotonic()
    for n in range(SUBSCRIBER_QUEUE_SIZE + 20):
        pipeline.decide("entry", f"34ABC{n:03d}")
    elapsed = time.monotonic() - started

    assert q.full()
    assert q.qsize() == SUBSCRIBER_QUEUE_SIZE
    assert elapsed < 10.0, "publishing must never block on a full subscriber"

    # Drop-oldest: the queue holds the *newest* events, not the first 256.
    oldest_kept = q.get_nowait()
    assert oldest_kept.plate == f"34ABC{20:03d}"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_start_stop_joins_cleanly_and_is_idempotent(db, monkeypatch, frame) -> None:
    settings = db
    init_db()

    made: list[ScriptedCamera] = []

    def fake_worker(self: PipelineOrchestrator, role: str, config: Any) -> Any:
        camera = ScriptedCamera(role, [frame] * 3)
        made.append(camera)
        return camera

    monkeypatch.setattr(PipelineOrchestrator, "_make_camera_worker", fake_worker)

    pipeline = _build_pipeline(settings)
    before = threading.active_count()

    pipeline.start()
    assert pipeline.running is True
    pipeline.start()  # idempotent, must not double up the threads
    assert len(made) == 2, "one worker per configured camera"

    time.sleep(0.3)
    pipeline.stop(timeout=5.0)
    assert pipeline.running is False
    pipeline.stop(timeout=5.0)  # idempotent

    assert all(camera.stopped for camera in made)
    deadline = time.monotonic() + 5.0
    while threading.active_count() > before and time.monotonic() < deadline:
        time.sleep(0.05)
    assert threading.active_count() <= before, "stop() must join every thread it started"


def test_stop_without_start_is_a_noop(db) -> None:
    pipeline = _build_pipeline(db)
    pipeline.stop()
    assert pipeline.running is False


def test_warmup_is_called_on_start(db, monkeypatch, frame) -> None:
    detector = FakeDetector()
    recognizer = FakeRecognizer()
    monkeypatch.setattr(
        PipelineOrchestrator,
        "_make_camera_worker",
        lambda self, role, config: ScriptedCamera(role, []),
    )
    pipeline = _build_pipeline(db, detector=detector, recognizer=recognizer)
    pipeline.start()
    try:
        assert detector.warmed_up is True
        assert recognizer.warmed_up is True
    finally:
        pipeline.stop(timeout=2.0)


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


def test_latest_frame_jpeg(db, frame) -> None:
    pytest.importorskip("cv2")
    pipeline = _build_pipeline(db)

    assert pipeline.latest_frame_jpeg("entry") is None

    with pipeline._frame_lock:
        pipeline._latest_frames["entry"] = frame

    encoded = pipeline.latest_frame_jpeg("entry", quality=60)
    assert isinstance(encoded, bytes)
    assert encoded[:2] == b"\xff\xd8", "JPEG SOI marker"


def test_retention_runs_at_startup(db, monkeypatch, frame) -> None:
    calls: list[int] = []
    monkeypatch.setattr(
        LogRepository, "purge_older_than", lambda self, days: calls.append(days) or 0
    )
    monkeypatch.setattr(
        PipelineOrchestrator,
        "_make_camera_worker",
        lambda self, role, config: ScriptedCamera(role, []),
    )

    pipeline = _build_pipeline(db)
    pipeline.start()
    try:
        deadline = time.monotonic() + 3.0
        while not calls and time.monotonic() < deadline:
            time.sleep(0.02)
        assert calls == [db.database.log_retention_days]
    finally:
        pipeline.stop(timeout=3.0)
