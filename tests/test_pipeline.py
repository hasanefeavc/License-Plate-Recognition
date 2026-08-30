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
from lpr.pipeline import orchestrator as orchestrator_module
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
    notifier: Any = None,
) -> PipelineOrchestrator:
    return PipelineOrchestrator(
        settings=settings,
        detector=detector or FakeDetector(),
        recognizer=recognizer or FakeRecognizer(),
        voter=voter or FakeVoter(),
        relay=relay or FakeRelay(),
        notifier=notifier,
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
# Pause (operator button, and the licence halt)
# ---------------------------------------------------------------------------


def test_pause_stops_detection_and_the_gate(db, frame) -> None:
    """An expired licence halts the pipeline through exactly this path."""
    PlateRepository().add("34ABC123")
    detector = FakeDetector()
    relay = FakeRelay()
    pipeline = _build_pipeline(db, detector=detector, relay=relay)

    pipeline.pause()

    assert pipeline.paused is True
    assert pipeline.process_frame("entry", frame) == []
    assert detector.calls == 0, "a paused pipeline must not pay for inference"
    assert relay.triggers == 0
    assert pipeline.decide("entry", "34ABC123") is None
    assert LogRepository().count_matching() == 0


def test_resume_brings_processing_back(db, frame) -> None:
    PlateRepository().add("34ABC123")
    relay = FakeRelay()
    pipeline = _build_pipeline(db, relay=relay)

    pipeline.pause()
    pipeline.process_frame("entry", frame)
    pipeline.resume()
    events = pipeline.process_frame("entry", frame)

    assert pipeline.paused is False
    assert [e.action for e in events] == [str(Action.GRANTED)]
    assert relay.triggers == 1


def test_pause_and_resume_are_idempotent(db) -> None:
    pipeline = _build_pipeline(db)
    pipeline.pause()
    pipeline.pause()
    assert pipeline.paused is True
    pipeline.resume()
    pipeline.resume()
    assert pipeline.paused is False


def test_a_paused_camera_loop_still_publishes_frames(db, frame) -> None:
    """The live view keeps working while processing is halted."""
    detector = FakeDetector()
    pipeline = _build_pipeline(db, detector=detector)
    pipeline._cameras["entry"] = ScriptedCamera("entry", [frame] * 4)
    pipeline.pause()

    stopper = threading.Thread(target=lambda: (time.sleep(0.4), pipeline._stop_event.set()))
    stopper.start()
    pipeline._process_camera("entry")
    stopper.join()

    assert detector.calls == 0
    assert pipeline.latest_frame("entry") is not None


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


def test_no_second_pulse_during_a_full_sliding_gate_cycle(db, monkeypatch, frame) -> None:
    """A car idling through a 20 s open cycle must produce exactly one pulse.

    This is the sliding-gate failure mode in miniature. The motor uses
    step-by-step logic -- pulse 1 opens, pulse 2 *stops* it mid-travel -- and
    the car sitting under the camera re-confirms on every pass of the pipeline
    for the whole 15-25 s the gate takes to open. Anything that lets a second
    pulse out during that window halts the gate on top of the driver.

    Virtual time, because the point is to cover the *whole* cycle: the
    orchestrator's cooldown reads ``time.monotonic``, so the clock is walked
    forward a second at a time rather than actually waiting.
    """
    settings = db
    settings.voting.cooldown_s = 20.0  # the shipped sliding-gate default
    PlateRepository().add("34ABC123")

    clock = {"now": 1000.0}
    monkeypatch.setattr(orchestrator_module.time, "monotonic", lambda: clock["now"])

    relay = FakeRelay()
    pipeline = _build_pipeline(settings, relay=relay)

    # Second 0: the car arrives and the gate is told to open.
    pipeline.process_frame("entry", frame)
    assert relay.triggers == 1

    # Seconds 1..19: still opening, and the plate is still in frame.
    for _ in range(19):
        clock["now"] += 1.0
        pipeline.process_frame("entry", frame)

    assert relay.triggers == 1, (
        "a second pulse inside the travel window would stop the gate mid-open"
    )

    # Past the cycle the gate is at rest, so re-triggering is legitimate again.
    clock["now"] += 1.5
    pipeline.process_frame("entry", frame)
    assert relay.triggers == 2


def test_a_second_car_is_not_blocked_by_the_first_cars_cooldown(db, monkeypatch) -> None:
    """The cooldown is per plate, not a gate-wide lockout.

    Worth pinning explicitly: it is what makes the window safe to lengthen to
    a sliding gate's travel time without stranding the next vehicle -- and it
    is also the limit of what this setting protects against.
    """
    settings = db
    settings.voting.cooldown_s = 20.0
    pipeline = _build_pipeline(settings)

    assert pipeline.decide("entry", "34ABC123").action == str(Action.DENIED)
    assert pipeline.decide("entry", "34ABC123").action == str(Action.COOLDOWN)
    assert pipeline.decide("entry", "06MNP99").action == str(Action.DENIED)


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


# ---------------------------------------------------------------------------
# E-mail notification wiring
# ---------------------------------------------------------------------------


class RecordingNotifier:
    """Stands in for ``lpr.notify.EmailNotifier`` at the pipeline boundary."""

    def __init__(self, wanted: tuple[str, ...] = ("unauthorized", "blacklisted")) -> None:
        self.wanted = set(wanted)
        self.sent: list[Any] = []
        self.started = False
        self.stopped = False

    def wants(self, reason: str) -> bool:
        return reason in self.wanted

    def notify(self, notification: Any) -> bool:
        self.sent.append(notification)
        return True

    def start(self) -> None:
        self.started = True

    def stop(self, timeout: float = 5.0) -> None:
        self.stopped = True

    @property
    def reasons(self) -> list[str]:
        return [item.reason for item in self.sent]


def test_a_refused_vehicle_raises_an_unauthorized_alert(db, frame) -> None:
    notifier = RecordingNotifier()
    pipeline = _build_pipeline(db, notifier=notifier)

    pipeline.process_frame("entry", frame)  # plate is not registered

    assert notifier.reasons == ["unauthorized"]
    assert notifier.sent[0].plate == "34ABC123"
    assert notifier.sent[0].camera == "entry"


def test_a_blocked_plate_raises_a_blacklisted_alert(db, frame) -> None:
    """On the list and barred is a different event from never listed."""
    PlateRepository().upsert("34ABC123", blocked=True)
    notifier = RecordingNotifier()
    pipeline = _build_pipeline(db, notifier=notifier)

    pipeline.process_frame("entry", frame)

    assert notifier.reasons == ["blacklisted"]


def test_an_authorised_vehicle_raises_no_alert(db, frame) -> None:
    """The alert is about refusals; a resident arriving is not news."""
    PlateRepository().add("34ABC123")
    notifier = RecordingNotifier()
    pipeline = _build_pipeline(db, notifier=notifier)

    pipeline.process_frame("entry", frame)

    assert notifier.sent == []


def test_an_expired_permit_is_refused(db, frame) -> None:
    """`expires_at` is an access rule, not decoration on the resident list."""
    PlateRepository().upsert("34ABC123", expires_at="2020-01-01T00:00:00+00:00")
    notifier = RecordingNotifier()
    relay = FakeRelay()
    pipeline = _build_pipeline(db, relay=relay, notifier=notifier)

    pipeline.process_frame("entry", frame)

    assert relay.triggers == 0, "an expired permit must not open the gate"
    assert notifier.reasons == ["unauthorized"]


def test_a_disinterested_notifier_is_not_called(db, frame) -> None:
    """`notify_on_unauthorized: false` must cost nothing, not send and discard."""
    notifier = RecordingNotifier(wanted=("blacklisted",))
    pipeline = _build_pipeline(db, notifier=notifier)

    pipeline.process_frame("entry", frame)

    assert notifier.sent == []


def test_a_failing_notifier_does_not_break_the_decision(db, frame) -> None:
    """The gate decision is already made, logged and photographed by this point."""

    class ExplodingNotifier(RecordingNotifier):
        def notify(self, notification: Any) -> bool:
            raise RuntimeError("smtp exploded")

    pipeline = _build_pipeline(db, notifier=ExplodingNotifier())
    events = pipeline.process_frame("entry", frame)

    assert [e.action for e in events] == [str(Action.DENIED)]
    assert LogRepository().count_matching() == 1


def test_no_notifier_is_the_normal_case(db, frame) -> None:
    """The default pipeline has none, and must not reference one."""
    pipeline = _build_pipeline(db)
    assert [e.action for e in pipeline.process_frame("entry", frame)] == [str(Action.DENIED)]


def test_a_cooldown_repeat_does_not_re_alert(db, monkeypatch, frame) -> None:
    """A car idling at the gate is one e-mail, not one per frame."""
    monkeypatch.setattr(db.voting, "cooldown_s", 60.0)
    notifier = RecordingNotifier()
    pipeline = _build_pipeline(db, notifier=notifier)

    for _ in range(4):
        pipeline.process_frame("entry", frame)

    assert len(notifier.sent) == 1


# ---------------------------------------------------------------------------
# The capture loop never runs on the caller's thread
# ---------------------------------------------------------------------------


def test_a_camera_that_cannot_open_does_not_block_the_caller(tmp_settings) -> None:
    """An absent /dev/video0 must cost the *worker* time, never the caller.

    `cv2.VideoCapture` on a missing device can take a noticeable moment, and a
    reconnect loop that ran anywhere but its own thread would put that latency
    straight into whatever called it -- an HTTP handler, or the event loop.
    """
    config = tmp_settings.cameras.entry
    config.source = "/dev/definitely-not-a-camera"
    config.reconnect_delay_s = 0.05

    worker = CameraWorker("entry", config)
    started = time.monotonic()
    worker.start()
    start_cost = time.monotonic() - started

    try:
        # start() hands off to the thread; it must not wait for a probe.
        assert start_cost < 0.5, f"start() blocked for {start_cost:.2f}s"

        # And the consumer side stays responsive while the worker retries.
        began = time.monotonic()
        assert worker.read(timeout=0.05) is None
        assert time.monotonic() - began < 0.5
    finally:
        worker.stop(timeout=2)


def test_the_capture_loop_runs_on_the_worker_thread(tmp_settings) -> None:
    """Pins where `_open` is called from, which is the property that matters."""
    config = tmp_settings.cameras.entry
    config.source = "/dev/definitely-not-a-camera"
    config.reconnect_delay_s = 0.05

    worker = CameraWorker("entry", config)
    threads: list[str] = []
    original = worker._open

    def watched():
        threads.append(threading.current_thread().name)
        return original()

    worker._open = watched
    caller = threading.current_thread().name

    worker.start()
    try:
        deadline = time.monotonic() + 2.0
        while not threads and time.monotonic() < deadline:
            time.sleep(0.02)
        assert threads, "the worker never attempted to open the camera"
        assert caller not in threads, "the open ran on the caller's thread"
        assert all(name.startswith("camera-") for name in threads)
    finally:
        worker.stop(timeout=2)


def test_the_worker_is_a_daemon_so_it_cannot_hold_shutdown_open(tmp_settings) -> None:
    worker = CameraWorker("entry", tmp_settings.cameras.entry)
    assert worker.daemon is True


# ---------------------------------------------------------------------------
# Expired permits at the barrier
# ---------------------------------------------------------------------------


def _days_from_now(days: float) -> str:
    """A stored-format UTC timestamp ``days`` from now; negative is the past."""
    from datetime import UTC, datetime, timedelta

    moment = datetime.now(UTC) + timedelta(days=days)
    return moment.replace(microsecond=0).isoformat()


def test_expired_permit_keeps_the_gate_closed(db, frame, caplog) -> None:
    """The bug this file's ``denied`` test could not catch.

    A plate whose permit lapsed is still *on the list* and still unblocked, so
    a membership-only check waves it through: the relay fires and the log says
    "gate opened" for a resident whose access ended yesterday. The assertion
    that matters is ``relay.triggers == 0`` -- the repository returning False
    proves nothing about the barrier, which the orchestrator drives.
    """
    import logging

    PlateRepository().upsert("34ABC123", owner="Ahmet", expires_at=_days_from_now(-1))
    relay = FakeRelay()
    pipeline = _build_pipeline(db, relay=relay)

    with caplog.at_level(logging.INFO, logger="lpr.pipeline.orchestrator"):
        events = pipeline.process_frame("entry", frame)

    assert relay.triggers == 0, "an expired permit must not open the barrier"
    assert [e.action for e in events] == [str(Action.DENIED)]
    assert pipeline.stats().grants == 0
    assert pipeline.stats().denials == 1
    assert LogRepository().recent(10)[0].action == str(Action.DENIED)
    assert "34ABC123 EXPIRED, gate kept closed" in caplog.text


def test_live_permit_still_opens_the_gate(db, frame) -> None:
    """The other side of the boundary: a valid end date is not a refusal."""
    PlateRepository().upsert("34ABC123", expires_at=_days_from_now(1))
    relay = FakeRelay()
    pipeline = _build_pipeline(db, relay=relay)

    events = pipeline.process_frame("entry", frame)

    assert relay.triggers == 1
    assert [e.action for e in events] == [str(Action.GRANTED)]


def _expired_operator(username: str = "bekci") -> None:
    """An account whose *application* licence ran out yesterday."""
    from lpr.db import UserRepository
    from lpr.user_license import STATUS_EXPIRED

    users = UserRepository()
    users.register(username, "parola1234", "operator")
    users.set_license(
        username,
        "eski-anahtar",
        _days_from_now(-1),
        STATUS_EXPIRED,
        duration_days=30,
        activated_at=_days_from_now(-31),
    )


def test_a_lapsed_user_licence_never_closes_the_barrier(db, frame, caplog) -> None:
    """The separation this whole design rests on, asserted at the relay.

    ``users.license_expires_at`` is a subscription to the dashboard and the
    API. The car park is not party to it. A resident whose landlord stopped
    paying for the software must still get through the gate, so the plate row
    alone decides -- and the assertion has to be ``relay.triggers == 1``,
    because the repository returning a verdict proves nothing about the
    barrier the orchestrator drives.
    """
    import logging

    _expired_operator()
    PlateRepository().upsert("34ABC123", owner="Ahmet", username="bekci")
    relay = FakeRelay()
    pipeline = _build_pipeline(db, relay=relay)

    with caplog.at_level(logging.INFO, logger="lpr.pipeline.orchestrator"):
        events = pipeline.process_frame("entry", frame)

    assert relay.triggers == 1, "a registered plate must open the gate"
    assert [e.action for e in events] == [str(Action.GRANTED)]
    assert pipeline.stats().grants == 1
    assert "34ABC123 registered, gate opened" in caplog.text


def test_the_plates_own_expiry_still_decides_for_a_lapsed_users_car(
    db, frame
) -> None:
    """The other half: the *plate's* permit is the one that can refuse.

    Otherwise this pair would pass for the wrong reason -- a gate that opened
    for everything would satisfy the test above.
    """
    _expired_operator()
    PlateRepository().upsert(
        "34ABC123", username="bekci", expires_at=_days_from_now(-1)
    )
    relay = FakeRelay()
    pipeline = _build_pipeline(db, relay=relay)

    events = pipeline.process_frame("entry", frame)

    assert relay.triggers == 0
    assert [e.action for e in events] == [str(Action.DENIED)]


def test_expired_permit_still_alerts_as_unauthorized(db, frame) -> None:
    """Naming the refusal in the log must not silence the notification.

    ``Notifier.wants`` answers False for any category it does not know, so
    routing expired plates to a new ``expired`` reason would have swapped a
    clearer log line for a missed alert. This pins the mapping that keeps the
    existing alert flowing.
    """
    PlateRepository().upsert("34ABC123", expires_at=_days_from_now(-1))
    notifier = RecordingNotifier()
    pipeline = _build_pipeline(db, notifier=notifier)

    pipeline.process_frame("entry", frame)

    assert notifier.reasons == ["unauthorized"]


# ---------------------------------------------------------------------------
# Fast path: the first confident read of a registered plate
# ---------------------------------------------------------------------------


class LadderRecognizer:
    """A recogniser shaped like the real one: cheap first view, costly rest.

    ``views`` counts the OCR passes actually taken, which is the whole point of
    the fast path -- the saving is passes not run, and a test that only checked
    the verdict could not see it. ``accept`` is honoured exactly as
    ``_BaseRecognizer.ballots`` honours it: checked after every view, and the
    ladder stops on the first True.
    """

    def __init__(self, reads: list[Any]) -> None:
        self._reads = list(reads)
        self.views = 0

    def recognize(self, crop: Any, accept: Any = None) -> Any:
        best = self._reads[0]
        for read in self._reads:
            self.views += 1
            best = read
            if accept is not None and accept(best):
                break
        return best

    def warmup(self) -> None:  # pragma: no cover - protocol completeness
        pass


def _read(text: str = "34ABC123", confidence: float = 0.95) -> PlateRead:
    return PlateRead(text=text, confidence=confidence, raw_text=text, valid=True)


def _ladder(text: str = "34ABC123", confidence: float = 0.95) -> LadderRecognizer:
    """Three views, all agreeing. Only the first should ever be needed."""
    return LadderRecognizer([_read(text, confidence)] * 3)


def test_a_registered_plate_opens_the_gate_on_its_first_view(db, frame, caplog) -> None:
    """The saving, asserted where it happens: two OCR passes never run.

    The voter here confirms *nothing* — so an event at all proves the decision
    did not come through the multi-frame path, and `views == 1` proves the
    enhanced views were never computed.
    """
    import logging

    PlateRepository().upsert("34ABC123", owner="Ahmet")
    relay = FakeRelay()
    voter = FakeVoter(confirm=False)
    recognizer = _ladder()
    pipeline = _build_pipeline(db, recognizer=recognizer, voter=voter, relay=relay)

    with caplog.at_level(logging.INFO, logger="lpr.pipeline.orchestrator"):
        events = pipeline.process_frame("entry", frame)

    assert recognizer.views == 1, "the escalation ladder should have stopped at view 1"
    assert [e.action for e in events] == [str(Action.GRANTED)]
    assert relay.triggers == 1
    assert voter.submissions == [], "the fast path must not go through the voter"
    assert pipeline.stats().fast_path_hits == 1
    assert "34ABC123 registered, gate opened" in caplog.text


def test_an_unregistered_plate_still_pays_for_the_whole_ladder(db, frame) -> None:
    """The fast path is for cars that may come in, not for confident reads.

    A stranger at the barrier is exactly the case the enhanced views and the
    multi-frame vote exist for, so nothing about that path may be skipped.
    """
    relay = FakeRelay()
    voter = FakeVoter(confirm=False)
    recognizer = _ladder("99ZZZ99")
    pipeline = _build_pipeline(db, recognizer=recognizer, voter=voter, relay=relay)

    events = pipeline.process_frame("entry", frame)

    assert recognizer.views == 3, "an unknown plate must not exit early"
    assert events == []
    assert relay.triggers == 0
    assert voter.submissions, "the read belongs to the voter, as before"
    assert pipeline.stats().fast_path_hits == 0


def test_a_blocked_plate_never_takes_the_fast_path(db, frame) -> None:
    """`authorization`, not membership. A barred resident is still listed."""
    PlateRepository().upsert("34ABC123", owner="Ahmet", blocked=True)
    relay = FakeRelay()
    recognizer = _ladder()
    pipeline = _build_pipeline(db, recognizer=recognizer, relay=relay)

    events = pipeline.process_frame("entry", frame)

    assert recognizer.views == 3
    assert relay.triggers == 0
    assert [e.action for e in events] == [str(Action.DENIED)]


def test_an_expired_permit_never_takes_the_fast_path(db, frame) -> None:
    """The same, for the other refusal the plate row can carry."""
    PlateRepository().upsert("34ABC123", expires_at=_days_from_now(-1))
    relay = FakeRelay()
    recognizer = _ladder()
    pipeline = _build_pipeline(db, recognizer=recognizer, relay=relay)

    pipeline.process_frame("entry", frame)

    assert recognizer.views == 3
    assert relay.triggers == 0


def test_the_fast_path_can_be_switched_off(db, frame) -> None:
    """A site that wants every read confirmed by several frames keeps that."""
    db.fast_path.enabled = False
    PlateRepository().upsert("34ABC123")
    relay = FakeRelay()
    voter = FakeVoter(confirm=False)
    recognizer = _ladder()
    pipeline = _build_pipeline(db, recognizer=recognizer, voter=voter, relay=relay)

    events = pipeline.process_frame("entry", frame)

    assert recognizer.views == 3
    assert events == [] and relay.triggers == 0
    assert voter.submissions, "with the fast path off, every read goes to the voter"


def test_the_fast_path_cannot_undercut_the_ocr_threshold(db, frame) -> None:
    """A read the ordinary path would discard must not open the gate.

    The two thresholds live in different sections and are set by different
    people; a fast path that accepted a 0.5 read while `ocr.min_confidence`
    said 0.8 would be an accuracy regression wearing the word "optimisation".
    """
    db.fast_path.min_confidence = 0.1
    db.ocr.min_confidence = 0.8
    PlateRepository().upsert("34ABC123")
    relay = FakeRelay()
    recognizer = _ladder(confidence=0.5)
    pipeline = _build_pipeline(db, recognizer=recognizer, relay=relay)

    events = pipeline.process_frame("entry", frame)

    assert recognizer.views == 3, "0.5 is below ocr.min_confidence and must not qualify"
    assert relay.triggers == 0
    assert events == []


def test_a_recogniser_that_never_heard_of_the_fast_path_still_works(db, frame) -> None:
    """The `Recognizer` protocol is one method, and third parties implement it.

    `FakeRecognizer.recognize` takes only a crop. The orchestrator must detect
    that at construction and stay on the ordinary path rather than calling it
    with a keyword it cannot accept.
    """
    PlateRepository().upsert("34ABC123")
    relay = FakeRelay()
    pipeline = _build_pipeline(db, relay=relay)  # the plain FakeRecognizer

    events = pipeline.process_frame("entry", frame)

    assert [e.action for e in events] == [str(Action.GRANTED)]
    assert relay.triggers == 1
    assert pipeline.stats().fast_path_hits == 0


def test_the_fast_path_survives_a_database_wobble(db, frame, monkeypatch) -> None:
    """A failed lookup falls back to the full path instead of killing the read."""
    PlateRepository().upsert("34ABC123")
    recognizer = _ladder()
    voter = FakeVoter(confirm=False)
    pipeline = _build_pipeline(db, recognizer=recognizer, voter=voter)

    def boom(_self: Any, _plate: str) -> str:
        raise RuntimeError("database is busy")

    # Patched on the class: PlateRepository uses __slots__, so the instance
    # cannot carry an override.
    monkeypatch.setattr(PlateRepository, "authorization", boom)

    events = pipeline.process_frame("entry", frame)

    assert recognizer.views == 3, "a lookup failure must not count as a hit"
    assert events == []
