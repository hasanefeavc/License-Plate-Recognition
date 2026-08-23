"""The recognition pipeline.

This is the object the API and the GUI both drive. It owns, per camera:

* a :class:`~lpr.pipeline.camera.CameraWorker` capture thread, and
* a processing thread that consumes that camera's queue.

and, process-wide, a retention thread that trims the ``logs`` table.

Dependency injection on purpose
-------------------------------
``detector``, ``recognizer``, ``voter`` and ``relay`` arrive as constructor
arguments typed only as the Protocols from :mod:`lpr.contracts`. This module
never imports :mod:`lpr.detect` or :mod:`lpr.ocr`, which means the whole
pipeline can be unit-tested with fakes on a machine that has neither torch
nor easyocr installed. :mod:`lpr.pipeline.factory` is the single place that
wires the real implementations in.

What runs where
---------------
Nothing slow happens on the capture path. The detector only sees every
``detection.frame_stride``-th frame (the main CPU saving), JPEG encoding
happens lazily in :meth:`PipelineOrchestrator.latest_frame_jpeg` when a
viewer actually asks for a frame, and the relay pulse is fire-and-forget.
Subscriber queues are bounded and drop their oldest item when full, so a
slow WebSocket client degrades its own stream instead of stalling
recognition.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import TYPE_CHECKING, Any

from lpr.contracts import (
    Action,
    CameraStatus,
    Detector,
    Frame,
    LprEvent,
    PipelineStats,
    PlateDetection,
    PlateRead,
    Recognizer,
    Relay,
    TrackAwareVoter,
    TrackingDetector,
    Voter,
    utc_now_iso,
)
from lpr.db import LogRepository, PlateRepository, init_db
from lpr.db.connection import close_all as close_thread_connection
from lpr.pipeline.camera import CameraWorker

if TYPE_CHECKING:  # pragma: no cover
    from lpr.config import CameraConfig, Settings

logger = logging.getLogger(__name__)

#: Bound on every subscriber queue handed out by :meth:`subscribe`.
SUBSCRIBER_QUEUE_SIZE = 256

#: How often the retention thread wakes up (24h).
RETENTION_INTERVAL_S = 24 * 60 * 60

#: How long a processing thread blocks waiting for a frame before looping
#: round to re-check the stop flag.
_FRAME_WAIT_S = 0.5


class PipelineOrchestrator:
    """Runs detection -> OCR -> voting -> gate decision for every camera."""

    def __init__(
        self,
        settings: Settings,
        detector: Detector,
        recognizer: Recognizer,
        voter: Voter,
        relay: Relay,
    ) -> None:
        if settings is None:  # convenience for callers that have no Settings yet
            from lpr.config import get_settings

            settings = get_settings()

        self._settings = settings
        self._detector = detector
        self._recognizer = recognizer
        self._voter = voter
        self._relay = relay

        # Optional capabilities, probed once. A detector that tracks gets one
        # tracker state per camera; a voter that understands tracks gets to
        # veto OCR passes. Anything simpler (a test fake, the contour
        # detector) keeps the original per-frame, text-only behaviour.
        self._tracking_detector: TrackingDetector | None = (
            detector if isinstance(detector, TrackingDetector) else None
        )
        self._track_voter: TrackAwareVoter | None = (
            voter if isinstance(voter, TrackAwareVoter) else None
        )

        # Live vote telemetry -> the same fan-out the decisions use, so the GUI
        # can watch a plate accumulate votes instead of only seeing the verdict.
        # Only wired when the voter offers the hook; anything else is untouched.
        if hasattr(voter, "on_vote"):
            voter.on_vote = self.publish_telemetry

        self._plates = PlateRepository()
        self._logs = LogRepository()

        self._cameras: dict[str, CameraWorker] = {}
        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()
        self._lifecycle_lock = threading.RLock()
        self._running = False

        self._frame_lock = threading.Lock()
        self._latest_frames: dict[str, Frame] = {}

        self._subscriber_lock = threading.Lock()
        self._subscribers: list[queue.Queue[LprEvent]] = []
        self._telemetry_subscribers: list[queue.Queue[LprEvent]] = []

        self._cooldown_lock = threading.Lock()
        #: (camera, plate) -> monotonic timestamp of the last logged decision
        self._cooldowns: dict[tuple[str, str], float] = {}

        self._stats_lock = threading.Lock()
        self._stats = PipelineStats()

        self._min_confidence = float(settings.ocr.min_confidence)
        self._frame_stride = max(1, int(settings.detection.frame_stride))
        self._cooldown_s = max(0.0, float(settings.voting.cooldown_s))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start every thread. Idempotent: a second call is a no-op."""
        with self._lifecycle_lock:
            if self._running:
                logger.debug("Pipeline already running")
                return

            init_db()
            self._stop_event.clear()
            self._warmup()

            for role, camera_config in self._camera_configs():
                worker = self._make_camera_worker(role, camera_config)
                self._cameras[role] = worker
                worker.start()

                processor = threading.Thread(
                    target=self._process_camera,
                    args=(role,),
                    name=f"process-{role}",
                    daemon=True,
                )
                processor.start()
                self._threads.append(processor)

            retention = threading.Thread(
                target=self._retention_loop, name="log-retention", daemon=True
            )
            retention.start()
            self._threads.append(retention)

            with self._stats_lock:
                self._stats.started_at = time.time()
            self._running = True
            logger.info("Pipeline started with cameras: %s", ", ".join(self._cameras))

    def stop(self, timeout: float = 5.0) -> None:
        """Stop everything and join every thread. Idempotent."""
        with self._lifecycle_lock:
            if not self._running and not self._threads and not self._cameras:
                return

            logger.info("Pipeline stopping")
            self._stop_event.set()

            deadline = time.monotonic() + max(0.0, timeout)

            for worker in self._cameras.values():
                worker.stop(timeout=max(0.0, deadline - time.monotonic()))

            for thread in self._threads:
                if thread is threading.current_thread():
                    continue
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
                if thread.is_alive():
                    logger.warning("Thread %s did not stop within the timeout", thread.name)

            self._cameras.clear()
            self._threads.clear()
            self._running = False

            try:
                self._relay.close()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Error closing the relay: %s", exc)

            with self._frame_lock:
                self._latest_frames.clear()

            logger.info("Pipeline stopped")

    @property
    def running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def stats(self) -> PipelineStats:
        """A snapshot of the counters plus every camera's current health."""
        cameras: dict[str, CameraStatus] = {
            role: worker.status() for role, worker in self._cameras.items()
        }
        with self._stats_lock:
            return PipelineStats(
                started_at=self._stats.started_at,
                plates_read=self._stats.plates_read,
                grants=self._stats.grants,
                denials=self._stats.denials,
                ocr_skipped=self._stats.ocr_skipped,
                cameras=cameras,
            )

    def camera_roles(self) -> list[str]:
        return list(self._cameras)

    def latest_frame_jpeg(self, camera: str, quality: int = 80) -> bytes | None:
        """JPEG-encode the newest frame for ``camera``, or None if there is none.

        Encoding happens here, on the *caller's* thread (an API request or an
        MJPEG streaming task), never on the capture or processing threads.
        A viewer that is not watching costs nothing.
        """
        frame = self.latest_frame(camera)
        if frame is None:
            return None
        try:
            import cv2
        except ImportError:  # pragma: no cover - opencv missing
            logger.warning("Cannot encode frames: opencv is not installed")
            return None
        try:
            ok, buffer = cv2.imencode(
                ".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), int(quality)]
            )
        except Exception as exc:
            logger.warning("JPEG encoding failed for camera %s: %s", camera, exc)
            return None
        if not ok:
            return None
        return bytes(buffer)

    def latest_frame(self, camera: str) -> Frame | None:
        """The newest raw frame for ``camera`` (no copy, do not mutate it)."""
        with self._frame_lock:
            frame = self._latest_frames.get(camera)
        if frame is not None:
            return frame
        worker = self._cameras.get(camera)
        return worker.latest() if worker is not None else None

    # ------------------------------------------------------------------
    # Event fan-out
    # ------------------------------------------------------------------

    def subscribe(self, telemetry: bool = False) -> queue.Queue[LprEvent]:
        """Register a new listener and return its own bounded event queue.

        The queue holds at most :data:`SUBSCRIBER_QUEUE_SIZE` events and
        drops its oldest entry when full, so a client that stops reading
        loses history but never applies back-pressure to the pipeline.

        Two separate streams, on purpose:

        * the default one carries :class:`~lpr.contracts.LprEvent` decisions
          only -- every one of them is also a row in the ``logs`` table;
        * ``telemetry=True`` carries plain dicts describing things that are
          *happening* (a plate read, a vote gaining ground) and are never
          recorded.

        Mixing them would force every existing consumer to type-check each
        item before touching ``.plate``, so they stay apart.
        """
        q: queue.Queue[LprEvent] = queue.Queue(maxsize=SUBSCRIBER_QUEUE_SIZE)
        with self._subscriber_lock:
            if telemetry:
                self._telemetry_subscribers.append(q)
            else:
                self._subscribers.append(q)
        logger.debug(
            "Subscriber added (%d events, %d telemetry)",
            len(self._subscribers),
            len(self._telemetry_subscribers),
        )
        return q

    def unsubscribe(self, q: queue.Queue[LprEvent]) -> None:
        """Remove a listener from whichever stream it is on. Idempotent."""
        with self._subscriber_lock:
            removed = False
            for group in (self._subscribers, self._telemetry_subscribers):
                try:
                    group.remove(q)
                    removed = True
                except ValueError:
                    continue
            if not removed:
                return
        logger.debug(
            "Subscriber removed (%d events, %d telemetry)",
            len(self._subscribers),
            len(self._telemetry_subscribers),
        )

    def publish_telemetry(self, payload: dict) -> None:
        """Fan out a non-decision event: a plate read, or a vote in progress.

        Goes only to ``subscribe(telemetry=True)`` listeners, so a consumer of
        the decision stream never has to deal with these. Never raises: this
        is called from the recognition path and from inside the voter.
        """
        if not isinstance(payload, dict):
            return
        payload.setdefault("ts", utc_now_iso())
        with self._subscriber_lock:
            subscribers = list(self._telemetry_subscribers)
        self._fan_out(subscribers, payload)

    def publish(self, event: LprEvent) -> None:
        """Fan a decision out to every subscriber, dropping oldest when full."""
        with self._subscriber_lock:
            subscribers = list(self._subscribers)
        self._fan_out(subscribers, event)

    @staticmethod
    def _fan_out(subscribers: list, event: Any) -> None:
        """Put ``event`` on every queue, evicting the oldest entry when full."""
        for q in subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                try:
                    q.get_nowait()
                except queue.Empty:  # pragma: no cover - raced with the consumer
                    pass
                try:
                    q.put_nowait(event)
                except queue.Full:  # pragma: no cover - raced with another producer
                    logger.debug("Subscriber queue still full; event dropped")

    # ------------------------------------------------------------------
    # Worker construction (overridable for tests)
    # ------------------------------------------------------------------

    def _camera_configs(self) -> list[tuple[str, CameraConfig]]:
        cameras = self._settings.cameras
        return [("entry", cameras.entry), ("exit", cameras.exit)]

    def _make_camera_worker(self, role: str, config: CameraConfig) -> CameraWorker:
        """Build one capture worker.

        Split out as a method purely so tests can substitute a fake capture
        source without touching OpenCV or a real device.
        """
        return CameraWorker(role, config, motion=self._settings.cameras.motion)

    def _warmup(self) -> None:
        for component in (self._detector, self._recognizer):
            warmup = getattr(component, "warmup", None)
            if warmup is None:
                continue
            try:
                warmup()
            except Exception as exc:
                logger.warning("Warmup failed for %r: %s", component, exc)

    # ------------------------------------------------------------------
    # Processing
    # ------------------------------------------------------------------

    def _process_camera(self, role: str) -> None:
        """One thread per camera: pull frames, detect, recognise, decide."""
        worker = self._cameras[role]
        frame_index = 0
        logger.info("Processing thread for camera %s started", role)

        try:
            while not self._stop_event.is_set():
                frame = worker.read(timeout=_FRAME_WAIT_S)
                if frame is None:
                    continue

                with self._frame_lock:
                    self._latest_frames[role] = frame

                frame_index += 1
                if frame_index % self._frame_stride != 0:
                    continue

                try:
                    self.process_frame(role, frame)
                except Exception:
                    # A failure on one frame must never take the camera down.
                    logger.exception("Error processing a frame from camera %s", role)
        finally:
            close_thread_connection()
            logger.info("Processing thread for camera %s stopped", role)

    def process_frame(self, camera: str, frame: Frame) -> list[LprEvent]:
        """Run one frame end to end. Returns the events it produced.

        Exposed (rather than inlined into the loop) so tests can drive the
        pipeline deterministically without threads.
        """
        events: list[LprEvent] = []
        detections = self._detect(camera, frame)
        if not detections:
            return events

        for detection in detections:
            track_id = getattr(detection, "track_id", None)

            # The expensive call in this loop is OCR. A plate whose track has
            # already opened the gate (or has proved unreadable) is skipped
            # here, before that cost is paid, instead of being recognised again
            # on every frame for as long as the car sits under the camera.
            if self._track_voter is not None and not self._track_voter.should_recognize(
                camera, track_id
            ):
                logger.debug(
                    "Camera %s: track %s already settled, skipping OCR", camera, track_id
                )
                with self._stats_lock:
                    self._stats.ocr_skipped += 1
                continue

            read = self._recognizer.recognize(detection.crop)
            if self._track_voter is not None:
                self._track_voter.note_recognized(camera, track_id)
            if not read.is_usable:
                logger.debug("Camera %s: unusable read %r", camera, read.raw_text)
                continue
            if read.confidence < self._min_confidence:
                logger.debug(
                    "Camera %s: %s below min_confidence (%.2f < %.2f)",
                    camera,
                    read.text,
                    read.confidence,
                    self._min_confidence,
                )
                continue

            with self._stats_lock:
                self._stats.plates_read += 1

            # A usable read is worth showing live even before it is confirmed:
            # this is what makes the GUI feed react as a car arrives rather
            # than only when the barrier moves.
            self.publish_telemetry(
                {
                    "kind": "read",
                    "camera": camera,
                    "plate": read.text,
                    "confidence": round(read.confidence, 4),
                    "raw_text": read.raw_text,
                    "track_id": track_id,
                }
            )

            confirmed = self._submit(camera, read, track_id)
            if not confirmed:
                continue

            event = self.decide(camera, confirmed, read.confidence)
            if event is not None:
                events.append(event)
                if self._track_voter is not None:
                    self._track_voter.note_decision(camera, track_id, confirmed)

        return events

    # -- optional-capability shims --------------------------------------

    def _detect(self, camera: str, frame: Frame) -> list[PlateDetection]:
        """Detect, giving each camera its own tracker state where supported."""
        if self._tracking_detector is not None:
            return self._tracking_detector.detect_tracked(frame, camera)
        return self._detector.detect(frame)

    def _submit(
        self, camera: str, read: PlateRead, track_id: int | None
    ) -> str | None:
        """Submit a read to the voter, with its track id when it understands one."""
        if self._track_voter is not None:
            return self._track_voter.submit(camera, read, track_id)
        return self._voter.submit(camera, read)

    def decide(self, camera: str, plate: str, confidence: float = 0.0) -> LprEvent | None:
        """Act on a confirmed plate: open the gate or refuse, then record it.

        Returns the event that was produced, or the cooldown event when the
        same plate is still inside its ``voting.cooldown_s`` window.
        """
        key = (camera, plate)
        now = time.monotonic()

        with self._cooldown_lock:
            last = self._cooldowns.get(key)
            in_cooldown = last is not None and (now - last) < self._cooldown_s
            if not in_cooldown:
                self._cooldowns[key] = now

        if in_cooldown:
            # Debug only, and deliberately not written to the logs table: a
            # car idling under the camera would otherwise add a row per
            # confirmation for as long as it sits there.
            logger.debug("Camera %s: %s still in cooldown, suppressed", camera, plate)
            event = LprEvent(
                ts=utc_now_iso(),
                camera=camera,
                plate=plate,
                action=str(Action.COOLDOWN),
                confidence=confidence,
            )
            self.publish(event)
            return event

        try:
            registered = self._plates.is_registered(plate)
        except Exception:
            logger.exception("Plate lookup failed for %s", plate)
            return self._record(camera, plate, Action.ERROR, confidence)

        if registered:
            try:
                # Non-blocking by contract: the pulse happens on the relay's
                # own worker thread, so this returns in microseconds.
                self._relay.trigger()
            except Exception:
                logger.exception("Relay trigger failed for %s", plate)
            with self._stats_lock:
                self._stats.grants += 1
            logger.info("Camera %s: %s registered, gate opened", camera, plate)
            return self._record(camera, plate, Action.GRANTED, confidence)

        with self._stats_lock:
            self._stats.denials += 1
        logger.info("Camera %s: %s not registered, denied", camera, plate)
        return self._record(camera, plate, Action.DENIED, confidence)

    def _record(
        self, camera: str, plate: str, action: Action, confidence: float
    ) -> LprEvent:
        """Persist one decision and fan it out to subscribers."""
        event = LprEvent(
            ts=utc_now_iso(),
            camera=camera,
            plate=plate,
            action=str(action),
            confidence=confidence,
        )
        try:
            row_id = self._logs.write(event)
            event = LprEvent(
                ts=event.ts,
                camera=event.camera,
                plate=event.plate,
                action=event.action,
                confidence=event.confidence,
                id=row_id,
            )
        except Exception:
            logger.exception("Could not write log row for %s", plate)

        self.publish(event)
        return event

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------

    def _retention_loop(self) -> None:
        """Purge old log rows now, then once a day.

        Runs on its own thread so the (potentially slow) first delete does
        not delay startup, and uses ``Event.wait`` so ``stop()`` interrupts
        it immediately instead of after up to 24 hours.
        """
        days = int(self._settings.database.log_retention_days)
        try:
            while True:
                try:
                    self._logs.purge_older_than(days)
                except Exception:
                    logger.exception("Log retention pass failed")
                if self._stop_event.wait(RETENTION_INTERVAL_S):
                    break
        finally:
            close_thread_connection()

    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"PipelineOrchestrator(running={self._running}, cameras={list(self._cameras)})"
