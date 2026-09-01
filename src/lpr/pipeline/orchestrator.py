"""The recognition pipeline.

This is the object the API and the GUI both drive. It owns, per camera:

* a :class:`~lpr.pipeline.camera.CameraWorker` capture thread, and
* a processing thread that consumes that camera's queue.

and, process-wide, a snapshot-writer thread and a retention thread that
trims both the ``logs`` table and the snapshot folder.

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
Nothing slow happens on the capture path. Frame enhancement, when it is
enabled, runs here on the processing thread and only on the frames that have
already passed the motion gate and the stride filter. The detector only sees
every ``detection.frame_stride``-th frame (the main CPU saving), JPEG encoding
happens lazily in :meth:`PipelineOrchestrator.latest_frame_jpeg` when a
viewer actually asks for a frame, and the relay pulse is fire-and-forget.
Event snapshots follow the same rule: the decision path only queues the
frame, and :mod:`lpr.pipeline.snapshots` encodes and writes it on its own
thread. Subscriber queues are bounded and drop their oldest item when full,
so a slow WebSocket client degrades its own stream instead of stalling
recognition.
"""

from __future__ import annotations

import inspect
import json
import logging
import queue
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

from lpr.contracts import (
    Action,
    CameraRole,
    CameraStatus,
    Detector,
    Frame,
    LprEvent,
    PipelineStats,
    PlateDetection,
    PlateRead,
    PredicateRecognizer,
    Recognizer,
    Relay,
    TrackAwareVoter,
    TrackingDetector,
    Voter,
    utc_now_iso,
)
from lpr.db import (
    PLATE_BLOCKED,
    PLATE_EXPIRED,
    PLATE_OK,
    PLATE_UNKNOWN,
    LogRepository,
    PlateRepository,
    SystemEventRepository,
    init_db,
)
from lpr.db.connection import close_all as close_thread_connection
from lpr.pipeline.camera import CameraWorker
from lpr.pipeline.snapshots import SnapshotWriter

if TYPE_CHECKING:  # pragma: no cover
    from lpr.config import CameraConfig, Settings

logger = logging.getLogger(__name__)

#: Bound on every subscriber queue handed out by :meth:`subscribe`.
SUBSCRIBER_QUEUE_SIZE = 256

#: How often the retention thread wakes up (24h).
RETENTION_INTERVAL_S = 24 * 60 * 60

#: How often the snapshot size / free-space limits are checked.
#:
#: Far shorter than the daily age-based pass, because the two answer different
#: questions. Age is a policy and a day's granularity is fine for it. Disk
#: pressure is an emergency: a busy site can fill a volume between two daily
#: passes, and when it does, SQLite writes start failing and the gate stops
#: being able to record what it did.
DISK_CHECK_INTERVAL_S = 5 * 60

#: How long a processing thread blocks waiting for a frame before looping
#: round to re-check the stop flag.
_FRAME_WAIT_S = 0.5

#: What the gate log says about each refusal. Every one of these is recorded as
#: ``Action.DENIED``; only the sentence differs. Keeping the distinction in the
#: message rather than in a new ``Action`` value is deliberate -- the ``logs``
#: table's ``action`` column is what ``stats_since`` totals and what the
#: dashboard colours, so a fifth value would quietly stop expired cars being
#: counted as denials and would render unlabelled in the live feed.
#: Verdict for a vehicle the anti-passback rule refuses. Not a
#: ``PlateRepository`` verdict -- the plate is perfectly valid, and that is the
#: point of the rule -- so it is defined here, where the decision is made.
PLATE_PASSBACK = "passback"

_DENIAL_LOG = {
    PLATE_EXPIRED: "EXPIRED, gate kept closed",
    PLATE_BLOCKED: "blocked, denied",
    PLATE_UNKNOWN: "not registered, denied",
    PLATE_PASSBACK: "already inside (anti-passback), denied",
}

#: Notification category per refusal, for :meth:`PipelineOrchestrator._notify_reason`.
#:
#: An expired permit deliberately raises the *same* ``unauthorized`` alert it
#: always did. :meth:`lpr.notify.Notifier.wants` answers False for any category
#: it does not know, so minting an ``expired`` one here would have silently
#: stopped a lapsed resident from alerting anybody -- turning a clearer log
#: line into a missed notification. Splitting the category is a notifier
#: change, with its own config flag, not a side effect of this one.
_NOTIFY_REASON = {
    PLATE_EXPIRED: "unauthorized",
    PLATE_BLOCKED: "blacklisted",
    PLATE_UNKNOWN: "unauthorized",
    # A registered vehicle refused for coming back in without leaving is not a
    # stranger and not blacklisted. It alerts as `unauthorized` because that is
    # the category the notifier knows and an operator filters on; minting a new
    # one would silently send nothing, since `Notifier.wants` answers False for
    # anything it does not recognise.
    PLATE_PASSBACK: "unauthorized",
}


def _accepts_predicate(recognizer: Any) -> bool:
    """True when ``recognizer.recognize`` takes the ``accept`` predicate.

    Probed once, at construction, rather than discovered by catching a
    ``TypeError`` per frame: that would also swallow a genuine ``TypeError``
    raised *inside* a recogniser and quietly downgrade the site to the slow
    path for the rest of its uptime.
    """
    try:
        return "accept" in inspect.signature(recognizer.recognize).parameters
    except (TypeError, ValueError, AttributeError):  # pragma: no cover - exotic callables
        return False


class _FastPathProbe:
    """One detection's early exit, and a record of whether it fired.

    Handed to the recogniser as the ``accept`` predicate. Per-detection rather
    than per-orchestrator on purpose: a camera thread each side of the gate
    runs :meth:`PipelineOrchestrator.process_frame` concurrently, and a flag on
    the orchestrator would let the entry camera's hit be read as the exit
    camera's. A short-lived object owned by the call has no such race.

    Never raises into the recogniser. A database wobble mid-read must fall back
    to the ordinary path -- which will consult the same repository again a
    moment later, through the code that is allowed to fail loudly -- rather
    than take down the OCR pass it was invited into.
    """

    __slots__ = ("_authorize", "_min_confidence", "fired", "plate")

    def __init__(self, min_confidence: float, authorize: Callable[[str], str]) -> None:
        self._min_confidence = min_confidence
        self._authorize = authorize
        self.fired = False
        self.plate = ""

    def __call__(self, verdict: PlateRead) -> bool:
        if not verdict.is_usable or verdict.confidence < self._min_confidence:
            return False
        try:
            if self._authorize(verdict.text) != PLATE_OK:
                return False
        except Exception:
            logger.debug("Fast-path lookup failed; using the full path", exc_info=True)
            return False
        self.fired = True
        self.plate = verdict.text
        return True


class PipelineOrchestrator:
    """Runs detection -> OCR -> voting -> gate decision for every camera."""

    def __init__(
        self,
        settings: Settings,
        detector: Detector,
        recognizer: Recognizer,
        voter: Voter,
        relay: Relay,
        frame_preprocessor: Callable[[Frame], Frame] | None = None,
        notifier: Any = None,
    ) -> None:
        if settings is None:  # convenience for callers that have no Settings yet
            from lpr.config import get_settings

            settings = get_settings()

        self._settings = settings
        self._detector = detector
        self._recognizer = recognizer
        self._voter = voter
        self._relay = relay
        #: Optional whole-frame enhancement, applied on the processing thread
        #: just before detection. Injected by :mod:`lpr.pipeline.factory` so
        #: this module keeps its "imports nothing from lpr.detect" property.
        self._frame_preprocessor = frame_preprocessor
        #: Optional e-mail alerting. Injected rather than constructed here so
        #: this module keeps no knowledge of SMTP, and so the tests can assert
        #: on what would have been sent.
        self._notifier = notifier

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

        # Fast path. Armed by `voting.fast_path_enabled`; a legacy top-level
        # `fast_path:` section is folded onto `voting` by Settings, so there is
        # one value to read here rather than two that can disagree.
        voting = settings.voting
        self._fast_path_enabled = bool(getattr(voting, "fast_path_enabled", False))
        # Floored at ocr.min_confidence: opening the gate on a read the
        # ordinary path would have thrown away is an accuracy regression, not
        # an optimisation, and the two thresholds are set in different files by
        # different people.
        self._fast_path_min_confidence = max(
            float(getattr(voting, "fast_path_confidence", 1.0)),
            float(settings.ocr.min_confidence),
        )
        # Whether the early exit can also skip the *OCR ladder*, which needs
        # the recogniser to understand the `accept` predicate. A test double or
        # a third-party engine implementing only the bare `Recognizer` protocol
        # does not, and must keep working unchanged -- it simply reads the crop
        # to the end and gets the whitelist check afterwards instead, which is
        # the half of the fast path that actually opens the gate early.
        self._fast_path_probes = self._fast_path_enabled and _accepts_predicate(recognizer)
        if self._fast_path_enabled:
            logger.info(
                "Fast-path enabled: a registered plate read at >= %.2f opens the "
                "gate on its first frame (OCR ladder short-circuit: %s)",
                self._fast_path_min_confidence,
                "on" if self._fast_path_probes else "off",
            )

        self._plates = PlateRepository()
        self._logs = LogRepository()
        self._system_events = SystemEventRepository()

        # Evidence retention. Built here (so it is available to tests that
        # never call start()), started and stopped with the pipeline.
        snapshots = settings.snapshots
        self._snapshots = SnapshotWriter(
            settings.paths.snapshots_dir,
            quality=snapshots.jpeg_quality,
            queue_size=snapshots.queue_size,
            retention_days=snapshots.retention_days,
            enabled=snapshots.enabled,
            # getattr: an older config.yaml without the pressure keys keeps the
            # previous age-only behaviour rather than failing to start.
            max_total_bytes=int(getattr(snapshots, "max_total_bytes", 0)),
            min_free_bytes=int(getattr(snapshots, "min_free_bytes", 0)),
            on_pressure=self._on_disk_pressure,
        )

        self._cameras: dict[str, CameraWorker] = {}
        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()
        #: Set = inference and gate decisions are suspended. Capture keeps
        #: running so the live view stays available and so resuming is
        #: instant; only the expensive, side-effecting half is gated. Used by
        #: the operator's pause button *and* by the licence watchdog.
        self._pause_event = threading.Event()
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
        #: Cap on OCR passes per frame. 0 = unlimited. See DetectionConfig.
        self._max_ocr_candidates = max(0, int(getattr(settings.detection, "max_ocr_candidates", 0)))
        self._cooldown_s = max(0.0, float(settings.voting.cooldown_s))

        # Anti-passback. getattr so an older config.yaml without the section
        # keeps the previous behaviour instead of failing to start.
        self._passback = getattr(settings, "anti_passback", None)
        if self._passback is not None and not getattr(self._passback, "enabled", False):
            # One representation of "off", so nothing downstream has to ask the
            # question twice and get two different answers.
            self._passback = None
        if self._passback is not None:
            exit_fitted = bool(getattr(settings.cameras.exit, "enabled", False))
            if not exit_fitted:
                logger.warning(
                    "anti_passback.enabled is on but no exit camera is fitted. "
                    "No exit will ever be recorded, so every vehicle would look "
                    "permanently inside and its second visit would be refused. "
                    "The rule is being disabled; fit cameras.exit or turn it off."
                )
                self._passback = None
            else:
                logger.info(
                    "Anti-passback active: a vehicle inside for less than %.0f min "
                    "cannot re-enter without an exit (%d exempt plate(s))",
                    float(getattr(self._passback, "window_s", 0)) / 60.0,
                    len(getattr(self._passback, "exempt", ()) or ()),
                )

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
            self._snapshots.start()
            self._start_notifier()
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

            # After the processing threads are joined, so nothing can queue
            # a snapshot while the writer is draining. Given a floor of its
            # own rather than whatever is left of the budget: shutting down
            # should not routinely discard the last image of the day.
            self._snapshots.stop(timeout=max(0.5, deadline - time.monotonic()))
            self._stop_notifier()

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
    # Pause / resume
    # ------------------------------------------------------------------

    def pause(self) -> None:
        """Suspend detection, OCR and gate decisions. Idempotent.

        Frames keep being captured and published (the operator can still see
        the cameras), but nothing is inferred, no relay is triggered and no
        decision is written. This is what an expired licence halts, and it is
        deliberately not ``stop()``: threads stay alive so a new key resumes
        processing without a restart.
        """
        if not self._pause_event.is_set():
            self._pause_event.set()
            logger.info("Pipeline paused: detection and relay suspended")

    def resume(self) -> None:
        """Undo :meth:`pause`. Idempotent."""
        if self._pause_event.is_set():
            self._pause_event.clear()
            logger.info("Pipeline resumed")

    @property
    def paused(self) -> bool:
        return self._pause_event.is_set()

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
                fast_path_hits=self._stats.fast_path_hits,
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
        """The newest raw frame for ``camera`` (no copy, do not mutate it).

        Read from the **capture** worker first, which updates on every frame
        it pulls off the device, at the full capture rate.
        ``self._latest_frames`` is written by the processing thread and only
        ever holds frames that got past the motion gate, so preferring it --
        as this method used to -- silently pinned the live preview to the
        inference path: on a still scene the gate passes one frame every
        ``motion.heartbeat_s`` (3 s by default), and the viewer watched a
        0.3 FPS slideshow that only came alive when something moved. Worse,
        anything that stalled the processing thread froze the preview with it,
        which is what made a slow OCR pass look like a dead camera.

        The fallback is kept for the pipeline driven without capture threads:
        tests and any caller invoking :meth:`process_frame` directly have no
        worker to read from.
        """
        worker = self._cameras.get(camera)
        if worker is not None:
            frame = worker.latest()
            if frame is not None:
                return frame
        with self._frame_lock:
            return self._latest_frames.get(camera)

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
        """The camera roles that will actually get a capture thread.

        Two roles are filtered out here rather than left to fail at open time:

        * **unfitted** -- ``source`` is blank. The single-camera setup is the
          common one, and a blank source is how it is expressed. Spawning a
          worker for it produces nothing but a "could not open source ''"
          warning every ``reconnect_delay_s`` forever.
        * **colliding** -- two roles naming the same physical device. V4L2
          gives exclusive access to one opener; the loser gets
          ``VIDIOC_QBUF: Bad file descriptor`` and reconnects forever, and
          which of the two loses depends on thread scheduling, so the symptom
          moves between cameras run to run. ``entry: "/dev/video0"`` with
          ``exit: "0"`` is the same webcam spelled two ways -- see
          :attr:`~lpr.config.CameraConfig.device_key`.

        The first role naming a device keeps it, so the order below (entry,
        then exit) decides the winner deterministically.
        """
        cameras = self._settings.cameras
        selected: list[tuple[str, CameraConfig]] = []
        claimed: dict[str, str] = {}

        for role, config in (("entry", cameras.entry), ("exit", cameras.exit)):
            if not config.enabled:
                logger.info(
                    "Camera %s has no source configured; skipping it", role
                )
                continue

            key = config.device_key
            owner = claimed.get(key) if key is not None else None
            if owner is not None:
                logger.warning(
                    "Camera %s (source %r) is the same device as camera %s "
                    "(source %r); skipping %s. Two capture threads cannot share "
                    "one V4L2 device -- give each role its own camera, or leave "
                    "one source blank.",
                    role,
                    config.source,
                    owner,
                    getattr(cameras, owner).source,
                    role,
                )
                continue

            if key is not None:
                claimed[key] = role
            selected.append((role, config))

        if not selected:
            logger.warning(
                "No usable camera sources configured; the pipeline will run "
                "without capture"
            )
        return selected

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

                if self._pause_event.is_set():
                    # Paused (operator, or an invalid licence): the frame is
                    # still published for the live view, but it costs nothing
                    # further -- no detector, no OCR, no relay.
                    continue

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
        if self._pause_event.is_set():
            # Also checked here, not only in the loop: process_frame() is
            # public and is what the tests and any future caller drive.
            return events

        # Detection (and therefore every crop cut out of it) runs on the
        # enhanced frame; `frame` itself stays untouched, so the live view and
        # the snapshot written further down remain what the camera saw.
        detections = self._detect(camera, self._prepare_frame(frame))
        if not detections:
            return events

        # OCR is the expensive stage -- hundreds of milliseconds per crop on
        # CPU -- and its cost is linear in the number of boxes the detector
        # returned. A frame holding a real plate needs one or two passes; a
        # frame yielding a dozen candidates means the detector is firing on
        # things that are not plates, and reading all of them is what turns a
        # slow frame into a pipeline that never catches up. Take the
        # best-scoring few and drop the tail.
        if self._max_ocr_candidates and len(detections) > self._max_ocr_candidates:
            detections = sorted(
                detections, key=lambda d: float(getattr(d, "confidence", 0.0)), reverse=True
            )[: self._max_ocr_candidates]
            logger.debug(
                "Camera %s: capped OCR at the %d best candidates",
                camera,
                self._max_ocr_candidates,
            )

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

            # The probe is what turns the OCR ladder into an early exit: the
            # recogniser stops the moment its running vote is a registered
            # plate read confidently enough, instead of computing the enhanced
            # views that exist to rescue crops this one did not need.
            probe = (
                _FastPathProbe(self._fast_path_min_confidence, self._plates.authorization)
                if self._fast_path_probes
                else None
            )
            if probe is not None:
                # Narrowed rather than duck-typed: `_accepts_predicate` proved
                # at construction that this recogniser takes the predicate.
                read = cast(PredicateRecognizer, self._recognizer).recognize(
                    detection.crop, accept=probe
                )
            else:
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

            # The probe only gets a say while the ladder is still running, and
            # a recogniser that takes no predicate never consults it at all.
            # Re-asking on the finished read is what makes "registered plate,
            # confident read, open on frame 1" hold for every recogniser
            # rather than only for the one that was handed a predicate.
            fast_plate = (
                probe.plate
                if probe is not None and probe.fired
                else self._probe_fast_path(read)
            )

            confirmed: str | None
            if fast_plate:
                # The multi-frame vote is skipped, not merely won early: this
                # plate is on the list and was read cleanly, so the frames the
                # voter would spend agreeing with itself are latency at a
                # barrier with a car sitting in front of it. `probe.plate` is
                # the exact string that was authorised -- identical to
                # `read.text` by construction, since the vote it accepted is
                # the vote the recogniser then returned, but acting on the
                # string that actually cleared the whitelist keeps that
                # equivalence from being load-bearing.
                with self._stats_lock:
                    self._stats.fast_path_hits += 1
                logger.debug(
                    "Camera %s: %s cleared the fast path at %.2f",
                    camera,
                    fast_plate,
                    read.confidence,
                )
                confirmed = fast_plate
            else:
                confirmed = self._submit(camera, read, track_id)
            if not confirmed:
                continue

            event = self.decide(camera, confirmed, read.confidence)
            if event is not None:
                events.append(event)
                self._capture_snapshot(camera, event, frame)
                if self._track_voter is not None:
                    self._track_voter.note_decision(camera, track_id, confirmed)

        return events

    def _probe_fast_path(self, read: PlateRead) -> str:
        """The plate in ``read`` if it clears the early exit, else ``""``.

        Runs the same :class:`_FastPathProbe` the recogniser would have been
        handed, so a hit recorded here is indistinguishable from one recorded
        mid-ladder: same confidence floor, same ``authorization`` call, same
        failure policy when the database wobbles.

        Cheap by construction -- the probe returns on the confidence check
        before it touches the database, so an ordinary sub-threshold read
        costs one float comparison.
        """
        if not self._fast_path_enabled:
            return ""
        probe = _FastPathProbe(
            self._fast_path_min_confidence, self._plates.authorization
        )
        return probe.plate if probe(read) else ""

    def _capture_snapshot(self, camera: str, event: LprEvent, frame: Frame) -> None:
        """Queue the frame behind one decision as evidence.

        Cooldown events are skipped on purpose: a car idling under the camera
        re-confirms its plate on every pass, and photographing each one would
        fill the disk with the same bumper. Refusals *are* photographed --
        an unregistered vehicle at the barrier is exactly what an operator
        goes looking for afterwards.
        """
        if event.action == str(Action.COOLDOWN):
            return

        # A refusal may also be worth an e-mail. The alert wants the snapshot
        # attached, so it is dispatched from the writer's completion callback
        # rather than from here -- that way it carries the very file that was
        # written instead of a second encode of the same frame.
        reason = self._notify_reason(event)
        on_saved = None
        if reason is not None:
            on_saved = lambda path: self._send_notification(event, reason, path)  # noqa: E731

        queued = self._snapshots.submit(
            event.plate, frame, camera=camera, on_saved=on_saved
        )
        if reason is not None and not queued:
            # Snapshots are off, or the disk is behind. The alert still goes
            # out; it just goes out without a photograph, which is far better
            # than staying silent about a refused vehicle.
            self._send_notification(event, reason, None)

    def _notify_reason(self, event: LprEvent) -> str | None:
        """Why this event should raise an alert, or ``None`` for silence.

        ``blacklisted`` outranks ``unauthorized``: a plate that is on the list
        and barred is a different (and usually more urgent) thing than one that
        was never listed, and an operator filtering their inbox needs them
        apart. An expired permit alerts as ``unauthorized``, exactly as it did
        before the gate log learned to name it: see ``_NOTIFY_REASON`` for why
        that is not the same question as what the log line says.
        """
        if self._notifier is None or event.action != str(Action.DENIED):
            return None
        try:
            reason = _NOTIFY_REASON.get(
                self._plates.authorization(event.plate), "unauthorized"
            )
            return reason if self._notifier.wants(reason) else None
        except Exception:
            logger.debug("Bildirim gerekçesi belirlenemedi", exc_info=True)
            return None

    def _send_notification(self, event: LprEvent, reason: str, snapshot: Any) -> None:
        """Hand one alert to the notifier. Never raises into the caller."""
        try:
            from lpr.notify import Notification

            self._notifier.notify(
                Notification(
                    plate=event.plate,
                    camera=event.camera,
                    reason=reason,
                    ts=event.ts,
                    confidence=event.confidence,
                    snapshot=snapshot,
                )
            )
        except Exception:
            logger.warning("Bildirim kuyruğa alınamadı: %s", event.plate, exc_info=True)

    @property
    def snapshots(self) -> SnapshotWriter:
        """The evidence writer, for the API's stats and for tests."""
        return self._snapshots

    # -- optional-capability shims --------------------------------------

    def _prepare_frame(self, frame: Frame) -> Frame:
        """Apply the injected frame preprocessor, if there is one.

        Runs on the per-camera *processing* thread, never on the capture
        thread: the capture loop's only job is to keep draining the camera, and
        anything slow there shows up as dropped frames rather than as latency.
        By the time a frame reaches here it has already survived the motion
        gate and the ``frame_stride`` decimation, so the cost is paid on the
        handful of frames per second that are actually going to be looked at.

        Failures fall back to the original frame -- a preprocessor that throws
        must cost one frame's enhancement, not the frame.
        """
        if self._frame_preprocessor is None:
            return frame
        try:
            enhanced = self._frame_preprocessor(frame)
        except Exception:
            logger.debug("frame preprocessing failed; using the raw frame", exc_info=True)
            return frame
        return enhanced if enhanced is not None else frame

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
        if self._pause_event.is_set():
            # Last line of defence for the gate itself: whatever path reaches
            # a decision while paused, the barrier does not move.
            logger.debug("Camera %s: %s ignored, pipeline paused", camera, plate)
            return None

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
            verdict = self._plates.authorization(plate)
        except Exception:
            logger.exception("Plate lookup failed for %s", plate)
            return self._record(camera, plate, Action.ERROR, confidence)

        if verdict == PLATE_OK and self._passback_refuses(camera, plate):
            # A registered vehicle, refused for coming back in without having
            # left. Handled here rather than inside `authorization` because it
            # is not a property of the plate record -- the same plate is
            # perfectly welcome tomorrow, and at the exit camera right now.
            verdict = PLATE_PASSBACK

        if verdict == PLATE_OK:
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

        # Every remaining verdict keeps the barrier shut. The relay is not
        # touched on any of these paths -- that is the whole point of routing
        # the decision through one branch rather than a chain of ifs that a
        # later edit could thread a `trigger()` back into.
        with self._stats_lock:
            self._stats.denials += 1
        logger.info(
            "Camera %s: %s %s", camera, plate, _DENIAL_LOG.get(verdict, "denied")
        )
        return self._record(camera, plate, Action.DENIED, confidence)

    def _passback_refuses(self, camera: str, plate: str) -> bool:
        """Is this an entry by a vehicle the log says is already inside?

        Four ways to answer no before the database is touched, in the order
        that matters:

        1. **The rule is off**, or an operator has raised the emergency bypass.
        2. **This is not the entry camera.** The check never runs on an exit,
           which is the safety rule the whole feature is built around: a
           vehicle that cannot leave is a vehicle trapped behind a barrier, and
           in a fire that is the failure that matters. Written as a guard here
           rather than as care at the call site, so a future edit to
           :meth:`decide` cannot reach it from the exit path by accident.
        3. **The plate is exempt** -- a service vehicle, the site manager.
        4. **Nothing granted in the window**, or the last grant was an exit.

        A database failure answers *no*. The rule is a refinement on top of an
        already-granted plate, and letting a lookup error close the barrier on
        a resident would trade a rare abuse for a common outage.
        """
        config = self._passback
        if config is None or not getattr(config, "enabled", False):
            return False
        if getattr(config, "emergency_bypass", False):
            logger.debug("Anti-passback bypassed for %s (emergency_bypass)", plate)
            return False
        if str(camera) != CameraRole.ENTRY.value:
            return False
        if plate in (getattr(config, "exempt", frozenset()) or frozenset()):
            logger.debug("Anti-passback: %s is exempt", plate)
            return False

        window = max(1.0, float(getattr(config, "window_s", 0.0)))
        since = (
            datetime.now(timezone.utc) - timedelta(seconds=window)
        ).isoformat(timespec="seconds")

        try:
            last = self._logs.last_granted_camera(plate, since)
        except Exception:
            logger.exception("Anti-passback lookup failed for %s; allowing", plate)
            return False

        if last != CameraRole.ENTRY.value:
            return False

        logger.info(
            "Anti-passback: %s was granted entry within the last %.0f min and has "
            "no recorded exit; refusing re-entry",
            plate,
            window / 60.0,
        )
        return True

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

    def _start_notifier(self) -> None:
        starter = getattr(self._notifier, "start", None)
        if callable(starter):
            try:
                starter()
            except Exception:
                logger.warning("E-posta bildirimleri başlatılamadı", exc_info=True)

    def _stop_notifier(self) -> None:
        stopper = getattr(self._notifier, "stop", None)
        if callable(stopper):
            try:
                stopper()
            except Exception:
                logger.warning("E-posta bildirimleri durdurulamadı", exc_info=True)

    def _retention_loop(self) -> None:
        """Purge old log rows and old snapshots now, then once a day.

        Runs on its own thread so the (potentially slow) first delete does
        not delay startup, and uses ``Event.wait`` so ``stop()`` interrupts
        it immediately instead of after up to 24 hours.

        All three stores are trimmed from this one thread rather than from
        three: they share a cadence, and a single pass keeps a log row and the
        image it refers to expiring together. The system-event trail is on a
        separate, longer clock -- it is a handful of rows a day, and "what did
        the machine do to itself last quarter" outlives "which cars came
        through last week".
        """
        days = int(self._settings.database.log_retention_days)
        event_days = int(
            getattr(getattr(self._settings, "system_update", None), "event_retention_days", 0)
        )
        try:
            next_age_pass = 0.0
            while True:
                now = time.monotonic()
                if now >= next_age_pass:
                    next_age_pass = now + RETENTION_INTERVAL_S
                    try:
                        self._logs.purge_older_than(days)
                    except Exception:
                        logger.exception("Log retention pass failed")
                    try:
                        self._snapshots.purge_older_than()
                    except Exception:
                        logger.exception("Snapshot retention pass failed")
                    try:
                        self._system_events.purge_older_than(event_days)
                    except Exception:
                        logger.exception("System event retention pass failed")

                # Every tick, not once a day: see DISK_CHECK_INTERVAL_S.
                try:
                    self._snapshots.enforce_limits()
                except Exception:
                    logger.exception("Snapshot disk-pressure pass failed")

                if self._stop_event.wait(DISK_CHECK_INTERVAL_S):
                    break
        finally:
            close_thread_connection()

    def _on_disk_pressure(self, source: str, detail: dict[str, Any]) -> None:
        """Record a disk-pressure deletion as a system event and an alert.

        Called from the retention thread when a size or free-space limit
        forced snapshots to be deleted early. Worth escalating rather than
        logging: evidence being dropped before its retention window is up
        means the site is under-provisioned, and the operator only finds out
        when they go looking for an image that is not there.
        """
        try:
            reclaimed_mb = int(detail.get("reclaimed_bytes", 0)) / 1024 / 1024
            free = detail.get("free_bytes")
            free_mb = "bilinmiyor" if free is None else f"{int(free) / 1024 / 1024:.0f} MB"
            message = (
                f"Disk baskisi: {detail.get('deleted', 0)} anlık görüntü silindi "
                f"({reclaimed_mb:.0f} MB), boş alan {free_mb}"
            )
            self._system_events.write(
                source=source,
                message=message,
                level="warning",
                detail=json.dumps(detail, ensure_ascii=False),
            )
        except Exception:
            logger.debug("Disk-pressure system event could not be written", exc_info=True)

    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"PipelineOrchestrator(running={self._running}, cameras={list(self._cameras)})"
