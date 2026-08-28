"""Per-camera capture threads.

The legacy app read both cameras from a single loop::

    ret1, frame1 = cap1.read()
    ret2, frame2 = cap2.read()

so a stalled or reconnecting entry camera froze the exit camera too, and an
RTSP timeout froze the whole application. Here each camera gets its own
:class:`CameraWorker` thread, and the two are completely independent.

The queue between capture and processing is **bounded** with drop-oldest
semantics. A slow consumer (a busy YOLO pass, a GC pause) can therefore never
apply back-pressure to capture; it just misses frames, which for a live feed
is exactly what you want. Dropped frames are counted so the deficit is
visible in :class:`lpr.contracts.CameraStatus` rather than silent.

Motion gating
-------------
A gate camera watches an empty driveway almost all day, and YOLO costs the
same on an empty driveway as it does on a car. :class:`MotionGate` runs a
~0.1 ms frame-difference check on every captured frame and only queues the
ones where something actually moved, which removes the overwhelming majority
of inference passes on a real site. It is deliberately crude: its job is to
answer "is this frame worth 30 ms of GPU time?", not to find plates.

``cv2`` is imported lazily inside the methods that need it so that importing
this module -- and therefore the whole pipeline package -- does not require
OpenCV to be installed.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any

from lpr.contracts import CameraStatus, Frame
from lpr.platform_compat import default_camera_backend

if TYPE_CHECKING:  # pragma: no cover
    from lpr.config import CameraConfig, MotionConfig

logger = logging.getLogger(__name__)

#: How many recent frame intervals feed the rolling FPS estimate.
_FPS_WINDOW = 30

# --- motion gating ---------------------------------------------------------

#: Target width of the image the difference is computed on. The frame is
#: subsampled to roughly this by an integer stride, which is ~15x cheaper than
#: an interpolated ``cv2.resize`` (measured: 0.05 ms vs 1.33 ms on 720p) and
#: plenty for "did a car-sized thing move".
MOTION_WORK_WIDTH = 320

#: Per-pixel brightness change that counts as movement. Below this is sensor
#: noise and compression artefacts.
MOTION_DELTA = 25

#: Weight of the newest frame in the running-average background. Low enough
#: that a car pausing at the barrier stays visible as motion for a few
#: seconds, high enough to absorb dusk, headlights and cloud shadow instead
#: of treating them as permanent movement.
MOTION_BACKGROUND_ALPHA = 0.15

#: Consecutive failures tolerated before the gate switches itself off and
#: lets every frame through. A broken motion check must degrade to "more
#: inference", never to "no detections".
MOTION_MAX_FAILURES = 3


class MotionGate:
    """Decides whether a frame is worth an ML inference pass.

    Cheap by construction, in this order:

    1. subsample by an integer stride to ~``MOTION_WORK_WIDTH`` px and take a
       single channel -- no interpolation, no colour conversion;
    2. blur away sensor noise;
    3. maintain the background with ``cv2.accumulateWeighted`` (a running
       average, not the previous frame: a car that stops mid-approach keeps
       registering as motion instead of vanishing the instant it holds still);
    4. ``absdiff`` + ``threshold`` + ``dilate`` + ``findContours``, and compare
       the largest contour against ``threshold``.

    Contour areas are scaled back to full-frame pixels before the comparison,
    so ``motion.threshold`` means the same thing whatever internal resolution
    the check happens to run at.

    Fails **open**: no OpenCV, an unreadable frame, or repeated errors all
    result in frames being passed through rather than dropped.
    """

    def __init__(
        self,
        threshold: float = 5000.0,
        heartbeat_s: float = 3.0,
        clock: Any = time.monotonic,
    ) -> None:
        self.threshold = max(0.0, float(threshold))
        self.heartbeat_s = max(0.0, float(heartbeat_s))
        self._clock = clock
        self._cv2: Any = None
        self._np: Any = None
        self._kernel: Any = None
        self._available = True
        self._failures = 0
        self._background: Any | None = None
        self._last_pass: float | None = None
        self._last_area = 0.0

    @classmethod
    def from_config(cls, config: MotionConfig) -> MotionGate | None:
        """Build a gate from ``cameras.motion``, or None when it is disabled."""
        if not getattr(config, "enabled", False):
            return None
        return cls(
            threshold=getattr(config, "threshold", 5000),
            heartbeat_s=getattr(config, "heartbeat_s", 3.0),
        )

    @property
    def last_area(self) -> float:
        """Largest moving area of the last checked frame, in full-frame pixels."""
        return self._last_area

    def should_process(self, frame: Frame) -> bool:
        """True if ``frame`` should reach the ML queue.

        Always True for the first frame, for a frame the gate cannot read, and
        once ``heartbeat_s`` has elapsed since the last frame it let through.
        """
        now = self._clock()

        if not self._available:
            self._last_pass = now
            return True

        due_for_heartbeat = (
            self.heartbeat_s > 0.0
            and self._last_pass is not None
            and (now - self._last_pass) >= self.heartbeat_s
        )

        try:
            moving_area = self._measure(frame)
        except Exception:
            self._failures += 1
            logger.debug("motion check failed (%d)", self._failures, exc_info=True)
            if self._failures >= MOTION_MAX_FAILURES:
                self._available = False
                logger.warning(
                    "disabling motion gating after %d consecutive failures; every "
                    "frame will now reach inference",
                    self._failures,
                )
            self._last_pass = now
            return True

        self._failures = 0

        if moving_area is None:  # not an image, or the first frame seen
            self._last_pass = now
            return True

        self._last_area = moving_area
        if moving_area >= self.threshold or due_for_heartbeat:
            self._last_pass = now
            return True
        return False

    def reset(self) -> None:
        """Forget the background. Call after a reconnect or a resolution change."""
        self._background = None
        self._last_pass = None

    # -- internals -----------------------------------------------------

    def _measure(self, frame: Frame) -> float | None:
        """Largest moving contour area in full-frame pixels, or None.

        None means "no opinion": the input is not an image, or it is the first
        frame and there is nothing to compare it against yet.
        """
        if self._cv2 is None:
            import cv2 as cv2_module  # lazy on purpose, see the module docstring
            import numpy as np_module

            self._cv2 = cv2_module
            self._np = np_module
            # Built once: the dilation kernel is the same on every frame, and
            # letting OpenCV synthesise its default costs an allocation a
            # frame at capture rate.
            self._kernel = np_module.ones((3, 3), np_module.uint8)
        cv2 = self._cv2
        np = self._np

        shape = getattr(frame, "shape", None)
        if not shape or len(shape) < 2 or getattr(frame, "ndim", 0) not in (2, 3):
            return None

        height, width = shape[0], shape[1]
        if height < 2 or width < 2:
            return None

        # Integer stride subsampling: a view, then one contiguous copy of the
        # small result. On a 3-channel frame take a single channel rather than
        # converting to grayscale -- a weighted sum over 900k pixels buys no
        # extra sensitivity to movement.
        step = max(1, int(width // MOTION_WORK_WIDTH))
        view = frame[::step, ::step, 1] if len(shape) == 3 else frame[::step, ::step]
        small = np.ascontiguousarray(view)
        if small.dtype != np.uint8:
            small = cv2.convertScaleAbs(small)
        gray = cv2.GaussianBlur(small, (5, 5), 0)

        if self._background is None or self._background.shape != gray.shape:
            # First frame, or the source changed resolution mid-run.
            self._background = gray.astype(np.float32)
            return None

        cv2.accumulateWeighted(gray, self._background, MOTION_BACKGROUND_ALPHA)
        delta = cv2.absdiff(gray, cv2.convertScaleAbs(self._background))
        _, mask = cv2.threshold(delta, MOTION_DELTA, 255, cv2.THRESH_BINARY)
        # Dilation closes the gaps a low-contrast object leaves in the mask, so
        # one car is one contour instead of a scatter of small ones.
        mask = cv2.dilate(mask, self._kernel, iterations=2)
        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        if not contours:
            return 0.0

        largest = max(cv2.contourArea(contour) for contour in contours)
        # Back to full-frame pixels: the area shrank by step^2 on subsampling.
        return float(largest) * float(step * step)


class CameraWorker(threading.Thread):
    """Captures one camera into a bounded, drop-oldest queue.

    Never raises out of :meth:`run`: open failures, read failures and
    decoder errors all funnel into the reconnect path so the thread stays
    alive for the life of the process.
    """

    def __init__(
        self,
        role: str,
        config: CameraConfig,
        name: str | None = None,
        motion: MotionConfig | MotionGate | None = None,
    ) -> None:
        super().__init__(name=name or f"camera-{role}", daemon=True)
        self.role = str(role)
        self._config = config
        # Accepts a MotionConfig (the normal path, from cameras.motion), a
        # ready-made gate (tests), or None to capture everything.
        if motion is None or isinstance(motion, MotionGate):
            self._motion: MotionGate | None = motion
        else:
            self._motion = MotionGate.from_config(motion)
        self._source = config.resolved_source
        self._queue: queue.Queue[Frame] = queue.Queue(maxsize=max(1, int(config.queue_size)))
        self._stop_event = threading.Event()
        self._capture: Any | None = None

        self._lock = threading.Lock()
        self._latest: Frame | None = None
        self._intervals: deque[float] = deque(maxlen=_FPS_WINDOW)
        self._last_monotonic: float | None = None
        self._status = CameraStatus(role=self.role, source=str(config.source))

        self._min_interval = 1.0 / config.fps_limit if config.fps_limit > 0 else 0.0
        self._reconnect_delay = max(0.1, float(config.reconnect_delay_s))

        if self._source is None:
            self._status.last_error = "no source configured"

    # -- consumer API ------------------------------------------------------

    def read(self, timeout: float = 1.0) -> Frame | None:
        """Pop the next queued frame, or None if none arrived within ``timeout``."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def latest(self) -> Frame | None:
        """The most recent frame captured, without consuming the queue.

        Used for MJPEG/preview streaming, which wants "whatever is on screen
        now" rather than the next unprocessed frame.
        """
        with self._lock:
            return self._latest

    def status(self) -> CameraStatus:
        """A snapshot copy of this camera's health counters."""
        with self._lock:
            return CameraStatus(
                role=self._status.role,
                source=self._status.source,
                connected=self._status.connected,
                fps=self._status.fps,
                frames_read=self._status.frames_read,
                frames_dropped=self._status.frames_dropped,
                motion_skipped=self._status.motion_skipped,
                last_error=self._status.last_error,
                last_frame_ts=self._status.last_frame_ts,
            )

    @property
    def enabled(self) -> bool:
        """False when this camera has no source, i.e. it is not fitted.

        A disabled worker is safe to construct and to start -- :meth:`run`
        returns immediately -- but the orchestrator does neither, so the
        thread never exists in the first place.
        """
        return self._source is not None

    @property
    def stopping(self) -> bool:
        return self._stop_event.is_set()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the thread to finish and release the capture device."""
        self._stop_event.set()
        if self.is_alive() and threading.current_thread() is not self:
            self.join(timeout=timeout)
            if self.is_alive():  # pragma: no cover - blocked in a driver read
                logger.warning("Camera worker %s did not stop within %.1fs", self.role, timeout)
        self._release()

    # -- capture loop ------------------------------------------------------

    def run(self) -> None:  # noqa: C901 - a capture loop is inherently branchy
        if self._source is None:
            # Belt and braces: the orchestrator already skips unfitted roles,
            # so reaching here means somebody started the worker directly.
            # Return rather than spin -- an empty source is a configuration
            # statement ("no camera here"), and retrying it forever produces a
            # warning every reconnect_delay_s for the life of the process.
            logger.info("Camera %s has no source configured; not capturing", self.role)
            return

        logger.info("Camera %s starting on source %r", self.role, self._source)
        while not self._stop_event.is_set():
            capture = self._capture
            if capture is None:
                capture = self._open()
                if capture is None:
                    if self._stop_event.wait(self._reconnect_delay):
                        break
                    continue

            frame_start = time.monotonic()
            try:
                ok, frame = capture.read()
            except Exception as exc:
                self._record_error(f"read failed: {exc}")
                self._release()
                if self._stop_event.wait(self._reconnect_delay):
                    break
                continue

            if not ok or frame is None:
                self._record_error("capture returned no frame")
                self._release()
                if self._stop_event.wait(self._reconnect_delay):
                    break
                continue

            self._publish(frame)

            if self._min_interval > 0.0:
                spare = self._min_interval - (time.monotonic() - frame_start)
                if spare > 0 and self._stop_event.wait(spare):
                    break

        self._release()
        logger.info("Camera %s stopped", self.role)

    # -- internals ---------------------------------------------------------

    def _open(self) -> Any | None:
        if self._source is None:  # pragma: no cover - run() returns first
            return None
        try:
            import cv2
        except ImportError as exc:  # pragma: no cover - opencv missing
            self._record_error(f"opencv is not installed: {exc}")
            return None

        try:
            backend = default_camera_backend()
        except Exception as exc:  # pragma: no cover - cv2 without the constant
            logger.debug("Falling back to the default capture backend: %s", exc)
            backend = 0

        try:
            capture = (
                cv2.VideoCapture(self._source, backend)
                if isinstance(self._source, int)
                else cv2.VideoCapture(self._source)
            )
            if not capture.isOpened():
                capture.release()
                self._record_error(f"could not open source {self._source!r}")
                return None

            capture.set(cv2.CAP_PROP_FRAME_WIDTH, self._config.width)
            capture.set(cv2.CAP_PROP_FRAME_HEIGHT, self._config.height)
            # A 1-frame driver buffer keeps latency down on RTSP feeds; not
            # every backend honours it, hence the best-effort try.
            try:
                capture.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            except Exception:  # pragma: no cover - backend without the property
                pass
        except Exception as exc:
            self._record_error(f"open failed: {exc}")
            return None

        self._capture = capture
        with self._lock:
            self._status.connected = True
            self._status.last_error = None
        logger.info("Camera %s connected to %r", self.role, self._source)
        return capture

    def _publish(self, frame: Frame) -> None:
        """Record a captured frame, and queue it if it is worth processing.

        Every frame updates the counters and ``latest()`` -- the live preview
        must keep moving even while inference is being skipped. Only frames
        the motion gate accepts are handed to the ML queue.
        """
        self._observe(frame)

        if self._motion is not None and not self._motion.should_process(frame):
            with self._lock:
                self._status.motion_skipped += 1
            return

        self._enqueue(frame)

    def _observe(self, frame: Frame) -> None:
        """Update ``latest()``, the FPS estimate and the frame counters."""
        now = time.monotonic()
        with self._lock:
            self._latest = frame
            self._status.frames_read += 1
            self._status.connected = True
            self._status.last_frame_ts = time.time()
            if self._last_monotonic is not None:
                self._intervals.append(now - self._last_monotonic)
            self._last_monotonic = now
            if self._intervals:
                mean = sum(self._intervals) / len(self._intervals)
                self._status.fps = (1.0 / mean) if mean > 0 else 0.0

    def _enqueue(self, frame: Frame) -> None:
        """Queue a frame, evicting the oldest one if the consumer is behind."""
        dropped = 0
        try:
            self._queue.put_nowait(frame)
        except queue.Full:
            try:
                self._queue.get_nowait()
                dropped = 1
            except queue.Empty:  # pragma: no cover - raced with the consumer
                pass
            try:
                self._queue.put_nowait(frame)
            except queue.Full:  # pragma: no cover - raced with another producer
                dropped += 1

        if dropped:
            with self._lock:
                self._status.frames_dropped += dropped

    def _record_error(self, message: str) -> None:
        with self._lock:
            self._status.connected = False
            self._status.last_error = message
            self._status.fps = 0.0
        logger.warning("Camera %s: %s", self.role, message)

    def _release(self) -> None:
        capture, self._capture = self._capture, None
        with self._lock:
            self._status.connected = False
        if self._motion is not None:
            # The scene behind a reconnect is not the scene before it (the
            # camera may have moved, or hours may have passed), and a stale
            # background would read as whole-frame motion.
            self._motion.reset()
        if capture is None:
            return
        try:
            capture.release()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Error releasing camera %s: %s", self.role, exc)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"CameraWorker(role={self.role!r}, source={self._source!r})"
