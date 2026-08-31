"""Event snapshots: one JPEG per gate decision, on a rolling window.

Why a separate thread
---------------------

The recognition path must not touch the disk. JPEG-encoding a 1080p frame
costs single-digit milliseconds and a write to a slow disk (or a full one,
or an NFS mount that has gone away) costs unbounded time -- either would be
paid on the camera's processing thread, directly delaying the next frame's
inference and, through the shared frame buffer, the live MJPEG stream.

So :class:`SnapshotWriter` owns a bounded queue and a single writer thread.
:meth:`SnapshotWriter.submit` only puts a reference on that queue and returns;
encoding and writing both happen on the writer thread. The queue is bounded
and *drops* when full, on the same principle as the camera queues: evidence
retention is best-effort and must never become backpressure on recognition.

Frames are queued by reference, not copied. ``cv2.VideoCapture.read()``
allocates a new array per call, so the frame handed to
:meth:`~lpr.pipeline.orchestrator.PipelineOrchestrator.process_frame` is
owned by that event alone and nothing overwrites it underneath the writer.

Retention
---------

:meth:`SnapshotWriter.purge_older_than` deletes ``*.jpg`` older than N days
by file modification time. The orchestrator's retention thread calls it at
startup and once a day thereafter, alongside the ``logs`` table purge.
"""

from __future__ import annotations

import logging
import queue
import re
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["SNAPSHOT_SUFFIX", "SnapshotWriter", "snapshot_filename"]

#: Extension every snapshot carries. Also what the purge matches on, so
#: nothing else an operator drops in the folder is ever deleted.
SNAPSHOT_SUFFIX = ".jpg"

#: Timestamp portion of a snapshot name: ``YYYYMMDD_HHMMSS``.
_STAMP_FORMAT = "%Y%m%d_%H%M%S"

#: Anything outside this set is stripped from the plate before it becomes a
#: filename. Normalised plates are already ``[A-Z0-9]``; this is the guard for
#: an OCR string that slipped through with a space or a stray symbol.
_UNSAFE = re.compile(r"[^A-Z0-9]+")

#: How long the writer thread blocks on the queue before re-checking the stop
#: flag. Matches the orchestrator's own frame-wait convention.
_QUEUE_WAIT_S = 0.5

#: Sentinel pushed by :meth:`SnapshotWriter.stop` to wake the writer at once
#: instead of waiting out the queue timeout.
_SHUTDOWN = object()


def snapshot_filename(plate: str, when: datetime | None = None) -> str:
    """``YYYYMMDD_HHMMSS_<PLATE>.jpg`` for one decision.

    *when* is interpreted in UTC, matching the ``ts`` written to the ``logs``
    table -- so the name of the image and the timestamp the operator sees in
    the history table are the same instant, with no timezone arithmetic in
    between.
    """
    moment = when or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    stamp = moment.astimezone(timezone.utc).strftime(_STAMP_FORMAT)
    safe_plate = _UNSAFE.sub("", str(plate).upper()) or "UNKNOWN"
    return f"{stamp}_{safe_plate}{SNAPSHOT_SUFFIX}"


class SnapshotWriter:
    """Encodes and writes event snapshots off the recognition path.

    Start it with :meth:`start`, hand it frames with :meth:`submit`, and stop
    it with :meth:`stop`. Every method is safe to call from any thread, and
    :meth:`submit` never blocks.
    """

    def __init__(
        self,
        directory: Path | str,
        *,
        quality: int = 85,
        queue_size: int = 64,
        retention_days: int = 10,
        enabled: bool = True,
        max_total_bytes: int = 0,
        min_free_bytes: int = 0,
        on_pressure: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.quality = max(1, min(100, int(quality)))
        self.retention_days = max(0, int(retention_days))
        self.enabled = bool(enabled)
        self.max_total_bytes = max(0, int(max_total_bytes))
        self.min_free_bytes = max(0, int(min_free_bytes))
        #: Called when a size or free-space limit forced a deletion, so the
        #: orchestrator can raise a system event and an e-mail. Disk pressure
        #: that only ever appears in a log line is disk pressure nobody acts on
        #: until the volume is full.
        self.on_pressure = on_pressure
        self.pressure_events = 0

        self._queue: queue.Queue[Any] = queue.Queue(maxsize=max(1, int(queue_size)))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        # Accepted-but-not-yet-written count, so callers can wait for the disk
        # to catch up. The queue's own ``unfinished_tasks`` is not usable for
        # this: it only moves on ``task_done()``, and it would still report a
        # job as pending while it is being encoded.
        self._inflight = 0
        self._inflight_lock = threading.Lock()
        self._idle = threading.Event()
        self._idle.set()

        self._written = 0
        self._dropped = 0
        self._failed = 0

    # -- lifecycle ------------------------------------------------------

    def start(self) -> None:
        """Start the writer thread. Idempotent."""
        if not self.enabled:
            logger.info("Event snapshots are disabled")
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run, name="snapshot-writer", daemon=True
            )
            self._thread.start()
        logger.info("Snapshot writer started: %s", self.directory)

    def stop(self, timeout: float = 5.0) -> None:
        """Drain what is already queued, then stop the thread. Idempotent."""
        with self._lock:
            thread = self._thread
            self._thread = None
        if thread is None:
            return
        self._stop_event.set()
        try:
            self._queue.put_nowait(_SHUTDOWN)
        except queue.Full:  # pragma: no cover - the timeout still wakes it
            pass
        thread.join(timeout=max(0.0, timeout))
        if thread.is_alive():  # pragma: no cover - disk wedged
            logger.warning("Snapshot writer did not stop within the timeout")
        logger.info(
            "Snapshot writer stopped (%d written, %d dropped, %d failed)",
            self._written,
            self._dropped,
            self._failed,
        )

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def flush(self, timeout: float = 5.0) -> bool:
        """Block until every accepted frame has been written to disk.

        Returns False if the writer was still busy when *timeout* expired.
        Nothing on the recognition path calls this -- it is for shutdown,
        tests, and any caller that needs a checkpoint.
        """
        return self._idle.wait(timeout)

    @property
    def stats(self) -> dict[str, int]:
        """Counters for the API's stats endpoint and for tests."""
        return {
            "written": self._written,
            "dropped": self._dropped,
            "failed": self._failed,
            "pending": self._inflight,
        }

    # -- producer side (called from the recognition path) ---------------

    def submit(
        self,
        plate: str,
        frame: Any,
        *,
        camera: str | None = None,
        when: datetime | None = None,
        on_saved: Callable[[Path | None], None] | None = None,
    ) -> bool:
        """Queue one frame to be saved. Never blocks; returns False if dropped.

        A full queue means the disk cannot keep up with the gate. Dropping is
        the deliberate choice: the alternative is stalling the camera thread
        that produced this decision.

        ``on_saved`` is called once per accepted frame, **on the writer
        thread**, with the finished path -- or with ``None`` when the write
        failed. It exists so the e-mail notifier can attach the very file this
        writer produced rather than encoding a second copy of the same frame,
        and it fires on failure too so an alert is never lost to a full disk.
        An exception from it is logged and swallowed: a broken consumer must
        not take down the writer or cost the next snapshot.
        """
        if not self.enabled or frame is None:
            return False
        if not self.running:
            # Nothing would ever drain the queue, so the ``on_saved`` consumer
            # would wait forever. Saying no lets the caller fall back.
            logger.debug("Snapshot writer is not running; %s not queued", plate)
            return False
        name = snapshot_filename(plate, when)
        with self._inflight_lock:
            self._inflight += 1
            self._idle.clear()
        try:
            self._queue.put_nowait((name, frame, camera, on_saved))
        except queue.Full:
            self._mark_done()
            self._dropped += 1
            logger.warning(
                "Snapshot queue full, dropping %s (%d dropped so far)",
                name,
                self._dropped,
            )
            return False
        return True

    # -- consumer side --------------------------------------------------

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=_QUEUE_WAIT_S)
            except queue.Empty:
                if self._stop_event.is_set():
                    return
                continue
            if item is _SHUTDOWN:
                # Everything queued before the sentinel has been written: the
                # queue is FIFO, so there is nothing left ahead of us.
                return
            name, frame, camera, on_saved = item
            try:
                path = self._write(name, frame, camera)
                if on_saved is not None:
                    # Announced even when the write failed (``path`` is None).
                    # The consumer is the e-mail notifier, and an alert about a
                    # refused vehicle must not be lost because the disk was
                    # full -- it goes out without the photograph instead.
                    self._announce(on_saved, path)
            except Exception:  # pragma: no cover - never kill the writer
                self._failed += 1
                logger.exception("Could not save snapshot %s", name)
            finally:
                self._mark_done()

    @staticmethod
    def _announce(callback: Callable[[Path | None], None], path: Path | None) -> None:
        """Hand the outcome to a consumer without trusting it."""
        try:
            callback(path)
        except Exception:
            logger.warning(
                "Snapshot callback failed for %s", path.name if path else "-", exc_info=True
            )

    def _mark_done(self) -> None:
        with self._inflight_lock:
            self._inflight = max(0, self._inflight - 1)
            if self._inflight == 0:
                self._idle.set()

    def _write(self, name: str, frame: Any, camera: str | None) -> Path | None:
        """Encode one frame and write it. Runs on the writer thread only."""
        try:
            import cv2
        except ImportError:  # pragma: no cover - opencv missing
            self._failed += 1
            logger.warning("Cannot save snapshots: opencv is not installed")
            return None

        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._failed += 1
            logger.warning("Snapshot directory %s unusable: %s", self.directory, exc)
            return None

        ok, buffer = cv2.imencode(
            SNAPSHOT_SUFFIX, frame, [int(cv2.IMWRITE_JPEG_QUALITY), self.quality]
        )
        if not ok:
            self._failed += 1
            logger.warning("JPEG encoding failed for snapshot %s", name)
            return None

        path = self._unique_path(name)
        # Written via a temporary file and renamed so a reader (or a backup
        # job) never sees a half-flushed JPEG under a final name.
        temp = path.with_name(path.name + ".part")
        try:
            temp.write_bytes(bytes(buffer))
            temp.replace(path)
        except OSError as exc:
            self._failed += 1
            logger.warning("Could not write snapshot %s: %s", path, exc)
            temp.unlink(missing_ok=True)
            return None

        self._written += 1
        logger.info(
            "Snapshot saved: %s%s", path.name, f" (camera {camera})" if camera else ""
        )
        return path

    def _unique_path(self, name: str) -> Path:
        """``name``, or ``name-2``/``-3``... if that second already has one.

        Two cameras can confirm different plates inside the same second, and
        the entry and exit lanes can see the same car. Rather than silently
        overwrite the earlier evidence, later frames get a suffix.
        """
        path = self.directory / name
        if not path.exists():
            return path
        stem = path.stem
        for counter in range(2, 1000):
            candidate = self.directory / f"{stem}-{counter}{SNAPSHOT_SUFFIX}"
            if not candidate.exists():
                return candidate
        return path  # pragma: no cover - 1000 collisions in one second

    # -- retention ------------------------------------------------------

    def purge_older_than(self, days: int | None = None) -> int:
        """Delete snapshots whose mtime is older than *days*. Returns the count.

        ``days <= 0`` disables the purge rather than deleting everything --
        the safe reading of a misconfigured value for something that exists
        to retain evidence. A disabled writer deletes nothing at all: it does
        not own the directory it was pointed at, so it must not prune it.
        """
        if not self.enabled:
            return 0
        limit_days = self.retention_days if days is None else int(days)
        if limit_days <= 0:
            logger.debug("Snapshot retention disabled (retention_days=%d)", limit_days)
            return 0
        if not self.directory.is_dir():
            return 0

        cutoff = time.time() - limit_days * 86400
        deleted = 0
        errors = 0
        for path in self.directory.glob(f"*{SNAPSHOT_SUFFIX}"):
            try:
                if path.stat().st_mtime >= cutoff:
                    continue
                path.unlink()
            except FileNotFoundError:
                continue  # another pass, or an operator, got there first
            except OSError as exc:
                errors += 1
                logger.warning("Could not delete snapshot %s: %s", path, exc)
                continue
            deleted += 1

        if deleted:
            logger.info("Deleted %d old snapshots (older than %d days)", deleted, limit_days)
        else:
            logger.debug("No snapshots older than %d days", limit_days)
        if errors:
            logger.warning("%d snapshots could not be deleted", errors)
        return deleted

    # -- disk pressure ---------------------------------------------------

    def _snapshot_files(self) -> list[tuple[float, int, Path]]:
        """Every snapshot as ``(mtime, size, path)``, oldest first.

        One ``stat`` per file and one sort, so the caller can answer both
        "how much is there" and "what goes next" without walking twice.
        """
        entries: list[tuple[float, int, Path]] = []
        for path in self.directory.glob(f"*{SNAPSHOT_SUFFIX}"):
            try:
                info = path.stat()
            except OSError:
                continue  # deleted under us; the next pass will not see it
            entries.append((info.st_mtime, info.st_size, path))
        entries.sort(key=lambda item: item[0])
        return entries

    def total_bytes(self) -> int:
        """Bytes currently occupied by snapshots."""
        if not self.directory.is_dir():
            return 0
        return sum(size for _mtime, size, _path in self._snapshot_files())

    def free_bytes(self) -> int | None:
        """Free space on the snapshot volume, or ``None`` if unknowable."""
        try:
            import shutil

            return int(shutil.disk_usage(self.directory).free)
        except (OSError, ValueError):
            logger.debug("Could not read free space for %s", self.directory, exc_info=True)
            return None

    def enforce_limits(self) -> int:
        """Delete oldest-first until the size and free-space limits are met.

        Returns the number of files deleted.

        Age-based retention is the normal mechanism and this is the backstop
        for the case age cannot cover: a site busy enough that ten days of
        evidence does not fit. Deletion is strictly oldest-first, so what
        survives is always the most recent evidence -- which is what an
        operator investigating an incident actually wants.

        Runs even when both limits would be satisfied by doing nothing, and
        returns 0; the cost is one directory listing, and the alternative is a
        flag that goes stale.
        """
        if not self.enabled or not self.directory.is_dir():
            return 0
        if self.max_total_bytes <= 0 and self.min_free_bytes <= 0:
            return 0

        entries = self._snapshot_files()
        if not entries:
            return 0

        total = sum(size for _mtime, size, _path in entries)
        free = self.free_bytes()

        over_size = self.max_total_bytes > 0 and total > self.max_total_bytes
        under_free = (
            self.min_free_bytes > 0 and free is not None and free < self.min_free_bytes
        )
        if not (over_size or under_free):
            return 0

        reason = "size ceiling" if over_size else "free space"
        logger.warning(
            "Snapshot %s reached: %.1f MB used, %s free. Deleting oldest first.",
            reason,
            total / 1024 / 1024,
            "unknown" if free is None else f"{free / 1024 / 1024:.1f} MB",
        )

        deleted = 0
        reclaimed = 0
        for _mtime, size, path in entries:
            still_over = self.max_total_bytes > 0 and total > self.max_total_bytes
            still_short = (
                self.min_free_bytes > 0
                and free is not None
                and (free + reclaimed) < self.min_free_bytes
            )
            if not (still_over or still_short):
                break
            # Never delete the last snapshot on the disk. If one file is the
            # difference between meeting the limit and not, the limit is
            # misconfigured or the volume is full of something else, and
            # deleting the only piece of evidence left would not fix either.
            if deleted >= len(entries) - 1:
                logger.error(
                    "Snapshot retention could not free enough space: %d file(s) left, "
                    "%.1f MB still used. Check snapshots.max_total_mb / min_free_mb, "
                    "and whether something else is filling this volume.",
                    len(entries) - deleted,
                    total / 1024 / 1024,
                )
                break
            try:
                path.unlink()
            except FileNotFoundError:
                total -= size
                continue
            except OSError as exc:
                logger.warning("Could not delete snapshot %s: %s", path, exc)
                continue
            total -= size
            reclaimed += size
            deleted += 1

        if deleted:
            self.pressure_events += 1
            logger.warning(
                "Deleted %d snapshot(s) (%.1f MB) to satisfy the %s limit",
                deleted,
                reclaimed / 1024 / 1024,
                reason,
            )
            self._notify_pressure(reason, deleted, reclaimed, total, free)
        return deleted

    def _notify_pressure(
        self, reason: str, deleted: int, reclaimed: int, remaining: int, free: int | None
    ) -> None:
        """Hand one disk-pressure event to the sink. Never raises."""
        sink = self.on_pressure
        if sink is None:
            return
        try:
            sink(
                "snapshot_retention",
                {
                    "reason": reason,
                    "deleted": deleted,
                    "reclaimed_bytes": reclaimed,
                    "remaining_bytes": remaining,
                    "free_bytes": free,
                    "directory": str(self.directory),
                },
            )
        except Exception:  # pragma: no cover - telemetry is never load-bearing
            logger.debug("Disk-pressure sink failed", exc_info=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"SnapshotWriter(dir={self.directory}, running={self.running}, "
            f"written={self._written}, dropped={self._dropped})"
        )
