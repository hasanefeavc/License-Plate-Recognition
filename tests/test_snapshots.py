"""Tests for event snapshots and their rolling retention.

The properties that matter here are the ones a naive implementation gets
wrong: saving must not run on the recognition thread, a slow disk must not
become backpressure on the gate, an idling car must not fill the disk with
identical frames, and the purge must delete only what it owns.
"""

from __future__ import annotations

import os
import threading
import time
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from lpr.contracts import Action
from lpr.pipeline.orchestrator import PipelineOrchestrator
from lpr.pipeline.snapshots import SnapshotWriter, snapshot_filename

from .conftest import FakeDetector, FakeRecognizer, FakeRelay, FakeVoter

cv2 = pytest.importorskip("cv2", reason="snapshot encoding needs opencv")


def _writer(tmp_path: Path, **kwargs: Any) -> SnapshotWriter:
    return SnapshotWriter(tmp_path / "snapshots", **kwargs)


def _drain(writer: SnapshotWriter, timeout: float = 5.0) -> None:
    """Block until the writer thread has caught up."""
    assert writer.flush(timeout), "snapshot writer did not drain"


def _age(path: Path, days: float) -> None:
    """Backdate a file's mtime by *days*."""
    when = time.time() - days * 86400
    os.utime(path, (when, when))


# ---------------------------------------------------------------------------
# Filename format
# ---------------------------------------------------------------------------


def test_filename_is_timestamp_then_plate() -> None:
    when = datetime(2026, 8, 27, 9, 14, 2, tzinfo=UTC)
    assert snapshot_filename("34ABC123", when) == "20260827_091402_34ABC123.jpg"


def test_filename_uses_utc_so_it_matches_the_log_row() -> None:
    """The name and the ``ts`` in the logs table must be the same instant."""
    aware = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone(timedelta(hours=3)))
    assert snapshot_filename("34ABC123", aware) == "20260827_090000_34ABC123.jpg"


def test_filename_strips_characters_a_filesystem_would_choke_on() -> None:
    when = datetime(2026, 8, 27, 9, 14, 2, tzinfo=UTC)
    assert snapshot_filename("34 abc/123", when) == "20260827_091402_34ABC123.jpg"
    assert snapshot_filename("", when) == "20260827_091402_UNKNOWN.jpg"


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def test_submit_writes_a_readable_jpeg(tmp_path, frame) -> None:
    writer = _writer(tmp_path)
    writer.start()
    try:
        assert writer.submit("34ABC123", frame, camera="entry") is True
        _drain(writer)
    finally:
        writer.stop()

    files = sorted((tmp_path / "snapshots").glob("*.jpg"))
    assert len(files) == 1
    assert files[0].name.endswith("_34ABC123.jpg")
    decoded = cv2.imread(str(files[0]))
    assert decoded is not None, "the file on disk must be a valid JPEG"
    assert decoded.shape == frame.shape
    assert writer.stats["written"] == 1


def test_no_partial_files_are_left_behind(tmp_path, frame) -> None:
    """Writes go through a .part file, so a reader never sees a half JPEG."""
    writer = _writer(tmp_path)
    writer.start()
    try:
        writer.submit("34ABC123", frame)
        _drain(writer)
    finally:
        writer.stop()
    assert list((tmp_path / "snapshots").glob("*.part")) == []


def test_same_second_collision_does_not_overwrite_evidence(tmp_path, frame) -> None:
    """Entry and exit can confirm inside one second; neither image is lost."""
    writer = _writer(tmp_path)
    when = datetime(2026, 8, 27, 9, 14, 2, tzinfo=UTC)
    writer.start()
    try:
        writer.submit("34ABC123", frame, camera="entry", when=when)
        writer.submit("34ABC123", frame, camera="exit", when=when)
        _drain(writer)
    finally:
        writer.stop()

    files = sorted(p.name for p in (tmp_path / "snapshots").glob("*.jpg"))
    assert files == ["20260827_091402_34ABC123-2.jpg", "20260827_091402_34ABC123.jpg"]


def test_submit_never_blocks_when_the_disk_cannot_keep_up(tmp_path, frame) -> None:
    """A wedged writer costs dropped evidence, never a stalled gate."""
    writer = _writer(tmp_path, queue_size=2)
    blocked = threading.Event()
    release = threading.Event()

    def wedged(*_args: Any, **_kwargs: Any) -> None:
        blocked.set()
        release.wait(timeout=5.0)

    writer._write = wedged  # type: ignore[method-assign]
    writer.start()
    try:
        writer.submit("34ABC001", frame)
        assert blocked.wait(timeout=5.0), "writer thread never picked the job up"

        started = time.monotonic()
        for n in range(50):
            writer.submit(f"34ABC{n:03d}", frame)
        elapsed = time.monotonic() - started

        assert elapsed < 1.0, "submit() must not wait on the writer thread"
        assert writer.stats["dropped"] > 0
    finally:
        release.set()
        writer.stop()


def test_a_disabled_writer_writes_nothing(tmp_path, frame) -> None:
    writer = _writer(tmp_path, enabled=False)
    writer.start()
    try:
        assert writer.submit("34ABC123", frame) is False
    finally:
        writer.stop()
    assert not (tmp_path / "snapshots").exists()


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def test_purge_deletes_only_snapshots_older_than_the_window(tmp_path) -> None:
    writer = _writer(tmp_path, retention_days=10)
    directory = tmp_path / "snapshots"
    directory.mkdir(parents=True)

    fresh = directory / "20260827_091402_FRESH.jpg"
    edge = directory / "20260817_091402_EDGE.jpg"
    stale = directory / "20260801_091402_STALE.jpg"
    for path in (fresh, edge, stale):
        path.write_bytes(b"x")
    _age(fresh, 1)
    _age(edge, 9.9)  # just inside the window
    _age(stale, 11)

    assert writer.purge_older_than() == 1
    assert fresh.exists() and edge.exists()
    assert not stale.exists()


def test_purge_leaves_other_file_types_alone(tmp_path) -> None:
    """The folder is not exclusively ours; only *.jpg is in scope."""
    writer = _writer(tmp_path, retention_days=10)
    directory = tmp_path / "snapshots"
    directory.mkdir(parents=True)

    keep = directory / "operator-notes.txt"
    png = directory / "20260801_091402_OLD.png"
    jpg = directory / "20260801_091402_OLD.jpg"
    for path in (keep, png, jpg):
        path.write_bytes(b"x")
        _age(path, 30)

    assert writer.purge_older_than() == 1
    assert keep.exists() and png.exists()
    assert not jpg.exists()


def test_purge_is_disabled_rather_than_total_when_days_is_zero(tmp_path) -> None:
    """A misconfigured 0 must not wipe the evidence folder."""
    writer = _writer(tmp_path, retention_days=0)
    directory = tmp_path / "snapshots"
    directory.mkdir(parents=True)
    old = directory / "20200101_000000_ANCIENT.jpg"
    old.write_bytes(b"x")
    _age(old, 5000)

    assert writer.purge_older_than() == 0
    assert old.exists()


def test_a_disabled_writer_never_prunes_a_directory_it_does_not_own(tmp_path) -> None:
    writer = _writer(tmp_path, enabled=False, retention_days=10)
    directory = tmp_path / "snapshots"
    directory.mkdir(parents=True)
    old = directory / "20200101_000000_ANCIENT.jpg"
    old.write_bytes(b"x")
    _age(old, 5000)

    assert writer.purge_older_than() == 0
    assert old.exists()


def test_purge_on_a_missing_directory_is_a_no_op(tmp_path) -> None:
    assert _writer(tmp_path, retention_days=10).purge_older_than() == 0


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------


def _pipeline(settings: Any, **kwargs: Any) -> PipelineOrchestrator:
    return PipelineOrchestrator(
        settings=settings,
        detector=kwargs.get("detector") or FakeDetector(),
        recognizer=kwargs.get("recognizer") or FakeRecognizer(),
        voter=kwargs.get("voter") or FakeVoter(),
        relay=kwargs.get("relay") or FakeRelay(),
    )


def test_a_confirmed_plate_is_photographed(db, frame) -> None:
    pipeline = _pipeline(db)
    pipeline.snapshots.start()
    try:
        events = pipeline.process_frame("entry", frame)
        assert [e.action for e in events] == [str(Action.DENIED)]
        _drain(pipeline.snapshots)
    finally:
        pipeline.snapshots.stop()

    files = list(db.paths.snapshots_dir.glob("*.jpg"))
    assert len(files) == 1, "a decision must leave exactly one image"
    assert files[0].name.endswith("_34ABC123.jpg")


def test_an_idling_car_is_photographed_once_not_once_per_frame(db, frame) -> None:
    """Cooldown events are decisions the log skips; the disk skips them too."""
    pipeline = _pipeline(db)
    pipeline.snapshots.start()
    try:
        pipeline.process_frame("entry", frame)
        for _ in range(20):
            pipeline.decide("entry", "34ABC123")
        _drain(pipeline.snapshots)
    finally:
        pipeline.snapshots.stop()

    assert len(list(db.paths.snapshots_dir.glob("*.jpg"))) == 1


def test_snapshots_land_under_the_configured_data_dir(db) -> None:
    assert db.paths.snapshots_dir == db.paths.data_dir / "snapshots"
    assert db.paths.snapshots_dir.is_dir()


def test_retention_pass_trims_both_the_log_table_and_the_snapshots(db, frame) -> None:
    """One thread, one cadence: a row and its image expire together."""
    pipeline = _pipeline(db)
    directory = db.paths.snapshots_dir
    stale = directory / "20200101_000000_ANCIENT.jpg"
    stale.write_bytes(b"x")
    _age(stale, 400)

    pipeline._stop_event.set()  # one pass, then exit immediately
    pipeline._retention_loop()

    assert not stale.exists()


# ---------------------------------------------------------------------------
# Disk pressure: the size ceiling and the free-space floor
# ---------------------------------------------------------------------------


def _fill(directory: Path, count: int, size: int = 1024) -> list[Path]:
    """`count` snapshot files, each `size` bytes, with increasing mtimes.

    The mtimes are set explicitly rather than left to the filesystem: several
    files written in the same millisecond would otherwise sort arbitrarily,
    and every assertion here is about deletion *order*.
    """
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for index in range(count):
        path = directory / f"2026-01-01_00-00-{index:02d}_34ABC{index:02d}.jpg"
        path.write_bytes(b"x" * size)
        os.utime(path, (1_700_000_000 + index, 1_700_000_000 + index))
        paths.append(path)
    return paths


def test_the_size_ceiling_deletes_oldest_first(tmp_path: Path) -> None:
    """What survives must always be the most recent evidence.

    An operator reaching for a snapshot is investigating something that just
    happened, so deleting newest-first would throw away exactly what is wanted.
    """
    directory = tmp_path / "snapshots"
    paths = _fill(directory, count=10, size=1024)
    writer = SnapshotWriter(directory, max_total_bytes=5 * 1024)

    deleted = writer.enforce_limits()

    assert deleted == 5
    survivors = sorted(p.name for p in directory.glob("*.jpg"))
    assert survivors == sorted(p.name for p in paths[5:]), "the newest five survive"


def test_nothing_is_deleted_while_under_the_ceiling(tmp_path: Path) -> None:
    directory = tmp_path / "snapshots"
    _fill(directory, count=4, size=1024)
    writer = SnapshotWriter(directory, max_total_bytes=1024 * 1024)
    assert writer.enforce_limits() == 0
    assert len(list(directory.glob("*.jpg"))) == 4


def test_a_zero_ceiling_disables_the_check(tmp_path: Path) -> None:
    """Age remains the only limit, which is the previous behaviour."""
    directory = tmp_path / "snapshots"
    _fill(directory, count=6, size=1024)
    writer = SnapshotWriter(directory, max_total_bytes=0, min_free_bytes=0)
    assert writer.enforce_limits() == 0
    assert len(list(directory.glob("*.jpg"))) == 6


def test_the_free_space_floor_triggers_deletion(tmp_path: Path, monkeypatch) -> None:
    """The disk can fill for reasons that have nothing to do with snapshots.

    Logs, a database that grew, another service on the same volume. The size
    ceiling would be satisfied and the gate log would still stop being
    writable, which is why this is a separate limit rather than a tuning of
    the first.
    """
    directory = tmp_path / "snapshots"
    _fill(directory, count=10, size=1024)
    writer = SnapshotWriter(directory, max_total_bytes=0, min_free_bytes=8 * 1024)

    reclaimed = {"free": 0}

    def fake_free() -> int:
        return 1024 + reclaimed["free"]

    monkeypatch.setattr(writer, "free_bytes", fake_free)
    deleted = writer.enforce_limits()

    assert deleted > 0, "a full volume must force snapshots out"
    assert len(list(directory.glob("*.jpg"))) < 10


def test_the_last_snapshot_is_never_deleted(tmp_path: Path, monkeypatch) -> None:
    """If one file is the difference, the limit is misconfigured.

    Deleting the only remaining piece of evidence would not fix a volume that
    something else is filling, and it would destroy the last thing an operator
    could look at.
    """
    directory = tmp_path / "snapshots"
    _fill(directory, count=3, size=1024)
    writer = SnapshotWriter(directory, max_total_bytes=1)
    monkeypatch.setattr(writer, "free_bytes", lambda: 0)

    writer.enforce_limits()

    assert len(list(directory.glob("*.jpg"))) == 1, "one survivor is kept"


def test_disk_pressure_raises_an_event(tmp_path: Path) -> None:
    """Pressure that only appears in a log line is pressure nobody acts on."""
    directory = tmp_path / "snapshots"
    _fill(directory, count=8, size=1024)
    seen: list[tuple[str, dict]] = []
    writer = SnapshotWriter(
        directory, max_total_bytes=3 * 1024, on_pressure=lambda s, d: seen.append((s, d))
    )

    writer.enforce_limits()

    assert len(seen) == 1
    source, detail = seen[0]
    assert source == "snapshot_retention"
    assert detail["deleted"] == 5
    assert detail["reason"] == "size ceiling"
    assert detail["reclaimed_bytes"] == 5 * 1024
    assert writer.pressure_events == 1


def test_a_failing_pressure_sink_does_not_break_retention(tmp_path: Path) -> None:
    directory = tmp_path / "snapshots"
    _fill(directory, count=8, size=1024)

    def explode(_source: str, _detail: dict) -> None:
        raise RuntimeError("event store is down")

    writer = SnapshotWriter(directory, max_total_bytes=3 * 1024, on_pressure=explode)
    assert writer.enforce_limits() == 5, "deletion still happened"


def test_a_disabled_writer_deletes_nothing(tmp_path: Path) -> None:
    """It does not own the directory it was pointed at, so it must not prune it."""
    directory = tmp_path / "snapshots"
    _fill(directory, count=8, size=1024)
    writer = SnapshotWriter(directory, enabled=False, max_total_bytes=1024)
    assert writer.enforce_limits() == 0
    assert len(list(directory.glob("*.jpg"))) == 8


def test_a_missing_directory_is_not_an_error(tmp_path: Path) -> None:
    writer = SnapshotWriter(tmp_path / "never-created", max_total_bytes=1024)
    assert writer.enforce_limits() == 0
    assert writer.total_bytes() == 0


def test_total_bytes_counts_only_snapshots(tmp_path: Path) -> None:
    directory = tmp_path / "snapshots"
    _fill(directory, count=3, size=1024)
    (directory / "notes.txt").write_bytes(b"y" * 9999)
    writer = SnapshotWriter(directory)
    assert writer.total_bytes() == 3 * 1024


def test_unknowable_free_space_does_not_trigger_deletion(tmp_path: Path, monkeypatch) -> None:
    """A stat that fails is not evidence of a full disk.

    Deleting evidence because the free-space check errored would destroy data
    on the strength of a failed measurement.
    """
    directory = tmp_path / "snapshots"
    _fill(directory, count=6, size=1024)
    writer = SnapshotWriter(directory, max_total_bytes=0, min_free_bytes=1024 * 1024)
    monkeypatch.setattr(writer, "free_bytes", lambda: None)
    assert writer.enforce_limits() == 0
    assert len(list(directory.glob("*.jpg"))) == 6
