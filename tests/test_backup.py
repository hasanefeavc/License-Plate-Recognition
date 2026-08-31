"""Tests for SQLite backup, restore and the pre-migration safety net.

The assertions that matter are about *consistency*, not about a file appearing.
Copying an open WAL database with ``shutil.copy`` also produces a file, and it
restores as a database missing its most recent transactions -- which is the
failure this module exists to avoid, and which a "the backup exists" test would
happily pass.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from lpr.db import PlateRepository, init_db
from lpr.db.backup import (
    MIGRATION_TAG,
    backup_database,
    backup_dir,
    list_backups,
    prune_backups,
    restore,
)


@pytest.fixture
def populated(db: Any) -> Any:
    """The tmp database with a couple of rows in it."""
    PlateRepository().upsert("34ABC123", owner="Ahmet")
    PlateRepository().upsert("06AB456", owner="Zeynep")
    return db


# ---------------------------------------------------------------------------
# Taking a backup
# ---------------------------------------------------------------------------


def test_a_backup_is_a_readable_database(populated: Any) -> None:
    """The whole point: the copy must open and hold the same rows.

    A file that exists is not a backup. This opens it with a fresh sqlite3
    connection -- no WAL sidecar, no shared state with the live database -- and
    reads the data back.
    """
    result = backup_database()
    assert result.ok and result.path is not None
    assert result.bytes_written > 0

    conn = sqlite3.connect(result.path)
    try:
        rows = dict(conn.execute("SELECT plate, owner FROM plates").fetchall())
    finally:
        conn.close()
    assert rows == {"34ABC123": "Ahmet", "06AB456": "Zeynep"}


def test_a_backup_captures_writes_made_after_the_last_checkpoint(populated: Any) -> None:
    """The reason for VACUUM INTO rather than copying the file.

    With WAL on, a row written moments ago may live only in the -wal sidecar.
    A file copy that takes plates.db alone would miss it; VACUUM INTO sees a
    consistent snapshot including the log.
    """
    PlateRepository().upsert("35ZZ99", owner="Son Yazan")
    result = backup_database()
    assert result.ok and result.path is not None

    conn = sqlite3.connect(result.path)
    try:
        row = conn.execute(
            "SELECT owner FROM plates WHERE plate = ?", ("35ZZ99",)
        ).fetchone()
    finally:
        conn.close()
    assert row is not None and row[0] == "Son Yazan"


def test_backups_taken_in_the_same_second_do_not_collide(populated: Any) -> None:
    """Timestamps have one-second resolution, so the name alone is not unique.

    Silently replacing the earlier copy would be data loss dressed as a
    successful backup -- and it would hit the pre-migration copy hardest,
    which is the one that must never be overwritten.
    """
    paths = {backup_database().path for _ in range(5)}
    assert len(paths) == 5
    assert all(path is not None and path.is_file() for path in paths)


def test_an_explicit_destination_is_honoured(populated: Any, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere" / "copy.db.bak"
    result = backup_database(target)
    assert result.ok
    assert result.path == target
    assert target.is_file()


def test_a_tagged_backup_is_named_for_its_purpose(populated: Any) -> None:
    result = backup_database(tag=MIGRATION_TAG)
    assert result.ok and result.path is not None
    assert MIGRATION_TAG in result.path.name


def test_a_failed_backup_reports_rather_than_raises(populated: Any, monkeypatch) -> None:
    """The scheduler logs and carries on; the migration path checks and stops.

    Both need a return value rather than an exception, and neither wants a
    backup failure to become a crash.
    """
    import lpr.db.backup as backup_module

    def explode(*_args: Any, **_kwargs: Any) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(backup_module, "get_connection", explode)
    result = backup_database()
    assert not result.ok
    assert result.error is not None
    assert result.path is None


def test_a_partial_backup_is_not_left_behind(populated: Any, monkeypatch) -> None:
    """A half-written file must never masquerade as a good copy."""
    import lpr.db.backup as backup_module

    class BrokenConn:
        def execute(self, _sql: str) -> None:
            raise sqlite3.OperationalError("out of space")

    monkeypatch.setattr(backup_module, "get_connection", lambda: BrokenConn())
    backup_database()
    assert not list(backup_dir().glob("*.part"))


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def test_prune_keeps_the_newest(populated: Any) -> None:
    for _ in range(10):
        backup_database()
    assert prune_backups(keep=3) == 7
    assert len(list_backups()) == 3


def test_prune_never_deletes_a_pre_migration_copy(populated: Any) -> None:
    """It is the rollback for an irreversible operation.

    A rolling window that swept these away would remove the safety net
    precisely when a run of upgrades had made it most valuable.
    """
    backup_database(tag=MIGRATION_TAG)
    for _ in range(8):
        backup_database()

    prune_backups(keep=1)
    survivors = [path.name for path in list_backups()]
    assert any(MIGRATION_TAG in name for name in survivors)


def test_prune_with_a_nonsense_keep_deletes_nothing(populated: Any) -> None:
    backup_database()
    assert prune_backups(keep=0) == 0
    assert len(list_backups()) == 1


def test_listing_is_newest_first(populated: Any) -> None:
    import os
    import time

    for index in range(3):
        result = backup_database()
        assert result.path is not None
        os.utime(result.path, (time.time() + index, time.time() + index))
    listed = list_backups()
    mtimes = [path.stat().st_mtime for path in listed]
    assert mtimes == sorted(mtimes, reverse=True)


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


def test_restore_puts_the_data_back(populated: Any) -> None:
    from lpr.db.connection import database_path, shutdown

    result = backup_database()
    assert result.path is not None

    PlateRepository().remove("34ABC123")
    assert PlateRepository().get("34ABC123") is None

    shutdown()  # every connection must be closed before the file is swapped
    assert restore(result.path) is True

    conn = sqlite3.connect(database_path())
    try:
        row = conn.execute(
            "SELECT owner FROM plates WHERE plate = ?", ("34ABC123",)
        ).fetchone()
    finally:
        conn.close()
    assert row is not None and row[0] == "Ahmet"


def test_restore_keeps_the_displaced_database(populated: Any) -> None:
    """A restore that turns out to be the wrong call is itself reversible."""
    from lpr.db.connection import database_path, shutdown

    result = backup_database()
    assert result.path is not None
    shutdown()
    restore(result.path)

    live = Path(database_path())
    displaced = list(live.parent.glob(f"{live.name}.failed-*"))
    assert displaced, "the replaced database was deleted rather than kept"


def test_restore_removes_stale_wal_sidecars(populated: Any) -> None:
    """A stale -wal beside a restored file re-applies what the restore undid."""
    from lpr.db.connection import database_path, shutdown

    result = backup_database()
    assert result.path is not None
    shutdown()

    live = Path(database_path())
    Path(str(live) + "-wal").write_bytes(b"stale")
    Path(str(live) + "-shm").write_bytes(b"stale")

    assert restore(result.path) is True
    assert not Path(str(live) + "-wal").exists()
    assert not Path(str(live) + "-shm").exists()


def test_restoring_a_missing_file_reports_rather_than_raises(db: Any, tmp_path: Path) -> None:
    assert restore(tmp_path / "nope.db.bak") is False


# ---------------------------------------------------------------------------
# The pre-migration gate
# ---------------------------------------------------------------------------


def test_no_backup_is_taken_when_the_schema_is_current(populated: Any) -> None:
    """Every restart would otherwise cost a copy, and push the genuinely
    valuable pre-upgrade ones out of any rolling window."""
    from lpr.db.connection import _initialised

    before = len(list_backups())
    _initialised.clear()
    init_db()
    assert len(list_backups()) == before


def test_an_upgrade_takes_a_backup_first(populated: Any) -> None:
    from lpr.db import schema
    from lpr.db.connection import _initialised, stored_schema_version, transaction

    with transaction() as tx:
        tx.execute(schema.UPSERT_SCHEMA_META, (schema.SCHEMA_VERSION_KEY, "7"))
    _initialised.clear()
    assert stored_schema_version() == 7

    init_db()

    assert any(MIGRATION_TAG in path.name for path in list_backups())
    assert stored_schema_version() == schema.SCHEMA_VERSION


def test_a_failed_upgrade_is_rolled_back(populated: Any) -> None:
    """The assertion the whole feature exists for.

    SQLite has no downgrade path, so restoring the file is the *only* rollback
    -- and a database migrated past the point of return with no copy is a lost
    site.
    """
    from lpr.db import schema
    from lpr.db.connection import _initialised, database_path, shutdown, transaction

    with transaction() as tx:
        tx.execute(schema.UPSERT_SCHEMA_META, (schema.SCHEMA_VERSION_KEY, "7"))
    _initialised.clear()

    original = schema.ALL_DDL
    schema.ALL_DDL = (*original, "CREATE TABLE broken (")
    try:
        with pytest.raises(sqlite3.OperationalError):
            init_db()
    finally:
        schema.ALL_DDL = original

    shutdown()
    conn = sqlite3.connect(database_path())
    try:
        rows = dict(conn.execute("SELECT plate, owner FROM plates").fetchall())
        version = conn.execute(
            "SELECT value FROM schema_meta WHERE key = ?", (schema.SCHEMA_VERSION_KEY,)
        ).fetchone()
    finally:
        conn.close()

    assert rows == {"34ABC123": "Ahmet", "06AB456": "Zeynep"}, "data survived"
    assert version is not None and version[0] == "7", "the version was rolled back too"


def test_an_upgrade_is_refused_when_the_backup_fails(populated: Any, monkeypatch) -> None:
    """Proceeding without a copy trades a recoverable situation for an
    unrecoverable one. A gate that will not start is a service call; a
    database migrated with no copy is a lost site."""
    import lpr.db.backup as backup_module
    from lpr.db import schema
    from lpr.db.connection import _initialised, transaction

    with transaction() as tx:
        tx.execute(schema.UPSERT_SCHEMA_META, (schema.SCHEMA_VERSION_KEY, "7"))
    _initialised.clear()

    monkeypatch.setattr(
        backup_module,
        "backup_database",
        lambda *a, **k: backup_module.BackupResult(path=None, error="no space"),
    )

    with pytest.raises(RuntimeError, match="pre-upgrade backup failed"):
        init_db()
