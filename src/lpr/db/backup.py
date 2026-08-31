"""Live SQLite backups, and the safety net around a schema upgrade.

Two callers, one mechanism:

* the scheduler, which takes a rolling backup on a timer, so a corrupted file
  or a deleted volume costs a day rather than the whole site's plate list; and
* :func:`lpr.db.connection.init_db`, which takes one immediately before it
  touches the schema, so a failed upgrade can be undone.

Why ``VACUUM INTO`` rather than copying the file
------------------------------------------------
The database is open, WAL is on, and the gate keeps writing while the backup
runs. Copying ``plates.db`` with ``shutil.copy`` captures the main file without
the write-ahead log, which is not a database -- it is a database missing its
most recent transactions, and it restores as one. ``VACUUM INTO`` runs inside
SQLite, sees a consistent snapshot including the WAL, and writes a compacted
file that opens cleanly. It also needs no extra connection, no locking dance
and no C API access that ``sqlite3.Connection.backup`` would want a second
connection for.

Why the migration backup is separate from the timer
---------------------------------------------------
A schema change is the one operation here that cannot be undone. SQLite has no
``ALTER TABLE DROP COLUMN`` worth relying on and no downgrade path at all, so
"restore the file" is the *only* rollback, and a backup from up to a day ago is
not one. :func:`backup_before_migration` runs synchronously, and
:func:`restore` puts the file back when the upgrade raises.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from lpr.db.connection import MEMORY, database_path, get_connection

logger = logging.getLogger(__name__)

__all__ = [
    "BACKUP_SUFFIX",
    "BackupResult",
    "backup_before_migration",
    "backup_database",
    "list_backups",
    "prune_backups",
    "restore",
]

#: Extension for a backup file. Distinct from ``.db`` on purpose: the retention
#: sweep in :func:`prune_backups` globs for it, and it must be impossible for
#: that glob to match the live database.
BACKUP_SUFFIX = ".db.bak"

#: Marker inserted into a pre-migration backup's name, so the scheduled
#: rolling backups and the one-off safety copies are told apart at a glance --
#: and so a pre-migration copy is never pruned as if it were routine.
MIGRATION_TAG = "premigrate"


@dataclass(frozen=True, slots=True)
class BackupResult:
    """What one backup attempt produced."""

    path: Path | None
    bytes_written: int = 0
    duration_s: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.path is not None and self.error is None


def _timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def _unique(target: Path) -> Path:
    """``target``, or the first free ``name-2``, ``name-3`` beside it.

    The timestamp in a generated name has one-second resolution, so two
    backups taken inside the same second would land on the same path and the
    second would silently replace the first. That is fine for a scheduler
    running hourly and wrong for anything else -- including the pre-migration
    copy, which may well be taken in the same second as a routine one and is
    the last thing that should be overwritten.
    """
    if not target.exists():
        return target
    suffixed = target.name.endswith(BACKUP_SUFFIX)
    stem = target.name[: -len(BACKUP_SUFFIX)] if suffixed else target.stem
    for index in range(2, 1000):
        candidate = target.with_name(f"{stem}-{index}{BACKUP_SUFFIX}")
        if not candidate.exists():
            return candidate
    return target  # pragma: no cover - 1000 backups in one second


def backup_dir(root: str | Path | None = None) -> Path:
    """Where backups live: ``<database dir>/backups`` unless told otherwise."""
    if root is not None:
        return Path(root)
    return Path(database_path()).parent / "backups"


def backup_database(
    destination: str | Path | None = None,
    *,
    tag: str = "",
) -> BackupResult:
    """Write a consistent copy of the live database. Never raises.

    ``destination`` may be a file or a directory; a directory (or ``None``, the
    default) gets a timestamped name inside it. Returns a :class:`BackupResult`
    whose ``ok`` says whether anything usable was produced -- callers on the
    scheduler path log it and carry on, while the migration path checks it and
    refuses to proceed without one.

    An in-memory database has nothing to back up and reports success with no
    path, so a test run does not have to special-case this.
    """
    started = time.perf_counter()
    source = database_path()
    if source == MEMORY:
        logger.debug("In-memory database; nothing to back up")
        return BackupResult(path=None)

    if destination is None:
        target_dir = backup_dir()
        target = target_dir / f"plates-{_timestamp()}{f'-{tag}' if tag else ''}{BACKUP_SUFFIX}"
    else:
        candidate = Path(destination)
        if candidate.is_dir() or not candidate.suffix:
            target = candidate / (
                f"plates-{_timestamp()}{f'-{tag}' if tag else ''}{BACKUP_SUFFIX}"
            )
        else:
            target = candidate

    target = _unique(target)

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("Could not create backup directory %s: %s", target.parent, exc)
        return BackupResult(path=None, error=str(exc))

    # VACUUM INTO refuses to overwrite, which is a feature: a half-written
    # backup must never masquerade as a good one. Write to a temporary name and
    # rename, so a reader can never observe a partial file under a real name.
    scratch = target.with_name(target.name + ".part")
    try:
        scratch.unlink(missing_ok=True)
        conn = get_connection()
        # Parameter binding is not allowed for VACUUM INTO's target, so the
        # path is interpolated -- as a quoted SQL string literal with embedded
        # quotes doubled, which is the escaping SQLite itself specifies.
        literal = str(scratch).replace("'", "''")
        conn.execute(f"VACUUM INTO '{literal}'")
        os.replace(scratch, target)
    except Exception as exc:
        scratch.unlink(missing_ok=True)
        logger.warning("Database backup failed: %s", exc, exc_info=True)
        return BackupResult(path=None, error=str(exc))

    try:
        written = target.stat().st_size
    except OSError:
        written = 0

    duration = time.perf_counter() - started
    logger.info(
        "Database backed up to %s (%.1f MB in %.2fs)",
        target,
        written / 1024 / 1024,
        duration,
    )
    return BackupResult(path=target, bytes_written=written, duration_s=duration)


def backup_before_migration(tag: str = MIGRATION_TAG) -> BackupResult:
    """Take the pre-upgrade safety copy. Same call, different name and intent.

    Named separately because the two backups have different failure policies:
    a scheduled backup that fails is logged, while a *this* one that fails is
    a reason not to migrate. The caller enforces that; this function only
    makes the distinction visible at the call site.
    """
    return backup_database(tag=tag)


def restore(backup: str | Path, *, target: str | Path | None = None) -> bool:
    """Put ``backup`` back in place of the live database. Returns success.

    The live file is moved aside rather than deleted, so a restore that turns
    out to be the wrong call is itself reversible. The WAL and shared-memory
    sidecars are removed: they belong to the database being replaced, and a
    stale ``-wal`` next to a restored file is how a "successful" restore comes
    back up with the transactions it was supposed to undo.

    Every connection to this database must be closed first. The caller owns
    that -- this function cannot know about the other threads' handles.
    """
    source = Path(backup)
    destination = Path(target) if target is not None else Path(database_path())

    if not source.is_file():
        logger.error("Cannot restore: %s does not exist", source)
        return False

    try:
        if destination.exists():
            aside = destination.with_name(f"{destination.name}.failed-{_timestamp()}")
            os.replace(destination, aside)
            logger.info("Displaced database kept at %s", aside)
        for sidecar in ("-wal", "-shm"):
            Path(str(destination) + sidecar).unlink(missing_ok=True)
        shutil.copy2(source, destination)
    except OSError as exc:
        logger.error("Restore from %s failed: %s", source, exc, exc_info=True)
        return False

    logger.warning("Database restored from %s", source)
    return True


def list_backups(root: str | Path | None = None) -> list[Path]:
    """Every backup file, newest first."""
    directory = backup_dir(root)
    if not directory.is_dir():
        return []
    entries = [path for path in directory.glob(f"*{BACKUP_SUFFIX}") if path.is_file()]
    entries.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return entries


def prune_backups(keep: int = 7, root: str | Path | None = None) -> int:
    """Delete all but the newest ``keep`` *routine* backups. Returns the count.

    Pre-migration copies are never pruned. They are the rollback for an
    irreversible operation, they are rare, and a rolling window that swept them
    away would remove the safety net precisely when a series of upgrades had
    made it most valuable.
    """
    if keep < 1:
        return 0
    routine = [path for path in list_backups(root) if MIGRATION_TAG not in path.name]
    deleted = 0
    for path in routine[keep:]:
        try:
            path.unlink()
            deleted += 1
        except OSError as exc:  # pragma: no cover - permissions
            logger.warning("Could not delete old backup %s: %s", path, exc)
    if deleted:
        logger.info("Pruned %d old database backup(s), keeping %d", deleted, keep)
    return deleted
