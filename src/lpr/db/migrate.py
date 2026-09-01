"""One-shot importer from the legacy single-file app's database layout.

The old ``plates.db`` looked like this::

    plates(plate TEXT PRIMARY KEY)
    users(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)   -- bare sha256
    log_dates(date TEXT PRIMARY KEY)                                -- bookkeeping
    logs_2024_05_01(timestamp TEXT, message TEXT)                   -- one per day!
    logs_2024_05_02(timestamp TEXT, message TEXT)
    ...

Each day's table was created with an f-string, the date was encoded in the
*table name* rather than in a column, and the payload was a free-text Turkish
sentence written for a Tkinter text widget. This module folds all of that
into the new ``plates`` / ``users`` / ``logs`` schema:

* ``logs_YYYY_MM_DD`` tables are discovered from ``sqlite_master``, the date
  is parsed out of the name and combined with the row's clock time to build
  a proper ISO-8601 UTC ``ts``.
* The free-text message is parsed back into ``(camera, plate, action)`` with
  the small grammar the old app actually emitted (see ``_MESSAGE_RULES``).
  A ``... > Plaka: 34ABC123`` line sets the "current plate" for that camera,
  so the follow-up "izin verildi" / "reddedildi" line can be attributed to
  it.
* Legacy password hashes are imported with a ``sha256$`` marker so
  ``UserRepository.verify`` accepts them exactly once and immediately
  rewrites the row with Argon2.

The whole import runs in one transaction and is idempotent: it records a
marker in ``schema_meta`` and additionally skips log rows that already exist.

Usage::

    python -m lpr.db.migrate               # migrate the configured database
    python -m lpr.db.migrate old_plates.db # import from a legacy file
"""

from __future__ import annotations

import argparse
import logging
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path

from lpr.contracts import Action, CameraRole, utc_now_iso
from lpr.db import schema
from lpr.db.connection import MEMORY, database_path, get_connection, init_db, transaction
from lpr.db.repository import LEGACY_PREFIX, normalise_plate

logger = logging.getLogger(__name__)

#: ``logs_2024_05_01`` -> groups ("2024", "05", "01")
LEGACY_LOG_TABLE_RE = re.compile(r"^logs_(\d{4})_(\d{2})_(\d{2})$")

#: ``2024-05-01 13:45:02`` (the legacy timestamp column) -> clock part.
LEGACY_TS_RE = re.compile(r"(\d{2}:\d{2}:\d{2})")

#: The plate as the old app printed it: "Giriş Kamerası > Plaka: 34 ABC 123".
PLATE_IN_MESSAGE_RE = re.compile(r"Plaka\s*[:>]\s*([A-Za-z0-9 ]{4,20})")

#: (needle, camera, action). Matched case-insensitively against the message.
_MESSAGE_RULES: tuple[tuple[str, str | None, Action], ...] = (
    ("giriş izni verildi", CameraRole.ENTRY, Action.GRANTED),
    ("giris izni verildi", CameraRole.ENTRY, Action.GRANTED),
    ("çıkış izni verildi", CameraRole.EXIT, Action.GRANTED),
    ("cikis izni verildi", CameraRole.EXIT, Action.GRANTED),
    ("giriş reddedildi", CameraRole.ENTRY, Action.DENIED),
    ("giris reddedildi", CameraRole.ENTRY, Action.DENIED),
    ("çıkış reddedildi", CameraRole.EXIT, Action.DENIED),
    ("cikis reddedildi", CameraRole.EXIT, Action.DENIED),
    ("izni verildi", None, Action.GRANTED),
    ("reddedildi", None, Action.DENIED),
)

UNKNOWN_PLATE = "UNKNOWN"


@dataclass(slots=True)
class MigrationReport:
    """What one :func:`migrate` run did. Also what gets logged as a summary."""

    source: str = ""
    legacy_log_tables: list[str] = field(default_factory=list)
    logs_imported: int = 0
    logs_skipped: int = 0
    logs_unparsed: int = 0
    plates_imported: int = 0
    users_imported: int = 0
    already_migrated: bool = False

    def summary(self) -> str:
        if self.already_migrated:
            return f"Legacy import already completed for {self.source}; nothing to do."
        return (
            f"Legacy import from {self.source}: "
            f"{len(self.legacy_log_tables)} per-day log table(s), "
            f"{self.logs_imported} log row(s) imported, "
            f"{self.logs_skipped} duplicate row(s) skipped, "
            f"{self.logs_unparsed} non-plate message(s) ignored, "
            f"{self.plates_imported} plate(s), {self.users_imported} user(s)."
        )


# ---------------------------------------------------------------------------
# Legacy introspection
# ---------------------------------------------------------------------------


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {str(row[0]) for row in rows}


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    # PRAGMA table_info cannot take a bound parameter, hence the quoted
    # identifier. `table` only ever comes from sqlite_master, never a user.
    safe = table.replace('"', '""')
    rows = conn.execute(f'PRAGMA table_info("{safe}")').fetchall()
    return {str(row[1]) for row in rows}


def find_legacy_log_tables(conn: sqlite3.Connection) -> list[str]:
    """All ``logs_YYYY_MM_DD`` tables present, oldest name first."""
    return sorted(name for name in _table_names(conn) if LEGACY_LOG_TABLE_RE.match(name))


def _legacy_table_date(table: str) -> str | None:
    match = LEGACY_LOG_TABLE_RE.match(table)
    if match is None:
        return None
    return "-".join(match.groups())


def _build_ts(day: str, raw_timestamp: str | None) -> str:
    """Combine the table-name date with the row's clock time into ISO-8601 UTC.

    The legacy rows stored local wall-clock time with no offset. There is no
    way to recover the original zone retroactively, so the value is tagged
    ``+00:00`` and treated as UTC from here on; the ordering within the
    archive is preserved, which is what the log viewer cares about.
    """
    clock = "00:00:00"
    if raw_timestamp:
        match = LEGACY_TS_RE.search(str(raw_timestamp))
        if match:
            clock = match.group(1)
    return f"{day}T{clock}+00:00"


def parse_legacy_message(message: str, last_plate: dict[str, str]) -> tuple[str, str, str] | None:
    """Turn one legacy log sentence into ``(camera, plate, action)``.

    ``last_plate`` maps camera role -> the most recently seen plate for that
    camera and is mutated as messages are consumed, which is how a bare
    "Kayıtlı plaka - Giriş izni verildi" line gets attributed to the plate
    announced on the line before it.

    Returns ``None`` for messages that are not plate events at all (system
    start/stop, camera-source changes, ...).
    """
    if not message:
        return None
    text = str(message)
    lowered = text.casefold()

    camera: str | None = None
    if "giriş" in lowered or "giris" in lowered:
        camera = str(CameraRole.ENTRY)
    elif "çıkış" in lowered or "cikis" in lowered:
        camera = str(CameraRole.EXIT)

    plate_match = PLATE_IN_MESSAGE_RE.search(text)
    if plate_match:
        plate = normalise_plate(plate_match.group(1))
        if plate:
            if camera is None:
                camera = str(CameraRole.ENTRY)
            last_plate[camera] = plate
            return camera, plate, str(Action.DETECTED)

    for needle, rule_camera, action in _MESSAGE_RULES:
        if needle in lowered:
            resolved = str(rule_camera) if rule_camera is not None else camera
            resolved = resolved or str(CameraRole.ENTRY)
            plate = last_plate.get(resolved, UNKNOWN_PLATE)
            return resolved, plate, str(action)

    return None


# ---------------------------------------------------------------------------
# Import steps
# ---------------------------------------------------------------------------


def _import_plates(
    tx: sqlite3.Connection, legacy: sqlite3.Connection, report: MigrationReport
) -> None:
    if "plates" not in _table_names(legacy):
        return
    columns = _column_names(legacy, "plates")
    if "plate" not in columns:
        logger.warning("Legacy 'plates' table has no 'plate' column; skipping.")
        return

    has_added_at = "added_at" in columns
    select = "SELECT plate, added_at FROM plates" if has_added_at else "SELECT plate FROM plates"
    for row in legacy.execute(select).fetchall():
        plate = normalise_plate(str(row[0] or ""))
        if not plate:
            continue
        added_at = str(row[1]) if has_added_at and row[1] else "1970-01-01T00:00:00+00:00"
        cur = tx.execute(
            "INSERT OR IGNORE INTO plates (plate, added_at, note) VALUES (?, ?, ?)",
            (plate, added_at, "imported from legacy database"),
        )
        report.plates_imported += int(cur.rowcount or 0)


def _import_users(
    tx: sqlite3.Connection, legacy: sqlite3.Connection, report: MigrationReport
) -> None:
    if "users" not in _table_names(legacy):
        return
    columns = _column_names(legacy, "users")
    if not {"username", "password_hash"} <= columns:
        logger.warning("Legacy 'users' table has an unexpected shape; skipping.")
        return

    has_role = "role" in columns
    select = (
        "SELECT username, password_hash, role FROM users"
        if has_role
        else "SELECT username, password_hash FROM users"
    )
    for row in legacy.execute(select).fetchall():
        username = str(row[0] or "").strip()
        digest = str(row[1] or "").strip()
        if not username or not digest:
            continue
        # Already-Argon2 rows (a partially migrated database) keep their hash.
        if digest.startswith("$argon2") or digest.startswith(LEGACY_PREFIX):
            stored = digest
        else:
            stored = f"{LEGACY_PREFIX}{digest}"
        role = str(row[2]) if has_role and row[2] else "operator"
        cur = tx.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, stored, role, "1970-01-01T00:00:00+00:00"),
        )
        report.users_imported += int(cur.rowcount or 0)


def _import_logs(
    tx: sqlite3.Connection, legacy: sqlite3.Connection, report: MigrationReport
) -> None:
    tables = find_legacy_log_tables(legacy)
    report.legacy_log_tables = tables
    if not tables:
        return

    for table in tables:
        day = _legacy_table_date(table)
        if day is None:  # pragma: no cover - guarded by the regex above
            continue
        columns = _column_names(legacy, table)
        if "message" not in columns:
            logger.warning("Legacy table %s has no 'message' column; skipping.", table)
            continue

        safe = table.replace('"', '""')
        order = "timestamp" if "timestamp" in columns else "rowid"
        select_ts = "timestamp" if "timestamp" in columns else "NULL"
        rows = legacy.execute(
            f'SELECT {select_ts}, message FROM "{safe}" ORDER BY {order}'  # noqa: S608
        ).fetchall()

        last_plate: dict[str, str] = {}
        for raw_ts, message in rows:
            parsed = parse_legacy_message(str(message or ""), last_plate)
            if parsed is None:
                report.logs_unparsed += 1
                continue
            camera, plate, action = parsed
            ts = _build_ts(day, raw_ts)

            existing = tx.execute(
                "SELECT 1 FROM logs WHERE ts = ? AND camera = ? AND plate = ? AND action = ?",
                (ts, camera, plate, action),
            ).fetchone()
            if existing is not None:
                report.logs_skipped += 1
                continue

            tx.execute(
                "INSERT INTO logs (ts, camera, plate, action, confidence) VALUES (?, ?, ?, ?, ?)",
                (ts, camera, plate, action, 0.0),
            )
            report.logs_imported += 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def already_migrated(conn: sqlite3.Connection) -> bool:
    row = conn.execute(schema.SELECT_SCHEMA_META, (schema.LEGACY_IMPORT_KEY,)).fetchone()
    return row is not None and bool(row[0])


def migrate(source: str | Path | None = None, force: bool = False) -> MigrationReport:
    """Import a legacy database into the current schema.

    Parameters
    ----------
    source:
        Path to the legacy ``plates.db``. Defaults to the configured
        database, i.e. an in-place upgrade of a file that already holds both
        the legacy tables and (after ``init_db``) the new ones.
    force:
        Re-run even if the ``schema_meta`` marker says the import already
        happened. Duplicate log rows are still skipped individually, so this
        is safe.
    """
    init_db()

    target = database_path()
    src = str(source) if source is not None else target
    report = MigrationReport(source=src)

    conn = get_connection()
    if already_migrated(conn) and not force:
        report.already_migrated = True
        logger.info(report.summary())
        return report

    if source is None or target == MEMORY:
        in_place = True
    else:
        in_place = Path(src).resolve() == Path(target).resolve()

    legacy: sqlite3.Connection
    if in_place:
        legacy = conn
    else:
        if not Path(src).exists():
            raise FileNotFoundError(f"Legacy database not found: {src}")
        # Read-only URI: the legacy file is never written to.
        legacy = sqlite3.connect(f"file:{Path(src).resolve()}?mode=ro", uri=True)

    try:
        with transaction() as tx:
            _import_plates(tx, legacy, report)
            _import_users(tx, legacy, report)
            _import_logs(tx, legacy, report)
            tx.execute(
                schema.UPSERT_SCHEMA_META,
                (schema.LEGACY_IMPORT_KEY, utc_now_iso()),
            )
    finally:
        if legacy is not conn:
            legacy.close()

    logger.info(report.summary())
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lpr.db.migrate",
        description="Import a legacy plates.db (per-day logs_* tables) into the new schema.",
    )
    parser.add_argument(
        "source",
        nargs="?",
        default=None,
        help="Legacy database file. Defaults to the configured database (in-place upgrade).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Run again even if the import marker is already set.",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging.")
    args = parser.parse_args(argv)

    from lpr.logging_conf import setup_logging

    setup_logging(level="DEBUG" if args.verbose else "INFO")

    try:
        report = migrate(args.source, force=args.force)
    except (FileNotFoundError, sqlite3.DatabaseError) as exc:
        logger.error("Migration failed: %s", exc)
        return 1

    print(report.summary())
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
