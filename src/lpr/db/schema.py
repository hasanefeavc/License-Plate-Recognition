"""Database schema: every DDL statement in the project lives here.

Two rules this module exists to enforce:

1. **Static SQL only.** Nothing here is built with an f-string, ``%`` or
   ``.format()``. The legacy app created one table per day
   (``logs_2024_05_01``) by interpolating a date into the DDL *and* into
   every ``INSERT``/``SELECT`` that touched it. That made the schema
   unknowable ahead of time, defeated prepared statements, prevented
   indexes and made cross-day queries impossible. There is now exactly one
   ``logs`` table with a ``ts`` column and real indexes.
2. **One place to look.** ``connection.init_db()`` applies ``ALL_DDL`` in a
   single transaction, so creating a database is idempotent and atomic.
"""

from __future__ import annotations

from typing import Final

#: Bumped whenever ``ALL_DDL`` changes shape. Stored in ``schema_meta``.
#: v2 added ``system_meta`` (licence token + anti-rollback clock).
SCHEMA_VERSION: Final[int] = 2

SCHEMA_VERSION_KEY: Final[str] = "schema_version"

#: Set by ``lpr.db.migrate`` once the legacy import has run, so that a second
#: run is a no-op.
LEGACY_IMPORT_KEY: Final[str] = "legacy_import_completed_at"


CREATE_PLATES: Final[str] = """
CREATE TABLE IF NOT EXISTS plates (
    plate    TEXT PRIMARY KEY,
    added_at TEXT NOT NULL,
    note     TEXT
)
"""

CREATE_USERS: Final[str] = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'operator',
    created_at    TEXT NOT NULL
)
"""

CREATE_LOGS: Final[str] = """
CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    camera     TEXT NOT NULL,
    plate      TEXT NOT NULL,
    action     TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0
)
"""

CREATE_SCHEMA_META: Final[str] = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
)
"""

#: Runtime state that is neither user data nor schema bookkeeping: the active
#: licence token and the monotonic "last seen" wall clock the licence check
#: uses to notice a rolled-back system clock. Deliberately a separate table
#: from ``schema_meta`` so a schema migration can never clobber a licence.
CREATE_SYSTEM_META: Final[str] = """
CREATE TABLE IF NOT EXISTS system_meta (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL
)
"""

CREATE_IDX_LOGS_TS: Final[str] = "CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts)"

CREATE_IDX_LOGS_PLATE: Final[str] = "CREATE INDEX IF NOT EXISTS idx_logs_plate ON logs(plate)"

CREATE_IDX_LOGS_CAMERA_TS: Final[str] = (
    "CREATE INDEX IF NOT EXISTS idx_logs_camera_ts ON logs(camera, ts)"
)

#: Applied in order, inside one transaction, by ``connection.init_db()``.
ALL_DDL: Final[tuple[str, ...]] = (
    CREATE_PLATES,
    CREATE_USERS,
    CREATE_LOGS,
    CREATE_SCHEMA_META,
    CREATE_SYSTEM_META,
    CREATE_IDX_LOGS_TS,
    CREATE_IDX_LOGS_PLATE,
    CREATE_IDX_LOGS_CAMERA_TS,
)

#: Connection-level pragmas applied to every new connection.
#:
#: - ``journal_mode=WAL``  : readers never block the single writer.
#: - ``synchronous=NORMAL``: safe under WAL, far fewer fsyncs than FULL.
#: - ``foreign_keys=ON``   : SQLite defaults this to OFF, per connection.
#: - ``busy_timeout=5000`` : wait up to 5s for the write lock instead of
#:   raising ``database is locked`` the instant two threads collide.
CONNECTION_PRAGMAS: Final[tuple[str, ...]] = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA foreign_keys=ON",
    "PRAGMA busy_timeout=5000",
)

UPSERT_SCHEMA_META: Final[str] = (
    "INSERT INTO schema_meta (key, value) VALUES (?, ?) "
    "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
)

SELECT_SCHEMA_META: Final[str] = "SELECT value FROM schema_meta WHERE key = ?"

UPSERT_SYSTEM_META: Final[str] = (
    "INSERT INTO system_meta (key, value, updated_at) VALUES (?, ?, ?) "
    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
    "updated_at = excluded.updated_at"
)

SELECT_SYSTEM_META: Final[str] = "SELECT value FROM system_meta WHERE key = ?"

DELETE_SYSTEM_META: Final[str] = "DELETE FROM system_meta WHERE key = ?"
