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
#: v3 added ``system_events`` (operational audit trail: OTA updates).
#: v4 added the resident columns on ``plates`` (owner, apartment, expires_at,
#: blocked), applied to existing databases by ``PLATES_ADDED_COLUMNS``.
#: v5 added ``users.token_ttl_min`` (per-account session length).
#: v6 added the per-operator licence columns on ``users``.
#: v7 split generation from activation: ``license_duration_days`` and
#: ``license_activated_at``, so the countdown starts when the operator enters
#: the key rather than when the admin cuts it.
#: v8 added ``plates.username``, recording which account a car belongs to. It
#: is ownership metadata for the management screen only: the barrier never
#: reads it, because a user's licence governs their access to the dashboard and
#: not their car's access to the car park.
#: v9 added ``logs.snapshot_path`` (the evidence photo behind a decision) and
#: the ``sessions`` table (entry/exit pairing and stay duration). Both are
#: additive: ``snapshot_path`` arrives through ``LOGS_ADDED_COLUMNS`` and every
#: pre-v9 row keeps NULL, which reads as "no photograph was linked", the same
#: answer a row whose file has since been pruned gives.
SCHEMA_VERSION: Final[int] = 9

SCHEMA_VERSION_KEY: Final[str] = "schema_version"

#: Set by ``lpr.db.migrate`` once the legacy import has run, so that a second
#: run is a no-op.
LEGACY_IMPORT_KEY: Final[str] = "legacy_import_completed_at"


CREATE_PLATES: Final[str] = """
CREATE TABLE IF NOT EXISTS plates (
    plate      TEXT PRIMARY KEY,
    added_at   TEXT NOT NULL,
    note       TEXT,
    owner      TEXT,
    apartment  TEXT,
    expires_at TEXT,
    blocked    INTEGER NOT NULL DEFAULT 0,
    username   TEXT
)
"""

#: Columns added to ``plates`` after v2 shipped, as ``(name, DDL fragment)``.
#:
#: ``CREATE TABLE IF NOT EXISTS`` does nothing to a table that already exists,
#: so a database created before v4 would silently keep the three-column
#: ``plates`` and every query naming ``owner`` would fail. ``init_db`` walks
#: this list against ``PRAGMA table_info`` and issues the missing
#: ``ALTER TABLE ADD COLUMN`` statements.
#:
#: Additive only, and every column nullable or defaulted -- SQLite can add such
#: a column to a populated table without rewriting it, and an older build
#: reading the same file still works because it never names them.
PLATES_ADDED_COLUMNS: Final[tuple[tuple[str, str], ...]] = (
    ("owner", "ALTER TABLE plates ADD COLUMN owner TEXT"),
    ("apartment", "ALTER TABLE plates ADD COLUMN apartment TEXT"),
    ("expires_at", "ALTER TABLE plates ADD COLUMN expires_at TEXT"),
    ("blocked", "ALTER TABLE plates ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0"),
    # Ownership metadata: which account a car belongs to. Deliberately *not* a
    # foreign key, and deliberately not consulted at the barrier -- see
    # ``PlateRepository.authorization``. NULL means "not recorded", which is
    # what every pre-v8 row is.
    ("username", "ALTER TABLE plates ADD COLUMN username TEXT"),
)

CREATE_USERS: Final[str] = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'operator',
    created_at    TEXT NOT NULL,
    token_ttl_min INTEGER,
    license_key           TEXT,
    license_expires_at    TEXT,
    license_status        TEXT,
    license_duration_days INTEGER,
    license_activated_at  TEXT
)
"""

#: Columns added to ``users`` after v4. Same additive migration as
#: ``PLATES_ADDED_COLUMNS``; see :func:`lpr.db.connection.init_db`.
#:
#: NULL means "use the default for this account's role", which is what every
#: pre-v5 row gets -- so an existing installation keeps working and simply
#: inherits the role policy rather than needing a backfill.
USERS_ADDED_COLUMNS: Final[tuple[tuple[str, str], ...]] = (
    ("token_ttl_min", "ALTER TABLE users ADD COLUMN token_ttl_min INTEGER"),
    ("license_key", "ALTER TABLE users ADD COLUMN license_key TEXT"),
    ("license_expires_at", "ALTER TABLE users ADD COLUMN license_expires_at TEXT"),
    ("license_status", "ALTER TABLE users ADD COLUMN license_status TEXT"),
    (
        "license_duration_days",
        "ALTER TABLE users ADD COLUMN license_duration_days INTEGER",
    ),
    ("license_activated_at", "ALTER TABLE users ADD COLUMN license_activated_at TEXT"),
)

CREATE_LOGS: Final[str] = """
CREATE TABLE IF NOT EXISTS logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    camera        TEXT NOT NULL,
    plate         TEXT NOT NULL,
    action        TEXT NOT NULL,
    confidence    REAL NOT NULL DEFAULT 0,
    snapshot_path TEXT
)
"""

#: Columns added to ``logs`` after v8. Same additive migration as
#: ``PLATES_ADDED_COLUMNS``; see :func:`lpr.db.connection.init_db`.
#:
#: ``snapshot_path`` is the evidence photo behind one decision, written by the
#: snapshot writer and linked back once the file exists on disk. Nullable
#: because it genuinely is optional at three separate moments: snapshots may be
#: switched off, the writer drops frames when the disk cannot keep up, and the
#: retention sweep deletes old files while their rows survive. Every one of
#: those reads as NULL, and the API answers 404 for all of them alike.
LOGS_ADDED_COLUMNS: Final[tuple[tuple[str, str], ...]] = (
    ("snapshot_path", "ALTER TABLE logs ADD COLUMN snapshot_path TEXT"),
)

#: Vehicle sessions: one row per stay, paired from the gate log.
#:
#: Deliberately a *record* of what the log already implies rather than a new
#: source of truth. ``PlateRepository.occupancy_since`` keeps deriving the live
#: count by scanning grants, and it is left alone: a derived number that
#: disagrees with this table is a bug detector worth keeping, and the barrier
#: must never depend on a bookkeeping table being healthy.
#:
#: ``entry_ts`` is nullable because an exit can legitimately arrive with no
#: entry behind it -- a car that was already inside when the system was
#: installed, or one whose entry read was missed. See
#: ``SessionRepository.close_session`` for why that is recorded rather than
#: dropped.
CREATE_SESSIONS: Final[str] = """
CREATE TABLE IF NOT EXISTS sessions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    plate            TEXT NOT NULL,
    entry_ts         TEXT,
    exit_ts          TEXT,
    entry_log_id     INTEGER,
    exit_log_id      INTEGER,
    duration_seconds INTEGER,
    status           TEXT NOT NULL DEFAULT 'open'
)
"""

#: ``get_active_sessions`` filters on ``status`` and orders by ``entry_ts``;
#: ``close_session`` looks up the open row for one plate. One composite index
#: serves both without a second structure to keep current.
CREATE_IDX_SESSIONS_STATUS_PLATE: Final[str] = (
    "CREATE INDEX IF NOT EXISTS idx_sessions_status_plate ON sessions(status, plate)"
)

CREATE_IDX_SESSIONS_ENTRY_TS: Final[str] = (
    "CREATE INDEX IF NOT EXISTS idx_sessions_entry_ts ON sessions(entry_ts)"
)

#: Status values. ``open`` is inside; ``closed`` is a completed stay;
#: ``orphan_exit`` is an exit whose entry was never seen.
SESSION_OPEN: Final[str] = "open"
SESSION_CLOSED: Final[str] = "closed"
SESSION_ORPHAN_EXIT: Final[str] = "orphan_exit"

_SESSION_COLUMNS: Final[str] = (
    "id, plate, entry_ts, exit_ts, entry_log_id, exit_log_id, duration_seconds, status"
)

INSERT_SESSION: Final[str] = (
    "INSERT INTO sessions (plate, entry_ts, entry_log_id, status) VALUES (?, ?, ?, ?)"
)

SELECT_OPEN_SESSION: Final[str] = (
    f"SELECT {_SESSION_COLUMNS} FROM sessions "
    "WHERE status = 'open' AND plate = ? ORDER BY id DESC LIMIT 1"
)

SELECT_ACTIVE_SESSIONS: Final[str] = (
    f"SELECT {_SESSION_COLUMNS} FROM sessions WHERE status = 'open' ORDER BY entry_ts ASC, id ASC"
)

SELECT_SESSIONS_HISTORY: Final[str] = (
    f"SELECT {_SESSION_COLUMNS} FROM sessions ORDER BY id DESC LIMIT ? OFFSET ?"
)

SELECT_SESSIONS_HISTORY_BY_PLATE: Final[str] = (
    f"SELECT {_SESSION_COLUMNS} FROM sessions WHERE plate = ? ORDER BY id DESC LIMIT ? OFFSET ?"
)

CLOSE_SESSION: Final[str] = (
    "UPDATE sessions SET exit_ts = ?, exit_log_id = ?, duration_seconds = ?, "
    "status = 'closed' WHERE id = ?"
)

INSERT_ORPHAN_EXIT: Final[str] = (
    "INSERT INTO sessions (plate, entry_ts, exit_ts, exit_log_id, status) "
    "VALUES (?, NULL, ?, ?, 'orphan_exit')"
)

COUNT_ACTIVE_SESSIONS: Final[str] = "SELECT COUNT(*) AS n FROM sessions WHERE status = 'open'"

COUNT_SESSIONS: Final[str] = "SELECT COUNT(*) AS n FROM sessions"

UPDATE_LOG_SNAPSHOT: Final[str] = "UPDATE logs SET snapshot_path = ? WHERE id = ?"

SELECT_LOG_SNAPSHOT: Final[str] = "SELECT snapshot_path FROM logs WHERE id = ?"

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

#: Operational audit trail, deliberately *not* the ``logs`` table.
#:
#: ``logs`` is plate traffic: every row is a vehicle at a barrier, and it is
#: what feeds the history view, the CSV export and the occupancy arithmetic.
#: Putting "an update ran at 03:00" in there would appear in an operator's
#: history as a car, and would be counted by ``occupancy_since``. A separate
#: table keeps the two kinds of history from corrupting each other.
CREATE_SYSTEM_EVENTS: Final[str] = """
CREATE TABLE IF NOT EXISTS system_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    source  TEXT NOT NULL,
    level   TEXT NOT NULL,
    message TEXT NOT NULL,
    detail  TEXT
)
"""

CREATE_IDX_SYSTEM_EVENTS_TS: Final[str] = (
    "CREATE INDEX IF NOT EXISTS idx_system_events_ts ON system_events(ts)"
)

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
    CREATE_SESSIONS,
    CREATE_SCHEMA_META,
    CREATE_SYSTEM_META,
    CREATE_SYSTEM_EVENTS,
    CREATE_IDX_LOGS_TS,
    CREATE_IDX_LOGS_PLATE,
    CREATE_IDX_LOGS_CAMERA_TS,
    CREATE_IDX_SESSIONS_STATUS_PLATE,
    CREATE_IDX_SESSIONS_ENTRY_TS,
    CREATE_IDX_SYSTEM_EVENTS_TS,
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

INSERT_SYSTEM_EVENT: Final[str] = (
    "INSERT INTO system_events (ts, source, level, message, detail) VALUES (?, ?, ?, ?, ?)"
)

SELECT_SYSTEM_EVENTS: Final[str] = (
    "SELECT id, ts, source, level, message, detail FROM system_events ORDER BY id DESC LIMIT ?"
)

SELECT_SYSTEM_EVENTS_BY_SOURCE: Final[str] = (
    "SELECT id, ts, source, level, message, detail FROM system_events "
    "WHERE source = ? ORDER BY id DESC LIMIT ?"
)

DELETE_SYSTEM_EVENTS_OLDER_THAN: Final[str] = "DELETE FROM system_events WHERE ts < ?"

#: Columns of ``plates`` in the order the CSV export writes them.
PLATE_COLUMNS: Final[tuple[str, ...]] = (
    "plate",
    "owner",
    "apartment",
    "note",
    "expires_at",
    "blocked",
    "added_at",
    "username",
)

SELECT_PLATE_DETAIL: Final[str] = (
    "SELECT plate, added_at, note, owner, apartment, expires_at, blocked, username "
    "FROM plates WHERE plate = ?"
)

SELECT_PLATES_DETAIL: Final[str] = (
    "SELECT plate, added_at, note, owner, apartment, expires_at, blocked, username "
    "FROM plates ORDER BY plate"
)

#: Never selects ``password_hash``. The licence *key* is included because an
#: admin has to be able to hand it to the operator it was issued for.
_USER_COLUMNS: Final[str] = (
    "username, role, created_at, token_ttl_min, "
    "license_key, license_expires_at, license_status, "
    "license_duration_days, license_activated_at"
)

SELECT_USERS: Final[str] = f"SELECT {_USER_COLUMNS} FROM users ORDER BY username"

SELECT_USER: Final[str] = f"SELECT {_USER_COLUMNS} FROM users WHERE username = ?"

UPDATE_USER_LICENSE: Final[str] = (
    "UPDATE users SET license_key = ?, license_expires_at = ?, license_status = ?, "
    "license_duration_days = ?, license_activated_at = ? WHERE username = ?"
)

COUNT_USERS_BY_ROLE: Final[str] = "SELECT COUNT(*) AS n FROM users WHERE role = ?"
