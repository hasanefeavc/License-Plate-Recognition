"""Thread-local SQLite connections.

The legacy application opened **one** ``sqlite3.Connection`` at import time
with ``check_same_thread=False`` and shared it between the Tkinter main loop
and the capture thread. That is not merely unsupported, it silently
corrupts cursor state: two threads stepping the same connection interleave
their statement execution and one of them gets the other's rows (or a
``ProgrammingError``, if it is lucky).

The fix here is the standard one: SQLite connections are cheap, so every
thread gets its own via ``threading.local()``. WAL journalling lets those
connections read concurrently while one writes, and ``busy_timeout`` makes
writer collisions wait instead of raising.

Typical use::

    from lpr.db import get_connection, init_db, transaction

    init_db()                      # once, at startup; idempotent
    conn = get_connection()        # this thread's connection
    with transaction() as conn:    # BEGIN IMMEDIATE / COMMIT / ROLLBACK
        conn.execute(...)
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from lpr.config import get_settings
from lpr.db import schema
from lpr.platform_compat import hide_file

logger = logging.getLogger(__name__)

#: Sentinel meaning "in-memory database". Because every thread opens its own
#: connection, a plain ``:memory:`` would give each thread a *different*
#: empty database. A shared-cache URI plus a process-lifetime keepalive
#: connection makes one in-memory database visible to all of them, which is
#: what tests expect.
MEMORY = ":memory:"
_MEMORY_URI = "file:lpr_shared_memdb?mode=memory&cache=shared"

_local = threading.local()

_registry_lock = threading.Lock()
#: thread ident -> connection, so ``shutdown()`` can reach connections that
#: belong to worker threads which have already exited.
_connections: dict[int, sqlite3.Connection] = {}

_init_lock = threading.Lock()
_initialised: set[str] = set()

#: Keeps the shared in-memory database alive even when no thread-local
#: connection is currently open.
_memory_keepalive: sqlite3.Connection | None = None


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def database_path() -> str:
    """The database this process should talk to, as a string.

    Returns the :data:`MEMORY` sentinel for in-memory configurations,
    otherwise an absolute filesystem path (whose parent directory is created
    on access by ``Settings.paths``).
    """
    settings = get_settings()
    raw = (settings.database.path or "").strip()
    if raw in {MEMORY, "", "file::memory:"}:
        return MEMORY
    return str(settings.paths.database)


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------


def _open(path: str) -> sqlite3.Connection:
    """Open and configure one connection. Never shared between threads."""
    global _memory_keepalive

    if path == MEMORY:
        conn = sqlite3.connect(_MEMORY_URI, uri=True, timeout=5.0)
        if _memory_keepalive is None:
            # Opened from whichever thread got here first; it is only ever
            # held open, never used to run statements, so thread affinity
            # does not matter in practice.
            _memory_keepalive = sqlite3.connect(
                _MEMORY_URI, uri=True, timeout=5.0, check_same_thread=False
            )
    else:
        conn = sqlite3.connect(path, timeout=5.0)

    conn.row_factory = sqlite3.Row
    # Autocommit mode: transactions are explicit and live in transaction().
    conn.isolation_level = None

    for pragma in schema.CONNECTION_PRAGMAS:
        try:
            conn.execute(pragma)
        except sqlite3.DatabaseError as exc:  # pragma: no cover - very unusual
            # An in-memory database ignores journal_mode=WAL (it reports
            # "memory"); anything else failing is worth a warning but is not
            # fatal, the connection still works with SQLite defaults.
            logger.warning("Could not apply %r: %s", pragma, exc)

    logger.debug("Opened SQLite connection to %s on thread %s", path, threading.get_ident())
    return conn


def get_connection() -> sqlite3.Connection:
    """Return this thread's connection, opening it on first use.

    If the configured database path has changed since this thread last
    connected (which is what happens when a test monkeypatches settings),
    the stale connection is closed and a fresh one is opened.
    """
    path = database_path()
    conn: sqlite3.Connection | None = getattr(_local, "conn", None)
    conn_path: str | None = getattr(_local, "path", None)

    if conn is not None and conn_path == path:
        return conn

    if conn is not None:
        _discard_local()

    conn = _open(path)
    _local.conn = conn
    _local.path = path
    with _registry_lock:
        _connections[threading.get_ident()] = conn
    return conn


def _discard_local() -> None:
    """Close and forget this thread's connection, if any."""
    conn: sqlite3.Connection | None = getattr(_local, "conn", None)
    _local.conn = None
    _local.path = None
    with _registry_lock:
        _connections.pop(threading.get_ident(), None)
    if conn is None:
        return
    try:
        conn.close()
    except sqlite3.Error as exc:  # pragma: no cover - defensive
        logger.debug("Error closing connection: %s", exc)


def close_all() -> None:
    """Close the calling thread's connection.

    Worker threads should call this on the way out so the file handle and
    WAL reader mark are released promptly rather than at interpreter exit.
    """
    _discard_local()


def shutdown() -> None:
    """Close every connection this process opened. Call once, at exit.

    Connections belonging to other threads are closed best-effort;
    ``sqlite3`` refuses cross-thread use, so a failure here is logged at
    debug level and the connection is simply dropped for the garbage
    collector to finalise.
    """
    global _memory_keepalive

    _discard_local()
    with _registry_lock:
        stragglers = list(_connections.items())
        _connections.clear()

    for ident, conn in stragglers:
        try:
            conn.close()
        except sqlite3.Error as exc:
            logger.debug("Could not close connection from thread %s: %s", ident, exc)

    if _memory_keepalive is not None:
        try:
            _memory_keepalive.close()
        except sqlite3.Error:  # pragma: no cover - defensive
            pass
        _memory_keepalive = None

    with _init_lock:
        _initialised.clear()


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """Run a block inside a transaction on the calling thread's connection.

    Commits on clean exit, rolls back on any exception, and re-raises. Safe
    to nest: an inner ``transaction()`` inside an outer one uses a SAVEPOINT
    so a partial failure does not silently commit the outer work.
    """
    conn = get_connection()

    if conn.in_transaction:
        savepoint = f"sp_{threading.get_ident()}_{id(conn)}"
        # Identifier is derived from integers we generate, never user input.
        conn.execute(f'SAVEPOINT "{savepoint}"')
        try:
            yield conn
        except BaseException:
            conn.execute(f'ROLLBACK TO "{savepoint}"')
            conn.execute(f'RELEASE "{savepoint}"')
            raise
        else:
            conn.execute(f'RELEASE "{savepoint}"')
        return

    # IMMEDIATE takes the write lock up front, so two writers queue on
    # busy_timeout instead of deadlocking on a deferred lock upgrade.
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        try:
            conn.rollback()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            logger.error("Rollback failed: %s", exc)
        raise
    else:
        conn.commit()


# ---------------------------------------------------------------------------
# Schema creation
# ---------------------------------------------------------------------------


def init_db(force: bool = False) -> None:
    """Create the schema if it is not there yet.

    Idempotent and safe to call from several threads at once: the work is
    guarded by a module lock and remembered per database path, so the DDL is
    applied at most once per path per process (and the DDL itself is all
    ``IF NOT EXISTS`` anyway).
    """
    path = database_path()

    with _init_lock:
        if path in _initialised and not force:
            return

        with transaction() as tx:
            for statement in schema.ALL_DDL:
                tx.execute(statement)
            tx.execute(
                schema.UPSERT_SCHEMA_META,
                (schema.SCHEMA_VERSION_KEY, str(schema.SCHEMA_VERSION)),
            )
        _initialised.add(path)
        logger.info("Database ready at %s (schema v%d)", path, schema.SCHEMA_VERSION)

    if path != MEMORY:
        # Windows nicety carried over from the legacy app; a documented
        # no-op everywhere else. All OS branching lives in platform_compat.
        hide_file(path)


def schema_version() -> int:
    """Version recorded in ``schema_meta``, or 0 if the table is empty."""
    conn = get_connection()
    row = conn.execute(schema.SELECT_SCHEMA_META, (schema.SCHEMA_VERSION_KEY,)).fetchone()
    if row is None:
        return 0
    try:
        return int(row["value"])
    except (TypeError, ValueError):  # pragma: no cover - corrupt metadata
        return 0
