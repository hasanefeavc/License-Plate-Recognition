"""Repositories: the only place in the project that writes SQL.

Design notes
------------
* Every class here is **stateless** and has a no-argument constructor. They
  do not hold a connection; each method calls
  :func:`lpr.db.connection.get_connection` and therefore automatically uses
  the calling thread's own connection. That makes a single module-level
  ``plates = PlateRepository()`` instance safe to share between the capture
  threads, the API workers and the GUI.
* All SQL is parameterised. No value ever reaches SQLite through string
  formatting; the only interpolation that happens at all is assembling
  fixed ``WHERE`` fragments from a whitelist in
  :meth:`LogRepository.query`.
* Passwords are hashed with Argon2id. The legacy database stored bare,
  unsalted SHA-256 digests; those are imported with a ``sha256$`` marker and
  transparently upgraded the next time the user logs in successfully.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from lpr.contracts import Action, CameraRole, LprEvent, utc_now_iso
from lpr.db import schema
from lpr.db.connection import get_connection, transaction

if TYPE_CHECKING:  # pragma: no cover
    from argon2 import PasswordHasher

logger = logging.getLogger(__name__)

#: Prefix marking a password hash imported from the legacy schema. Anything
#: without this prefix is an Argon2 PHC string ("$argon2id$...").
LEGACY_PREFIX = "sha256$"

DEFAULT_ROLE = "operator"
ADMIN_ROLE = "admin"


def normalise_plate(plate: str) -> str:
    """Canonical plate form: uppercase, no whitespace at all.

    ``" 34 abc 123 "`` -> ``"34ABC123"``. Applied on every read and every
    write so a lookup can never miss because of stray spacing or case.
    """
    if not plate:
        return ""
    return "".join(str(plate).split()).upper()


def _row_to_event(row: Any) -> LprEvent:
    return LprEvent(
        id=row["id"],
        ts=row["ts"],
        camera=row["camera"],
        plate=row["plate"],
        action=row["action"],
        confidence=float(row["confidence"]),
    )


# ---------------------------------------------------------------------------
# Plates
# ---------------------------------------------------------------------------


class PlateRepository:
    """The whitelist of plates allowed through the gate."""

    __slots__ = ()

    def is_registered(self, plate: str) -> bool:
        key = normalise_plate(plate)
        if not key:
            return False
        conn = get_connection()
        row = conn.execute("SELECT 1 FROM plates WHERE plate = ?", (key,)).fetchone()
        return row is not None

    def add(self, plate: str, note: str | None = None) -> bool:
        """Register a plate. Returns False if it was already registered."""
        key = normalise_plate(plate)
        if not key:
            return False
        with transaction() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO plates (plate, added_at, note) VALUES (?, ?, ?)",
                (key, utc_now_iso(), note),
            )
            added = cur.rowcount > 0
        if added:
            logger.info("Plate registered: %s", key)
        return added

    def remove(self, plate: str) -> bool:
        """Deregister a plate. Returns False if it was not registered."""
        key = normalise_plate(plate)
        if not key:
            return False
        with transaction() as conn:
            cur = conn.execute("DELETE FROM plates WHERE plate = ?", (key,))
            removed = cur.rowcount > 0
        if removed:
            logger.info("Plate removed: %s", key)
        return removed

    def get(self, plate: str) -> dict[str, Any] | None:
        key = normalise_plate(plate)
        if not key:
            return None
        conn = get_connection()
        row = conn.execute(
            "SELECT plate, added_at, note FROM plates WHERE plate = ?", (key,)
        ).fetchone()
        return dict(row) if row is not None else None

    def all(self) -> list[str]:
        conn = get_connection()
        rows = conn.execute("SELECT plate FROM plates ORDER BY plate").fetchall()
        return [row["plate"] for row in rows]

    def all_detailed(self) -> list[dict[str, Any]]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT plate, added_at, note FROM plates ORDER BY plate"
        ).fetchall()
        return [dict(row) for row in rows]

    def count(self) -> int:
        conn = get_connection()
        row = conn.execute("SELECT COUNT(*) AS n FROM plates").fetchone()
        return int(row["n"])


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


class LogRepository:
    """Append-only event log. One table, indexed, no per-day tables."""

    __slots__ = ()

    def write(self, event: LprEvent) -> int:
        """Persist one event and return its rowid."""
        with transaction() as conn:
            cur = conn.execute(
                "INSERT INTO logs (ts, camera, plate, action, confidence) VALUES (?, ?, ?, ?, ?)",
                (
                    event.ts or utc_now_iso(),
                    str(event.camera),
                    normalise_plate(event.plate),
                    str(event.action),
                    float(event.confidence),
                ),
            )
            return int(cur.lastrowid or 0)

    def query(
        self,
        since: str | None = None,
        until: str | None = None,
        camera: str | None = None,
        plate: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[LprEvent]:
        """Filtered, paginated history, newest first.

        ``since`` / ``until`` are ISO-8601 UTC strings compared lexically,
        which is exactly equivalent to comparing the instants because the
        format is fixed-width (see ``contracts.utc_now_iso``).
        """
        clauses: list[str] = []
        params: list[Any] = []

        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts <= ?")
            params.append(until)
        if camera:
            clauses.append("camera = ?")
            params.append(str(camera))
        if plate:
            clauses.append("plate = ?")
            params.append(normalise_plate(plate))

        # Only fixed fragments from the list above are ever joined in here;
        # every value travels as a bound parameter.
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT id, ts, camera, plate, action, confidence FROM logs"
            f"{where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        )
        params.append(max(0, int(limit)))
        params.append(max(0, int(offset)))

        conn = get_connection()
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_event(row) for row in rows]

    def count_matching(
        self,
        since: str | None = None,
        until: str | None = None,
        camera: str | None = None,
        plate: str | None = None,
    ) -> int:
        """Total rows a :meth:`query` with the same filters would match."""
        clauses: list[str] = []
        params: list[Any] = []
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts <= ?")
            params.append(until)
        if camera:
            clauses.append("camera = ?")
            params.append(str(camera))
        if plate:
            clauses.append("plate = ?")
            params.append(normalise_plate(plate))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        conn = get_connection()
        row = conn.execute(f"SELECT COUNT(*) AS n FROM logs{where}", params).fetchone()
        return int(row["n"])

    def occupancy_since(self, ts: str) -> dict[str, int]:
        """How many vehicles are inside, counted from the log since ``ts``.

        A plate is "inside" when its most recent *granted* event in the window
        happened at the entry camera. That is deliberately not
        ``entries - exits``: a car that triggers the entry camera twice would
        push a running tally up for ever, and a car that entered before the
        window opened would push it negative. Counting distinct plates by
        their latest direction cannot do either.

        SQLite's bare-column rule makes ``camera`` here the value from the row
        that produced ``MAX(ts)``, which is exactly the last direction seen.
        Served by ``idx_logs_camera_ts``.
        """
        conn = get_connection()
        rows = conn.execute(
            """
            SELECT plate, camera, MAX(ts) AS last_ts
            FROM logs
            WHERE ts >= ? AND action = ?
            GROUP BY plate
            """,
            (ts, str(Action.GRANTED)),
        ).fetchall()

        inside = sum(1 for row in rows if row["camera"] == CameraRole.ENTRY.value)
        totals = conn.execute(
            """
            SELECT camera, COUNT(*) AS n
            FROM logs
            WHERE ts >= ? AND action = ?
            GROUP BY camera
            """,
            (ts, str(Action.GRANTED)),
        ).fetchall()
        counts = {row["camera"]: int(row["n"]) for row in totals}
        return {
            "inside": inside,
            "entries": counts.get(CameraRole.ENTRY.value, 0),
            "exits": counts.get(CameraRole.EXIT.value, 0),
        }

    def recent(self, limit: int = 50) -> list[LprEvent]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT id, ts, camera, plate, action, confidence FROM logs "
            "ORDER BY id DESC LIMIT ?",
            (max(0, int(limit)),),
        ).fetchall()
        return [_row_to_event(row) for row in rows]

    def dates(self) -> list[str]:
        """Distinct ``YYYY-MM-DD`` days that have log rows, newest first.

        Replaces the legacy ``log_dates`` bookkeeping table, which had to be
        kept in sync by hand with the per-day ``logs_*`` tables.
        """
        conn = get_connection()
        rows = conn.execute(
            "SELECT DISTINCT date(ts) AS day FROM logs ORDER BY day DESC"
        ).fetchall()
        return [row["day"] for row in rows if row["day"]]

    def purge_older_than(self, days: int) -> int:
        """Delete rows older than ``days``; returns the number removed.

        ``days <= 0`` disables retention and is a no-op.
        """
        if days <= 0:
            return 0
        # Build the cutoff in Python so it is byte-for-byte the same format
        # as the stored ts (utc_now_iso), which makes the lexical comparison
        # exactly equivalent to a chronological one.
        cutoff = (
            (datetime.now(timezone.utc) - timedelta(days=int(days)))
            .replace(microsecond=0)
            .isoformat()
        )
        with transaction() as conn:
            cur = conn.execute("DELETE FROM logs WHERE ts < ?", (cutoff,))
            removed = int(cur.rowcount or 0)
        if removed:
            logger.info("Purged %d log rows older than %d days", removed, days)
        return removed

    def stats_since(self, ts: str) -> dict[str, Any]:
        """Aggregate counters for everything logged at or after ``ts``."""
        conn = get_connection()
        row = conn.execute(
            """
            SELECT
                COUNT(*)                                            AS total,
                COUNT(DISTINCT plate)                               AS unique_plates,
                SUM(CASE WHEN action = ? THEN 1 ELSE 0 END)         AS granted,
                SUM(CASE WHEN action = ? THEN 1 ELSE 0 END)         AS denied,
                SUM(CASE WHEN action = ? THEN 1 ELSE 0 END)         AS detected,
                SUM(CASE WHEN action = ? THEN 1 ELSE 0 END)         AS errors
            FROM logs WHERE ts >= ?
            """,
            (
                str(Action.GRANTED),
                str(Action.DENIED),
                str(Action.DETECTED),
                str(Action.ERROR),
                ts,
            ),
        ).fetchone()

        per_camera_rows = conn.execute(
            "SELECT camera, COUNT(*) AS n FROM logs WHERE ts >= ? GROUP BY camera",
            (ts,),
        ).fetchall()

        return {
            "since": ts,
            "total": int(row["total"] or 0),
            "unique_plates": int(row["unique_plates"] or 0),
            "granted": int(row["granted"] or 0),
            "denied": int(row["denied"] or 0),
            "detected": int(row["detected"] or 0),
            "errors": int(row["errors"] or 0),
            "per_camera": {r["camera"]: int(r["n"]) for r in per_camera_rows},
        }


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

_hasher: PasswordHasher | None = None


def _password_hasher() -> PasswordHasher:
    """Lazily build the process-wide Argon2 hasher.

    Imported lazily so that importing this module (and therefore the whole
    pipeline) does not require argon2-cffi to be installed until somebody
    actually touches a password.
    """
    global _hasher
    if _hasher is None:
        try:
            from argon2 import PasswordHasher as _PH
        except ImportError as exc:  # pragma: no cover - dependency missing
            raise RuntimeError(
                "argon2-cffi is required for password hashing. "
                "Install it with: pip install 'argon2-cffi>=23.1,<24'"
            ) from exc
        _hasher = _PH()
    return _hasher


def _legacy_digest(password: str) -> str:
    """The legacy app's hash: bare, unsalted SHA-256 hex. Never produce new ones."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class UserRepository:
    """Operator accounts.

    Hashes are Argon2id PHC strings. Rows imported from the legacy database
    carry a ``sha256$<hex>`` marker: :meth:`verify` still accepts them once,
    and immediately rewrites the row with an Argon2 hash so the weak digest
    disappears from the database on first login.
    """

    __slots__ = ()

    def is_first_user(self) -> bool:
        """True while no account exists (the bootstrap-admin case)."""
        conn = get_connection()
        row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return int(row["n"]) == 0

    def exists(self, username: str) -> bool:
        name = (username or "").strip()
        if not name:
            return False
        conn = get_connection()
        row = conn.execute("SELECT 1 FROM users WHERE username = ?", (name,)).fetchone()
        return row is not None

    def count(self) -> int:
        conn = get_connection()
        row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return int(row["n"])

    def register(self, username: str, password: str, role: str = DEFAULT_ROLE) -> bool:
        """Create an account. Returns False if the username is taken or invalid."""
        name = (username or "").strip()
        if not name or not password:
            return False
        digest = _password_hasher().hash(password)
        with transaction() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?)",
                (name, digest, role or DEFAULT_ROLE, utc_now_iso()),
            )
            created = cur.rowcount > 0
        if created:
            logger.info("User registered: %s (role=%s)", name, role)
        else:
            logger.warning("Registration refused, username already taken: %s", name)
        return created

    def verify(self, username: str, password: str) -> bool:
        """Check a password. Never logs, returns or raises the password itself.

        Accepts both Argon2 hashes and legacy ``sha256$`` rows; a successful
        legacy verification rewrites the row as Argon2 before returning.
        """
        name = (username or "").strip()
        if not name or not password:
            return False

        conn = get_connection()
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (name,)
        ).fetchone()
        if row is None:
            # Still spend time hashing so a missing user is not obviously
            # faster than a wrong password.
            try:
                _password_hasher().hash(password)
            except RuntimeError:  # pragma: no cover - argon2 missing
                pass
            return False

        stored = str(row["password_hash"])

        if stored.startswith(LEGACY_PREFIX):
            expected = stored[len(LEGACY_PREFIX) :]
            if not hmac.compare_digest(expected, _legacy_digest(password)):
                return False
            logger.info("Upgrading legacy SHA-256 password hash for user %s", name)
            self._store_hash(name, _password_hasher().hash(password))
            return True

        hasher = _password_hasher()
        try:
            hasher.verify(stored, password)
        except Exception:
            # argon2 raises VerifyMismatchError / VerificationError /
            # InvalidHash; all of them mean "not authenticated".
            return False

        try:
            if hasher.check_needs_rehash(stored):
                logger.info("Rehashing password for user %s with current parameters", name)
                self._store_hash(name, hasher.hash(password))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("check_needs_rehash failed for %s: %s", name, exc)
        return True

    def set_password(self, username: str, password: str) -> bool:
        """Replace a user's password. Returns False if the user is unknown."""
        name = (username or "").strip()
        if not name or not password:
            return False
        return self._store_hash(name, _password_hasher().hash(password))

    def set_role(self, username: str, role: str) -> bool:
        name = (username or "").strip()
        if not name:
            return False
        with transaction() as conn:
            cur = conn.execute(
                "UPDATE users SET role = ? WHERE username = ?", (role or DEFAULT_ROLE, name)
            )
            return cur.rowcount > 0

    def delete(self, username: str) -> bool:
        name = (username or "").strip()
        if not name:
            return False
        with transaction() as conn:
            cur = conn.execute("DELETE FROM users WHERE username = ?", (name,))
            return cur.rowcount > 0

    def get_role(self, username: str) -> str | None:
        name = (username or "").strip()
        if not name:
            return None
        conn = get_connection()
        row = conn.execute("SELECT role FROM users WHERE username = ?", (name,)).fetchone()
        return str(row["role"]) if row is not None else None

    def list_users(self) -> list[dict[str, Any]]:
        """All accounts, without password material of any kind."""
        conn = get_connection()
        rows = conn.execute(
            "SELECT username, role, created_at FROM users ORDER BY username"
        ).fetchall()
        return [dict(row) for row in rows]

    def needs_rehash(self, username: str) -> bool:
        """True while the stored hash is still the legacy SHA-256 form."""
        name = (username or "").strip()
        conn = get_connection()
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (name,)
        ).fetchone()
        if row is None:
            return False
        return str(row["password_hash"]).startswith(LEGACY_PREFIX)

    # -- internals ---------------------------------------------------------

    def _store_hash(self, username: str, digest: str) -> bool:
        with transaction() as conn:
            cur = conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?", (digest, username)
            )
            return cur.rowcount > 0


# ---------------------------------------------------------------------------
# System metadata
# ---------------------------------------------------------------------------
# System events (operational audit trail)
# ---------------------------------------------------------------------------


class SystemEventRepository:
    """Append-only operational history: OTA updates, and anything like them.

    Deliberately separate from :class:`LogRepository`. ``logs`` is plate
    traffic -- it drives the history view, the CSV export and the occupancy
    arithmetic -- so an "update installed" row in there would show up in an
    operator's history as a vehicle and be counted as one. These two kinds of
    history have different readers, different retention pressure and different
    schemas; sharing a table would only make both worse.
    """

    __slots__ = ()

    #: Levels are advisory, matching the logging module so the admin UI can
    #: colour a row without inventing its own vocabulary.
    LEVELS = ("info", "warning", "error")

    def write(
        self,
        source: str,
        message: str,
        level: str = "info",
        detail: str | None = None,
    ) -> int:
        """Record one event and return its rowid; 0 if it could not be stored.

        Never raises. This is an audit trail, not a control path -- a failure
        to write the breadcrumb must not abort the operation that produced it,
        which for the nightly updater would mean a database hiccup cancelling
        an update.
        """
        normalised = level if level in self.LEVELS else "info"
        try:
            with transaction() as conn:
                cur = conn.execute(
                    schema.INSERT_SYSTEM_EVENT,
                    (
                        utc_now_iso(),
                        str(source)[:64],
                        normalised,
                        str(message)[:512],
                        None if detail is None else str(detail)[:4000],
                    ),
                )
                return int(cur.lastrowid or 0)
        except Exception:
            logger.warning("Sistem olayı kaydedilemedi: %s", message, exc_info=True)
            return 0

    def recent(self, limit: int = 50, source: str | None = None) -> list[dict[str, Any]]:
        """Most recent events first, newest at index 0."""
        capped = max(1, min(int(limit), 500))
        try:
            conn = get_connection()
            if source:
                rows = conn.execute(
                    schema.SELECT_SYSTEM_EVENTS_BY_SOURCE, (str(source), capped)
                ).fetchall()
            else:
                rows = conn.execute(schema.SELECT_SYSTEM_EVENTS, (capped,)).fetchall()
        except Exception:
            logger.warning("Sistem olayları okunamadı", exc_info=True)
            return []
        return [
            {
                "id": int(row["id"]),
                "ts": str(row["ts"]),
                "source": str(row["source"]),
                "level": str(row["level"]),
                "message": str(row["message"]),
                "detail": row["detail"],
            }
            for row in rows
        ]

    def purge_older_than(self, days: int) -> int:
        """Delete events older than ``days``; ``days <= 0`` is a no-op."""
        if days <= 0:
            return 0
        cutoff = (
            (datetime.now(timezone.utc) - timedelta(days=int(days)))
            .replace(microsecond=0)
            .isoformat()
        )
        try:
            with transaction() as conn:
                cur = conn.execute(schema.DELETE_SYSTEM_EVENTS_OLDER_THAN, (cutoff,))
                removed = int(cur.rowcount or 0)
        except Exception:
            logger.warning("Sistem olayları temizlenemedi", exc_info=True)
            return 0
        if removed:
            logger.info("Purged %d system events older than %d days", removed, days)
        return removed


# ---------------------------------------------------------------------------


class SystemMetaRepository:
    """Small key/value store for runtime state that is not user data.

    Holds the active licence token and the anti-rollback clock (see
    :mod:`lpr.license`). Separate from ``schema_meta`` on purpose: that table
    belongs to the migration machinery, this one to the running system.

    Every method tolerates the table not existing yet -- the licence check
    runs on entry points (the generator, an offline GUI) that may reach a
    database before :func:`lpr.db.init_db` has been called, and a missing
    table there must read as "nothing stored", never as a crash.
    """

    __slots__ = ()

    def get(self, key: str) -> str | None:
        name = (key or "").strip()
        if not name:
            return None
        row = self._fetch(name)
        if row is None:
            return None
        value = row["value"]
        return None if value is None else str(value)

    def set(self, key: str, value: str) -> None:
        name = (key or "").strip()
        if not name:
            return
        self._ensure_table()
        with transaction() as conn:
            conn.execute(
                schema.UPSERT_SYSTEM_META, (name, str(value), utc_now_iso())
            )

    def delete(self, key: str) -> bool:
        name = (key or "").strip()
        if not name:
            return False
        try:
            with transaction() as conn:
                cur = conn.execute(schema.DELETE_SYSTEM_META, (name,))
                return cur.rowcount > 0
        except sqlite3.OperationalError:
            return False

    # -- internals ---------------------------------------------------------

    def _fetch(self, name: str) -> Any:
        conn = get_connection()
        try:
            return conn.execute(schema.SELECT_SYSTEM_META, (name,)).fetchone()
        except sqlite3.OperationalError:
            # "no such table": nothing was ever stored, which is a valid state.
            return None

    @staticmethod
    def _ensure_table() -> None:
        with transaction() as conn:
            conn.execute(schema.CREATE_SYSTEM_META)
