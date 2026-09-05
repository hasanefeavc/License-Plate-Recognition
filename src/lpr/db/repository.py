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
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
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


def iso_bound(value: str | None, *, end_of_day: bool = False) -> str | None:
    """Canonicalise a ``since``/``until`` bound into the stored ts format.

    Timestamps are stored as :func:`~lpr.contracts.utc_now_iso` produces them --
    ``2026-08-28T14:32:11+00:00`` -- and compared *lexically*, which is only
    equivalent to comparing instants while both sides are byte-for-byte the
    same shape. Every bug this function exists to prevent is a violation of
    that precondition:

    * A bare ``YYYY-MM-DD`` is **shorter** than any stored timestamp, so
      ``ts <= '2026-08-28'`` is false for every row on 2026-08-28 -- the day
      filter that silently returned nothing. A date is a whole day, so it
      expands to that day's first or last second depending on which end of the
      range it is.
    * ``2026-08-28T00:00:00.000Z`` -- what JavaScript's ``toISOString()``
      produces -- disagrees with the stored form in both the milliseconds and
      the ``Z``. It happens to sort correctly most of the time, which is worse
      than never, because the disagreement only shows up on rows within a
      second of a boundary.
    * An offset-bearing bound like ``2026-08-28T00:00:00+03:00`` is a real
      instant that must be *converted*, not compared as text.

    Anything unparseable is passed through unchanged rather than raising: a
    malformed filter should narrow somebody's search, not 500 their request.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        logger.debug("unparseable date bound %r, passed through as-is", text)
        return text

    # A bare date carries no time, so it stands for the whole day.
    if len(text) == 10:
        parsed = (
            parsed.replace(hour=23, minute=59, second=59)
            if end_of_day
            else parsed.replace(hour=0, minute=0, second=0)
        )

    # Naive input is taken as UTC: everything this project writes is UTC, so a
    # bound without an offset means the same clock as the stored rows.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC).replace(microsecond=0).isoformat()


DEFAULT_ROLE = "operator"
ADMIN_ROLE = "admin"

#: Outcomes of :meth:`PlateRepository.authorization` -- why the gate opened or
#: stayed shut. Deliberately *not* :class:`~lpr.contracts.Action` values: these
#: are reasons for a decision, while ``Action`` is what was recorded in the
#: ``logs`` table, and every refusal here is still logged as ``denied`` so the
#: history counters and the dashboard keep totalling the same things.
PLATE_OK = "ok"
PLATE_BLOCKED = "blocked"
PLATE_EXPIRED = "expired"
PLATE_UNKNOWN = "unknown"


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

    def authorization(self, plate: str) -> str:
        """Why ``plate`` may or may not open the gate, in one lookup.

        Returns one of :data:`PLATE_OK`, :data:`PLATE_BLOCKED`,
        :data:`PLATE_EXPIRED` or :data:`PLATE_UNKNOWN`. Three things can make a
        listed plate *not* count, and all three are access decisions rather
        than bookkeeping:

        * ``blocked`` -- on the list deliberately, to be refused. A resident
          who has moved out stays visible (and auditable) instead of being
          deleted and silently re-addable by the next import.
        * ``expires_at`` in the past -- a temporary permit that has run out.
        * absent -- never registered.

        The reason, not just a yes/no, because every refusal looks identical in
        the log otherwise: an operator staring at "denied" for a resident whose
        permit lapsed last night cannot tell it from a plate that was never
        registered, which is exactly the call they get.

        **The barrier deliberately does not consult ``plates.username``.** That
        column records which account a car belongs to, and that account's
        ``license_expires_at`` governs *its* access to the dashboard and the
        API -- not this car's access to the car park. The two are different
        subscriptions with different blast radii: a lapsed dashboard licence is
        a billing matter, while a closed barrier strands a resident in the
        street. Application access is enforced in
        :func:`lpr.api.security.require_license`, and it stops there.

        ``blocked`` outranks expiry, matching
        :func:`lpr.api.schemas.plate_status`, so one plate cannot be described
        two ways by the gate and the management screen.

        Still one indexed primary-key lookup on the recognition path; only the
        comparison moved out of SQL, so the reason survives it. Expiry is
        compared lexically against :func:`~lpr.contracts.utc_now_iso`, which is
        sound because every writer stores the same fixed-width UTC shape -- see
        :func:`iso_bound` for what goes wrong when that is not true.
        """
        key = normalise_plate(plate)
        if not key:
            return PLATE_UNKNOWN
        conn = get_connection()
        row = conn.execute(
            "SELECT COALESCE(blocked, 0) AS blocked, expires_at FROM plates WHERE plate = ?",
            (key,),
        ).fetchone()
        if row is None:
            return PLATE_UNKNOWN
        if int(row["blocked"] or 0):
            return PLATE_BLOCKED
        expires = str(row["expires_at"] or "").strip()
        if expires and expires <= utc_now_iso():
            return PLATE_EXPIRED
        return PLATE_OK

    def is_registered(self, plate: str) -> bool:
        """True when ``plate`` may open the gate right now.

        A thin reading of :meth:`authorization`, which is the single place the
        access rules live.
        """
        return self.authorization(plate) == PLATE_OK

    def is_blocked(self, plate: str) -> bool:
        """True when ``plate`` is on the list *and* flagged blocked.

        Distinct from "not registered": an unknown car is unauthorised, a
        blocked one was listed and then barred, and the two justify different
        notifications.
        """
        return self.authorization(plate) == PLATE_BLOCKED

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

    def update(self, plate: str, **fields: Any) -> bool:
        """Patch only the columns named in ``fields``. Returns False if unknown.

        Distinct from :meth:`upsert`, which writes every column and therefore
        blanks anything the caller did not supply. A dashboard toggling the
        blocked flag must not wipe the owner and expiry it never sent, so a
        partial update needs partial SQL.
        """
        key = normalise_plate(plate)
        if not key:
            return False

        allowed = ("owner", "apartment", "note", "expires_at", "blocked", "username")
        updates = {name: fields[name] for name in allowed if name in fields}
        if not updates:
            return False
        if "blocked" in updates:
            updates["blocked"] = int(bool(updates["blocked"]))

        # Column names come from `allowed`, never from the caller, so this
        # interpolation cannot carry anything a request supplied.
        assignments = ", ".join(f"{name} = ?" for name in updates)
        with transaction() as conn:
            cur = conn.execute(
                f"UPDATE plates SET {assignments} WHERE plate = ?",  # noqa: S608
                (*updates.values(), key),
            )
            changed = cur.rowcount > 0
        if changed:
            logger.info("Plate updated: %s (%s)", key, ", ".join(updates))
        return changed

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
        row = conn.execute(schema.SELECT_PLATE_DETAIL, (key,)).fetchone()
        return dict(row) if row is not None else None

    def upsert(
        self,
        plate: str,
        owner: str | None = None,
        apartment: str | None = None,
        note: str | None = None,
        expires_at: str | None = None,
        blocked: bool = False,
        overwrite: bool = True,
        username: str | None = None,
    ) -> str:
        """Insert or update one resident record. Returns what it did.

        Returns ``"added"``, ``"updated"``, ``"skipped"`` (already present and
        ``overwrite`` is off) or ``"invalid"`` (the plate normalises to
        nothing). The CSV importer reports those counts back to the operator,
        which is the whole reason they are distinguished.

        ``overwrite=False`` is the safe import mode: an existing row is left
        exactly as it is rather than having its owner and expiry quietly
        replaced by whatever a spreadsheet happened to contain.
        """
        key = normalise_plate(plate)
        if not key:
            return "invalid"

        with transaction() as conn:
            existing = conn.execute("SELECT 1 FROM plates WHERE plate = ?", (key,)).fetchone()
            if existing is not None and not overwrite:
                return "skipped"

            if existing is None:
                conn.execute(
                    "INSERT INTO plates "
                    "(plate, added_at, note, owner, apartment, expires_at, blocked, username) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        key,
                        utc_now_iso(),
                        note,
                        owner,
                        apartment,
                        expires_at,
                        int(blocked),
                        username,
                    ),
                )
                return "added"

            # added_at is deliberately untouched: it records when the plate was
            # first admitted, not when a spreadsheet last mentioned it.
            conn.execute(
                "UPDATE plates SET note = ?, owner = ?, apartment = ?, "
                "expires_at = ?, blocked = ?, username = ? WHERE plate = ?",
                (note, owner, apartment, expires_at, int(blocked), username, key),
            )
            return "updated"

    def all(self) -> list[str]:
        conn = get_connection()
        rows = conn.execute("SELECT plate FROM plates ORDER BY plate").fetchall()
        return [row["plate"] for row in rows]

    def all_detailed(self) -> list[dict[str, Any]]:
        conn = get_connection()
        rows = conn.execute(schema.SELECT_PLATES_DETAIL).fetchall()
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

    def attach_snapshot(self, log_id: int, path: Any) -> bool:
        """Link the evidence photo for one decision. Never raises.

        Returns True when a row was updated. Resilient by contract: this runs
        on the snapshot writer's thread, after the decision is already recorded
        and the barrier has already moved, so a failure here costs a thumbnail
        in the history view and nothing else. Losing the event because the
        photograph could not be linked would be the wrong trade by a wide
        margin.
        """
        if not log_id or path is None:
            return False
        try:
            with transaction() as conn:
                cur = conn.execute(schema.UPDATE_LOG_SNAPSHOT, (str(path), int(log_id)))
                return bool(cur.rowcount)
        except Exception:
            logger.warning("Could not link snapshot to log row %s", log_id, exc_info=True)
            return False

    def snapshot_path(self, log_id: int) -> str | None:
        """The linked photo for one row, or ``None`` when there is not one.

        ``None`` covers every reason alike -- unknown row, snapshots disabled,
        a frame the writer dropped, a file the retention sweep has since
        removed. The caller cannot act differently on any of them, so they are
        not distinguished here.
        """
        try:
            conn = get_connection()
            row = conn.execute(schema.SELECT_LOG_SNAPSHOT, (int(log_id),)).fetchone()
        except Exception:
            logger.debug("Could not read snapshot path for log row %s", log_id, exc_info=True)
            return None
        if row is None:
            return None
        value = row["snapshot_path"]
        return str(value) if value else None

    def ids_with_snapshots(self, ids: Sequence[int]) -> set[int]:
        """Which of ``ids`` have a photo linked.

        One query for a whole page rather than one per row: the history view
        renders up to a thousand rows and only needs to know whether to draw a
        thumbnail affordance, not what is behind it.
        """
        wanted = [int(value) for value in ids if value]
        if not wanted:
            return set()
        try:
            conn = get_connection()
            # Only integers, produced by the comprehension above, are ever
            # interpolated -- the values themselves travel as parameters.
            placeholders = ",".join("?" * len(wanted))
            rows = conn.execute(
                "SELECT id FROM logs "  # noqa: S608
                f"WHERE snapshot_path IS NOT NULL AND id IN ({placeholders})",
                wanted,
            ).fetchall()
        except Exception:
            logger.debug("Could not read snapshot availability", exc_info=True)
            return set()
        return {int(row["id"]) for row in rows}

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

        ``since`` / ``until`` accept a bare ``YYYY-MM-DD`` date, a full ISO-8601
        timestamp in any timezone, or the ``...Z`` form a browser produces.
        :func:`iso_bound` folds all of them into the stored format first, which
        is what makes the lexical comparison below equivalent to comparing
        instants; passing a bound through raw is how a whole-day filter ends up
        matching nothing.
        """
        clauses: list[str] = []
        params: list[Any] = []

        start = iso_bound(since)
        end = iso_bound(until, end_of_day=True)

        if start:
            clauses.append("ts >= ?")
            params.append(start)
        if end:
            clauses.append("ts <= ?")
            params.append(end)
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
        """Total rows a :meth:`query` with the same filters would match.

        Bounds go through :func:`iso_bound` exactly as in :meth:`query`. They
        have to: a count that disagreed with the list it is counting would be a
        subtler bug than either one being wrong alone.
        """
        clauses: list[str] = []
        params: list[Any] = []
        start = iso_bound(since)
        end = iso_bound(until, end_of_day=True)
        if start:
            clauses.append("ts >= ?")
            params.append(start)
        if end:
            clauses.append("ts <= ?")
            params.append(end)
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

    def last_granted_camera(self, plate: str, since: str) -> str | None:
        """Which camera last granted ``plate`` at or after ``since``.

        The anti-passback question, asked of the same data the occupancy count
        uses: a plate whose most recent grant was at the entry camera is
        inside. ``None`` means no grant in the window, which is the normal
        state for a car that has not been here today -- and, deliberately, also
        the state a car falls back to once the window expires, so a missed exit
        event cannot strand a vehicle for ever.

        Ordered by ``id`` as well as ``ts``, and that tiebreak is load-bearing
        rather than tidiness: ``ts`` is an ISO string with one-second
        resolution, so a vehicle that drives in and straight back out -- or any
        pair of events inside the same second -- leaves two rows SQLite is free
        to return in either order. Without the rowid the answer would be a coin
        toss, and the losing side of it refuses a resident at the barrier.

        Served by ``idx_logs_plate`` and ``idx_logs_camera_ts``.
        """
        name = normalise_plate(plate)
        if not name:
            return None
        try:
            row = (
                get_connection()
                .execute(
                    """
                SELECT camera
                FROM logs
                WHERE plate = ? AND action = ? AND ts >= ?
                ORDER BY ts DESC, id DESC
                LIMIT 1
                """,
                    (name, str(Action.GRANTED), since),
                )
                .fetchone()
            )
        except Exception:
            logger.warning("Son geçiş yönü okunamadı: %s", name, exc_info=True)
            return None
        return None if row is None else str(row["camera"])

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
            "SELECT id, ts, camera, plate, action, confidence FROM logs ORDER BY id DESC LIMIT ?",
            (max(0, int(limit)),),
        ).fetchall()
        return [_row_to_event(row) for row in rows]

    def dates(self, tz_offset_minutes: int = 0) -> list[str]:
        """Distinct ``YYYY-MM-DD`` days that have log rows, newest first.

        ``tz_offset_minutes`` is minutes **east of UTC** -- 180 for Turkey --
        and buckets the rows into that timezone's calendar days rather than
        UTC's. It matters because these strings become the options in the
        history day picker: a gate read at 01:30 in Istanbul is stored as
        22:30 the previous day in UTC, so a UTC-bucketed list offers the
        operator a day that is not the day they were working.

        Defaults to 0, i.e. UTC days, which is the right answer for a caller
        that has no opinion (a script, a test) and preserves the previous
        behaviour for anyone who does not pass it. Deliberately *not*
        ``date(ts, 'localtime')``: that reads the timezone of the server
        process, which in a container is UTC no matter where the site is.
        """
        conn = get_connection()
        offset = int(tz_offset_minutes)
        if offset:
            rows = conn.execute(
                "SELECT DISTINCT date(ts, ?) AS day FROM logs ORDER BY day DESC",
                (f"{offset:+d} minutes",),
            ).fetchall()
        else:
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
        cutoff = (datetime.now(UTC) - timedelta(days=int(days))).replace(microsecond=0).isoformat()
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
# Sessions
# ---------------------------------------------------------------------------


class SessionRepository:
    """Vehicle stays, paired from the gate log: one row per visit.

    A *record* of what the log already implies, not a second source of truth.
    ``PlateRepository.occupancy_since`` still derives the live count by
    scanning grants and is untouched, for two reasons: a derived number that
    disagrees with this table is a free bug detector, and the barrier must
    never come to depend on a bookkeeping table being healthy.

    Every method swallows its own errors and reports failure in the return
    value. These are called from the decision path, after the relay has already
    fired -- a broken sessions table must cost accounting, never a gate.

    Two situations are not exceptional and are handled deliberately, because
    both are ordinary at a real site:

    **A second entry for a plate already inside.** The open session is kept and
    no new one is opened. The first entry is the true arrival, and a duplicate
    entry read -- a missed exit, a car re-read while it waits at the barrier,
    an operator waving one through twice -- must not restart the clock or
    manufacture a phantom stay. :meth:`start_session` is therefore idempotent
    for as long as a session stays open.

    **An exit with no open session.** A closed row is written with a NULL
    ``entry_ts`` and status ``orphan_exit``. The exit genuinely happened, so
    dropping it would leave the audit trail claiming a car never left; but
    inventing an entry time to compute a duration against would be fabricating
    data. ``duration_seconds`` stays NULL and the row is visibly incomplete,
    which is the honest shape for "we saw half of this".
    """

    __slots__ = ()

    def start_session(self, plate: str, entry_ts: str, log_id: int | None = None) -> int | None:
        """Open a stay for ``plate``. Returns the session id, or ``None``.

        Returns the *existing* id when one is already open for this plate --
        see the class docstring. ``None`` means the write failed, which the
        caller is expected to log and ignore.
        """
        normalised = normalise_plate(plate)
        if not normalised:
            return None
        try:
            existing = self.open_session(normalised)
            if existing is not None:
                return int(existing["id"])
            with transaction() as conn:
                cur = conn.execute(
                    schema.INSERT_SESSION,
                    (
                        normalised,
                        entry_ts or utc_now_iso(),
                        int(log_id) if log_id else None,
                        schema.SESSION_OPEN,
                    ),
                )
                return int(cur.lastrowid or 0) or None
        except Exception:
            logger.warning("Could not open a session for %s", normalised, exc_info=True)
            return None

    def close_session(self, plate: str, exit_ts: str, log_id: int | None = None) -> int | None:
        """Close the open stay for ``plate``. Returns the session id, or ``None``.

        With no open session this records an ``orphan_exit`` instead of doing
        nothing, and returns that row's id.
        """
        normalised = normalise_plate(plate)
        if not normalised:
            return None
        stamp = exit_ts or utc_now_iso()
        try:
            existing = self.open_session(normalised)
            if existing is None:
                with transaction() as conn:
                    cur = conn.execute(
                        schema.INSERT_ORPHAN_EXIT,
                        (normalised, stamp, int(log_id) if log_id else None),
                    )
                logger.info("Exit for %s with no open session; recorded as orphan", normalised)
                return int(cur.lastrowid or 0) or None

            duration = _duration_seconds(existing["entry_ts"], stamp)
            with transaction() as conn:
                conn.execute(
                    schema.CLOSE_SESSION,
                    (stamp, int(log_id) if log_id else None, duration, int(existing["id"])),
                )
            return int(existing["id"])
        except Exception:
            logger.warning("Could not close the session for %s", normalised, exc_info=True)
            return None

    def open_session(self, plate: str) -> dict[str, Any] | None:
        """The open stay for ``plate``, or ``None``."""
        normalised = normalise_plate(plate)
        if not normalised:
            return None
        conn = get_connection()
        row = conn.execute(schema.SELECT_OPEN_SESSION, (normalised,)).fetchone()
        return dict(row) if row is not None else None

    def get_active_sessions(self) -> list[dict[str, Any]]:
        """Every vehicle currently inside, longest stay first.

        Ordered by ``entry_ts`` ascending so the oldest -- the one an operator
        is most likely to be asking about -- is at the top.
        """
        try:
            conn = get_connection()
            rows = conn.execute(schema.SELECT_ACTIVE_SESSIONS).fetchall()
        except Exception:
            logger.warning("Could not read active sessions", exc_info=True)
            return []
        now = utc_now_iso()
        result: list[dict[str, Any]] = []
        for row in rows:
            record = dict(row)
            # An open stay has no exit yet, so its duration is "so far". Computed
            # on read rather than stored, because a stored value would be wrong
            # from the moment it was written.
            record["duration_seconds"] = _duration_seconds(record.get("entry_ts"), now)
            result.append(record)
        return result

    def history(
        self, plate: str | None = None, limit: int = 200, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Completed and open stays, newest first."""
        bounded_limit = max(1, min(1000, int(limit)))
        bounded_offset = max(0, int(offset))
        try:
            conn = get_connection()
            if plate:
                rows = conn.execute(
                    schema.SELECT_SESSIONS_HISTORY_BY_PLATE,
                    (normalise_plate(plate), bounded_limit, bounded_offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    schema.SELECT_SESSIONS_HISTORY, (bounded_limit, bounded_offset)
                ).fetchall()
        except Exception:
            logger.warning("Could not read session history", exc_info=True)
            return []
        return [dict(row) for row in rows]

    def active_count(self) -> int:
        """How many vehicles are inside according to this table."""
        try:
            conn = get_connection()
            row = conn.execute(schema.COUNT_ACTIVE_SESSIONS).fetchone()
            return int(row["n"])
        except Exception:
            logger.warning("Could not count active sessions", exc_info=True)
            return 0

    def count(self) -> int:
        try:
            conn = get_connection()
            row = conn.execute(schema.COUNT_SESSIONS).fetchone()
            return int(row["n"])
        except Exception:
            return 0


def _duration_seconds(entry_ts: Any, exit_ts: Any) -> int | None:
    """Whole seconds between two stored timestamps, or ``None``.

    ``None`` for a missing or unparseable bound rather than 0: a stay of
    unknown length and a stay of no length are different facts, and an
    ``orphan_exit`` reporting "0 seconds" would read as a car that arrived and
    left in the same instant. Negative results are also ``None`` -- a clock
    that went backwards between the two reads has produced a duration nobody
    should act on.
    """
    if not entry_ts or not exit_ts:
        return None
    try:
        start = datetime.fromisoformat(str(entry_ts))
        end = datetime.fromisoformat(str(exit_ts))
    except (TypeError, ValueError):
        return None
    seconds = int((end - start).total_seconds())
    return seconds if seconds >= 0 else None


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

    def register(
        self,
        username: str,
        password: str,
        role: str = DEFAULT_ROLE,
        token_ttl_min: int | None = None,
    ) -> bool:
        """Create an account. Returns False if the username is taken or invalid.

        ``token_ttl_min`` is how long this account's sessions last. ``None``
        means "use the default for the role", which is what every account
        created before the column existed carries -- so the policy can be
        retuned centrally without touching a single row.
        """
        name = (username or "").strip()
        if not name or not password:
            return False
        digest = _password_hasher().hash(password)
        ttl = int(token_ttl_min) if token_ttl_min else None
        # A new operator is waiting for a key, not missing one. Admins get no
        # licence row at all -- they are exempt, and a status on their row
        # would only be something to keep in sync with a rule that ignores it.
        from lpr.user_license import STATUS_PENDING, requires_license

        assigned_role = role or DEFAULT_ROLE
        status = STATUS_PENDING if requires_license(assigned_role) else None
        with transaction() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO users "
                "(username, password_hash, role, created_at, token_ttl_min, license_status) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, digest, assigned_role, utc_now_iso(), ttl, status),
            )
            created = cur.rowcount > 0
        if created:
            logger.info("User registered: %s (role=%s)", name, role)
        else:
            logger.warning("Registration refused, username already taken: %s", name)
        return created

    def create_bootstrap_admin(self, username: str, password: str) -> bool:
        """Create the very first account as ``admin``, atomically.

        Returns ``False`` when the installation already has an account -- the
        caller then falls through to the ordinary admin-authenticated path.

        The atomicity is the entire point. The route used to ask
        :meth:`is_first_user` and then, after an ``await``, call
        :meth:`register` with the admin role. Two requests arriving together
        on a fresh installation both saw an empty table and both were made
        administrators, so somebody watching a box being provisioned could end
        up with an account of their own beside the installer's -- and the
        installer would see nothing but a successful setup. The ``UNIQUE``
        constraint on ``username`` does not help, because the two accounts have
        different names.

        ``BEGIN IMMEDIATE`` rather than the usual :func:`transaction` helper:
        that one opens SQLite's default *deferred* transaction, which takes no
        write lock until the first write and so would let both readers through
        the count exactly as before. IMMEDIATE takes the reserved lock up
        front, which is what makes the count and the insert one decision.
        """
        name = (username or "").strip()
        if not name or not password:
            return False

        digest = _password_hasher().hash(password)
        conn = get_connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
            if int(row["n"]) != 0:
                conn.rollback()
                return False
            # Admins hold no licence row -- they are exempt, and a status on
            # their row would only be something to keep in sync with a rule
            # that ignores it. Same reasoning as `register`.
            conn.execute(
                "INSERT INTO users "
                "(username, password_hash, role, created_at, token_ttl_min, license_status) "
                "VALUES (?, ?, 'admin', ?, NULL, NULL)",
                (name, digest, utc_now_iso()),
            )
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

        logger.info("Bootstrap administrator created: %s", name)
        return True

    def verify(self, username: str, password: str) -> bool:
        """Check a password. Never logs, returns or raises the password itself.

        Accepts both Argon2 hashes and legacy ``sha256$`` rows; a successful
        legacy verification rewrites the row as Argon2 before returning.
        """
        name = (username or "").strip()
        if not name or not password:
            return False

        conn = get_connection()
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (name,)).fetchone()
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
        """Remove an account.

        Any plates recorded against it keep working: ``plates.username`` is
        ownership metadata, not a gate permit, so losing it changes nothing at
        the barrier. See :meth:`PlateRepository.authorization`.
        """
        name = (username or "").strip()
        if not name:
            return False
        with transaction() as conn:
            conn.execute("UPDATE plates SET username = NULL WHERE username = ?", (name,))
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
        return [dict(row) for row in conn.execute(schema.SELECT_USERS).fetchall()]

    def get(self, username: str) -> dict[str, Any] | None:
        """One account, or ``None``. Never returns password material.

        Used on the authentication path to confirm the account behind a token
        still exists, so this is deliberately a single indexed primary-key
        lookup and selects no hash.
        """
        name = (username or "").strip()
        if not name:
            return None
        conn = get_connection()
        row = conn.execute(schema.SELECT_USER, (name,)).fetchone()
        return dict(row) if row is not None else None

    def set_license(
        self,
        username: str,
        key: str | None,
        expires_at: str | None,
        status: str,
        duration_days: int | None = None,
        activated_at: str | None = None,
    ) -> bool:
        """Store one account's licence state. Returns False if unknown.

        Written only at *activation* and at revocation -- generating a key
        touches nothing here, because a key that nobody has entered yet says
        nothing about the account it names.

        Revocation keeps the key and the dates and changes the status. The key
        is signed and cannot be un-signed, so ``license_status`` is the only
        thing that can actually withdraw it -- and keeping the rest lets an
        admin see what was revoked and when it had been due to end.
        """
        name = (username or "").strip()
        if not name:
            return False
        with transaction() as conn:
            cur = conn.execute(
                schema.UPDATE_USER_LICENSE,
                (
                    key,
                    expires_at,
                    status,
                    int(duration_days) if duration_days else None,
                    activated_at,
                    name,
                ),
            )
            changed = cur.rowcount > 0
        if changed:
            logger.info("Lisans güncellendi: %s (%s, bitiş %s)", name, status, expires_at)
        return changed

    def count_by_role(self, role: str) -> int:
        """How many accounts hold ``role``.

        Exists so deleting a user can refuse to remove the last admin, which
        would otherwise lock everyone out of user management permanently --
        there is no recovery path short of editing the database by hand.
        """
        conn = get_connection()
        row = conn.execute(schema.COUNT_USERS_BY_ROLE, (role,)).fetchone()
        return int(row["n"]) if row is not None else 0

    def needs_rehash(self, username: str) -> bool:
        """True while the stored hash is still the legacy SHA-256 form."""
        name = (username or "").strip()
        conn = get_connection()
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (name,)).fetchone()
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
        cutoff = (datetime.now(UTC) - timedelta(days=int(days))).replace(microsecond=0).isoformat()
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
            conn.execute(schema.UPSERT_SYSTEM_META, (name, str(value), utc_now_iso()))

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
