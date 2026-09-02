"""Tests for the persistence layer.

These lock in the fixes for the legacy defects: a single cross-thread
connection, per-day tables built by string interpolation, and unsalted
SHA-256 passwords.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from lpr.contracts import Action, CameraRole, LprEvent, utc_now_iso
from lpr.db import (
    LogRepository,
    PlateRepository,
    SessionRepository,
    UserRepository,
    get_connection,
    normalise_plate,
    schema_version,
)
from lpr.db.repository import LEGACY_PREFIX, _legacy_digest, iso_bound


def _iso(days_ago: float = 0.0) -> str:
    moment = datetime.now(UTC) - timedelta(days=days_ago)
    return moment.replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------


def test_schema_is_created_and_versioned(db) -> None:
    conn = get_connection()
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"plates", "users", "logs", "schema_meta"} <= tables
    assert schema_version() >= 1


def test_no_per_day_log_tables_exist(db) -> None:
    """The legacy layout created one table per day; there is now exactly one."""
    LogRepository().write(
        LprEvent(ts=utc_now_iso(), camera="entry", plate="34ABC123", action="granted")
    )
    conn = get_connection()
    names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    assert not [name for name in names if name.startswith("logs_")]


def test_wal_pragma_is_actually_set(db) -> None:
    conn = get_connection()
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert str(mode).lower() == "wal"

    assert int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) == 1
    assert int(conn.execute("PRAGMA busy_timeout").fetchone()[0]) == 5000
    # NORMAL == 1
    assert int(conn.execute("PRAGMA synchronous").fetchone()[0]) == 1


def test_indexes_exist(db) -> None:
    conn = get_connection()
    names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_logs_ts", "idx_logs_plate", "idx_logs_camera_ts"} <= names


def test_connections_are_thread_local(db) -> None:
    main_conn = get_connection()
    other: list[sqlite3.Connection] = []

    def grab() -> None:
        other.append(get_connection())

    thread = threading.Thread(target=grab)
    thread.start()
    thread.join()

    assert other, "worker thread produced no connection"
    assert other[0] is not main_conn


def test_same_thread_reuses_one_connection(db) -> None:
    assert get_connection() is get_connection()


def test_concurrent_writers_all_commit(db) -> None:
    """Four threads writing at once: every row lands, nothing raises."""
    logs = LogRepository()
    errors: list[BaseException] = []
    per_thread = 20

    def writer(index: int) -> None:
        try:
            for n in range(per_thread):
                logs.write(
                    LprEvent(
                        ts=utc_now_iso(),
                        camera=str(CameraRole.ENTRY if index % 2 else CameraRole.EXIT),
                        plate=f"34ABC{index:02d}{n:02d}",
                        action=str(Action.DETECTED),
                        confidence=0.5,
                    )
                )
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)
        finally:
            from lpr.db import close_all

            close_all()

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, f"concurrent writers raised: {errors}"
    total = get_connection().execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    assert total == 4 * per_thread


def test_transaction_rolls_back_on_error(db) -> None:
    from lpr.db import transaction

    plates = PlateRepository()
    plates.add("34AAA111")

    with pytest.raises(RuntimeError), transaction() as conn:
        conn.execute(
            "INSERT INTO plates (plate, added_at, note) VALUES (?, ?, ?)",
            ("34BBB222", utc_now_iso(), None),
        )
        raise RuntimeError("boom")

    assert plates.all() == ["34AAA111"]


# ---------------------------------------------------------------------------
# Plates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("34abc123", "34ABC123"),
        ("  34 ABC 123  ", "34ABC123"),
        ("34\tabc\n123", "34ABC123"),
        ("", ""),
    ],
)
def test_normalise_plate(raw: str, expected: str) -> None:
    assert normalise_plate(raw) == expected


def test_plate_crud_and_normalisation(db) -> None:
    plates = PlateRepository()

    assert plates.count() == 0
    assert plates.add(" 34 abc 123 ") is True
    assert plates.add("34ABC123") is False, "duplicate add must report False"
    assert plates.count() == 1

    # Any spelling of the same plate resolves to the same row.
    assert plates.is_registered("34abc123")
    assert plates.is_registered("  34 ABC 123 ")
    assert plates.all() == ["34ABC123"]

    assert plates.is_registered("06XYZ99") is False
    assert plates.remove("06XYZ99") is False

    assert plates.remove("34 abc 123") is True
    assert plates.count() == 0


def test_plate_note_is_stored(db) -> None:
    plates = PlateRepository()
    plates.add("34ABC123", note="director")
    record = plates.get("34abc123")
    assert record is not None
    assert record["note"] == "director"
    assert record["added_at"]


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


def _seed_logs(logs: LogRepository) -> None:
    rows = [
        (_iso(30), "entry", "34AAA111", Action.GRANTED, 0.9),
        (_iso(20), "entry", "34BBB222", Action.DENIED, 0.8),
        (_iso(5), "exit", "34AAA111", Action.GRANTED, 0.7),
        (_iso(1), "exit", "34CCC333", Action.DENIED, 0.6),
        (_iso(0), "entry", "34AAA111", Action.DETECTED, 0.5),
    ]
    for ts, camera, plate, action, confidence in rows:
        logs.write(
            LprEvent(ts=ts, camera=camera, plate=plate, action=str(action), confidence=confidence)
        )


def test_log_write_returns_rowid(db) -> None:
    logs = LogRepository()
    first = logs.write(
        LprEvent(ts=utc_now_iso(), camera="entry", plate="34ABC123", action="granted")
    )
    second = logs.write(
        LprEvent(ts=utc_now_iso(), camera="entry", plate="34ABC124", action="denied")
    )
    assert first > 0
    assert second == first + 1


def test_log_query_filters(db) -> None:
    logs = LogRepository()
    _seed_logs(logs)

    assert len(logs.query(limit=100)) == 5
    assert len(logs.query(camera="entry", limit=100)) == 3
    assert len(logs.query(plate="34aaa111", limit=100)) == 3
    assert len(logs.query(since=_iso(6), limit=100)) == 3
    assert len(logs.query(since=_iso(6), until=_iso(2), limit=100)) == 1
    assert len(logs.query(camera="exit", plate="34AAA111", limit=100)) == 1


def test_log_query_pagination_and_ordering(db) -> None:
    logs = LogRepository()
    _seed_logs(logs)

    page1 = logs.query(limit=2, offset=0)
    page2 = logs.query(limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert {e.id for e in page1}.isdisjoint({e.id for e in page2})
    # Newest first.
    assert page1[0].ts >= page1[1].ts >= page2[0].ts

    assert logs.count_matching() == 5
    assert logs.count_matching(camera="entry") == 3


def test_log_recent_and_dates(db) -> None:
    logs = LogRepository()
    _seed_logs(logs)

    recent = logs.recent(2)
    assert len(recent) == 2

    dates = logs.dates()
    assert len(dates) == len(set(dates))
    assert dates == sorted(dates, reverse=True)
    assert all(len(day) == 10 for day in dates)


# ---------------------------------------------------------------------------
# Date bounds
#
# Timestamps are stored as fixed-width UTC ISO strings and compared lexically,
# which is only equivalent to comparing instants while both sides are the same
# shape. Every case below is a shape that is not, and each one silently
# mis-filtered before `iso_bound` existed.
# ---------------------------------------------------------------------------


def test_a_bare_date_bound_covers_the_whole_day() -> None:
    """The defect itself, at the unit level.

    ``"2026-05-02"`` is ten characters; a stored ts is twenty-five. Comparing
    them as text puts every row on that day *after* the upper bound, so the
    filter matched nothing while the unfiltered list kept working.
    """
    assert iso_bound("2026-05-02") == "2026-05-02T00:00:00+00:00"
    assert iso_bound("2026-05-02", end_of_day=True) == "2026-05-02T23:59:59+00:00"


def test_a_browser_instant_is_folded_into_the_stored_shape() -> None:
    """`toISOString()` brings milliseconds and a `Z`; the stored form has neither."""
    assert iso_bound("2026-05-02T00:00:00.000Z") == "2026-05-02T00:00:00+00:00"


def test_an_offset_bound_is_converted_to_utc() -> None:
    """Local midnight in Istanbul is 21:00 the previous day in UTC."""
    assert iso_bound("2026-05-03T00:00:00+03:00") == "2026-05-02T21:00:00+00:00"


def test_a_bound_already_in_the_stored_shape_is_left_alone() -> None:
    assert iso_bound("2026-05-02T14:32:11+00:00") == "2026-05-02T14:32:11+00:00"


def test_a_naive_bound_is_read_as_utc() -> None:
    """Everything this project writes is UTC, so an offsetless bound is too."""
    assert iso_bound("2026-05-02T14:32:11") == "2026-05-02T14:32:11+00:00"


def test_an_empty_bound_is_no_bound() -> None:
    assert iso_bound(None) is None
    assert iso_bound("") is None
    assert iso_bound("   ") is None


def test_an_unparseable_bound_narrows_the_search_rather_than_raising() -> None:
    """A malformed filter must not turn into a 500 on somebody's history view."""
    assert iso_bound("bugün") == "bugün"


def test_a_day_filter_selects_exactly_that_day(db) -> None:
    """End to end through real SQLite, including both inclusive edges."""
    logs = LogRepository()
    day = datetime(2026, 5, 2, tzinfo=UTC)
    for moment, plate in (
        (day - timedelta(seconds=1), "34BEFORE"),
        (day, "34FIRST1"),
        (day.replace(hour=23, minute=59, second=59), "34LAST01"),
        (day + timedelta(days=1), "34AFTER1"),
    ):
        logs.write(
            LprEvent(
                ts=moment.isoformat(),
                camera=CameraRole.ENTRY,
                plate=plate,
                action=Action.GRANTED,
            )
        )

    found = {e.plate for e in logs.query(since="2026-05-02", until="2026-05-02", limit=100)}
    assert found == {"34FIRST1", "34LAST01"}
    assert logs.count_matching(since="2026-05-02", until="2026-05-02") == 2


def test_the_count_agrees_with_the_list_it_counts(db) -> None:
    """Two code paths, one set of bounds; drift between them is a subtler bug."""
    logs = LogRepository()
    _seed_logs(logs)
    for bound in (_iso(6), _iso(6)[:10]):
        assert logs.count_matching(since=bound) == len(logs.query(since=bound, limit=100))


def test_the_day_list_can_be_bucketed_in_another_timezone(db) -> None:
    """22:30 UTC is 01:30 the next day in Istanbul, and belongs on that day."""
    logs = LogRepository()
    logs.write(
        LprEvent(
            ts="2026-05-02T22:30:00+00:00",
            camera=CameraRole.ENTRY,
            plate="34LATE01",
            action=Action.GRANTED,
        )
    )

    assert logs.dates() == ["2026-05-02"]
    assert logs.dates(tz_offset_minutes=180) == ["2026-05-03"]
    assert logs.dates(tz_offset_minutes=-300) == ["2026-05-02"]


def test_log_plate_is_normalised_on_write(db) -> None:
    logs = LogRepository()
    logs.write(LprEvent(ts=utc_now_iso(), camera="entry", plate=" 34 abc 123 ", action="granted"))
    assert logs.query(plate="34ABC123")[0].plate == "34ABC123"


def test_retention_purge(db) -> None:
    logs = LogRepository()
    _seed_logs(logs)

    removed = logs.purge_older_than(10)
    assert removed == 2  # the 30- and 20-day-old rows
    assert logs.count_matching() == 3

    assert logs.purge_older_than(0) == 0
    assert logs.purge_older_than(-5) == 0
    assert logs.count_matching() == 3


def test_stats_since(db) -> None:
    logs = LogRepository()
    _seed_logs(logs)

    stats = logs.stats_since(_iso(10))
    assert stats["total"] == 3
    assert stats["granted"] == 1
    assert stats["denied"] == 1
    assert stats["detected"] == 1
    assert stats["unique_plates"] == 2  # 34AAA111 twice, 34CCC333 once
    assert stats["per_camera"]["exit"] == 2


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def test_first_user_and_registration(db) -> None:
    users = UserRepository()
    assert users.is_first_user() is True

    assert users.register("admin", "correct horse battery staple", role="admin") is True
    assert users.is_first_user() is False
    assert users.exists("admin") is True
    assert users.register("admin", "another") is False, "duplicate username"

    listed = users.list_users()
    assert [u["username"] for u in listed] == ["admin"]
    assert listed[0]["role"] == "admin"
    # No password material is ever exposed.
    assert "password_hash" not in listed[0]


def test_argon2_round_trip(db) -> None:
    users = UserRepository()
    users.register("operator", "s3cret-passphrase")

    stored = (
        get_connection()
        .execute("SELECT password_hash FROM users WHERE username = ?", ("operator",))
        .fetchone()["password_hash"]
    )
    assert stored.startswith("$argon2"), "passwords must be Argon2, never plain sha256"
    assert "s3cret-passphrase" not in stored

    assert users.verify("operator", "s3cret-passphrase") is True
    assert users.verify("operator", "wrong") is False
    assert users.verify("nobody", "s3cret-passphrase") is False


def test_set_password(db) -> None:
    users = UserRepository()
    users.register("operator", "old-password")
    assert users.set_password("operator", "new-password") is True
    assert users.verify("operator", "old-password") is False
    assert users.verify("operator", "new-password") is True
    assert users.set_password("ghost", "whatever") is False


def test_legacy_sha256_verify_then_rehash(db) -> None:
    """A legacy row authenticates once, then is silently upgraded to Argon2."""
    from lpr.db import transaction

    password = "legacy-password"
    legacy_hash = f"{LEGACY_PREFIX}{_legacy_digest(password)}"
    with transaction() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("olduser", legacy_hash, "operator", utc_now_iso()),
        )

    users = UserRepository()
    assert users.needs_rehash("olduser") is True
    assert users.verify("olduser", "wrong-password") is False
    # A failed attempt must not upgrade anything.
    assert users.needs_rehash("olduser") is True

    assert users.verify("olduser", password) is True

    stored = (
        get_connection()
        .execute("SELECT password_hash FROM users WHERE username = ?", ("olduser",))
        .fetchone()["password_hash"]
    )
    assert stored.startswith("$argon2")
    assert users.needs_rehash("olduser") is False
    # Still works after the upgrade.
    assert users.verify("olduser", password) is True


def test_roles_and_deletion(db) -> None:
    users = UserRepository()
    users.register("op", "pw-one")
    assert users.get_role("op") == "operator"
    assert users.set_role("op", "admin") is True
    assert users.get_role("op") == "admin"
    assert users.delete("op") is True
    assert users.exists("op") is False


# ---------------------------------------------------------------------------
# Legacy migration
# ---------------------------------------------------------------------------


def test_migrate_legacy_database(db, tmp_path) -> None:
    """A legacy plates.db (per-day tables, sha256 users) folds into the new schema."""
    from lpr.db.migrate import migrate

    legacy_path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(legacy_path)
    legacy.executescript(
        """
        CREATE TABLE plates (plate TEXT PRIMARY KEY);
        CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL);
        CREATE TABLE log_dates (date TEXT PRIMARY KEY);
        CREATE TABLE logs_2024_05_01 (timestamp TEXT, message TEXT);
        """
    )
    legacy.execute("INSERT INTO plates VALUES ('34 abc 123')")
    legacy.execute("INSERT INTO users VALUES (?, ?)", ("olduser", _legacy_digest("legacy-pw")))
    legacy.execute("INSERT INTO log_dates VALUES ('2024-05-01')")
    legacy.executemany(
        "INSERT INTO logs_2024_05_01 (timestamp, message) VALUES (?, ?)",
        [
            ("2024-05-01 08:00:00", "Sistem devam ediyor"),
            ("2024-05-01 08:00:01", "Giriş Kamerası > Plaka: 34 ABC 123"),
            ("2024-05-01 08:00:02", "Kayıtlı plaka - Giriş izni verildi"),
            ("2024-05-01 09:00:00", "Çıkış Kamerası > Plaka: 06XYZ99"),
            ("2024-05-01 09:00:01", "Kayıtlı değil - Çıkış reddedildi"),
        ],
    )
    legacy.commit()
    legacy.close()

    report = migrate(legacy_path)
    assert report.legacy_log_tables == ["logs_2024_05_01"]
    assert report.plates_imported == 1
    assert report.users_imported == 1
    assert report.logs_imported == 4
    assert report.logs_unparsed == 1

    assert PlateRepository().all() == ["34ABC123"]

    logs = LogRepository()
    imported = logs.query(plate="34ABC123", limit=100)
    assert [e.action for e in imported] == [str(Action.GRANTED), str(Action.DETECTED)]
    assert all(e.ts.startswith("2024-05-01T") for e in imported)

    denied = logs.query(plate="06XYZ99", limit=100)
    assert {e.camera for e in denied} == {"exit"}
    assert str(Action.DENIED) in {e.action for e in denied}

    # Legacy password still works exactly once, then is upgraded.
    users = UserRepository()
    assert users.needs_rehash("olduser") is True
    assert users.verify("olduser", "legacy-pw") is True
    assert users.needs_rehash("olduser") is False

    # Idempotent.
    second = migrate(legacy_path)
    assert second.already_migrated is True
    assert logs.count_matching() == 4


# ---------------------------------------------------------------------------
# System events
# ---------------------------------------------------------------------------


def _events() -> Any:
    from lpr.db import SystemEventRepository

    return SystemEventRepository()


def test_system_events_round_trip(db: Any) -> None:
    repo = _events()
    assert repo.write("ota", "Gecelik denetim: sistem güncel.") > 0

    rows = repo.recent()
    assert len(rows) == 1
    assert rows[0]["source"] == "ota"
    assert rows[0]["level"] == "info"
    assert rows[0]["ts"]


def test_system_events_come_back_newest_first(db: Any) -> None:
    repo = _events()
    for index in range(3):
        repo.write("ota", f"olay {index}")
    assert [row["message"] for row in repo.recent()] == ["olay 2", "olay 1", "olay 0"]


def test_system_events_filter_by_source(db: Any) -> None:
    repo = _events()
    repo.write("ota", "güncelleme")
    repo.write("license", "lisans")
    assert len(repo.recent(source="ota")) == 1
    assert len(repo.recent()) == 2


def test_an_unknown_level_falls_back_to_info(db: Any) -> None:
    """The UI colours rows by level; an unexpected value must not break it."""
    repo = _events()
    repo.write("ota", "mesaj", level="catastrophic")
    assert repo.recent()[0]["level"] == "info"


def test_system_events_are_kept_out_of_the_plate_log(db: Any) -> None:
    """The two histories share a database, never a table.

    An OTA row in ``logs`` would show up in an operator's vehicle history and
    be counted by the occupancy arithmetic.
    """
    from lpr.db import LogRepository

    _events().write("ota", "Otomatik güncelleme başlatıldı")
    assert LogRepository().recent(limit=10) == []


def test_system_event_retention_is_a_no_op_at_zero(db: Any) -> None:
    repo = _events()
    repo.write("ota", "kalsın")
    assert repo.purge_older_than(0) == 0
    assert len(repo.recent()) == 1


def test_system_event_retention_keeps_recent_rows(db: Any) -> None:
    repo = _events()
    repo.write("ota", "bugün")
    assert repo.purge_older_than(30) == 0
    assert len(repo.recent()) == 1


def test_a_long_message_is_truncated_rather_than_rejected(db: Any) -> None:
    """Compose output is long; losing the row entirely would be worse."""
    repo = _events()
    assert repo.write("ota", "x" * 5000, detail="y" * 9000) > 0
    row = repo.recent()[0]
    assert len(row["message"]) <= 512
    assert len(row["detail"]) <= 4000


# ---------------------------------------------------------------------------
# Partial plate updates
# ---------------------------------------------------------------------------


def test_update_writes_only_the_named_columns(db: Any) -> None:
    """The whole reason update() exists next to upsert().

    ``upsert`` writes every column, so a dashboard toggling the blocked flag
    through it would blank the owner and expiry it never sent.
    """
    from lpr.db import PlateRepository

    repo = PlateRepository()
    repo.upsert(
        "34ABC123",
        owner="Ali",
        apartment="B-12",
        note="Kiracı",
        expires_at="2027-01-01T00:00:00+00:00",
    )
    assert repo.update("34ABC123", blocked=True) is True

    row = repo.get("34ABC123")
    assert row["blocked"] == 1
    assert row["owner"] == "Ali"
    assert row["apartment"] == "B-12"
    assert row["note"] == "Kiracı"
    assert row["expires_at"] == "2027-01-01T00:00:00+00:00"


def test_update_leaves_added_at_alone(db: Any) -> None:
    """It records when the plate was first admitted, not when it was edited."""
    from lpr.db import PlateRepository

    repo = PlateRepository()
    repo.upsert("34ABC123")
    original = repo.get("34ABC123")["added_at"]
    repo.update("34ABC123", owner="Yeni")
    assert repo.get("34ABC123")["added_at"] == original


def test_update_reports_an_unknown_plate(db: Any) -> None:
    from lpr.db import PlateRepository

    assert PlateRepository().update("99ZZZ99", blocked=True) is False


def test_update_with_nothing_to_write_is_a_no_op(db: Any) -> None:
    from lpr.db import PlateRepository

    repo = PlateRepository()
    repo.upsert("34ABC123")
    assert repo.update("34ABC123") is False


def test_update_ignores_columns_it_does_not_own(db: Any) -> None:
    """Column names come from a fixed list, never from the caller.

    That list is what makes the ``SET`` clause safe to build by interpolation:
    an unrecognised key contributes nothing to the SQL at all.
    """
    from lpr.db import PlateRepository

    repo = PlateRepository()
    repo.upsert("34ABC123")
    original = repo.get("34ABC123")

    assert repo.update("34ABC123", added_at="tampered", nonsense=1) is False
    assert repo.get("34ABC123") == original


def test_update_ignores_unknown_keys_but_still_applies_known_ones(db: Any) -> None:
    from lpr.db import PlateRepository

    repo = PlateRepository()
    repo.upsert("34ABC123")
    assert repo.update("34ABC123", owner="Ali", nonsense=1) is True
    assert repo.get("34ABC123")["owner"] == "Ali"


def test_blocking_a_plate_closes_the_gate_to_it(db: Any) -> None:
    from lpr.db import PlateRepository

    repo = PlateRepository()
    repo.upsert("34ABC123")
    assert repo.is_registered("34ABC123") is True

    repo.update("34ABC123", blocked=True)
    assert repo.is_registered("34ABC123") is False
    assert repo.is_blocked("34ABC123") is True


# ---------------------------------------------------------------------------
# Expiry as an access decision
# ---------------------------------------------------------------------------


def test_expired_permit_does_not_authorize(db: Any) -> None:
    """A permit that ran out yesterday must not open the gate.

    The failure this guards against is the quiet one: the plate is still on
    the list, still unblocked, and every screen still shows it -- so an
    ``is_registered`` that only checked membership would wave it through and
    the log would read "gate opened" for a resident who stopped paying.
    """
    from lpr.db import PLATE_EXPIRED, PlateRepository

    repo = PlateRepository()
    repo.upsert("35ACP245", owner="Ahmet", expires_at=_iso(days_ago=1))

    assert repo.authorization("35ACP245") == PLATE_EXPIRED
    assert repo.is_registered("35ACP245") is False
    # Still listed -- expiry is a refusal, not a deletion.
    assert repo.get("35ACP245") is not None


def test_permit_valid_until_tomorrow_still_authorizes(db: Any) -> None:
    """The other half of the boundary: expiry must not refuse a live permit."""
    from lpr.db import PLATE_OK, PlateRepository

    repo = PlateRepository()
    repo.upsert("35ACP246", expires_at=_iso(days_ago=-1))
    assert repo.authorization("35ACP246") == PLATE_OK
    assert repo.is_registered("35ACP246") is True


def test_blocked_outranks_expired(db: Any) -> None:
    """One plate cannot be described two ways by the gate and the UI.

    ``lpr.api.schemas.plate_status`` reports ``blocked`` for a barred plate
    whose permit also lapsed; the gate has to agree, or an operator reading
    "expired" on screen would chase a renewal for a car that is barred.
    """
    from lpr.api.schemas import plate_status
    from lpr.db import PLATE_BLOCKED, PlateRepository

    repo = PlateRepository()
    repo.upsert("35ACP247", expires_at=_iso(days_ago=1), blocked=True)

    assert repo.authorization("35ACP247") == PLATE_BLOCKED
    assert plate_status(repo.get("35ACP247")) == "blocked"


def test_no_expiry_means_permanent(db: Any) -> None:
    """A resident with no end date is not accidentally expired."""
    from lpr.db import PLATE_OK, PLATE_UNKNOWN, PlateRepository

    repo = PlateRepository()
    repo.upsert("35ACP248")
    assert repo.authorization("35ACP248") == PLATE_OK
    # An empty string is what a blanked date field writes, and must read the
    # same as NULL rather than sorting below every timestamp and expiring.
    repo.update("35ACP248", expires_at="")
    assert repo.authorization("35ACP248") == PLATE_OK
    assert repo.authorization("99ZZZ99") == PLATE_UNKNOWN


def test_authorization_ignores_the_owning_accounts_licence(db) -> None:
    """A plate's verdict must not depend on ``users.license_expires_at``.

    That column is one person's subscription to the dashboard and the API.
    Letting it reach the barrier would mean an unpaid software invoice
    stranding a resident in the street -- two failures whose blast radii are
    not comparable, which is why the dependency must not exist in this
    direction.
    """
    from lpr.db import PLATE_OK, PlateRepository, UserRepository
    from lpr.user_license import STATUS_EXPIRED

    users = UserRepository()
    users.register("bekci", "parola1234", "operator")
    users.set_license("bekci", "eski", "2000-01-01T00:00:00+00:00", STATUS_EXPIRED)

    repo = PlateRepository()
    repo.upsert("35ACP250", owner="Ahmet", username="bekci")

    assert repo.authorization("35ACP250") == PLATE_OK
    assert repo.is_registered("35ACP250") is True


# ---------------------------------------------------------------------------
# Snapshot linkage
# ---------------------------------------------------------------------------


def _log_row(camera: str = "entry", plate: str = "34ABC123") -> int:
    return LogRepository().write(
        LprEvent(ts=_iso(), camera=camera, plate=plate, action="granted", confidence=0.9)
    )


def test_the_logs_table_carries_a_snapshot_column(db) -> None:
    conn = get_connection()
    columns = {row[1] for row in conn.execute("PRAGMA table_info(logs)")}
    assert "snapshot_path" in columns


def test_a_snapshot_can_be_linked_to_a_row(db) -> None:
    logs = LogRepository()
    row_id = _log_row()
    assert logs.attach_snapshot(row_id, "/snaps/a.jpg") is True
    assert logs.snapshot_path(row_id) == "/snaps/a.jpg"


def test_a_row_with_no_snapshot_reports_none(db) -> None:
    logs = LogRepository()
    assert logs.snapshot_path(_log_row()) is None


def test_an_unknown_row_reports_none_rather_than_raising(db) -> None:
    assert LogRepository().snapshot_path(999_999) is None


def test_linking_to_a_missing_row_is_false_not_an_exception(db) -> None:
    """A lost thumbnail must never become a lost event."""
    assert LogRepository().attach_snapshot(999_999, "/snaps/a.jpg") is False


def test_linking_nothing_is_a_no_op(db) -> None:
    logs = LogRepository()
    row_id = _log_row()
    assert logs.attach_snapshot(row_id, None) is False
    assert logs.attach_snapshot(0, "/snaps/a.jpg") is False


def test_only_rows_with_a_photo_are_reported_as_having_one(db) -> None:
    logs = LogRepository()
    linked, bare = _log_row(), _log_row(camera="exit")
    logs.attach_snapshot(linked, "/snaps/a.jpg")
    assert logs.ids_with_snapshots([linked, bare]) == {linked}


def test_asking_about_no_rows_costs_no_query(db) -> None:
    assert LogRepository().ids_with_snapshots([]) == set()


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def test_a_granted_entry_opens_a_stay(db) -> None:
    sessions = SessionRepository()
    session_id = sessions.start_session("34ABC123", "2026-05-01T09:00:00+00:00", 1)
    assert session_id
    active = sessions.get_active_sessions()
    assert [row["plate"] for row in active] == ["34ABC123"]
    assert active[0]["status"] == "open"


def test_a_second_entry_for_a_car_already_inside_keeps_the_first(db) -> None:
    """The first entry is the true arrival.

    A duplicate entry read -- a missed exit, a car re-read while it waits at
    the barrier -- must not restart the clock or manufacture a phantom stay.
    """
    sessions = SessionRepository()
    first = sessions.start_session("34ABC123", "2026-05-01T09:00:00+00:00", 1)
    second = sessions.start_session("34ABC123", "2026-05-01T09:05:00+00:00", 2)

    assert second == first
    assert len(sessions.get_active_sessions()) == 1
    assert sessions.get_active_sessions()[0]["entry_ts"] == "2026-05-01T09:00:00+00:00"


def test_an_exit_closes_the_stay_and_records_its_duration(db) -> None:
    sessions = SessionRepository()
    sessions.start_session("34ABC123", "2026-05-01T09:00:00+00:00", 1)
    sessions.close_session("34ABC123", "2026-05-01T11:30:00+00:00", 2)

    assert sessions.get_active_sessions() == []
    row = sessions.history(limit=1)[0]
    assert row["status"] == "closed"
    assert row["duration_seconds"] == 9000
    assert row["exit_log_id"] == 2


def test_an_exit_with_no_open_stay_is_recorded_not_dropped(db) -> None:
    """A car leaving is evidence, even when its arrival was never seen.

    Dropping it would leave the trail claiming the car never left; inventing an
    entry time to measure against would be fabricating data. The row is kept
    with a NULL entry and no duration, which is the honest shape.
    """
    sessions = SessionRepository()
    assert sessions.close_session("99XY999", "2026-05-01T12:00:00+00:00", 7)

    row = sessions.history(limit=1)[0]
    assert row["status"] == "orphan_exit"
    assert row["entry_ts"] is None
    assert row["duration_seconds"] is None
    assert sessions.get_active_sessions() == []


def test_an_open_stay_reports_its_duration_so_far(db) -> None:
    """Computed on read: a stored value would be stale the moment it was written."""
    sessions = SessionRepository()
    sessions.start_session("34ABC123", _iso(days_ago=0.5), 1)
    assert sessions.get_active_sessions()[0]["duration_seconds"] >= 43_000


def test_active_stays_are_ordered_oldest_first(db) -> None:
    sessions = SessionRepository()
    sessions.start_session("06BZ1234", "2026-05-01T11:00:00+00:00", 1)
    sessions.start_session("34ABC123", "2026-05-01T09:00:00+00:00", 2)
    assert [row["plate"] for row in sessions.get_active_sessions()] == ["34ABC123", "06BZ1234"]


def test_an_empty_plate_is_refused(db) -> None:
    sessions = SessionRepository()
    assert sessions.start_session("", "2026-05-01T09:00:00+00:00", 1) is None
    assert sessions.close_session("   ", "2026-05-01T09:00:00+00:00", 1) is None


def test_a_clock_that_went_backwards_yields_no_duration(db) -> None:
    """An unknown length and a zero length are different facts."""
    sessions = SessionRepository()
    sessions.start_session("34ABC123", "2026-05-01T11:00:00+00:00", 1)
    sessions.close_session("34ABC123", "2026-05-01T09:00:00+00:00", 2)
    assert sessions.history(limit=1)[0]["duration_seconds"] is None


def test_the_active_count_matches_the_active_list(db) -> None:
    sessions = SessionRepository()
    sessions.start_session("34ABC123", _iso(), 1)
    sessions.start_session("06BZ1234", _iso(), 2)
    sessions.close_session("34ABC123", _iso(), 3)
    assert sessions.active_count() == len(sessions.get_active_sessions()) == 1


def test_history_can_be_filtered_by_plate(db) -> None:
    sessions = SessionRepository()
    sessions.start_session("34ABC123", _iso(), 1)
    sessions.start_session("06BZ1234", _iso(), 2)
    rows = sessions.history(plate="34ABC123")
    assert [row["plate"] for row in rows] == ["34ABC123"]


def test_history_paginates(db) -> None:
    sessions = SessionRepository()
    for index in range(5):
        sessions.start_session(f"34AB{index}12", _iso(), index + 1)
    assert len(sessions.history(limit=2)) == 2
    assert len(sessions.history(limit=2, offset=4)) == 1


def test_sessions_do_not_disturb_the_derived_occupancy(db) -> None:
    """`occupancy_since` stays the source of truth for the live count.

    The two are computed independently on purpose: a disagreement is a bug
    detector, and the barrier must never depend on the sessions table.
    """
    logs = LogRepository()
    logs.write(LprEvent(ts=_iso(), camera="entry", plate="34ABC123", action="granted"))
    SessionRepository().start_session("34ABC123", _iso(), 1)
    assert logs.occupancy_since(_iso(days_ago=1))["inside"] == 1
