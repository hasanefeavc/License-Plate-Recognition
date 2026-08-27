"""Tests for the persistence layer.

These lock in the fixes for the legacy defects: a single cross-thread
connection, per-day tables built by string interpolation, and unsalted
SHA-256 passwords.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from lpr.contracts import Action, CameraRole, LprEvent, utc_now_iso
from lpr.db import (
    LogRepository,
    PlateRepository,
    UserRepository,
    get_connection,
    init_db,
    normalise_plate,
    schema_version,
)
from lpr.db.repository import LEGACY_PREFIX, _legacy_digest


def _iso(days_ago: float = 0.0) -> str:
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return moment.replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------


def test_schema_is_created_and_versioned(db) -> None:
    conn = get_connection()
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"plates", "users", "logs", "schema_meta"} <= tables
    assert schema_version() >= 1


def test_no_per_day_log_tables_exist(db) -> None:
    """The legacy layout created one table per day; there is now exactly one."""
    LogRepository().write(
        LprEvent(ts=utc_now_iso(), camera="entry", plate="34ABC123", action="granted")
    )
    conn = get_connection()
    names = [
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    ]
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
    names = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
    }
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

    with pytest.raises(RuntimeError):
        with transaction() as conn:
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
            LprEvent(
                ts=ts, camera=camera, plate=plate, action=str(action), confidence=confidence
            )
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


def test_log_plate_is_normalised_on_write(db) -> None:
    logs = LogRepository()
    logs.write(
        LprEvent(ts=utc_now_iso(), camera="entry", plate=" 34 abc 123 ", action="granted")
    )
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

    stored = get_connection().execute(
        "SELECT password_hash FROM users WHERE username = ?", ("operator",)
    ).fetchone()["password_hash"]
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

    stored = get_connection().execute(
        "SELECT password_hash FROM users WHERE username = ?", ("olduser",)
    ).fetchone()["password_hash"]
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
    legacy.execute(
        "INSERT INTO users VALUES (?, ?)", ("olduser", _legacy_digest("legacy-pw"))
    )
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
    repo.upsert("34ABC123", owner="Ali", apartment="B-12", note="Kiracı",
                expires_at="2027-01-01T00:00:00+00:00")
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
