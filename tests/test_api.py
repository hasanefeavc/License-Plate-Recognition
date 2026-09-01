"""Tests for the HTTP API.

The pipeline and the repositories are replaced by local fakes: nothing here
imports ``lpr.pipeline``, so the suite runs without torch, ultralytics or
easyocr. The fake orchestrator implements exactly the public surface
:mod:`lpr.api.routes` is allowed to use.

The one deliberate exception is the date-filtering section, which drives the
real :class:`~lpr.db.LogRepository` over a temporary SQLite file. A fake that
records its arguments cannot show whether a day filter actually selects that
day, and that comparison is exactly where the bug it guards against lived.
``lpr.db`` needs nothing but stdlib ``sqlite3``, so this costs the suite no ML
dependency; the imports are kept function-local so collection still succeeds
without a database.

``TestClient`` is deliberately *not* used as a context manager -- entering it
would run the real lifespan (init_db + build_pipeline), which is precisely what
these tests replace.
"""

from __future__ import annotations

import types
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from lpr.api import deps  # noqa: E402
from lpr.api.main import create_app  # noqa: E402
from lpr.api.security import LICENSE_LAPSED_DETAIL, create_token  # noqa: E402
from lpr.contracts import LprEvent, utc_now_iso  # noqa: E402
from lpr.license import LicenseError, LicenseStatus  # noqa: E402

_MISSING = object()


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakePlateRepository:
    def __init__(self, plates: dict[str, str | None] | None = None) -> None:
        self._plates: dict[str, str | None] = dict(plates or {})

    def is_registered(self, plate: str) -> bool:
        return plate in self._plates

    def add(self, plate: str, note: str | None = None) -> bool:
        if plate in self._plates:
            return False
        self._plates[plate] = note
        return True

    def remove(self, plate: str) -> bool:
        return self._plates.pop(plate, _MISSING) is not _MISSING

    def all(self) -> list[str]:
        return sorted(self._plates)

    def count(self) -> int:
        return len(self._plates)


class FakeLogRepository:
    def __init__(self, events: list[Any] | None = None) -> None:
        self.events = list(events or [])
        self.last_query: dict[str, Any] | None = None
        self.written: list[Any] = []
        #: Offset the last ``dates()`` call was made with.
        self.dates_offset: int | None = None

    def write(self, event: Any) -> int:
        self.written.append(event)
        return len(self.written)

    def query(
        self,
        since: str | None = None,
        until: str | None = None,
        camera: str | None = None,
        plate: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[Any]:
        self.last_query = {
            "since": since,
            "until": until,
            "camera": camera,
            "plate": plate,
            "limit": limit,
            "offset": offset,
        }
        return self.events

    def recent(self, limit: int) -> list[Any]:
        return self.events[:limit]

    def dates(self, tz_offset_minutes: int = 0) -> list[str]:
        self.dates_offset = tz_offset_minutes
        return ["2026-05-02", "2026-05-01"]

    def purge_older_than(self, days: int) -> int:
        return 0


class FakeUserRepository:
    def __init__(self, users: dict[str, tuple[str, str]] | None = None) -> None:
        # username -> (password, role)
        self._users: dict[str, tuple[str, str]] = dict(users or {})

    def is_first_user(self) -> bool:
        return not self._users

    def exists(self, username: str) -> bool:
        return username in self._users

    def register(self, username: str, password: str, role: str = "operator") -> bool:
        if username in self._users:
            return False
        self._users[username] = (password, role)
        return True

    def verify(self, username: str, password: str) -> bool:
        stored = self._users.get(username)
        return stored is not None and stored[0] == password

    def list_users(self) -> list[dict[str, Any]]:
        return [
            {"username": name, "role": role, "created_at": "2026-05-01"}
            for name, (_pw, role) in self._users.items()
        ]


class FakeRelay:
    def __init__(self) -> None:
        self.triggers = 0

    def trigger(self) -> None:
        self.triggers += 1


class FakePipeline:
    """Implements only what routes.py is contractually allowed to call."""

    def __init__(self, connected: bool = True) -> None:
        self.running = True
        self.relay = FakeRelay()
        self.subscribers: list[Any] = []
        self.telemetry_subscribers: list[Any] = []
        self._connected = connected
        self.frame = b"\xff\xd8fake-jpeg\xff\xd9"
        self.paused = False

    def pause(self) -> None:
        self.paused = True

    def resume(self) -> None:
        self.paused = False

    def stats(self) -> Any:
        return types.SimpleNamespace(
            started_at=1_700_000_000.0,
            plates_read=7,
            grants=5,
            denials=2,
            cameras={
                "entry": types.SimpleNamespace(
                    role="entry",
                    source="0",
                    connected=self._connected,
                    fps=12.5,
                    frames_read=100,
                    frames_dropped=1,
                    motion_skipped=900,
                    last_error=None,
                    last_frame_ts=1_700_000_100.0,
                ),
                "exit": types.SimpleNamespace(
                    role="exit",
                    source="1",
                    connected=False,
                    fps=0.0,
                    frames_read=0,
                    frames_dropped=0,
                    last_error="kamera yok",
                    last_frame_ts=0.0,
                ),
            },
        )

    def latest_frame_jpeg(self, camera: str, quality: int = 80) -> bytes | None:
        return self.frame

    def subscribe(self, telemetry: bool = False) -> Any:
        import queue

        q: Any = queue.Queue()
        if telemetry:
            self.telemetry_subscribers.append(q)
        else:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: Any) -> None:
        for group in (self.subscribers, self.telemetry_subscribers):
            if q in group:
                group.remove(q)

    def unsubscribe(self, q: Any) -> None:
        if q in self.subscribers:
            self.subscribers.remove(q)

    def start(self) -> None:  # pragma: no cover - lifespan is not exercised
        self.running = True

    def stop(self, timeout: float = 5.0) -> None:  # pragma: no cover
        self.running = False


def valid_license(client: str = "Test Sitesi") -> LicenseStatus:
    return LicenseStatus(
        valid=True,
        reason="ok",
        detail="Lisans geçerli.",
        client=client,
        issued_at="2026-01-01T00:00:00+00:00",
        expires_at="2099-01-01T00:00:00+00:00",
        seconds_remaining=86400.0,
    )


class FakeLicenseGuard:
    """Stand-in for ``lpr.license.LicenseGuard``: no crypto, no database.

    The real guard is covered by ``tests/test_license.py``; here the point is
    only what the endpoints do with a valid or invalid one.
    """

    def __init__(self, status: LicenseStatus | None = None) -> None:
        self.status = status or valid_license()
        self.activated: list[str] = []

    def refresh(self, **_kwargs: Any) -> LicenseStatus:
        return self.status

    def activate(self, token: str) -> LicenseStatus:
        if token == "gecersiz-anahtar":
            raise LicenseError("Lisans anahtarı geçersiz.", "invalid")
        self.activated.append(token)
        self.status = valid_license()
        return self.status


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def plate_repo() -> FakePlateRepository:
    return FakePlateRepository()


@pytest.fixture()
def log_repo() -> FakeLogRepository:
    return FakeLogRepository()


@pytest.fixture()
def user_repo() -> FakeUserRepository:
    return FakeUserRepository()


@pytest.fixture()
def api_app(
    plate_repo: FakePlateRepository,
    log_repo: FakeLogRepository,
    user_repo: FakeUserRepository,
) -> Any:
    app = create_app()
    app.state.pipeline = FakePipeline()
    # The lifespan (and therefore the licence watchdog) never runs in these
    # tests, so the guard is installed directly. A licensed app is the
    # baseline; ``expired_app`` covers the other half.
    app.state.license_guard = FakeLicenseGuard()
    app.dependency_overrides[deps.get_plate_repository] = lambda: plate_repo
    app.dependency_overrides[deps.get_log_repository] = lambda: log_repo
    app.dependency_overrides[deps.get_user_repository] = lambda: user_repo
    return app


@pytest.fixture()
def expired_app(api_app: Any) -> Any:
    """A licensed app whose licence has just lapsed, pipeline held paused."""
    api_app.state.license_guard = FakeLicenseGuard(
        LicenseStatus.failure("expired", expires_at="2026-01-01T00:00:00+00:00")
    )
    deps.apply_license_state(api_app, False)
    return api_app


@pytest.fixture()
def api_client(api_app: Any) -> TestClient:
    # No `with`: the real lifespan must not run.
    return TestClient(api_app)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_token() -> str:
    return create_token("admin", "admin")


@pytest.fixture()
def operator_token() -> str:
    return create_token("operator", "operator")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def test_health_without_auth(api_client: TestClient) -> None:
    response = api_client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["pipeline_running"] is True
    assert body["cameras"] == {"entry": True, "exit": False}


def test_health_reports_degraded_without_pipeline(api_app: Any) -> None:
    api_app.state.pipeline = None
    api_app.state.pipeline_error = "torch bulunamadı"
    client = TestClient(api_app)

    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["pipeline_running"] is False
    assert body["cameras"] == {"entry": False, "exit": False}
    assert "torch" in (body["detail"] or "")


def test_health_degraded_when_no_camera_connected(api_app: Any) -> None:
    api_app.state.pipeline = FakePipeline(connected=False)
    client = TestClient(api_app)

    body = client.get("/health").json()

    assert body["status"] == "degraded"
    assert body["pipeline_running"] is True


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_first_user_registers_without_auth_and_becomes_admin(
    api_client: TestClient, user_repo: FakeUserRepository
) -> None:
    response = api_client.post(
        "/api/auth/register", json={"username": "kurulum", "password": "gizli123"}
    )

    assert response.status_code == 201
    body = response.json()
    assert body["role"] == "admin"
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert user_repo.exists("kurulum")


def test_second_registration_requires_admin_token(
    api_client: TestClient, user_repo: FakeUserRepository, operator_token: str
) -> None:
    user_repo.register("kurulum", "gizli123", "admin")

    anonymous = api_client.post(
        "/api/auth/register", json={"username": "ikinci", "password": "gizli123"}
    )
    assert anonymous.status_code == 401

    as_operator = api_client.post(
        "/api/auth/register",
        json={"username": "ikinci", "password": "gizli123"},
        headers=auth(operator_token),
    )
    assert as_operator.status_code == 403
    assert not user_repo.exists("ikinci")


def test_second_registration_succeeds_for_admin(
    api_client: TestClient, user_repo: FakeUserRepository, admin_token: str
) -> None:
    user_repo.register("kurulum", "gizli123", "admin")

    response = api_client.post(
        "/api/auth/register",
        json={"username": "ikinci", "password": "gizli123", "role": "operator"},
        headers=auth(admin_token),
    )

    assert response.status_code == 201
    assert response.json()["role"] == "operator"
    assert user_repo.exists("ikinci")


def test_login_returns_token_that_authorises_calls(
    api_client: TestClient, user_repo: FakeUserRepository
) -> None:
    user_repo.register("mudur", "gizli123", "admin")

    login = api_client.post(
        "/api/auth/login", json={"username": "mudur", "password": "gizli123"}
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    assert login.json()["role"] == "admin"

    me = api_client.get("/api/auth/me", headers=auth(token))
    assert me.status_code == 200
    body = me.json()
    # Field-wise: UserOut gained token_ttl_min, and an exact match would turn
    # every additive field into a breakage.
    assert body["username"] == "mudur"
    assert body["role"] == "admin"


def test_login_with_wrong_password_is_401(
    api_client: TestClient, user_repo: FakeUserRepository
) -> None:
    user_repo.register("mudur", "dogru", "admin")

    response = api_client.post(
        "/api/auth/login", json={"username": "mudur", "password": "yanlis"}
    )

    assert response.status_code == 401
    assert response.json()["error"]["status"] == 401


def test_unauthenticated_call_is_401(api_client: TestClient) -> None:
    response = api_client.get("/api/plates")
    assert response.status_code == 401


def test_invalid_token_is_401(api_client: TestClient) -> None:
    response = api_client.get("/api/plates", headers=auth("not-a-jwt"))
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Plates
# ---------------------------------------------------------------------------


def test_an_operator_may_manage_plates(
    api_client: TestClient, operator_token: str, plate_repo: FakePlateRepository
) -> None:
    """Plate CRUD is an operator's job -- they are the ones at the barrier."""
    created = api_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=auth(operator_token)
    )
    assert created.status_code == 201
    assert plate_repo.is_registered("34ABC123")

    removed = api_client.delete("/api/plates/34ABC123", headers=auth(operator_token))
    assert removed.status_code == 200


def test_plate_writes_still_require_authentication(api_client: TestClient) -> None:
    assert api_client.post("/api/plates", json={"plate": "34ABC123"}).status_code == 401
    assert api_client.delete("/api/plates/34ABC123").status_code == 401


def test_plate_crud_round_trip(
    api_client: TestClient,
    admin_token: str,
    operator_token: str,
    plate_repo: FakePlateRepository,
) -> None:
    created = api_client.post(
        "/api/plates",
        json={"plate": " 34 abc 123 ", "note": "Müdür aracı"},
        headers=auth(admin_token),
    )
    assert created.status_code == 201
    assert created.json() == {"plate": "34ABC123", "registered": True}
    assert plate_repo.is_registered("34ABC123")

    listed = api_client.get("/api/plates", headers=auth(operator_token))
    assert listed.status_code == 200
    body = listed.json()
    # Field-wise rather than exact-equality: `records` was added alongside
    # `plates`, and an exact match would make every additive field a breakage.
    assert body["plates"] == ["34ABC123"]
    assert body["count"] == 1
    assert [row["plate"] for row in body["records"]] == ["34ABC123"]

    duplicate = api_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=auth(admin_token)
    )
    assert duplicate.status_code == 409

    deleted = api_client.delete("/api/plates/34ABC123", headers=auth(admin_token))
    assert deleted.status_code == 200
    assert deleted.json()["registered"] is False
    assert plate_repo.all() == []


def test_delete_missing_plate_is_404(api_client: TestClient, admin_token: str) -> None:
    response = api_client.delete("/api/plates/99ZZZ999", headers=auth(admin_token))

    assert response.status_code == 404
    assert "99ZZZ999" in response.json()["error"]["detail"]


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


def test_log_query_params_reach_the_repository(
    api_client: TestClient, operator_token: str, log_repo: FakeLogRepository
) -> None:
    response = api_client.get(
        "/api/logs",
        params={
            "since": "2026-05-01",
            "until": "2026-05-02",
            "camera": "entry",
            "plate": "34-abc-123",
            "limit": 50,
            "offset": 10,
        },
        headers=auth(operator_token),
    )

    assert response.status_code == 200
    assert log_repo.last_query == {
        "since": "2026-05-01",
        "until": "2026-05-02",
        "camera": "entry",
        "plate": "34ABC123",
        "limit": 50,
        "offset": 10,
    }


def test_logs_are_serialised_from_events(
    api_client: TestClient, operator_token: str, log_repo: FakeLogRepository
) -> None:
    from lpr.contracts import LprEvent

    log_repo.events = [
        LprEvent(
            ts="2026-05-01T09:15:00+00:00",
            camera="entry",
            plate="34ABC123",
            action="granted",
            confidence=0.97123,
            id=3,
        )
    ]

    body = api_client.get("/api/logs", headers=auth(operator_token)).json()

    assert body == [
        {
            "id": 3,
            "ts": "2026-05-01T09:15:00+00:00",
            "camera": "entry",
            "plate": "34ABC123",
            "action": "granted",
            "confidence": 0.9712,
        }
    ]


def test_log_dates(api_client: TestClient, operator_token: str) -> None:
    response = api_client.get("/api/logs/dates", headers=auth(operator_token))

    assert response.status_code == 200
    assert response.json() == ["2026-05-02", "2026-05-01"]


# ---------------------------------------------------------------------------
# Date filtering, over a real database
#
# The fake log repository records the filters it was handed but does not apply
# them, so it can prove the *plumbing* and nothing about whether a day filter
# actually selects that day. These run the real LogRepository against real
# SQLite, because the reported bug -- every preset except "Tümü" returning an
# empty list -- lived entirely in the comparison the fake does not perform.
# ---------------------------------------------------------------------------


@pytest.fixture()
def real_log_app(api_app: Any, db: Any) -> Any:
    """``api_app`` with the genuine LogRepository behind ``/api/logs``."""
    from lpr.db import LogRepository

    repo = LogRepository()
    api_app.dependency_overrides[deps.get_log_repository] = lambda: repo
    return api_app


def _log_at(moment: datetime, plate: str, camera: str = "entry") -> None:
    """Write one log row at a chosen instant, through the real repository.

    ``moment`` is converted to UTC first, whatever timezone it arrives in,
    because that is the only thing the production write path ever stores
    (:func:`lpr.contracts.utc_now_iso`) and the lexical ``ts`` comparison in
    the repository depends on every row being in that one shape. Writing a
    ``+03:00`` offset straight through would put a 23:59 local row *after* the
    day's upper bound as text while being before it in time -- a failure that
    belongs to the test, not to the filter it is aiming at.
    """
    from lpr.db import LogRepository

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    LogRepository().write(
        LprEvent(
            ts=moment.astimezone(timezone.utc).replace(microsecond=0).isoformat(),
            camera=camera,
            plate=plate,
            action="granted",
            confidence=0.9,
        )
    )


def _plates(response: Any) -> set[str]:
    return {row["plate"] for row in response.json()}


def test_filtering_by_today_returns_todays_logs(
    real_log_app: Any, operator_token: str
) -> None:
    """The reported bug: picking a day returned nothing at all.

    ``until="2026-08-28"`` is *shorter* than the stored
    ``"2026-08-28T14:32:11+00:00"``, so a lexical ``ts <= ?`` put every row on
    that day after the bound and the filter matched zero rows -- while "Tümü",
    which sends no dates, kept working. That asymmetry is the whole signature
    of the defect.
    """
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%d")

    _log_at(now.replace(hour=14, minute=32, second=11), "34TODAY1")
    _log_at(now - timedelta(days=1), "34YEST01")

    client = TestClient(real_log_app)
    response = client.get(
        "/api/logs",
        params={"since": today, "until": today},
        headers=auth(operator_token),
    )

    assert response.status_code == 200
    assert _plates(response) == {"34TODAY1"}, "today's log must come back"
    assert yesterday != today


def test_filtering_by_yesterday_returns_only_yesterday(
    real_log_app: Any, operator_token: str
) -> None:
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)

    _log_at(now, "34TODAY1")
    _log_at(yesterday, "34YEST01")

    client = TestClient(real_log_app)
    response = client.get(
        "/api/logs",
        params={
            "since": yesterday.strftime("%Y-%m-%d"),
            "until": yesterday.strftime("%Y-%m-%d"),
        },
        headers=auth(operator_token),
    )

    assert _plates(response) == {"34YEST01"}


def test_a_day_filter_includes_the_very_last_second_of_the_day(
    real_log_app: Any, operator_token: str
) -> None:
    """Both ends of the expanded window are inclusive.

    23:59:59 is the row an off-by-one in the upper bound drops, and the one
    nobody notices is missing until a night-shift read goes unaccounted for.
    """
    day = datetime(2026, 5, 2, tzinfo=timezone.utc)
    _log_at(day.replace(hour=0, minute=0, second=0), "34FIRST1")
    _log_at(day.replace(hour=23, minute=59, second=59), "34LAST01")
    _log_at(day + timedelta(days=1), "34NEXT01")

    client = TestClient(real_log_app)
    response = client.get(
        "/api/logs",
        params={"since": "2026-05-02", "until": "2026-05-02"},
        headers=auth(operator_token),
    )

    assert _plates(response) == {"34FIRST1", "34LAST01"}


def test_an_older_single_day_returns_its_afternoon_rows(
    real_log_app: Any, operator_token: str
) -> None:
    """The reported symptom: picking an *older* day from the dropdown was empty.

    Three days back at 15:00 local is the interesting case rather than an
    arbitrary one. It sits in the middle of the working day, so no day-boundary
    arithmetic can excuse dropping it, and it is far enough back that a filter
    which only ever worked for "today" -- because an unbounded query happened
    to return today's rows anyway -- is caught here and nowhere else.

    Driven through the API with the exact bounds ``web/app.js`` computes, east
    of Greenwich, so the whole chain is under test: the browser's local-midnight
    instants, the ``...Z`` spelling they arrive in, and the repository's
    normalisation of both ends.
    """
    east = timezone(timedelta(hours=3))  # Europe/Istanbul, the deployed site
    day = (datetime.now(east) - timedelta(days=3)).date()

    def at(hour: int, minute: int = 0) -> datetime:
        """That local day at a given wall-clock time, east of Greenwich."""
        return datetime(day.year, day.month, day.day, hour, minute, tzinfo=east)

    _log_at(at(15), "34AFT001")  # the record the report named
    _log_at(at(0), "34FIRST1")  # local midnight, the lower edge
    _log_at(at(23, 59), "34LAST01")  # last minute, the upper edge
    _log_at(at(15) - timedelta(days=1), "34PREV01")
    _log_at(at(15) + timedelta(days=1), "34NEXT01")

    # Exactly what dayRange() sends: local midnight and 23:59:59.999 as UTC
    # instants with a trailing Z.
    since = at(0).astimezone(timezone.utc)
    until = datetime(
        day.year, day.month, day.day, 23, 59, 59, 999_000, tzinfo=east
    ).astimezone(timezone.utc)

    client = TestClient(real_log_app)
    response = client.get(
        "/api/logs",
        params={
            "since": since.isoformat().replace("+00:00", "Z"),
            "until": until.isoformat().replace("+00:00", "Z"),
        },
        headers=auth(operator_token),
    )

    assert response.status_code == 200
    assert _plates(response) == {"34AFT001", "34FIRST1", "34LAST01"}


def test_an_older_single_day_works_from_the_bare_date_too(
    real_log_app: Any, operator_token: str
) -> None:
    """The same day, filtered by the dropdown's own ``YYYY-MM-DD`` value.

    Anything holding the API directly -- the CSV export, a curl, a script --
    passes the bare date rather than recomputing instants, so both spellings
    have to select the same afternoon row.
    """
    day = (datetime.now(timezone.utc) - timedelta(days=3)).date()
    _log_at(datetime(day.year, day.month, day.day, 15, 0, tzinfo=timezone.utc), "34AFT001")
    _log_at(datetime(day.year, day.month, day.day, 23, 59, 59, tzinfo=timezone.utc), "34LAST01")
    _log_at(datetime.now(timezone.utc), "34TODAY1")

    client = TestClient(real_log_app)
    response = client.get(
        "/api/logs",
        params={"since": str(day), "until": str(day)},
        headers=auth(operator_token),
    )

    assert _plates(response) == {"34AFT001", "34LAST01"}


def test_the_day_picker_and_the_day_filter_agree_east_of_greenwich(
    real_log_app: Any, operator_token: str
) -> None:
    """Every day the picker offers must return the row that put it there.

    These are two different pieces of arithmetic -- SQLite bucketing in
    ``dates()``, Python bounds in ``query()`` -- over the same rows, and a
    disagreement between them is invisible until an operator picks the one day
    that falls through the gap. Late-evening reads are where they diverge: 23:30
    in Istanbul is stored as 20:30 UTC the *same* day, but 01:30 is stored as
    22:30 the day *before*.
    """
    from lpr.db import LogRepository

    east = timezone(timedelta(hours=3))
    base = (datetime.now(east) - timedelta(days=3)).replace(
        minute=0, second=0, microsecond=0
    )
    for hour in range(24):
        _log_at(base.replace(hour=hour), f"34H{hour:05d}")

    client = TestClient(real_log_app)
    offered = LogRepository().dates(180)
    assert offered, "the picker must offer the day these rows landed on"

    seen: set[str] = set()
    for day_text in offered:
        year, month, date = (int(part) for part in day_text.split("-"))
        since = datetime(year, month, date, tzinfo=east).astimezone(timezone.utc)
        until = datetime(
            year, month, date, 23, 59, 59, 999_000, tzinfo=east
        ).astimezone(timezone.utc)
        response = client.get(
            "/api/logs",
            params={
                "since": since.isoformat().replace("+00:00", "Z"),
                "until": until.isoformat().replace("+00:00", "Z"),
                "limit": 1000,
            },
            headers=auth(operator_token),
        )
        assert response.status_code == 200
        assert _plates(response), f"the picker offered {day_text} but it filters to nothing"
        seen |= _plates(response)

    # Every row is reachable through some offered day: none falls in a gap.
    assert seen == {f"34H{hour:05d}" for hour in range(24)}


def test_the_unfiltered_view_still_returns_everything(
    real_log_app: Any, operator_token: str
) -> None:
    """"Tümü" was the one option that worked; it has to keep working."""
    now = datetime.now(timezone.utc)
    _log_at(now, "34TODAY1")
    _log_at(now - timedelta(days=1), "34YEST01")

    client = TestClient(real_log_app)
    response = client.get("/api/logs", headers=auth(operator_token))

    assert _plates(response) == {"34TODAY1", "34YEST01"}


def test_full_iso_bounds_from_a_browser_are_accepted(
    real_log_app: Any, operator_token: str
) -> None:
    """What the dashboard actually sends: local midnight, as a `...Z` instant.

    JavaScript's `toISOString()` yields milliseconds and a `Z`, neither of
    which appears in the stored format. Comparing those two shapes as text is
    only accidentally correct, so the server normalises before comparing.
    """
    _log_at(datetime(2026, 5, 2, 12, 0, 0, tzinfo=timezone.utc), "34MIDDAY")
    _log_at(datetime(2026, 5, 3, 12, 0, 0, tzinfo=timezone.utc), "34NEXTDY")

    client = TestClient(real_log_app)
    response = client.get(
        "/api/logs",
        params={
            "since": "2026-05-02T00:00:00.000Z",
            "until": "2026-05-02T23:59:59.999Z",
        },
        headers=auth(operator_token),
    )

    assert _plates(response) == {"34MIDDAY"}


def test_an_offset_bearing_bound_is_converted_not_compared_as_text(
    real_log_app: Any, operator_token: str
) -> None:
    """A local-midnight bound in UTC+3 selects the local day, not the UTC one.

    01:30 in Istanbul is 22:30 the previous day in UTC. An operator asking for
    "3 May" in Istanbul must get that read; a UTC-day filter would file it
    under 2 May and lose it.
    """
    _log_at(datetime(2026, 5, 2, 22, 30, 0, tzinfo=timezone.utc), "34LATE01")
    _log_at(datetime(2026, 5, 2, 20, 0, 0, tzinfo=timezone.utc), "34EARLY1")

    client = TestClient(real_log_app)
    response = client.get(
        "/api/logs",
        params={
            "since": "2026-05-03T00:00:00+03:00",  # == 2026-05-02T21:00:00Z
            "until": "2026-05-03T23:59:59+03:00",
        },
        headers=auth(operator_token),
    )

    assert _plates(response) == {"34LATE01"}


def test_the_day_list_can_be_bucketed_in_the_operators_timezone(
    real_log_app: Any, operator_token: str
) -> None:
    """The other half of the drift: the picker must offer the operator's days.

    Without a matching offset the list and the filter disagree about where the
    day starts, and a day plainly holding rows comes back empty when chosen.
    """
    _log_at(datetime(2026, 5, 2, 22, 30, 0, tzinfo=timezone.utc), "34LATE01")

    client = TestClient(real_log_app)
    utc_days = client.get("/api/logs/dates", headers=auth(operator_token)).json()
    istanbul = client.get(
        "/api/logs/dates", params={"tz_offset": 180}, headers=auth(operator_token)
    ).json()

    assert utc_days == ["2026-05-02"]
    assert istanbul == ["2026-05-03"], "22:30 UTC is 01:30 the next day in Istanbul"


def test_an_implausible_timezone_offset_is_refused(
    real_log_app: Any, operator_token: str
) -> None:
    """Better a 422 than a silently skewed day list."""
    client = TestClient(real_log_app)
    response = client.get(
        "/api/logs/dates", params={"tz_offset": 5000}, headers=auth(operator_token)
    )
    assert response.status_code == 422


def test_bad_log_camera_is_422(api_client: TestClient, operator_token: str) -> None:
    response = api_client.get(
        "/api/logs", params={"camera": "garaj"}, headers=auth(operator_token)
    )

    assert response.status_code == 422
    assert response.json()["error"]["status"] == 422


# ---------------------------------------------------------------------------
# Stats / cameras / pipeline / relay
# ---------------------------------------------------------------------------


def test_stats(api_client: TestClient, operator_token: str) -> None:
    body = api_client.get("/api/stats", headers=auth(operator_token)).json()

    assert body["running"] is True
    assert body["plates_read"] == 7
    assert body["grants"] == 5
    assert body["denials"] == 2
    assert {c["role"] for c in body["cameras"]} == {"entry", "exit"}


def test_cameras(api_client: TestClient, operator_token: str) -> None:
    body = api_client.get("/api/cameras", headers=auth(operator_token)).json()

    by_role = {c["role"]: c for c in body}
    assert by_role["entry"]["connected"] is True
    assert by_role["exit"]["last_error"] == "kamera yok"


def test_cameras_without_pipeline_still_answers(
    api_app: Any, operator_token: str
) -> None:
    api_app.state.pipeline = None
    client = TestClient(api_app)

    body = client.get("/api/cameras", headers=auth(operator_token)).json()

    assert [c["role"] for c in body] == ["entry", "exit"]
    assert all(c["connected"] is False for c in body)


def test_stats_without_pipeline_is_503(api_app: Any, operator_token: str) -> None:
    api_app.state.pipeline = None
    client = TestClient(api_app)

    response = client.get("/api/stats", headers=auth(operator_token))

    assert response.status_code == 503


def test_pause_and_resume(api_client: TestClient, admin_token: str, api_app: Any) -> None:
    paused = api_client.post("/api/pipeline/pause", headers=auth(admin_token))
    assert paused.status_code == 200
    assert paused.json()["paused"] is True
    assert api_app.state.paused is True

    resumed = api_client.post("/api/pipeline/resume", headers=auth(admin_token))
    assert resumed.json()["paused"] is False
    assert api_app.state.paused is False


def test_an_operator_may_pause_the_pipeline(
    api_client: TestClient, operator_token: str
) -> None:
    """Pausing is shift-floor work, not administration."""
    assert (
        api_client.post("/api/pipeline/pause", headers=auth(operator_token)).status_code == 200
    )


def test_pausing_still_requires_authentication(api_client: TestClient) -> None:
    assert api_client.post("/api/pipeline/pause").status_code == 401


def test_relay_trigger_writes_manual_event(
    api_client: TestClient, admin_token: str, api_app: Any, log_repo: FakeLogRepository
) -> None:
    response = api_client.post("/api/relay/trigger", headers=auth(admin_token))

    assert response.status_code == 200
    body = response.json()
    assert body["triggered"] is True
    assert body["plate"] == "MANUAL"
    assert api_app.state.pipeline.relay.triggers == 1
    assert len(log_repo.written) == 1
    assert log_repo.written[0].plate == "MANUAL"
    assert log_repo.written[0].action == "granted"


def test_an_operator_may_open_the_gate(
    api_client: TestClient, operator_token: str, api_app: Any
) -> None:
    """Opening the barrier is the operator's job; that is what they are there for."""
    response = api_client.post("/api/relay/trigger", headers=auth(operator_token))
    assert response.status_code == 200
    assert api_app.state.pipeline.relay.triggers == 1


def test_opening_the_gate_still_requires_authentication(api_client: TestClient) -> None:
    assert api_client.post("/api/relay/trigger").status_code == 401


# ---------------------------------------------------------------------------
# Stream
# ---------------------------------------------------------------------------


def test_unknown_camera_is_404(api_client: TestClient, operator_token: str) -> None:
    response = api_client.get("/api/stream/garaj", headers=auth(operator_token))

    assert response.status_code == 404
    assert "garaj" in response.json()["error"]["detail"]


def test_stream_without_token_is_401(api_client: TestClient) -> None:
    assert api_client.get("/api/stream/entry").status_code == 401


class RoledPipeline(FakePipeline):
    """A pipeline that reports exactly which cameras have a capture worker.

    ``frame=None`` makes it a camera that is enabled but currently silent,
    which is the only shape a stream test can safely open: a pipeline that
    always yields a frame streams forever and hangs the test client.
    """

    def __init__(self, roles: list[str], frame: bytes | None = None) -> None:
        super().__init__()
        self._roles = list(roles)
        self.frame = frame
        self.frame_calls = 0

    def camera_roles(self) -> list[str]:
        return list(self._roles)

    def latest_frame_jpeg(self, camera: str, quality: int = 80) -> bytes | None:
        self.frame_calls += 1
        return self.frame


@pytest.fixture()
def brief_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink the idle window so a frameless stream ends inside a test."""
    from lpr.api import routes

    monkeypatch.setattr(routes, "_STREAM_IDLE_TIMEOUT_S", 0.3)
    monkeypatch.setattr(routes, "_STREAM_IDLE_POLL_S", 0.1)


def _pipeline_client(api_app: Any, pipeline: Any) -> TestClient:
    api_app.state.pipeline = pipeline
    return TestClient(api_app)


def test_a_disabled_camera_is_refused_immediately(
    api_app: Any, operator_token: str
) -> None:
    """The hang this fixes.

    A camera with no worker never produces a frame, so the generator used to
    hold the connection for the full idle timeout before giving up. A browser
    allows only a handful of connections per host, so that dead stream was
    paid for by every other request the page needed -- the slow load.
    """
    pipeline = RoledPipeline(["entry"])
    client = _pipeline_client(api_app, pipeline)

    response = client.get("/api/stream/exit", headers=auth(operator_token))

    assert response.status_code == 404
    assert "exit" in response.json()["error"]["detail"]
    assert pipeline.frame_calls == 0, "the refusal must precede the waiting loop"


def test_an_enabled_camera_still_streams(
    api_app: Any, operator_token: str, brief_stream: None
) -> None:
    """The check must not cost a working camera its stream."""
    client = _pipeline_client(api_app, RoledPipeline(["entry", "exit"]))

    response = client.get("/api/stream/entry", headers=auth(operator_token))

    assert response.status_code == 200
    assert "multipart/x-mixed-replace" in response.headers["content-type"]


def test_a_configured_but_disconnected_camera_is_not_refused(
    api_app: Any, operator_token: str, brief_stream: None
) -> None:
    """Disabled and disconnected are different, and only one is permanent.

    A camera that has a worker but is not currently connected may come back
    inside the stream's own idle window, so it keeps its stream. 404ing it
    would turn a passing cable fault into a blank tile until the next reload.
    """
    pipeline = RoledPipeline(["entry", "exit"])
    pipeline._connected = False
    client = _pipeline_client(api_app, pipeline)

    assert client.get("/api/stream/entry", headers=auth(operator_token)).status_code == 200


def test_a_silent_camera_is_polled_gently_not_thirty_times_a_second(
    api_app: Any, operator_token: str, brief_stream: None
) -> None:
    """Each poll is a thread-pool hop, and the pool serves every other request.

    Asking a dark camera at the full frame rate was ~30 hops a second
    returning nothing, which is what made one bad camera slow the whole
    dashboard. With a 0.3s window and a 0.1s idle poll this is a handful of
    calls; at the frame rate it would be an order of magnitude more.
    """
    pipeline = RoledPipeline(["entry"])
    client = _pipeline_client(api_app, pipeline)

    client.get("/api/stream/entry", headers=auth(operator_token))

    assert 1 <= pipeline.frame_calls <= 6, f"{pipeline.frame_calls} polls in a 0.3s window"


def test_a_pipeline_that_cannot_report_its_cameras_is_given_the_benefit(
    api_app: Any, operator_token: str, brief_stream: None
) -> None:
    """Unknowable must mean "allow", never "404".

    Guessing wrong in this direction breaks a working camera, which is a worse
    failure than the hang the check exists to prevent.
    """

    class Opaque(RoledPipeline):
        def __init__(self) -> None:
            super().__init__([])

        camera_roles = None  # type: ignore[assignment]

        def stats(self) -> Any:
            return types.SimpleNamespace(started_at=0.0, plates_read=0, grants=0, denials=0)

    assert client_status(api_app, Opaque(), operator_token) == 200


def client_status(api_app: Any, pipeline: Any, token: str, camera: str = "entry") -> int:
    return _pipeline_client(api_app, pipeline).get(
        f"/api/stream/{camera}", headers=auth(token)
    ).status_code


def test_the_camera_list_falls_back_to_stats_when_there_is_no_accessor() -> None:
    """``FakePipeline`` and older pipelines expose the roles only via stats()."""
    from lpr.api.routes import _streamable_roles

    assert _streamable_roles(FakePipeline()) == {"entry", "exit"}
    assert _streamable_roles(RoledPipeline(["entry"])) == {"entry"}


def test_an_unknown_role_is_still_404_before_the_camera_check(
    api_app: Any, operator_token: str
) -> None:
    """A bad path stays a 404 about the *name*, not about being disabled."""
    response = _pipeline_client(api_app, RoledPipeline(["entry"])).get(
        "/api/stream/garaj", headers=auth(operator_token)
    )

    assert response.status_code == 404
    assert "Bilinmeyen kamera" in response.json()["error"]["detail"]


def test_unknown_camera_source_is_404(api_client: TestClient, admin_token: str) -> None:
    response = api_client.post(
        "/api/cameras/garaj/source", json={"source": "0"}, headers=auth(admin_token)
    )

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics(api_client: TestClient, operator_token: str) -> None:
    response = api_client.get("/api/metrics", headers=auth(operator_token))
    assert response.status_code == 200
    body = response.json()

    assert body["running"] is True
    assert body["plates_read"] == 7
    assert body["grants"] == 5
    assert body["denials"] == 2
    assert body["uptime_s"] > 0
    # Frame counters are summed across cameras, not reported per camera.
    assert body["motion_skipped"] == 900
    assert body["frames_read"] == 100
    assert body["frames_dropped"] == 1
    assert body["cameras_total"] == 2
    assert body["cameras_connected"] == 1


def test_metrics_requires_auth(api_client: TestClient) -> None:
    assert api_client.get("/api/metrics").status_code == 401


def test_metrics_without_pipeline_is_503(api_app: Any, operator_token: str) -> None:
    api_app.state.pipeline = None
    client = TestClient(api_app)
    assert client.get("/api/metrics", headers=auth(operator_token)).status_code == 503


def test_metrics_agrees_with_stats(api_client: TestClient, operator_token: str) -> None:
    """The two endpoints read one snapshot; they must never disagree."""
    metrics = api_client.get("/api/metrics", headers=auth(operator_token)).json()
    stats = api_client.get("/api/stats", headers=auth(operator_token)).json()
    for key in ("running", "plates_read", "grants", "denials", "ocr_skipped"):
        assert metrics[key] == stats[key], key


# ---------------------------------------------------------------------------
# Licensing
# ---------------------------------------------------------------------------


def test_metrics_reports_the_licence(api_client: TestClient, operator_token: str) -> None:
    body = api_client.get("/api/metrics", headers=auth(operator_token)).json()
    assert body["license_valid"] is True
    assert body["license_reason"] == "ok"
    assert body["license_client"] == "Test Sitesi"
    assert body["license_expires_at"] == "2099-01-01T00:00:00+00:00"


def test_license_status_is_readable_by_any_user(
    api_client: TestClient, operator_token: str
) -> None:
    response = api_client.get("/api/license", headers=auth(operator_token))
    assert response.status_code == 200
    assert response.json()["valid"] is True


def test_license_status_requires_auth(api_client: TestClient) -> None:
    assert api_client.get("/api/license").status_code == 401


def test_an_expired_deployment_licence_no_longer_halts_the_pipeline(
    expired_app: Any
) -> None:
    """The installation-wide licence is reported, not enforced.

    Access control lives in the per-user model now. An expiry that stops a site
    recognising plates -- with an administrator standing there unable to
    restart it -- is an outage, not a commercial control.
    """
    assert expired_app.state.paused is False
    assert expired_app.state.pipeline.paused is False


def test_an_expired_deployment_licence_no_longer_blocks_the_gate(
    expired_app: Any
) -> None:
    client = TestClient(expired_app)
    response = client.post("/api/relay/trigger", headers=auth(create_token("admin", "admin")))
    assert response.status_code == 200
    assert expired_app.state.pipeline.relay.triggers == 1


def test_an_expired_deployment_licence_does_not_block_resume(expired_app: Any) -> None:
    """There is nothing to recover from: the licence never paused anything."""
    client = TestClient(expired_app)
    response = client.post("/api/pipeline/resume", headers=auth(create_token("admin", "admin")))
    assert response.status_code == 200
    assert expired_app.state.paused is False


def test_submitting_a_key_releases_the_halt(expired_app: Any) -> None:
    client = TestClient(expired_app)
    token = create_token("admin", "admin")

    response = client.post(
        "/api/license", headers=auth(token), json={"key": "yeni-lisans-anahtari-jwt"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["pipeline_halted"] is False
    assert expired_app.state.license_halted is False
    assert expired_app.state.paused is False
    assert expired_app.state.pipeline.paused is False
    assert expired_app.state.license_guard.activated == ["yeni-lisans-anahtari-jwt"]


def test_a_rejected_deployment_key_is_a_400_carrying_the_reason(
    expired_app: Any
) -> None:
    """The endpoint still validates keys; it just no longer gates anything."""
    client = TestClient(expired_app)
    response = client.post(
        "/api/license",
        json={"key": "gecersiz-anahtar"},  # what FakeLicenseGuard refuses
        headers=auth(create_token("admin", "admin")),
    )
    assert response.status_code == 400
    assert "geçersiz" in response.json()["error"]["detail"]


def test_pasted_key_whitespace_is_stripped(expired_app: Any) -> None:
    """Keys arrive wrapped across lines out of an e-mail."""
    client = TestClient(expired_app)
    client.post(
        "/api/license",
        headers=auth(create_token("admin", "admin")),
        json={"key": "  yeni-lisans\n-anahtari-jwt  "},
    )
    assert expired_app.state.license_guard.activated == ["yeni-lisans-anahtari-jwt"]


def test_submitting_a_key_requires_admin(
    api_client: TestClient, operator_token: str
) -> None:
    response = api_client.post(
        "/api/license", headers=auth(operator_token), json={"key": "a" * 40}
    )
    assert response.status_code == 403


def test_manual_pause_survives_a_licence_renewal(expired_app: Any) -> None:
    """An operator's pause must not be undone by the licence coming back."""
    client = TestClient(expired_app)
    token = create_token("admin", "admin")

    client.post("/api/pipeline/pause", headers=auth(token))
    client.post("/api/license", headers=auth(token), json={"key": "yeni-anahtar-jwt-degeri"})

    assert expired_app.state.license_halted is False
    assert expired_app.state.paused is True


# ---------------------------------------------------------------------------
# WebSocket event stream
# ---------------------------------------------------------------------------


def test_ws_events_served_at_the_api_path(api_client: TestClient, operator_token: str) -> None:
    with api_client.websocket_connect(f"/api/ws/events?token={operator_token}") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"
        assert hello["username"] == "operator"


def test_ws_events_still_served_at_the_legacy_path(
    api_client: TestClient, operator_token: str
) -> None:
    """An older GUI build must keep working against a new server."""
    with api_client.websocket_connect(f"/ws/events?token={operator_token}") as ws:
        assert ws.receive_json()["type"] == "hello"


def test_ws_rejects_a_bad_token(api_client: TestClient) -> None:
    with api_client.websocket_connect("/api/ws/events?token=nope") as ws:
        assert ws.receive_json()["type"] == "error"


def test_ws_pushes_camera_status_on_connect(
    api_client: TestClient, operator_token: str
) -> None:
    with api_client.websocket_connect(f"/api/ws/events?token={operator_token}") as ws:
        ws.receive_json()  # hello
        status = ws.receive_json()
        assert status["type"] == "camera_status"
        roles = {cam["role"]: cam for cam in status["cameras"]}
        assert roles["entry"]["connected"] is True
        assert roles["entry"]["motion_skipped"] == 900
        assert roles["exit"]["connected"] is False


def test_ws_forwards_decisions_and_telemetry_separately(
    api_client: TestClient, api_app: Any, operator_token: str
) -> None:
    pipeline = api_app.state.pipeline
    with api_client.websocket_connect(f"/api/ws/events?token={operator_token}") as ws:
        ws.receive_json()  # hello
        ws.receive_json()  # camera_status

        event = LprEvent(
            ts=utc_now_iso(), camera="entry", plate="34ABC123", action="granted"
        )
        for q in pipeline.subscribers:
            q.put(event)
        for q in pipeline.telemetry_subscribers:
            q.put({"kind": "read", "camera": "entry", "plate": "34ABC123"})

        seen: dict[str, Any] = {}
        for _ in range(6):
            message = ws.receive_json()
            if message["type"] in ("event", "telemetry"):
                seen[message["type"]] = message["data"]
            if len(seen) == 2:
                break

        assert seen["event"]["plate"] == "34ABC123"
        assert seen["event"]["action"] == "granted"
        assert seen["telemetry"]["kind"] == "read"


# ---------------------------------------------------------------------------
# System / OTA update
# ---------------------------------------------------------------------------


class FakeUpdater:
    """Stands in for ``lpr.updater.SystemUpdater`` at the HTTP boundary."""

    def __init__(self, enabled: bool = True, error: Exception | None = None) -> None:
        self.enabled = enabled
        self.error = error
        self.starts = 0
        #: One entry per accepted start, recording the ``force`` it was given.
        self.forced: list[bool] = []
        self._status = types.SimpleNamespace(
            to_dict=lambda: {
                "state": "idle",
                "step": None,
                "detail": "",
                "running": False,
                "started_at": None,
                "finished_at": None,
                "commit_before": None,
                "commit_after": None,
                "forced": False,
                "log": [],
            }
        )

    def version(self) -> Any:
        return types.SimpleNamespace(
            to_dict=lambda: {
                "version": "v1.0.0-2-g6845136",
                "commit": "6845136fc5071a3e0bdd11d1",
                "short_commit": "6845136",
                "branch": "main",
                "dirty": False,
            }
        )

    @property
    def status(self) -> Any:
        return self._status

    def start(self, force: bool = False) -> Any:
        self.starts += 1
        if self.error is not None:
            raise self.error
        self.forced.append(bool(force))
        self._status = types.SimpleNamespace(
            to_dict=lambda: {
                "state": "running",
                "step": "pull",
                "detail": (
                    "Zorla yeniden derleme başlatıldı."
                    if force
                    else "Güncelleme başlatıldı."
                ),
                "running": True,
                "started_at": 1.0,
                "finished_at": None,
                "commit_before": "aaa",
                "commit_after": None,
                "forced": bool(force),
                "log": [],
            }
        )
        return self._status


@pytest.fixture()
def updater() -> FakeUpdater:
    return FakeUpdater()


@pytest.fixture()
def update_client(api_app: Any, updater: FakeUpdater) -> TestClient:
    api_app.dependency_overrides[deps.get_system_updater] = lambda: updater
    # deps.get_system_updater is also called directly (not as a dependency) by
    # the handlers, so the app-state cache has to hold the fake too.
    api_app.state.system_updater = updater
    return TestClient(api_app)


def test_version_requires_authentication(update_client: TestClient) -> None:
    assert update_client.get("/api/system/version").status_code == 401


def test_version_is_readable_by_an_operator(
    update_client: TestClient, operator_token: str
) -> None:
    """An operator who can see the running version can report it on the phone."""
    response = update_client.get("/api/system/version", headers=auth(operator_token))
    assert response.status_code == 200
    body = response.json()
    # A readable tag for the eye, the raw hash for identity -- both surfaced.
    assert body["version"] == "v1.0.0-2-g6845136"
    assert body["short_commit"] == "6845136"
    assert body["commit"] == "6845136fc5071a3e0bdd11d1"
    assert body["branch"] == "main"
    assert body["update_enabled"] is True


def test_update_requires_authentication(update_client: TestClient) -> None:
    assert update_client.post("/api/system/update").status_code == 401


def test_an_operator_may_trigger_an_update(
    update_client: TestClient, operator_token: str, updater: FakeUpdater
) -> None:
    """Deliberate policy: operators run OTA updates on this deployment.

    Worth knowing what that grants -- the updater runs `git pull` and a
    `docker compose` rebuild, so this is code execution on the host for anyone
    holding an operator session.
    """
    response = update_client.post("/api/system/update", headers=auth(operator_token))
    assert response.status_code == 202
    assert updater.starts == 1


def test_updating_still_requires_authentication(
    update_client: TestClient, updater: FakeUpdater
) -> None:
    assert update_client.post("/api/system/update").status_code == 401
    assert updater.starts == 0


def test_an_operator_may_read_the_update_status(
    update_client: TestClient, operator_token: str
) -> None:
    assert (
        update_client.get("/api/system/update", headers=auth(operator_token)).status_code == 200
    )


def test_an_admin_can_start_an_update(
    update_client: TestClient, admin_token: str, updater: FakeUpdater
) -> None:
    response = update_client.post("/api/system/update", headers=auth(admin_token))
    assert response.status_code == 202, "202: the work outlives the request"
    body = response.json()
    assert body["accepted"] is True
    assert body["state"] == "running"
    assert updater.starts == 1


def test_a_disabled_updater_answers_503(
    api_app: Any, admin_token: str
) -> None:
    disabled = FakeUpdater(enabled=False, error=RuntimeError("Sistem güncellemesi devre dışı."))
    api_app.state.system_updater = disabled
    api_app.dependency_overrides[deps.get_system_updater] = lambda: disabled
    response = TestClient(api_app).post("/api/system/update", headers=auth(admin_token))
    assert response.status_code == 503


def test_a_concurrent_update_answers_409(api_app: Any, admin_token: str) -> None:
    busy = FakeUpdater(error=RuntimeError("Zaten devam eden bir güncelleme var."))
    api_app.state.system_updater = busy
    api_app.dependency_overrides[deps.get_system_updater] = lambda: busy
    response = TestClient(api_app).post("/api/system/update", headers=auth(admin_token))
    assert response.status_code == 409


def test_update_status_is_readable_by_an_admin(
    update_client: TestClient, admin_token: str
) -> None:
    response = update_client.get("/api/system/update", headers=auth(admin_token))
    assert response.status_code == 200
    assert response.json()["state"] == "idle"


def test_the_update_endpoint_accepts_no_caller_supplied_target(
    update_client: TestClient, admin_token: str, updater: FakeUpdater
) -> None:
    """A body naming another repo must not change what gets pulled.

    The body model holds ``force`` and nothing else, so a caller-supplied
    remote is dropped on the way in rather than reaching a command line. This
    pins that shape -- the request is accepted, and the update it starts is
    the ordinary configured one.
    """
    response = update_client.post(
        "/api/system/update",
        headers=auth(admin_token),
        json={"remote": "https://evil.example/repo", "branch": "payload"},
    )
    assert response.status_code == 202
    assert updater.starts == 1
    assert updater.forced == [False], "an unknown key must not turn into a force"


def test_an_update_without_a_body_is_not_forced(
    update_client: TestClient, admin_token: str, updater: FakeUpdater
) -> None:
    """The plain button posts nothing at all; that must stay the safe path."""
    response = update_client.post("/api/system/update", headers=auth(admin_token))
    assert response.status_code == 202
    assert updater.forced == [False]
    assert response.json()["forced"] is False


def test_an_admin_can_ask_for_a_forced_rebuild(
    update_client: TestClient, admin_token: str, updater: FakeUpdater
) -> None:
    """``force: true`` has to reach the updater, or the button does nothing."""
    response = update_client.post(
        "/api/system/update",
        headers=auth(admin_token),
        json={"force": True},
    )
    assert response.status_code == 202
    assert updater.forced == [True]

    body = response.json()
    assert body["accepted"] is True
    assert body["forced"] is True, "the client needs to know not to await a new commit"


def test_a_forced_rebuild_is_refused_while_one_is_running(
    api_app: Any, admin_token: str
) -> None:
    """Forcing must not become a way around the single-flight guard."""
    busy = FakeUpdater(error=RuntimeError("Zaten devam eden bir güncelleme var."))
    api_app.state.system_updater = busy
    api_app.dependency_overrides[deps.get_system_updater] = lambda: busy
    response = TestClient(api_app).post(
        "/api/system/update",
        headers=auth(admin_token),
        json={"force": True},
    )
    assert response.status_code == 409


def test_a_forced_rebuild_still_needs_the_feature_enabled(
    api_app: Any, admin_token: str
) -> None:
    """``force`` overrides the no-op check, never the deployment's own switch."""
    disabled = FakeUpdater(enabled=False, error=RuntimeError("Sistem güncellemesi devre dışı."))
    api_app.state.system_updater = disabled
    api_app.dependency_overrides[deps.get_system_updater] = lambda: disabled
    response = TestClient(api_app).post(
        "/api/system/update",
        headers=auth(admin_token),
        json={"force": True},
    )
    assert response.status_code == 503


def test_a_forced_rebuild_still_requires_authentication(
    update_client: TestClient, updater: FakeUpdater
) -> None:
    assert update_client.post("/api/system/update", json={"force": True}).status_code == 401
    assert updater.starts == 0


class FakeSystemEventRepo:
    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows = rows or []
        self.queries: list[tuple[int, str | None]] = []

    def recent(self, limit: int = 50, source: str | None = None) -> list[dict[str, Any]]:
        self.queries.append((limit, source))
        rows = [r for r in self.rows if source is None or r["source"] == source]
        return rows[:limit]


@pytest.fixture()
def events_repo() -> FakeSystemEventRepo:
    return FakeSystemEventRepo(
        [
            {
                "id": 2,
                "ts": "2026-08-27T03:00:04+00:00",
                "source": "ota",
                "level": "warning",
                "message": "2 yeni sürüm bulundu. Otomatik güncelleme başlatılıyor.",
                "detail": None,
            },
            {
                "id": 1,
                "ts": "2026-08-26T03:00:02+00:00",
                "source": "ota",
                "level": "info",
                "message": "Gecelik denetim: sistem güncel.",
                "detail": "Sistem güncel.",
            },
        ]
    )


@pytest.fixture()
def events_client(api_app: Any, events_repo: FakeSystemEventRepo) -> TestClient:
    api_app.state.system_event_repository = events_repo
    api_app.dependency_overrides[deps.get_system_event_repository] = lambda: events_repo
    return TestClient(api_app)


def test_system_events_require_authentication(
    events_client: TestClient, operator_token: str
) -> None:
    """Readable by an operator, who is the one who finds the gate rebuilt."""
    assert events_client.get("/api/system/events").status_code == 401
    assert (
        events_client.get("/api/system/events", headers=auth(operator_token)).status_code == 200
    )


def test_an_admin_reads_the_audit_trail_newest_first(
    events_client: TestClient, admin_token: str
) -> None:
    response = events_client.get("/api/system/events", headers=auth(admin_token))
    assert response.status_code == 200
    body = response.json()
    assert [row["id"] for row in body] == [2, 1]
    assert body[0]["level"] == "warning"


def test_the_audit_trail_can_be_filtered_and_limited(
    events_client: TestClient, admin_token: str, events_repo: FakeSystemEventRepo
) -> None:
    response = events_client.get(
        "/api/system/events?limit=1&source=ota", headers=auth(admin_token)
    )
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert events_repo.queries[-1] == (1, "ota")


def test_the_audit_trail_rejects_an_absurd_limit(
    events_client: TestClient, admin_token: str
) -> None:
    assert (
        events_client.get("/api/system/events?limit=99999", headers=auth(admin_token)).status_code
        == 422
    )


# ---------------------------------------------------------------------------
# CSV import / export
# ---------------------------------------------------------------------------


class ImportablePlateRepository(FakePlateRepository):
    """Adds the resident columns the CSV importer writes."""

    def __init__(self) -> None:
        super().__init__()
        self.details: dict[str, dict[str, Any]] = {}

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
        existing = plate in self.details
        if existing and not overwrite:
            return "skipped"
        self.details[plate] = {
            "plate": plate,
            "owner": owner,
            "apartment": apartment,
            "note": note,
            "username": username,
            "expires_at": expires_at,
            "blocked": int(blocked),
            "added_at": "2026-08-27T00:00:00+00:00",
        }
        self._plates[plate] = note
        return "updated" if existing else "added"

    def get(self, plate: str) -> dict[str, Any] | None:
        return self.details.get(plate)

    def update(self, plate: str, **fields: Any) -> bool:
        """Partial write, mirroring PlateRepository.update: only what is sent."""
        row = self.details.get(plate)
        if row is None:
            return False
        allowed = ("owner", "apartment", "note", "expires_at", "blocked")
        changes = {name: fields[name] for name in allowed if name in fields}
        if not changes:
            return False
        if "blocked" in changes:
            changes["blocked"] = int(bool(changes["blocked"]))
        row.update(changes)
        return True

    def all_detailed(self) -> list[dict[str, Any]]:
        return [self.details[key] for key in sorted(self.details)]


@pytest.fixture()
def csv_repo() -> ImportablePlateRepository:
    return ImportablePlateRepository()


@pytest.fixture()
def csv_client(api_app: Any, csv_repo: ImportablePlateRepository) -> TestClient:
    api_app.dependency_overrides[deps.get_plate_repository] = lambda: csv_repo
    return TestClient(api_app)


def upload(client: TestClient, token: str, body: bytes, query: str = "") -> Any:
    return client.post(
        f"/api/plates/import{query}",
        headers=auth(token),
        files={"file": ("residents.csv", body, "text/csv")},
    )


def test_an_operator_may_import_plates(
    csv_client: TestClient, operator_token: str
) -> None:
    assert upload(csv_client, operator_token, b"plate\n34ABC123\n").status_code == 200


def test_importing_still_requires_authentication(csv_client: TestClient) -> None:
    response = csv_client.post(
        "/api/plates/import", files={"file": ("r.csv", b"plate\n34ABC123\n", "text/csv")}
    )
    assert response.status_code == 401


def test_plate_import_reports_counts_per_row(
    csv_client: TestClient, admin_token: str, csv_repo: ImportablePlateRepository
) -> None:
    body = "plaka;sahibi;daire\r\n34ABC123;Ali Şen;A-12\r\n???;Bozuk;\r\n".encode("utf-8-sig")
    response = upload(csv_client, admin_token, body)

    assert response.status_code == 200
    report = response.json()
    assert report["added"] == 1
    assert report["invalid"] == 1
    assert report["errors"], "a rejected row must say which one it was"
    assert csv_repo.details["34ABC123"]["owner"] == "Ali Şen"


def test_plate_import_skips_existing_by_default(
    csv_client: TestClient, admin_token: str
) -> None:
    body = b"plate,owner\r\n34ABC123,Ali\r\n"
    assert upload(csv_client, admin_token, body).json()["added"] == 1

    again = upload(csv_client, admin_token, b"plate,owner\r\n34ABC123,Baska\r\n").json()
    assert again["skipped"] == 1
    assert again["updated"] == 0


def test_plate_import_overwrites_when_asked(csv_client: TestClient, admin_token: str) -> None:
    upload(csv_client, admin_token, b"plate,owner\r\n34ABC123,Ali\r\n")
    again = upload(
        csv_client, admin_token, b"plate,owner\r\n34ABC123,Yeni\r\n", "?overwrite=true"
    ).json()
    assert again["updated"] == 1


def test_plate_import_rejects_a_file_without_a_plate_column(
    csv_client: TestClient, admin_token: str
) -> None:
    report = upload(csv_client, admin_token, b"owner,apartment\r\nAli,A-12\r\n").json()
    assert report["added"] == 0
    assert report["errors"]


def test_an_operator_may_export_plates(
    csv_client: TestClient, operator_token: str
) -> None:
    assert csv_client.get("/api/plates/export", headers=auth(operator_token)).status_code == 200


def test_plate_export_returns_a_downloadable_csv(
    csv_client: TestClient, admin_token: str
) -> None:
    upload(csv_client, admin_token, "plate,owner\r\n34ABC123,Ali Şen\r\n".encode())
    response = csv_client.get("/api/plates/export", headers=auth(admin_token))

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    assert ".csv" in response.headers["content-disposition"]
    body = response.content.decode("utf-8-sig")
    assert "34ABC123" in body and "Ali Şen" in body


def test_event_export_requires_authentication(api_client: TestClient) -> None:
    assert api_client.get("/api/events/export").status_code == 401


def test_event_export_is_readable_by_an_operator(
    api_client: TestClient, operator_token: str, log_repo: FakeLogRepository
) -> None:
    """An operator on the gate is exactly who needs the shift's history."""
    log_repo.events.append(
        LprEvent(ts=utc_now_iso(), camera="entry", plate="34ABC123", action="denied", id=1)
    )
    response = api_client.get("/api/events/export", headers=auth(operator_token))

    assert response.status_code == 200
    body = response.content.decode("utf-8-sig")
    assert "id,ts,camera,plate,action,confidence" in body
    assert "34ABC123" in body


def test_event_export_passes_the_filters_through(
    api_client: TestClient, operator_token: str, log_repo: FakeLogRepository
) -> None:
    """The download must match what the operator is looking at on screen."""
    api_client.get(
        "/api/events/export?camera=entry&plate=34+abc+123&limit=5",
        headers=auth(operator_token),
    )
    assert log_repo.last_query is not None, "the export must actually query"
    assert log_repo.last_query["camera"] == "entry"
    assert log_repo.last_query["plate"] == "34ABC123", "the plate filter must be normalised"


def test_event_export_rejects_an_absurd_limit(
    api_client: TestClient, operator_token: str
) -> None:
    assert (
        api_client.get("/api/events/export?limit=999999", headers=auth(operator_token)).status_code
        == 422
    )


# ---------------------------------------------------------------------------
# Plate management: resident records, status and the block toggle
# ---------------------------------------------------------------------------


@pytest.fixture()
def detail_client(api_app: Any, csv_repo: ImportablePlateRepository) -> TestClient:
    """A client whose plate repository carries the schema-v4 columns."""
    api_app.dependency_overrides[deps.get_plate_repository] = lambda: csv_repo
    return TestClient(api_app)


def test_adding_a_plate_stores_the_resident_detail(
    detail_client: TestClient, admin_token: str, csv_repo: ImportablePlateRepository
) -> None:
    response = detail_client.post(
        "/api/plates",
        headers=auth(admin_token),
        json={
            "plate": " 34 abc 123 ",
            "owner": "Ahmet Yılmaz",
            "apartment": "B Blok D:12",
            "note": "Müdür aracı",
        },
    )
    assert response.status_code == 201
    stored = csv_repo.details["34ABC123"]
    assert stored["owner"] == "Ahmet Yılmaz"
    assert stored["apartment"] == "B Blok D:12"


def test_a_bare_date_is_widened_to_the_end_of_that_day(
    detail_client: TestClient, admin_token: str, csv_repo: ImportablePlateRepository
) -> None:
    """A date picker sends 2027-01-01; stored as midnight it expires a day early.

    The resident's sticker says they are valid until the 1st, so being refused
    on the 1st is the bug this guards.
    """
    detail_client.post(
        "/api/plates",
        headers=auth(admin_token),
        json={"plate": "34ABC123", "expires_at": "2027-01-01"},
    )
    assert csv_repo.details["34ABC123"]["expires_at"] == "2027-01-01T23:59:59+00:00"


def test_an_explicit_timestamp_is_left_alone(
    detail_client: TestClient, admin_token: str, csv_repo: ImportablePlateRepository
) -> None:
    detail_client.post(
        "/api/plates",
        headers=auth(admin_token),
        json={"plate": "34ABC123", "expires_at": "2027-01-01T08:00:00+00:00"},
    )
    assert csv_repo.details["34ABC123"]["expires_at"] == "2027-01-01T08:00:00+00:00"


def test_the_list_carries_both_shapes(
    detail_client: TestClient, admin_token: str, operator_token: str
) -> None:
    """`plates` for the desktop client, `records` for the management screen."""
    detail_client.post(
        "/api/plates", headers=auth(admin_token), json={"plate": "34ABC123", "owner": "Ali"}
    )
    body = detail_client.get("/api/plates", headers=auth(operator_token)).json()

    assert body["plates"] == ["34ABC123"]
    assert body["records"][0]["owner"] == "Ali"
    assert body["records"][0]["status"] == "active"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({}, "active"),
        ({"blocked": True}, "blocked"),
        ({"expires_at": "2020-01-01"}, "expired"),
        ({"expires_at": "2099-01-01"}, "guest"),
        ({"blocked": True, "expires_at": "2020-01-01"}, "blocked"),
    ],
)
def test_status_is_derived_for_the_badge(
    detail_client: TestClient, admin_token: str, payload: dict[str, Any], expected: str
) -> None:
    """Derived server-side: a browser with a wrong clock must not show a badge
    that contradicts what the gate will do. Blocked outranks expired."""
    detail_client.post(
        "/api/plates", headers=auth(admin_token), json={"plate": "34ABC123", **payload}
    )
    records = detail_client.get("/api/plates", headers=auth(admin_token)).json()["records"]
    assert records[0]["status"] == expected


def test_the_block_toggle_preserves_the_other_fields(
    detail_client: TestClient, admin_token: str, csv_repo: ImportablePlateRepository
) -> None:
    """The whole reason PATCH is partial: a toggle must not blank the resident."""
    detail_client.post(
        "/api/plates",
        headers=auth(admin_token),
        json={"plate": "34ABC123", "owner": "Ali", "apartment": "B-12", "note": "Kiracı"},
    )
    response = detail_client.patch(
        "/api/plates/34ABC123", headers=auth(admin_token), json={"blocked": True}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["blocked"] is True
    assert body["status"] == "blocked"
    assert body["owner"] == "Ali"
    assert body["apartment"] == "B-12"
    assert body["note"] == "Kiracı"


def test_unblocking_restores_the_active_status(
    detail_client: TestClient, admin_token: str
) -> None:
    detail_client.post(
        "/api/plates", headers=auth(admin_token), json={"plate": "34ABC123", "blocked": True}
    )
    body = detail_client.patch(
        "/api/plates/34ABC123", headers=auth(admin_token), json={"blocked": False}
    ).json()
    assert body["status"] == "active"


def test_an_operator_may_block_a_plate(
    detail_client: TestClient, admin_token: str, operator_token: str
) -> None:
    """Blocking a plate is exactly what an operator at the gate needs to do."""
    detail_client.post("/api/plates", headers=auth(admin_token), json={"plate": "34ABC123"})
    response = detail_client.patch(
        "/api/plates/34ABC123", headers=auth(operator_token), json={"blocked": True}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "blocked"


def test_patching_an_unknown_plate_is_a_404(
    detail_client: TestClient, admin_token: str
) -> None:
    response = detail_client.patch(
        "/api/plates/99ZZZ99", headers=auth(admin_token), json={"blocked": True}
    )
    assert response.status_code == 404


def test_an_empty_patch_is_rejected(detail_client: TestClient, admin_token: str) -> None:
    """A no-op write should say so rather than report success."""
    detail_client.post("/api/plates", headers=auth(admin_token), json={"plate": "34ABC123"})
    response = detail_client.patch(
        "/api/plates/34ABC123", headers=auth(admin_token), json={}
    )
    assert response.status_code == 400


def test_a_patch_rejects_unknown_fields(detail_client: TestClient, admin_token: str) -> None:
    """`extra="forbid"` keeps a typo'd key from silently doing nothing."""
    response = detail_client.patch(
        "/api/plates/34ABC123", headers=auth(admin_token), json={"blokked": True}
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# User management and role-scoped sessions
# ---------------------------------------------------------------------------


class ManagedUserRepository:
    """A user repository with the schema-v5 surface the routes use.

    Self-contained rather than subclassing ``FakeUserRepository``: that one
    stores ``(password, role)`` tuples, and the routes under test want rows
    carrying ``created_at`` and ``token_ttl_min`` too.
    """

    def __init__(self) -> None:
        self.rows: dict[str, dict[str, Any]] = {}
        self.passwords: dict[str, str] = {}

    def is_first_user(self) -> bool:
        return not self.rows

    def exists(self, username: str) -> bool:
        return (username or "").strip() in self.rows

    def verify(self, username: str, password: str) -> bool:
        return self.passwords.get((username or "").strip()) == password

    def register(
        self,
        username: str,
        password: str,
        role: str = "operator",
        token_ttl_min: int | None = None,
    ) -> bool:
        name = (username or "").strip()
        if not name or name in self.rows:
            return False
        from lpr.user_license import STATUS_PENDING, requires_license

        self.rows[name] = {
            "username": name,
            "role": role,
            "created_at": "2026-08-27T00:00:00+00:00",
            "token_ttl_min": token_ttl_min,
            # Mirrors the real repository: an operator starts waiting for a key.
            "license_status": STATUS_PENDING if requires_license(role) else None,
        }
        self.passwords[name] = password
        return True

    def get(self, username: str) -> dict[str, Any] | None:
        return self.rows.get((username or "").strip())

    def list_users(self) -> list[dict[str, Any]]:
        return [self.rows[key] for key in sorted(self.rows)]

    def count_by_role(self, role: str) -> int:
        return sum(1 for row in self.rows.values() if row["role"] == role)

    def delete(self, username: str) -> bool:
        name = (username or "").strip()
        self.passwords.pop(name, None)
        return self.rows.pop(name, None) is not None

    def set_license(
        self,
        username: str,
        key: str | None,
        expires_at: str | None,
        status: str,
        duration_days: int | None = None,
        activated_at: str | None = None,
    ) -> bool:
        row = self.rows.get((username or "").strip())
        if row is None:
            return False
        row["license_key"] = key
        row["license_expires_at"] = expires_at
        row["license_status"] = status
        row["license_duration_days"] = duration_days
        row["license_activated_at"] = activated_at
        return True


@pytest.fixture()
def users_repo() -> ManagedUserRepository:
    repo = ManagedUserRepository()
    repo.register("mudur", "parola1234", "admin")
    repo.register("bekci", "parola1234", "operator")
    return repo


@pytest.fixture()
def users_client(api_app: Any, users_repo: ManagedUserRepository) -> TestClient:
    api_app.dependency_overrides[deps.get_user_repository] = lambda: users_repo
    return TestClient(api_app)


def admin_auth() -> dict[str, str]:
    return auth(create_token("mudur", "admin"))


def operator_auth() -> dict[str, str]:
    """A token for the operator the users fixture actually defines.

    The generic ``operator_token`` names an account those fixtures do not
    create, and the revocation check rejects a token whose account is gone --
    correctly, but that is a 401 and not the 403 these tests are about.
    """
    return auth(create_token("bekci", "operator"))


# -- listing ----------------------------------------------------------------


def test_listing_users_requires_admin(users_client: TestClient) -> None:
    assert users_client.get("/api/users").status_code == 401
    assert users_client.get("/api/users", headers=operator_auth()).status_code == 403


def test_listing_users_never_returns_password_material(
    users_client: TestClient
) -> None:
    """A leaked hash is an offline cracking target; it must not leave the box."""
    response = users_client.get("/api/users", headers=admin_auth())
    assert response.status_code == 200
    body = response.text.lower()
    assert "password" not in body and "hash" not in body


def test_listing_users_reports_the_session_length(users_client: TestClient) -> None:
    rows = users_client.get("/api/users", headers=admin_auth()).json()
    assert {row["username"] for row in rows} == {"mudur", "bekci"}
    assert all("token_ttl_min" in row for row in rows)


# -- creation ---------------------------------------------------------------


def test_creating_a_user_requires_admin(users_client: TestClient) -> None:
    payload = {"username": "yeni", "password": "parola1234"}
    assert users_client.post("/api/users", json=payload).status_code == 401
    assert (
        users_client.post("/api/users", json=payload, headers=operator_auth()).status_code == 403
    )


def test_an_admin_creates_an_operator(
    users_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    response = users_client.post(
        "/api/users",
        headers=admin_auth(),
        json={"username": "yeni", "password": "parola1234", "role": "operator"},
    )
    assert response.status_code == 201
    assert response.json()["role"] == "operator"
    assert users_repo.rows["yeni"]["role"] == "operator"


def test_a_per_account_session_length_is_stored(
    users_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    users_client.post(
        "/api/users",
        headers=admin_auth(),
        json={"username": "gece", "password": "parola1234", "token_ttl_min": 60},
    )
    assert users_repo.rows["gece"]["token_ttl_min"] == 60


def test_a_duplicate_username_is_a_conflict(users_client: TestClient) -> None:
    response = users_client.post(
        "/api/users", headers=admin_auth(), json={"username": "bekci", "password": "parola1234"}
    )
    assert response.status_code == 409


def test_a_short_password_is_rejected(users_client: TestClient) -> None:
    """8 characters is the floor; the form says so and the API enforces it."""
    response = users_client.post(
        "/api/users", headers=admin_auth(), json={"username": "yeni", "password": "kisa"}
    )
    assert response.status_code == 422


def test_an_unknown_role_is_rejected(users_client: TestClient) -> None:
    response = users_client.post(
        "/api/users",
        headers=admin_auth(),
        json={"username": "yeni", "password": "parola1234", "role": "superuser"},
    )
    assert response.status_code == 422


# -- deletion ---------------------------------------------------------------


def test_deleting_a_user_requires_admin(users_client: TestClient) -> None:
    assert users_client.delete("/api/users/bekci").status_code == 401
    assert users_client.delete("/api/users/bekci", headers=operator_auth()).status_code == 403


def test_an_admin_deletes_an_operator(
    users_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    response = users_client.delete("/api/users/bekci", headers=admin_auth())
    assert response.status_code == 200
    assert "bekci" not in users_repo.rows


def test_deleting_an_unknown_user_is_a_404(users_client: TestClient) -> None:
    assert users_client.delete("/api/users/yok", headers=admin_auth()).status_code == 404


def test_an_admin_cannot_delete_their_own_account(
    users_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    """The request would succeed and then invalidate the token that made it."""
    users_repo.register("mudur2", "parola1234", "admin")  # so the last-admin rule does not apply
    response = users_client.delete("/api/users/mudur", headers=admin_auth())
    assert response.status_code == 400
    assert "mudur" in users_repo.rows


def test_the_last_admin_cannot_be_deleted(
    users_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    """There is no recovery: with no admin left, nobody can create one."""
    response = users_client.delete("/api/users/mudur", headers=admin_auth())
    assert response.status_code == 409
    assert "yönetici" in response.json()["error"]["detail"].lower()
    assert users_repo.count_by_role("admin") == 1


def test_the_last_admin_rule_is_checked_before_the_self_rule(
    users_client: TestClient
) -> None:
    """When both apply, the last-admin message is the one that says what to do.

    "Ask another admin" is unhelpful on an installation with no other admin.
    """
    response = users_client.delete("/api/users/mudur", headers=admin_auth())
    assert response.status_code == 409, "409 is the last-admin refusal, 400 the self one"


def test_an_admin_can_be_deleted_while_another_remains(
    users_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    users_repo.register("mudur2", "parola1234", "admin")
    assert users_client.delete("/api/users/mudur2", headers=admin_auth()).status_code == 200


# -- session length ---------------------------------------------------------


def test_an_admin_login_issues_a_long_session(
    users_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    response = users_client.post(
        "/api/auth/login", json={"username": "mudur", "password": "parola1234"}
    )
    assert response.status_code == 200
    assert response.json()["expires_in"] >= 300 * 86400, "an admin should stay signed in"


def test_an_operator_login_issues_a_shift_session(
    users_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    response = users_client.post(
        "/api/auth/login", json={"username": "bekci", "password": "parola1234"}
    )
    assert response.json()["expires_in"] == 8 * 3600


def test_a_per_account_override_beats_the_role_policy(
    users_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    users_repo.register("gece", "parola1234", "operator", token_ttl_min=60)
    response = users_client.post(
        "/api/auth/login", json={"username": "gece", "password": "parola1234"}
    )
    assert response.json()["expires_in"] == 3600


# -- bootstrap signalling ---------------------------------------------------


def test_health_reports_setup_required_on_an_empty_installation(
    api_app: Any
) -> None:
    """The login screen reads this to decide whether to offer bootstrap."""
    empty = ManagedUserRepository()
    api_app.dependency_overrides[deps.get_user_repository] = lambda: empty
    assert TestClient(api_app).get("/health").json()["setup_required"] is True


def test_health_stops_advertising_setup_once_an_account_exists(
    users_client: TestClient
) -> None:
    assert users_client.get("/health").json()["setup_required"] is False


# ---------------------------------------------------------------------------
# Per-operator licence enforcement
# ---------------------------------------------------------------------------


@pytest.fixture()
def licensing(tmp_settings: Any, users_repo: ManagedUserRepository) -> Any:
    """Licence enforcement switched on, with an admin and an operator."""
    tmp_settings.license_secret = "s" * 40
    return tmp_settings


@pytest.fixture()
def license_client(
    api_app: Any, users_repo: ManagedUserRepository, licensing: Any
) -> TestClient:
    api_app.dependency_overrides[deps.get_user_repository] = lambda: users_repo
    api_app.state.user_repository = users_repo
    return TestClient(api_app)


def test_an_unlicensed_operator_is_blocked_with_403(
    license_client: TestClient
) -> None:
    """403, with the detail carrying the reason.

    A lapsed licence and an ordinary role refusal are both "you may not", and
    the dashboard tells them apart by this exact string -- which is why it is
    asserted here and not just the status.
    """
    response = license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    )
    assert response.status_code == 403
    assert response.json()["error"]["detail"] == LICENSE_LAPSED_DETAIL


def test_an_admin_is_never_blocked(license_client: TestClient) -> None:
    """Exempt by construction: the account that issues keys cannot need one."""
    response = license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=admin_auth()
    )
    assert response.status_code == 201


def test_a_licensed_operator_passes(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    from lpr.user_license import activate, issue_key

    key = issue_key("bekci", 30, licensing)
    state = activate(key, "bekci", licensing)
    users_repo.set_license(
        "bekci", key, state.expires_at, state.status,
        duration_days=state.duration_days, activated_at=state.activated_at,
    )

    response = license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    )
    assert response.status_code == 201


def test_a_revoked_licence_blocks_immediately(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    """Revocation is a database fact; the signed key cannot be un-signed."""
    from lpr.user_license import STATUS_REVOKED, activate, issue_key

    key = issue_key("bekci", 30, licensing)
    state = activate(key, "bekci", licensing)
    users_repo.set_license(
        "bekci", key, state.expires_at, state.status,
        duration_days=state.duration_days, activated_at=state.activated_at,
    )
    assert license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    ).status_code == 201

    users_repo.set_license("bekci", key, state.expires_at, STATUS_REVOKED)
    assert license_client.post(
        "/api/plates", json={"plate": "06MNP99"}, headers=operator_auth()
    ).status_code == 403


def test_reading_your_own_licence_is_never_gated(license_client: TestClient) -> None:
    """An operator whose licence lapsed is exactly who needs to read this."""
    response = license_client.get("/api/license/me", headers=operator_auth())
    assert response.status_code == 200
    assert response.json()["status"] == "pending_activation"


def test_an_admin_reads_an_unlimited_licence(license_client: TestClient) -> None:
    body = license_client.get("/api/license/me", headers=admin_auth()).json()
    assert body["status"] == "unlimited"
    assert body["valid"] is True
    assert body["unlimited"] is True


def test_activating_a_key_is_never_gated(
    license_client: TestClient, licensing: Any
) -> None:
    """It is the way *out* of being unlicensed, so it cannot require a licence."""
    from lpr.user_license import issue_key

    response = license_client.post(
        "/api/license/activate",
        json={"key": issue_key("bekci", 30, licensing)},
        headers=operator_auth(),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "active"
    assert body["activated_at"], "activation is what starts the countdown"
    assert body["expires_at"]


def test_activating_someone_elses_key_is_refused(
    license_client: TestClient, licensing: Any
) -> None:
    from lpr.user_license import issue_key

    response = license_client.post(
        "/api/license/activate",
        json={"key": issue_key("baskasi", 30, licensing)},
        headers=operator_auth(),
    )
    assert response.status_code == 400


def test_activation_unblocks_the_operator(
    license_client: TestClient, licensing: Any
) -> None:
    from lpr.user_license import issue_key

    assert license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    ).status_code == 403

    license_client.post(
        "/api/license/activate",
        json={"key": issue_key("bekci", 30, licensing)},
        headers=operator_auth(),
    )

    assert license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    ).status_code == 201


def _expire(users_repo: ManagedUserRepository, licensing: Any, username: str = "bekci") -> None:
    """Give ``username`` a licence that ran out yesterday."""
    from datetime import datetime, timedelta, timezone

    from lpr.user_license import STATUS_ACTIVE

    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    users_repo.set_license(
        username, "eski-anahtar", yesterday, STATUS_ACTIVE, duration_days=30
    )


# -- the application door ----------------------------------------------------


def test_an_expired_operator_cannot_log_in(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    """Refused at the door, so the account never holds a token at all."""
    _expire(users_repo, licensing)

    response = license_client.post(
        "/api/auth/login", json={"username": "bekci", "password": "parola1234"}
    )
    assert response.status_code == 403
    assert response.json()["error"]["detail"] == LICENSE_LAPSED_DETAIL
    assert "access_token" not in response.text


def test_a_wrong_password_still_reads_as_a_wrong_password(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    """The licence is checked *after* the credentials, and must not mask them.

    Answering "your licence lapsed" to a typo would send an operator hunting
    for a key they do not need.
    """
    _expire(users_repo, licensing)

    response = license_client.post(
        "/api/auth/login", json={"username": "bekci", "password": "yanlis-parola"}
    )
    assert response.status_code == 401


def test_an_admin_logs_in_without_any_licence(license_client: TestClient) -> None:
    """Exempt by construction; the account that issues keys cannot need one."""
    response = license_client.post(
        "/api/auth/login", json={"username": "mudur", "password": "parola1234"}
    )
    assert response.status_code == 200


def test_a_key_sent_with_the_credentials_is_the_way_back_in(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    """Otherwise the refusal is a trap: locked out of the dashboard, and out
    of the endpoint that would unlock it."""
    from lpr.user_license import issue_key

    _expire(users_repo, licensing)
    response = license_client.post(
        "/api/auth/login",
        json={
            "username": "bekci",
            "password": "parola1234",
            "license_key": issue_key("bekci", 30, licensing),
        },
    )
    assert response.status_code == 200
    assert response.json()["access_token"]
    # The countdown started here, not when the admin cut the key.
    assert users_repo.get("bekci")["license_activated_at"]


def test_a_key_issued_to_somebody_else_does_not_open_the_door(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    from lpr.user_license import issue_key

    _expire(users_repo, licensing)
    response = license_client.post(
        "/api/auth/login",
        json={
            "username": "bekci",
            "password": "parola1234",
            "license_key": issue_key("baskasi", 30, licensing),
        },
    )
    assert response.status_code == 400


# -- reading the site --------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/api/plates", "/api/logs", "/api/logs/dates", "/api/stats", "/api/cameras",
     "/api/parking", "/api/events/export", "/api/system/version"],
)
def test_an_expired_operator_cannot_read_the_site_either(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any,
    path: str,
) -> None:
    """A lapsed licence is not a read-only mode; it is the door being shut.

    These were on plain authentication while only the write endpoints were
    gated, which left an expired account still watching the car park.
    """
    _expire(users_repo, licensing)
    response = license_client.get(path, headers=operator_auth())
    assert response.status_code == 403
    assert response.json()["error"]["detail"] == LICENSE_LAPSED_DETAIL


def test_an_expired_operator_cannot_watch_the_cameras(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    """The stream takes its token in the query string, so it needs its own
    check -- and a live feed is exactly what must not survive the lapse."""
    _expire(users_repo, licensing)
    token = create_token("bekci", "operator")

    response = license_client.get(f"/api/stream/entry?token={token}")
    assert response.status_code == 403
    assert response.json()["error"]["detail"] == LICENSE_LAPSED_DETAIL


def test_an_expired_operator_cannot_hold_the_event_socket(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    """A socket is a standing subscription to the site; the lapse ends it."""
    _expire(users_repo, licensing)
    token = create_token("bekci", "operator")

    with license_client.websocket_connect(f"/api/ws/events?token={token}") as ws:
        message = ws.receive_json()
        assert message["type"] == "error"
        assert message["detail"] == LICENSE_LAPSED_DETAIL


def test_a_licensed_operator_still_reads_the_site(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    """The other side of the gate: enforcement must not lock out the licensed."""
    from lpr.user_license import activate, issue_key

    key = issue_key("bekci", 30, licensing)
    state = activate(key, "bekci", licensing)
    users_repo.set_license(
        "bekci", key, state.expires_at, state.status,
        duration_days=state.duration_days, activated_at=state.activated_at,
    )

    assert license_client.get("/api/plates", headers=operator_auth()).status_code == 200


def test_an_expired_operator_can_still_ask_who_they_are(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    """The endpoints that explain the lapse, and undo it, stay open."""
    _expire(users_repo, licensing)

    assert license_client.get("/api/auth/me", headers=operator_auth()).status_code == 200
    body = license_client.get("/api/license/me", headers=operator_auth()).json()
    assert body["status"] == "expired"
    assert body["valid"] is False


# -- admin-side generation ---------------------------------------------------


def test_generating_a_licence_requires_admin(license_client: TestClient) -> None:
    response = license_client.post(
        "/api/users/bekci/license", json={"days": 30}, headers=operator_auth()
    )
    assert response.status_code == 403


def test_generating_a_key_does_not_activate_the_account(
    license_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    """Generation hands over an artefact; it must not start the countdown.

    An admin cutting a key on Friday for a Monday start would otherwise burn
    the weekend off the operator's licence.
    """
    response = license_client.post(
        "/api/users/bekci/license", json={"days": 90}, headers=admin_auth()
    )
    assert response.status_code == 201
    body = response.json()

    assert body["key"], "the admin has to be able to pass the key on"
    assert body["status"] == "pending_activation", "the account is untouched"
    assert body["expires_at"] is None

    row = users_repo.rows["bekci"]
    assert row.get("license_key") is None, "nothing is written until activation"
    assert row.get("license_expires_at") is None


def test_the_generated_key_carries_the_requested_span(
    license_client: TestClient
) -> None:
    """30 days asked for is 30 days signed into the token.

    The regression this guards: the dashboard used to post whatever a single
    panel-wide dropdown said -- 365 unless somebody had changed it -- for
    whichever row was clicked, so a 30-day operator was handed a year.
    """
    from lpr.user_license import inspect_key

    response = license_client.post(
        "/api/users/bekci/license", json={"days": 30}, headers=admin_auth()
    )
    assert response.status_code == 201
    key = response.json()["key"]

    info = inspect_key(key)
    assert info.username == "bekci"
    assert info.duration_days == 30, "the token must encode the span that was asked for"


@pytest.mark.parametrize("days", [1, 30, 90, 365, 3650])
def test_every_accepted_span_survives_the_round_trip(
    license_client: TestClient, days: int
) -> None:
    from lpr.user_license import inspect_key

    response = license_client.post(
        "/api/users/bekci/license", json={"days": days}, headers=admin_auth()
    )
    assert response.status_code == 201
    assert inspect_key(response.json()["key"]).duration_days == days


def test_omitting_the_span_is_refused_rather_than_defaulted_to_a_year(
    license_client: TestClient
) -> None:
    """A missing `days` used to mean 365 silently.

    Unknown keys were already forbidden, but a *missing* one was not, so a
    caller with a typo'd field name got a one-year licence and no complaint.
    The span a licence grants is not something to guess at.
    """
    response = license_client.post(
        "/api/users/bekci/license", json={}, headers=admin_auth()
    )
    assert response.status_code == 422


def test_an_out_of_range_span_is_refused(license_client: TestClient) -> None:
    for days in (0, -1, 3651):
        response = license_client.post(
            "/api/users/bekci/license", json={"days": days}, headers=admin_auth()
        )
        assert response.status_code == 422, f"{days} should not be issuable"


def test_a_generated_key_still_leaves_the_operator_blocked(
    license_client: TestClient
) -> None:
    license_client.post("/api/users/bekci/license", json={"days": 90}, headers=admin_auth())
    assert license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    ).status_code == 403


def test_generating_a_licence_for_an_admin_is_refused(
    license_client: TestClient
) -> None:
    """A key that would never be checked is misleading to hand somebody."""
    response = license_client.post(
        "/api/users/mudur/license", json={"days": 30}, headers=admin_auth()
    )
    assert response.status_code == 400


def test_generating_for_an_unknown_user_is_a_404(license_client: TestClient) -> None:
    response = license_client.post(
        "/api/users/yok/license", json={"days": 30}, headers=admin_auth()
    )
    assert response.status_code == 404


def test_revoking_requires_admin(license_client: TestClient) -> None:
    assert (
        license_client.delete("/api/users/bekci/license", headers=operator_auth()).status_code
        == 403
    )


def test_revoking_keeps_the_key_but_changes_the_status(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    """Keeping it lets an admin see what was revoked."""
    from lpr.user_license import issue_key

    key = issue_key("bekci", 30, licensing)
    license_client.post("/api/license/activate", json={"key": key}, headers=operator_auth())
    assert users_repo.rows["bekci"]["license_key"] == key

    response = license_client.delete("/api/users/bekci/license", headers=admin_auth())
    assert response.status_code == 200
    assert response.json()["status"] == "revoked"
    assert users_repo.rows["bekci"]["license_key"] == key


def test_a_30_day_key_yields_a_30_day_licence_end_to_end(
    license_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    """The whole reported path: generate 30 -> activate -> read back 30.

    Checks the three places the number has to agree: the signed token, the
    stored account row, and what /api/users hands the dashboard to render.
    """
    from lpr.user_license import inspect_key

    generated = license_client.post(
        "/api/users/bekci/license", json={"days": 30}, headers=admin_auth()
    )
    assert generated.status_code == 201
    key = generated.json()["key"]

    # 1. the token payload
    assert inspect_key(key).duration_days == 30

    # A key is issued to a person and is activated by that person: the route
    # binds it to the calling account, so bekci enters their own key.
    activated = license_client.post(
        "/api/license/activate", json={"key": key}, headers=operator_auth()
    )
    assert activated.status_code == 200, activated.text
    assert activated.json()["duration_days"] == 30

    # 2. the stored row
    row = users_repo.rows["bekci"]
    assert int(row["license_duration_days"]) == 30

    # 3. what the dashboard renders
    listed = {
        r["username"]: r
        for r in license_client.get("/api/users", headers=admin_auth()).json()
    }
    assert listed["bekci"]["license_duration_days"] == 30
    assert listed["bekci"]["license_status"] == "active"

    # And the date the table prints is 30 days out, not 365.
    from datetime import datetime, timezone

    expires = datetime.fromisoformat(listed["bekci"]["license_expires_at"])
    remaining = (expires - datetime.now(timezone.utc)).total_seconds() / 86400.0
    assert 29 <= remaining <= 30, f"{remaining:.1f} days -- expected a 30-day span"


def test_the_user_listing_reports_live_licence_state(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    from lpr.user_license import issue_key

    def listing() -> dict[str, Any]:
        return {r["username"]: r for r in license_client.get("/api/users", headers=admin_auth()).json()}

    assert listing()["mudur"]["license_status"] == "unlimited"
    assert listing()["bekci"]["license_status"] == "pending_activation"

    license_client.post(
        "/api/license/activate",
        json={"key": issue_key("bekci", 30, licensing)},
        headers=operator_auth(),
    )
    row = listing()["bekci"]
    assert row["license_status"] == "active"
    assert row["license_expires_at"] and row["license_activated_at"]


def test_the_auth_path_uses_the_overridden_repository(api_app: Any) -> None:
    """The revocation check must resolve its repository as a dependency.

    ``app.dependency_overrides`` is keyed on the callable's identity, so
    calling ``deps.get_user_repository(request)`` directly would silently
    bypass the override -- and the auth path would talk to the process's real
    database on every request, in tests and in any app that swaps the
    repository for its own reasons.
    """
    seen: list[str] = []

    class Watching(FakeUserRepository):
        def get(self, username: str) -> dict[str, Any] | None:
            seen.append(username)
            return {"username": username, "role": "admin"}

    api_app.dependency_overrides[deps.get_user_repository] = lambda: Watching()
    response = TestClient(api_app).get(
        "/api/auth/me", headers=auth(create_token("mudur", "admin"))
    )

    assert response.status_code == 200
    assert seen == ["mudur"], "the override was bypassed"


# ---------------------------------------------------------------------------
# Viewer role: read everything, change nothing
# ---------------------------------------------------------------------------


@pytest.fixture()
def viewer_token() -> str:
    return create_token("watcher", "viewer")


VIEWER_READS = [
    ("get", "/api/plates"),
    ("get", "/api/stats"),
    ("get", "/api/metrics"),
    ("get", "/api/cameras"),
    ("get", "/api/logs"),
    # /api/parking is deliberately absent: FakeLogRepository has no
    # occupancy_since, so the route 500s for every role. That is a gap in the
    # test double, not in the viewer role, and asserting around it here would
    # only hide it.
]

VIEWER_WRITES = [
    ("post", "/api/relay/trigger", None),
    ("post", "/api/plates", {"plate": "34ABC123"}),
    ("delete", "/api/plates/34ABC123", None),
    ("patch", "/api/plates/34ABC123", {"owner": "yeni"}),
    ("put", "/api/parking", {"capacity": 50}),
    ("post", "/api/pipeline/pause", None),
    ("post", "/api/pipeline/resume", None),
]


@pytest.mark.parametrize(("method", "path"), VIEWER_READS)
def test_a_viewer_may_read(
    api_client: TestClient, viewer_token: str, method: str, path: str
) -> None:
    """The role exists so a gatehouse attendant can watch the feed and look up
    a pass without also being handed the gate-open button."""
    response = getattr(api_client, method)(path, headers=auth(viewer_token))
    assert response.status_code != 403, response.text
    assert response.status_code < 500, response.text


@pytest.mark.parametrize(("method", "path", "body"), VIEWER_WRITES)
def test_a_viewer_may_not_write(
    api_client: TestClient,
    viewer_token: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
) -> None:
    """Every mutation, refused at the dependency rather than per handler."""
    kwargs: dict[str, Any] = {"headers": auth(viewer_token)}
    if body is not None:
        kwargs["json"] = body
    response = getattr(api_client, method)(path, **kwargs)
    assert response.status_code == 403, f"{method} {path} -> {response.status_code}"
    assert "salt okunur" in response.json()["error"]["detail"]


def test_a_viewer_may_not_open_the_barrier(
    api_client: TestClient, viewer_token: str
) -> None:
    """Named on its own because it is the reason the role exists.

    Before it, an attendant who needed to read the pass log had to be given
    `operator`, which carries manual gate control.
    """
    response = api_client.post("/api/relay/trigger", headers=auth(viewer_token))
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/api/users", {"username": "x", "password": "y" * 12, "role": "viewer"}),
        ("delete", "/api/users/someone", None),
    ],
)
def test_a_viewer_may_not_manage_users(
    api_client: TestClient,
    viewer_token: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
) -> None:
    kwargs: dict[str, Any] = {"headers": auth(viewer_token)}
    if body is not None:
        kwargs["json"] = body
    assert getattr(api_client, method)(path, **kwargs).status_code == 403


def test_an_operator_may_still_write(
    api_client: TestClient, operator_token: str
) -> None:
    """The guard is a floor, not a narrowing: nothing an operator could do
    before may have been taken away."""
    response = api_client.post("/api/relay/trigger", headers=auth(operator_token))
    assert response.status_code != 403, response.text


def test_an_admin_may_still_write(api_client: TestClient, admin_token: str) -> None:
    response = api_client.post("/api/relay/trigger", headers=auth(admin_token))
    assert response.status_code != 403, response.text


def test_a_token_with_an_unknown_role_gets_the_least_authority(
    api_client: TestClient,
) -> None:
    """A role this build has never heard of -- a downgrade, a typo, a forged
    claim -- must rank below everything, not above it."""
    token = create_token("stranger", "superuser")
    assert api_client.post("/api/relay/trigger", headers=auth(token)).status_code == 403


def test_whoami_reports_the_viewer_role(
    api_client: TestClient, viewer_token: str
) -> None:
    response = api_client.get("/api/auth/me", headers=auth(viewer_token))
    assert response.status_code == 200
    assert response.json()["role"] == "viewer"


# ---------------------------------------------------------------------------
# Login rate limiting
# ---------------------------------------------------------------------------


def test_repeated_bad_logins_are_eventually_refused_with_429(
    api_client: TestClient, api_app: Any
) -> None:
    """The endpoint had no limit at all; argon2 alone does not stop guessing."""
    from lpr.api.ratelimit import LoginLimiter

    api_app.state.login_limiter = LoginLimiter(lockout_after=3)
    body = {"username": "admin", "password": "wrong"}

    for _ in range(3):
        assert api_client.post("/api/auth/login", json=body).status_code == 401

    refused = api_client.post("/api/auth/login", json=body)
    assert refused.status_code == 429
    assert "Retry-After" in refused.headers


def test_the_lockout_response_says_how_long_to_wait(
    api_client: TestClient, api_app: Any
) -> None:
    from lpr.api.ratelimit import LoginLimiter

    api_app.state.login_limiter = LoginLimiter(lockout_after=1)
    body = {"username": "admin", "password": "wrong"}
    api_client.post("/api/auth/login", json=body)

    refused = api_client.post("/api/auth/login", json=body)
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) >= 1
    assert "saniye" in refused.json()["error"]["detail"]


def test_a_lockout_does_not_leak_whether_the_account_exists(
    api_client: TestClient, api_app: Any
) -> None:
    """Both a real and an invented username must look the same before lockout.

    Telling an attacker which usernames are real halves their work.
    """
    from lpr.api.ratelimit import LoginLimiter

    api_app.state.login_limiter = LoginLimiter(lockout_after=10)
    real = api_client.post("/api/auth/login", json={"username": "admin", "password": "x"})
    fake = api_client.post("/api/auth/login", json={"username": "nobody", "password": "x"})
    assert real.status_code == fake.status_code == 401
    assert real.json()["error"]["detail"] == fake.json()["error"]["detail"]
