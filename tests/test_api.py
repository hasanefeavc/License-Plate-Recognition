"""Tests for the HTTP API.

The pipeline and the repositories are replaced by local fakes: nothing here
imports ``lpr.pipeline`` or ``lpr.db``, so the suite runs without torch,
ultralytics, easyocr or a database file. The fake orchestrator implements
exactly the public surface :mod:`lpr.api.routes` is allowed to use.

``TestClient`` is deliberately *not* used as a context manager -- entering it
would run the real lifespan (init_db + build_pipeline), which is precisely what
these tests replace.
"""

from __future__ import annotations

import types
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from lpr.api import deps  # noqa: E402
from lpr.api.main import create_app  # noqa: E402
from lpr.api.security import create_token  # noqa: E402
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

    def dates(self) -> list[str]:
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


def test_relay_trigger_requires_admin(api_client: TestClient, operator_token: str) -> None:
    assert (
        api_client.post("/api/relay/trigger", headers=auth(operator_token)).status_code == 403
    )


# ---------------------------------------------------------------------------
# Stream
# ---------------------------------------------------------------------------


def test_unknown_camera_is_404(api_client: TestClient, operator_token: str) -> None:
    response = api_client.get("/api/stream/garaj", headers=auth(operator_token))

    assert response.status_code == 404
    assert "garaj" in response.json()["error"]["detail"]


def test_stream_without_token_is_401(api_client: TestClient) -> None:
    assert api_client.get("/api/stream/entry").status_code == 401


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


def test_expired_licence_halts_the_pipeline(expired_app: Any) -> None:
    client = TestClient(expired_app)
    token = create_token("admin", "admin")

    body = client.get("/api/license", headers=auth(token)).json()
    assert body["valid"] is False
    assert body["reason"] == "expired"
    assert body["pipeline_halted"] is True

    assert expired_app.state.paused is True
    assert expired_app.state.pipeline.paused is True


def test_expired_licence_blocks_the_gate(expired_app: Any) -> None:
    """The barrier is the licensed function; halting only the ML half is not
    enough."""
    client = TestClient(expired_app)
    response = client.post("/api/relay/trigger", headers=auth(create_token("admin", "admin")))
    assert response.status_code == 402
    assert expired_app.state.pipeline.relay.triggers == 0


def test_expired_licence_cannot_be_resumed_by_hand(expired_app: Any) -> None:
    client = TestClient(expired_app)
    response = client.post("/api/pipeline/resume", headers=auth(create_token("admin", "admin")))
    assert response.status_code == 402
    assert expired_app.state.paused is True


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


def test_a_rejected_key_is_a_400_carrying_the_reason(expired_app: Any) -> None:
    client = TestClient(expired_app)
    response = client.post(
        "/api/license",
        headers=auth(create_token("admin", "admin")),
        json={"key": "gecersiz-anahtar"},
    )
    assert response.status_code == 400
    assert "geçersiz" in response.json()["error"]["detail"]
    assert expired_app.state.paused is True


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

    def start(self) -> Any:
        self.starts += 1
        if self.error is not None:
            raise self.error
        self._status = types.SimpleNamespace(
            to_dict=lambda: {
                "state": "running",
                "step": "pull",
                "detail": "Güncelleme başlatıldı.",
                "running": True,
                "started_at": 1.0,
                "finished_at": None,
                "commit_before": "aaa",
                "commit_after": None,
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

    ``start()`` takes no arguments, so there is nowhere for a caller-supplied
    remote to go even if one were sent. This pins that shape.
    """
    response = update_client.post(
        "/api/system/update",
        headers=auth(admin_token),
        json={"remote": "https://evil.example/repo", "branch": "payload"},
    )
    assert response.status_code == 202
    assert updater.starts == 1


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
    ) -> str:
        existing = plate in self.details
        if existing and not overwrite:
            return "skipped"
        self.details[plate] = {
            "plate": plate,
            "owner": owner,
            "apartment": apartment,
            "note": note,
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
        self.rows[name] = {
            "username": name,
            "role": role,
            "created_at": "2026-08-27T00:00:00+00:00",
            "token_ttl_min": token_ttl_min,
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
        self, username: str, key: str | None, expires_at: str | None, status: str
    ) -> bool:
        row = self.rows.get((username or "").strip())
        if row is None:
            return False
        row["license_key"] = key
        row["license_expires_at"] = expires_at
        row["license_status"] = status
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


# -- listing ----------------------------------------------------------------


def test_listing_users_requires_admin(
    users_client: TestClient, operator_token: str
) -> None:
    assert users_client.get("/api/users").status_code == 401
    assert users_client.get("/api/users", headers=auth(operator_token)).status_code == 403


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


def test_creating_a_user_requires_admin(
    users_client: TestClient, operator_token: str
) -> None:
    payload = {"username": "yeni", "password": "parola1234"}
    assert users_client.post("/api/users", json=payload).status_code == 401
    assert (
        users_client.post("/api/users", json=payload, headers=auth(operator_token)).status_code
        == 403
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


def test_deleting_a_user_requires_admin(
    users_client: TestClient, operator_token: str
) -> None:
    assert users_client.delete("/api/users/bekci").status_code == 401
    assert (
        users_client.delete("/api/users/bekci", headers=auth(operator_token)).status_code == 403
    )


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


def operator_auth() -> dict[str, str]:
    return auth(create_token("bekci", "operator"))


def test_an_unlicensed_operator_is_blocked_with_402(
    license_client: TestClient
) -> None:
    """402, not 403. The dashboard opens the key dialog on exactly this code.

    403 would say "not your role", which is wrong and offers nothing to do.
    """
    response = license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    )
    assert response.status_code == 402


def test_an_admin_is_never_blocked(license_client: TestClient) -> None:
    """Exempt by construction: the account that issues keys cannot need one."""
    response = license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=admin_auth()
    )
    assert response.status_code == 201


def test_a_licensed_operator_passes(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    from lpr.user_license import STATUS_ACTIVE, issue_key

    key, expires_at = issue_key("bekci", 30, licensing)
    users_repo.set_license("bekci", key, expires_at, STATUS_ACTIVE)

    response = license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    )
    assert response.status_code == 201


def test_a_revoked_licence_blocks_immediately(
    license_client: TestClient, users_repo: ManagedUserRepository, licensing: Any
) -> None:
    """Revocation is a database fact; the signed key cannot be un-signed."""
    from lpr.user_license import STATUS_ACTIVE, STATUS_REVOKED, issue_key

    key, expires_at = issue_key("bekci", 30, licensing)
    users_repo.set_license("bekci", key, expires_at, STATUS_ACTIVE)
    assert license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    ).status_code == 201

    users_repo.set_license("bekci", key, expires_at, STATUS_REVOKED)
    assert license_client.post(
        "/api/plates", json={"plate": "06MNP99"}, headers=operator_auth()
    ).status_code == 402


def test_reading_your_own_licence_is_never_gated(license_client: TestClient) -> None:
    """An operator whose licence lapsed is exactly who needs to read this."""
    response = license_client.get("/api/license/me", headers=operator_auth())
    assert response.status_code == 200
    assert response.json()["status"] == "missing"


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

    key, _ = issue_key("bekci", 30, licensing)
    response = license_client.post(
        "/api/license/activate", json={"key": key}, headers=operator_auth()
    )
    assert response.status_code == 200
    assert response.json()["status"] == "active"


def test_activating_someone_elses_key_is_refused(
    license_client: TestClient, licensing: Any
) -> None:
    from lpr.user_license import issue_key

    key, _ = issue_key("baskasi", 30, licensing)
    response = license_client.post(
        "/api/license/activate", json={"key": key}, headers=operator_auth()
    )
    assert response.status_code == 400


def test_activation_unblocks_the_operator(
    license_client: TestClient, licensing: Any
) -> None:
    from lpr.user_license import issue_key

    assert license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    ).status_code == 402

    key, _ = issue_key("bekci", 30, licensing)
    license_client.post("/api/license/activate", json={"key": key}, headers=operator_auth())

    assert license_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=operator_auth()
    ).status_code == 201


# -- admin-side generation ---------------------------------------------------


def test_generating_a_licence_requires_admin(license_client: TestClient) -> None:
    response = license_client.post(
        "/api/users/bekci/license", json={"days": 30}, headers=operator_auth()
    )
    assert response.status_code == 403


def test_an_admin_generates_a_key_and_gets_it_back(
    license_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    """Returned once so the admin can hand it over; also stored on the row."""
    response = license_client.post(
        "/api/users/bekci/license", json={"days": 90}, headers=admin_auth()
    )
    assert response.status_code == 201
    body = response.json()
    assert body["key"], "the admin has to be able to pass the key on"
    assert body["status"] == "active"
    assert 89 < body["days_remaining"] <= 90
    assert users_repo.rows["bekci"]["license_key"] == body["key"]


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
    license_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    """Keeping it lets an admin see what was revoked."""
    license_client.post("/api/users/bekci/license", json={"days": 30}, headers=admin_auth())
    issued = users_repo.rows["bekci"]["license_key"]

    response = license_client.delete("/api/users/bekci/license", headers=admin_auth())
    assert response.status_code == 200
    assert response.json()["status"] == "revoked"
    assert users_repo.rows["bekci"]["license_key"] == issued


def test_the_user_listing_reports_live_licence_state(
    license_client: TestClient, users_repo: ManagedUserRepository
) -> None:
    license_client.post("/api/users/bekci/license", json={"days": 30}, headers=admin_auth())
    rows = {row["username"]: row for row in license_client.get("/api/users", headers=admin_auth()).json()}

    assert rows["mudur"]["license_status"] == "unlimited"
    assert rows["bekci"]["license_status"] == "active"
    assert rows["bekci"]["license_expires_at"]
