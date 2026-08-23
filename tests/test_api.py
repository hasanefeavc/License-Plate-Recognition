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
    app.dependency_overrides[deps.get_plate_repository] = lambda: plate_repo
    app.dependency_overrides[deps.get_log_repository] = lambda: log_repo
    app.dependency_overrides[deps.get_user_repository] = lambda: user_repo
    return app


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
    assert me.json() == {"username": "mudur", "role": "admin", "created_at": None}


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


def test_plate_write_requires_admin(api_client: TestClient, operator_token: str) -> None:
    response = api_client.post(
        "/api/plates", json={"plate": "34ABC123"}, headers=auth(operator_token)
    )

    assert response.status_code == 403


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
    assert listed.json() == {"plates": ["34ABC123"], "count": 1}

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


def test_pause_requires_admin(api_client: TestClient, operator_token: str) -> None:
    assert api_client.post("/api/pipeline/pause", headers=auth(operator_token)).status_code == 403


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
