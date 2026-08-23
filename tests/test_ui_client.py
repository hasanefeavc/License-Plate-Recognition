"""Tests for the desktop client's transport layer.

Nothing here imports Tkinter (not even indirectly): ``lpr.ui.client`` is pure
requests/websocket code, which is exactly why it lives in its own module. The
HTTP session and the WebSocket connection are both replaced by local fakes, so
no socket is ever opened.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

import pytest

pytest.importorskip("requests")

import requests  # noqa: E402

from lpr.ui.client import EventStream, LprApiError, LprClient, _ws_url  # noqa: E402

BASE_URL = "http://testserver:8000"


def wait_for(predicate: Any, timeout: float = 3.0, interval: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


# ---------------------------------------------------------------------------
# Fake HTTP transport
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        payload: Any = None,
        *,
        reason: str = "OK",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.reason = reason
        self.headers = headers or {}

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeStreamResponse:
    def __init__(self, chunks: list[bytes], boundary: str = "lprframe") -> None:
        self.status_code = 200
        self._chunks = chunks
        self.headers = {
            "Content-Type": f"multipart/x-mixed-replace; boundary={boundary}"
        }
        self.closed = False

    def iter_content(self, chunk_size: int = 8192) -> Any:
        yield from self._chunks

    def json(self) -> Any:  # pragma: no cover - only used on error paths
        raise ValueError("no json")

    def close(self) -> None:
        self.closed = True


class FakeSession:
    """Records every call and replays a scripted list of responses."""

    def __init__(self, responses: list[Any] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[dict[str, Any]] = []
        self.stream_response: Any = None
        self.stream_calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError(f"beklenmeyen istek: {method} {url}")
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def get(self, url: str, **kwargs: Any) -> Any:
        self.stream_calls.append({"url": url, **kwargs})
        if isinstance(self.stream_response, Exception):
            raise self.stream_response
        return self.stream_response


def make_client(responses: list[Any] | None = None) -> tuple[LprClient, FakeSession]:
    session = FakeSession(responses)
    return LprClient(BASE_URL, session=session, timeout=(0.1, 0.1)), session


# ---------------------------------------------------------------------------
# Auth / token attachment
# ---------------------------------------------------------------------------


def test_login_stores_token_and_attaches_it_to_later_calls() -> None:
    client, session = make_client(
        [
            FakeResponse(
                200,
                {
                    "access_token": "tok-123",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "username": "mudur",
                    "role": "admin",
                },
            ),
            FakeResponse(200, {"plates": ["34ABC123"], "count": 1}),
        ]
    )

    client.login("mudur", "gizli")

    assert client.token == "tok-123"
    assert client.username == "mudur"
    assert client.is_admin is True
    # The login request itself must NOT carry an Authorization header.
    assert "Authorization" not in session.calls[0]["headers"]

    assert client.list_plates() == ["34ABC123"]
    assert session.calls[1]["headers"]["Authorization"] == "Bearer tok-123"
    assert session.calls[1]["url"] == f"{BASE_URL}/api/plates"


def test_logout_clears_the_token() -> None:
    client, _session = make_client(
        [FakeResponse(200, {"access_token": "t", "username": "u", "role": "admin"})]
    )
    client.login("u", "p")

    client.logout()

    assert client.token is None
    assert client.is_authenticated is False


def test_login_without_token_in_body_raises() -> None:
    client, _session = make_client([FakeResponse(200, {"detail": "boş"})])

    with pytest.raises(LprApiError):
        client.login("u", "p")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def test_4xx_raises_lpr_api_error_with_status_and_detail() -> None:
    client, _session = make_client(
        [
            FakeResponse(
                404,
                {"error": {"status": 404, "title": "Not Found", "detail": "Plaka bulunamadı"}},
                reason="Not Found",
            )
        ]
    )
    client.set_token("tok")

    with pytest.raises(LprApiError) as excinfo:
        client.remove_plate("34ABC123")

    assert excinfo.value.status_code == 404
    assert "Plaka bulunamadı" in str(excinfo.value)
    assert excinfo.value.is_offline is False


def test_401_is_flagged_as_auth_error() -> None:
    client, _session = make_client([FakeResponse(401, {"detail": "Kimlik doğrulama gerekli"})])

    with pytest.raises(LprApiError) as excinfo:
        client.list_plates()

    assert excinfo.value.is_auth_error is True


def test_connection_error_is_retried_once_then_succeeds() -> None:
    client, session = make_client(
        [
            requests.ConnectionError("boom"),
            FakeResponse(200, {"plates": [], "count": 0}),
        ]
    )
    client.set_token("tok")

    assert client.list_plates() == []
    assert len(session.calls) == 2


def test_connection_error_twice_raises_offline_error() -> None:
    client, session = make_client(
        [requests.ConnectionError("boom"), requests.ConnectionError("boom")]
    )

    with pytest.raises(LprApiError) as excinfo:
        client.list_plates()

    assert excinfo.value.status_code is None
    assert excinfo.value.is_offline is True
    assert len(session.calls) == 2


def test_http_error_is_not_retried() -> None:
    client, session = make_client([FakeResponse(500, None, reason="Internal Server Error")])

    with pytest.raises(LprApiError) as excinfo:
        client.list_plates()

    assert excinfo.value.status_code == 500
    assert len(session.calls) == 1


# ---------------------------------------------------------------------------
# Regular endpoints
# ---------------------------------------------------------------------------


def test_logs_sends_only_the_provided_filters() -> None:
    client, session = make_client([FakeResponse(200, [])])
    client.set_token("tok")

    client.logs(since="2026-05-01", camera="entry", limit=25)

    assert session.calls[0]["params"] == {
        "limit": 25,
        "offset": 0,
        "since": "2026-05-01",
        "camera": "entry",
    }


def test_add_and_remove_plate() -> None:
    client, session = make_client(
        [FakeResponse(201, {"plate": "34ABC123", "registered": True}), FakeResponse(200, {})]
    )
    client.set_token("tok")

    assert client.add_plate("34ABC123", "not")["plate"] == "34ABC123"
    assert client.remove_plate("34ABC123") is True
    assert session.calls[0]["json"] == {"plate": "34ABC123", "note": "not"}
    assert session.calls[1]["method"] == "DELETE"


def test_pause_and_resume_report_state() -> None:
    client, _session = make_client(
        [FakeResponse(200, {"paused": True, "running": True}),
         FakeResponse(200, {"paused": False, "running": True})]
    )
    client.set_token("tok")

    assert client.pause() is True
    assert client.resume() is False


# ---------------------------------------------------------------------------
# MJPEG parsing
# ---------------------------------------------------------------------------


def _part(payload: bytes, boundary: str = "lprframe", with_length: bool = True) -> bytes:
    header = f"--{boundary}\r\nContent-Type: image/jpeg\r\n".encode()
    if with_length:
        header += f"Content-Length: {len(payload)}\r\n".encode()
    return header + b"\r\n" + payload + b"\r\n"


def test_mjpeg_frames_parses_content_length_parts() -> None:
    client, session = make_client()
    client.set_token("tok")
    body = _part(b"AAAA") + _part(b"BBBBBB")
    # Deliberately split mid-frame so the buffering path is exercised.
    session.stream_response = FakeStreamResponse([body[:9], body[9:40], body[40:]])

    frames = list(client.mjpeg_frames("entry"))

    assert frames == [b"AAAA", b"BBBBBB"]
    assert session.stream_calls[0]["headers"]["Authorization"] == "Bearer tok"
    assert session.stream_calls[0]["stream"] is True
    assert session.stream_response.closed is True


def test_mjpeg_frames_falls_back_to_boundary_scanning() -> None:
    client, session = make_client()
    body = _part(b"AAAA", with_length=False) + _part(b"BBBB", with_length=False)
    session.stream_response = FakeStreamResponse([body])

    frames = list(client.mjpeg_frames("exit"))

    # The trailing part has no following boundary, so only the first is emitted.
    assert frames == [b"AAAA"]


def test_mjpeg_frames_raises_on_rejected_stream() -> None:
    client, session = make_client()
    session.stream_response = FakeResponse(401, {"detail": "yok"})

    with pytest.raises(LprApiError) as excinfo:
        list(client.mjpeg_frames("entry"))

    assert excinfo.value.status_code == 401


def test_mjpeg_frames_raises_when_stream_cannot_be_opened() -> None:
    client, session = make_client()
    session.stream_response = requests.ConnectionError("down")

    with pytest.raises(LprApiError):
        list(client.mjpeg_frames("entry"))


# ---------------------------------------------------------------------------
# EventStream
# ---------------------------------------------------------------------------


class FakeWebSocket:
    def __init__(self, messages: list[str]) -> None:
        self._messages = list(messages)
        self.closed = False

    def recv(self) -> str:
        if self._messages:
            return self._messages.pop(0)
        raise ConnectionError("bağlantı kapandı")

    def close(self) -> None:
        self.closed = True


def test_ws_url_carries_scheme_and_token() -> None:
    assert _ws_url("http://host:8000", "/ws/events", "tok") == (
        "ws://host:8000/ws/events?token=tok"
    )
    assert _ws_url("https://host", "/ws/events", None) == "wss://host/ws/events"


def test_event_stream_drains_queue_and_skips_pings() -> None:
    sockets: list[FakeWebSocket] = []

    def factory(url: str) -> FakeWebSocket:
        socket = FakeWebSocket(
            [
                json.dumps({"type": "ping"}),
                json.dumps({"type": "event", "data": {"plate": "34ABC123"}}),
                json.dumps({"type": "event", "data": {"plate": "06XYZ42"}}),
            ]
            if not sockets
            else []
        )
        sockets.append(socket)
        return socket

    stream = EventStream(
        BASE_URL,
        lambda: "tok",
        connect_factory=factory,
        initial_backoff=0.01,
        max_backoff=0.02,
    )
    stream.start()
    try:
        assert wait_for(lambda: stream.reconnects >= 1)
    finally:
        stream.stop()

    messages = stream.poll()
    plates = [m["data"]["plate"] for m in messages if m.get("type") == "event"]
    assert plates == ["34ABC123", "06XYZ42"]
    assert all(m.get("type") != "ping" for m in messages)
    assert sockets[0].closed is True


def test_event_stream_reconnects_after_a_dropped_connection() -> None:
    attempts: list[str] = []
    barrier = threading.Event()

    def factory(url: str) -> FakeWebSocket:
        attempts.append(url)
        if len(attempts) == 1:
            return FakeWebSocket([json.dumps({"type": "event", "data": {"n": 1}})])
        barrier.set()
        return FakeWebSocket([json.dumps({"type": "event", "data": {"n": 2}})])

    stream = EventStream(
        BASE_URL,
        lambda: "tok",
        connect_factory=factory,
        initial_backoff=0.01,
        max_backoff=0.02,
    )
    stream.start()
    try:
        assert barrier.wait(timeout=3.0)
        assert wait_for(lambda: len(attempts) >= 2)
    finally:
        stream.stop()

    assert "token=tok" in attempts[0]
    assert stream.reconnects >= 1
    numbers = [m["data"]["n"] for m in stream.poll() if m.get("type") == "event"]
    assert numbers[:2] == [1, 2]


def test_event_stream_survives_a_failing_connect() -> None:
    calls: list[str] = []

    def factory(url: str) -> Any:
        calls.append(url)
        raise OSError("bağlanılamadı")

    stream = EventStream(
        BASE_URL,
        lambda: None,
        connect_factory=factory,
        initial_backoff=0.01,
        max_backoff=0.02,
    )
    stream.start()
    try:
        assert wait_for(lambda: len(calls) >= 2)
    finally:
        stream.stop()

    assert stream.connected is False
    assert stream.running is False


def test_poll_never_blocks_on_an_empty_queue() -> None:
    stream = EventStream(BASE_URL, lambda: None, connect_factory=lambda url: FakeWebSocket([]))

    assert stream.poll() == []


def test_client_event_stream_uses_current_token() -> None:
    client, _session = make_client()
    client.set_token("tok-9")

    stream = client.event_stream(connect_factory=lambda url: FakeWebSocket([]))

    assert stream.base_url == BASE_URL
    assert "token=tok-9" in _ws_url(stream.base_url, stream.path, client.token)


# ---------------------------------------------------------------------------
# Async transport (the websockets-style path)
# ---------------------------------------------------------------------------


class FakeAsyncWebSocket:
    """Mimics a ``websockets`` connection: awaitable recv/close."""

    def __init__(self, messages: list[str], hold_open: bool = False) -> None:
        self._messages = list(messages)
        self.closed = False
        self._hold_open = hold_open

    async def recv(self) -> str:
        import asyncio

        if self._messages:
            return self._messages.pop(0)
        if self._hold_open:
            await asyncio.sleep(0.05)
            return json.dumps({"type": "ping"})
        raise ConnectionError("bağlantı kapandı")

    async def close(self) -> None:
        self.closed = True


class FakeAsyncContextConnect:
    """Mimics ``websockets.connect(...)``: an async context manager."""

    def __init__(self, socket: FakeAsyncWebSocket) -> None:
        self._socket = socket

    async def __aenter__(self) -> FakeAsyncWebSocket:
        return self._socket

    async def __aexit__(self, *exc: Any) -> None:
        await self._socket.close()


def test_event_stream_consumes_an_async_connection() -> None:
    sockets: list[FakeAsyncWebSocket] = []

    def factory(url: str) -> FakeAsyncWebSocket:
        socket = FakeAsyncWebSocket(
            [
                json.dumps({"type": "ping"}),
                json.dumps({"type": "event", "data": {"plate": "34ABC123"}}),
                json.dumps({"type": "telemetry", "data": {"kind": "read"}}),
            ]
            if not sockets
            else []
        )
        sockets.append(socket)
        return socket

    stream = EventStream(
        BASE_URL, lambda: "tok", connect_factory=factory,
        initial_backoff=0.01, max_backoff=0.02,
    )
    stream.start()
    try:
        assert wait_for(lambda: stream.reconnects >= 1)
    finally:
        stream.stop()

    messages = stream.poll()
    assert [m["type"] for m in messages if m["type"] != "status"] == ["event", "telemetry"]
    assert sockets[0].closed is True


def test_event_stream_enters_an_async_context_manager() -> None:
    """``websockets.connect`` returns a context manager, not a socket."""
    socket = FakeAsyncWebSocket([json.dumps({"type": "event", "data": {"n": 1}})])

    stream = EventStream(
        BASE_URL, lambda: None,
        connect_factory=lambda url: FakeAsyncContextConnect(socket),
        initial_backoff=0.01, max_backoff=0.02,
    )
    stream.start()
    try:
        assert wait_for(lambda: stream.reconnects >= 1)
    finally:
        stream.stop()

    assert [m["data"]["n"] for m in stream.poll() if m["type"] == "event"] == [1]
    assert socket.closed is True


def test_stop_interrupts_the_backoff_promptly() -> None:
    """A long backoff must not make shutdown wait for it."""

    def factory(url: str) -> Any:
        raise OSError("bağlanılamadı")

    stream = EventStream(
        BASE_URL, lambda: None, connect_factory=factory,
        initial_backoff=30.0, max_backoff=30.0,
    )
    stream.start()
    assert wait_for(lambda: stream.reconnects >= 1)

    started = time.monotonic()
    stream.stop(timeout=5.0)
    assert time.monotonic() - started < 2.0, "stop() waited out the backoff"
    assert stream.running is False


def test_event_stream_defaults_to_the_api_path() -> None:
    stream = EventStream(BASE_URL, lambda: None)
    assert stream.path == "/api/ws/events"


def test_event_stream_can_be_restarted() -> None:
    stream = EventStream(
        BASE_URL, lambda: None,
        connect_factory=lambda url: FakeAsyncWebSocket([], hold_open=True),
        initial_backoff=0.01, max_backoff=0.02,
    )
    stream.start()
    assert wait_for(lambda: stream.connected)
    stream.stop()
    assert stream.running is False

    stream.start()
    assert wait_for(lambda: stream.connected)
    stream.stop()
