"""HTTP/WebSocket client for the LPR API.

This module is the *only* thing the desktop GUI is allowed to talk to, and it
imports **no** Tkinter, OpenCV, database or ML code. That is deliberate: it
makes the whole transport layer unit-testable with a mocked session, and it is
what decouples the GUI process from the recognition process.

Three pieces:

``LprClient``
    Request/response calls. Keeps the bearer token, retries once on a
    connection error, raises :class:`LprApiError` (carrying the HTTP status)
    for anything that is not a 2xx.

``LprClient.mjpeg_frames``
    Generator over the ``multipart/x-mixed-replace`` camera stream, yielding
    one JPEG payload at a time.

``EventStream``
    Background thread holding a WebSocket to ``/ws/events``, pushing decoded
    events into a ``queue.Queue`` with exponential-backoff reconnects. The UI
    thread calls :meth:`EventStream.poll`, which never blocks.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
import queue
import re
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any, TypedDict
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import requests

logger = logging.getLogger(__name__)

__all__ = [
    "CameraInfo",
    "EventStream",
    "HealthInfo",
    "LicenseInfo",
    "LogEntry",
    "LprApiError",
    "LprClient",
    "StatsInfo",
]

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
#: Server route for the live event stream. The server also still serves the
#: pre-/api/ path, so a new client works against an older server too.
DEFAULT_EVENTS_PATH = "/api/ws/events"
#: (connect, read) timeouts for ordinary calls.
DEFAULT_TIMEOUT: tuple[float, float] = (5.0, 15.0)
#: Read timeout for the never-ending MJPEG response.
STREAM_TIMEOUT: tuple[float, float] = (5.0, 30.0)

_CONTENT_LENGTH_RE = re.compile(rb"Content-Length:\s*(\d+)", re.IGNORECASE)
_BOUNDARY_RE = re.compile(r"boundary=([^;\s]+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Typed payloads (plain dicts at runtime -- the wire format, unchanged)
# ---------------------------------------------------------------------------


class LogEntry(TypedDict, total=False):
    id: int | None
    ts: str
    camera: str
    plate: str
    action: str
    confidence: float


class CameraInfo(TypedDict, total=False):
    role: str
    source: str
    connected: bool
    fps: float
    frames_read: int
    frames_dropped: int
    last_error: str | None
    last_frame_ts: float


class StatsInfo(TypedDict, total=False):
    running: bool
    started_at: float
    uptime_s: float
    plates_read: int
    grants: int
    denials: int
    cameras: list[CameraInfo]


class LicenseInfo(TypedDict, total=False):
    valid: bool
    reason: str
    detail: str
    client: str | None
    issued_at: str | None
    expires_at: str | None
    seconds_remaining: float | None
    days_remaining: float | None
    pipeline_halted: bool


class HealthInfo(TypedDict, total=False):
    status: str
    version: str
    pipeline_running: bool
    cameras: dict[str, bool]
    detail: str | None


class LprApiError(RuntimeError):
    """Any failed API call. ``status_code`` is ``None`` for transport errors."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        payload: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload

    @property
    def is_auth_error(self) -> bool:
        return self.status_code in (401, 403)

    @property
    def is_offline(self) -> bool:
        return self.status_code is None

    def __str__(self) -> str:
        base = super().__str__()
        return f"[{self.status_code}] {base}" if self.status_code else base


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class LprClient:
    """Synchronous client for the LPR HTTP API."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        session: Any | None = None,
        timeout: tuple[float, float] = DEFAULT_TIMEOUT,
        token: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = session if session is not None else requests.Session()
        self._token = token
        self._username: str | None = None
        self._role: str | None = None

    # -- token ----------------------------------------------------------

    @property
    def token(self) -> str | None:
        return self._token

    @property
    def username(self) -> str | None:
        return self._username

    @property
    def role(self) -> str | None:
        return self._role

    @property
    def is_admin(self) -> bool:
        return self._role == "admin"

    @property
    def is_authenticated(self) -> bool:
        return bool(self._token)

    def set_token(self, token: str | None) -> None:
        self._token = token

    def logout(self) -> None:
        self._token = None
        self._username = None
        self._role = None

    def _headers(self, auth: bool = True) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if auth and self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    # -- transport ------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        auth: bool = True,
        expected: tuple[int, ...] = (200, 201, 204),
    ) -> Any:
        """One call, with a single retry when the connection itself failed.

        Only connection-level failures are retried -- a 4xx/5xx is a real
        answer from the server and retrying it would just double the damage.
        """
        url = self.url(path)
        last_exc: Exception | None = None

        for attempt in (0, 1):
            try:
                response = self._session.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=self._headers(auth),
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt == 0:
                    logger.debug("%s %s başarısız, yeniden denenecek: %s", method, url, exc)
                    time.sleep(0.25)
                    continue
                break
            return self._parse(response, expected)

        raise LprApiError(f"Sunucuya ulaşılamıyor: {self.base_url}") from last_exc

    @staticmethod
    def _parse(response: Any, expected: tuple[int, ...]) -> Any:
        status = int(response.status_code)
        try:
            payload = response.json()
        except ValueError:
            # requests raises a ValueError subclass for a non-JSON body.
            payload = None

        if status in expected:
            return payload

        detail = None
        if isinstance(payload, dict):
            error = payload.get("error")
            if isinstance(error, dict):
                detail = error.get("detail")
            elif "detail" in payload:
                detail = payload.get("detail")
        if detail is None:
            detail = getattr(response, "reason", None) or f"HTTP {status}"
        raise LprApiError(str(detail), status_code=status, payload=payload)

    # -- auth -----------------------------------------------------------

    def login(self, username: str, password: str) -> dict[str, Any]:
        """Authenticate and remember the returned bearer token."""
        data = self._request(
            "POST",
            "/api/auth/login",
            json_body={"username": username, "password": password},
            auth=False,
            expected=(200,),
        )
        return self._store_token(data)

    def register(
        self, username: str, password: str, role: str = "operator"
    ) -> dict[str, Any]:
        """Create an account. Works without a token only for the first user."""
        data = self._request(
            "POST",
            "/api/auth/register",
            json_body={"username": username, "password": password, "role": role},
            expected=(200, 201),
        )
        return self._store_token(data)

    def _store_token(self, data: Any) -> dict[str, Any]:
        if not isinstance(data, dict) or not data.get("access_token"):
            raise LprApiError("Sunucudan geçerli bir oturum anahtarı gelmedi")
        self._token = str(data["access_token"])
        self._username = str(data.get("username") or "")
        self._role = str(data.get("role") or "operator")
        return data

    def whoami(self) -> dict[str, Any]:
        data = self._request("GET", "/api/auth/me", expected=(200,))
        return data if isinstance(data, dict) else {}

    # -- health / stats -------------------------------------------------

    def health(self) -> HealthInfo:
        data = self._request("GET", "/health", auth=False, expected=(200,))
        return data if isinstance(data, dict) else {}  # type: ignore[return-value]

    def stats(self) -> StatsInfo:
        data = self._request("GET", "/api/stats", expected=(200,))
        return data if isinstance(data, dict) else {}  # type: ignore[return-value]

    def metrics(self) -> dict[str, Any]:
        """Flat operational counters: uptime, reads, and the work skipped."""
        data = self._request("GET", "/api/metrics", expected=(200,))
        return data if isinstance(data, dict) else {}

    # -- licence --------------------------------------------------------

    def license_status(self) -> LicenseInfo:
        """Current licence state as the server sees it."""
        data = self._request("GET", "/api/license", expected=(200,))
        return data if isinstance(data, dict) else {}  # type: ignore[return-value]

    def activate_license(self, key: str) -> LicenseInfo:
        """Submit a new licence key. Raises :class:`LprApiError` if rejected.

        A 400 here is the normal, expected answer for a mistyped or expired
        key: its ``detail`` is the sentence to show the operator.
        """
        data = self._request(
            "POST",
            "/api/license",
            json_body={"key": "".join((key or "").split())},
            expected=(200, 201),
        )
        return data if isinstance(data, dict) else {}  # type: ignore[return-value]

    def cameras(self) -> list[CameraInfo]:
        data = self._request("GET", "/api/cameras", expected=(200,))
        return list(data) if isinstance(data, list) else []

    def set_camera_source(self, camera: str, source: str) -> CameraInfo:
        data = self._request(
            "POST",
            f"/api/cameras/{quote(camera)}/source",
            json_body={"source": source},
            expected=(200,),
        )
        return data if isinstance(data, dict) else {}  # type: ignore[return-value]

    # -- plates ---------------------------------------------------------

    def list_plates(self) -> list[str]:
        data = self._request("GET", "/api/plates", expected=(200,))
        if isinstance(data, dict):
            return [str(p) for p in data.get("plates", [])]
        return []

    def add_plate(self, plate: str, note: str | None = None) -> dict[str, Any]:
        data = self._request(
            "POST",
            "/api/plates",
            json_body={"plate": plate, "note": note},
            expected=(200, 201),
        )
        return data if isinstance(data, dict) else {}

    def remove_plate(self, plate: str) -> bool:
        self._request(
            "DELETE", f"/api/plates/{quote(plate, safe='')}", expected=(200, 204)
        )
        return True

    # -- logs -----------------------------------------------------------

    def logs(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
        camera: str | None = None,
        plate: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[LogEntry]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        if camera:
            params["camera"] = camera
        if plate:
            params["plate"] = plate
        data = self._request("GET", "/api/logs", params=params, expected=(200,))
        return list(data) if isinstance(data, list) else []

    def log_dates(self) -> list[str]:
        data = self._request("GET", "/api/logs/dates", expected=(200,))
        return [str(d) for d in data] if isinstance(data, list) else []

    # -- control --------------------------------------------------------

    def trigger_relay(self) -> dict[str, Any]:
        data = self._request("POST", "/api/relay/trigger", expected=(200, 201))
        return data if isinstance(data, dict) else {}

    def pause(self) -> bool:
        data = self._request("POST", "/api/pipeline/pause", expected=(200,))
        return bool(data.get("paused")) if isinstance(data, dict) else True

    def resume(self) -> bool:
        data = self._request("POST", "/api/pipeline/resume", expected=(200,))
        return bool(data.get("paused")) if isinstance(data, dict) else False

    # -- MJPEG ----------------------------------------------------------

    def mjpeg_frames(
        self, camera: str, *, quality: int = 80, chunk_size: int = 8192
    ) -> Iterator[bytes]:
        """Yield JPEG payloads from ``/api/stream/{camera}`` until it ends.

        Parses ``multipart/x-mixed-replace`` by hand: ``Content-Length`` when
        the server provides it (ours does), boundary scanning otherwise.
        Raises :class:`LprApiError` if the stream cannot be opened; a stream
        that dies mid-flight simply stops yielding, so the caller's own
        reconnect loop stays in charge.
        """
        url = self.url(f"/api/stream/{quote(camera)}")
        params = {"quality": quality}
        try:
            response = self._session.get(
                url,
                params=params,
                headers=self._headers(),
                stream=True,
                timeout=STREAM_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise LprApiError(f"Görüntü akışı açılamadı: {exc}") from exc

        status = int(getattr(response, "status_code", 0))
        if status != 200:
            try:
                payload = response.json()
            except Exception:
                payload = None
            raise LprApiError(
                f"Görüntü akışı reddedildi ({status})", status_code=status, payload=payload
            )

        boundary = self._boundary_of(response)
        try:
            yield from self._iter_multipart(response.iter_content(chunk_size), boundary)
        except requests.RequestException as exc:
            logger.debug("Görüntü akışı kesildi: %s", exc)
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    @staticmethod
    def _boundary_of(response: Any) -> bytes:
        headers = getattr(response, "headers", None) or {}
        content_type = ""
        try:
            content_type = str(headers.get("Content-Type", "") or "")
        except Exception:  # pragma: no cover - exotic header mapping
            content_type = ""
        match = _BOUNDARY_RE.search(content_type)
        token = match.group(1).strip('"') if match else "lprframe"
        return b"--" + token.encode("ascii", "replace")

    @staticmethod
    def _iter_multipart(chunks: Iterator[bytes], boundary: bytes) -> Iterator[bytes]:
        buffer = bytearray()
        for chunk in chunks:
            if not chunk:
                continue
            buffer.extend(chunk)
            while True:
                header_end = buffer.find(b"\r\n\r\n")
                if header_end == -1:
                    break
                header = bytes(buffer[:header_end])
                match = _CONTENT_LENGTH_RE.search(header)
                body_start = header_end + 4
                if match:
                    length = int(match.group(1))
                    if len(buffer) < body_start + length:
                        break  # wait for the rest of this frame
                    yield bytes(buffer[body_start : body_start + length])
                    del buffer[: body_start + length]
                    continue
                next_boundary = buffer.find(boundary, body_start)
                if next_boundary == -1:
                    break
                yield bytes(buffer[body_start:next_boundary]).rstrip(b"\r\n")
                del buffer[:next_boundary]

    # -- events ---------------------------------------------------------

    def event_stream(self, **kwargs: Any) -> "EventStream":
        """Build an :class:`EventStream` bound to this client's token."""
        return EventStream(self.base_url, lambda: self._token, **kwargs)


# ---------------------------------------------------------------------------
# WebSocket event stream
# ---------------------------------------------------------------------------


def _ws_url(base_url: str, path: str, token: str | None) -> str:
    parts = urlsplit(base_url)
    scheme = "wss" if parts.scheme == "https" else "ws"
    query = urlencode({"token": token}) if token else ""
    return urlunsplit((scheme, parts.netloc, path, query, ""))


class _SyncConnectionAdapter:
    """Wraps a blocking WebSocket object so the asyncio loop can drive it.

    Exists for injected ``connect_factory`` implementations that hand back a
    plain synchronous socket. Their ``recv``/``close`` run on the loop's
    executor, so a blocking read never stalls the event loop.
    """

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    async def recv(self) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._connection.recv)

    async def close(self) -> None:
        loop = asyncio.get_running_loop()
        with contextlib.suppress(Exception):
            await loop.run_in_executor(None, self._connection.close)


class EventStream:
    """Background WebSocket reader with auto-reconnect.

    Runs an ``asyncio`` event loop on its own daemon thread and consumes the
    server stream with the ``websockets`` library. The loop thread only ever
    touches a ``queue.Queue``; :meth:`poll` is the single hand-off point to the
    caller, it never blocks, and it is the *only* thing the Tk main thread
    calls. No widget is ever touched from here.

    Disconnects are expected, not exceptional: a dropped socket, a failed
    connect and a server restart all land in the same path, which publishes a
    ``{"type": "status", "connected": False}`` message and retries with capped
    exponential backoff until :meth:`stop`.

    ``connect_factory`` overrides how the socket is opened. It may be a
    coroutine function (like ``websockets.connect``) or a plain callable
    returning a blocking socket -- the latter is adapted automatically.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        token_provider: Callable[[], str | None] | None = None,
        *,
        path: str = DEFAULT_EVENTS_PATH,
        connect_factory: Callable[[str], Any] | None = None,
        max_queue: int = 2000,
        initial_backoff: float = 1.0,
        max_backoff: float = 30.0,
        recv_timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.path = path
        self._token_provider = token_provider or (lambda: None)
        self._connect_factory = connect_factory or self._default_connect
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._connected = threading.Event()
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._recv_timeout = recv_timeout
        self.reconnects = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake: asyncio.Event | None = None

    # -- lifecycle ------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="lpr-event-stream", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Signal the loop to finish and wait for its thread. Idempotent."""
        self._stop.set()
        # Interrupt an in-flight backoff sleep from this (foreign) thread.
        loop, wake = self._loop, self._wake
        if loop is not None and wake is not None and not loop.is_closed():
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(wake.set)
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None
        self._connected.clear()

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # -- consumption ----------------------------------------------------

    def poll(self, max_items: int = 500) -> list[dict[str, Any]]:
        """Everything buffered since the previous call. Never blocks."""
        drained: list[dict[str, Any]] = []
        while len(drained) < max_items:
            try:
                drained.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return drained

    def _publish(self, item: dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            # Prefer fresh events over stale ones: drop the oldest, keep going.
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(item)
            except (queue.Empty, queue.Full):  # pragma: no cover - racing drain
                pass

    # -- worker ---------------------------------------------------------

    def _default_connect(self, url: str) -> Any:
        """Open the real socket. Lazy import: only the GUI extra ships it."""
        import websockets

        return websockets.connect(
            url,
            open_timeout=self._recv_timeout,
            ping_interval=None,  # the server sends its own keep-alive pings
            max_queue=64,
        )

    def _run_loop(self) -> None:
        """Thread entry point: own event loop, torn down on the way out."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._main())
        except Exception:  # pragma: no cover - the loop must not raise out
            logger.exception("Olay akışı döngüsü beklenmedik şekilde sonlandı")
        finally:
            with contextlib.suppress(Exception):
                loop.run_until_complete(loop.shutdown_asyncgens())
            asyncio.set_event_loop(None)
            loop.close()
            self._loop = None
            self._wake = None
            self._connected.clear()

    async def _main(self) -> None:
        self._wake = asyncio.Event()
        backoff = self._initial_backoff

        while not self._stop.is_set():
            token = self._token_provider()
            url = _ws_url(self.base_url, self.path, token)
            connection: Any = None
            try:
                connection = await self._open(url)
                self._connected.set()
                backoff = self._initial_backoff
                logger.info("Olay akışı bağlandı: %s", self.path)
                self._publish({"type": "status", "connected": True})
                await self._read_loop(connection)
            except Exception as exc:
                logger.debug("Olay akışı bağlantı hatası: %s", exc)
            finally:
                self._connected.clear()
                if connection is not None:
                    with contextlib.suppress(Exception):
                        await connection.close()

            if self._stop.is_set():
                break
            self._publish({"type": "status", "connected": False})
            self.reconnects += 1
            await self._sleep(backoff)
            backoff = min(self._max_backoff, backoff * 2)

        self._connected.clear()

    async def _open(self, url: str) -> Any:
        """Open a connection, whatever kind of factory was supplied."""
        result = self._connect_factory(url)
        if inspect.isawaitable(result):
            result = await result

        # websockets.connect(...) returns an async context manager; entering it
        # yields the live protocol object.
        enter = getattr(result, "__aenter__", None)
        if enter is not None:
            result = await enter()

        if inspect.iscoroutinefunction(getattr(result, "recv", None)):
            return result
        return _SyncConnectionAdapter(result)

    async def _sleep(self, seconds: float) -> None:
        """Back off, but wake immediately if :meth:`stop` is called."""
        wake = self._wake
        if wake is None:  # pragma: no cover - only before _main starts
            await asyncio.sleep(seconds)
            return
        with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
            await asyncio.wait_for(wake.wait(), timeout=seconds)

    async def _read_loop(self, connection: Any) -> None:
        while not self._stop.is_set():
            raw = await asyncio.wait_for(connection.recv(), timeout=self._recv_timeout)
            if raw is None or raw == "":
                raise ConnectionError("Bağlantı kapandı")
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            try:
                message = json.loads(raw)
            except (ValueError, TypeError):
                logger.debug("Olay akışında çözülemeyen mesaj atlandı")
                continue
            if not isinstance(message, dict):
                continue
            if message.get("type") == "ping":
                continue
            self._publish(message)
