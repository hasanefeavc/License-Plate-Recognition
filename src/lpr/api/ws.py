"""WebSocket fan-out of pipeline events.

``WS /ws/events`` streams every :class:`~lpr.contracts.LprEvent` produced by the
pipeline to every connected client as JSON.

Two things make this endpoint fiddlier than it looks:

1. **Auth.** A browser cannot attach an ``Authorization`` header to a WebSocket
   handshake, so the bearer token arrives as the ``?token=`` query parameter.
   An invalid or missing token is closed with policy-violation code ``1008``.

2. **Threading.** ``pipeline.subscribe()`` hands back a *thread-safe*
   ``queue.Queue`` that pipeline worker threads push into. Calling ``q.get()``
   directly from a coroutine would block the whole event loop -- every other
   request in the process would stall behind one idle WebSocket. Reads
   therefore go through ``run_in_executor`` with a short timeout, which keeps
   the loop free and lets the connection notice a disconnect promptly.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import queue
from typing import Any

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from lpr.api.security import AuthError, AuthUser, user_from_token

logger = logging.getLogger(__name__)

ws_router = APIRouter()

#: Blocking ``queue.get`` slice, in seconds. Also the disconnect-detection
#: granularity: nothing waits longer than this before re-checking the socket.
QUEUE_POLL_S = 1.0
#: Idle seconds before a keep-alive ping is pushed to the client.
PING_INTERVAL_S = 20.0
#: Upper bound on events coalesced into one wake-up.
MAX_BATCH = 50
#: Policy-violation close code used for auth failures.
CLOSE_POLICY_VIOLATION = 1008
#: Canonical event-stream route, alongside the rest of the /api surface.
EVENTS_PATH = "/api/ws/events"
#: The route this stream used to live at. Still served so a GUI from an older
#: build keeps working against a new server.
LEGACY_EVENTS_PATH = "/ws/events"
#: How often camera health is pushed to clients while the stream is idle.
CAMERA_STATUS_INTERVAL_S = 5.0

__all__ = [
    "CAMERA_STATUS_INTERVAL_S",
    "CLOSE_POLICY_VIOLATION",
    "EVENTS_PATH",
    "LEGACY_EVENTS_PATH",
    "ConnectionManager",
    "PING_INTERVAL_S",
    "QUEUE_POLL_S",
    "camera_status_payload",
    "manager",
    "ws_router",
]


class ConnectionManager:
    """Tracks live sockets so the server can report and broadcast to them."""

    def __init__(self) -> None:
        self._active: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._active.add(websocket)
        logger.info("WebSocket bağlandı (toplam: %d)", len(self._active))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._active.discard(websocket)
        logger.info("WebSocket ayrıldı (toplam: %d)", len(self._active))

    @property
    def count(self) -> int:
        return len(self._active)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        """Send ``payload`` to every live socket, dropping the dead ones."""
        async with self._lock:
            targets = list(self._active)
        dead: list[WebSocket] = []
        for socket in targets:
            if not await _safe_send(socket, payload):
                dead.append(socket)
        if dead:
            async with self._lock:
                for socket in dead:
                    self._active.discard(socket)


#: Process-wide manager. Sockets are transient, so this holds no state that
#: outlives a connection and is safe to keep at module scope.
manager = ConnectionManager()


async def _safe_send(websocket: WebSocket, payload: dict[str, Any]) -> bool:
    """Send JSON, returning ``False`` when the socket is gone."""
    if websocket.client_state is not WebSocketState.CONNECTED:
        return False
    try:
        await websocket.send_text(json.dumps(payload, ensure_ascii=False))
        return True
    except (WebSocketDisconnect, RuntimeError, ConnectionError):
        return False
    except Exception:  # pragma: no cover - unexpected transport failure
        logger.debug("WebSocket gönderimi başarısız", exc_info=True)
        return False


def _drain(q: "queue.Queue[Any]") -> list[Any]:
    """Blocking read of one event plus whatever else is already queued.

    Always called inside ``run_in_executor`` -- never on the event loop.
    Returns an empty list when the poll window expires with nothing to send.
    """
    try:
        first = q.get(True, QUEUE_POLL_S)
    except queue.Empty:
        return []
    items = [first]
    while len(items) < MAX_BATCH:
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            break
    return items


def _as_payload(event: Any) -> dict[str, Any]:
    """Normalise whatever the pipeline queued into the wire format."""
    if isinstance(event, dict):
        return event
    to_dict = getattr(event, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        if isinstance(result, dict):
            return result
    return {"value": str(event)}


def camera_status_payload(pipeline: Any) -> dict[str, Any] | None:
    """One ``camera_status`` message, or None if the pipeline cannot report.

    Read straight off ``pipeline.stats()`` rather than pushed by the capture
    threads: camera health is a *level*, not an event, so a client that
    reconnects wants the current value, not the history it missed.
    """
    if pipeline is None:
        return None
    try:
        stats = pipeline.stats()
        cameras = getattr(stats, "cameras", None) or {}
        items = cameras.values() if isinstance(cameras, dict) else cameras
        payload = [
            {
                "role": getattr(cam, "role", ""),
                "source": getattr(cam, "source", ""),
                "connected": bool(getattr(cam, "connected", False)),
                "fps": round(float(getattr(cam, "fps", 0.0)), 2),
                "frames_read": int(getattr(cam, "frames_read", 0)),
                "frames_dropped": int(getattr(cam, "frames_dropped", 0)),
                "motion_skipped": int(getattr(cam, "motion_skipped", 0)),
                "last_error": getattr(cam, "last_error", None),
            }
            for cam in items
        ]
    except Exception:  # pragma: no cover - a status read must never kill the socket
        logger.debug("Kamera durumu okunamadı", exc_info=True)
        return None
    return {"type": "camera_status", "cameras": payload}


async def _authenticate(websocket: WebSocket, token: str | None) -> AuthUser | None:
    """Accept the socket, then close it with 1008 if the token is no good.

    Accepting first is deliberate: a close *before* accept is surfaced by most
    ASGI servers as a bare HTTP 403 with no close code, and the client needs to
    see 1008 to tell "your token expired" apart from "the server is down".
    """
    await websocket.accept()
    try:
        return user_from_token(token or "")
    except AuthError as exc:
        logger.info("WebSocket kimlik doğrulaması reddedildi: %s", exc)
        await _safe_send(websocket, {"type": "error", "detail": str(exc)})
        with contextlib.suppress(Exception):
            await websocket.close(code=CLOSE_POLICY_VIOLATION, reason=str(exc))
        return None


async def _watch_for_close(websocket: WebSocket) -> None:
    """Consume inbound frames purely to notice the client hanging up."""
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, RuntimeError, ConnectionError):
        return
    except Exception:  # pragma: no cover - transport-level oddity
        logger.debug("WebSocket okuma sonlandı", exc_info=True)
        return


@ws_router.websocket(EVENTS_PATH)
@ws_router.websocket(LEGACY_EVENTS_PATH)
async def events_socket(
    websocket: WebSocket,
    token: str | None = Query(default=None, description="Bearer token"),
) -> None:
    """Live event stream: plate reads, gate decisions and camera status.

    Served at both :data:`EVENTS_PATH` (``/api/ws/events``, which is where
    everything under the API lives and what the GUI client asks for) and the
    original :data:`LEGACY_EVENTS_PATH`, so a client from an older build keeps
    working after the server is updated.
    """
    user = await _authenticate(websocket, token)
    if user is None:
        return

    await manager.connect(websocket)
    pipeline = getattr(websocket.app.state, "pipeline", None)
    event_queue: "queue.Queue[Any] | None" = None
    telemetry_queue: queue.Queue[Any] | None = None
    reader = asyncio.create_task(_watch_for_close(websocket))
    loop = asyncio.get_running_loop()

    try:
        await _safe_send(
            websocket,
            {
                "type": "hello",
                "username": user.username,
                "role": user.role,
                "pipeline": pipeline is not None,
            },
        )

        if pipeline is not None:
            try:
                event_queue = pipeline.subscribe()
            except Exception:
                logger.exception("Olay kuyruğuna abone olunamadı")
                event_queue = None
                await _safe_send(
                    websocket,
                    {"type": "error", "detail": "Olay akışı kullanılamıyor"},
                )
            else:
                # Live telemetry (reads, votes in progress) rides the same
                # socket on a separate subscription. Optional: an orchestrator
                # from an older build has no telemetry stream, and the socket
                # still carries every decision.
                try:
                    telemetry_queue = pipeline.subscribe(telemetry=True)
                except TypeError:
                    logger.debug("İşlem hattı telemetri akışını desteklemiyor")
                except Exception:  # pragma: no cover - defensive
                    logger.warning("Telemetri akışına abone olunamadı", exc_info=True)
        else:
            await _safe_send(
                websocket,
                {"type": "error", "detail": "İşlem hattı çalışmıyor"},
            )

        # Camera health up front, so a client that has just (re)connected can
        # paint its status panel without waiting for the first interval.
        status = camera_status_payload(pipeline)
        if status is not None:
            await _safe_send(websocket, status)

        idle_for = 0.0
        since_status = 0.0
        while not reader.done():
            if websocket.client_state is not WebSocketState.CONNECTED:
                break

            if event_queue is None:
                # Degraded mode: nothing to pump, just keep the socket warm so
                # the client's reconnect loop stays quiet.
                await asyncio.sleep(QUEUE_POLL_S)
                events: list[Any] = []
            else:
                events = await loop.run_in_executor(None, _drain, event_queue)

            telemetry = _drain(telemetry_queue) if telemetry_queue is not None else []

            if events or telemetry:
                idle_for = 0.0
                for event in events:
                    payload = {"type": "event", "data": _as_payload(event)}
                    if not await _safe_send(websocket, payload):
                        raise WebSocketDisconnect(code=1006)
                for item in telemetry:
                    payload = {"type": "telemetry", "data": _as_payload(item)}
                    if not await _safe_send(websocket, payload):
                        raise WebSocketDisconnect(code=1006)
                continue

            since_status += QUEUE_POLL_S
            if since_status >= CAMERA_STATUS_INTERVAL_S:
                since_status = 0.0
                status = camera_status_payload(pipeline)
                if status is not None and not await _safe_send(websocket, status):
                    break

            idle_for += QUEUE_POLL_S
            if idle_for >= PING_INTERVAL_S:
                idle_for = 0.0
                if not await _safe_send(websocket, {"type": "ping"}):
                    break
    except WebSocketDisconnect:
        logger.debug("WebSocket istemcisi bağlantıyı kapattı")
    except asyncio.CancelledError:  # pragma: no cover - server shutdown
        raise
    except Exception:  # pragma: no cover - never leak a traceback to the wire
        logger.exception("WebSocket oturumu hata ile sonlandı")
    finally:
        if pipeline is not None:
            for q in (event_queue, telemetry_queue):
                if q is None:
                    continue
                try:
                    pipeline.unsubscribe(q)
                except Exception:  # pragma: no cover - best effort
                    logger.warning("Olay kuyruğu aboneliği kaldırılamadı", exc_info=True)
        reader.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await reader
        await manager.disconnect(websocket)
        if websocket.client_state is WebSocketState.CONNECTED:
            with contextlib.suppress(Exception):
                await websocket.close()
