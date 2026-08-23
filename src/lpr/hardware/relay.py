"""Gate relay drivers.

The legacy app opened the barrier like this, *on the camera capture thread*::

    ser.write(b"A")
    time.sleep(1)      # <-- both cameras frozen for a whole second
    ser.write(b"a")

Every gate opening therefore cost a second of capture on **both** feeds, so
the system was blindest exactly when a car was passing through it.

Here the pulse runs on a dedicated worker thread. :meth:`SerialRelay.trigger`
only hands a token to a queue and returns immediately, which is the property
``tests/test_relay.py`` asserts. Requests that arrive while a pulse is
already in flight are dropped rather than queued, so a plate that keeps being
confirmed cannot build an unbounded backlog of gate pulses.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import TYPE_CHECKING, Any

from lpr.contracts import Relay

if TYPE_CHECKING:  # pragma: no cover
    from lpr.config import Settings

logger = logging.getLogger(__name__)

#: Token pushed onto the worker queue for one open/close pulse.
_PULSE = "pulse"
#: Token that tells the worker to exit.
_STOP = "stop"

#: Serial reopen backoff bounds, in seconds.
_BACKOFF_START = 1.0
_BACKOFF_MAX = 30.0


class MockRelay:
    """Stand-in for the real hardware.

    Used when the relay is disabled, explicitly mocked, has no serial port to
    talk to, or when pyserial is not installed. Implements the same
    :class:`lpr.contracts.Relay` protocol so nothing downstream needs to know.
    """

    def __init__(self, reason: str = "relay mocked", pulse_ms: int = 1000) -> None:
        self._reason = reason
        self._pulse_ms = pulse_ms
        self._closed = False
        self.triggers = 0
        logger.info("Using MockRelay (%s)", reason)

    def trigger(self) -> None:
        if self._closed:
            return
        self.triggers += 1
        logger.info(
            "MockRelay: gate pulse #%d (%d ms) - %s", self.triggers, self._pulse_ms, self._reason
        )

    def close(self) -> None:
        self._closed = True

    @property
    def available(self) -> bool:
        return not self._closed

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"MockRelay(reason={self._reason!r}, triggers={self.triggers})"


class SerialRelay:
    """Serial gate relay with a non-blocking :meth:`trigger`.

    One daemon worker thread owns the serial port; nothing else touches it,
    so there is no locking around the device itself. The port is opened
    lazily on the first pulse and re-opened with exponential backoff after a
    ``serial.SerialException``.
    """

    def __init__(
        self,
        port: str,
        baud: int = 9600,
        open_byte: str = "A",
        close_byte: str = "a",
        pulse_ms: int = 1000,
    ) -> None:
        self._port = port
        self._baud = int(baud)
        self._open_byte = _to_byte(open_byte, b"A")
        self._close_byte = _to_byte(close_byte, b"a")
        self._pulse_s = max(0.0, int(pulse_ms) / 1000.0)

        self._queue: queue.Queue[str] = queue.Queue()
        self._serial: Any | None = None
        self._closed = False
        self._last_error: str | None = None
        self._backoff = _BACKOFF_START
        self._next_open_attempt = 0.0

        # Coalescing state: only one pulse may be outstanding at a time.
        self._lock = threading.Lock()
        self._in_flight = False
        self.pulses_sent = 0
        self.pulses_dropped = 0

        self._thread = threading.Thread(
            target=self._run, name=f"relay-{port}", daemon=True
        )
        self._thread.start()
        logger.info("SerialRelay worker started for %s @ %d baud", port, self._baud)

    # -- public API --------------------------------------------------------

    def trigger(self) -> None:
        """Request one gate pulse. Returns immediately; never blocks or raises.

        If a pulse is already being sent the request is dropped: the gate is
        already opening, and queueing a second pulse behind it would only
        make the barrier flap.
        """
        if self._closed:
            return
        with self._lock:
            if self._in_flight:
                self.pulses_dropped += 1
                logger.debug("Gate pulse already in flight; dropping request")
                return
            self._in_flight = True
        self._queue.put(_PULSE)

    def close(self) -> None:
        """Stop the worker and release the serial port. Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._queue.put(_STOP)
        # Give an in-flight pulse time to finish before giving up on the join.
        self._thread.join(timeout=self._pulse_s + 2.0)
        if self._thread.is_alive():  # pragma: no cover - worker wedged in serial I/O
            logger.warning("Relay worker did not stop within the timeout")
        self._close_serial()
        logger.info("SerialRelay closed (%d pulses sent, %d dropped)",
                    self.pulses_sent, self.pulses_dropped)

    @property
    def available(self) -> bool:
        """True when the port is open, or not yet tried and not known broken."""
        if self._closed:
            return False
        ser = self._serial
        if ser is not None:
            try:
                return bool(ser.is_open)
            except Exception:  # pragma: no cover - driver misbehaving
                return False
        return self._last_error is None

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def port(self) -> str:
        return self._port

    # -- worker ------------------------------------------------------------

    def _run(self) -> None:
        while True:
            token = self._queue.get()
            if token == _STOP:
                self._queue.task_done()
                break
            try:
                self._pulse()
            except Exception as exc:  # never let the worker thread die
                self._last_error = str(exc)
                logger.exception("Unexpected error while pulsing the gate relay")
            finally:
                with self._lock:
                    self._in_flight = False
                self._queue.task_done()

    def _pulse(self) -> None:
        ser = self._ensure_serial()
        if ser is None:
            logger.warning("Gate pulse skipped: serial port %s unavailable", self._port)
            return
        try:
            ser.write(self._open_byte)
            ser.flush()
            # The only sleep in the whole relay, and it is on this thread.
            time.sleep(self._pulse_s)
            ser.write(self._close_byte)
            ser.flush()
        except Exception as exc:
            if _is_serial_exception(exc):
                self._last_error = str(exc)
                logger.warning("Serial write failed on %s: %s", self._port, exc)
                self._close_serial()
                self._schedule_retry()
                return
            raise
        self.pulses_sent += 1
        self._backoff = _BACKOFF_START
        self._last_error = None
        logger.info("Gate pulse sent on %s (%.0f ms)", self._port, self._pulse_s * 1000)

    def _ensure_serial(self) -> Any | None:
        if self._serial is not None:
            try:
                if self._serial.is_open:
                    return self._serial
            except Exception:  # pragma: no cover - driver misbehaving
                pass
            self._close_serial()

        now = time.monotonic()
        if now < self._next_open_attempt:
            return None

        serial_mod = _import_serial()
        if serial_mod is None:
            self._last_error = "pyserial is not installed"
            self._schedule_retry()
            return None

        try:
            self._serial = serial_mod.Serial(self._port, self._baud, timeout=1, write_timeout=2)
        except Exception as exc:
            self._serial = None
            self._last_error = str(exc)
            logger.warning("Could not open serial port %s: %s", self._port, exc)
            self._schedule_retry()
            return None

        self._last_error = None
        self._backoff = _BACKOFF_START
        logger.info("Serial port %s opened", self._port)
        return self._serial

    def _schedule_retry(self) -> None:
        self._next_open_attempt = time.monotonic() + self._backoff
        self._backoff = min(_BACKOFF_MAX, self._backoff * 2)

    def _close_serial(self) -> None:
        ser, self._serial = self._serial, None
        if ser is None:
            return
        try:
            ser.close()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Error closing serial port: %s", exc)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"SerialRelay(port={self._port!r}, available={self.available})"


# ---------------------------------------------------------------------------
# Helpers / factory
# ---------------------------------------------------------------------------


def _to_byte(value: str, default: bytes) -> bytes:
    """Config gives the pulse bytes as one-character strings ("A"/"a")."""
    try:
        encoded = str(value).encode("latin-1")
    except (UnicodeEncodeError, AttributeError):
        return default
    return encoded or default


def _import_serial() -> Any | None:
    try:
        import serial
    except ImportError:
        return None
    return serial


def _is_serial_exception(exc: BaseException) -> bool:
    serial_mod = _import_serial()
    if serial_mod is None:
        return False
    serial_error = getattr(serial_mod, "SerialException", None)
    return serial_error is not None and isinstance(exc, serial_error)


def build_relay(settings: Settings | None = None) -> Relay:
    """Pick a relay implementation for the current configuration.

    Falls back to :class:`MockRelay` -- never raises -- when the relay is
    disabled, mocked, has no resolvable port, or pyserial is missing. A
    missing barrier must not stop the recognition pipeline from running.
    """
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()

    config = settings.relay

    if not config.enabled:
        return MockRelay("relay.enabled is false", config.pulse_ms)
    if config.mock:
        return MockRelay("relay.mock is true", config.pulse_ms)

    port = config.resolved_port
    if not port:
        return MockRelay("no serial port resolved (relay.port=auto found nothing)", config.pulse_ms)
    if _import_serial() is None:
        return MockRelay("pyserial is not installed", config.pulse_ms)

    try:
        return SerialRelay(
            port=port,
            baud=config.baud,
            open_byte=config.open_byte,
            close_byte=config.close_byte,
            pulse_ms=config.pulse_ms,
        )
    except Exception as exc:  # pragma: no cover - constructor only starts a thread
        logger.error("Could not start the serial relay on %s: %s", port, exc)
        return MockRelay(f"serial relay failed to start: {exc}", config.pulse_ms)
