"""Gate relay drivers beyond the serial board.

``SerialRelay`` in :mod:`lpr.hardware.relay` covers a USB or RS-232 relay
board, which is what a retrofit gate usually has. Three other wirings are just
as common on the sites this product targets, and none of them worked before:

``GpioRelay``
    A Raspberry Pi driving a relay HAT directly. No intermediate board, no
    serial port -- the pin *is* the contact.

``ModbusRelay``
    An industrial I/O module addressed as a coil, over RTU (RS-485) or TCP.
    This is what a barrier installed by an access-control contractor is most
    likely to be sitting behind.

``HttpRelay``
    A networked IP relay with a small web interface. Popular because it needs
    no wiring back to the server at all, only a network drop.

All three keep the contract the pipeline relies on and that
``tests/test_relay.py`` pins: :meth:`trigger` returns immediately, never
raises, and never blocks a recognition thread. The pulse -- which involves a
sleep, and for HTTP a network round trip -- happens on a worker thread, and a
request arriving while a pulse is in flight is *dropped* rather than queued.
A car that keeps re-confirming its plate must not make the barrier flap.

Every dependency is imported lazily inside the driver that needs it. A site
running a serial relay does not install ``pymodbus``, and importing this module
must not require it.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["GpioRelay", "HttpRelay", "ModbusRelay", "WorkerRelay"]

_PULSE = "pulse"
_STOP = "stop"

#: Reopen backoff bounds, shared with SerialRelay's constants by value rather
#: than by import so a change to one is a deliberate change to the other.
_BACKOFF_START = 1.0
_BACKOFF_MAX = 30.0


class WorkerRelay:
    """Queue, worker thread and pulse coalescing, shared by the drivers below.

    Subclasses implement :meth:`_close_contact`, :meth:`_open_contact` and
    optionally :meth:`_connect` / :meth:`_disconnect`. Everything about
    threading, dropping and error handling lives here, so a new driver is
    three short methods rather than a copy of this file.

    Deliberately *not* retrofitted onto ``SerialRelay``. That class is covered
    by tests which are the specification for this behaviour, and rewriting the
    one working driver to introduce three new ones is how a gate stops opening.
    """

    #: Set by subclasses for log lines and ``repr``.
    kind = "relay"

    def __init__(self, pulse_ms: int = 1000, name: str = "") -> None:
        self._pulse_s = max(0.0, int(pulse_ms) / 1000.0)
        self._name = name or self.kind

        self._queue: queue.Queue[str] = queue.Queue()
        self._closed = False
        self._last_error: str | None = None
        self._backoff = _BACKOFF_START
        self._next_open_attempt = 0.0
        self._connected = False

        self._lock = threading.Lock()
        self._in_flight = False
        self.pulses_sent = 0
        self.pulses_dropped = 0

        self._thread = threading.Thread(
            target=self._run, name=f"relay-{self._name}", daemon=True
        )
        self._thread.start()
        logger.info("%s worker started (%s)", type(self).__name__, self._name)

    # -- Relay protocol ----------------------------------------------------

    def trigger(self) -> None:
        """Request one gate pulse. Returns immediately; never blocks or raises."""
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
        """Stop the worker and release the device. Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._queue.put(_STOP)
        self._thread.join(timeout=self._pulse_s + 3.0)
        if self._thread.is_alive():  # pragma: no cover - wedged in driver I/O
            logger.warning("%s worker did not stop within the timeout", self._name)
        self._safe_disconnect()
        logger.info(
            "%s closed (%d pulses sent, %d dropped)",
            type(self).__name__,
            self.pulses_sent,
            self.pulses_dropped,
        )

    @property
    def available(self) -> bool:
        if self._closed:
            return False
        return self._connected or self._last_error is None

    @property
    def last_error(self) -> str | None:
        return self._last_error

    # -- worker ------------------------------------------------------------

    def _run(self) -> None:
        while True:
            token = self._queue.get()
            if token == _STOP:
                self._queue.task_done()
                break
            try:
                self._pulse()
            except Exception as exc:  # the worker thread must never die
                self._last_error = str(exc)
                logger.exception("Unexpected error while pulsing the gate relay")
            finally:
                with self._lock:
                    self._in_flight = False
                self._queue.task_done()

    def _pulse(self) -> None:
        if not self._ensure_connected():
            logger.warning("Gate pulse skipped: %s unavailable", self._name)
            return
        try:
            self._close_contact()
            # The only sleep in the driver, and it is on this thread.
            time.sleep(self._pulse_s)
            self._open_contact()
        except Exception as exc:
            self._last_error = str(exc)
            logger.warning("Gate pulse failed on %s: %s", self._name, exc)
            # Try to leave the contact open. A relay stuck closed holds the
            # barrier up, which is the worse of the two failure directions.
            try:
                self._open_contact()
            except Exception:
                logger.error(
                    "Could not release the gate contact on %s. The barrier may be "
                    "held open -- check it.",
                    self._name,
                )
            self._safe_disconnect()
            self._schedule_retry()
            return

        self.pulses_sent += 1
        self._backoff = _BACKOFF_START
        self._last_error = None
        logger.info("Gate pulse sent on %s (%.0f ms)", self._name, self._pulse_s * 1000)

    def _ensure_connected(self) -> bool:
        if self._connected:
            return True
        if time.monotonic() < self._next_open_attempt:
            return False
        try:
            self._connect()
        except Exception as exc:
            self._last_error = str(exc)
            logger.warning("Could not open %s: %s", self._name, exc)
            self._schedule_retry()
            return False
        self._connected = True
        self._last_error = None
        self._backoff = _BACKOFF_START
        return True

    def _schedule_retry(self) -> None:
        self._next_open_attempt = time.monotonic() + self._backoff
        self._backoff = min(self._backoff * 2, _BACKOFF_MAX)

    def _safe_disconnect(self) -> None:
        self._connected = False
        try:
            self._disconnect()
        except Exception:  # pragma: no cover - teardown of a broken device
            logger.debug("Error disconnecting %s", self._name, exc_info=True)

    # -- subclass hooks ----------------------------------------------------

    def _connect(self) -> None:
        """Open the device. Raise to report failure."""

    def _disconnect(self) -> None:
        """Release the device. Must tolerate never having connected."""

    def _close_contact(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _open_contact(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"{type(self).__name__}({self._name}, available={self.available}, "
            f"sent={self.pulses_sent}, dropped={self.pulses_dropped})"
        )


class GpioRelay(WorkerRelay):
    """A relay wired straight to a Raspberry Pi pin.

    ``active_low`` is not a detail to guess at. Most cheap opto-isolated relay
    boards energise on a LOW signal, so a driver that assumes active-high
    drives the pin the wrong way round: instead of a one-second pulse, the
    contact closes at start-up and stays closed, and the barrier is held open
    for the life of the process. It is configuration
    (``relay.gpio_active_low``) with a default that matches the common board.

    Uses ``gpiozero`` when present -- it handles pin factories, cleanup and
    both Pi generations -- and falls back to ``RPi.GPIO``.
    """

    kind = "gpio"

    def __init__(self, pin: int, active_low: bool = True, pulse_ms: int = 1000) -> None:
        self._pin = int(pin)
        self._active_low = bool(active_low)
        self._device: Any | None = None
        self._backend = ""
        super().__init__(pulse_ms=pulse_ms, name=f"gpio{self._pin}")

    def _connect(self) -> None:
        try:
            from gpiozero import DigitalOutputDevice

            # initial_value=False means "not energised", which gpiozero maps
            # through active_high for us -- so the contact starts open on
            # either board polarity.
            self._device = DigitalOutputDevice(
                self._pin, active_high=not self._active_low, initial_value=False
            )
            self._backend = "gpiozero"
            return
        except ImportError:
            pass

        try:
            import RPi.GPIO as GPIO
        except ImportError as exc:
            raise RuntimeError(
                "neither gpiozero nor RPi.GPIO is installed; "
                "pip install gpiozero to drive a GPIO relay"
            ) from exc

        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        idle = GPIO.HIGH if self._active_low else GPIO.LOW
        GPIO.setup(self._pin, GPIO.OUT, initial=idle)
        self._device = GPIO
        self._backend = "RPi.GPIO"

    def _disconnect(self) -> None:
        device = self._device
        self._device = None
        if device is None:
            return
        if self._backend == "gpiozero":
            device.close()
        else:
            device.cleanup(self._pin)

    def _close_contact(self) -> None:
        if self._backend == "gpiozero":
            self._device.on()  # type: ignore[union-attr]
        else:
            level = self._device.LOW if self._active_low else self._device.HIGH  # type: ignore[union-attr]
            self._device.output(self._pin, level)  # type: ignore[union-attr]

    def _open_contact(self) -> None:
        if self._device is None:
            return
        if self._backend == "gpiozero":
            self._device.off()
        else:
            level = self._device.HIGH if self._active_low else self._device.LOW
            self._device.output(self._pin, level)


class ModbusRelay(WorkerRelay):
    """An industrial I/O module addressed as a Modbus coil, over RTU or TCP.

    The pulse is two coil writes -- ``True`` then ``False`` -- with the hold
    between them, which is what an access-control contractor's barrier
    controller expects on its "open" input.

    Uses ``pymodbus``, imported lazily: a site running a serial relay has no
    reason to install it.
    """

    kind = "modbus"

    def __init__(
        self,
        *,
        mode: str = "tcp",
        host: str = "127.0.0.1",
        port: int = 502,
        unit: int = 1,
        coil: int = 0,
        baud: int = 9600,
        pulse_ms: int = 1000,
    ) -> None:
        self._mode = (mode or "tcp").strip().lower()
        self._host = host
        self._port = int(port)
        self._unit = int(unit)
        self._coil = int(coil)
        self._baud = int(baud)
        self._client: Any | None = None
        name = (
            f"modbus-tcp {host}:{port}/{coil}"
            if self._mode == "tcp"
            else f"modbus-rtu {host}/{coil}"
        )
        super().__init__(pulse_ms=pulse_ms, name=name)

    def _connect(self) -> None:
        try:
            if self._mode == "rtu":
                from pymodbus.client import ModbusSerialClient

                client = ModbusSerialClient(port=self._host, baudrate=self._baud, timeout=2)
            else:
                from pymodbus.client import ModbusTcpClient

                client = ModbusTcpClient(self._host, port=self._port, timeout=2)
        except ImportError as exc:
            raise RuntimeError(
                "pymodbus is not installed; pip install pymodbus to drive a "
                "Modbus relay"
            ) from exc

        if not client.connect():
            raise RuntimeError(f"could not connect to {self._name}")
        self._client = client

    def _disconnect(self) -> None:
        client = self._client
        self._client = None
        if client is not None:
            client.close()

    def _write_coil(self, value: bool) -> None:
        client = self._client
        if client is None:
            raise RuntimeError("modbus client is not connected")
        # pymodbus renamed the unit-id keyword between 2.x and 3.x, and a
        # deployment pins whichever it pins. Try the modern spelling first.
        try:
            result = client.write_coil(self._coil, value, slave=self._unit)
        except TypeError:
            result = client.write_coil(self._coil, value, unit=self._unit)
        if hasattr(result, "isError") and result.isError():
            raise RuntimeError(f"modbus write to coil {self._coil} failed: {result}")

    def _close_contact(self) -> None:
        self._write_coil(True)

    def _open_contact(self) -> None:
        self._write_coil(False)


class HttpRelay(WorkerRelay):
    """A networked IP relay driven over its own web interface.

    Two URLs. ``close_url`` is optional: many boards have a built-in timer and
    release the contact themselves, and for those the pulse width is set on the
    board rather than here. When it is blank this driver does not sleep either
    -- holding the worker for a second to do nothing would only delay the next
    vehicle.

    ``{pulse_ms}`` anywhere in either URL is substituted, which is how the
    boards that *do* take the duration as a query parameter want it.

    Uses ``urllib`` from the standard library rather than ``requests``: this is
    one request with a timeout, on a worker thread, and the pipeline should not
    grow a dependency for it.
    """

    kind = "http"

    def __init__(
        self,
        open_url: str,
        close_url: str = "",
        *,
        method: str = "GET",
        timeout_s: float = 5.0,
        user: str = "",
        password: str = "",
        pulse_ms: int = 1000,
    ) -> None:
        if not (open_url or "").strip():
            raise ValueError("HttpRelay needs relay.http_open_url")
        self._open_url = open_url.strip()
        self._close_url = (close_url or "").strip()
        self._method = (method or "GET").strip().upper()
        self._timeout = float(timeout_s)
        self._user = user
        self._password = password

        from lpr.masking import mask_url

        # `{pulse_ms}` is substituted once, here, rather than per request.
        # The width does not change, and doing it at the call site meant the
        # name (which reaches log lines) and the URL disagreed.
        held_ms = 0 if not self._close_url else int(pulse_ms)
        self._open_url = self._open_url.replace("{pulse_ms}", str(held_ms or int(pulse_ms)))
        self._close_url = self._close_url.replace("{pulse_ms}", str(int(pulse_ms)))

        super().__init__(pulse_ms=pulse_ms, name=f"http {mask_url(self._open_url)}")
        # A board that releases itself needs no hold on our side.
        if not self._close_url:
            self._pulse_s = 0.0

    def _request(self, url: str) -> None:
        import base64
        import urllib.error
        import urllib.request

        request = urllib.request.Request(url, method=self._method)
        if self._user:
            token = base64.b64encode(
                f"{self._user}:{self._password}".encode()
            ).decode("ascii")
            request.add_header("Authorization", f"Basic {token}")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                status = int(getattr(response, "status", 200) or 200)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"relay returned HTTP {exc.code}") from exc
        except Exception as exc:
            from lpr.masking import mask_text

            raise RuntimeError(f"relay request failed: {mask_text(exc)}") from exc
        if status >= 400:  # pragma: no cover - urllib raises for these
            raise RuntimeError(f"relay returned HTTP {status}")

    def _connect(self) -> None:
        # Nothing to open: each pulse is a fresh request. A long-lived
        # connection to a device on a site LAN is a thing that dies silently
        # between uses, and this is one request every few minutes.
        return

    def _close_contact(self) -> None:
        self._request(self._open_url)

    def _open_contact(self) -> None:
        if self._close_url:
            self._request(self._close_url)
