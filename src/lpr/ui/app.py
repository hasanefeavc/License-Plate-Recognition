"""Desktop client entry point (``lpr-gui``).

Architecture
------------

The GUI process contains no OpenCV capture, no database and no ML model. It
speaks to ``lpr-api`` exclusively through :class:`lpr.ui.client.LprClient`, so
the recognition service can live on another machine (or in the container) and
the operator's laptop only needs Tk, Pillow and requests.

Threading rules -- the one invariant this whole module exists to enforce:

* Worker threads (MJPEG readers, status poller, every request triggered by a
  button) **never touch a widget**. They only ``_post()`` a message onto
  ``self._ui_queue``.
* A single ``root.after(50, self._drain)`` loop on the Tk main thread pops
  those messages and is the only code allowed to mutate widgets.
* :class:`~lpr.ui.client.EventStream` follows the same rule: its thread fills a
  queue, and ``poll()`` is called from ``_drain``.

The legacy application called ``widget.config(...)`` straight from capture
threads; that is what produced the intermittent "main thread is not in main
loop" crashes this rewrite removes.

Licensing
---------

The server is the authority: it halts its own pipeline when the licence is
invalid and reports that through ``GET /api/license`` (polled) and a
``{"type": "license"}`` WebSocket message (immediate). The client mirrors that
state -- it freezes both camera panes, shows the reason, and opens the modal
:class:`~lpr.ui.license_dialog.LicenseDialog`. Nothing here decides whether a
key is valid; it only submits what the operator typed and applies the answer.
"""

from __future__ import annotations

import argparse
import io
import logging
import queue
import threading
import time
import tkinter as tk
from collections.abc import Callable
from tkinter import ttk
from typing import Any

from lpr.logging_conf import setup_logging
from lpr.ui.client import DEFAULT_BASE_URL, EventStream, LprApiError, LprClient
from lpr.ui.license_dialog import LicenseDialog, format_license_state
from lpr.ui.views import (
    COL_BG,
    TTKBOOTSTRAP_AVAILABLE,
    TXT_APP_TITLE,
    CameraPane,
    HistoryWindow,
    LoginView,
    MainView,
    PlatesWindow,
    apply_style,
    configure_styles,
)

logger = logging.getLogger(__name__)

__all__ = ["LprApp", "build_parser", "main"]

#: Tk main-loop polling interval for the UI queue, in milliseconds.
DRAIN_INTERVAL_MS = 50
#: How often the status poller asks the API for camera/pipeline state.
STATUS_POLL_S = 2.0
#: Backoff between MJPEG reconnect attempts.
STREAM_RETRY_S = 3.0
#: Skip frame delivery when the UI queue is this far behind (slow machine).
UI_QUEUE_HIGH_WATER = 60

try:
    from PIL import Image  # type: ignore[import-not-found]

    PIL_AVAILABLE = True
except Exception:  # pragma: no cover - panes fall back to a text placeholder
    Image = None  # type: ignore[assignment]
    PIL_AVAILABLE = False


def _format_uptime(seconds: float) -> str:
    total = max(0, int(seconds))
    return f"{total // 3600:02d}:{(total % 3600) // 60:02d}:{total % 60:02d}"


def _activity_text(data: dict[str, Any]) -> str:
    """One status-bar line describing a live telemetry event."""
    camera = str(data.get("camera", "?"))
    plate = str(data.get("plate", "") or "?")
    if data.get("kind") == "vote":
        votes = data.get("votes", 0)
        needed = data.get("needed", 0)
        state = "onaylandı" if data.get("confirmed") else f"{votes}/{needed} oy"
        return f"{camera}: {plate} - {state}"
    confidence = data.get("confidence")
    suffix = f" ({float(confidence):.0%})" if isinstance(confidence, (int, float)) else ""
    return f"{camera}: {plate} okundu{suffix}"


def _create_root(theme: str) -> tk.Tk:
    """Themed root window when ttkbootstrap is installed, plain Tk otherwise."""
    if TTKBOOTSTRAP_AVAILABLE:
        try:
            import ttkbootstrap as tb  # type: ignore[import-not-found]

            return tb.Window(themename=theme)
        except Exception:  # pragma: no cover - broken theme name / no X display
            logger.warning("ttkbootstrap teması yüklenemedi, standart tema kullanılıyor")
    return tk.Tk()


class LprApp:
    """Controller: owns the client, the worker threads and the Tk main loop."""

    def __init__(
        self,
        api_url: str = DEFAULT_BASE_URL,
        *,
        theme: str = "darkly",
        client: LprClient | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.client = client or LprClient(self.api_url)
        self._ui_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._events: EventStream | None = None

        self._started_at = time.monotonic()
        self._last_uptime_second = -1
        self._paused = False
        self._fullscreen = False
        self._offline = False
        self._plates_window: PlatesWindow | None = None
        self._history_window: HistoryWindow | None = None
        self._license: dict[str, Any] = {}
        self._license_locked = False
        self._license_dialog: LicenseDialog | None = None

        self.root = _create_root(theme)
        self.root.title(f"{TXT_APP_TITLE} - {self.api_url}")
        self.root.geometry("1280x820")
        self.root.minsize(960, 640)
        configure_styles(self.root)
        try:
            # Keeps the dark surface behind the dashboard right out to the
            # window edge, including the plain-Tk fallback root.
            self.root.configure(background=COL_BG)
        except tk.TclError:  # pragma: no cover - exotic window manager
            pass

        self.root.bind("<F11>", self._on_f11)
        self.root.bind("<Escape>", self._on_escape)
        self.root.protocol("WM_DELETE_WINDOW", self.shutdown)

        self._container = ttk.Frame(self.root)
        apply_style(self._container, "Surface.TFrame")
        self._container.pack(fill="both", expand=True)
        self.login_view: LoginView | None = None
        self.main_view: MainView | None = None
        self._show_login()

    # ------------------------------------------------------------------
    # Thread -> UI hand-off
    # ------------------------------------------------------------------

    def _post(self, kind: str, payload: Any = None) -> None:
        """The ONLY way a worker thread may reach the UI."""
        self._ui_queue.put((kind, payload))

    def _spawn(self, name: str, target: Callable[[], None]) -> threading.Thread:
        thread = threading.Thread(target=target, name=name, daemon=True)
        self._threads.append(thread)
        thread.start()
        return thread

    def _call_api(
        self,
        func: Callable[[], Any],
        ok_kind: str,
        *,
        error_kind: str = "toast",
        name: str = "lpr-api-call",
    ) -> None:
        """Run one API call off the UI thread and post its outcome."""

        def work() -> None:
            try:
                result = func()
            except LprApiError as exc:
                self._post(error_kind, str(exc))
                return
            except Exception as exc:  # pragma: no cover - unexpected client bug
                logger.exception("Beklenmeyen istemci hatası")
                self._post(error_kind, str(exc))
                return
            self._post(ok_kind, result)

        self._spawn(name, work)

    # ------------------------------------------------------------------
    # Screens
    # ------------------------------------------------------------------

    def _clear_container(self) -> None:
        for child in self._container.winfo_children():
            child.destroy()
        self.login_view = None
        self.main_view = None

    def _show_login(self) -> None:
        self._clear_container()
        self.login_view = LoginView(self._container, self._on_login_submit)
        self.login_view.pack(expand=True)

    def _show_main(self) -> None:
        self._clear_container()
        self.main_view = MainView(
            self._container,
            {
                "toggle_pause": self.toggle_pause,
                "toggle_fullscreen": self.toggle_fullscreen,
                "open_plates": self.open_plates,
                "open_history": self.open_history,
                "open_gate": self.open_gate,
                "logout": self.logout,
                "apply_source": self.apply_camera_source,
                "open_license": self.open_license,
            },
        )
        self.main_view.pack(fill="both", expand=True)
        self.main_view.set_user(self.client.username or "", self.client.role or "")
        self._started_at = time.monotonic()
        if self._license:
            # A re-login must not hand back an unlocked UI on an expired site.
            self._apply_license(self._license, force=True)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _on_login_submit(self, username: str, password: str, register: bool) -> None:
        def work() -> None:
            try:
                if register:
                    self.client.register(username, password)
                else:
                    self.client.login(username, password)
            except LprApiError as exc:
                if register and exc.status_code in (401, 403):
                    self._post(
                        "login_error",
                        "Sistemde zaten kullanıcı var. Yeni hesabı bir yönetici oluşturmalı.",
                    )
                elif exc.is_offline:
                    self._post("login_error", f"Sunucuya ulaşılamıyor: {self.api_url}")
                else:
                    self._post("login_error", str(exc))
                return
            except Exception as exc:  # pragma: no cover - unexpected client bug
                logger.exception("Oturum açma başarısız")
                self._post("login_error", str(exc))
                return
            self._post("login_ok", None)

        self._spawn("lpr-login", work)

    def _on_login_ok(self) -> None:
        logger.info("Oturum açıldı: %s", self.client.username)
        self._show_main()
        self._start_workers()

    def logout(self) -> None:
        self._stop_workers()
        self.client.logout()
        for window in (self._plates_window, self._history_window, self._license_dialog):
            if window is not None:
                try:
                    window.destroy()
                except Exception:  # pragma: no cover - already gone
                    pass
        self._plates_window = None
        self._history_window = None
        self._license_dialog = None
        self._license_locked = False
        self._show_login()

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def _start_workers(self) -> None:
        self._stop.clear()
        self._threads = []
        for role in ("entry", "exit"):
            self._spawn(f"lpr-stream-{role}", lambda role=role: self._stream_worker(role))
        self._spawn("lpr-status", self._status_worker)

        self._events = self.client.event_stream()
        self._events.start()

    def _stop_workers(self) -> None:
        self._stop.set()
        if self._events is not None:
            self._events.stop()
            self._events = None
        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=0.2)
        self._threads = []

    def _stream_worker(self, role: str) -> None:
        """Read MJPEG frames forever, decoding to PIL off the UI thread."""
        while not self._stop.is_set():
            try:
                for jpeg in self.client.mjpeg_frames(role):
                    if self._stop.is_set():
                        break
                    if self._ui_queue.qsize() > UI_QUEUE_HIGH_WATER:
                        continue  # UI cannot keep up; drop rather than queue
                    if not PIL_AVAILABLE:
                        continue
                    try:
                        image = Image.open(io.BytesIO(jpeg))
                        image.load()
                    except Exception:
                        continue  # a truncated frame is not worth a log line
                    self._post("frame", (role, image))
            except LprApiError as exc:
                logger.debug("Görüntü akışı hatası (%s): %s", role, exc)
                self._post("camera_offline", role)
            except Exception:  # pragma: no cover - defensive
                logger.debug("Görüntü akışı beklenmedik hata (%s)", role, exc_info=True)
                self._post("camera_offline", role)
            if self._stop.wait(STREAM_RETRY_S):
                break

    def _status_worker(self) -> None:
        """Poll cameras + stats so the badges and counters stay honest."""
        while not self._stop.is_set():
            try:
                cameras = self.client.cameras()
                stats = self.client.stats()
                license_info = self.client.license_status()
            except LprApiError as exc:
                self._post("offline", str(exc))
            except Exception:  # pragma: no cover - defensive
                logger.debug("Durum sorgusu başarısız", exc_info=True)
                self._post("offline", "Durum bilgisi alınamadı")
            else:
                self._post("online", None)
                self._post("cameras", cameras)
                self._post("stats", stats)
                self._post("license", license_info)
            if self._stop.wait(STATUS_POLL_S):
                break

    # ------------------------------------------------------------------
    # Toolbar actions (all delegate to a worker thread)
    # ------------------------------------------------------------------

    def toggle_pause(self) -> None:
        target = not self._paused
        self._call_api(
            (self.client.pause if target else self.client.resume),
            "paused",
            name="lpr-pause",
        )

    def toggle_fullscreen(self) -> None:
        self._fullscreen = not self._fullscreen
        try:
            self.root.attributes("-fullscreen", self._fullscreen)
        except tk.TclError:  # pragma: no cover - window manager without support
            logger.debug("Tam ekran desteklenmiyor")

    def _on_f11(self, _event: Any = None) -> str:
        self.toggle_fullscreen()
        return "break"

    def _on_escape(self, _event: Any = None) -> str:
        if self._fullscreen:
            self._fullscreen = False
            try:
                self.root.attributes("-fullscreen", False)
            except tk.TclError:  # pragma: no cover
                pass
        return "break"

    def open_gate(self) -> None:
        self._call_api(self.client.trigger_relay, "gate_opened", name="lpr-relay")

    def apply_camera_source(self, role: str, source: str) -> None:
        if not source:
            return
        self._call_api(
            lambda: self.client.set_camera_source(role, source),
            "source_applied",
            name=f"lpr-source-{role}",
        )

    # -- licence --------------------------------------------------------

    def open_license(self) -> None:
        """Show the licence dialog, raising the existing one if it is open."""
        if self._license_dialog is not None and self._license_dialog.winfo_exists():
            self._license_dialog.lift()
            return
        self._license_dialog = LicenseDialog(
            self.root,
            self.submit_license,
            message=format_license_state(self._license),
            on_close=self._on_license_dialog_closed,
        )

    def _on_license_dialog_closed(self) -> None:
        self._license_dialog = None

    def submit_license(self, key: str) -> None:
        """Send a key to the server; the answer comes back through the queue."""

        def work() -> None:
            try:
                info = self.client.activate_license(key)
            except LprApiError as exc:
                self._post("license_result", (False, str(exc), None))
                return
            except Exception as exc:  # pragma: no cover - unexpected client bug
                logger.exception("Lisans etkinleştirme başarısız")
                self._post("license_result", (False, str(exc), None))
                return
            self._post("license_result", (True, "", info))

        self._spawn("lpr-license", work)

    def _apply_license(self, info: dict[str, Any], *, force: bool = False) -> None:
        """Mirror the server's licence state onto the widgets. Main thread only."""
        view = self.main_view
        if view is None:
            return

        self._license = dict(info or {})
        valid = bool(self._license.get("valid"))
        view.set_license_text(format_license_state(self._license), valid)

        locked = not valid
        if locked == self._license_locked and not force:
            return

        self._license_locked = locked
        view.set_license_locked(locked, str(self._license.get("detail") or ""))

        if locked:
            logger.warning("Lisans geçersiz: arayüz kilitlendi (%s)", self._license.get("reason"))
            self.open_license()
            if self._license_dialog is not None:
                self._license_dialog.set_state_text(format_license_state(self._license))
        elif self._license_dialog is not None and self._license_dialog.winfo_exists():
            self._license_dialog.set_result(True)

    # -- plates window --------------------------------------------------

    def open_plates(self) -> None:
        if self._plates_window is not None and self._plates_window.winfo_exists():
            self._plates_window.lift()
            self.refresh_plates()
            return
        self._plates_window = PlatesWindow(
            self.root,
            {
                "refresh": self.refresh_plates,
                "add": self.add_plate,
                "remove": self.remove_plate,
            },
        )
        self.refresh_plates()

    def refresh_plates(self) -> None:
        self._call_api(self.client.list_plates, "plates", name="lpr-plates")

    def add_plate(self, plate: str, note: str | None = None) -> None:
        def work() -> None:
            try:
                self.client.add_plate(plate, note)
            except LprApiError as exc:
                self._post("plates_status", str(exc))
                return
            self._post("plates_status", f"{plate} eklendi.")
            try:
                self._post("plates", self.client.list_plates())
            except LprApiError as exc:  # pragma: no cover - transient
                self._post("plates_status", str(exc))

        self._spawn("lpr-plate-add", work)

    def remove_plate(self, plate: str) -> None:
        def work() -> None:
            try:
                self.client.remove_plate(plate)
            except LprApiError as exc:
                self._post("plates_status", str(exc))
                return
            self._post("plates_status", f"{plate} silindi.")
            try:
                self._post("plates", self.client.list_plates())
            except LprApiError as exc:  # pragma: no cover - transient
                self._post("plates_status", str(exc))

        self._spawn("lpr-plate-remove", work)

    # -- history window -------------------------------------------------

    def open_history(self) -> None:
        if self._history_window is not None and self._history_window.winfo_exists():
            self._history_window.lift()
            return
        self._history_window = HistoryWindow(self.root, {"load": self.load_history})
        self._call_api(self.client.log_dates, "history_dates", name="lpr-log-dates")

    def load_history(self, day: str) -> None:
        self._call_api(
            lambda: self.client.logs(since=day, until=day, limit=1000),
            "history_events",
            name="lpr-history",
        )

    # ------------------------------------------------------------------
    # The single UI-mutating loop
    # ------------------------------------------------------------------

    def _drain(self) -> None:
        """Main-thread pump: the only function that writes to widgets."""
        try:
            while True:
                kind, payload = self._ui_queue.get_nowait()
                try:
                    self._handle(kind, payload)
                except Exception:  # pragma: no cover - never kill the pump
                    logger.exception("Arayüz mesajı işlenemedi: %s", kind)
        except queue.Empty:
            pass

        if self._events is not None:
            for message in self._events.poll():
                # Each event is dispatched as its own `after(0, ...)` callback
                # rather than applied inline: one malformed or slow event
                # cannot then stall the rest of the pump, and every widget
                # write is an independently scheduled main-thread task.
                #
                # Scheduling happens *here*, on the Tk thread, and never from
                # the stream's asyncio thread. Tk's `after` is not safe to call
                # from a foreign thread -- it touches the Tcl interpreter --
                # so the queue hand-off in EventStream.poll() is what makes
                # this thread-safe. Calling root.after directly from the
                # reader would be the bug this design avoids.
                self.root.after(0, self._dispatch_event, message)

        self._tick_uptime()
        self.root.after(DRAIN_INTERVAL_MS, self._drain)

    def _dispatch_event(self, message: dict[str, Any]) -> None:
        """Apply one stream event to the widgets. Always on the Tk thread."""
        try:
            self._handle_event(message)
        except Exception:  # pragma: no cover - never kill the pump
            logger.exception("Olay işlenemedi")

    def _tick_uptime(self) -> None:
        if self.main_view is None:
            return
        elapsed = time.monotonic() - self._started_at
        second = int(elapsed)
        if second != self._last_uptime_second:
            self._last_uptime_second = second
            self.main_view.set_uptime(_format_uptime(elapsed))

    def _handle(self, kind: str, payload: Any) -> None:
        if kind == "login_ok":
            self._on_login_ok()
            return
        if kind == "login_error":
            if self.login_view is not None:
                self.login_view.set_busy(False)
                self.login_view.clear_password()
                self.login_view.show_error(str(payload))
            return

        view = self.main_view
        if view is None:
            return

        if kind == "frame":
            if self._license_locked:
                # Belt and braces: the pane ignores frames while locked, and
                # they are dropped here too so nothing is decoded for a view
                # that will not render it.
                return
            role, image = payload
            pane: CameraPane | None = view.panes.get(role)
            if pane is not None:
                pane.set_image(image)
                pane.set_connected(True)
        elif kind == "camera_offline":
            pane = view.panes.get(str(payload))
            if pane is not None:
                pane.clear_image()
                pane.set_connected(False)
        elif kind == "cameras":
            view.set_cameras(list(payload or []))
        elif kind == "stats":
            view.set_stats(dict(payload or {}))
        elif kind == "offline":
            self._offline = True
            view.set_banner(True)
        elif kind == "online":
            if self._offline:
                self._offline = False
            view.set_banner(False)
        elif kind == "license":
            self._apply_license(dict(payload or {}))
        elif kind == "license_result":
            ok, message, info = payload
            if self._license_dialog is not None and self._license_dialog.winfo_exists():
                self._license_dialog.set_result(bool(ok), str(message))
            if ok and isinstance(info, dict):
                self._apply_license(info)
        elif kind == "paused":
            self._paused = bool(payload)
            view.set_paused(self._paused)
        elif kind == "gate_opened":
            view.set_banner(False)
            logger.info("Kapı elle açıldı")
        elif kind == "source_applied":
            view.set_cameras([dict(payload)] if isinstance(payload, dict) else [])
        elif kind == "toast":
            logger.info("Uyarı: %s", payload)
            view.set_banner(True, str(payload))
        elif kind == "plates":
            if self._plates_window is not None and self._plates_window.winfo_exists():
                self._plates_window.set_plates([str(p) for p in payload or []])
        elif kind == "plates_status":
            if self._plates_window is not None and self._plates_window.winfo_exists():
                self._plates_window.set_status(str(payload))
        elif kind == "history_dates":
            if self._history_window is not None and self._history_window.winfo_exists():
                self._history_window.set_dates([str(d) for d in payload or []])
        elif kind == "history_events":
            if self._history_window is not None and self._history_window.winfo_exists():
                self._history_window.set_events(list(payload or []))

    def _handle_event(self, message: dict[str, Any]) -> None:
        """Handle one decoded WebSocket message (main thread)."""
        view = self.main_view
        if view is None:
            return
        kind = message.get("type")
        if kind == "event":
            data = message.get("data")
            if isinstance(data, dict):
                view.log_pane.add_event(data)
        elif kind == "telemetry":
            # Reads and votes in progress: shown as live activity, never added
            # to the log table -- nothing here is a recorded decision.
            data = message.get("data")
            if isinstance(data, dict):
                view.set_activity(_activity_text(data))
        elif kind == "license":
            # Pushed the moment the server's watchdog sees the state flip, so
            # the UI locks without waiting for the next status poll.
            data = message.get("license")
            if isinstance(data, dict):
                self._apply_license(data)
        elif kind == "camera_status":
            cameras = message.get("cameras")
            if isinstance(cameras, list):
                view.set_cameras(cameras)
        elif kind == "status":
            connected = bool(message.get("connected"))
            if connected:
                view.set_banner(False)
            else:
                view.set_banner(True, "Olay akışı koptu - yeniden bağlanılıyor...")
        elif kind == "error":
            view.set_banner(True, str(message.get("detail", "")))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self) -> None:
        self.root.after(DRAIN_INTERVAL_MS, self._drain)
        try:
            self.root.mainloop()
        finally:
            self._stop_workers()

    def shutdown(self) -> None:
        logger.info("Arayüz kapatılıyor")
        self._stop_workers()
        try:
            self.root.destroy()
        except Exception:  # pragma: no cover - already destroyed
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lpr-gui",
        description="Plaka Tanıma Sistemi masaüstü istemcisi",
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_BASE_URL,
        help=f"lpr-api adresi (varsayılan: {DEFAULT_BASE_URL})",
    )
    parser.add_argument("--theme", default="darkly", help="ttkbootstrap teması")
    parser.add_argument("--log-level", default="INFO", help="Günlük seviyesi")
    parser.add_argument("--fullscreen", action="store_true", help="Tam ekran olarak başlat")
    return parser


def main(argv: list[str] | None = None) -> int:
    """``lpr-gui`` console-script entry point."""
    args = build_parser().parse_args(argv)
    setup_logging(level=args.log_level, json=False)
    logger.info("Masaüstü istemci başlatılıyor (%s)", args.api_url)

    try:
        app = LprApp(args.api_url, theme=args.theme)
    except tk.TclError as exc:
        # No display (headless server, SSH without X forwarding).
        logger.error("Grafik arayüz başlatılamadı: %s", exc)
        return 2

    if args.fullscreen:
        app.toggle_fullscreen()
    app.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
