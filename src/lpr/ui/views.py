"""Tkinter widgets for the LPR desktop client.

Everything in this module is *passive*: widgets render what they are given and
report user intent through injected callbacks. They never perform I/O, never
import :mod:`lpr.ui.client` and never spawn threads. All network work belongs
to :mod:`lpr.ui.app`, which is also the only place that mutates these widgets
-- and only from the Tk main thread.

That split is the fix for the legacy application's central bug, where capture
and database threads called ``widget.config(...)`` directly and produced
sporadic ``RuntimeError: main thread is not in main loop`` crashes.
"""

from __future__ import annotations

import importlib.util
import logging
import tkinter as tk
from collections.abc import Callable, Iterable, Sequence
from tkinter import ttk
from typing import Any

logger = logging.getLogger(__name__)

# ttkbootstrap is part of the optional "gui" extra. Detected without importing
# it, so this module stays importable (and testable) on a bare install.
TTKBOOTSTRAP_AVAILABLE = importlib.util.find_spec("ttkbootstrap") is not None

try:
    from PIL import Image, ImageTk  # type: ignore[import-not-found]

    PIL_AVAILABLE = True
except Exception:  # pragma: no cover - camera panes degrade to a text placeholder
    Image = None  # type: ignore[assignment]
    ImageTk = None  # type: ignore[assignment]
    PIL_AVAILABLE = False
    logger.warning(
        "Pillow (PIL.ImageTk) bulunamadı: kamera panelleri görüntü yerine metin "
        "gösterecek. Kurulum: pip install -e '.[gui]'"
    )

__all__ = [
    "CameraPane",
    "HistoryWindow",
    "LogPane",
    "LoginView",
    "MainView",
    "PlatesWindow",
    "TTKBOOTSTRAP_AVAILABLE",
    "configure_styles",
]

# -- Turkish UI strings -----------------------------------------------------

TXT_APP_TITLE = "Plaka Tanıma Sistemi"
TXT_LOGIN_TITLE = "Oturum Açın"
TXT_FIRST_USER_TITLE = "İlk Kullanıcıyı Oluşturun"
TXT_FIRST_USER_HINT = (
    "Sistemde kayıtlı kullanıcı yok. Oluşturacağınız ilk hesap yönetici olacaktır."
)
TXT_USERNAME = "Kullanıcı Adı"
TXT_PASSWORD = "Parola"
TXT_LOGIN = "Giriş Yap"
TXT_REGISTER = "Kaydol"
TXT_ENTRY = "Giriş"
TXT_EXIT = "Çıkış"
TXT_CONNECTED = "Bağlı"
TXT_DISCONNECTED = "Bağlı Değil"
TXT_LIVE_LOG = "Canlı Kayıt"
TXT_HISTORY = "Geçmiş Kayıtlar"
TXT_PLATES = "Plakalar"
TXT_PAUSE = "Duraklat"
TXT_RESUME = "Devam Et"
TXT_FULLSCREEN = "Tam Ekran (F11)"
TXT_OPEN_GATE = "Bariyeri Aç"
TXT_LOGOUT = "Oturumu Kapat"
TXT_UPTIME = "Çalışma Süresi"
TXT_SOURCE = "Kaynak"
TXT_APPLY = "Uygula"
TXT_ADD = "Ekle"
TXT_REMOVE = "Sil"
TXT_REFRESH = "Yenile"
TXT_DATE = "Tarih"
TXT_NO_SIGNAL = "Görüntü yok"
TXT_OFFLINE_BANNER = "Sunucuya bağlanılamıyor - yeniden deneniyor..."
TXT_CLOSE = "Kapat"
TXT_NOTE = "Not"

_LOG_COLUMNS = (
    ("ts", "Zaman", 150),
    ("camera", "Kamera", 80),
    ("plate", "Plaka", 130),
    ("action", "Durum", 100),
    ("confidence", "Güven", 70),
)

_ACTION_LABELS = {
    "granted": "İzİN VERİLDİ",
    "denied": "REDDEDİLDİ",
    "detected": "TESPİT",
    "cooldown": "BEKLEMEDE",
    "error": "HATA",
}

_CAMERA_LABELS = {"entry": TXT_ENTRY, "exit": TXT_EXIT}


def configure_styles(root: tk.Misc) -> ttk.Style:
    """Register the handful of custom styles the views rely on.

    Works with or without ttkbootstrap: only plain ``ttk.Style`` features are
    used, so a machine without the theme package still gets readable badges.
    """
    style = ttk.Style(root)
    style.configure("Badge.Ok.TLabel", foreground="#0f7b3f", font=("", 10, "bold"))
    style.configure("Badge.Bad.TLabel", foreground="#b3261e", font=("", 10, "bold"))
    style.configure("Banner.TLabel", foreground="#ffffff", background="#b3261e")
    style.configure("Title.TLabel", font=("", 16, "bold"))
    style.configure("Mono.TLabel", font=("TkFixedFont", 10))
    return style


def _action_label(action: str) -> str:
    return _ACTION_LABELS.get(action, action.upper())


def _camera_label(camera: str) -> str:
    return _CAMERA_LABELS.get(camera, camera)


def _event_row(event: dict[str, Any]) -> tuple[str, ...]:
    confidence = event.get("confidence") or 0.0
    try:
        confidence_text = f"{float(confidence) * 100:.0f}%"
    except (TypeError, ValueError):
        confidence_text = "-"
    return (
        str(event.get("ts", "")).replace("T", " ").replace("+00:00", ""),
        _camera_label(str(event.get("camera", ""))),
        str(event.get("plate", "")),
        _action_label(str(event.get("action", ""))),
        confidence_text,
    )


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


class LoginView(ttk.Frame):
    """Credentials screen, doubling as the first-user bootstrap form."""

    def __init__(
        self,
        master: tk.Misc,
        on_submit: Callable[[str, str, bool], None],
        **kwargs: Any,
    ) -> None:
        super().__init__(master, padding=32, **kwargs)
        self._on_submit = on_submit
        self._register_mode = False

        self._title = ttk.Label(self, text=TXT_LOGIN_TITLE, style="Title.TLabel")
        self._title.grid(row=0, column=0, columnspan=2, pady=(0, 4))

        self._hint = ttk.Label(self, text="", wraplength=380, justify="center")
        self._hint.grid(row=1, column=0, columnspan=2, pady=(0, 16))

        ttk.Label(self, text=TXT_USERNAME).grid(row=2, column=0, sticky="w", pady=4)
        self._username = ttk.Entry(self, width=28)
        self._username.grid(row=2, column=1, pady=4, padx=(8, 0))

        ttk.Label(self, text=TXT_PASSWORD).grid(row=3, column=0, sticky="w", pady=4)
        self._password = ttk.Entry(self, width=28, show="*")
        self._password.grid(row=3, column=1, pady=4, padx=(8, 0))

        self._error = ttk.Label(self, text="", style="Badge.Bad.TLabel", wraplength=380)
        self._error.grid(row=4, column=0, columnspan=2, pady=(12, 4))

        buttons = ttk.Frame(self)
        buttons.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        buttons.columnconfigure(0, weight=1)
        buttons.columnconfigure(1, weight=1)
        self._login_button = ttk.Button(
            buttons, text=TXT_LOGIN, command=lambda: self._submit(False)
        )
        self._login_button.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self._register_button = ttk.Button(
            buttons, text=TXT_REGISTER, command=lambda: self._submit(True)
        )
        self._register_button.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        self._username.bind("<Return>", lambda _event: self._password.focus_set())
        self._password.bind("<Return>", lambda _event: self._submit(self._register_mode))
        self.after(100, self._username.focus_set)

    # -- state (main thread only) ---------------------------------------

    def set_first_user(self, first_user: bool) -> None:
        """Switch between the login and the initial-registration wording.

        On a fresh installation there is nobody to log in as, so the login
        button is hidden and only the (admin-creating) registration remains.
        """
        self._register_mode = first_user
        self._title.configure(text=TXT_FIRST_USER_TITLE if first_user else TXT_LOGIN_TITLE)
        self._hint.configure(text=TXT_FIRST_USER_HINT if first_user else "")
        if first_user:
            self._login_button.grid_remove()
        else:
            self._login_button.grid()

    def set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self._login_button.configure(state=state)
        self._register_button.configure(state=state)

    def show_error(self, message: str) -> None:
        self._error.configure(text=message)

    def clear_password(self) -> None:
        self._password.delete(0, tk.END)

    def _submit(self, register: bool) -> None:
        username = self._username.get().strip()
        password = self._password.get()
        if not username or not password:
            self.show_error("Kullanıcı adı ve parola zorunludur.")
            return
        self.show_error("")
        self.set_busy(True)
        self._on_submit(username, password, register)


# ---------------------------------------------------------------------------
# Camera pane
# ---------------------------------------------------------------------------


class CameraPane(ttk.Labelframe):
    """One live camera view: image, connection badge and editable source."""

    def __init__(
        self,
        master: tk.Misc,
        role: str,
        title: str,
        on_source_apply: Callable[[str, str], None],
        **kwargs: Any,
    ) -> None:
        super().__init__(master, text=title, padding=8, **kwargs)
        self.role = role
        self._on_source_apply = on_source_apply
        self._photo: Any = None  # keeps the PhotoImage alive

        header = ttk.Frame(self)
        header.pack(fill="x")
        self._badge = ttk.Label(header, text=TXT_DISCONNECTED, style="Badge.Bad.TLabel")
        self._badge.pack(side="right")
        self._fps = ttk.Label(header, text="")
        self._fps.pack(side="left")

        self._canvas = ttk.Label(
            self, text=TXT_NO_SIGNAL, anchor="center", background="#101318", foreground="#8a8f98"
        )
        self._canvas.pack(fill="both", expand=True, pady=8)

        controls = ttk.Frame(self)
        controls.pack(fill="x")
        ttk.Label(controls, text=f"{TXT_SOURCE}:").pack(side="left")
        self._source = ttk.Entry(controls)
        self._source.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(controls, text=TXT_APPLY, command=self._apply_source).pack(side="left")
        self._source.bind("<Return>", lambda _event: self._apply_source())

    # -- state (main thread only) ---------------------------------------

    def set_connected(self, connected: bool, fps: float = 0.0) -> None:
        self._badge.configure(
            text=TXT_CONNECTED if connected else TXT_DISCONNECTED,
            style="Badge.Ok.TLabel" if connected else "Badge.Bad.TLabel",
        )
        self._fps.configure(text=f"{fps:.1f} FPS" if connected and fps else "")

    def set_source(self, source: str) -> None:
        if self._source is self.focus_get():
            return  # never fight the operator's cursor
        current = self._source.get()
        if current != source:
            self._source.delete(0, tk.END)
            self._source.insert(0, source)

    def set_image(self, pil_image: Any) -> None:
        """Render a PIL image, scaled to the pane's current size."""
        if not PIL_AVAILABLE or pil_image is None:
            return
        width = max(160, self._canvas.winfo_width())
        height = max(120, self._canvas.winfo_height())
        try:
            scaled = self._fit(pil_image, width, height)
            self._photo = ImageTk.PhotoImage(scaled)
            self._canvas.configure(image=self._photo, text="")
        except Exception:  # pragma: no cover - Tk image failure
            logger.debug("Kare gösterilemedi", exc_info=True)

    def clear_image(self) -> None:
        self._photo = None
        self._canvas.configure(image="", text=TXT_NO_SIGNAL)

    @staticmethod
    def _fit(pil_image: Any, width: int, height: int) -> Any:
        source_w, source_h = pil_image.size
        if not source_w or not source_h:
            return pil_image
        ratio = min(width / source_w, height / source_h)
        ratio = max(ratio, 0.05)
        target = (max(1, int(source_w * ratio)), max(1, int(source_h * ratio)))
        resample = getattr(getattr(Image, "Resampling", Image), "BILINEAR", 2)
        return pil_image.resize(target, resample)

    def _apply_source(self) -> None:
        self._on_source_apply(self.role, self._source.get().strip())


# ---------------------------------------------------------------------------
# Log panes
# ---------------------------------------------------------------------------


class LogPane(ttk.Labelframe):
    """Scrolling table of events. Newest first, bounded in size."""

    def __init__(
        self, master: tk.Misc, title: str = TXT_LIVE_LOG, max_rows: int = 500, **kwargs: Any
    ) -> None:
        super().__init__(master, text=title, padding=8, **kwargs)
        self.max_rows = max_rows

        self.tree = ttk.Treeview(
            self, columns=[c[0] for c in _LOG_COLUMNS], show="headings", height=10
        )
        for key, heading, width in _LOG_COLUMNS:
            self.tree.heading(key, text=heading)
            self.tree.column(key, width=width, anchor="w", stretch=True)
        self.tree.tag_configure("granted", foreground="#0f7b3f")
        self.tree.tag_configure("denied", foreground="#b3261e")

        scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def add_event(self, event: dict[str, Any]) -> None:
        action = str(event.get("action", ""))
        self.tree.insert("", 0, values=_event_row(event), tags=(action,))
        children = self.tree.get_children()
        if len(children) > self.max_rows:
            for item in children[self.max_rows :]:
                self.tree.delete(item)

    def set_events(self, events: Iterable[dict[str, Any]]) -> None:
        self.clear()
        for event in events:
            self.tree.insert(
                "", "end", values=_event_row(event), tags=(str(event.get("action", "")),)
            )

    def clear(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)


# ---------------------------------------------------------------------------
# Main window body
# ---------------------------------------------------------------------------


class MainView(ttk.Frame):
    """Toolbar + two camera panes + live log + status bar."""

    def __init__(
        self,
        master: tk.Misc,
        callbacks: dict[str, Callable[..., Any]],
        **kwargs: Any,
    ) -> None:
        super().__init__(master, padding=8, **kwargs)
        self._callbacks = callbacks

        # -- toolbar ----------------------------------------------------
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x")

        self._pause_button = ttk.Button(
            toolbar, text=TXT_PAUSE, command=lambda: self._call("toggle_pause")
        )
        self._pause_button.pack(side="left", padx=(0, 6))
        ttk.Button(toolbar, text=TXT_PLATES, command=lambda: self._call("open_plates")).pack(
            side="left", padx=6
        )
        ttk.Button(toolbar, text=TXT_HISTORY, command=lambda: self._call("open_history")).pack(
            side="left", padx=6
        )
        ttk.Button(toolbar, text=TXT_OPEN_GATE, command=lambda: self._call("open_gate")).pack(
            side="left", padx=6
        )
        ttk.Button(
            toolbar, text=TXT_FULLSCREEN, command=lambda: self._call("toggle_fullscreen")
        ).pack(side="left", padx=6)
        ttk.Button(toolbar, text=TXT_LOGOUT, command=lambda: self._call("logout")).pack(
            side="right"
        )

        # -- offline banner --------------------------------------------
        self._banner = ttk.Label(
            self, text=TXT_OFFLINE_BANNER, style="Banner.TLabel", anchor="center", padding=6
        )
        # Packed/forgotten dynamically by set_banner().

        # -- camera panes ----------------------------------------------
        cameras = ttk.Frame(self)
        self._cameras_frame = cameras
        cameras.pack(fill="both", expand=True, pady=8)
        cameras.columnconfigure(0, weight=1, uniform="cam")
        cameras.columnconfigure(1, weight=1, uniform="cam")
        cameras.rowconfigure(0, weight=1)

        on_source = self._callbacks.get("apply_source", lambda *_: None)
        self.panes: dict[str, CameraPane] = {
            "entry": CameraPane(cameras, "entry", TXT_ENTRY, on_source),
            "exit": CameraPane(cameras, "exit", TXT_EXIT, on_source),
        }
        self.panes["entry"].grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self.panes["exit"].grid(row=0, column=1, sticky="nsew", padx=(4, 0))

        # -- live log ---------------------------------------------------
        self.log_pane = LogPane(self)
        self.log_pane.pack(fill="both", expand=True)

        # -- status bar -------------------------------------------------
        status = ttk.Frame(self)
        status.pack(fill="x", pady=(8, 0))
        self._uptime = ttk.Label(status, text=f"{TXT_UPTIME}: 00:00:00", style="Mono.TLabel")
        self._uptime.pack(side="left")
        self._user = ttk.Label(status, text="")
        self._user.pack(side="left", padx=16)
        # Live activity: what the pipeline is doing *right now* (a plate being
        # read, votes accumulating). Transient by design -- the durable record
        # is the log table.
        self._activity = ttk.Label(status, text="", style="Mono.TLabel")
        self._activity.pack(side="left", padx=16)
        self._stats = ttk.Label(status, text="", style="Mono.TLabel")
        self._stats.pack(side="right")

    # -- state (main thread only) ---------------------------------------

    def _call(self, name: str, *args: Any) -> None:
        callback = self._callbacks.get(name)
        if callback is not None:
            callback(*args)

    def set_banner(self, visible: bool, message: str = TXT_OFFLINE_BANNER) -> None:
        if visible:
            self._banner.configure(text=message)
            if not self._banner.winfo_ismapped():
                # Slot it between the toolbar and the camera grid.
                self._banner.pack(fill="x", before=self._cameras_frame)
        elif self._banner.winfo_ismapped():
            self._banner.pack_forget()

    def set_paused(self, paused: bool) -> None:
        self._pause_button.configure(text=TXT_RESUME if paused else TXT_PAUSE)

    def set_uptime(self, text: str) -> None:
        self._uptime.configure(text=f"{TXT_UPTIME}: {text}")

    def set_activity(self, text: str) -> None:
        """Show one line of live pipeline activity in the status bar."""
        self._activity.configure(text=text)

    def set_user(self, username: str, role: str) -> None:
        self._user.configure(text=f"{username} ({role})")

    def set_stats(self, stats: dict[str, Any]) -> None:
        self._stats.configure(
            text=(
                f"Okunan: {stats.get('plates_read', 0)}  "
                f"İzin: {stats.get('grants', 0)}  "
                f"Ret: {stats.get('denials', 0)}"
            )
        )

    def set_cameras(self, cameras: Sequence[dict[str, Any]]) -> None:
        seen: set[str] = set()
        for camera in cameras:
            role = str(camera.get("role", ""))
            pane = self.panes.get(role)
            if pane is None:
                continue
            seen.add(role)
            pane.set_connected(bool(camera.get("connected")), float(camera.get("fps") or 0.0))
            pane.set_source(str(camera.get("source", "")))
        for role, pane in self.panes.items():
            if role not in seen:
                pane.set_connected(False)


# ---------------------------------------------------------------------------
# Secondary windows
# ---------------------------------------------------------------------------


class PlatesWindow(tk.Toplevel):
    """Registered-plate management: list, add, remove."""

    def __init__(
        self,
        master: tk.Misc,
        callbacks: dict[str, Callable[..., Any]],
    ) -> None:
        super().__init__(master)
        self.title(f"{TXT_APP_TITLE} - {TXT_PLATES}")
        self.geometry("460x520")
        self.transient(master.winfo_toplevel())
        self._callbacks = callbacks

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)

        entry_row = ttk.Frame(body)
        entry_row.pack(fill="x")
        self._plate_entry = ttk.Entry(entry_row)
        self._plate_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(entry_row, text=TXT_ADD, command=self._add).pack(side="left", padx=(6, 0))
        self._plate_entry.bind("<Return>", lambda _event: self._add())

        note_row = ttk.Frame(body)
        note_row.pack(fill="x", pady=(6, 10))
        ttk.Label(note_row, text=f"{TXT_NOTE}:").pack(side="left")
        self._note_entry = ttk.Entry(note_row)
        self._note_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))

        self.listbox = tk.Listbox(body, activestyle="dotbox")
        scroll = ttk.Scrollbar(body, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scroll.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")

        footer = ttk.Frame(self, padding=(12, 0, 12, 12))
        footer.pack(fill="x")
        ttk.Button(footer, text=TXT_REMOVE, command=self._remove).pack(side="left")
        ttk.Button(footer, text=TXT_REFRESH, command=lambda: self._call("refresh")).pack(
            side="left", padx=6
        )
        self._status = ttk.Label(footer, text="")
        self._status.pack(side="left", padx=12)
        ttk.Button(footer, text=TXT_CLOSE, command=self.destroy).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _call(self, name: str, *args: Any) -> None:
        callback = self._callbacks.get(name)
        if callback is not None:
            callback(*args)

    def _add(self) -> None:
        plate = self._plate_entry.get().strip().upper()
        if not plate:
            return
        note = self._note_entry.get().strip() or None
        self._plate_entry.delete(0, tk.END)
        self._note_entry.delete(0, tk.END)
        self._call("add", plate, note)

    def _remove(self) -> None:
        selection = self.listbox.curselection()
        if not selection:
            self.set_status("Silmek için bir plaka seçin.")
            return
        self._call("remove", self.listbox.get(selection[0]))

    # -- state (main thread only) ---------------------------------------

    def set_plates(self, plates: Sequence[str]) -> None:
        self.listbox.delete(0, tk.END)
        for plate in plates:
            self.listbox.insert(tk.END, plate)
        self.set_status(f"{len(plates)} plaka kayıtlı.")

    def set_status(self, message: str) -> None:
        self._status.configure(text=message)


class HistoryWindow(tk.Toplevel):
    """Historical log viewer with a date picker."""

    def __init__(
        self,
        master: tk.Misc,
        callbacks: dict[str, Callable[..., Any]],
    ) -> None:
        super().__init__(master)
        self.title(f"{TXT_APP_TITLE} - {TXT_HISTORY}")
        self.geometry("820x520")
        self.transient(master.winfo_toplevel())
        self._callbacks = callbacks

        header = ttk.Frame(self, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text=f"{TXT_DATE}:").pack(side="left")
        self.date_var = tk.StringVar()
        self.date_box = ttk.Combobox(header, textvariable=self.date_var, state="readonly", width=16)
        self.date_box.pack(side="left", padx=6)
        self.date_box.bind("<<ComboboxSelected>>", lambda _event: self._load())
        ttk.Button(header, text=TXT_REFRESH, command=self._load).pack(side="left")
        self._status = ttk.Label(header, text="")
        self._status.pack(side="left", padx=12)
        ttk.Button(header, text=TXT_CLOSE, command=self.destroy).pack(side="right")

        self.log_pane = LogPane(self, title=TXT_HISTORY, max_rows=5000)
        self.log_pane.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _load(self) -> None:
        day = self.date_var.get().strip()
        if day:
            callback = self._callbacks.get("load")
            if callback is not None:
                callback(day)

    # -- state (main thread only) ---------------------------------------

    def set_dates(self, dates: Sequence[str]) -> None:
        values = list(dates)
        self.date_box.configure(values=values)
        if values and not self.date_var.get():
            self.date_var.set(values[0])
            self._load()
        if not values:
            self.set_status("Kayıt bulunamadı.")

    def set_events(self, events: Sequence[dict[str, Any]]) -> None:
        self.log_pane.set_events(events)
        self.set_status(f"{len(events)} kayıt.")

    def set_status(self, message: str) -> None:
        self._status.configure(text=message)
