"""Tkinter widgets for the LPR desktop client.

Everything in this module is *passive*: widgets render what they are given and
report user intent through injected callbacks. They never perform I/O, never
import :mod:`lpr.ui.client` and never spawn threads. All network work belongs
to :mod:`lpr.ui.app`, which is also the only place that mutates these widgets
-- and only from the Tk main thread.

That split is the fix for the legacy application's central bug, where capture
and database threads called ``widget.config(...)`` directly and produced
sporadic ``RuntimeError: main thread is not in main loop`` crashes.

Dashboard layout
----------------

:class:`MainView` is a control-room dashboard rather than a stack of grey
frames. Five grid rows, top to bottom::

    row 0  header strip   brand | uptime | operator + link state
    row 1  banner         offline / licence warning (gridded on demand)
    row 2  body           camera cards (3fr) | live plate feed (1fr)
    row 3  telemetry      activity line | counters | licence summary
    row 4  control panel  Bariyeri Aç, Plaka Girişi, Geçmiş, ...

Colours come from :data:`COL_*` and are applied to plain ``tk`` chrome
(frames and labels) so the dark palette holds even when the ttkbootstrap
theme is unavailable. Interactive widgets stay ``ttk`` and carry a
``bootstyle`` when ttkbootstrap has patched the ttk constructors; see
:func:`bootstyle_kwargs`, which drops the keyword on a bare install so this
module keeps importing (and testing) without the optional "gui" extra.

:mod:`lpr.ui.license_dialog` renders into the same dashboard, so the small
shared kit -- the palette, :func:`ui_font`, :func:`mono_font`,
:func:`card_frame`, :func:`caption_label`, :func:`bootstyle_kwargs` and
:func:`set_bootstyle` -- is public rather than module-private.
"""

from __future__ import annotations

import importlib.util
import logging
import re
import sys
import tkinter as tk
from collections.abc import Callable, Iterable, Sequence
from tkinter import font as tkfont
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
    "LivePlateFeed",
    "LogPane",
    "LoginView",
    "MainView",
    "PlatesWindow",
    "TTKBOOTSTRAP_AVAILABLE",
    "bootstyle_kwargs",
    "caption_label",
    "card_frame",
    "configure_styles",
    "mono_font",
    "apply_style",
    "derive_style",
    "set_bootstyle",
    "tk_canvas",
    "tk_frame",
    "tk_label",
    "tk_text",
    "ui_font",
]

# -- Turkish UI strings -----------------------------------------------------

TXT_APP_TITLE = "Plaka Tanıma Sistemi"
TXT_DASHBOARD = "KONTROL PANELİ"
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
TXT_MANUAL_PLATE = "Plaka Girişi"
TXT_PLATE_FIELD = "Plaka"
TXT_PLATES_HINT = (
    "Kameranın okuyamadığı bir aracı elle kaydedin. Kayıtlı plakalara bariyer otomatik açılır."
)
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
TXT_NO_EVENTS = "Henüz plaka okunmadı."
TXT_OFFLINE_BANNER = "Sunucuya bağlanılamıyor - yeniden deneniyor..."
TXT_CLOSE = "Kapat"
TXT_NOTE = "Not"
TXT_LICENSE_LOCKED = "LİSANS SÜRESİ DOLDU"
TXT_LICENSE_BANNER = (
    "Lisans geçersiz - görüntü işleme durduruldu. Yeni bir lisans anahtarı girin."
)
TXT_LICENSE_BUTTON = "Lisans Gir"
TXT_STAT_READ = "OKUNAN"
TXT_STAT_GRANT = "İZİN"
TXT_STAT_DENY = "RET"

# -- Dark control-room palette ---------------------------------------------

#: Window surface behind the cards.
COL_BG = "#10141b"
#: Top header and bottom control panel chrome.
COL_HEADER = "#161c26"
#: Card body.
COL_CARD = "#1a2029"
#: One row inside a card (a plate entry in the live feed).
COL_ROW = "#212936"
#: Video area with nothing to show.
COL_VOID = "#0a0d12"
COL_BORDER = "#2c3542"
COL_TEXT = "#e8ecf3"
COL_MUTED = "#78859a"
COL_OK = "#2ecc71"
COL_BAD = "#ff5c5c"
COL_WARN = "#f0ad4e"
COL_ACCENT = "#4c9aff"

#: Width in pixels of the status stripe down each side of a plate card. It is
#: the horizontal padding of the card's inner frame -- see
#: :meth:`LivePlateFeed._build_card`.
STRIPE_PX = 4

#: Placeholder glyphs. Deliberately BMP symbols rather than emoji: these
#: render in the default Tk font on Linux and Windows, colour emoji do not.
ICON_NO_SIGNAL = "⚠"  # warning sign
ICON_LOCKED = "⊘"  # circled division slash ("no entry")
ICON_BRAND = "◉"  # fisheye

# -- Fonts ------------------------------------------------------------------

_UI_CANDIDATES = ("Segoe UI", "Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans")
_MONO_CANDIDATES = ("Consolas", "DejaVu Sans Mono", "Menlo", "Liberation Mono", "Courier New")

#: Resolved by :func:`configure_styles`, which the controller calls before any
#: view is built. The defaults are what Tk falls back to on a bare X server.
_UI_FAMILY = "Helvetica"
_MONO_FAMILY = "Courier"


def _pick_family(root: tk.Misc, candidates: Sequence[str], fallback: str) -> str:
    """First installed family from *candidates*, or *fallback*."""
    try:
        available = set(tkfont.families(root))
    except Exception:  # pragma: no cover - no display / broken font server
        return fallback
    for name in candidates:
        if name in available:
            return name
    return fallback


def ui_font(size: int = 10, weight: str = "normal") -> tuple[str, int, str]:
    return (_UI_FAMILY, size, weight)


def mono_font(size: int = 10, weight: str = "normal") -> tuple[str, int, str]:
    return (_MONO_FAMILY, size, weight)


# -- ttkbootstrap plumbing --------------------------------------------------


#: Cached answer from :func:`_bootstyle_active`; ``None`` until it is known.
_BOOTSTYLE_SUPPORTED: bool | None = None


def _bootstyle_active() -> bool:
    """True when ``ttk`` widgets accept the ``bootstyle`` keyword.

    ttkbootstrap 1.x installs constructor overrides on every ``tkinter.ttk``
    widget class the moment it is imported, which is what lets this module
    stay on stdlib ttk and still get themed widgets. The controller imports
    it in ``_create_root``, long before any view is built.

    That patching is a 1.x implementation detail rather than a promise, so
    the answer is *probed* (build one throwaway frame with a ``bootstyle``)
    instead of inferred from the import. A release that stopped patching --
    2.x does exactly that -- degrades to plain ttk widgets on the dark
    styles this module configures, rather than raising ``TclError`` out of
    every constructor.
    """
    global _BOOTSTYLE_SUPPORTED
    if _BOOTSTYLE_SUPPORTED is not None:
        return _BOOTSTYLE_SUPPORTED
    if "ttkbootstrap" not in sys.modules or tk._default_root is None:  # type: ignore[attr-defined]
        # Not a verdict yet: ttkbootstrap (or the root) may still arrive.
        return False
    try:
        probe = ttk.Frame(None, bootstyle="secondary")  # type: ignore[call-arg]
    except Exception:
        _BOOTSTYLE_SUPPORTED = False
        logger.info("ttkbootstrap 'bootstyle' desteklemiyor, düz ttk kullanılıyor")
    else:
        probe.destroy()
        _BOOTSTYLE_SUPPORTED = True
    return _BOOTSTYLE_SUPPORTED


#: Cached answer from :func:`_tk_autostyle_patched`; ``None`` until known.
_AUTOSTYLE_SUPPORTED: bool | None = None


def _tk_autostyle_patched() -> bool:
    """True when ttkbootstrap has also wrapped the plain ``tk`` constructors.

    Probed separately from :func:`_bootstyle_active` because it is a distinct
    piece of ttkbootstrap machinery, patching a different set of classes.
    """
    global _AUTOSTYLE_SUPPORTED
    if _AUTOSTYLE_SUPPORTED is not None:
        return _AUTOSTYLE_SUPPORTED
    if "ttkbootstrap" not in sys.modules or tk._default_root is None:  # type: ignore[attr-defined]
        return False
    try:
        probe = tk.Frame(None, autostyle=False)  # type: ignore[call-arg]
    except Exception:
        _AUTOSTYLE_SUPPORTED = False
    else:
        probe.destroy()
        _AUTOSTYLE_SUPPORTED = True
    return _AUTOSTYLE_SUPPORTED


def _no_autostyle(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Opt one plain ``tk`` widget out of ttkbootstrap's re-colouring.

    ttkbootstrap wraps ``tk.Frame``/``Label``/``Text``/``Canvas`` and friends
    so that every instance is repainted in the active theme's flat background
    the moment it is built -- which silently discards the ``bg``/``fg`` this
    module passes, and with them the whole dark palette and the plate cards'
    status stripes. ``autostyle=False`` is ttkbootstrap's own opt-out.
    """
    if _tk_autostyle_patched():
        kwargs["autostyle"] = False
    return kwargs


def tk_frame(master: tk.Misc, **kwargs: Any) -> tk.Frame:
    """A ``tk.Frame`` that keeps the colours it is given. See :func:`_no_autostyle`."""
    return tk.Frame(master, **_no_autostyle(kwargs))


def tk_label(master: tk.Misc, **kwargs: Any) -> tk.Label:
    """A ``tk.Label`` that keeps the colours it is given."""
    return tk.Label(master, **_no_autostyle(kwargs))


def tk_canvas(master: tk.Misc, **kwargs: Any) -> tk.Canvas:
    """A ``tk.Canvas`` that keeps the colours it is given."""
    return tk.Canvas(master, **_no_autostyle(kwargs))


def tk_text(master: tk.Misc, **kwargs: Any) -> tk.Text:
    """A ``tk.Text`` that keeps the colours it is given."""
    return tk.Text(master, **_no_autostyle(kwargs))


def bootstyle_kwargs(**kwargs: Any) -> dict[str, Any]:
    """Widget kwargs with ``bootstyle`` dropped on a bare (no-theme) install."""
    if _bootstyle_active():
        return kwargs
    return {key: value for key, value in kwargs.items() if key != "bootstyle"}


def apply_style(widget: tk.Misc, name: str) -> None:
    """Assign a ttk style *after* the widget exists.

    ttkbootstrap's constructor override rewrites the ``style`` option of every
    ttk widget it builds, so a name handed to the constructor is silently
    discarded and the widget renders with the theme default. Assigning it
    afterwards is what actually sticks -- on plain ttk it is equivalent.
    """
    try:
        widget.configure(style=name)  # type: ignore[call-arg]
    except tk.TclError:  # pragma: no cover - unknown style name
        logger.debug("Stil uygulanamadı: %s", name, exc_info=True)


def derive_style(widget: tk.Misc, prefix: str, **options: Any) -> str:
    """Give *widget* a private style derived from the one it already carries.

    ttkbootstrap hands every widget of a given colour the *same* style name,
    so configuring that name directly leaks the change to every other widget
    wearing it. A derived ``"Prefix.<existing>"`` name inherits the theme's
    colours and layout through ttk's dotted-name lookup, while the overrides
    land on this widget alone. Returns the name in use.
    """
    parent = str(widget.cget("style") or "") or widget.winfo_class()
    name = f"{prefix}.{parent}"
    try:
        ttk.Style(widget).configure(name, **options)
    except tk.TclError:  # pragma: no cover - exotic theme
        logger.debug("Türetilmiş stil kurulamadı: %s", name, exc_info=True)
        return parent
    apply_style(widget, name)
    return name


def set_bootstyle(widget: tk.Misc, bootstyle: str) -> None:
    """Recolour an existing widget; a no-op without ttkbootstrap."""
    if not _bootstyle_active():
        return
    try:
        widget.configure(bootstyle=bootstyle)  # type: ignore[call-arg]
    except tk.TclError:  # pragma: no cover - unknown style name
        logger.debug("bootstyle uygulanamadı: %s", bootstyle)


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

_ACTION_COLORS = {
    "granted": COL_OK,
    "denied": COL_BAD,
    "detected": COL_ACCENT,
    "cooldown": COL_WARN,
    "error": COL_BAD,
}

_CAMERA_LABELS = {"entry": TXT_ENTRY, "exit": TXT_EXIT}

#: ``34ABC123`` -> ``34 ABC 123``. Turkish plates only; anything else is shown
#: exactly as the pipeline read it.
_PLATE_RE = re.compile(r"^(\d{2})([A-ZÇĞİÖŞÜ]{1,3})(\d{2,5})$")


def configure_styles(root: tk.Misc) -> ttk.Style:
    """Resolve fonts and register the styles the views rely on.

    Works with or without ttkbootstrap: the dark palette is carried by
    explicitly configured styles (and by plain ``tk`` chrome inside the
    widgets), so a machine without the theme package still gets a dark,
    readable dashboard rather than grey Motif frames.
    """
    global _UI_FAMILY, _MONO_FAMILY
    _UI_FAMILY = _pick_family(root, _UI_CANDIDATES, _UI_FAMILY)
    _MONO_FAMILY = _pick_family(root, _MONO_CANDIDATES, _MONO_FAMILY)

    style = ttk.Style(root)

    # Names the rest of the client (including license_dialog) depends on.
    style.configure("Badge.Ok.TLabel", foreground=COL_OK, font=ui_font(10, "bold"))
    style.configure("Badge.Bad.TLabel", foreground=COL_BAD, font=ui_font(10, "bold"))
    style.configure(
        "Banner.TLabel",
        foreground="#ffffff",
        background=COL_BAD,
        font=ui_font(10, "bold"),
    )
    style.configure("Title.TLabel", font=ui_font(18, "bold"))
    style.configure("Mono.TLabel", font=mono_font(10))

    # Dashboard surfaces. ttk styles inherit along the dotted name, so a
    # bootstyle-generated "success.TButton" picks the font up from "TButton".
    style.configure("TButton", font=ui_font(10, "bold"))
    style.configure("Surface.TFrame", background=COL_BG)
    style.configure("Card.TFrame", background=COL_CARD)
    style.configure("Treeview", font=ui_font(10), rowheight=26)
    style.configure("Treeview.Heading", font=ui_font(9, "bold"))
    return style


def _action_label(action: str) -> str:
    return _ACTION_LABELS.get(action, action.upper())


def _action_color(action: str) -> str:
    return _ACTION_COLORS.get(action, COL_ACCENT)


def _camera_label(camera: str) -> str:
    return _CAMERA_LABELS.get(camera, camera)


def _format_plate(plate: Any) -> str:
    """Group a plate for display: ``34ABC123`` -> ``34 ABC 123``."""
    text = str(plate or "").strip().upper().replace(" ", "")
    match = _PLATE_RE.match(text)
    if match is None:
        return text or "-"
    return f"{match.group(1)} {match.group(2)} {match.group(3)}"


def _confidence_text(event: dict[str, Any]) -> str:
    confidence = event.get("confidence") or 0.0
    try:
        return f"{float(confidence) * 100:.0f}%"
    except (TypeError, ValueError):
        return "-"


def _timestamp_text(event: dict[str, Any]) -> str:
    return str(event.get("ts", "")).replace("T", " ").replace("+00:00", "")


def _clock_text(event: dict[str, Any]) -> str:
    """Just the wall-clock part of a timestamp, for the compact feed cards."""
    stamp = _timestamp_text(event).strip()
    if not stamp:
        return "--:--:--"
    return stamp.split(" ")[-1][:8]


def _event_row(event: dict[str, Any]) -> tuple[str, ...]:
    return (
        _timestamp_text(event),
        _camera_label(str(event.get("camera", ""))),
        str(event.get("plate", "")),
        _action_label(str(event.get("action", ""))),
        _confidence_text(event),
    )


def card_frame(master: tk.Misc) -> tuple[tk.Frame, tk.Frame]:
    """A hairline-bordered dark card: returns ``(outer, body)``.

    ``outer`` is what the caller geometry-manages; ``body`` is where content
    goes. The border is a 1px frame showing through the padding rather than a
    ttk relief, which no theme can restyle out from under us.
    """
    outer = tk_frame(master, bg=COL_BORDER)
    body = tk_frame(outer, bg=COL_CARD)
    body.pack(fill="both", expand=True, padx=1, pady=1)
    return outer, body


def caption_label(master: tk.Misc, text: str, bg: str = COL_CARD) -> tk.Label:
    """Small upper-case caption above a value."""
    return tk_label(master, text=text, bg=bg, fg=COL_MUTED, font=ui_font(8, "bold"))


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
        super().__init__(master, padding=24, **kwargs)
        apply_style(self, "Surface.TFrame")
        self._on_submit = on_submit
        self._register_mode = False

        outer, card = card_frame(self)
        outer.pack(expand=True)
        form = tk_frame(card, bg=COL_CARD)
        form.pack(padx=40, pady=34)
        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)

        brand = tk_frame(form, bg=COL_CARD)
        brand.grid(row=0, column=0, columnspan=2, pady=(0, 22))
        tk_label(
            brand, text=ICON_BRAND, bg=COL_CARD, fg=COL_ACCENT, font=ui_font(16, "bold")
        ).pack(side="left")
        tk_label(
            brand,
            text=TXT_APP_TITLE.upper(),
            bg=COL_CARD,
            fg=COL_TEXT,
            font=ui_font(12, "bold"),
        ).pack(side="left", padx=(8, 0))

        self._title = tk_label(
            form, text=TXT_LOGIN_TITLE, bg=COL_CARD, fg=COL_TEXT, font=ui_font(20, "bold")
        )
        self._title.grid(row=1, column=0, columnspan=2, pady=(0, 4))

        self._hint = tk_label(
            form,
            text="",
            bg=COL_CARD,
            fg=COL_MUTED,
            font=ui_font(10),
            wraplength=380,
            justify="center",
        )
        self._hint.grid(row=2, column=0, columnspan=2, pady=(0, 14))

        caption_label(form, TXT_USERNAME.upper()).grid(row=3, column=0, columnspan=2, sticky="w")
        self._username = ttk.Entry(form, width=32, font=ui_font(11))
        self._username.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(4, 12), ipady=4)

        caption_label(form, TXT_PASSWORD.upper()).grid(row=5, column=0, columnspan=2, sticky="w")
        self._password = ttk.Entry(form, width=32, show="*", font=ui_font(11))
        self._password.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(4, 0), ipady=4)

        self._error = tk_label(
            form,
            text="",
            bg=COL_CARD,
            fg=COL_BAD,
            font=ui_font(10, "bold"),
            wraplength=380,
            justify="center",
        )
        self._error.grid(row=7, column=0, columnspan=2, pady=(12, 4))

        buttons = tk_frame(form, bg=COL_CARD)
        buttons.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        buttons.columnconfigure(0, weight=1)
        buttons.columnconfigure(1, weight=1)
        self._login_button = ttk.Button(
            buttons,
            text=TXT_LOGIN,
            padding=(0, 12),
            command=lambda: self._submit(False),
            **bootstyle_kwargs(bootstyle="success"),
        )
        self._login_button.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self._register_button = ttk.Button(
            buttons,
            text=TXT_REGISTER,
            padding=(0, 12),
            command=lambda: self._submit(True),
            **bootstyle_kwargs(bootstyle="secondary-outline"),
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


class CameraPane(ttk.Frame):
    """One live camera card: image, link badge, FPS and editable source.

    The video area is a plain ``tk.Label`` on a near-black background with a
    centred placeholder frame ``place``d over it. Showing a frame hides the
    placeholder; losing the stream (or the licence) brings it back with an
    icon and a colour that says which of the two happened.
    """

    def __init__(
        self,
        master: tk.Misc,
        role: str,
        title: str,
        on_source_apply: Callable[[str, str], None],
        **kwargs: Any,
    ) -> None:
        super().__init__(master, **kwargs)
        apply_style(self, "Card.TFrame")
        self.role = role
        self.title_text = title
        self._on_source_apply = on_source_apply
        self._photo: Any = None  # keeps the PhotoImage alive
        #: While locked the pane ignores incoming frames entirely, so the view
        #: freezes on the licence message instead of showing a live picture
        #: the site is no longer licensed to process.
        self._locked = False
        self._lock_text = TXT_LICENSE_LOCKED

        outer, card = card_frame(self)
        outer.pack(fill="both", expand=True)

        header = tk_frame(card, bg=COL_CARD)
        header.pack(fill="x", padx=12, pady=(10, 8))
        self._dot = tk_label(header, text="●", bg=COL_CARD, fg=COL_BAD, font=ui_font(10))
        self._dot.pack(side="left")
        tk_label(
            header,
            text=title.upper(),
            bg=COL_CARD,
            fg=COL_TEXT,
            font=ui_font(11, "bold"),
        ).pack(side="left", padx=(7, 0))
        self._badge = tk_label(
            header,
            text=TXT_DISCONNECTED,
            bg=COL_CARD,
            fg=COL_BAD,
            font=ui_font(9, "bold"),
        )
        self._badge.pack(side="right")
        self._fps = tk_label(header, text="", bg=COL_CARD, fg=COL_MUTED, font=mono_font(9))
        self._fps.pack(side="right", padx=(0, 12))

        video = tk_frame(
            card, bg=COL_VOID, highlightthickness=1, highlightbackground=COL_BORDER
        )
        video.pack(fill="both", expand=True, padx=12)
        self._canvas = tk_label(video, bg=COL_VOID, borderwidth=0, anchor="center")
        self._canvas.pack(fill="both", expand=True)

        self._placeholder = tk_frame(video, bg=COL_VOID)
        self._ph_icon = tk_label(
            self._placeholder, text=ICON_NO_SIGNAL, bg=COL_VOID, fg=COL_MUTED, font=ui_font(30)
        )
        self._ph_icon.pack()
        self._ph_text = tk_label(
            self._placeholder,
            text=TXT_NO_SIGNAL,
            bg=COL_VOID,
            fg=COL_MUTED,
            font=ui_font(11, "bold"),
            wraplength=340,
            justify="center",
        )
        self._ph_text.pack(pady=(8, 0))
        self._show_placeholder(ICON_NO_SIGNAL, TXT_NO_SIGNAL, COL_MUTED)

        controls = tk_frame(card, bg=COL_CARD)
        controls.pack(fill="x", padx=12, pady=(8, 10))
        caption_label(controls, TXT_SOURCE.upper()).pack(side="left")
        self._source = ttk.Entry(controls, font=mono_font(9))
        self._source.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(
            controls,
            text=TXT_APPLY,
            width=9,
            command=self._apply_source,
            **bootstyle_kwargs(bootstyle="secondary-outline"),
        ).pack(side="left")
        self._source.bind("<Return>", lambda _event: self._apply_source())

    # -- placeholder ----------------------------------------------------

    def _show_placeholder(self, icon: str, text: str, color: str) -> None:
        self._ph_icon.configure(text=icon, fg=color)
        self._ph_text.configure(text=text, fg=color)
        if not self._placeholder.winfo_manager():
            self._placeholder.place(relx=0.5, rely=0.5, anchor="center")

    def _hide_placeholder(self) -> None:
        if self._placeholder.winfo_manager():
            self._placeholder.place_forget()

    # -- state (main thread only) ---------------------------------------

    def set_connected(self, connected: bool, fps: float = 0.0) -> None:
        color = COL_OK if connected else COL_BAD
        self._badge.configure(text=TXT_CONNECTED if connected else TXT_DISCONNECTED, fg=color)
        self._dot.configure(fg=color)
        self._fps.configure(text=f"{fps:.1f} FPS" if connected and fps else "")

    def set_source(self, source: str) -> None:
        if self._source is self.focus_get():
            return  # never fight the operator's cursor
        current = self._source.get()
        if current != source:
            self._source.delete(0, tk.END)
            self._source.insert(0, source)

    def set_locked(self, locked: bool, message: str = TXT_LICENSE_LOCKED) -> None:
        """Freeze (or thaw) the pane. A locked pane renders no further frames."""
        self._locked = bool(locked)
        self._lock_text = message or TXT_LICENSE_LOCKED
        if self._locked:
            self._photo = None
            self._canvas.configure(image="")
            self._show_placeholder(ICON_LOCKED, self._lock_text, COL_BAD)
        else:
            self._show_placeholder(ICON_NO_SIGNAL, TXT_NO_SIGNAL, COL_MUTED)

    @property
    def locked(self) -> bool:
        return self._locked

    def set_image(self, pil_image: Any) -> None:
        """Render a PIL image, scaled to the pane's current size."""
        if self._locked or not PIL_AVAILABLE or pil_image is None:
            return
        width = max(160, self._canvas.winfo_width())
        height = max(120, self._canvas.winfo_height())
        try:
            scaled = self._fit(pil_image, width, height)
            self._photo = ImageTk.PhotoImage(scaled)
            self._canvas.configure(image=self._photo)
            self._hide_placeholder()
        except Exception:  # pragma: no cover - Tk image failure
            logger.debug("Kare gösterilemedi", exc_info=True)

    def clear_image(self) -> None:
        self._photo = None
        self._canvas.configure(image="")
        if self._locked:
            self._show_placeholder(ICON_LOCKED, self._lock_text, COL_BAD)
        else:
            self._show_placeholder(ICON_NO_SIGNAL, TXT_NO_SIGNAL, COL_MUTED)

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
# Live plate feed (dashboard right-hand panel)
# ---------------------------------------------------------------------------


class LivePlateFeed(ttk.Frame):
    """Scrolling stack of plate cards, newest on top.

    Exposes exactly the :class:`LogPane` surface -- ``add_event``,
    ``set_events``, ``clear`` -- so ``MainView.log_pane`` stays a drop-in for
    the controller, which never learns which of the two it is talking to.
    """

    def __init__(
        self,
        master: tk.Misc,
        title: str = TXT_LIVE_LOG,
        max_rows: int = 80,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, **kwargs)
        apply_style(self, "Card.TFrame")
        self.max_rows = max_rows
        self._cards: list[tk.Widget] = []

        outer, card = card_frame(self)
        outer.pack(fill="both", expand=True)

        header = tk_frame(card, bg=COL_CARD)
        header.pack(fill="x", padx=12, pady=(10, 8))
        tk_label(
            header, text=title.upper(), bg=COL_CARD, fg=COL_TEXT, font=ui_font(11, "bold")
        ).pack(side="left")
        self._count = tk_label(
            header, text="0", bg=COL_CARD, fg=COL_ACCENT, font=mono_font(11, "bold")
        )
        self._count.pack(side="right")
        tk_frame(card, bg=COL_BORDER, height=1).pack(fill="x", padx=12)

        body = tk_frame(card, bg=COL_CARD)
        body.pack(fill="both", expand=True)
        self._canvas = tk_canvas(
            body, bg=COL_CARD, highlightthickness=0, borderwidth=0, width=300
        )
        scroll = ttk.Scrollbar(body, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y", pady=6)
        self._canvas.pack(side="left", fill="both", expand=True)

        self._inner = tk_frame(self._canvas, bg=COL_CARD)
        self._window = self._canvas.create_window((0, 0), window=self._inner, anchor="nw")
        self._inner.bind("<Configure>", self._on_inner_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        # Wheel bindings are global while the pointer is inside the feed, and
        # released again on the way out, so they never shadow another widget.
        self._canvas.bind("<Enter>", self._bind_wheel)
        self._canvas.bind("<Leave>", self._unbind_wheel)

        self._empty = tk_label(
            self._inner,
            text=TXT_NO_EVENTS,
            bg=COL_CARD,
            fg=COL_MUTED,
            font=ui_font(10),
            pady=28,
        )
        self._empty.pack(fill="x")

    # -- scrolling ------------------------------------------------------

    def _on_inner_configure(self, _event: Any = None) -> None:
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event: Any) -> None:
        self._canvas.itemconfigure(self._window, width=event.width)

    def _bind_wheel(self, _event: Any = None) -> None:
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self._canvas.bind_all(sequence, self._on_wheel)

    def _unbind_wheel(self, _event: Any = None) -> None:
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self._canvas.unbind_all(sequence)

    def _on_wheel(self, event: Any) -> None:
        if getattr(event, "num", 0) == 4:
            delta = -1
        elif getattr(event, "num", 0) == 5:
            delta = 1
        else:
            delta = -1 if getattr(event, "delta", 0) > 0 else 1
        try:
            self._canvas.yview_scroll(delta, "units")
        except tk.TclError:  # pragma: no cover - canvas gone mid-scroll
            pass

    # -- cards ----------------------------------------------------------

    def _build_card(self, event: dict[str, Any]) -> tk.Frame:
        """One plate card: status is carried by side stripes, not by ink.

        Tk has no per-side border, so the stripes are a padding trick: the
        outer frame is filled with the status colour and the dark inner frame
        is packed over it with ``padx=STRIPE_PX, pady=0``. Only the left and
        right edges of the outer frame stay uncovered, which reads as a pair
        of vertical rules -- green for a granted pass, red for a refusal.

        Because the stripe says it, the text does not: plate and confidence
        are plain white and the metadata line is muted, so a wall of cards
        scans as a list rather than as five competing colours.
        """
        action = str(event.get("action", ""))
        accent = _action_color(action)

        card = tk_frame(self._inner, bg=accent)
        body = tk_frame(card, bg=COL_ROW)
        body.pack(fill="both", expand=True, padx=STRIPE_PX, pady=0)
        content = tk_frame(body, bg=COL_ROW)
        content.pack(fill="both", expand=True, padx=10, pady=8)

        top = tk_frame(content, bg=COL_ROW)
        top.pack(fill="x")
        tk_label(
            top,
            text=_format_plate(event.get("plate", "")),
            bg=COL_ROW,
            fg=COL_TEXT,
            font=mono_font(15, "bold"),
            anchor="w",
        ).pack(side="left")
        tk_label(
            top,
            text=_confidence_text(event),
            bg=COL_ROW,
            fg=COL_TEXT,
            font=ui_font(13, "bold"),
        ).pack(side="right")

        bottom = tk_frame(content, bg=COL_ROW)
        bottom.pack(fill="x", pady=(5, 0))
        tk_label(
            bottom,
            text=_camera_label(str(event.get("camera", ""))).upper(),
            bg=COL_ROW,
            fg=COL_MUTED,
            font=ui_font(8, "bold"),
        ).pack(side="left")
        tk_label(
            bottom,
            text=_action_label(action),
            bg=COL_ROW,
            fg=COL_MUTED,
            font=ui_font(8, "bold"),
        ).pack(side="left", padx=(10, 0))
        tk_label(
            bottom,
            text=_clock_text(event),
            bg=COL_ROW,
            fg=COL_MUTED,
            font=mono_font(9),
        ).pack(side="right")
        return card

    def _trim(self) -> None:
        while len(self._cards) > self.max_rows:
            self._cards.pop().destroy()

    def _update_count(self) -> None:
        self._count.configure(text=str(len(self._cards)))

    # -- state (main thread only) ---------------------------------------

    def add_event(self, event: dict[str, Any]) -> None:
        """Prepend one plate read to the top of the feed."""
        try:
            at_top = self._canvas.yview()[0] <= 0.01
        except tk.TclError:  # pragma: no cover - not mapped yet
            at_top = True

        self._empty.pack_forget()
        card = self._build_card(event)
        card.pack(fill="x", padx=8, pady=4)
        if self._cards:
            card.pack_configure(before=self._cards[0])
        self._cards.insert(0, card)
        self._trim()
        self._update_count()
        if at_top:
            # Only follow the newest read when the operator has not scrolled
            # away to study an older one.
            self._canvas.yview_moveto(0.0)

    def set_events(self, events: Iterable[dict[str, Any]]) -> None:
        self.clear()
        rows = list(events)
        if not rows:
            return
        self._empty.pack_forget()
        for event in rows:
            card = self._build_card(event)
            card.pack(fill="x", padx=8, pady=4)
            self._cards.append(card)
        self._trim()
        self._update_count()

    def clear(self) -> None:
        for card in self._cards:
            card.destroy()
        self._cards = []
        self._update_count()
        if not self._empty.winfo_manager():
            self._empty.pack(fill="x")


# ---------------------------------------------------------------------------
# Log panes
# ---------------------------------------------------------------------------


class LogPane(ttk.Labelframe):
    """Scrolling table of events. Newest first, bounded in size.

    Still the right widget for the history window, where an operator scans
    hundreds of rows and wants columns; the live dashboard uses
    :class:`LivePlateFeed` instead.
    """

    def __init__(
        self, master: tk.Misc, title: str = TXT_LIVE_LOG, max_rows: int = 500, **kwargs: Any
    ) -> None:
        super().__init__(master, text=title, padding=8, **kwargs)
        self.max_rows = max_rows

        self.tree = ttk.Treeview(
            self, columns=[c[0] for c in _LOG_COLUMNS], show="headings", height=10
        )
        # Derived rather than configured on the shared "Treeview": ttkbootstrap
        # sets its own row height when it builds the theme, which is tighter
        # than a control-room table wants to be read at.
        log_style = derive_style(self.tree, "Log", font=ui_font(10), rowheight=28)
        ttk.Style(self).configure(f"{log_style}.Heading", font=ui_font(9, "bold"))
        for key, heading, width in _LOG_COLUMNS:
            self.tree.heading(key, text=heading)
            self.tree.column(key, width=width, anchor="w", stretch=True)
        for action, color in _ACTION_COLORS.items():
            self.tree.tag_configure(action, foreground=color)

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
    """Header + camera cards + live plate feed + telemetry + control panel."""

    def __init__(
        self,
        master: tk.Misc,
        callbacks: dict[str, Callable[..., Any]],
        **kwargs: Any,
    ) -> None:
        super().__init__(master, padding=10, **kwargs)
        apply_style(self, "Surface.TFrame")
        self._callbacks = callbacks
        self._style = ttk.Style(self)
        self._banner_visible = False
        self._license_locked = False

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)  # only the camera/feed body grows

        self._build_header()

        # -- offline / licence banner ----------------------------------
        self._banner = ttk.Label(
            self, text=TXT_OFFLINE_BANNER, anchor="center", padding=8
        )
        apply_style(self._banner, "Banner.TLabel")
        # Gridded and removed dynamically by set_banner().

        self._build_body()
        self._build_telemetry()
        self._build_controls()

    # -- construction ---------------------------------------------------

    def _build_header(self) -> None:
        """Brand on the left, uptime centred, operator and link state right."""
        header = tk_frame(
            self, bg=COL_HEADER, highlightthickness=1, highlightbackground=COL_BORDER
        )
        header.grid(row=0, column=0, sticky="ew")
        for column in (0, 1, 2):
            header.columnconfigure(column, weight=1, uniform="header")

        brand = tk_frame(header, bg=COL_HEADER)
        brand.grid(row=0, column=0, sticky="w", padx=14, pady=9)
        tk_label(
            brand, text=ICON_BRAND, bg=COL_HEADER, fg=COL_ACCENT, font=ui_font(17, "bold")
        ).pack(side="left")
        titles = tk_frame(brand, bg=COL_HEADER)
        titles.pack(side="left", padx=(9, 0))
        tk_label(
            titles,
            text=TXT_APP_TITLE.upper(),
            bg=COL_HEADER,
            fg=COL_TEXT,
            font=ui_font(12, "bold"),
        ).pack(anchor="w")
        caption_label(titles, TXT_DASHBOARD, bg=COL_HEADER).pack(anchor="w")

        center = tk_frame(header, bg=COL_HEADER)
        center.grid(row=0, column=1)
        caption_label(center, TXT_UPTIME.upper(), bg=COL_HEADER).pack()
        self._uptime = tk_label(
            center, text="00:00:00", bg=COL_HEADER, fg=COL_TEXT, font=mono_font(15, "bold")
        )
        self._uptime.pack()

        right = tk_frame(header, bg=COL_HEADER)
        right.grid(row=0, column=2, sticky="e", padx=14)
        # Packed right-to-left: link state sits on the outside edge.
        self._connection = tk_label(
            right,
            text=TXT_DISCONNECTED,
            bg=COL_HEADER,
            fg=COL_BAD,
            font=ui_font(10, "bold"),
        )
        self._connection.pack(side="right")
        self._connection_dot = tk_label(
            right, text="●", bg=COL_HEADER, fg=COL_BAD, font=ui_font(10)
        )
        self._connection_dot.pack(side="right", padx=(0, 6))
        self._user = tk_label(
            right, text="", bg=COL_HEADER, fg=COL_TEXT, font=ui_font(10, "bold")
        )
        self._user.pack(side="right", padx=(0, 18))

    def _build_body(self) -> None:
        """Camera cards (3fr) beside the live plate feed (1fr)."""
        body = ttk.Frame(self)
        apply_style(body, "Surface.TFrame")
        body.grid(row=2, column=0, sticky="nsew", pady=10)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=1, minsize=320)
        body.rowconfigure(0, weight=1)

        cameras = ttk.Frame(body)
        apply_style(cameras, "Surface.TFrame")
        self._cameras_frame = cameras
        cameras.grid(row=0, column=0, sticky="nsew")
        cameras.columnconfigure(0, weight=1, uniform="cam")
        cameras.columnconfigure(1, weight=1, uniform="cam")
        cameras.rowconfigure(0, weight=1)

        on_source = self._callbacks.get("apply_source", lambda *_: None)
        self.panes: dict[str, CameraPane] = {
            "entry": CameraPane(cameras, "entry", TXT_ENTRY, on_source),
            "exit": CameraPane(cameras, "exit", TXT_EXIT, on_source),
        }
        self.panes["entry"].grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self.panes["exit"].grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        self.log_pane = LivePlateFeed(body)
        self.log_pane.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

    def _build_telemetry(self) -> None:
        """Live activity on the left, counters and licence on the right."""
        strip = tk_frame(self, bg=COL_BG)
        strip.grid(row=3, column=0, sticky="ew", pady=(0, 10))

        # Live activity: what the pipeline is doing *right now* (a plate being
        # read, votes accumulating). Transient by design -- the durable record
        # is the plate feed.
        self._activity = tk_label(
            strip, text="", bg=COL_BG, fg=COL_MUTED, font=mono_font(9), anchor="w"
        )
        self._activity.pack(side="left")

        # Built right-to-left so they read OKUNAN / İZİN / RET left-to-right.
        self._stat_denials = self._stat_tile(strip, TXT_STAT_DENY, COL_BAD)
        self._stat_grants = self._stat_tile(strip, TXT_STAT_GRANT, COL_OK)
        self._stat_plates = self._stat_tile(strip, TXT_STAT_READ, COL_ACCENT)

        self._license = tk_label(
            strip, text="", bg=COL_BG, fg=COL_MUTED, font=mono_font(9)
        )
        self._license.pack(side="right", padx=(0, 18))

    @staticmethod
    def _stat_tile(master: tk.Misc, caption: str, color: str) -> tk.Label:
        box = tk_frame(
            master, bg=COL_HEADER, highlightthickness=1, highlightbackground=COL_BORDER
        )
        box.pack(side="right", padx=(8, 0))
        value = tk_label(box, text="0", bg=COL_HEADER, fg=color, font=mono_font(12, "bold"))
        value.pack(padx=14, pady=(4, 0))
        caption_label(box, caption, bg=COL_HEADER).pack(padx=14, pady=(0, 5))
        return value

    def _build_controls(self) -> None:
        """Bottom control panel. Size and colour carry the hierarchy."""
        footer = tk_frame(
            self, bg=COL_HEADER, highlightthickness=1, highlightbackground=COL_BORDER
        )
        footer.grid(row=4, column=0, sticky="ew")
        row = tk_frame(footer, bg=COL_HEADER)
        row.pack(fill="x", padx=12, pady=10)

        # The one action an operator reaches for under pressure: biggest,
        # solid, and the only success-coloured control in the window.
        self._gate_button = ttk.Button(
            row,
            text=TXT_OPEN_GATE,
            padding=(30, 16),
            command=lambda: self._call("open_gate"),
            **bootstyle_kwargs(bootstyle="success"),
        )
        self._gate_button.pack(side="left")
        self._emphasise_gate_button()

        ttk.Button(
            row,
            text=TXT_MANUAL_PLATE,
            padding=(18, 12),
            command=lambda: self._call("open_plates"),
            **bootstyle_kwargs(bootstyle="info"),
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            row,
            text=TXT_HISTORY,
            padding=(18, 12),
            command=lambda: self._call("open_history"),
            **bootstyle_kwargs(bootstyle="secondary"),
        ).pack(side="left", padx=(10, 0))
        self._pause_button = ttk.Button(
            row,
            text=TXT_PAUSE,
            padding=(18, 12),
            command=lambda: self._call("toggle_pause"),
            **bootstyle_kwargs(bootstyle="warning-outline"),
        )
        self._pause_button.pack(side="left", padx=(10, 0))
        ttk.Button(
            row,
            text=TXT_FULLSCREEN,
            padding=(18, 12),
            command=lambda: self._call("toggle_fullscreen"),
            **bootstyle_kwargs(bootstyle="secondary-outline"),
        ).pack(side="left", padx=(10, 0))

        ttk.Button(
            row,
            text=TXT_LOGOUT,
            padding=(18, 12),
            command=lambda: self._call("logout"),
            **bootstyle_kwargs(bootstyle="danger-outline"),
        ).pack(side="right")
        # Always available, not only once the licence has expired: an
        # installer renewing a key a week early should not have to wait for
        # the system to stop first.
        ttk.Button(
            row,
            text=TXT_LICENSE_BUTTON,
            padding=(18, 12),
            command=lambda: self._call("open_license"),
            **bootstyle_kwargs(bootstyle="info-outline"),
        ).pack(side="right", padx=(0, 10))

    def _emphasise_gate_button(self) -> None:
        """Give the gate button a larger font than the rest of the panel.

        ``font`` is a style option, not a widget one, so the only way to
        enlarge a single ttk button is to touch a style. It has to be a
        *private* one: ttkbootstrap hands every ``bootstyle="success"``
        widget the same shared "success.TButton", so configuring that
        directly would also inflate the login button and the plate window's
        "Ekle". Deriving "Gate.success.TButton" from it keeps ttk's
        dotted-name inheritance -- the bootstrap colours and layout still
        resolve through the parent -- while the font override lands on this
        button alone.
        """
        options: dict[str, Any] = {"font": ui_font(13, "bold")}
        if not _bootstyle_active():
            # No ttkbootstrap: paint the success colour ourselves.
            options.update(foreground="#ffffff", background=COL_OK)
        derive_style(self._gate_button, "Gate", **options)

    # -- state (main thread only) ---------------------------------------

    def _call(self, name: str, *args: Any) -> None:
        callback = self._callbacks.get(name)
        if callback is not None:
            callback(*args)

    def _set_connection(self, online: bool) -> None:
        color = COL_OK if online else COL_BAD
        self._connection.configure(
            text=TXT_CONNECTED if online else TXT_DISCONNECTED, fg=color
        )
        self._connection_dot.configure(fg=color)

    def set_banner(self, visible: bool, message: str = TXT_OFFLINE_BANNER) -> None:
        if visible:
            self._banner.configure(text=message)
            if not self._banner_visible:
                # Slot it between the header and the camera grid.
                self._banner.grid(row=1, column=0, sticky="ew", pady=(10, 0))
                self._banner_visible = True
        elif self._banner_visible:
            self._banner.grid_remove()
            self._banner_visible = False
        # The banner is the client's one "something is wrong" channel, so the
        # header pill mirrors it: no banner means the link is healthy.
        self._set_connection(not visible)

    def set_paused(self, paused: bool) -> None:
        self._pause_button.configure(text=TXT_RESUME if paused else TXT_PAUSE)
        # Outline on both sides of the toggle: the solid "success" style
        # belongs to the gate button alone, and borrowing it here would drag
        # in its deliberately oversized font.
        set_bootstyle(self._pause_button, "success-outline" if paused else "warning-outline")

    def set_license_text(self, text: str, ok: bool = True) -> None:
        """One-line licence summary in the telemetry strip."""
        self._license.configure(text=text, fg=COL_MUTED if ok else COL_BAD)

    def set_license_locked(self, locked: bool, message: str = TXT_LICENSE_LOCKED) -> None:
        """Freeze both camera panes and show the licence banner.

        The banner is the same widget the offline state uses, so a licensed
        system that merely lost the network still reports *that* instead of
        being masked by a licence message.
        """
        self._license_locked = bool(locked)
        for pane in self.panes.values():
            pane.set_locked(self._license_locked, message)
        if self._license_locked:
            self.set_banner(True, TXT_LICENSE_BANNER)
        else:
            self.set_banner(False)

    @property
    def license_locked(self) -> bool:
        return self._license_locked

    def set_uptime(self, text: str) -> None:
        self._uptime.configure(text=text)

    def set_activity(self, text: str) -> None:
        """Show one line of live pipeline activity in the telemetry strip."""
        self._activity.configure(text=text)

    def set_user(self, username: str, role: str) -> None:
        self._user.configure(text=f"{username} ({role})")

    def set_stats(self, stats: dict[str, Any]) -> None:
        self._stat_plates.configure(text=str(stats.get("plates_read", 0)))
        self._stat_grants.configure(text=str(stats.get("grants", 0)))
        self._stat_denials.configure(text=str(stats.get("denials", 0)))

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
    """Registered-plate management: list, add, remove.

    This is also the dashboard's "Plaka Girişi" (manual plate entry) screen --
    typing a plate here is how an operator admits a vehicle the cameras could
    not read.
    """

    def __init__(
        self,
        master: tk.Misc,
        callbacks: dict[str, Callable[..., Any]],
    ) -> None:
        super().__init__(master)
        self.title(f"{TXT_APP_TITLE} - {TXT_PLATES}")
        self.geometry("660x640")
        self.minsize(580, 560)
        self.configure(background=COL_BG)
        self.transient(master.winfo_toplevel())
        self._callbacks = callbacks

        # Packed at the very end, after the footer: pack hands out space in
        # call order, so an expanding body claimed first squeezes the footer
        # buttons down to nothing on a short window.
        body = ttk.Frame(self, padding=14)
        apply_style(body, "Surface.TFrame")

        heading = tk_frame(body, bg=COL_BG)
        heading.pack(fill="x", pady=(0, 12))
        tk_label(
            heading,
            text=TXT_MANUAL_PLATE.upper(),
            bg=COL_BG,
            fg=COL_TEXT,
            font=ui_font(13, "bold"),
        ).pack(anchor="w")
        tk_label(
            heading,
            text=TXT_PLATES_HINT,
            bg=COL_BG,
            fg=COL_MUTED,
            font=ui_font(9),
        ).pack(anchor="w", pady=(2, 0))

        # -- entry form ------------------------------------------------
        form_outer, form = card_frame(body)
        form_outer.pack(fill="x")
        grid = tk_frame(form, bg=COL_CARD)
        grid.pack(fill="x", padx=14, pady=12)
        grid.columnconfigure(0, weight=2)
        grid.columnconfigure(1, weight=3)

        caption_label(grid, TXT_PLATE_FIELD.upper()).grid(row=0, column=0, sticky="w")
        caption_label(grid, TXT_NOTE.upper()).grid(row=0, column=1, sticky="w", padx=(10, 0))
        self._plate_entry = ttk.Entry(grid, font=mono_font(14, "bold"))
        self._plate_entry.grid(row=1, column=0, sticky="ew", pady=(4, 0), ipady=6)
        self._note_entry = ttk.Entry(grid, font=ui_font(10))
        self._note_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(4, 0), ipady=6)
        ttk.Button(
            grid,
            text=TXT_ADD,
            padding=(22, 10),
            command=self._add,
            **bootstyle_kwargs(bootstyle="success"),
        ).grid(row=1, column=2, sticky="e", padx=(10, 0), pady=(4, 0))

        # Enter from either field submits: an operator admitting a car at the
        # barrier types the plate and hits Return without reaching for a mouse.
        self._plate_entry.bind("<Return>", lambda _event: self._add())
        self._note_entry.bind("<Return>", lambda _event: self._add())

        # -- registered plates ------------------------------------------
        list_outer, list_card = card_frame(body)
        list_outer.pack(fill="both", expand=True, pady=(12, 0))
        list_header = tk_frame(list_card, bg=COL_CARD)
        list_header.pack(fill="x", padx=14, pady=(10, 8))
        tk_label(
            list_header,
            text=TXT_PLATES.upper(),
            bg=COL_CARD,
            fg=COL_TEXT,
            font=ui_font(11, "bold"),
        ).pack(side="left")
        self._count = tk_label(
            list_header, text="0", bg=COL_CARD, fg=COL_ACCENT, font=mono_font(11, "bold")
        )
        self._count.pack(side="right")
        tk_frame(list_card, bg=COL_BORDER, height=1).pack(fill="x", padx=14)

        table = tk_frame(list_card, bg=COL_CARD)
        table.pack(fill="both", expand=True, padx=14, pady=10)
        self.tree = ttk.Treeview(
            table,
            columns=("index", "plate"),
            show="headings",
            selectmode="browse",
        )
        tree_style = derive_style(
            self.tree, "Plates", font=mono_font(12), rowheight=34
        )
        ttk.Style(self).configure(f"{tree_style}.Heading", font=ui_font(9, "bold"))
        self.tree.heading("index", text="#")
        self.tree.heading("plate", text=TXT_PLATE_FIELD)
        self.tree.column("index", width=60, anchor="center", stretch=False)
        self.tree.column("plate", anchor="w", stretch=True)
        # Zebra striping: cheap to apply per row and the only way to get it,
        # since ttk has no alternating-row option.
        self.tree.tag_configure("odd", background=COL_ROW)
        self.tree.tag_configure("even", background=COL_CARD)
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<Delete>", lambda _event: self._remove())

        # -- footer ------------------------------------------------------
        footer = ttk.Frame(self, padding=(14, 0, 14, 14))
        apply_style(footer, "Surface.TFrame")
        footer.pack(side="bottom", fill="x")
        ttk.Button(
            footer,
            text=TXT_REMOVE,
            padding=(18, 10),
            command=self._remove,
            **bootstyle_kwargs(bootstyle="danger"),
        ).pack(side="left")
        ttk.Button(
            footer,
            text=TXT_REFRESH,
            padding=(18, 10),
            command=lambda: self._call("refresh"),
            **bootstyle_kwargs(bootstyle="secondary-outline"),
        ).pack(side="left", padx=8)
        self._status = tk_label(footer, text="", bg=COL_BG, fg=COL_MUTED, font=ui_font(9))
        self._status.pack(side="left", padx=12)
        ttk.Button(
            footer,
            text=TXT_CLOSE,
            padding=(18, 10),
            command=self.destroy,
            **bootstyle_kwargs(bootstyle="secondary"),
        ).pack(side="right")

        body.pack(fill="both", expand=True)

        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.after(100, self._plate_entry.focus_set)

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
        selection = self.tree.selection()
        if not selection:
            self.set_status("Silmek için bir plaka seçin.")
            return
        values = self.tree.item(selection[0], "values")
        if len(values) < 2:  # pragma: no cover - malformed row
            return
        self._call("remove", str(values[1]))

    # -- state (main thread only) ---------------------------------------

    def set_plates(self, plates: Sequence[str]) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for position, plate in enumerate(plates, start=1):
            self.tree.insert(
                "",
                "end",
                values=(position, plate),
                tags=("odd" if position % 2 else "even",),
            )
        self._count.configure(text=str(len(plates)))
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
        self.configure(background=COL_BG)
        self.transient(master.winfo_toplevel())
        self._callbacks = callbacks

        header = ttk.Frame(self, padding=12)
        apply_style(header, "Surface.TFrame")
        header.pack(fill="x")
        caption_label(header, TXT_DATE.upper(), bg=COL_BG).pack(side="left")
        self.date_var = tk.StringVar()
        self.date_box = ttk.Combobox(header, textvariable=self.date_var, state="readonly", width=16)
        self.date_box.pack(side="left", padx=6)
        self.date_box.bind("<<ComboboxSelected>>", lambda _event: self._load())
        ttk.Button(
            header,
            text=TXT_REFRESH,
            command=self._load,
            **bootstyle_kwargs(bootstyle="secondary-outline"),
        ).pack(side="left")
        self._status = tk_label(header, text="", bg=COL_BG, fg=COL_MUTED, font=ui_font(9))
        self._status.pack(side="left", padx=12)
        ttk.Button(
            header, text=TXT_CLOSE, command=self.destroy, **bootstyle_kwargs(bootstyle="secondary")
        ).pack(side="right")

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
