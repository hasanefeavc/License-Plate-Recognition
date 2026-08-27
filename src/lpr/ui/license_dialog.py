"""Modal licence-key dialog for the desktop client.

Passive, like everything else in the view layer: it renders what it is given
and reports what the operator typed through an injected callback. It performs
no I/O, knows nothing about :mod:`lpr.ui.client`, and is only ever mutated
from the Tk main thread -- :class:`~lpr.ui.app.LprApp` submits the key on a
worker thread and calls back in through :meth:`LicenseDialog.set_result`.

The key is a JWT: long, base64url, and pasted rather than typed. That is why
the input is a wrapping ``Text`` widget rather than an ``Entry``, and why
every whitespace character is stripped on submit -- a key copied out of an
e-mail arrives with line breaks in it.

Visually it is an activation screen rather than a form: one centred card on
the dashboard's dark surface, a status pill that turns green or red with the
licence, and a single prominent action. The palette, fonts and ttkbootstrap
helpers all come from :mod:`lpr.ui.views` so the two windows cannot drift
apart. That import is one-way -- views knows nothing about this module.
"""

from __future__ import annotations

import logging
import tkinter as tk
from collections.abc import Callable
from tkinter import ttk
from typing import Any

from lpr.ui.views import (
    COL_BAD,
    COL_BG,
    COL_BORDER,
    COL_CARD,
    COL_MUTED,
    COL_OK,
    COL_TEXT,
    COL_VOID,
    ICON_BRAND,
    apply_style,
    bootstyle_kwargs,
    caption_label,
    card_frame,
    mono_font,
    tk_frame,
    tk_label,
    tk_text,
    ui_font,
)

logger = logging.getLogger(__name__)

__all__ = ["LicenseDialog", "TXT_LICENSE_TITLE", "format_license_state"]

TXT_LICENSE_TITLE = "Lisans Anahtarı"
TXT_LICENSE_EXPIRED = "LİSANS SÜRESİ DOLDU"
TXT_LICENSE_PROMPT = (
    "Sistemin çalışmaya devam etmesi için geçerli bir lisans anahtarı girin. "
    "Anahtarı sistem sağlayıcınızdan temin edebilirsiniz."
)
TXT_LICENSE_FIELD = "Lisans Anahtarı (JWT)"
TXT_LICENSE_SUBMIT = "Etkinleştir"
TXT_LICENSE_CLOSE = "Kapat"
TXT_LICENSE_BUSY = "Anahtar doğrulanıyor..."
TXT_LICENSE_EMPTY = "Lütfen bir lisans anahtarı yapıştırın."
TXT_LICENSE_OK = "Lisans etkinleştirildi."
TXT_LICENSE_ACTIVE = "LİSANS ETKİN"
TXT_LICENSE_STATE = "Mevcut Durum"
TXT_LICENSE_SHORTCUT = "Ctrl+Enter ile onaylayın"

#: Human-readable summary per reason code from ``lpr.license``. The server
#: always sends its own ``detail`` sentence; these are the fallback for a
#: reason this build has not seen before.
_REASON_LABELS = {
    "ok": "Lisans geçerli.",
    "missing": "Lisans anahtarı girilmemiş.",
    "expired": "Lisans süresi doldu.",
    "invalid": "Lisans anahtarı geçersiz.",
    "not_yet_valid": "Lisans henüz başlamadı.",
    "clock_rollback": "Sistem saati geriye alınmış.",
    "no_secret": "Sunucuda lisans doğrulama anahtarı tanımlı değil.",
}


def format_license_state(license_info: dict[str, Any]) -> str:
    """One line describing a licence, for the status bar or the overlay."""
    if not license_info:
        return ""
    detail = str(license_info.get("detail") or "").strip()
    reason = str(license_info.get("reason") or "")
    text = detail or _REASON_LABELS.get(reason, reason)

    client = license_info.get("client")
    days = license_info.get("days_remaining")
    if license_info.get("valid"):
        parts = ["Lisans"]
        if client:
            parts.append(str(client))
        if isinstance(days, (int, float)):
            parts.append(f"{days:.0f} gün kaldı")
        return " - ".join(parts)

    expires = license_info.get("expires_at")
    if expires:
        text = f"{text} (bitiş: {str(expires).replace('T', ' ').replace('+00:00', '')})"
    return text


class LicenseDialog(tk.Toplevel):
    """Modal window asking for a new licence key.

    ``on_submit`` receives the cleaned key string. The dialog does not close
    itself on submit: it waits for :meth:`set_result`, because only the caller
    knows whether the server accepted the key.
    """

    def __init__(
        self,
        master: tk.Misc,
        on_submit: Callable[[str], None],
        *,
        message: str = "",
        on_close: Callable[[], None] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, **kwargs)
        self._on_submit = on_submit
        self._on_close = on_close

        self.title(TXT_LICENSE_TITLE)
        self.geometry("640x700")
        self.minsize(560, 620)
        # winfo_toplevel(), not master: the caller may hand us a frame, and
        # only a window can own a transient. Same convention as views.py.
        self.transient(master.winfo_toplevel())
        self.protocol("WM_DELETE_WINDOW", self._close)

        self.configure(background=COL_BG)

        surface = ttk.Frame(self, padding=22)
        apply_style(surface, "Surface.TFrame")
        surface.pack(fill="both", expand=True)
        outer, card = card_frame(surface)
        outer.pack(fill="both", expand=True)
        body = tk_frame(card, bg=COL_CARD)
        body.pack(fill="both", expand=True, padx=28, pady=24)

        # -- masthead ---------------------------------------------------
        brand = tk_frame(body, bg=COL_CARD)
        brand.pack()
        tk_label(
            brand, text=ICON_BRAND, bg=COL_CARD, fg=COL_OK, font=ui_font(15, "bold")
        ).pack(side="left")
        tk_label(
            brand,
            text=TXT_LICENSE_TITLE.upper(),
            bg=COL_CARD,
            fg=COL_TEXT,
            font=ui_font(11, "bold"),
        ).pack(side="left", padx=(8, 0))

        self._headline = tk_label(
            body,
            text=TXT_LICENSE_EXPIRED,
            bg=COL_CARD,
            fg=COL_BAD,
            font=ui_font(19, "bold"),
        )
        self._headline.pack(pady=(14, 6))
        tk_label(
            body,
            text=TXT_LICENSE_PROMPT,
            bg=COL_CARD,
            fg=COL_MUTED,
            font=ui_font(10),
            wraplength=460,
            justify="center",
        ).pack()

        # -- current licence state --------------------------------------
        caption_label(body, TXT_LICENSE_STATE.upper()).pack(pady=(18, 4))
        self._state = tk_label(
            body,
            text=message,
            bg=COL_CARD,
            fg=COL_MUTED,
            font=ui_font(10, "bold"),
            wraplength=460,
            justify="center",
        )
        self._state.pack()

        # -- key input ---------------------------------------------------
        caption_label(body, TXT_LICENSE_FIELD.upper()).pack(anchor="w", pady=(20, 4))
        entry_border = tk_frame(body, bg=COL_BORDER)
        entry_border.pack(fill="both", expand=True)
        self._entry = tk_text(
            entry_border,
            height=6,
            wrap="char",
            font=mono_font(10),
            bg=COL_VOID,
            fg=COL_TEXT,
            insertbackground=COL_TEXT,
            selectbackground=COL_OK,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            padx=10,
            pady=8,
        )
        self._entry.pack(fill="both", expand=True, padx=1, pady=1)

        self._status = tk_label(
            body,
            text="",
            bg=COL_CARD,
            fg=COL_MUTED,
            font=ui_font(10, "bold"),
            wraplength=460,
            justify="center",
        )
        self._status.pack(pady=(10, 0))

        # -- actions ------------------------------------------------------
        buttons = tk_frame(body, bg=COL_CARD)
        buttons.pack(fill="x", pady=(16, 0))
        self._submit_button = ttk.Button(
            buttons,
            text=TXT_LICENSE_SUBMIT,
            padding=(28, 14),
            command=self._submit,
            **bootstyle_kwargs(bootstyle="success"),
        )
        self._submit_button.pack(side="right")
        ttk.Button(
            buttons,
            text=TXT_LICENSE_CLOSE,
            padding=(20, 14),
            command=self._close,
            **bootstyle_kwargs(bootstyle="secondary-outline"),
        ).pack(side="right", padx=(0, 10))
        tk_label(
            buttons,
            text=TXT_LICENSE_SHORTCUT,
            bg=COL_CARD,
            fg=COL_MUTED,
            font=ui_font(8),
        ).pack(side="left", pady=(4, 0))

        # Ctrl-Return submits; a plain Return inserts a newline, which is what
        # a multi-line paste needs.
        self._set_licensed(False)
        self._entry.bind("<Control-Return>", lambda _event: self._submit())
        self.after(100, self._entry.focus_set)

        self._grab()

    # -- state (main thread only) ---------------------------------------

    def _set_licensed(self, active: bool) -> None:
        """Repaint the headline and the state line for the licence verdict.

        Green and "LİSANS ETKİN" once the server has accepted a key, red and
        "LİSANS SÜRESİ DOLDU" otherwise -- which is how the window opens,
        since the only thing that forces it up is an invalid licence.
        """
        color = COL_OK if active else COL_BAD
        self._headline.configure(
            text=TXT_LICENSE_ACTIVE if active else TXT_LICENSE_EXPIRED, fg=color
        )
        self._state.configure(fg=color)

    def set_state_text(self, message: str) -> None:
        """Update the "why you are seeing this" line."""
        self._state.configure(text=message)

    def set_busy(self, busy: bool) -> None:
        self._submit_button.configure(state="disabled" if busy else "normal")
        if busy:
            self._status.configure(text=TXT_LICENSE_BUSY, fg=COL_MUTED)

    def set_result(self, ok: bool, message: str = "") -> None:
        """Report the server's verdict. Closes the dialog when accepted."""
        self.set_busy(False)
        if ok:
            self._set_licensed(True)
            self._status.configure(text=message or TXT_LICENSE_OK, fg=COL_OK)
            self.after(600, self._close)
            return
        self._status.configure(text=message, fg=COL_BAD)

    def clear(self) -> None:
        self._entry.delete("1.0", tk.END)

    # -- internals -------------------------------------------------------

    def _grab(self) -> None:
        """Make the window modal, tolerating a window manager that refuses."""
        try:
            self.grab_set()
        except tk.TclError:  # pragma: no cover - no window manager
            logger.debug("Lisans penceresi kilitlenemedi")

    def _submit(self) -> str:
        key = "".join(self._entry.get("1.0", tk.END).split())
        if not key:
            self._status.configure(text=TXT_LICENSE_EMPTY, fg=COL_BAD)
            return "break"
        self.set_busy(True)
        self._on_submit(key)
        return "break"

    def _close(self) -> None:
        try:
            self.grab_release()
        except tk.TclError:  # pragma: no cover - never grabbed
            pass
        if self._on_close is not None:
            try:
                self._on_close()
            except Exception:  # pragma: no cover - callback bug
                logger.exception("Lisans penceresi kapatma geri çağrısı başarısız")
        self.destroy()
