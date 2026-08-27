"""Email alerts for refused vehicles, with the event snapshot attached.

An SMTP conversation takes anywhere from 50 ms to a wedged TCP timeout, so
none of it happens on the recognition path. :meth:`EmailNotifier.notify` puts a
message on a bounded queue and returns; one daemon worker owns the connection
and does the talking. That is the same shape as the relay and the snapshot
writer, and for the same reason -- the camera thread must never wait on
something outside the box.

What gets sent
--------------
Two situations, separately switchable:

* **unauthorized** -- the plate is not on the list at all.
* **blacklisted** -- the plate *is* on the list but flagged ``blocked``.

They are different events to an operator. An unknown car at 3 a.m. is a
question; a barred one is an answer, and usually a more urgent one.

Failure policy
--------------
Nothing here can fail the gate. A refused connection, a rejected recipient, a
missing snapshot and a full queue are all logged and dropped. The mail server
is the least reliable component in the system and the one whose failure matters
least: the decision was already made, recorded in ``logs`` and photographed
before this module was ever asked to do anything.
"""

from __future__ import annotations

import logging
import queue
import smtplib
import threading
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lpr.config import Settings, SmtpConfig

logger = logging.getLogger(__name__)

__all__ = ["EmailNotifier", "Notification", "build_notifier"]

#: Port that means implicit TLS. Everything else is plain-then-STARTTLS.
IMPLICIT_TLS_PORT = 465

#: Never attach anything larger than this. A snapshot is a 1080p JPEG (~200 KB)
#: but a misconfigured camera could hand us something far bigger, and a mail
#: server that rejects an oversized message would cost the whole alert.
MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024

#: Sentinel that stops the worker thread.
_STOP = object()

_REASON_LABELS = {
    "unauthorized": "Yetkisiz Araç",
    "blacklisted": "Kara Listedeki Araç",
}


@dataclass(frozen=True, slots=True)
class Notification:
    """One alert waiting to be sent."""

    plate: str
    camera: str
    reason: str
    ts: str
    confidence: float = 0.0
    snapshot: Path | None = None

    @property
    def label(self) -> str:
        return _REASON_LABELS.get(self.reason, self.reason)

    def subject(self) -> str:
        return f"[LPR] {self.label}: {self.plate} ({self.camera})"

    def body(self) -> str:
        lines = [
            f"{self.label} tespit edildi.",
            "",
            f"Plaka      : {self.plate}",
            f"Kamera     : {self.camera}",
            f"Zaman      : {self.ts}",
            f"Güven      : {self.confidence:.2f}",
        ]
        if self.snapshot is None:
            lines += ["", "(Anlık görüntü mevcut değil.)"]
        return "\n".join(lines)


class EmailNotifier:
    """Sends alerts on a worker thread. ``notify`` never blocks or raises."""

    def __init__(self, config: "SmtpConfig", sender: Any = None) -> None:
        self._config = config
        # Injectable purely so the tests can drive every branch without an
        # SMTP server; production passes nothing and gets smtplib.
        self._send = sender or self._send_via_smtp

        self._queue: queue.Queue[Any] = queue.Queue(maxsize=int(config.queue_size))
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self.sent = 0
        self.failed = 0
        self.dropped = 0

    # -- lifecycle -------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return bool(self._config.usable)

    def start(self) -> None:
        """Start the worker. A no-op when the configuration is unusable."""
        if not self.enabled:
            logger.debug("E-posta bildirimleri kapalı veya eksik yapılandırılmış")
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run, name="lpr-email-notifier", daemon=True)
        self._thread.start()
        logger.info(
            "E-posta bildirimleri açık: %s -> %s",
            self._config.host,
            ", ".join(self._config.recipients),
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Drain what is queued, then stop the worker. Idempotent."""
        self._stopping.set()
        thread = self._thread
        if thread is None:
            return
        try:
            self._queue.put_nowait(_STOP)
        except queue.Full:  # pragma: no cover - worker will see the flag anyway
            pass
        thread.join(timeout=timeout)
        self._thread = None

    # -- producer side (called from the recognition path) ----------------

    def wants(self, reason: str) -> bool:
        """Whether this kind of event is configured to notify at all.

        Checked by the caller *before* a snapshot path is resolved, so a site
        that only cares about blacklisted plates does no work for the
        unauthorised ones.
        """
        if not self.enabled:
            return False
        if reason == "unauthorized":
            return bool(self._config.notify_on_unauthorized)
        if reason == "blacklisted":
            return bool(self._config.notify_on_blacklisted)
        return False

    def notify(self, notification: Notification) -> bool:
        """Queue one alert. Returns False when it was dropped.

        Drop-oldest, not drop-newest: a backlog means the mail server is slow,
        and the alert an operator wants is the one that just happened.
        """
        if not self.wants(notification.reason):
            return False
        if self._thread is None or not self._thread.is_alive():
            logger.debug("E-posta çalışanı çalışmıyor, bildirim atlandı")
            return False

        try:
            self._queue.put_nowait(notification)
            return True
        except queue.Full:
            pass

        try:
            self._queue.get_nowait()
            self.dropped += 1
        except queue.Empty:  # pragma: no cover - raced with the worker
            pass
        try:
            self._queue.put_nowait(notification)
            return True
        except queue.Full:  # pragma: no cover - raced with another producer
            self.dropped += 1
            return False

    # -- consumer side ---------------------------------------------------

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            try:
                self._deliver(item)
            except Exception:  # pragma: no cover - _deliver is already total
                logger.exception("E-posta gönderimi beklenmedik şekilde başarısız")
            if self._stopping.is_set() and self._queue.empty():
                return

    def _deliver(self, notification: Notification) -> None:
        try:
            message = self.build_message(notification)
        except Exception:
            self.failed += 1
            logger.warning("E-posta oluşturulamadı: %s", notification.plate, exc_info=True)
            return

        try:
            self._send(message)
        except Exception as exc:
            self.failed += 1
            logger.warning("E-posta gönderilemedi (%s): %s", notification.plate, exc, exc_info=True)
            return

        self.sent += 1
        logger.info(
            "Bildirim gönderildi: %s (%s), ek=%s",
            notification.plate,
            notification.reason,
            notification.snapshot.name if notification.snapshot else "yok",
        )

    # -- message construction --------------------------------------------

    def build_message(self, notification: Notification) -> EmailMessage:
        """Build the MIME message, attaching the snapshot when there is one.

        A missing, unreadable or oversized snapshot degrades to a text-only
        alert. Losing the photograph is a much smaller loss than losing the
        alert, and it is exactly when something is wrong with the disk that an
        operator most wants to hear from the gate.
        """
        message = EmailMessage()
        message["Subject"] = notification.subject()
        message["From"] = formataddr(("LPR", self._config.sender))
        message["To"] = ", ".join(self._config.recipients)
        message["Date"] = formatdate(localtime=True)
        message.set_content(notification.body())

        image = self._read_snapshot(notification.snapshot)
        if image is not None:
            message.add_attachment(
                image,
                maintype="image",
                subtype="jpeg",
                filename=notification.snapshot.name,  # type: ignore[union-attr]
            )
        return message

    @staticmethod
    def _read_snapshot(path: Path | None) -> bytes | None:
        if path is None:
            return None
        try:
            if not path.is_file():
                logger.debug("Anlık görüntü bulunamadı: %s", path)
                return None
            size = path.stat().st_size
            if size == 0 or size > MAX_ATTACHMENT_BYTES:
                logger.warning("Anlık görüntü eklenemedi (%d bayt): %s", size, path)
                return None
            return path.read_bytes()
        except OSError:
            logger.warning("Anlık görüntü okunamadı: %s", path, exc_info=True)
            return None

    # -- transport --------------------------------------------------------

    def _send_via_smtp(self, message: EmailMessage) -> None:
        """Open a connection, send one message, close. Raises on failure.

        A connection per message rather than a pooled one: alerts are rare
        (one per refused vehicle, already rate-limited by the gate's own
        cooldown), and a long-lived socket to a mail server is a thing that
        silently dies between uses.
        """
        config = self._config
        timeout = float(config.timeout_s)

        if int(config.port) == IMPLICIT_TLS_PORT:
            client: smtplib.SMTP = smtplib.SMTP_SSL(config.host, int(config.port), timeout=timeout)
        else:
            client = smtplib.SMTP(config.host, int(config.port), timeout=timeout)

        try:
            client.ehlo()
            if config.use_tls and int(config.port) != IMPLICIT_TLS_PORT:
                client.starttls()
                client.ehlo()
            if config.user:
                client.login(config.user, config.password)
            client.send_message(message)
        finally:
            try:
                client.quit()
            except Exception:  # pragma: no cover - already failing
                client.close()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"EmailNotifier(enabled={self.enabled}, sent={self.sent}, "
            f"failed={self.failed}, dropped={self.dropped})"
        )


def build_notifier(settings: "Settings | None" = None, sender: Any = None) -> EmailNotifier:
    """Construct the notifier from settings. Never raises."""
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()
    config = getattr(settings, "smtp", None)
    if config is None:  # pragma: no cover - older Settings
        from lpr.config import SmtpConfig

        config = SmtpConfig()
    if config.enabled and not config.usable:
        logger.warning(
            "smtp.enabled açık ama yapılandırma eksik (host/from_email/to_emails); "
            "e-posta bildirimleri devre dışı"
        )
    return EmailNotifier(config, sender=sender)
