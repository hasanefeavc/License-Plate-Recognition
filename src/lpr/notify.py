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

    def __init__(self, config: SmtpConfig, sender: Any = None) -> None:
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
        #: Set once a 535 has been explained, so a gate whose credential is
        #: wrong reports it at the first refused notification instead of at
        #: every one. See ``_warn_authentication``.
        self._auth_warned = False
        #: Alerts thrown away because the notifier was never in a position to
        #: send them -- unusable configuration, or a worker that was not
        #: started. Counted separately from ``dropped`` (a full queue), which
        #: is a mail server that is merely slow. Surfaced once per process as
        #: a warning: repeating it per refused vehicle would bury the log.
        self.suppressed = 0
        self._warned_unconfigured = False

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
            # Two very different silences share this branch. An operator who
            # switched this category off wanted silence and gets it. An
            # operator whose configuration is incomplete did not, and would
            # otherwise never learn that the alert existed.
            if not self.enabled:
                self._warn_unconfigured(notification, self._config.missing_fields)
            return False
        if self._thread is None or not self._thread.is_alive():
            # Usable configuration but no worker: start() was never called, or
            # the pipeline is already stopping. Worth a warning either way --
            # this is a correctly configured site silently not alerting.
            self._warn_unconfigured(notification, ["start() çağrılmadı"])
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

    def _warn_unconfigured(self, notification: Notification, reason: list[str]) -> None:
        """Account for an alert nothing will ever send. Warns once per process."""
        self.suppressed += 1
        if self._warned_unconfigured:
            logger.debug("Bildirim gönderilemedi (%s), yapılandırma eksik", notification.plate)
            return
        self._warned_unconfigured = True
        logger.warning(
            "%s plakası için '%s' uyarısı gönderilemedi: %s. Bu uyarı süreç başına "
            "bir kez yazılır; toplam sayı EmailNotifier.suppressed alanındadır.",
            notification.plate,
            notification.reason,
            ", ".join(reason) or "e-posta kapalı",
        )

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
        except smtplib.SMTPAuthenticationError as exc:
            self.failed += 1
            self._warn_authentication(exc)
            return
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

    def _warn_authentication(self, exc: smtplib.SMTPAuthenticationError) -> None:
        """Say what a 535 from Gmail actually means, once.

        The server's own words are ``(535, b'5.7.8 Username and Password not
        accepted')`` -- or ``BadCredentials`` -- which reads as "you typed your
        password wrong". For Gmail and Google Workspace it almost never is:
        those accounts refuse the account password over SMTP outright, and want
        a 16-character app password minted separately at
        https://myaccount.google.com/apppasswords, which in turn needs 2-step
        verification enabled first. Nothing in the server's reply says so, and
        the operator has no reason to guess it.

        Logged once per process rather than per notification. The credential
        cannot fix itself, so a gate that is refusing entries would otherwise
        repeat this at every unauthorised plate, and the flood is what buries
        the first occurrence.
        """
        if self._auth_warned:
            logger.debug("SMTP kimlik doğrulama hatası yineledi: %s", exc)
            return
        self._auth_warned = True
        logger.error(
            "SMTP kimlik doğrulaması reddedildi (%s). Gmail/Google Workspace "
            "hesaplarında hesap parolası SMTP için kabul edilmez: "
            "https://myaccount.google.com/apppasswords adresinden 16 karakterlik "
            "bir uygulama parolası (app password) oluşturup LPR_SMTP__PASSWORD "
            "değerine .env dosyasında yazın. Bunun için önce 2 adımlı doğrulama "
            "açık olmalıdır.",
            exc,
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
            f"failed={self.failed}, dropped={self.dropped}, "
            f"suppressed={self.suppressed})"
        )


def build_notifier(settings: Settings | None = None, sender: Any = None) -> EmailNotifier:
    """Construct the notifier from settings. Never raises."""
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()
    config = getattr(settings, "smtp", None)
    if config is None:  # pragma: no cover - older Settings
        from lpr.config import SmtpConfig

        config = SmtpConfig()
    if config.enabled and not config.usable:
        missing = ", ".join(config.missing_fields)
        logger.warning(
            "smtp.enabled açık ama şu alanlar eksik: %s. E-posta bildirimleri "
            "devre dışı; yetkisiz/kara listedeki araçlar için uyarı GÖNDERİLMEYECEK. "
            "Parola için config.yaml yerine LPR_SMTP__PASSWORD ortam değişkenini "
            "kullanın (Gmail'de hesap parolası değil, 16 haneli uygulama parolası).",
            missing,
        )
    return EmailNotifier(config, sender=sender)
