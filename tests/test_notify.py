"""Tests for the e-mail alert path.

No SMTP server anywhere: ``EmailNotifier`` takes an injectable sender, so the
transport is a list the test reads afterwards. The one place real ``smtplib``
behaviour matters -- which class is constructed for which port -- is checked by
patching the module rather than by opening a socket.

The assertions worth reading first are the ones about *not* sending, and about
failing quietly. This module sits behind a gate decision that has already been
made, recorded and photographed; nothing it does may propagate back.
"""

from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest

from lpr.config import SmtpConfig
from lpr.notify import MAX_ATTACHMENT_BYTES, EmailNotifier, Notification, build_notifier


class RecordingSender:
    """Stands in for the SMTP transport."""

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.messages: list[EmailMessage] = []

    def __call__(self, message: EmailMessage) -> None:
        if self.error is not None:
            raise self.error
        self.messages.append(message)


def config(**overrides: Any) -> SmtpConfig:
    base: dict[str, Any] = {
        "enabled": True,
        "host": "smtp.example.com",
        "port": 587,
        "user": "gate@example.com",
        "password": "hunter2",
        "from_email": "gate@example.com",
        "to_emails": ["guard@example.com"],
    }
    base.update(overrides)
    return SmtpConfig(**base)


def notification(**overrides: Any) -> Notification:
    base: dict[str, Any] = {
        "plate": "34ABC123",
        "camera": "entry",
        "reason": "unauthorized",
        "ts": "2026-08-27T03:14:00+00:00",
        "confidence": 0.91,
    }
    base.update(overrides)
    return Notification(**base)


def run(notifier: EmailNotifier, *notifications: Notification) -> None:
    """Deliver synchronously, so assertions do not race the worker thread."""
    for item in notifications:
        notifier._deliver(item)


@pytest.fixture()
def snapshot(tmp_path: Path) -> Path:
    path = tmp_path / "34ABC123_20260827-031400.jpg"
    path.write_bytes(b"\xff\xd8\xff" + b"jpegbytes" * 32)
    return path


# ---------------------------------------------------------------------------
# Gating: when nothing may be sent
# ---------------------------------------------------------------------------


def test_email_is_disabled_by_default() -> None:
    """Reaching out to a third-party mail server is an opt-in."""
    assert SmtpConfig().enabled is False
    assert EmailNotifier(SmtpConfig()).enabled is False


@pytest.mark.parametrize(
    ("missing", "value"),
    [("host", ""), ("to_emails", []), ("from_email", "")],
)
def test_an_incomplete_configuration_is_not_usable(missing: str, value: Any) -> None:
    """Half-filled settings are one warning at startup, not a failure per event."""
    overrides: dict[str, Any] = {missing: value}
    if missing == "from_email":
        overrides["user"] = ""  # sender falls back to user, so clear both
    assert EmailNotifier(config(**overrides)).enabled is False


def test_a_disabled_notifier_sends_nothing() -> None:
    sender = RecordingSender()
    notifier = EmailNotifier(config(enabled=False), sender=sender)
    assert notifier.notify(notification()) is False
    assert sender.messages == []


@pytest.mark.parametrize(
    ("reason", "flag"),
    [("unauthorized", "notify_on_unauthorized"), ("blacklisted", "notify_on_blacklisted")],
)
def test_each_reason_has_its_own_switch(reason: str, flag: str) -> None:
    on = EmailNotifier(config(**{flag: True}))
    off = EmailNotifier(config(**{flag: False}))
    assert on.wants(reason) is True
    assert off.wants(reason) is False


def test_an_unknown_reason_never_sends() -> None:
    """A granted entry is not an alert, whatever else is switched on."""
    assert EmailNotifier(config()).wants("granted") is False


def test_notify_before_start_does_not_queue() -> None:
    """No worker means nothing would ever drain the queue."""
    notifier = EmailNotifier(config(), sender=RecordingSender())
    assert notifier.notify(notification()) is False


# ---------------------------------------------------------------------------
# Message construction
# ---------------------------------------------------------------------------


def test_the_message_carries_the_plate_camera_and_reason() -> None:
    notifier = EmailNotifier(config(), sender=RecordingSender())
    message = notifier.build_message(notification())

    assert "34ABC123" in message["Subject"]
    assert "entry" in message["Subject"]
    assert "Yetkisiz" in message["Subject"]
    assert "34ABC123" in message.get_content()


def test_a_blacklisted_alert_reads_differently_from_an_unauthorised_one() -> None:
    """An operator filtering their inbox needs the two apart."""
    notifier = EmailNotifier(config(), sender=RecordingSender())
    unknown = notifier.build_message(notification(reason="unauthorized"))["Subject"]
    barred = notifier.build_message(notification(reason="blacklisted"))["Subject"]
    assert unknown != barred
    assert "Kara Liste" in barred


def test_the_snapshot_is_attached_as_a_jpeg(snapshot: Path) -> None:
    notifier = EmailNotifier(config(), sender=RecordingSender())
    message = notifier.build_message(notification(snapshot=snapshot))

    attachments = list(message.iter_attachments())
    assert len(attachments) == 1
    assert attachments[0].get_content_type() == "image/jpeg"
    assert attachments[0].get_filename() == snapshot.name
    assert attachments[0].get_payload(decode=True) == snapshot.read_bytes()


def test_a_missing_snapshot_still_sends_a_text_alert(tmp_path: Path) -> None:
    """Losing the photograph is a far smaller loss than losing the alert."""
    notifier = EmailNotifier(config(), sender=RecordingSender())
    message = notifier.build_message(notification(snapshot=tmp_path / "gone.jpg"))

    assert list(message.iter_attachments()) == []
    assert "34ABC123" in message.get_content()


def test_an_oversized_snapshot_is_dropped_not_the_alert(tmp_path: Path) -> None:
    """A rejected oversized message would cost the whole notification."""
    huge = tmp_path / "huge.jpg"
    huge.write_bytes(b"\x00" * (MAX_ATTACHMENT_BYTES + 1))
    notifier = EmailNotifier(config(), sender=RecordingSender())
    message = notifier.build_message(notification(snapshot=huge))
    assert list(message.iter_attachments()) == []


def test_an_empty_snapshot_file_is_not_attached(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jpg"
    empty.write_bytes(b"")
    notifier = EmailNotifier(config(), sender=RecordingSender())
    assert list(notifier.build_message(notification(snapshot=empty)).iter_attachments()) == []


def test_all_recipients_are_addressed() -> None:
    notifier = EmailNotifier(
        config(to_emails=["a@example.com", " b@example.com ", ""]), sender=RecordingSender()
    )
    header = notifier.build_message(notification())["To"]
    assert "a@example.com" in header and "b@example.com" in header


def test_the_sender_falls_back_to_the_smtp_user() -> None:
    """Most providers require the envelope sender to be the authenticated user."""
    assert config(from_email="", user="gate@example.com").sender == "gate@example.com"


# ---------------------------------------------------------------------------
# Delivery and failure
# ---------------------------------------------------------------------------


def test_a_delivered_alert_is_counted(snapshot: Path) -> None:
    sender = RecordingSender()
    notifier = EmailNotifier(config(), sender=sender)
    run(notifier, notification(snapshot=snapshot))

    assert notifier.sent == 1
    assert notifier.failed == 0
    assert len(sender.messages) == 1


def test_a_refused_connection_is_counted_not_raised() -> None:
    """The mail server is the least reliable component and the least important.

    The decision it is reporting on has already been made, logged and
    photographed; an SMTP failure must not surface anywhere near the gate.
    """
    notifier = EmailNotifier(config(), sender=RecordingSender(ConnectionRefusedError("down")))
    run(notifier, notification())

    assert notifier.sent == 0
    assert notifier.failed == 1


def test_delivery_survives_a_sender_raising_a_bare_exception() -> None:
    notifier = EmailNotifier(config(), sender=RecordingSender(RuntimeError("boom")))
    run(notifier, notification())
    assert notifier.failed == 1


def test_the_worker_drains_the_queue_end_to_end(snapshot: Path) -> None:
    """The one test that exercises start/notify/stop as the pipeline uses it."""
    sender = RecordingSender()
    notifier = EmailNotifier(config(), sender=sender)
    notifier.start()
    try:
        assert notifier.notify(notification(snapshot=snapshot)) is True
    finally:
        notifier.stop(timeout=5)

    assert notifier.sent == 1
    assert sender.messages[0]["Subject"].startswith("[LPR]")


def test_stop_is_safe_without_start() -> None:
    EmailNotifier(config(), sender=RecordingSender()).stop()


# ---------------------------------------------------------------------------
# Transport selection
# ---------------------------------------------------------------------------


def test_port_465_connects_over_implicit_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    """465 is SMTPS: STARTTLS on it fails, so the class must differ."""
    import lpr.notify as notify_module

    used: list[str] = []

    class FakeSMTP:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            used.append(type(self).__name__)

        def ehlo(self) -> None: ...
        def starttls(self) -> None:
            used.append("starttls")

        def login(self, *args: Any) -> None: ...
        def send_message(self, message: Any) -> None: ...
        def quit(self) -> None: ...

    class FakeSMTPSSL(FakeSMTP):
        pass

    monkeypatch.setattr(notify_module.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(notify_module.smtplib, "SMTP_SSL", FakeSMTPSSL)

    EmailNotifier(config(port=465))._send_via_smtp(EmailMessage())
    assert used == ["FakeSMTPSSL"], "465 must not attempt STARTTLS"

    used.clear()
    EmailNotifier(config(port=587))._send_via_smtp(EmailMessage())
    assert used == ["FakeSMTP", "starttls"]


# ---------------------------------------------------------------------------
# build_notifier
# ---------------------------------------------------------------------------


def test_build_notifier_warns_but_does_not_raise_on_a_half_configuration(
    tmp_settings: Any,
) -> None:
    """A bad mail configuration must never stop the pipeline from starting."""
    tmp_settings.smtp.enabled = True
    tmp_settings.smtp.host = ""
    notifier = build_notifier(tmp_settings)
    assert notifier.enabled is False


def test_a_user_without_a_password_is_not_usable() -> None:
    """The exact shape a deployment lands in after the credential moves to .env.

    `config.yaml` ships `user` filled and `password` empty. Starting the worker
    on that would fail authentication once per refused vehicle; refusing up
    front makes it one warning at startup instead.
    """
    assert EmailNotifier(config(user="gate@example.com", password="")).enabled is False


def test_a_relay_that_wants_no_authentication_is_still_usable() -> None:
    """An internal MTA on port 25 has no user and needs no password."""
    assert EmailNotifier(config(user="", password="")).enabled is True


# ---------------------------------------------------------------------------
# Accounting for the alerts that are never sent
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"host": ""}, ["host"]),
        ({"to_emails": []}, ["to_emails"]),
        ({"password": ""}, ["password"]),
        ({"from_email": "", "user": ""}, ["from_email"]),  # sender falls back to user
        ({"host": "", "password": ""}, ["host", "password"]),
        ({}, []),
    ],
)
def test_missing_fields_names_every_gap(overrides: Any, expected: list[str]) -> None:
    """The startup warning has to say *which* key is empty, not just "eksik"."""
    assert config(**overrides).missing_fields == expected


def test_a_disabled_config_is_missing_nothing() -> None:
    """An operator who turned e-mail off is not misconfigured."""
    assert config(enabled=False, host="").missing_fields == []


def test_usable_still_agrees_with_missing_fields() -> None:
    """The two views of the same question must never disagree."""
    for overrides in ({}, {"host": ""}, {"password": ""}, {"enabled": False}):
        cfg = config(**overrides)
        assert cfg.usable is (cfg.enabled and not cfg.missing_fields)


def test_build_notifier_names_the_missing_key(tmp_settings: Any, caplog: Any) -> None:
    """The half-configured case that shipped: user set, password blank.

    Without the field name in the log this is indistinguishable from a gate
    nobody drove up to -- the service starts, reports no error, and sends
    nothing for the rest of its uptime.
    """
    import logging

    tmp_settings.smtp.enabled = True
    tmp_settings.smtp.host = "smtp.example.com"
    tmp_settings.smtp.from_email = "gate@example.com"
    tmp_settings.smtp.to_emails = ["guard@example.com"]
    tmp_settings.smtp.user = "gate@example.com"
    tmp_settings.smtp.password = ""

    with caplog.at_level(logging.WARNING, logger="lpr.notify"):
        notifier = build_notifier(tmp_settings)

    assert notifier.enabled is False
    assert "password" in caplog.text
    assert "LPR_SMTP__PASSWORD" in caplog.text


def test_an_alert_dropped_for_want_of_configuration_is_counted(caplog: Any) -> None:
    """A refused vehicle nobody hears about must at least leave a trace."""
    import logging

    notifier = EmailNotifier(config(password=""), sender=RecordingSender())
    with caplog.at_level(logging.WARNING, logger="lpr.notify"):
        assert notifier.notify(notification()) is False

    assert notifier.suppressed == 1
    assert "34ABC123" in caplog.text
    assert "password" in caplog.text


def test_the_unconfigured_warning_is_written_once_per_process(caplog: Any) -> None:
    """One refused vehicle per frame must not become one warning per frame."""
    import logging

    notifier = EmailNotifier(config(password=""), sender=RecordingSender())
    with caplog.at_level(logging.WARNING, logger="lpr.notify"):
        for _ in range(5):
            notifier.notify(notification())

    assert notifier.suppressed == 5, "every dropped alert is still counted"
    assert caplog.text.count("LPR_SMTP__PASSWORD") == 0
    assert len([r for r in caplog.records if r.levelno >= logging.WARNING]) == 1


def test_a_switched_off_category_is_not_a_misconfiguration(caplog: Any) -> None:
    """Silence the operator asked for stays silent, and uncounted."""
    import logging

    notifier = EmailNotifier(config(notify_on_unauthorized=False), sender=RecordingSender())
    with caplog.at_level(logging.WARNING, logger="lpr.notify"):
        assert notifier.notify(notification()) is False

    assert notifier.suppressed == 0
    assert caplog.records == []


def test_a_usable_notifier_that_was_never_started_warns(caplog: Any) -> None:
    """Correct configuration plus a missing start() is the worst silence of all."""
    import logging

    notifier = EmailNotifier(config(), sender=RecordingSender())
    with caplog.at_level(logging.WARNING, logger="lpr.notify"):
        assert notifier.notify(notification()) is False

    assert notifier.suppressed == 1
    assert "start()" in caplog.text


def test_the_shipped_config_does_not_carry_a_password(tmp_settings: Any) -> None:
    """config.yaml is committed; the credential belongs in .env."""
    from lpr.config import Settings

    assert Settings().smtp.password == ""
