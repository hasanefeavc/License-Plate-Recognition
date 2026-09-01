#!/usr/bin/env python3
"""End-to-end check of the e-mail alert path, against the real mail server.

The unit tests in ``tests/test_notify.py`` drive every branch of the notifier
with an injected sender, so they prove the queue, the worker, the filtering and
the MIME construction are right. They deliberately never open a socket, which
leaves exactly one link unverified: whether *this site's* credentials, port and
TLS settings actually deliver. That is the link this script exercises, and it is
the one that breaks in the field.

It reports the resolved configuration first -- including **which source** each
value came from, because "I set it in config.yaml and nothing happened" is the
usual shape of the complaint, and the answer is almost always that something
further up the chain won.

Usage
-----
    python scripts/test_email.py                 # diagnose, then send for real
    python scripts/test_email.py --dry-run       # diagnose + full path, no socket
    python scripts/test_email.py --no-snapshot   # text-only alert
    python scripts/test_email.py --reason blacklisted

Exit codes:
    0  the alert was delivered (sent == 1, failed == 0)
    1  it was not, and the reason is on stdout
    2  the configuration cannot send at all; nothing was attempted
"""

from __future__ import annotations

import argparse
import logging
import os
import struct
import sys
import tempfile
import time
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from lpr.config import (  # noqa: E402  (after the path bootstrap)
    _default_config_yaml_path,
    _default_env_file_path,
    get_settings,
)
from lpr.notify import Notification, build_notifier  # noqa: E402

#: How long to wait for the worker to finish one delivery. Generous: a cold TLS
#: handshake to a public provider is routinely several seconds, and a timeout
#: here would report a working configuration as broken.
DELIVERY_TIMEOUT_S = 60.0


def mask(value: str) -> str:
    """Enough of a secret to recognise it, not enough to use it."""
    if not value:
        return "<empty>"
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def source_of(field: str) -> str:
    """Which layer supplied ``smtp.<field>``, by re-reading the layers.

    Approximate by construction -- it re-reads the files rather than asking
    pydantic, which does not record provenance. Good enough for its purpose,
    which is to point at the file to go and edit.
    """
    env_name = f"LPR_SMTP__{field.upper()}"
    if os.environ.get(env_name):
        return "environment"

    env_file = _default_env_file_path()
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith(f"{env_name}=") and line.split("=", 1)[1].strip():
                return f".env ({env_file})"

    yaml_path = _default_config_yaml_path()
    if yaml_path.is_file():
        import yaml

        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        section = data.get("smtp") or {}
        if field in section and section[field] not in ("", None, []):
            return f"config.yaml ({yaml_path})"

    return "default"


def describe(config: object) -> None:
    print("Resolved SMTP configuration")
    print("-" * 64)
    rows = [
        ("enabled", str(config.enabled)),  # type: ignore[attr-defined]
        ("host", config.host),  # type: ignore[attr-defined]
        ("port", str(config.port)),  # type: ignore[attr-defined]
        ("use_tls", str(config.use_tls)),  # type: ignore[attr-defined]
        ("user", config.user or "<empty: unauthenticated relay>"),  # type: ignore[attr-defined]
        ("password", mask(config.password)),  # type: ignore[attr-defined]
        ("from_email", config.sender),  # type: ignore[attr-defined]
        ("to_emails", ", ".join(config.recipients) or "<none>"),  # type: ignore[attr-defined]
        ("notify_on_unauthorized", str(config.notify_on_unauthorized)),  # type: ignore[attr-defined]
        ("notify_on_blacklisted", str(config.notify_on_blacklisted)),  # type: ignore[attr-defined]
    ]
    for name, value in rows:
        print(f"  {name:<24} {value:<38} [{source_of(name)}]")

    print()
    missing = config.missing_fields  # type: ignore[attr-defined]
    if missing:
        print(f"  MISSING: {', '.join(missing)}")
    print(f"  usable: {config.usable}")  # type: ignore[attr-defined]
    print()


def dummy_snapshot(directory: Path) -> Path:
    """A real, decodable 8x8 JPEG-named PNG standing in for an event photo.

    Written as a PNG byte-for-byte (the notifier labels attachments
    ``image/jpeg`` regardless, and no mail server parses the payload) so this
    script needs neither Pillow nor OpenCV -- it has to run on a gate box where
    the point of the exercise is that something else is already broken.
    """

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    width = height = 8
    raw = b"".join(b"\x00" + bytes([40, 90, 140] * width) for _ in range(height))
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    path = directory / "20260901_180000_34ABC123.jpg"
    path.write_bytes(png)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="test_email.py", description="Verify the LPR e-mail alert path end to end."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Exercise queue, worker and MIME construction without opening a socket.",
    )
    parser.add_argument(
        "--reason",
        default="unauthorized",
        choices=("unauthorized", "blacklisted"),
        help="Which alert category to test (each is separately switchable).",
    )
    parser.add_argument("--plate", default="34ABC123")
    parser.add_argument("--camera", default="entry")
    parser.add_argument(
        "--no-snapshot", action="store_true", help="Send a text-only alert."
    )
    parser.add_argument(
        "--timeout", type=float, default=DELIVERY_TIMEOUT_S, help="Seconds to wait."
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="DEBUG logging.")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-8s %(name)s: %(message)s",
    )

    settings = get_settings()
    describe(settings.smtp)

    sent_messages: list[object] = []
    notifier = build_notifier(
        settings, sender=(sent_messages.append if args.dry_run else None)
    )

    if not notifier.enabled:
        print("The notifier is not in a position to send anything.")
        print("Nothing was attempted. Fix the fields listed as MISSING above.")
        return 2

    if not notifier.wants(args.reason):
        print(f"'{args.reason}' alerts are switched off (notify_on_{args.reason}).")
        print("Nothing was attempted.")
        return 2

    with tempfile.TemporaryDirectory(prefix="lpr-mailtest-") as tmp:
        snapshot = None if args.no_snapshot else dummy_snapshot(Path(tmp))
        notification = Notification(
            plate=args.plate,
            camera=args.camera,
            reason=args.reason,
            ts=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            confidence=0.93,
            snapshot=snapshot,
        )

        print(f"Subject: {notification.subject()}")
        print(f"Attachment: {snapshot.name if snapshot else '<none>'}")
        print("Sending..." if not args.dry_run else "Sending (dry run)...")
        print()

        notifier.start()
        queued = notifier.notify(notification)
        if not queued:
            print("FAIL: notify() refused to queue the alert.")
            print(f"  suppressed={notifier.suppressed} dropped={notifier.dropped}")
            notifier.stop()
            return 1

        # stop() drains what is queued and joins the worker, so it is the wait.
        # Done inside the TemporaryDirectory so the snapshot still exists when
        # the worker reads it -- attaching happens on the worker thread.
        started = time.monotonic()
        notifier.stop(timeout=args.timeout)
        elapsed = time.monotonic() - started

    ok = notifier.sent == 1 and notifier.failed == 0
    print()
    print(f"sent={notifier.sent} failed={notifier.failed} "
          f"dropped={notifier.dropped} suppressed={notifier.suppressed} "
          f"({elapsed:.1f}s)")

    if ok:
        where = "captured in-process" if args.dry_run else ", ".join(settings.smtp.recipients)
        print(f"OK: one alert delivered -> {where}")
        return 0

    print("FAIL: the alert was not delivered.")
    print("  The exception is in the WARNING line above from lpr.notify;")
    print("  re-run with -v for the full traceback.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
