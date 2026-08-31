"""Redaction of credentials embedded in URLs.

An RTSP camera is addressed as ``rtsp://admin:hunter2@10.0.0.5:554/Streaming``.
The password is part of the address, so every place the address is handled is a
place the password leaks: the connection log line, the reconnect warning, the
camera-status object the dashboard renders, the JSON the API returns, and the
log bundle an operator emails to support when the gate misbehaves.

That last one is the reason this module exists rather than a ``logger.debug``
somewhere. A site's camera password reaching a support inbox is a disclosure
nobody notices, because the log looked like a log.

Pure python and dependency-free so it can be used from the capture thread, the
API layer and the GUI without dragging anything along.

What is kept
------------
Everything that helps somebody diagnose the camera: scheme, host, port and
path. Only the userinfo is replaced, and the *username* survives -- knowing the
account is ``admin`` versus ``operator`` is diagnostic, and it is not the
secret. ``rtsp://admin:hunter2@10.0.0.5/s1`` becomes
``rtsp://admin:***@10.0.0.5/s1``.
"""

from __future__ import annotations

import re

__all__ = ["REDACTION", "mask_url", "mask_text"]

#: What replaces a password. Fixed-width and obviously not a value, so it
#: cannot be mistaken for the real thing in a screenshot.
REDACTION = "***"

#: ``scheme://userinfo@host``. The userinfo half is what gets rewritten.
#:
#: Deliberately narrow: it only fires when there is a scheme *and* an ``@``
#: before the first ``/``, so a Windows device path, a file path containing an
#: ``@``, or a plain ``0``/``/dev/video0`` camera source passes through
#: untouched. Over-eager redaction of a source that has no credentials makes
#: the log less useful for no security gain.
_URL_CREDENTIALS_RE = re.compile(
    r"""
    (?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*://)   # rtsp:// http:// rtmp:// ...
    (?P<user>[^/?#\s:@]+)                      # username, no separators in it
    (?::(?P<password>[^/?#\s@]*))?             # optional :password
    (?P<at>@)
    """,
    re.VERBOSE,
)


def mask_url(value: object) -> str:
    """``value`` as a string with any URL password replaced by :data:`REDACTION`.

    Total: a non-string, an empty value or something that is not a URL at all
    is returned as its plain string form. A camera source is just as often
    ``0`` or ``/dev/video0`` as it is an RTSP URL, and this is called on all of
    them.

    A URL carrying a username but no password is left alone -- there is nothing
    to hide, and rewriting it would suggest a credential exists where none
    does.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if "://" not in text or "@" not in text:
        return text

    def _replace(match: re.Match[str]) -> str:
        if match.group("password") is None:
            return match.group(0)
        return f"{match.group('scheme')}{match.group('user')}:{REDACTION}@"

    try:
        return _URL_CREDENTIALS_RE.sub(_replace, text)
    except Exception:  # pragma: no cover - defensive; masking must never raise
        # Failing closed: if the pattern cannot be applied, return something
        # with no credential in it rather than the original string.
        return "<redacted url>"


def mask_text(value: object) -> str:
    """Mask every URL credential inside a longer piece of text.

    For exception messages and driver output, where the URL is embedded in a
    sentence: OpenCV reports failures as ``Could not open rtsp://admin:pw@...``
    and that string goes straight into ``CameraStatus.last_error``, which the
    API serves.

    Identical to :func:`mask_url` today -- the pattern is not anchored, so it
    already matches mid-string. Kept as a separate name because the two have
    different contracts: this one promises nothing about preserving the rest of
    the text, and may grow other redactions later.
    """
    return mask_url(value)
