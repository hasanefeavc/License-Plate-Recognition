"""Centralised logging setup.

Call ``setup_logging()`` once, as early as possible (main.py / lpr-api /
lpr-gui entry points). Safe to call more than once -- it is idempotent and
will not stack duplicate handlers.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_CONFIGURED_MARKER = "_lpr_configured"

# Third-party loggers that are noisy at INFO/DEBUG and drown out our own
# messages; always pinned to WARNING regardless of our own log level.
_NOISY_LOGGERS = ("ultralytics", "easyocr", "PIL", "urllib3", "asyncio")

_PLAIN_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_PLAIN_DATEFMT = "%Y-%m-%d %H:%M:%S"


class _JsonFormatter(logging.Formatter):
    """One JSON object per line -- friendly to container log collectors."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack_info"] = self.stack_info
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(
    level: str | int = "INFO",
    json: bool = False,
    data_dir: str | Path = "data",
    log_filename: str = "lpr.log",
) -> logging.Logger:
    """Configure the root logger.

    Parameters
    ----------
    level:
        A ``logging`` level name ("INFO", "DEBUG", ...) or numeric level.
    json:
        Plain human-readable text when False (default, good for a TTY);
        single-line JSON per record when True (good for container stdout /
        log aggregators).
    data_dir:
        Directory the rotating log file is written into. Created if missing.
    log_filename:
        Name of the rotating log file within ``data_dir``.

    Idempotent: calling this again (e.g. because both main.py and a
    sub-component call it) reconfigures level/format on the existing
    handlers instead of adding duplicates.
    """
    root = logging.getLogger()
    resolved_level = logging.getLevelName(level) if isinstance(level, str) else level
    # getLevelName on an unknown string returns "Level <str>", guard against that.
    if isinstance(resolved_level, str):
        resolved_level = logging.INFO

    if getattr(root, _CONFIGURED_MARKER, False):
        root.setLevel(resolved_level)
        for handler in root.handlers:
            handler.setFormatter(_build_formatter(json))
        _silence_noisy_loggers()
        return root

    root.setLevel(resolved_level)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(_build_formatter(json))
    root.addHandler(stream_handler)

    try:
        log_dir = Path(data_dir).expanduser().resolve()
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / log_filename,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(_build_formatter(json))
        root.addHandler(file_handler)
    except OSError as exc:
        # Non-fatal: stdout logging still works even if the file handler
        # can't be created (read-only filesystem, permissions, ...).
        root.warning("Could not attach rotating file log handler: %s", exc)

    _silence_noisy_loggers()
    setattr(root, _CONFIGURED_MARKER, True)
    return root


def _build_formatter(json_mode: bool) -> logging.Formatter:
    if json_mode:
        return _JsonFormatter()
    return logging.Formatter(_PLAIN_FORMAT, datefmt=_PLAIN_DATEFMT)


def _silence_noisy_loggers() -> None:
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
