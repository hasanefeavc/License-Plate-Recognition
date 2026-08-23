"""Optical character recognition, normalisation and multi-frame voting.

Public surface:

    from lpr.ocr import build_recognizer, build_voter, normalize_plate

    recognizer = build_recognizer()      # a Recognizer, per lpr.contracts
    recognizer.warmup()
    read = recognizer.recognize(detection.crop)

    voter = build_voter()                # a Voter, per lpr.contracts
    plate = voter.submit("entry", read)  # str once confirmed, else None

Import cost matters here. ``lpr.ocr.normalize`` and ``lpr.ocr.voting`` are pure
python (standard library only) and are re-exported eagerly, so tests, the API
and the GUI can use them with nothing installed. The recogniser backends pull
in numpy, cv2 and eventually easyocr/paddle, so they are resolved lazily via
:func:`build_recognizer` and module-level ``__getattr__`` -- importing
``lpr.ocr`` on its own costs nothing.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from lpr.ocr.normalize import (
    CONFUSION_MAP,
    PLATE_RE,
    TURKISH_LETTERS,
    coerce_positional,
    extract_candidates,
    normalize_plate,
    strip_noise,
    validate,
)
from lpr.ocr.voting import MultiFrameVoter, build_voter, levenshtein

if TYPE_CHECKING:
    from lpr.config import Settings
    from lpr.contracts import Recognizer

logger = logging.getLogger(__name__)

__all__ = [
    "CONFUSION_MAP",
    "PLATE_RE",
    "TURKISH_LETTERS",
    "EasyOcrRecognizer",
    "MultiFrameVoter",
    "PaddleOcrRecognizer",
    "build_recognizer",
    "build_voter",
    "coerce_positional",
    "extract_candidates",
    "levenshtein",
    "normalize_plate",
    "strip_noise",
    "validate",
]

#: Backends selectable through ``settings.ocr.backend``.
BACKENDS = ("easyocr", "paddleocr")


def build_recognizer(settings: "Settings | None" = None) -> "Recognizer":
    """Construct the recogniser named by ``settings.ocr.backend``.

    Raises ``RuntimeError`` for an unknown backend name, and (from the backend
    class itself) for a known backend whose package is not installed -- with a
    message naming the package to install. There is no silent fallback: a
    service that quietly runs on a different OCR engine than the one it was
    configured with is worse than one that refuses to start.
    """
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()

    backend = (settings.ocr.backend or "").strip().lower()
    if backend == "easyocr":
        from lpr.ocr.recognizer import EasyOcrRecognizer

        return EasyOcrRecognizer(settings)
    if backend == "paddleocr":
        from lpr.ocr.recognizer import PaddleOcrRecognizer

        return PaddleOcrRecognizer(settings)

    raise RuntimeError(
        f"Unknown ocr.backend {settings.ocr.backend!r}. Supported backends: "
        f"{', '.join(BACKENDS)}."
    )


def __getattr__(name: str) -> Any:
    """Resolve the heavy backend classes on first attribute access (PEP 562)."""
    if name in ("EasyOcrRecognizer", "PaddleOcrRecognizer"):
        from lpr.ocr import recognizer

        return getattr(recognizer, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
