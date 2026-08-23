"""Plate detection.

Public surface:

    from lpr.detect import build_detector
    detector = build_detector()          # a Detector, per lpr.contracts
    detector.warmup()
    detections = detector.detect(frame)

Importing this package is cheap -- it pulls in numpy and cv2 but never torch or
ultralytics, which are imported lazily when a YOLO detector is actually
constructed.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from lpr.contracts import Detector
from lpr.detect.preprocess import (
    EnhancedCrop,
    LetterboxResult,
    crop_with_padding,
    deskew,
    enhance_plate,
    letterbox,
    sharpness,
)
from lpr.detect.yolo import ContourPlateDetector, YoloPlateDetector, plausible_box

if TYPE_CHECKING:
    from lpr.config import Settings

logger = logging.getLogger(__name__)

__all__ = [
    "ContourPlateDetector",
    "EnhancedCrop",
    "LetterboxResult",
    "YoloPlateDetector",
    "build_detector",
    "crop_with_padding",
    "deskew",
    "enhance_plate",
    "letterbox",
    "plausible_box",
    "sharpness",
]


def build_detector(settings: "Settings | None" = None) -> Detector:
    """Construct the configured detector.

    Returns :class:`~lpr.detect.yolo.YoloPlateDetector`. If -- and only if --
    the weights file is missing, it falls back to the much weaker
    :class:`~lpr.detect.yolo.ContourPlateDetector` with a loud warning, so a
    fresh checkout or a container with an unprovisioned models/ volume still
    starts. Every other failure (ultralytics not installed, corrupt weights,
    unusable device) propagates: those are misconfigurations that must be
    fixed, not papered over with a detector nobody would choose.
    """
    try:
        return YoloPlateDetector(settings)
    except RuntimeError as exc:
        message = str(exc)
        if "weights not found" not in message.lower():
            raise
        logger.warning(
            "=" * 72
            + "\nNo detection weights found -- falling back to the legacy contour "
            "detector.\n%s\nThe contour detector is MATERIALLY LESS ACCURATE: it needs a "
            "clean,\nwell-lit, near-frontal plate border and will miss angled, blurred, "
            "night\nand partially-occluded plates entirely. Do not run a real gate on it.\n"
            + "=" * 72,
            message,
        )
        return ContourPlateDetector(settings)
