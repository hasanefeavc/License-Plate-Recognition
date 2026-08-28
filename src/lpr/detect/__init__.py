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
    FRAME_CLAHE_CLIP_LIMIT,
    FRAME_UNSHARP_AMOUNT,
    EnhancedCrop,
    LetterboxResult,
    crop_with_padding,
    deskew,
    enhance_frame,
    enhance_plate,
    letterbox,
    rectify_perspective,
    sharpness,
    unsharp_mask,
)
from lpr.detect.yolo import (
    ContourPlateDetector,
    UnusablePlateWeights,
    YoloPlateDetector,
    plausible_box,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    import numpy as np

    from lpr.config import Settings

logger = logging.getLogger(__name__)

__all__ = [
    "ContourPlateDetector",
    "EnhancedCrop",
    "LetterboxResult",
    "UnusablePlateWeights",
    "YoloPlateDetector",
    "build_detector",
    "build_frame_preprocessor",
    "crop_with_padding",
    "deskew",
    "enhance_frame",
    "enhance_plate",
    "letterbox",
    "plausible_box",
    "rectify_perspective",
    "sharpness",
    "unsharp_mask",
]


def build_detector(settings: "Settings | None" = None) -> Detector:
    """Construct the configured detector.

    Returns :class:`~lpr.detect.yolo.YoloPlateDetector`. It falls back to the
    much weaker :class:`~lpr.detect.yolo.ContourPlateDetector`, with a loud
    warning, in exactly two cases:

    * the weights file is missing -- a fresh checkout, or a container with an
      unprovisioned ``models/`` volume, still starts;
    * the weights load but hold no plate class
      (:class:`~lpr.detect.yolo.UnusablePlateWeights`) -- in practice the stock
      COCO model. Its 80 classes contain no licence plate, so running it means
      every car, person and chair in frame becomes a "plate candidate" and is
      sent to OCR. The contour detector is weak, but it is at least looking for
      plate-shaped things, and it does not spend seconds a frame proving it.

    Every other failure (ultralytics not installed, corrupt weights, unusable
    device) propagates: those are misconfigurations that must be fixed, not
    papered over with a detector nobody would choose.
    """
    try:
        return YoloPlateDetector(settings)
    except UnusablePlateWeights as exc:
        logger.warning(
            "=" * 72
            + "\nDetection weights are not a plate model -- falling back to the legacy "
            "contour\ndetector.\n%s\nThe contour detector is MATERIALLY LESS ACCURATE: it "
            "needs a clean, well-lit,\nnear-frontal plate border and will miss angled, "
            "blurred, night and\npartially-occluded plates entirely. Do not run a real "
            "gate on it.\n" + "=" * 72,
            exc,
        )
        return ContourPlateDetector(settings)
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


def build_frame_preprocessor(
    settings: "Settings | None" = None,
) -> Callable[[np.ndarray], np.ndarray] | None:
    """A whole-frame enhancement callable, or ``None`` when it is switched off.

    Returns ``None`` unless ``preprocess.frame_enhance`` is set, so the default
    pipeline pays nothing at all -- not even a function call per frame, since
    the orchestrator short-circuits on the ``None``.

    The returned callable is a closure over the configured CLAHE and unsharp
    parameters rather than a bound method, which keeps the orchestrator's
    dependency on this package to a single plain ``Callable``.
    """
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()

    cfg = getattr(settings, "preprocess", None)
    if not bool(getattr(cfg, "frame_enhance", False)):
        return None

    clip_limit = float(getattr(cfg, "frame_clahe_clip", FRAME_CLAHE_CLIP_LIMIT))
    unsharp_amount = float(getattr(cfg, "frame_unsharp_amount", FRAME_UNSHARP_AMOUNT))
    logger.info(
        "Whole-frame enhancement enabled (clahe_clip=%.2f, unsharp=%.2f)",
        clip_limit,
        unsharp_amount,
    )

    def preprocess_frame(frame: np.ndarray) -> np.ndarray:
        return enhance_frame(frame, clip_limit=clip_limit, unsharp_amount=unsharp_amount)

    return preprocess_frame
