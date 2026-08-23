"""Frame and crop preprocessing helpers.

Everything here is a *total* function: it validates its own inputs, catches its
own exceptions, logs at debug level and falls back to returning the input
unchanged. A preprocessing failure must never take down a capture thread --
the worst acceptable outcome is a slightly worse OCR result on one frame.

The OCR pre-pass (:func:`enhance_plate`) is where a large share of the
recognition accuracy comes from. Plate crops out of a 720p frame are often
20-30 px tall, low contrast at night and washed out in daylight; feeding that
straight to a recogniser wastes most of the model's capability. Upscaling to a
sane character height, equalising local contrast with CLAHE and offering a
binarised variant alongside the grayscale one gives the recogniser two very
different shots at the same crop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import cv2
import numpy as np

logger = logging.getLogger(__name__)

__all__ = [
    "EnhancedCrop",
    "LetterboxResult",
    "crop_with_padding",
    "deskew",
    "enhance_plate",
    "letterbox",
    "sharpness",
]

#: Target height a plate crop is upscaled to before OCR.
TARGET_CROP_HEIGHT = 64

#: Never blow a crop up by more than this; interpolating a 6 px crop to 64 px
#: invents detail rather than revealing it.
MAX_UPSCALE = 4.0

#: CLAHE parameters. clipLimit 2.0 is the usual compromise: enough local
#: contrast to separate characters from a dirty plate, not so much that sensor
#: noise is amplified into fake strokes.
CLAHE_CLIP_LIMIT = 2.0
CLAHE_TILE_GRID = (8, 8)

#: Deskew is bounded: a plate seen at more than this angle is better handled by
#: the detector's next frame than by a rotation that smears the glyphs.
MAX_DESKEW_DEGREES = 15.0


@dataclass(frozen=True, slots=True)
class LetterboxResult:
    """A resized, padded frame plus everything needed to undo the transform."""

    image: np.ndarray
    scale: float
    pad_x: float
    pad_y: float
    original_shape: tuple[int, int]  # (height, width) of the source frame

    def unmap_point(self, x: float, y: float) -> tuple[float, float]:
        """Map a point from letterboxed coordinates back to source pixels."""
        if self.scale <= 0:
            return x, y
        return (x - self.pad_x) / self.scale, (y - self.pad_y) / self.scale

    def unmap_box(self, box: tuple[float, float, float, float]) -> tuple[int, int, int, int]:
        """Map an ``(x1, y1, x2, y2)`` box back to source-frame integer pixels.

        The result is clamped to the source frame, so a box that the model
        pushed into the padding still lands inside the image.
        """
        x1, y1, x2, y2 = box
        ux1, uy1 = self.unmap_point(x1, y1)
        ux2, uy2 = self.unmap_point(x2, y2)
        height, width = self.original_shape
        cx1 = int(round(max(0.0, min(float(width), ux1))))
        cy1 = int(round(max(0.0, min(float(height), uy1))))
        cx2 = int(round(max(0.0, min(float(width), ux2))))
        cy2 = int(round(max(0.0, min(float(height), uy2))))
        if cx2 < cx1:
            cx1, cx2 = cx2, cx1
        if cy2 < cy1:
            cy1, cy2 = cy2, cy1
        return cx1, cy1, cx2, cy2


@dataclass(frozen=True, slots=True)
class EnhancedCrop:
    """The variants of one plate crop that get handed to the recogniser."""

    gray: np.ndarray
    binary: np.ndarray | None

    @property
    def variants(self) -> list[np.ndarray]:
        """Grayscale first (usually the better read), binarised second."""
        out = [self.gray]
        if self.binary is not None:
            out.append(self.binary)
        return out


def _is_image(frame: object) -> bool:
    return isinstance(frame, np.ndarray) and frame.ndim in (2, 3) and frame.size > 0


def letterbox(
    frame: np.ndarray,
    size: int | tuple[int, int] = 640,
    color: tuple[int, int, int] = (114, 114, 114),
) -> LetterboxResult:
    """Resize ``frame`` into ``size`` preserving aspect ratio, padding the rest.

    Returns the padded image together with the scale and padding, so detections
    made on the letterboxed image can be mapped back to source pixels via
    :meth:`LetterboxResult.unmap_box`. On any failure the source frame is
    returned with an identity transform.
    """
    target_h, target_w = (size, size) if isinstance(size, int) else (size[1], size[0])
    if not _is_image(frame):
        logger.debug("letterbox: not an image, returning identity")
        empty = frame if isinstance(frame, np.ndarray) else np.zeros((1, 1, 3), np.uint8)
        return LetterboxResult(empty, 1.0, 0.0, 0.0, (1, 1))

    height, width = frame.shape[:2]
    try:
        scale = min(target_h / height, target_w / width)
        new_w = max(1, int(round(width * scale)))
        new_h = max(1, int(round(height * scale)))
        interp = cv2.INTER_AREA if scale < 1.0 else cv2.INTER_LINEAR
        resized = cv2.resize(frame, (new_w, new_h), interpolation=interp)

        pad_w = target_w - new_w
        pad_h = target_h - new_h
        left = pad_w // 2
        top = pad_h // 2
        padded = cv2.copyMakeBorder(
            resized,
            top,
            pad_h - top,
            left,
            pad_w - left,
            cv2.BORDER_CONSTANT,
            value=color,
        )
        return LetterboxResult(padded, scale, float(left), float(top), (height, width))
    except Exception:
        logger.debug("letterbox failed, returning identity transform", exc_info=True)
        return LetterboxResult(frame, 1.0, 0.0, 0.0, (height, width))


def crop_with_padding(
    frame: np.ndarray,
    bbox: tuple[int, int, int, int],
    pad_ratio: float = 0.05,
) -> np.ndarray:
    """Crop ``bbox`` out of ``frame`` with a margin, clamped to the frame.

    A tight detector box often shaves the first and last character; a few
    percent of margin costs nothing and recovers them. Returns an empty array
    only when the box lies fully outside the frame.
    """
    if not _is_image(frame):
        return np.zeros((0, 0, 3), np.uint8)
    height, width = frame.shape[:2]
    try:
        x1, y1, x2, y2 = (int(v) for v in bbox)
        if x2 < x1:
            x1, x2 = x2, x1
        if y2 < y1:
            y1, y2 = y2, y1

        pad = max(0.0, float(pad_ratio))
        pad_x = int(round((x2 - x1) * pad))
        pad_y = int(round((y2 - y1) * pad))

        cx1 = max(0, min(width, x1 - pad_x))
        cy1 = max(0, min(height, y1 - pad_y))
        cx2 = max(0, min(width, x2 + pad_x))
        cy2 = max(0, min(height, y2 + pad_y))
        if cx2 <= cx1 or cy2 <= cy1:
            logger.debug("crop_with_padding: empty box %s in %sx%s", bbox, width, height)
            return np.zeros((0, 0, 3), np.uint8) if frame.ndim == 3 else np.zeros((0, 0), np.uint8)
        return frame[cy1:cy2, cx1:cx2].copy()
    except Exception:
        logger.debug("crop_with_padding failed for %s", bbox, exc_info=True)
        return frame


def to_gray(crop: np.ndarray) -> np.ndarray:
    """Grayscale view of a BGR (or already-gray) crop."""
    if crop.ndim == 2:
        return crop
    if crop.shape[2] == 4:
        return cv2.cvtColor(crop, cv2.COLOR_BGRA2GRAY)
    return cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)


def enhance_plate(crop: np.ndarray, target_height: int = TARGET_CROP_HEIGHT) -> EnhancedCrop:
    """Prepare a plate crop for OCR.

    Upscale small crops to ``target_height`` (cubic, capped at
    :data:`MAX_UPSCALE`), convert to grayscale, equalise local contrast with
    CLAHE, denoise lightly, and produce an adaptive-threshold variant
    alongside. The recogniser tries both variants and keeps the better read --
    binarisation wins on clean high-contrast plates and loses badly on shadowed
    ones, so neither can be the only option.

    Always returns an :class:`EnhancedCrop`; on failure ``gray`` is the input
    and ``binary`` is ``None``.
    """
    if not _is_image(crop):
        empty = crop if isinstance(crop, np.ndarray) else np.zeros((1, 1), np.uint8)
        return EnhancedCrop(gray=empty, binary=None)

    try:
        gray = to_gray(crop)

        height = gray.shape[0]
        if height > 0 and height < target_height:
            factor = min(MAX_UPSCALE, target_height / height)
            if factor > 1.01:
                new_w = max(1, int(round(gray.shape[1] * factor)))
                new_h = max(1, int(round(height * factor)))
                gray = cv2.resize(gray, (new_w, new_h), interpolation=cv2.INTER_CUBIC)

        clahe = cv2.createCLAHE(clipLimit=CLAHE_CLIP_LIMIT, tileGridSize=CLAHE_TILE_GRID)
        gray = clahe.apply(gray)

        # Edge-preserving denoise: a plain Gaussian would soften the very
        # strokes the recogniser needs.
        gray = cv2.bilateralFilter(gray, d=5, sigmaColor=40, sigmaSpace=40)

        binary: np.ndarray | None = None
        try:
            block = 25 if min(gray.shape[:2]) >= 27 else max(3, (min(gray.shape[:2]) // 2) * 2 + 1)
            binary = cv2.adaptiveThreshold(
                gray,
                255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY,
                block,
                15,
            )
        except Exception:
            logger.debug("adaptive threshold variant unavailable", exc_info=True)
            binary = None

        return EnhancedCrop(gray=gray, binary=binary)
    except Exception:
        logger.debug("enhance_plate failed, returning input unchanged", exc_info=True)
        return EnhancedCrop(gray=crop, binary=None)


def deskew(crop: np.ndarray, max_degrees: float = MAX_DESKEW_DEGREES) -> np.ndarray:
    """Rotate a crop so its text baseline is horizontal.

    The angle is estimated from the minimum-area rectangle around the largest
    text blob. Rotation is bounded to +/- ``max_degrees``: beyond that the
    estimate is more likely to be a bad contour than a genuinely tilted plate,
    and rotating on it would destroy an otherwise readable crop. Returns the
    input unchanged when no reliable angle can be found.
    """
    if not _is_image(crop):
        return crop
    try:
        gray = to_gray(crop)
        if min(gray.shape[:2]) < 8:
            return crop

        _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
        contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        if not contours:
            return crop

        largest = max(contours, key=cv2.contourArea)
        if cv2.contourArea(largest) < 10:
            return crop

        (_, _), (rw, rh), angle = cv2.minAreaRect(largest)
        # OpenCV reports the angle of the rectangle's first edge; fold it into
        # the [-45, 45] range that means "tilt away from horizontal".
        if rw < rh:
            angle = angle - 90.0
        if angle < -45.0:
            angle += 90.0
        elif angle > 45.0:
            angle -= 90.0

        if abs(angle) < 0.5 or abs(angle) > max_degrees:
            return crop

        height, width = crop.shape[:2]
        matrix = cv2.getRotationMatrix2D((width / 2.0, height / 2.0), angle, 1.0)
        return cv2.warpAffine(
            crop,
            matrix,
            (width, height),
            flags=cv2.INTER_CUBIC,
            borderMode=cv2.BORDER_REPLICATE,
        )
    except Exception:
        logger.debug("deskew failed, returning input unchanged", exc_info=True)
        return crop


def sharpness(crop: np.ndarray) -> float:
    """Variance of the Laplacian -- higher means sharper.

    Used to throw motion-blurred crops away *before* they reach OCR, where
    they would otherwise produce a confident-looking wrong read that then has
    to be out-voted. Returns ``0.0`` for anything unusable.
    """
    if not _is_image(crop):
        return 0.0
    try:
        gray = to_gray(crop)
        if gray.size == 0:
            return 0.0
        return float(cv2.Laplacian(gray, cv2.CV_64F).var())
    except Exception:
        logger.debug("sharpness failed, reporting 0.0", exc_info=True)
        return 0.0
