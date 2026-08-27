"""OCR backends.

Two interchangeable implementations of the :class:`~lpr.contracts.Recognizer`
protocol, EasyOCR and PaddleOCR, selected by ``settings.ocr.backend``. Both
share the same strategy, which is where the accuracy comes from:

1. Build several views of the same crop -- CLAHE'd and sharpened grayscale, an
   adaptive-threshold binarisation, and a deskewed version. These fail in
   different ways, so a plate that one view garbles another usually reads
   cleanly. If none of them yields a *grammatical* plate, escalate to a
   perspective-corrected copy of the crop and try again; that second stage is
   what recovers a plate photographed from the side, and it is skipped
   entirely on the plates the cheap views already read.
2. Run the recogniser over every view, parse *each* text fragment as well as
   the concatenation of them (plates are frequently split into two boxes at
   the province/letters boundary).
3. Normalise every candidate through :func:`lpr.ocr.normalize.normalize_plate`
   and keep the best by ``(valid, confidence)`` -- a grammatical read always
   beats a higher-scoring ungrammatical one.

Both backends are imported lazily inside ``__init__`` so that importing this
module never drags in torch or paddle, and both **always return a PlateRead**;
failures surface as ``valid=False`` rather than exceptions or ``None``, because
a single unreadable frame is normal operation, not an error.

``settings.ocr.min_confidence`` is deliberately *not* applied here. This layer
reports what it saw as faithfully as it can; the pipeline owns the accept/
reject threshold, and the voter owns the "was it seen repeatedly" question.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import numpy as np

from lpr.contracts import PlateRead
from lpr.detect.preprocess import (
    UNSHARP_AMOUNT,
    deskew,
    enhance_plate,
    rectify_perspective,
)
from lpr.ocr.normalize import normalize_plate

if TYPE_CHECKING:
    from lpr.config import Settings

logger = logging.getLogger(__name__)

__all__ = ["EasyOcrRecognizer", "PaddleOcrRecognizer"]

_EMPTY = PlateRead(text="", confidence=0.0, raw_text="", valid=False)


def _synthetic_crop() -> np.ndarray:
    """A small blank BGR crop, used to warm the backends up."""
    return np.full((64, 200, 3), 255, dtype=np.uint8)


def _usable(images: list[np.ndarray | None]) -> list[np.ndarray]:
    """Drop anything that is not a non-empty array."""
    return [img for img in images if isinstance(img, np.ndarray) and img.size > 0]


def _crop_variants(crop: np.ndarray, unsharp_amount: float = UNSHARP_AMOUNT) -> list[np.ndarray]:
    """Grayscale, binarised and deskewed views of one plate crop."""
    enhanced = enhance_plate(crop, unsharp_amount=unsharp_amount)
    variants: list[np.ndarray | None] = list(enhanced.variants)
    straightened = deskew(enhanced.gray)
    if straightened is not enhanced.gray:
        variants.append(straightened)
    return _usable(variants)


def _rectified_variants(
    crop: np.ndarray, unsharp_amount: float = UNSHARP_AMOUNT
) -> list[np.ndarray]:
    """Perspective-corrected views of one plate crop, or ``[]`` if it has none.

    Rectification finds the plate's four-corner outline and warps it back to a
    head-on rectangle, which is the one correction :func:`deskew` cannot make:
    deskew rotates, and a plate photographed from the side needs its
    foreshortened far edge stretched, not turned. Running the standard
    enhancement over the flattened crop afterwards gives the recogniser the
    same grayscale/binarised pair it gets on the first pass.
    """
    flattened = rectify_perspective(crop)
    if flattened is None:
        return []
    enhanced = enhance_plate(flattened, unsharp_amount=unsharp_amount)
    return _usable(list(enhanced.variants))


def _weighted_confidence(fragments: list[tuple[str, float]]) -> float:
    """Character-weighted mean confidence over the fragments of one read.

    Backends score whole detections, not characters. Weighting each score by
    its fragment length approximates a per-character average, so a confident
    two-character fragment cannot outweigh a shaky six-character one.
    """
    total_chars = sum(len(text) for text, _ in fragments)
    if total_chars <= 0:
        return 0.0
    weighted = sum(conf * len(text) for text, conf in fragments)
    return max(0.0, min(1.0, weighted / total_chars))


class _BaseRecognizer:
    """Shared candidate-selection logic for the concrete backends."""

    #: Overridden per instance from ``settings.preprocess`` by each backend's
    #: ``__init__``. Class-level defaults keep the base class usable on its own,
    #: which is what the tests subclass.
    _unsharp_amount: float = UNSHARP_AMOUNT
    _rectify_enabled: bool = True

    def _configure_preprocessing(self, settings: "Settings") -> None:
        """Read the crop-preprocessing knobs off ``settings``.

        ``getattr`` throughout, so a Settings object predating the
        ``preprocess`` section (or a test double standing in for one) keeps the
        built-in defaults instead of raising.
        """
        cfg = getattr(settings, "preprocess", None)
        self._unsharp_amount = float(getattr(cfg, "crop_unsharp_amount", UNSHARP_AMOUNT))
        self._rectify_enabled = bool(getattr(cfg, "rectify_perspective", True))

    def _read_fragments(self, image: np.ndarray) -> list[tuple[str, float]]:  # pragma: no cover
        raise NotImplementedError

    def recognize(self, crop: np.ndarray) -> PlateRead:
        """Best plate read for ``crop``; ``valid=False`` when nothing parses."""
        if not isinstance(crop, np.ndarray) or crop.size == 0:
            return _EMPTY

        best: PlateRead | None = None
        for stage in self._variant_stages(crop):
            for image in stage:
                best = self._best_of(image, best)
            # Escalate only while nothing grammatical has turned up. The later
            # stages exist for the crops the cheap views could not read; running
            # them on a plate that already parsed would double the OCR cost of
            # every ordinary car at the gate for no gain.
            if best is not None and best.valid:
                break

        return best if best is not None else _EMPTY

    def _variant_stages(self, crop: np.ndarray) -> Iterator[list[np.ndarray]]:
        """Views of ``crop`` to try, in order, cheapest and likeliest first.

        A generator rather than a list: the caller stops pulling as soon as it
        has a valid read, so a stage nobody asks for is never computed.
        """
        try:
            standard = _crop_variants(crop, self._unsharp_amount)
        except Exception:
            logger.debug("crop preprocessing failed; using the raw crop", exc_info=True)
            standard = []
        yield standard or [crop]

        if not self._rectify_enabled:
            return
        try:
            rectified = _rectified_variants(crop, self._unsharp_amount)
        except Exception:
            logger.debug("perspective rectification failed for one crop", exc_info=True)
            return
        if rectified:
            logger.debug(
                "%s: no valid read from the standard views, retrying perspective-corrected",
                type(self).__name__,
            )
            yield rectified

    def _best_of(self, image: np.ndarray, best: PlateRead | None) -> PlateRead | None:
        """Read one crop variant and return whichever of it and ``best`` wins."""
        try:
            fragments = self._read_fragments(image)
        except Exception:
            logger.debug("%s failed on one crop variant", type(self).__name__, exc_info=True)
            return best
        if not fragments:
            return best

        candidates: list[tuple[str, float]] = []
        # The joined fragments: a plate split across two boxes.
        joined = " ".join(text for text, _ in fragments if text)
        if joined:
            candidates.append((joined, _weighted_confidence(fragments)))
        # And each fragment on its own: the plate plus surrounding noise.
        for text, conf in fragments:
            if text:
                candidates.append((text, conf))

        for raw_text, confidence in candidates:
            read = normalize_plate(raw_text, confidence)
            if best is None or _score(read) > _score(best):
                best = read
        return best

    def warmup(self) -> None:
        """Run one recognition on a synthetic crop to pay the lazy-init cost."""
        try:
            self.recognize(_synthetic_crop())
            logger.info("%s warmup complete", type(self).__name__)
        except Exception:
            logger.warning("%s warmup failed", type(self).__name__, exc_info=True)


def _score(read: PlateRead) -> tuple[int, float]:
    """Ranking key: grammatical first, then confidence."""
    return (1 if read.valid else 0, read.confidence)


class EasyOcrRecognizer(_BaseRecognizer):
    """EasyOCR backend (satisfies ``Recognizer``)."""

    def __init__(self, settings: "Settings | None" = None) -> None:
        if settings is None:
            from lpr.config import get_settings

            settings = get_settings()
        self._settings = settings
        self._configure_preprocessing(settings)
        cfg = settings.ocr
        self.allowlist = cfg.allowlist
        self.gpu = bool(cfg.gpu)

        try:
            import easyocr
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "easyocr is not installed but ocr.backend is 'easyocr'. Install "
                "it with `pip install -r requirements.txt` (or `pip install "
                "easyocr`), or set ocr.backend to 'paddleocr'."
            ) from exc

        logger.info("initialising EasyOCR (gpu=%s)", self.gpu)
        self._reader = easyocr.Reader(["en"], gpu=self.gpu)

    def _read_fragments(self, image: np.ndarray) -> list[tuple[str, float]]:
        results = self._reader.readtext(
            image,
            allowlist=self.allowlist,
            detail=1,
            paragraph=False,
        )
        fragments: list[tuple[str, float]] = []
        for item in results or []:
            try:
                # (bbox, text, confidence)
                text = str(item[1])
                confidence = float(item[2]) if len(item) > 2 else 0.0
            except (IndexError, TypeError, ValueError):
                continue
            if text.strip():
                fragments.append((text, confidence))
        return fragments


class PaddleOcrRecognizer(_BaseRecognizer):
    """PaddleOCR backend (satisfies ``Recognizer``).

    PaddleOCR has no allowlist parameter, so the Turkish alphabet restriction
    is enforced downstream by :mod:`lpr.ocr.normalize` instead of at the
    decoder.
    """

    def __init__(self, settings: "Settings | None" = None) -> None:
        if settings is None:
            from lpr.config import get_settings

            settings = get_settings()
        self._settings = settings
        self._configure_preprocessing(settings)

        try:
            from paddleocr import PaddleOCR
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "paddleocr is not installed but ocr.backend is 'paddleocr'. "
                "Install it with `pip install paddleocr paddlepaddle`, or set "
                "ocr.backend to 'easyocr'."
            ) from exc

        logger.info("initialising PaddleOCR")
        try:
            self._ocr = PaddleOCR(use_angle_cls=True, lang="en", show_log=False)
        except (TypeError, ValueError):
            # `show_log` was removed in newer paddleocr releases.
            self._ocr = PaddleOCR(use_angle_cls=True, lang="en")

    def _read_fragments(self, image: np.ndarray) -> list[tuple[str, float]]:
        try:
            results = self._ocr.ocr(image, cls=True)
        except TypeError:
            # Newer releases dropped the `cls` keyword.
            results = self._ocr.ocr(image)
        return _parse_paddle_result(results)


def _parse_paddle_result(results: Any) -> list[tuple[str, float]]:
    """Flatten PaddleOCR output into ``(text, confidence)`` pairs.

    The shape has changed across releases (``[[ [box, (text, conf)], ... ]]``,
    and a ``None`` page when nothing is found), so this walks the structure
    defensively rather than indexing blindly.
    """
    fragments: list[tuple[str, float]] = []
    if not results:
        return fragments
    for page in results:
        if not page:
            continue
        for line in page:
            try:
                payload = line[1]
                text = str(payload[0])
                confidence = float(payload[1])
            except (IndexError, TypeError, ValueError):
                continue
            if text.strip():
                fragments.append((text, confidence))
    return fragments
