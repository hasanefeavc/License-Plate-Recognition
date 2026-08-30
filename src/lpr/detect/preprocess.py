"""Frame and crop preprocessing helpers.

Everything here is a *total* function: it validates its own inputs, catches its
own exceptions, logs at debug level and falls back to returning the input
unchanged. A preprocessing failure must never take down a capture thread --
the worst acceptable outcome is a slightly worse OCR result on one frame.

The OCR pre-pass (:func:`enhance_plate`) is where a large share of the
recognition accuracy comes from. Plate crops out of a 720p frame are often
20-30 px tall, low contrast at night and washed out in daylight; feeding that
straight to a recogniser wastes most of the model's capability. Upscaling to a
sane character height, normalising the exposure of a crop shot under a
headlight or in deep shadow, equalising local contrast with CLAHE, sharpening the
stroke edges back up with an unsharp mask and offering a binarised variant
alongside the grayscale one gives the recogniser several very different shots
at the same crop.

Angled plates get two further tools, both of them geometric rather than
photometric. :func:`deskew` rotates a tilted crop back to horizontal, and
:func:`rectify_perspective` warps a plate photographed from the side back to a
head-on rectangle. They are separate because they cost very different amounts:
deskew is cheap enough to run on every crop, whereas rectification runs an edge
detector and a contour pass and is worth paying for only once the cheaper reads
have already failed.

:func:`enhance_frame` is the whole-frame counterpart, for use ahead of the
detector rather than ahead of OCR. It is off by default -- see
``preprocess.frame_enhance`` in the config -- because unlike everything else
here it changes what the *detector* sees.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass

import cv2
import numpy as np

logger = logging.getLogger(__name__)

__all__ = [
    "EnhancedCrop",
    "LetterboxResult",
    "apply_gamma",
    "auto_gamma",
    "crop_with_padding",
    "deskew",
    "enhance_frame",
    "enhance_plate",
    "hard_case_variants",
    "ink_ratio",
    "invert",
    "letterbox",
    "otsu_binarize",
    "normalize_lighting",
    "rectify_perspective",
    "separate_characters",
    "sharpness",
    "stretch_contrast",
    "unsharp_mask",
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

#: Unsharp masking. ``amount`` is how much of the image's own high-frequency
#: detail is added back on top of it. 0.6 visibly crisps glyph edges; past
#: roughly 1.2 a white halo appears along every stroke, which a binariser then
#: reads as an extra stroke.
UNSHARP_AMOUNT = 0.6
UNSHARP_RADIUS = 3

#: Local contrast (in grey levels) a pixel needs before it is sharpened at all.
#: At 0 the flat background of a plate -- i.e. its sensor noise -- is amplified
#: just as eagerly as a character edge.
UNSHARP_THRESHOLD = 4

#: Whole-frame enhancement is deliberately gentler than the crop pre-pass. The
#: detector is a CNN trained on ordinary frames, so the goal here is to lift a
#: shadowed plate out of the background, not to restyle the image.
FRAME_CLAHE_CLIP_LIMIT = 2.0
FRAME_CLAHE_TILE_GRID = (8, 8)
FRAME_UNSHARP_AMOUNT = 0.5

#: Healthy mean-luminance band for a plate crop, normalised to 0..1.
#:
#: Deliberately *not* a single mid-grey target. A plate is bimodal by
#: construction -- dark glyphs on a light field -- so a correctly exposed one
#: sits around 0.7, and its exact mean says more about how many characters it
#: carries than about its exposure. Driving that to mid grey would "correct"
#: every well-lit plate in the country. Instead the band marks the range in
#: which no correction is needed at all; only a crop outside it is pulled back
#: to the nearest edge, which keeps the intervention minimal and directional.
GAMMA_HEALTHY_LOW = 0.35
GAMMA_HEALTHY_HIGH = 0.78

#: Gamma is bounded. Outside this range the exponent is no longer correcting an
#: exposure, it is inventing detail in pixels that were clipped to 0 or 255 at
#: the sensor -- and a plate blown out that badly is better recovered from the
#: next frame than from arithmetic.
MIN_GAMMA = 0.4
MAX_GAMMA = 2.5

#: Percentiles used by :func:`stretch_contrast`. Plain min/max scaling is
#: hostage to a single specular highlight or one dead pixel; clipping a couple
#: of percent off each end is what makes the stretch robust on a muddy plate
#: with a bright rivet in the corner.
CONTRAST_LOW_PERCENTILE = 2.0
CONTRAST_HIGH_PERCENTILE = 98.0

#: Don't stretch a crop whose usable range is already this wide -- there is
#: nothing to gain, and amplifying it only amplifies noise with it.
MIN_STRETCH_RANGE = 200

#: Below this spread between the percentiles the crop carries no recoverable
#: contrast at all (a uniform grey wall, a fully blown-out plate). Stretching
#: it would multiply sensor noise up into fake structure.
MIN_USABLE_RANGE = 8

#: Perspective rectification bounds. A quadrilateral covering less than this
#: fraction of the crop is a glyph or a mounting bolt, not the plate outline.
MIN_QUAD_AREA_RATIO = 0.25

#: How much of its own minimum-area rectangle a contour must fill before that
#: rectangle is accepted as the plate outline. A plate border traces a nearly
#: perfect rectangle and fills ~0.9 of it; an L-shaped shadow edge or a spray
#: of glyph contours fills far less, and warping on one of those would smear
#: the crop. This is the guard that makes the minAreaRect fallback safe.
MIN_BOX_FILL_RATIO = 0.6

#: Minimum spread between the 5th and 95th percentile of a crop before Otsu is
#: worth running. Otsu assumes a bimodal histogram -- dark glyphs, light field.
#: Given a flat crop instead it still returns a threshold, splitting sensor
#: noise into confident-looking black and white speckle that reads as glyphs.
MIN_OTSU_SPREAD = 12

#: Plate-like aspect window for the rectified output. Outside it the quad was
#: not a plate, and warping to it would smear the glyphs past recognition.
MIN_RECTIFIED_ASPECT = 1.2
MAX_RECTIFIED_ASPECT = 8.0

#: How far a corner must sit from the crop's own corner before the quad counts
#: as a real outline, as a fraction of the crop's width/height with a 2 px
#: floor. Edge detection on a noisy or tightly cropped plate readily traces the
#: crop border itself; warping that back to a rectangle is an identity
#: transform, and the OCR pass over it is wasted. A genuine side-view plate
#: displaces its far corners by far more than this -- a trapezoid worth
#: correcting has one edge 20-40% shorter than the other -- so the test
#: separates the two cases cleanly.
#: The absolute floor matters on short crops, where 3% of a 40 px height is
#: under two pixels -- tighter than Canny plus ``approxPolyDP`` can localise a
#: corner in the first place, so the test would never fire.
NO_OP_CORNER_TOLERANCE_RATIO = 0.03
MIN_NO_OP_CORNER_TOLERANCE = 4.0

#: Structuring element used to break the ink bridges between tightly-set
#: characters (see :func:`separate_characters`). One pixel wide, three tall,
#: and both numbers are load-bearing.
#:
#: **Why vertical.** The intuition that merged characters need *horizontal*
#: thinning is wrong, and measurably so. Two adjacent glyphs do not merge
#: across the full height of the gap between them -- they touch only over the
#: few rows where their strokes come closest, leaving the gap column white
#: above and below. That bridge is therefore short in **y**, not in x, and only
#: an erosion along y reaches it: white grows down from above and up from
#: below until the bridge is gone. A horizontal kernel can only eat into the
#: gap from its left and right ends, which are exactly where the glyph strokes
#: are, so it thins the characters without ever reopening the join.
#:
#: **Why odd.** ``getStructuringElement`` centres the anchor, so an even height
#: erodes asymmetrically -- one row from one side only -- which both halves the
#: bridge thickness it can clear and shifts every glyph half a pixel. Three
#: takes one row from each side, symmetrically, clearing bridges up to two rows
#: thick; that covers the overwhelming majority, and the opening below puts the
#: stroke weight back afterwards.
TIGHT_FONT_KERNEL = (1, 3)

#: Ink coverage outside which :func:`separate_characters` declines to run.
#: Below the floor there is no bridge to break and eroding would only thin
#: already-thin strokes into gaps; above the ceiling the crop is mostly ink
#: (a shadow, a blown-out binarisation) and no amount of erosion recovers
#: glyphs from it.
MIN_TIGHT_FONT_INK = 0.10
MAX_TIGHT_FONT_INK = 0.60


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
    #: The binarised view with the ink bridges between tightly-set characters
    #: broken (:func:`separate_characters`). ``None`` when the crop did not
    #: need it or could not be given it -- which is the common case, so this
    #: costs an extra OCR pass only on the bold, tight-set plates it exists
    #: for. Defaulted so that constructing an ``EnhancedCrop`` positionally,
    #: as the tests and the older call sites do, keeps working.
    separated: np.ndarray | None = None

    @property
    def variants(self) -> list[np.ndarray]:
        """Views to read, best-odds first.

        Grayscale (usually the better read), then the binarisation, then the
        de-bridged binarisation when there is one. Order matters only as a
        tie-break: every view that reads anything votes, and the ensemble
        weighs agreement across them rather than taking the first answer.
        """
        out = [self.gray]
        if self.binary is not None:
            out.append(self.binary)
        if self.separated is not None:
            out.append(self.separated)
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


def enhance_plate(
    crop: np.ndarray,
    target_height: int = TARGET_CROP_HEIGHT,
    unsharp_amount: float = UNSHARP_AMOUNT,
    normalize_light: bool = True,
    tight_font: bool = True,
    tight_font_kernel: tuple[int, int] = TIGHT_FONT_KERNEL,
) -> EnhancedCrop:
    """Prepare a plate crop for OCR.

    Upscale small crops to ``target_height`` (cubic, capped at
    :data:`MAX_UPSCALE`), convert to grayscale, equalise local contrast with
    CLAHE, denoise lightly, sharpen with an unsharp mask, and produce an
    adaptive-threshold variant alongside. The recogniser tries both variants
    and keeps the better read -- binarisation wins on clean high-contrast
    plates and loses badly on shadowed ones, so neither can be the only option.

    The step order is load-bearing. Global exposure first
    (:func:`normalize_lighting`: dynamic gamma, then a percentile contrast
    stretch), because everything downstream assumes a sanely-exposed crop --
    CLAHE in particular works per tile and will amplify the noise inside a
    black tile to full scale if the crop arrives underexposed. CLAHE second,
    for the local contrast that separates a character from a dirty plate.
    Denoise third, so the unsharp mask has no isolated hot pixels left to
    amplify. Sharpen fourth, which puts back the stroke edges the bilateral
    filter softened. Binarise last, off the sharpened image, because a crisper
    edge is exactly what makes the adaptive threshold land on the glyph
    boundary instead of a few pixels inside it.

    ``tight_font`` adds a fourth product: the binarisation with the ink bridges
    between adjacent characters broken (:func:`separate_characters`). It is
    derived from the binary rather than replacing it, because the erosion that
    rescues a bold APP plate would thin a delicate one into gaps -- so both
    views go to the recogniser and the ensemble decides. Only crops whose ink
    coverage says there is a bridge to break produce one, so on an ordinary
    plate this costs a cheap pixel count and no OCR pass at all.

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

        # Global exposure before local contrast -- see the docstring.
        if normalize_light:
            gray = normalize_lighting(gray)

        clahe = cv2.createCLAHE(clipLimit=CLAHE_CLIP_LIMIT, tileGridSize=CLAHE_TILE_GRID)
        gray = clahe.apply(gray)

        # Edge-preserving denoise: a plain Gaussian would soften the very
        # strokes the recogniser needs.
        gray = cv2.bilateralFilter(gray, d=5, sigmaColor=40, sigmaSpace=40)

        # Put the stroke edges back. This is the step that separates a
        # character from its own shadow on a plate lit from the side, which is
        # the usual failure mode on an angled read.
        gray = unsharp_mask(gray, amount=unsharp_amount)

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

        separated = (
            separate_characters(binary, tight_font_kernel)
            if tight_font and binary is not None
            else None
        )

        return EnhancedCrop(gray=gray, binary=binary, separated=separated)
    except Exception:
        logger.debug("enhance_plate failed, returning input unchanged", exc_info=True)
        return EnhancedCrop(gray=crop, binary=None)


def otsu_binarize(gray: np.ndarray) -> np.ndarray | None:
    """Global Otsu threshold of ``gray``, or ``None`` when it would be noise.

    Complements the adaptive threshold in :func:`enhance_plate` rather than
    replacing it, because the two fail on opposite crops. Adaptive
    thresholding decides per neighbourhood, which is what rescues a plate lit
    from one side -- but on a *uniformly* dark night crop every neighbourhood
    is flat, so it thresholds each one against its own noise and returns
    speckle. Otsu picks one global cut from the whole histogram, which is
    exactly right when the entire crop is dark but still bimodal.

    Declines on a crop with no real spread, where the "two modes" Otsu splits
    would be the noise floor and itself.
    """
    if not _is_image(gray):
        return None
    try:
        flat = to_gray(gray)
        low, high = np.percentile(flat, (5.0, 95.0))
        if float(high) - float(low) < MIN_OTSU_SPREAD:
            logger.debug("otsu declined: spread %.1f too flat to threshold", float(high - low))
            return None
        _, binary = cv2.threshold(flat, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        return binary
    except Exception:
        logger.debug("otsu_binarize failed", exc_info=True)
        return None


def invert(image: np.ndarray) -> np.ndarray:
    """Photographic negative of ``image``; returns the input on failure.

    Turkish plates are dark glyphs on a light field, and both recognisers are
    trained accordingly. Two situations flip that polarity: IR illuminators at
    night, which drive a retroreflective plate to white and its glyphs to
    black-on-glare, and the plate appearing as a bright patch in an otherwise
    black frame. Handing the recogniser the negative costs one pass and is
    often the difference between a read and nothing at all.
    """
    if not _is_image(image):
        return image
    try:
        return cv2.bitwise_not(image)
    except Exception:
        logger.debug("invert failed, returning input unchanged", exc_info=True)
        return image


def ink_ratio(binary: np.ndarray) -> float:
    """Fraction of ``binary`` occupied by ink, whichever polarity it is in.

    Glyphs are the *minority* class on any plate crop worth reading -- strokes
    cover well under half the plate -- so the smaller of the two populations is
    the ink. Deciding it that way rather than assuming black-on-white means
    this works unchanged on the inverted, IR-lit crops
    :func:`hard_case_variants` produces.
    """
    if not _is_image(binary) or binary.size == 0:
        return 0.0
    try:
        dark = float(np.count_nonzero(binary < 128)) / float(binary.size)
    except Exception:  # pragma: no cover - defensive
        return 0.0
    return min(dark, 1.0 - dark)


def separate_characters(
    binary: np.ndarray,
    kernel_size: tuple[int, int] = TIGHT_FONT_KERNEL,
) -> np.ndarray | None:
    """Break the ink bridges between tightly-set characters.

    The APP-style plates -- thick strokes, very little space between glyphs --
    lose their character boundaries at binarisation. Adaptive thresholding
    decides per neighbourhood, and in the narrow gap between two heavy strokes
    the whole neighbourhood is ink, so the gap thresholds *as* ink and the two
    characters come out as one blob. The recogniser then reads that blob as a
    single wide glyph, which is why these plates fail as a dropped or invented
    character rather than as a confusable one: "34ABC123" arriving as
    "34AEC123" or "34ABC23".

    The repair is a morphological **opening of the ink** with the vertical
    kernel above -- not a bare erosion. Both break the bridge, but an erosion
    leaves every stroke permanently thinner, and thinned strokes are how a
    "B" becomes an "8" and a "0" becomes a "O". The opening's dilation step puts
    that weight back: once the bridge has been eroded away there is no ink left
    in the gap column for the dilation to grow from, so the separation survives
    while the glyphs return to their original thickness. That asymmetry is the
    entire reason opening is the right primitive here.

    Polarity is detected rather than assumed (see :func:`ink_ratio`), because
    the same function has to serve the inverted, IR-lit views. OpenCV's
    ``MORPH_OPEN`` erodes the *bright* class, so opening the ink means
    ``MORPH_CLOSE`` when the ink is dark -- which is the ordinary daylight
    plate -- and ``MORPH_OPEN`` when it is bright.

    Returns ``None`` -- meaning "no useful variant here", not an error -- when
    the crop is unusable, when the opening changes nothing, or when the ink
    coverage says there is no bridge to break. ``None`` rather than the input
    unchanged so the caller does not spend an OCR pass re-reading a view it has
    already seen.
    """
    if not _is_image(binary):
        return None
    try:
        flat = to_gray(binary)
        coverage = ink_ratio(flat)
        if not (MIN_TIGHT_FONT_INK <= coverage <= MAX_TIGHT_FONT_INK):
            return None

        width = max(1, int(kernel_size[0]))
        height = max(1, int(kernel_size[1]))
        if width == 1 and height == 1:
            return None  # a 1x1 kernel is the identity
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (width, height))

        # Which operation opens the *ink* depends on which class the ink is.
        # MORPH_OPEN removes thin bright features, so it opens the ink only on
        # an inverted crop; on an ordinary dark-glyph plate the equivalent is
        # MORPH_CLOSE, which removes thin dark ones.
        dark_fraction = float(np.count_nonzero(flat < 128)) / float(flat.size)
        ink_is_dark = dark_fraction <= 0.5
        operation = cv2.MORPH_CLOSE if ink_is_dark else cv2.MORPH_OPEN
        separated = cv2.morphologyEx(flat, operation, kernel)

        # An opening that changed nothing means there was no bridge; handing
        # the recogniser a byte-identical view would buy a duplicate ballot.
        if np.array_equal(separated, flat):
            return None
        return separated
    except Exception:
        logger.debug("separate_characters failed", exc_info=True)
        return None


def hard_case_variants(gray: np.ndarray) -> list[np.ndarray]:
    """Last-resort views of an already-enhanced crop, for when nothing read.

    Up to four, in descending order of how often they pay off: the Otsu
    binarisation (the low-light case the adaptive threshold cannot serve), the
    negative of the grayscale (the reversed-polarity case), the negative of
    the Otsu image (both at once), and the Otsu image with tight-set characters
    prised apart (:func:`separate_characters`).

    The last one is here as well as in :func:`enhance_plate` because Otsu takes
    one global cut, which on a bold plate is *more* prone to bridging than the
    adaptive threshold, not less: a single threshold cannot be tight enough for
    the gap between two heavy strokes and loose enough for the plate's darker
    corner at the same time.

    Deliberately *not* part of :func:`enhance_plate`. These views are wrong for
    an ordinary daylight plate -- inverting a perfectly readable crop invites a
    confident misread -- and every extra view is another OCR pass on every car
    at the gate. They earn their cost only on a crop the standard views have
    already failed, so the caller escalates to them rather than always paying.

    Never raises; an unusable input yields an empty list.
    """
    if not _is_image(gray):
        return []
    try:
        flat = to_gray(gray)
        variants: list[np.ndarray] = []

        otsu = otsu_binarize(flat)
        if otsu is not None:
            variants.append(otsu)
        variants.append(invert(flat))
        if otsu is not None:
            variants.append(invert(otsu))
            separated = separate_characters(otsu)
            if separated is not None:
                variants.append(separated)
        return [v for v in variants if isinstance(v, np.ndarray) and v.size > 0]
    except Exception:
        logger.debug("hard_case_variants failed", exc_info=True)
        return []


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


def unsharp_mask(
    image: np.ndarray,
    amount: float = UNSHARP_AMOUNT,
    radius: int = UNSHARP_RADIUS,
    threshold: int = UNSHARP_THRESHOLD,
) -> np.ndarray:
    """Sharpen ``image`` by adding back its own high-frequency detail.

    Computes ``image + amount * (image - blur(image))`` with saturating uint8
    arithmetic, so a highlight clips to white instead of wrapping round to
    black. ``threshold`` leaves pixels whose local contrast is already below it
    untouched, which keeps the flat background of a plate -- and the sensor
    noise living in it -- from being amplified into texture that the binariser
    would go on to read as strokes.

    Returns a new array; the input is never modified. Returns the input
    unchanged on any failure, or when ``amount`` is not positive.
    """
    if not _is_image(image) or amount <= 0:
        return image
    try:
        ksize = max(3, int(radius) | 1)  # GaussianBlur needs an odd kernel
        blurred = cv2.GaussianBlur(image, (ksize, ksize), 0)
        sharpened = cv2.addWeighted(image, 1.0 + float(amount), blurred, -float(amount), 0.0)

        if threshold > 0:
            # Keep the sharpened pixels only where there was detail to sharpen.
            flat = cv2.absdiff(image, blurred) < int(threshold)
            np.copyto(sharpened, image, where=flat)
        return sharpened
    except Exception:
        logger.debug("unsharp_mask failed, returning input unchanged", exc_info=True)
        return image


def enhance_frame(
    frame: np.ndarray,
    clip_limit: float = FRAME_CLAHE_CLIP_LIMIT,
    tile_grid: tuple[int, int] = FRAME_CLAHE_TILE_GRID,
    unsharp_amount: float = FRAME_UNSHARP_AMOUNT,
) -> np.ndarray:
    """Local-contrast and edge enhancement for a whole capture frame.

    Equalises local contrast with CLAHE, then applies a mild unsharp mask. On a
    colour frame CLAHE runs on the L channel of LAB and the chroma channels are
    left alone, so the result is the same scene with its shadows opened up
    rather than a recoloured one. That distinction matters here in a way it
    does not for a crop: the consumer is a CNN trained on ordinary frames, and
    shifting the colour distribution is a good way to lose detections.

    Returns a new array; the input frame is never modified, so the copy kept
    for the live view and for snapshot evidence stays what the camera actually
    saw. Returns the input unchanged on any failure.
    """
    if not _is_image(frame):
        return frame
    try:
        clahe = cv2.createCLAHE(clipLimit=float(clip_limit), tileGridSize=tuple(tile_grid))
        if frame.ndim == 2:
            equalised = clahe.apply(frame)
        else:
            bgr = frame[:, :, :3] if frame.shape[2] == 4 else frame
            lightness, a_chan, b_chan = cv2.split(cv2.cvtColor(bgr, cv2.COLOR_BGR2LAB))
            merged = cv2.merge((clahe.apply(lightness), a_chan, b_chan))
            equalised = cv2.cvtColor(merged, cv2.COLOR_LAB2BGR)
        return unsharp_mask(equalised, amount=unsharp_amount)
    except Exception:
        logger.debug("enhance_frame failed, returning input unchanged", exc_info=True)
        return frame


def _order_quad(points: np.ndarray) -> np.ndarray:
    """Order four corners as top-left, top-right, bottom-right, bottom-left."""
    ordered = np.zeros((4, 2), dtype=np.float32)
    total = points.sum(axis=1)
    diff = np.diff(points, axis=1).ravel()  # y - x
    ordered[0] = points[int(np.argmin(total))]  # smallest x+y -> top-left
    ordered[2] = points[int(np.argmax(total))]  # largest x+y  -> bottom-right
    ordered[1] = points[int(np.argmin(diff))]  # smallest y-x -> top-right
    ordered[3] = points[int(np.argmax(diff))]  # largest y-x  -> bottom-left
    return ordered


def _plate_quad(gray: np.ndarray) -> np.ndarray | None:
    """Four corners of the plate outline in ``gray``, or ``None`` if not found.

    Works off Canny edges rather than a threshold because the plate border is
    a strong edge at every exposure, whereas its brightness relative to the
    bumper is not. The morphological close bridges the gaps that a dirty or
    partly shadowed border leaves in that outline; without it the contour
    fragments and no four-point approximation survives.
    """
    height, width = gray.shape[:2]
    area = float(height) * float(width)
    if area <= 0:
        return None

    edges = cv2.Canny(cv2.GaussianBlur(gray, (5, 5), 0), 50, 150)
    edges = cv2.morphologyEx(edges, cv2.MORPH_CLOSE, np.ones((3, 3), np.uint8))
    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None

    # Largest first, and stop as soon as they are too small to be the plate.
    candidates = [
        contour
        for contour in sorted(contours, key=cv2.contourArea, reverse=True)[:5]
        if cv2.contourArea(contour) >= area * MIN_QUAD_AREA_RATIO
    ]

    for contour in candidates:
        perimeter = cv2.arcLength(contour, True)
        if perimeter <= 0:
            continue
        # Loosen the approximation until it collapses to a quadrilateral; a
        # single fixed epsilon finds the outline on clean borders only.
        for epsilon_ratio in (0.02, 0.03, 0.05):
            approx = cv2.approxPolyDP(contour, epsilon_ratio * perimeter, True)
            if len(approx) == 4 and cv2.isContourConvex(approx):
                return approx.reshape(4, 2).astype(np.float32)

    # Nothing collapsed to a clean quadrilateral. Fall back to the minimum-area
    # *rotated rectangle*, which always yields four points.
    #
    # This is a weaker correction by construction -- a rectangle cannot express
    # the trapezoid of a true side-on view, so warping one back is a rotation
    # and a scale, not a perspective fix. It is still worth having, because it
    # covers the case nothing else does: a plate rotated past
    # MAX_DESKEW_DEGREES, where a broken or cluttered border stops approxPolyDP
    # finding the outline and deskew refuses the angle as implausible. Without
    # this the crop gets no geometric correction at all.
    for contour in candidates:
        quad = _min_area_quad(contour)
        if quad is not None:
            return quad
    return None


def _min_area_quad(contour: np.ndarray) -> np.ndarray | None:
    """Corners of ``contour``'s minimum-area rotated rectangle, if it fits well.

    The fill ratio is the whole safety argument. ``cv2.minAreaRect`` returns a
    rectangle for *any* contour, including an L-shaped shadow edge or a smear
    of glyph blobs, and warping the crop onto one of those destroys it. A real
    plate border fills close to all of its own bounding rectangle, so requiring
    :data:`MIN_BOX_FILL_RATIO` rejects the shapes that are not plate outlines
    while keeping the ones that are.
    """
    try:
        rect = cv2.minAreaRect(contour)
        (_, _), (rect_w, rect_h), _ = rect
        rect_area = float(rect_w) * float(rect_h)
        if rect_area <= 0:
            return None
        if cv2.contourArea(contour) / rect_area < MIN_BOX_FILL_RATIO:
            return None
        return cv2.boxPoints(rect).astype(np.float32)
    except Exception:
        logger.debug("minAreaRect fallback failed", exc_info=True)
        return None


def _is_crop_border(ordered: np.ndarray, shape: tuple[int, int]) -> bool:
    """True when the quad is just the crop's own rectangle, to within a pixel or two.

    Canny finds the crop's edges as readily as the plate's, especially on a
    tight or noisy crop. The resulting quad warps to an identity transform, so
    detecting it here saves the caller a pointless OCR pass over a copy of the
    image it already has.
    """
    height, width = shape
    corners = np.array(
        [[0.0, 0.0], [width - 1.0, 0.0], [width - 1.0, height - 1.0], [0.0, height - 1.0]],
        dtype=np.float32,
    )
    tolerance = np.array(
        [
            max(MIN_NO_OP_CORNER_TOLERANCE, width * NO_OP_CORNER_TOLERANCE_RATIO),
            max(MIN_NO_OP_CORNER_TOLERANCE, height * NO_OP_CORNER_TOLERANCE_RATIO),
        ],
        dtype=np.float32,
    )
    return bool(np.all(np.abs(ordered - corners) <= tolerance))


def rectify_perspective(crop: np.ndarray) -> np.ndarray | None:
    """Flatten a plate seen at an angle into a head-on view.

    :func:`deskew` can only *rotate*, which straightens a tilted camera but
    does nothing for a plate photographed from the side: there the near edge is
    longer than the far one and every character is trapezoidal. This finds the
    plate's four-corner outline and warps that quadrilateral back to a
    rectangle, turning a side-view crop into something a recogniser trained on
    head-on plates can actually read.

    Deliberately conservative. A quad that is too small, non-convex, or that
    would rectify to a non-plate aspect ratio is rejected rather than guessed
    at, because a wrong warp does not degrade a crop gracefully -- it destroys
    it. Returns ``None`` whenever no trustworthy outline is found, so the
    caller keeps whatever it already had.
    """
    if not _is_image(crop):
        return None
    try:
        gray = to_gray(crop)
        if min(gray.shape[:2]) < 16:
            return None

        quad = _plate_quad(gray)
        if quad is None:
            return None

        top_left, top_right, bottom_right, bottom_left = _order_quad(quad)
        ordered = np.array([top_left, top_right, bottom_right, bottom_left], dtype=np.float32)

        if _is_crop_border(ordered, gray.shape[:2]):
            logger.debug("rectify_perspective: quad is the crop border, nothing to correct")
            return None

        # Size the output from the longer of each opposing pair, i.e. from the
        # near edge, so the foreshortened far edge is stretched up to it rather
        # than the near edge being squashed down.
        target_w = int(
            round(
                max(
                    float(np.linalg.norm(bottom_right - bottom_left)),
                    float(np.linalg.norm(top_right - top_left)),
                )
            )
        )
        target_h = int(
            round(
                max(
                    float(np.linalg.norm(top_right - bottom_right)),
                    float(np.linalg.norm(top_left - bottom_left)),
                )
            )
        )
        if target_w < 16 or target_h < 8:
            return None

        aspect = target_w / target_h
        if not (MIN_RECTIFIED_ASPECT <= aspect <= MAX_RECTIFIED_ASPECT):
            logger.debug("rejecting rectified aspect %.2f, not plate-like", aspect)
            return None

        destination = np.array(
            [
                [0.0, 0.0],
                [target_w - 1.0, 0.0],
                [target_w - 1.0, target_h - 1.0],
                [0.0, target_h - 1.0],
            ],
            dtype=np.float32,
        )
        matrix = cv2.getPerspectiveTransform(ordered, destination)
        return cv2.warpPerspective(
            crop,
            matrix,
            (target_w, target_h),
            flags=cv2.INTER_CUBIC,
            borderMode=cv2.BORDER_REPLICATE,
        )
    except Exception:
        logger.debug("rectify_perspective failed", exc_info=True)
        return None


def auto_gamma(
    image: np.ndarray,
    low: float = GAMMA_HEALTHY_LOW,
    high: float = GAMMA_HEALTHY_HIGH,
) -> float:
    """Gamma exponent that would pull ``image`` back into a healthy exposure band.

    A crop whose mean luminance already lies inside ``[low, high]`` needs no
    correction and gets ``1.0``. One that falls outside is pulled back to the
    *nearest edge* of the band -- not to the middle of it -- by solving
    ``mean ** gamma == target`` for gamma, i.e.
    ``gamma = log(target) / log(mean)`` on the mean normalised to 0..1.

    Below 1 the curve brightens a crop shot in deep shadow; above 1 it pulls
    back one blown out by a headlight or a low winter sun. Correcting only to
    the band edge keeps the intervention as small as the problem: a plate at
    0.80 is nudged, a plate at 0.95 is rescued, and the two do not get the same
    treatment just because both are "too bright".

    Returns ``1.0`` for an unusable image and for the degenerate means (0.0 and
    1.0) where the logarithm has no answer -- a crop clipped to solid black or
    solid white has no exposure left to recover.
    """
    if not _is_image(image):
        return 1.0
    try:
        gray = to_gray(image)
        if gray.size == 0:
            return 1.0
        mean = float(gray.mean()) / 255.0
        if low <= mean <= high:
            return 1.0
        # log(0) and log(1) are where this stops being solvable at all.
        if mean <= 0.01 or mean >= 0.99:
            return 1.0

        target = low if mean < low else high
        gamma = math.log(max(1e-6, min(1.0 - 1e-6, target))) / math.log(mean)
        return float(max(MIN_GAMMA, min(MAX_GAMMA, gamma)))
    except Exception:
        logger.debug("auto_gamma failed, reporting 1.0", exc_info=True)
        return 1.0


def apply_gamma(image: np.ndarray, gamma: float) -> np.ndarray:
    """Apply a gamma curve to ``image`` through a 256-entry lookup table.

    A LUT rather than per-pixel ``pow``: the input is uint8, so there are only
    256 possible answers, and computing them once turns the correction into a
    single ``cv2.LUT`` pass. Returns a new array, and returns the input
    unchanged for a gamma of (effectively) 1.
    """
    if not _is_image(image) or abs(float(gamma) - 1.0) < 1e-3:
        return image
    try:
        safe_gamma = max(MIN_GAMMA, min(MAX_GAMMA, float(gamma)))
        table = np.array(
            [((value / 255.0) ** safe_gamma) * 255.0 for value in range(256)],
            dtype=np.float32,
        )
        return cv2.LUT(image, np.clip(table, 0, 255).astype(np.uint8))
    except Exception:
        logger.debug("apply_gamma failed, returning input unchanged", exc_info=True)
        return image


def stretch_contrast(
    image: np.ndarray,
    low_percentile: float = CONTRAST_LOW_PERCENTILE,
    high_percentile: float = CONTRAST_HIGH_PERCENTILE,
) -> np.ndarray:
    """Rescale ``image`` so its percentile range spans the full 0..255.

    Percentile-based rather than min/max: a single specular highlight off a
    rivet, or one dead pixel, pins a min/max stretch to the extremes and
    achieves nothing. Clipping a couple of percent off each end makes the
    scaling reflect the bulk of the crop instead.

    Returns the input unchanged when the range is already wide enough to gain
    nothing (:data:`MIN_STRETCH_RANGE`), and when it is so narrow that there is
    no signal to recover (:data:`MIN_USABLE_RANGE`) -- stretching a flat grey
    crop only multiplies its sensor noise into fake structure.
    """
    if not _is_image(image):
        return image
    try:
        gray = to_gray(image)
        low = float(np.percentile(gray, low_percentile))
        high = float(np.percentile(gray, high_percentile))
        spread = high - low
        if spread < MIN_USABLE_RANGE or spread >= MIN_STRETCH_RANGE:
            return image

        scale = 255.0 / spread
        return cv2.convertScaleAbs(image, alpha=scale, beta=-low * scale)
    except Exception:
        logger.debug("stretch_contrast failed, returning input unchanged", exc_info=True)
        return image


def normalize_lighting(
    image: np.ndarray,
    low: float = GAMMA_HEALTHY_LOW,
    high: float = GAMMA_HEALTHY_HIGH,
) -> np.ndarray:
    """Normalise exposure on a crop shot in extreme light.

    Two global corrections, in order: dynamic gamma to move the crop's mean
    luminance towards mid grey, then a percentile contrast stretch to spread
    what is left across the full range.

    This runs *before* CLAHE rather than instead of it, and the split is the
    point. CLAHE equalises contrast **locally**, inside each 8x8 tile, which is
    exactly the wrong tool for a crop that is globally too dark or globally
    blown out -- it will happily amplify the noise inside a black tile to full
    scale. Fixing the global exposure first means CLAHE's clip limit then
    operates on a sanely-exposed image and does the job it is good at.

    Both stages are self-limiting (see :data:`GAMMA_HEALTHY_LOW` /
    :data:`GAMMA_HEALTHY_HIGH` and :data:`MIN_STRETCH_RANGE`), so a normally-lit
    plate passes through untouched. Returns the input unchanged on any failure.
    """
    if not _is_image(image):
        return image
    try:
        corrected = apply_gamma(image, auto_gamma(image, low, high))
        return stretch_contrast(corrected)
    except Exception:
        logger.debug("normalize_lighting failed, returning input unchanged", exc_info=True)
        return image
