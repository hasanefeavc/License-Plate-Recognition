"""Tests for the detection layer.

cv2 and numpy are required for anything here to mean something, so they are
skipped at collection time when absent. torch / ultralytics are *not* required:
the detector classes are imported inside the test bodies, and the tests that
genuinely need a model are guarded with ``pytest.importorskip`` individually.
That keeps this file collectable in a CI job with no ML wheels installed.
"""

from __future__ import annotations

import pytest

cv2 = pytest.importorskip("cv2", reason="opencv is required for detection tests")
np = pytest.importorskip("numpy", reason="numpy is required for detection tests")

from lpr.detect.preprocess import (  # noqa: E402  (must follow the skip guards)
    apply_gamma,
    auto_gamma,
    crop_with_padding,
    deskew,
    enhance_frame,
    enhance_plate,
    hard_case_variants,
    invert,
    letterbox,
    normalize_lighting,
    otsu_binarize,
    rectify_perspective,
    sharpness,
    stretch_contrast,
    unsharp_mask,
)
from lpr.detect.yolo import plausible_box  # noqa: E402

FRAME_H, FRAME_W = 720, 1280


def make_frame(height: int = FRAME_H, width: int = FRAME_W) -> np.ndarray:
    return np.zeros((height, width, 3), dtype=np.uint8)


def make_plate_crop(height: int = 40, width: int = 160) -> np.ndarray:
    """A synthetic plate: white background with dark bars standing in for glyphs."""
    crop = np.full((height, width, 3), 235, dtype=np.uint8)
    for index in range(6):
        x = 10 + index * 24
        crop[8 : height - 8, x : x + 10] = 20
    return crop


# ---------------------------------------------------------------------------
# Box plausibility
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bbox",
    [
        (100, 100, 300, 150),  # 200x50, aspect 4.0 -- a textbook plate
        (0, 0, 60, 20),  # 60x20, aspect 3.0, at the frame corner
        (500, 400, 800, 450),  # aspect 6.0, a grazing angle
    ],
)
def test_plausible_box_accepts_plate_shapes(bbox: tuple[int, int, int, int]) -> None:
    assert plausible_box(bbox, (FRAME_H, FRAME_W, 3)) is True


@pytest.mark.parametrize(
    ("bbox", "reason"),
    [
        ((100, 100, 200, 200), "square: aspect 1.0 is below the plate range"),
        ((100, 100, 900, 150), "aspect 16.0 is above the plate range"),
        ((100, 100, 130, 110), "too small in absolute pixels"),
        ((100, 100, 100, 150), "zero width"),
        ((100, 100, 300, 100), "zero height"),
        ((300, 150, 100, 100), "inverted corners"),
    ],
)
def test_plausible_box_rejects_non_plates(bbox: tuple[int, int, int, int], reason: str) -> None:
    assert plausible_box(bbox, (FRAME_H, FRAME_W, 3)) is False, reason


def test_plausible_box_rejects_boxes_too_small_for_the_frame() -> None:
    """A plate-shaped box can still be far too few pixels to read."""
    tiny = (0, 0, 45, 14)  # aspect ~3.2, but a speck in a 4K frame
    assert plausible_box(tiny, (720, 1280, 3)) is True
    assert plausible_box(tiny, (2160, 3840, 3)) is False


def test_plausible_box_survives_garbage_input() -> None:
    garbage = ("a", "b", "c", "d")
    assert plausible_box(garbage, (FRAME_H, FRAME_W)) is False  # type: ignore[arg-type]
    assert plausible_box((0, 0, 200, 50), ()) is True


# ---------------------------------------------------------------------------
# letterbox
# ---------------------------------------------------------------------------


def test_letterbox_preserves_aspect_ratio_and_pads_to_size() -> None:
    result = letterbox(make_frame(), 640)
    assert result.image.shape[:2] == (640, 640)
    assert result.scale == pytest.approx(640 / 1280)
    assert result.pad_x == pytest.approx(0.0)
    assert result.pad_y == pytest.approx((640 - 360) / 2)
    assert result.original_shape == (FRAME_H, FRAME_W)


def test_letterbox_coordinate_round_trip() -> None:
    """A box mapped forward and back must land where it started."""
    result = letterbox(make_frame(), 640)
    source_box = (100.0, 200.0, 340.0, 260.0)

    forward = tuple(
        value * result.scale + (result.pad_x if index % 2 == 0 else result.pad_y)
        for index, value in enumerate(source_box)
    )
    x1, y1, x2, y2 = result.unmap_box(forward)  # type: ignore[arg-type]

    assert (x1, y1, x2, y2) == pytest.approx(source_box, abs=1.0)


def test_letterbox_unmap_clamps_padding_into_the_frame() -> None:
    result = letterbox(make_frame(), 640)
    # A box the model placed entirely inside the grey padding.
    x1, y1, x2, y2 = result.unmap_box((10.0, 0.0, 200.0, 40.0))
    assert 0 <= x1 <= x2 <= FRAME_W
    assert 0 <= y1 <= y2 <= FRAME_H


def test_letterbox_of_a_non_square_target() -> None:
    result = letterbox(make_frame(480, 640), (320, 320))
    assert result.image.shape[:2] == (320, 320)


def test_letterbox_never_raises_on_junk() -> None:
    result = letterbox(np.zeros((0, 0, 3), dtype=np.uint8), 640)
    assert result.scale == 1.0


# ---------------------------------------------------------------------------
# crop_with_padding
# ---------------------------------------------------------------------------


def test_crop_with_padding_adds_a_margin() -> None:
    frame = make_frame(200, 200)
    crop = crop_with_padding(frame, (50, 50, 150, 100), pad_ratio=0.1)
    # 100x50 box, 10% pad -> 10px horizontally, 5px vertically, both sides
    assert crop.shape[:2] == (60, 120)


def test_crop_with_padding_clamps_at_the_frame_edges() -> None:
    frame = make_frame(100, 100)
    top_left = crop_with_padding(frame, (0, 0, 50, 20), pad_ratio=0.5)
    assert top_left.shape[:2] == (30, 75)  # padding truncated at x=0 and y=0

    # 40x20 box at the corner: 20px/10px of padding, truncated at x=100, y=100
    bottom_right = crop_with_padding(frame, (60, 80, 100, 100), pad_ratio=0.5)
    assert bottom_right.shape[:2] == (30, 60)
    assert bottom_right.size > 0


def test_crop_with_padding_handles_a_box_outside_the_frame() -> None:
    frame = make_frame(100, 100)
    assert crop_with_padding(frame, (200, 200, 300, 250), pad_ratio=0.0).size == 0


def test_crop_with_padding_copies_rather_than_views() -> None:
    frame = make_frame(100, 100)
    crop = crop_with_padding(frame, (10, 10, 60, 30), pad_ratio=0.0)
    crop[:] = 255
    assert frame[10:30, 10:60].max() == 0


def test_crop_with_padding_normalises_inverted_boxes() -> None:
    frame = make_frame(100, 100)
    crop = crop_with_padding(frame, (60, 30, 10, 10), pad_ratio=0.0)
    assert crop.shape[:2] == (20, 50)


# ---------------------------------------------------------------------------
# sharpness
# ---------------------------------------------------------------------------


def test_sharpness_orders_sharp_above_blurred() -> None:
    sharp = make_plate_crop()
    blurred = cv2.GaussianBlur(sharp, (9, 9), 0)
    very_blurred = cv2.GaussianBlur(sharp, (21, 21), 0)

    assert sharpness(sharp) > sharpness(blurred) > sharpness(very_blurred)


def test_sharpness_of_a_flat_image_is_near_zero() -> None:
    assert sharpness(np.full((40, 160, 3), 128, dtype=np.uint8)) == pytest.approx(0.0, abs=1e-6)


def test_sharpness_never_raises() -> None:
    assert sharpness(np.zeros((0, 0, 3), dtype=np.uint8)) == 0.0
    assert sharpness(None) == 0.0  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# enhance_plate / deskew
# ---------------------------------------------------------------------------


def test_enhance_plate_returns_two_variants() -> None:
    enhanced = enhance_plate(make_plate_crop())
    assert enhanced.gray.ndim == 2
    assert enhanced.binary is not None
    assert enhanced.binary.ndim == 2
    assert len(enhanced.variants) == 2


def test_enhance_plate_upscales_small_crops() -> None:
    enhanced = enhance_plate(make_plate_crop(height=20, width=80), target_height=64)
    assert enhanced.gray.shape[0] >= 60


def test_enhance_plate_does_not_shrink_large_crops() -> None:
    enhanced = enhance_plate(make_plate_crop(height=120, width=400), target_height=64)
    assert enhanced.gray.shape[0] == 120


def test_enhance_plate_never_raises() -> None:
    enhanced = enhance_plate(np.zeros((0, 0, 3), dtype=np.uint8))
    assert enhanced.binary is None


def test_deskew_keeps_the_crop_shape_and_is_bounded() -> None:
    crop = make_plate_crop()
    rotated = cv2.warpAffine(
        crop,
        cv2.getRotationMatrix2D((80.0, 20.0), 8.0, 1.0),
        (160, 40),
        borderMode=cv2.BORDER_REPLICATE,
    )
    straightened = deskew(rotated)
    assert straightened.shape == rotated.shape


def test_deskew_returns_the_input_when_it_cannot_estimate() -> None:
    flat = np.full((30, 100, 3), 200, dtype=np.uint8)
    assert deskew(flat) is flat
    tiny = np.zeros((3, 3, 3), dtype=np.uint8)
    assert deskew(tiny) is tiny


# ---------------------------------------------------------------------------
# unsharp_mask
# ---------------------------------------------------------------------------


def make_soft_plate(height: int = 60, width: int = 240) -> np.ndarray:
    """A plate crop whose glyph edges have been blurred, as a soft optic would."""
    return cv2.GaussianBlur(make_plate_crop(height, width), (5, 5), 0)


def test_unsharp_mask_raises_edge_contrast() -> None:
    """The point of sharpening: measurably crisper edges than the input."""
    soft = make_soft_plate()
    assert sharpness(unsharp_mask(soft, amount=0.8)) > sharpness(soft)


def test_unsharp_mask_is_a_no_op_at_zero_amount() -> None:
    crop = make_soft_plate()
    assert unsharp_mask(crop, amount=0.0) is crop


def test_unsharp_mask_does_not_modify_its_input() -> None:
    """Frames are shared with the live view and the snapshot writer."""
    crop = make_soft_plate()
    before = crop.copy()
    unsharp_mask(crop, amount=1.0)
    assert np.array_equal(crop, before)


def test_unsharp_mask_threshold_protects_flat_regions() -> None:
    """Sensor noise on a flat plate background must not be amplified."""
    noisy_flat = np.full((60, 240), 128, dtype=np.uint8)
    rng = np.random.default_rng(0)
    noisy_flat = np.clip(
        noisy_flat.astype(np.int16) + rng.integers(-2, 3, noisy_flat.shape), 0, 255
    ).astype(np.uint8)

    guarded = unsharp_mask(noisy_flat, amount=2.0, threshold=6)
    unguarded = unsharp_mask(noisy_flat, amount=2.0, threshold=0)
    assert float(guarded.std()) < float(unguarded.std())


def test_unsharp_mask_saturates_instead_of_wrapping() -> None:
    """uint8 overflow would turn a highlight into a black hole."""
    crop = make_plate_crop()
    assert unsharp_mask(crop, amount=3.0).max() <= 255


def test_unsharp_mask_never_raises_on_junk() -> None:
    assert unsharp_mask(None) is None  # type: ignore[arg-type]
    empty = np.zeros((0, 0), dtype=np.uint8)
    assert unsharp_mask(empty) is empty


# ---------------------------------------------------------------------------
# enhance_frame
# ---------------------------------------------------------------------------


def make_dark_frame(height: int = 240, width: int = 320) -> np.ndarray:
    """A low-contrast night frame: everything squeezed into a narrow band."""
    rng = np.random.default_rng(1)
    return rng.integers(40, 90, (height, width, 3), dtype=np.uint8)


def test_enhance_frame_expands_contrast() -> None:
    frame = make_dark_frame()
    assert float(enhance_frame(frame).std()) > float(frame.std())


def test_enhance_frame_preserves_shape_and_dtype() -> None:
    frame = make_dark_frame()
    enhanced = enhance_frame(frame)
    assert enhanced.shape == frame.shape
    assert enhanced.dtype == frame.dtype


def test_enhance_frame_does_not_modify_its_input() -> None:
    """The untouched frame is what the live view and the snapshot record."""
    frame = make_dark_frame()
    before = frame.copy()
    enhance_frame(frame)
    assert np.array_equal(frame, before)


def test_enhance_frame_handles_a_grayscale_frame() -> None:
    gray = cv2.cvtColor(make_dark_frame(), cv2.COLOR_BGR2GRAY)
    enhanced = enhance_frame(gray)
    assert enhanced.shape == gray.shape
    assert enhanced.ndim == 2


def test_enhance_frame_leaves_colour_roughly_alone() -> None:
    """CLAHE runs on LAB lightness, so hue must not swing wildly."""
    frame = make_dark_frame()
    enhanced = enhance_frame(frame)
    before = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)[:, :, 0].astype(float)
    after = cv2.cvtColor(enhanced, cv2.COLOR_BGR2HSV)[:, :, 0].astype(float)
    assert abs(float(before.mean()) - float(after.mean())) < 15.0


def test_enhance_frame_never_raises_on_junk() -> None:
    assert enhance_frame(None) is None  # type: ignore[arg-type]
    empty = np.zeros((0, 0, 3), dtype=np.uint8)
    assert enhance_frame(empty) is empty


# ---------------------------------------------------------------------------
# Dynamic lighting: auto_gamma / apply_gamma / stretch_contrast
# ---------------------------------------------------------------------------


def make_lit_plate(scale: float = 1.0, offset: int = 0) -> np.ndarray:
    """A plate crop re-exposed: ``scale`` for shadow, ``offset`` for glare."""
    base = cv2.cvtColor(make_plate_crop(60, 240), cv2.COLOR_BGR2GRAY).astype(np.float32)
    return np.clip(base * scale + offset, 0, 255).astype(np.uint8)


def test_auto_gamma_leaves_a_well_exposed_plate_alone() -> None:
    """A plate is bimodal and legitimately bright; that is not a fault to correct."""
    assert auto_gamma(make_lit_plate()) == pytest.approx(1.0)


def test_auto_gamma_brightens_a_crop_shot_in_deep_shadow() -> None:
    assert auto_gamma(make_lit_plate(scale=0.18)) < 1.0


def test_auto_gamma_darkens_a_crop_blown_out_by_glare() -> None:
    assert auto_gamma(make_lit_plate(offset=150)) > 1.0


def test_auto_gamma_corrects_proportionally_to_the_problem() -> None:
    """A slightly bright plate must not get the same treatment as a blown one."""
    mild = auto_gamma(make_lit_plate(offset=90))
    severe = auto_gamma(make_lit_plate(offset=150))
    assert 1.0 < mild < severe


def test_auto_gamma_stays_within_its_bounds() -> None:
    for image in (make_lit_plate(scale=0.02), make_lit_plate(offset=250)):
        assert 0.4 <= auto_gamma(image) <= 2.5


def test_auto_gamma_declines_on_a_fully_clipped_crop() -> None:
    """Solid black and solid white have no exposure left to recover."""
    assert auto_gamma(np.zeros((40, 160), dtype=np.uint8)) == pytest.approx(1.0)
    assert auto_gamma(np.full((40, 160), 255, dtype=np.uint8)) == pytest.approx(1.0)


def test_auto_gamma_never_raises() -> None:
    assert auto_gamma(None) == 1.0  # type: ignore[arg-type]
    assert auto_gamma(np.zeros((0, 0), dtype=np.uint8)) == 1.0


def test_apply_gamma_brightens_below_one_and_darkens_above() -> None:
    crop = make_lit_plate(scale=0.4)
    assert apply_gamma(crop, 0.5).mean() > crop.mean()
    assert apply_gamma(crop, 2.0).mean() < crop.mean()


def test_apply_gamma_of_one_is_the_identity() -> None:
    crop = make_lit_plate()
    assert apply_gamma(crop, 1.0) is crop


def test_apply_gamma_does_not_modify_its_input() -> None:
    crop = make_lit_plate(scale=0.3)
    before = crop.copy()
    apply_gamma(crop, 0.5)
    assert np.array_equal(crop, before)


def test_apply_gamma_never_raises() -> None:
    assert apply_gamma(None, 0.5) is None  # type: ignore[arg-type]


def test_stretch_contrast_expands_a_narrow_histogram() -> None:
    narrow = make_lit_plate(scale=0.25)
    assert float(stretch_contrast(narrow).std()) > float(narrow.std())


def test_stretch_contrast_ignores_an_already_wide_histogram() -> None:
    """Nothing to gain, and amplifying it would amplify the noise too."""
    wide = make_lit_plate()
    assert stretch_contrast(wide) is wide


def test_stretch_contrast_refuses_a_crop_with_no_signal() -> None:
    """A flat grey crop would otherwise have its sensor noise blown up to full scale."""
    flat = np.full((60, 240), 128, dtype=np.uint8)
    assert stretch_contrast(flat) is flat


def test_stretch_contrast_survives_a_single_hot_pixel() -> None:
    """Percentiles, not min/max: one specular highlight must not pin the scale."""
    narrow = make_lit_plate(scale=0.25)
    spiked = narrow.copy()
    spiked[0, 0] = 255
    assert float(stretch_contrast(spiked).std()) > float(spiked.std())


def test_stretch_contrast_never_raises() -> None:
    assert stretch_contrast(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# normalize_lighting
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scale", "offset", "label"),
    [
        (0.18, 0, "deep shadow"),
        (0.45, 0, "underexposed"),
        (1.0, 90, "glare"),
        (1.0, 150, "blown out by a headlight"),
    ],
)
def test_normalize_lighting_recovers_contrast_at_the_extremes(
    scale: float, offset: int, label: str
) -> None:
    crop = make_lit_plate(scale=scale, offset=offset)
    assert float(normalize_lighting(crop).std()) > float(crop.std()), label


def test_normalize_lighting_leaves_a_well_exposed_plate_untouched() -> None:
    """Self-limiting: the common case must not pay for the rescue path."""
    crop = make_lit_plate()
    assert normalize_lighting(crop) is crop


def test_normalize_lighting_does_not_modify_its_input() -> None:
    crop = make_lit_plate(scale=0.2)
    before = crop.copy()
    normalize_lighting(crop)
    assert np.array_equal(crop, before)


def test_normalize_lighting_never_raises() -> None:
    assert normalize_lighting(None) is None  # type: ignore[arg-type]
    empty = np.zeros((0, 0), dtype=np.uint8)
    assert normalize_lighting(empty) is empty


def test_enhance_plate_recovers_a_night_crop_better_with_normalisation() -> None:
    """The end-to-end effect of the lighting stage inside the OCR pre-pass."""
    night = cv2.cvtColor(make_lit_plate(scale=0.15), cv2.COLOR_GRAY2BGR)
    with_norm = enhance_plate(night, normalize_light=True).gray
    without = enhance_plate(night, normalize_light=False).gray
    assert float(with_norm.std()) > float(without.std())


# ---------------------------------------------------------------------------
# rectify_perspective
# ---------------------------------------------------------------------------


def make_plate_scene(height: int = 60, width: int = 240) -> np.ndarray:
    """A bordered plate sitting on a dark bumper, i.e. with an outline to find."""
    scene = np.full((height + 40, width + 80, 3), 40, dtype=np.uint8)
    plate = np.full((height, width, 3), 240, dtype=np.uint8)
    cv2.rectangle(plate, (0, 0), (width - 1, height - 1), (30, 30, 30), 2)
    for index in range(6):
        x = 15 + index * 38
        plate[12 : height - 12, x : x + 16] = 20
    scene[20 : 20 + height, 40 : 40 + width] = plate
    return scene


def skew(scene: np.ndarray, pinch: int = 10) -> np.ndarray:
    """Squash the left edge vertically, as a plate seen from the side would be."""
    height, width = scene.shape[:2]
    source = np.float32([[0, 0], [width - 1, 0], [width - 1, height - 1], [0, height - 1]])
    target = np.float32(
        [[0, pinch], [width - 1, 0], [width - 1, height - 1], [0, height - 1 - pinch]]
    )
    return cv2.warpPerspective(
        scene,
        cv2.getPerspectiveTransform(source, target),
        (width, height),
        borderMode=cv2.BORDER_REPLICATE,
    )


def test_rectify_perspective_flattens_an_angled_plate() -> None:
    """The whole point: a side-view plate comes back plate-shaped."""
    rectified = rectify_perspective(skew(make_plate_scene()))
    assert rectified is not None
    aspect = rectified.shape[1] / rectified.shape[0]
    assert 1.2 <= aspect <= 8.0


def test_rectify_perspective_output_is_more_rectangular_than_the_input() -> None:
    """The far edge is stretched back up towards the near one."""
    skewed = skew(make_plate_scene(), pinch=14)
    rectified = rectify_perspective(skewed)
    assert rectified is not None
    # The plate occupied ~4:1 before the skew; rectification should land nearer
    # that than the skewed crop's own bounding box does.
    assert rectified.shape[0] > 8 and rectified.shape[1] > 16


def test_rectify_perspective_declines_when_there_is_no_outline() -> None:
    """No trustworthy quad means None, so the caller keeps what it had."""
    assert rectify_perspective(np.full((60, 240, 3), 200, dtype=np.uint8)) is None


def test_rectify_perspective_rejects_the_crop_border_as_a_quad() -> None:
    """Edge detection finds the crop's own rectangle; warping it is a no-op."""
    rng = np.random.default_rng(0)
    noise = rng.integers(0, 255, (60, 240, 3), dtype=np.uint8)
    assert rectify_perspective(noise) is None


def test_rectify_perspective_declines_on_a_crop_too_small_to_judge() -> None:
    assert rectify_perspective(np.zeros((8, 8, 3), dtype=np.uint8)) is None


def test_rectify_perspective_never_raises_on_junk() -> None:
    assert rectify_perspective(None) is None  # type: ignore[arg-type]
    assert rectify_perspective(np.zeros((0, 0, 3), dtype=np.uint8)) is None


# ---------------------------------------------------------------------------
# minAreaRect fallback
#
# approxPolyDP only finds the outline when the border traces cleanly enough to
# collapse to four points. On a dirty or partly occluded plate it does not, and
# the crop used to get no geometric correction at all -- deskew refuses
# anything past 15 degrees, so a plate rotated further than that had nothing.
# ---------------------------------------------------------------------------


def make_rotated_plate_scene(degrees: float = 25.0) -> np.ndarray:
    """A bordered plate rotated well past what `deskew` is willing to correct.

    The canvas is sized so the *rotated* plate still fits inside it with a
    margin. Rotating `make_plate_scene()` in place instead pushes the plate's
    corners off the edge, which leaves no closed outline for the contour pass
    to find and quietly tests nothing.
    """
    canvas_h, canvas_w = 180, 264
    plate_h, plate_w = 60, 240

    scene = np.full((canvas_h, canvas_w, 3), 40, dtype=np.uint8)
    plate = np.full((plate_h, plate_w, 3), 240, dtype=np.uint8)
    cv2.rectangle(plate, (0, 0), (plate_w - 1, plate_h - 1), (30, 30, 30), 2)
    for index in range(6):
        x = 15 + index * 38
        plate[12 : plate_h - 12, x : x + 16] = 20

    top, left = (canvas_h - plate_h) // 2, (canvas_w - plate_w) // 2
    scene[top : top + plate_h, left : left + plate_w] = plate

    matrix = cv2.getRotationMatrix2D((canvas_w / 2.0, canvas_h / 2.0), degrees, 1.0)
    return cv2.warpAffine(scene, matrix, (canvas_w, canvas_h), borderMode=cv2.BORDER_REPLICATE)


def test_a_plate_rotated_past_the_deskew_limit_is_still_rectified() -> None:
    """The gap the fallback closes, end to end.

    `deskew` refuses anything past MAX_DESKEW_DEGREES (15) as more likely a bad
    contour than a real tilt, so a plate at 25 degrees gets no rotation from
    it. Rectification is what is left, and it has to produce something
    plate-shaped rather than declining.
    """
    rectified = rectify_perspective(make_rotated_plate_scene(25.0))

    assert rectified is not None
    aspect = rectified.shape[1] / rectified.shape[0]
    assert 1.2 <= aspect <= 8.0, f"rectified to a non-plate aspect {aspect:.2f}"


def test_the_min_area_fallback_finds_a_quad_when_the_polygon_fit_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force every polygon approximation to miss, and the outline is still found.

    Monkeypatching `approxPolyDP` into always returning a pentagon is the only
    reliable way to exercise this: which real crops defeat the polygon fit
    depends on OpenCV's contour tracing, so a fixture chosen to fail today
    might start succeeding on the next version and silently stop testing the
    fallback.
    """
    from lpr.detect import preprocess as pre

    def never_a_quad(contour, epsilon, closed):  # type: ignore[no-untyped-def]
        return np.zeros((5, 1, 2), dtype=np.int32)

    monkeypatch.setattr(pre.cv2, "approxPolyDP", never_a_quad)

    gray = cv2.cvtColor(make_rotated_plate_scene(), cv2.COLOR_BGR2GRAY)
    quad = pre._plate_quad(gray)

    assert quad is not None, "minAreaRect should have supplied the four corners"
    assert quad.shape == (4, 2)


def test_the_min_area_fallback_accepts_a_well_filled_rectangle() -> None:
    """A plate border fills nearly all of its own bounding rectangle."""
    from lpr.detect.preprocess import _min_area_quad

    box = cv2.boxPoints(((100.0, 50.0), (160.0, 40.0), 20.0)).astype(np.int32)
    quad = _min_area_quad(box.reshape(-1, 1, 2))

    assert quad is not None
    assert quad.shape == (4, 2)


def test_the_min_area_fallback_rejects_a_shape_that_is_not_a_rectangle() -> None:
    """The guard that makes the fallback safe.

    `minAreaRect` returns a rectangle for *any* contour, an L-shaped shadow
    edge included, and warping a crop onto one of those destroys it. An L fills
    little of its own bounding box, so the fill ratio rejects it.
    """
    from lpr.detect.preprocess import _min_area_quad

    ell = np.array(
        [[0, 0], [100, 0], [100, 20], [20, 20], [20, 100], [0, 100]],
        dtype=np.int32,
    ).reshape(-1, 1, 2)
    assert _min_area_quad(ell) is None


def test_the_min_area_fallback_never_raises_on_junk() -> None:
    from lpr.detect.preprocess import _min_area_quad

    assert _min_area_quad(np.zeros((0, 1, 2), dtype=np.int32)) is None


# ---------------------------------------------------------------------------
# Low-light: Otsu, inversion and the hard-case views
# ---------------------------------------------------------------------------


def make_night_crop(scale: float = 0.18) -> np.ndarray:
    """A plate at night: correct structure, almost all of the range missing."""
    crop = make_plate_crop()
    gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
    return (gray.astype(np.float32) * scale).astype(np.uint8)


def test_otsu_binarize_splits_a_dark_crop_into_two_levels() -> None:
    """The low-light case: dark, but still bimodal, so one global cut works."""
    binary = otsu_binarize(make_night_crop())

    assert binary is not None
    assert set(np.unique(binary)).issubset({0, 255})
    assert 0 in np.unique(binary) and 255 in np.unique(binary)


def test_otsu_recovers_contrast_the_adaptive_threshold_loses() -> None:
    """Why Otsu is here at all, rather than reusing `enhance_plate`'s variant.

    On a uniformly dark crop every neighbourhood is flat, so an adaptive
    threshold cuts each one against its own noise. Otsu takes a single cut from
    the whole histogram, which is what that crop actually needs.
    """
    night = make_night_crop()
    binary = otsu_binarize(night)
    assert binary is not None

    # The glyph bars are at a known place; they must survive as one solid run.
    column = binary[binary.shape[0] // 2]
    transitions = int(np.count_nonzero(np.diff(column.astype(np.int16)) != 0))
    assert 2 <= transitions <= 24, f"expected clean glyph edges, got {transitions}"


def test_otsu_declines_on_a_crop_with_nothing_to_split() -> None:
    """A flat wall has no two modes; thresholding it would return noise."""
    assert otsu_binarize(np.full((40, 160), 90, dtype=np.uint8)) is None


def test_otsu_never_raises_on_junk() -> None:
    assert otsu_binarize(None) is None  # type: ignore[arg-type]
    assert otsu_binarize(np.zeros((0, 0), dtype=np.uint8)) is None


def test_invert_is_its_own_inverse() -> None:
    crop = make_night_crop()
    assert np.array_equal(invert(invert(crop)), crop)


def test_invert_flips_a_light_on_dark_plate_to_dark_on_light() -> None:
    """The IR-illuminator case: bright glyphs on a dark field, back to normal."""
    reversed_polarity = invert(cv2.cvtColor(make_plate_crop(), cv2.COLOR_BGR2GRAY))
    restored = invert(reversed_polarity)

    # The field is the bright majority again, as both recognisers expect.
    assert float(restored.mean()) > float(reversed_polarity.mean())


def test_invert_never_raises_on_junk() -> None:
    assert invert(None) is None  # type: ignore[arg-type]
    empty = np.zeros((0, 0), dtype=np.uint8)
    assert invert(empty) is empty


def test_hard_case_variants_offers_otsu_and_both_inversions() -> None:
    variants = hard_case_variants(make_night_crop())
    assert len(variants) == 3
    assert all(v.size > 0 for v in variants)


def test_hard_case_variants_still_offers_an_inversion_without_otsu() -> None:
    """A flat crop has no Otsu, but its negative is still worth a pass."""
    variants = hard_case_variants(np.full((40, 160), 90, dtype=np.uint8))
    assert len(variants) == 1


def test_hard_case_variants_accepts_a_colour_crop() -> None:
    """It sits behind `enhance_plate` in the pipeline but must not assume it."""
    assert len(hard_case_variants(make_plate_crop())) == 3


def test_hard_case_variants_never_raises_on_junk() -> None:
    assert hard_case_variants(None) == []  # type: ignore[arg-type]
    assert hard_case_variants(np.zeros((0, 0), dtype=np.uint8)) == []


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def test_missing_weights_point_at_the_fetch_script() -> None:
    """A missing model must fail loudly with the fix, not silently degrade."""
    config = pytest.importorskip("lpr.config")
    from lpr.detect.yolo import YoloPlateDetector

    settings = config.Settings(
        detection=config.DetectionConfig(model_path="definitely-not-here.pt")
    )
    with pytest.raises(RuntimeError, match="fetch_models.py"):
        YoloPlateDetector(settings)


def test_build_detector_falls_back_to_contours_without_weights() -> None:
    config = pytest.importorskip("lpr.config")
    from lpr.detect import build_detector
    from lpr.detect.yolo import ContourPlateDetector

    settings = config.Settings(
        detection=config.DetectionConfig(model_path="definitely-not-here.pt")
    )
    detector = build_detector(settings)
    assert isinstance(detector, ContourPlateDetector)


def test_device_auto_resolves_without_torch_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    from lpr import accel
    from lpr.detect.yolo import YoloPlateDetector

    assert YoloPlateDetector._resolve_device("auto") in {"cpu", "cuda"}
    assert YoloPlateDetector._resolve_device("cpu") == "cpu"

    # An explicit GPU request is honoured only when there is a GPU. On a CPU
    # runner it must come back as "cpu" rather than being passed through:
    # ultralytics raises on an unavailable device, build_detector catches that
    # and silently substitutes the far weaker contour detector, so passing the
    # bad device through turns a config error into an accuracy regression.
    monkeypatch.setattr(accel, "cuda_available", lambda: False)
    assert YoloPlateDetector._resolve_device("CUDA") == "cpu"
    assert YoloPlateDetector._resolve_device("0") == "cpu"

    monkeypatch.setattr(accel, "cuda_available", lambda: True)
    assert YoloPlateDetector._resolve_device("CUDA") == "cuda"
    # ultralytics spells GPU ordinals bare; torch's .to() needs the prefix.
    assert YoloPlateDetector._resolve_device("0") == "cuda:0"
    assert YoloPlateDetector._resolve_device("auto") == "cuda"


def test_onnx_export_is_ignored_on_a_cuda_host() -> None:
    """The ONNX preference is a CPU optimisation and must not pull us off the GPU.

    requirements.txt installs the CPU onnxruntime wheel deliberately, so
    adopting an export on a CUDA box would move detection from the GPU to the
    CPU -- slower than the .pt it replaced, and announced only by one INFO line.
    """
    from lpr.detect.yolo import YoloPlateDetector

    detector = YoloPlateDetector.__new__(YoloPlateDetector)
    detector.prefer_onnx = True

    detector.device = "cpu"
    assert detector._onnx_wanted() is True
    detector.device = "cuda"
    assert detector._onnx_wanted() is False
    detector.device = "cuda:0"
    assert detector._onnx_wanted() is False

    detector.prefer_onnx = False
    detector.device = "cpu"
    assert detector._onnx_wanted() is False


def test_contour_detector_satisfies_the_protocol_and_never_raises() -> None:
    config = pytest.importorskip("lpr.config")
    from lpr.contracts import Detector, PlateDetection
    from lpr.detect.yolo import ContourPlateDetector

    detector = ContourPlateDetector(config.Settings())
    assert isinstance(detector, Detector)

    assert detector.detect(make_frame(240, 320)) == []  # blank frame, nothing to find
    assert detector.detect(np.zeros((0, 0, 3), dtype=np.uint8)) == []
    assert detector.detect(None) == []  # type: ignore[arg-type]
    detector.warmup()

    # A bright plate-shaped rectangle on a dark frame is the one case the
    # legacy detector was ever good at.
    frame = make_frame(480, 640)
    frame[200:250, 220:420] = 255
    frame[208:242, 232:408] = make_plate_crop(34, 176)
    detections = detector.detect(frame)
    assert all(isinstance(d, PlateDetection) for d in detections)
    for detection in detections:
        assert plausible_box(detection.bbox, frame.shape)
        assert detection.crop.size > 0
        assert 0.0 <= detection.confidence <= 1.0
    # confidence-sorted, best first
    confidences = [d.confidence for d in detections]
    assert confidences == sorted(confidences, reverse=True)


def test_yolo_detector_end_to_end() -> None:
    """Only runs where real *plate* weights and ultralytics are both available."""
    config = pytest.importorskip("lpr.config")
    pytest.importorskip("ultralytics")
    from pathlib import Path

    from lpr.contracts import Detector
    from lpr.detect.yolo import UnusablePlateWeights, YoloPlateDetector

    settings = config.Settings()
    weights = YoloPlateDetector._resolve_weights(settings.detection.model_path, settings)
    if not Path(weights).exists():
        pytest.skip(f"no detection weights at {weights}")

    try:
        detector = YoloPlateDetector(settings)
    except UnusablePlateWeights as exc:
        # A file existing at models/ is not the same as a plate model existing
        # there: a checkout whose fetch fell back to the COCO baseline lands
        # here. Covered by the fallback tests below.
        pytest.skip(f"weights present but not a plate model: {exc}")

    assert isinstance(detector, Detector)
    detector.warmup()
    assert detector.detect(make_frame(480, 640)) == []


# ---------------------------------------------------------------------------
# Weights that load but cannot find plates
# ---------------------------------------------------------------------------


class _NamedModel:
    """Stands in for a loaded ultralytics model with a given class map."""

    def __init__(self, names) -> None:
        self.names = names


def test_a_single_class_model_needs_no_class_filter() -> None:
    """A dedicated fine-tune: one class, and it is the plate."""
    from lpr.detect.yolo import YoloPlateDetector

    assert YoloPlateDetector._resolve_plate_classes(_NamedModel({0: "plate"})) == {0}
    # Unnamed, but there is only one thing it can be.
    assert YoloPlateDetector._resolve_plate_classes(_NamedModel({0: "0"})) is None


def test_a_multi_class_model_is_filtered_to_its_plate_classes() -> None:
    from lpr.detect.yolo import YoloPlateDetector

    names = {0: "car", 1: "license_plate", 2: "person"}
    assert YoloPlateDetector._resolve_plate_classes(_NamedModel(names)) == {1}


def test_coco_weights_are_rejected_rather_than_treated_as_plates() -> None:
    """80 classes, none of them a plate: the stock COCO model.

    Accepting it (the old behaviour) meant every car, person and chair in
    frame became a plate candidate and was sent to OCR -- the single largest
    source of wasted CPU on a box with no GPU.
    """
    from lpr.detect.yolo import UnusablePlateWeights, YoloPlateDetector

    coco = _NamedModel({index: f"class{index}" for index in range(80)})
    with pytest.raises(UnusablePlateWeights, match="80 classes"):
        YoloPlateDetector._resolve_plate_classes(coco)


def test_build_detector_falls_back_to_contours_on_unusable_weights(monkeypatch) -> None:
    from lpr.detect import ContourPlateDetector, build_detector
    from lpr.detect.yolo import UnusablePlateWeights

    def refuse(settings=None):
        raise UnusablePlateWeights("80 classes and none is a plate")

    monkeypatch.setattr("lpr.detect.YoloPlateDetector", refuse)
    assert isinstance(build_detector(None), ContourPlateDetector)


def test_build_detector_still_propagates_real_misconfiguration(monkeypatch) -> None:
    """Only 'missing' and 'not a plate model' fall back; nothing else does."""
    from lpr.detect import build_detector

    def explode(settings=None):
        raise RuntimeError("CUDA device requested but unavailable")

    monkeypatch.setattr("lpr.detect.YoloPlateDetector", explode)
    with pytest.raises(RuntimeError, match="CUDA"):
        build_detector(None)


def test_a_blank_model_path_resolves_to_the_default_weights_file() -> None:
    """Not to the models *directory*, which used to pass the exists() check."""
    config = pytest.importorskip("lpr.config")
    from lpr.detect.yolo import DEFAULT_WEIGHTS_NAME, YoloPlateDetector

    settings = config.Settings()
    resolved = YoloPlateDetector._resolve_weights("", settings)
    assert resolved.name == DEFAULT_WEIGHTS_NAME
    assert resolved.parent == settings.paths.models_dir


# ---------------------------------------------------------------------------
# Detection downscaling
# ---------------------------------------------------------------------------


def test_downscale_is_a_no_op_below_the_target() -> None:
    from lpr.detect.yolo import _downscale

    frame = make_frame(240, 320)
    out, scale = _downscale(frame, 640)
    assert out is frame and scale == 1.0

    out, scale = _downscale(frame, 0)  # disabled
    assert out is frame and scale == 1.0


def test_downscale_preserves_aspect_ratio_and_reports_its_scale() -> None:
    from lpr.detect.yolo import _downscale

    out, scale = _downscale(make_frame(720, 1280), 640)
    assert out.shape[1] == 640
    assert out.shape[0] == 360  # 720 * 0.5
    assert scale == pytest.approx(0.5)


def test_contour_boxes_come_back_in_full_frame_coordinates() -> None:
    """The whole point of downscaling: the caller must not notice it happened.

    The same plate is detected at capture resolution and at 320 px wide; the
    boxes must agree to within the rounding the downscale introduces.
    """
    config = pytest.importorskip("lpr.config")
    from lpr.detect.yolo import ContourPlateDetector

    frame = make_frame(480, 640)
    frame[200:250, 220:420] = 255
    frame[208:242, 232:408] = make_plate_crop(34, 176)

    full = ContourPlateDetector(config.Settings(detection={"downscale_width": 0}))
    small = ContourPlateDetector(config.Settings(detection={"downscale_width": 320}))

    full_boxes = full.detect(frame)
    small_boxes = small.detect(frame)
    if not full_boxes or not small_boxes:
        pytest.skip("the contour detector found nothing to compare")

    for detection in small_boxes:
        assert plausible_box(detection.bbox, frame.shape)
        # Full-frame coordinates, not the 320-wide working image's.
        assert detection.bbox[2] <= frame.shape[1]
        assert detection.bbox[3] <= frame.shape[0]

    best_full, best_small = full_boxes[0].bbox, small_boxes[0].bbox
    assert all(abs(a - b) <= 8 for a, b in zip(best_full, best_small, strict=True))


# ---------------------------------------------------------------------------
# ONNX backend selection
# ---------------------------------------------------------------------------


def _bare_detector(imgsz: int = 640):
    """A YoloPlateDetector with only the fields the ONNX helpers touch.

    Built without __init__ so these tests need neither weights nor torch.
    """
    from lpr.detect.yolo import YoloPlateDetector

    detector = object.__new__(YoloPlateDetector)
    detector.imgsz = imgsz
    return detector


def test_onnx_candidate_found_next_to_the_pt(tmp_path) -> None:
    from lpr.detect.yolo import YoloPlateDetector

    weights = tmp_path / "plate_yolov8n.pt"
    weights.write_bytes(b"pt")
    assert YoloPlateDetector._onnx_candidate(weights) is None, "no export yet"

    export = tmp_path / "plate_yolov8n.onnx"
    export.write_bytes(b"onnx")
    assert YoloPlateDetector._onnx_candidate(weights) == export


def test_onnx_candidate_ignores_non_pt_weights(tmp_path) -> None:
    """An explicitly configured .onnx (or .engine) is used as-is, not re-derived."""
    from lpr.detect.yolo import YoloPlateDetector

    export = tmp_path / "plate_yolov8n.onnx"
    export.write_bytes(b"onnx")
    assert YoloPlateDetector._onnx_candidate(export) is None


class _FakeBackend:
    def __init__(self, imgsz=None, dynamic=False) -> None:
        if imgsz is not None:
            self.imgsz = imgsz
        self.dynamic = dynamic


class _FakeModel:
    def __init__(self, backend) -> None:
        self.predictor = type("P", (), {"model": backend})()


def test_static_export_at_the_configured_imgsz_is_accepted() -> None:
    detector = _bare_detector(imgsz=640)
    detector._check_static_imgsz(_FakeModel(_FakeBackend(imgsz=[640, 640])))


def test_static_export_at_another_imgsz_is_rejected() -> None:
    """The failure ONNX Runtime would otherwise raise mid-shift, at startup."""
    detector = _bare_detector(imgsz=320)
    with pytest.raises(RuntimeError, match=r"fixed at imgsz=\[640, 640\].*is 320"):
        detector._check_static_imgsz(_FakeModel(_FakeBackend(imgsz=[640, 640])))


def test_dynamic_export_accepts_any_imgsz() -> None:
    detector = _bare_detector(imgsz=320)
    detector._check_static_imgsz(_FakeModel(_FakeBackend(imgsz=[640, 640], dynamic=True)))


def test_export_without_declared_imgsz_is_left_to_the_inference_check() -> None:
    detector = _bare_detector(imgsz=320)
    detector._check_static_imgsz(_FakeModel(_FakeBackend()))
    detector._check_static_imgsz(_FakeModel(None))
    detector._check_static_imgsz(type("M", (), {})())
