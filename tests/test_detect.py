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
    crop_with_padding,
    deskew,
    enhance_plate,
    letterbox,
    sharpness,
)
from lpr.detect.yolo import plausible_box  # noqa: E402

FRAME_H, FRAME_W = 720, 1280


def make_frame(height: int = FRAME_H, width: int = FRAME_W) -> "np.ndarray":
    return np.zeros((height, width, 3), dtype=np.uint8)


def make_plate_crop(height: int = 40, width: int = 160) -> "np.ndarray":
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


def test_device_auto_resolves_without_torch_installed() -> None:
    from lpr.detect.yolo import YoloPlateDetector

    assert YoloPlateDetector._resolve_device("auto") in {"cpu", "cuda"}
    assert YoloPlateDetector._resolve_device("cpu") == "cpu"
    assert YoloPlateDetector._resolve_device("CUDA") == "cuda"


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
    """Only runs where real weights and ultralytics are both available."""
    config = pytest.importorskip("lpr.config")
    pytest.importorskip("ultralytics")
    from pathlib import Path

    from lpr.contracts import Detector
    from lpr.detect.yolo import YoloPlateDetector

    settings = config.Settings()
    weights = YoloPlateDetector._resolve_weights(settings.detection.model_path, settings)
    if not Path(weights).exists():
        pytest.skip(f"no detection weights at {weights}")

    detector = YoloPlateDetector(settings)
    assert isinstance(detector, Detector)
    detector.warmup()
    assert detector.detect(make_frame(480, 640)) == []


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
