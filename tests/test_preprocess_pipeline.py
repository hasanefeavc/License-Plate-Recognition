"""Tests for how the preprocessing enhancements are wired into the pipeline.

The primitives themselves (``unsharp_mask``, ``enhance_frame``,
``rectify_perspective``) are covered in ``test_detect``. What matters here is
the wiring: that the expensive views are only built for crops the cheap ones
could not read, that whole-frame enhancement reaches the detector without
reaching the evidence snapshot, and that a preprocessor blowing up costs one
frame's enhancement rather than the frame.
"""

from __future__ import annotations

from typing import Any

import pytest

np = pytest.importorskip("numpy", reason="numpy is required for preprocessing tests")
pytest.importorskip("cv2", reason="opencv is required for preprocessing tests")

from lpr.contracts import PlateDetection, PlateRead  # noqa: E402
from lpr.detect import build_frame_preprocessor  # noqa: E402
from lpr.ocr.recognizer import _BaseRecognizer  # noqa: E402
from lpr.pipeline.orchestrator import PipelineOrchestrator  # noqa: E402

from .conftest import FakeDetector, FakeRecognizer, FakeRelay, FakeVoter  # noqa: E402


def make_plate_scene(height: int = 60, width: int = 240) -> "np.ndarray":
    """A bordered plate on a dark bumper: an outline rectification can find."""
    import cv2

    scene = np.full((height + 40, width + 80, 3), 40, dtype=np.uint8)
    plate = np.full((height, width, 3), 240, dtype=np.uint8)
    cv2.rectangle(plate, (0, 0), (width - 1, height - 1), (30, 30, 30), 2)
    for index in range(6):
        x = 15 + index * 38
        plate[12 : height - 12, x : x + 16] = 20
    scene[20 : 20 + height, 40 : 40 + width] = plate
    return scene


# ---------------------------------------------------------------------------
# Recogniser: staged escalation
# ---------------------------------------------------------------------------


class ScriptedRecognizer(_BaseRecognizer):
    """A ``_BaseRecognizer`` whose backend returns canned text per variant.

    ``reads`` is consumed one entry per crop variant, so the number of entries
    taken is exactly the number of OCR passes the escalation logic asked for.
    """

    def __init__(self, reads: list[str]) -> None:
        self._reads = list(reads)
        self.variants_seen: list[tuple[int, ...]] = []

    def _read_fragments(self, image: "np.ndarray") -> list[tuple[str, float]]:
        self.variants_seen.append(tuple(image.shape))
        if not self._reads:
            return []
        text = self._reads.pop(0)
        return [(text, 0.9)] if text else []


def test_a_valid_read_stops_the_escalation() -> None:
    """The perspective stage must not be paid for on a plate that already read.

    Every *cheap* view is still read even after one of them parses -- they are
    ranked against each other and the best wins. What must not happen is
    escalating to the expensive stage, so the count is compared against the
    same crop with rectification switched off.
    """
    crop = make_plate_scene()

    recognizer = ScriptedRecognizer(["34ABC123"])
    read = recognizer.recognize(crop)
    assert read.valid is True

    baseline = ScriptedRecognizer(["34ABC123"])
    baseline._rectify_enabled = False
    baseline.recognize(crop)

    assert len(recognizer.variants_seen) == len(baseline.variants_seen)


def test_an_unreadable_crop_escalates_to_perspective_correction() -> None:
    """When no standard view yields a plate, the rectified views are tried."""
    recognizer = ScriptedRecognizer([])  # every variant reads as nothing
    skewed = _skew(make_plate_scene())
    recognizer.recognize(skewed)

    standard = ScriptedRecognizer([])
    standard._rectify_enabled = False
    standard.recognize(skewed)

    assert len(recognizer.variants_seen) > len(standard.variants_seen)


def test_rectification_can_be_switched_off() -> None:
    recognizer = ScriptedRecognizer([])
    recognizer._rectify_enabled = False
    before = len(recognizer.variants_seen)
    recognizer.recognize(_skew(make_plate_scene()))
    # Only the standard views: grayscale, binarised, and possibly a deskew.
    assert before < len(recognizer.variants_seen) <= 3


def test_recognize_still_returns_a_read_when_every_variant_fails() -> None:
    recognizer = ScriptedRecognizer([])
    read = recognizer.recognize(make_plate_scene())
    assert isinstance(read, PlateRead)
    assert read.valid is False


def test_recognize_rejects_junk_without_touching_the_backend() -> None:
    recognizer = ScriptedRecognizer(["34ABC123"])
    assert recognizer.recognize(np.zeros((0, 0, 3), dtype=np.uint8)).valid is False
    assert recognizer.variants_seen == []


def _skew(scene: "np.ndarray", pinch: int = 10) -> "np.ndarray":
    import cv2

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


# ---------------------------------------------------------------------------
# build_frame_preprocessor
# ---------------------------------------------------------------------------


def test_frame_preprocessor_is_none_unless_enabled(tmp_settings: Any) -> None:
    """The default pipeline pays nothing, not even a call per frame."""
    tmp_settings.preprocess.frame_enhance = False
    assert build_frame_preprocessor(tmp_settings) is None


def test_frame_preprocessor_enhances_when_enabled(tmp_settings: Any) -> None:
    tmp_settings.preprocess.frame_enhance = True
    preprocess = build_frame_preprocessor(tmp_settings)
    assert preprocess is not None

    rng = np.random.default_rng(2)
    dark = rng.integers(40, 90, (120, 160, 3), dtype=np.uint8)
    assert float(preprocess(dark).std()) > float(dark.std())


# ---------------------------------------------------------------------------
# Orchestrator: the frame hook
# ---------------------------------------------------------------------------


def _pipeline(settings: Any, **kwargs: Any) -> PipelineOrchestrator:
    return PipelineOrchestrator(
        settings=settings,
        detector=kwargs.pop("detector", None) or FakeDetector(),
        recognizer=kwargs.pop("recognizer", None) or FakeRecognizer(),
        voter=kwargs.pop("voter", None) or FakeVoter(),
        relay=kwargs.pop("relay", None) or FakeRelay(),
        **kwargs,
    )


class RecordingDetector(FakeDetector):
    """Remembers the frame it was handed, so the test can identify it."""

    def __init__(self) -> None:
        super().__init__()
        self.frames: list[Any] = []

    def detect(self, frame: Any) -> list[PlateDetection]:
        self.frames.append(frame)
        return super().detect(frame)


def test_the_detector_sees_the_enhanced_frame(tmp_settings: Any) -> None:
    marker = np.full((80, 160, 3), 7, dtype=np.uint8)
    detector = RecordingDetector()
    pipeline = _pipeline(tmp_settings, detector=detector, frame_preprocessor=lambda _frame: marker)

    pipeline.process_frame("entry", np.zeros((80, 160, 3), dtype=np.uint8))
    assert detector.frames and detector.frames[0] is marker


def test_the_original_frame_is_what_gets_published_and_photographed(
    tmp_settings: Any,
) -> None:
    """Enhancement is an aid to recognition, not a rewrite of the evidence."""
    original = np.zeros((80, 160, 3), dtype=np.uint8)
    captured: list[Any] = []

    pipeline = _pipeline(
        tmp_settings,
        frame_preprocessor=lambda _frame: np.full((80, 160, 3), 7, dtype=np.uint8),
    )
    # Signature mirrors SnapshotWriter.submit, including the on_saved hook the
    # notifier uses, so this stub keeps failing loudly if that contract moves.
    def fake_submit(plate, frame, *, camera=None, when=None, on_saved=None):
        captured.append(frame)
        return True

    pipeline._snapshots.submit = fake_submit

    pipeline.process_frame("entry", original)
    assert captured, "the decision should have queued a snapshot"
    assert all(frame is original for frame in captured)


def test_a_failing_preprocessor_costs_the_enhancement_not_the_frame(
    tmp_settings: Any,
) -> None:
    def explode(_frame: Any) -> Any:
        raise RuntimeError("preprocessor blew up")

    original = np.zeros((80, 160, 3), dtype=np.uint8)
    detector = RecordingDetector()
    pipeline = _pipeline(tmp_settings, detector=detector, frame_preprocessor=explode)

    events = pipeline.process_frame("entry", original)
    assert detector.frames and detector.frames[0] is original
    assert events, "the frame should still have been recognised"


def test_no_preprocessor_leaves_the_frame_untouched(tmp_settings: Any) -> None:
    original = np.zeros((80, 160, 3), dtype=np.uint8)
    detector = RecordingDetector()
    pipeline = _pipeline(tmp_settings, detector=detector)

    pipeline.process_frame("entry", original)
    assert detector.frames and detector.frames[0] is original
