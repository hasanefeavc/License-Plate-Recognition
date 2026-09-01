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


def make_plate_scene(height: int = 60, width: int = 240) -> np.ndarray:
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

    def _read_fragments(self, image: np.ndarray) -> list[tuple[str, float]]:
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
    """With both escalation stages off, only the standard views are built."""
    recognizer = ScriptedRecognizer([])
    recognizer._rectify_enabled = False
    recognizer._hard_cases_enabled = False
    before = len(recognizer.variants_seen)
    recognizer.recognize(_skew(make_plate_scene()))
    # Only the standard views: grayscale, binarised, and possibly a deskew.
    assert before < len(recognizer.variants_seen) <= 3


def test_the_two_escalation_stages_are_independent() -> None:
    """Switching rectification off must not also switch the Otsu stage off."""
    crop = _skew(make_plate_scene())

    neither = ScriptedRecognizer([])
    neither._rectify_enabled = False
    neither._hard_cases_enabled = False
    neither.recognize(crop)

    hard_only = ScriptedRecognizer([])
    hard_only._rectify_enabled = False
    hard_only._hard_cases_enabled = True
    hard_only.recognize(crop)

    assert len(hard_only.variants_seen) > len(neither.variants_seen)


# ---------------------------------------------------------------------------
# Recogniser: the hard-case (Otsu / inverted) stage
# ---------------------------------------------------------------------------


class ConstantRecognizer(_BaseRecognizer):
    """Reads the same text at the same confidence from every view.

    ``ScriptedRecognizer`` consumes one canned read per view, which is what
    makes it useful for counting passes but useless for asking "what happens
    when every view agrees at confidence X" -- the question the escalation
    floor turns on.
    """

    def __init__(self, text: str, confidence: float) -> None:
        self._text = text
        self._confidence = confidence
        self.variants_seen: list[tuple[int, ...]] = []

    def _read_fragments(self, image: np.ndarray) -> list[tuple[str, float]]:
        self.variants_seen.append(tuple(image.shape))
        return [(self._text, self._confidence)]


def test_an_unreadable_crop_reaches_the_otsu_and_inverted_views() -> None:
    """The night-crop stage: last in line, and it must actually be reached."""
    crop = make_plate_scene()

    without = ScriptedRecognizer([])
    without._hard_cases_enabled = False
    without.recognize(crop)

    with_hard = ScriptedRecognizer([])
    with_hard._hard_cases_enabled = True
    with_hard.recognize(crop)

    assert len(with_hard.variants_seen) > len(without.variants_seen)


def test_a_confident_read_never_reaches_the_hard_case_views() -> None:
    """The whole cost argument: an ordinary car at the gate pays stage one only."""
    crop = _skew(make_plate_scene())

    confident = ConstantRecognizer("34ABC123", 0.95)
    read = confident.recognize(crop)
    assert read.valid is True

    floor = ConstantRecognizer("34ABC123", 0.95)
    floor._rectify_enabled = False
    floor._hard_cases_enabled = False
    floor.recognize(crop)

    assert len(confident.variants_seen) == len(floor.variants_seen)


def test_a_grammatical_but_unconvincing_read_keeps_escalating() -> None:
    """The gap this closes.

    A read that parses but scores below the floor used to end the search, and
    the pipeline would then reject it for being under ``ocr.min_confidence``.
    The crop was discarded without ever being shown the views most likely to
    rescue it -- exactly the low-light and angled crops this stage exists for.
    """
    crop = _skew(make_plate_scene())

    confident = ConstantRecognizer("34ABC123", 0.95)
    confident.recognize(crop)

    unsure = ConstantRecognizer("34ABC123", 0.20)
    unsure.recognize(crop)

    assert len(unsure.variants_seen) > len(confident.variants_seen)


def test_the_escalation_floor_still_reports_the_read_it_escalated_on() -> None:
    """Escalating must add evidence, never discard what was already found."""
    unsure = ConstantRecognizer("34ABC123", 0.20)
    read = unsure.recognize(_skew(make_plate_scene()))
    assert read.valid is True
    assert read.text == "34ABC123"


def test_the_escalation_floor_can_be_switched_off() -> None:
    """`escalate_below_confidence: 0` restores stopping at the first valid read."""
    crop = _skew(make_plate_scene())

    floored = ConstantRecognizer("34ABC123", 0.20)
    floored.recognize(crop)

    unfloored = ConstantRecognizer("34ABC123", 0.20)
    unfloored._escalate_below = 0.0
    unfloored.recognize(crop)

    assert len(unfloored.variants_seen) < len(floored.variants_seen)


def test_an_invalid_read_escalates_however_confident_it_is() -> None:
    """Confidence cannot substitute for grammar: junk is junk at 0.99."""
    crop = _skew(make_plate_scene())

    junk = ConstantRecognizer("XX", 0.99)
    junk.recognize(crop)

    valid = ConstantRecognizer("34ABC123", 0.99)
    valid.recognize(crop)

    assert len(junk.variants_seen) > len(valid.variants_seen)


def test_recognize_still_returns_a_read_when_every_variant_fails() -> None:
    recognizer = ScriptedRecognizer([])
    read = recognizer.recognize(make_plate_scene())
    assert isinstance(read, PlateRead)
    assert read.valid is False


def test_recognize_rejects_junk_without_touching_the_backend() -> None:
    recognizer = ScriptedRecognizer(["34ABC123"])
    assert recognizer.recognize(np.zeros((0, 0, 3), dtype=np.uint8)).valid is False
    assert recognizer.variants_seen == []


def _skew(scene: np.ndarray, pinch: int = 10) -> np.ndarray:
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


# ---------------------------------------------------------------------------
# Tight-font ("APP"-style) character separation
# ---------------------------------------------------------------------------


def bold_plate(bridge_rows: int, glyphs: int = 6) -> np.ndarray:
    """A binarised plate whose heavy glyphs are joined by ``bridge_rows`` of ink.

    Stands in for the APP failure: thick strokes set so close that the gap
    between two of them thresholds as ink over the few rows where the strokes
    come nearest, welding the pair into one blob. ``bridge_rows=0`` is the same
    plate with the gaps intact, i.e. nothing to repair.
    """
    import cv2

    image = np.full((64, 26 * glyphs + 12), 255, np.uint8)
    x = 12
    for _ in range(glyphs):
        cv2.rectangle(image, (x, 16), (x + 22, 48), 0, -1)
        x += 26
    x = 12 + 22
    for _ in range(glyphs - 1):
        if bridge_rows:
            image[30 : 30 + bridge_rows, x : x + 4] = 0
        x += 26
    return image


def ink_blobs(image: np.ndarray) -> int:
    """Connected dark regions -- what the recogniser is asked to read as glyphs."""
    import cv2

    count, _ = cv2.connectedComponents((image < 128).astype(np.uint8))
    return count - 1  # discount the background


def test_bridged_characters_are_pulled_back_apart() -> None:
    """The whole point: one welded blob becomes six readable glyphs again."""
    from lpr.detect.preprocess import separate_characters

    merged = bold_plate(bridge_rows=2)
    assert ink_blobs(merged) == 1, "the fixture must actually be merged"

    repaired = separate_characters(merged)
    assert repaired is not None
    assert ink_blobs(repaired) == 6


def test_the_repair_keeps_the_strokes_it_is_not_aimed_at() -> None:
    """Opening, not eroding: thinned strokes are how B becomes 8 and 0 becomes O.

    The erosion half of the opening breaks the bridge; the dilation half puts
    the stroke weight back, and cannot rebuild the bridge because there is no
    ink left in the gap column to grow from. A bare erosion would leave every
    glyph permanently thinner, trading one misread for another.
    """
    from lpr.detect.preprocess import separate_characters

    merged = bold_plate(bridge_rows=2)
    before = int(np.count_nonzero(merged < 128))
    repaired = separate_characters(merged)
    assert repaired is not None

    kept = int(np.count_nonzero(repaired < 128)) / before
    assert kept > 0.97, f"opening should preserve stroke weight, kept {kept:.1%}"


def test_a_crop_with_nothing_to_repair_costs_no_ocr_pass() -> None:
    """``None`` means "no new view", which is what keeps this cheap.

    Returning the input unchanged would hand the recogniser a byte-identical
    image and buy a duplicate ballot at the price of a full OCR pass on every
    ordinary plate at the gate.
    """
    from lpr.detect.preprocess import separate_characters

    assert separate_characters(bold_plate(bridge_rows=0)) is None
    assert separate_characters(np.full((64, 200), 255, np.uint8)) is None
    assert separate_characters(np.zeros((64, 200), np.uint8)) is None
    assert separate_characters(None) is None  # type: ignore[arg-type]
    assert separate_characters(np.zeros((0, 0), np.uint8)) is None


def test_the_repair_survives_reversed_polarity() -> None:
    """The IR-lit views are inverted, and hard_case_variants feeds them in too."""
    import cv2

    from lpr.detect.preprocess import separate_characters

    inverted = cv2.bitwise_not(bold_plate(bridge_rows=2))
    repaired = separate_characters(inverted)

    assert repaired is not None
    assert ink_blobs(cv2.bitwise_not(repaired)) == 6


def test_a_bridge_thicker_than_the_kernel_is_declined_not_mangled() -> None:
    """Better to offer no view than a view that is still merged *and* thinner."""
    from lpr.detect.preprocess import separate_characters

    assert separate_characters(bold_plate(bridge_rows=4)) is None


def test_a_taller_kernel_clears_a_thicker_bridge() -> None:
    """``preprocess.tight_font_kernel`` is the knob for a site that needs more."""
    from lpr.detect.preprocess import separate_characters

    merged = bold_plate(bridge_rows=4)
    repaired = separate_characters(merged, kernel_size=(1, 7))

    assert repaired is not None
    assert ink_blobs(repaired) == 6


def test_the_separated_view_reaches_the_recogniser() -> None:
    """enhance_plate must publish it, or none of the above matters in the app."""
    from lpr.detect.preprocess import enhance_plate

    scene = np.dstack([bold_plate(bridge_rows=2)] * 3)

    with_repair = enhance_plate(scene, tight_font=True)
    without = enhance_plate(scene, tight_font=False)

    assert without.separated is None
    assert with_repair.separated is not None
    # Exactly one extra view, appended rather than replacing the binarisation:
    # the repair rescues a bold font and would thin a delicate one, so both
    # have to reach the ensemble for agreement between them to decide.
    assert len(with_repair.variants) == len(without.variants) + 1
    assert with_repair.variants[-1] is with_repair.separated


def test_the_tight_font_view_can_be_switched_off_from_config() -> None:
    """A site whose plates are thin-set should not pay for a view it cannot use."""
    config = pytest.importorskip("lpr.config")

    class Probe(_BaseRecognizer):
        def _read_fragments(self, image: Any) -> list[tuple[str, float]]:
            return []

    probe = Probe()
    probe._configure_preprocessing(
        config.Settings(preprocess=config.PreprocessConfig(tight_font_variant=False))
    )
    assert probe._tight_font is False

    probe._configure_preprocessing(
        config.Settings(preprocess=config.PreprocessConfig(tight_font_kernel=(1, 5)))
    )
    assert probe._tight_font is True
    assert probe._tight_font_kernel == (1, 5)


def test_the_accept_predicate_stops_the_ladder_mid_stage() -> None:
    """The fast path's other half, at the level that actually pays for it.

    Without a predicate this crop costs every view the first stage produces.
    With one that is satisfied by the first read, it costs exactly one -- and
    the check has to happen per *view*, not per stage, because stage one is
    itself several OCR passes.
    """
    scene = make_plate_scene()

    baseline = ScriptedRecognizer(["34ABC123"] * 12)
    baseline.recognize(scene)
    assert len(baseline.variants_seen) > 1, "the first stage is more than one view"

    quick = ScriptedRecognizer(["34ABC123"] * 12)
    verdict = quick.recognize(scene, accept=lambda read: read.valid)

    assert len(quick.variants_seen) == 1
    assert verdict.text == "34ABC123"


def test_a_predicate_that_never_agrees_changes_nothing() -> None:
    """The early exit is an addition, not a new policy: refuse it and the
    existing escalation rules decide exactly as they did before."""
    scene = make_plate_scene()

    plain = ScriptedRecognizer(["", "", "34ABC123"] + ["34ABC123"] * 9)
    plain.recognize(scene)

    with_predicate = ScriptedRecognizer(["", "", "34ABC123"] + ["34ABC123"] * 9)
    with_predicate.recognize(scene, accept=lambda _read: False)

    assert len(with_predicate.variants_seen) == len(plain.variants_seen)
