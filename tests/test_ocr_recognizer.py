"""Tests for how the EasyOCR backend is *constructed*.

Recognition quality is covered by test_ensemble.py and test_normalize.py. What
is tested here is the startup contract, which is where this backend has
historically hurt: which device it claims, where it keeps its ~100 MB of
weights, and whether a bad network can wedge the service before it ever serves
a request.

The real easyocr package is never imported. A fake module is injected instead,
so the whole file runs in a CI job with no ML wheels and no GPU -- and so the
"the download hangs forever" case can actually be provoked, which against the
real library would mean a genuinely hanging test.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("numpy", reason="numpy is required for the OCR backends")
pytest.importorskip("cv2", reason="opencv is required for the OCR backends")

from lpr import accel  # noqa: E402
from lpr.ocr.recognizer import EASYOCR_WEIGHTS, EasyOcrRecognizer  # noqa: E402


class FakeReader:
    """Records the kwargs it was built with; optionally fails on demand."""

    #: Every construction attempt across the process, newest last.
    calls: list[dict[str, Any]] = []

    def __init__(self, langs: list[str], **kwargs: Any) -> None:
        type(self).calls.append({"langs": langs, **kwargs})
        failure = kwargs.pop("_fail_with", None) or self._failure_for(kwargs)
        if failure is not None:
            raise failure

    #: Set by a test to make construction fail; consulted per attempt.
    failure_hook: Any = None

    @classmethod
    def _failure_for(cls, kwargs: dict[str, Any]) -> Exception | None:
        return cls.failure_hook(kwargs) if cls.failure_hook else None

    def readtext(self, image: Any, **kwargs: Any) -> list[Any]:
        return []


@pytest.fixture
def fake_easyocr(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Inject a stand-in ``easyocr`` module and reset its recorded state."""
    FakeReader.calls = []
    FakeReader.failure_hook = None
    module = type(sys)("easyocr")
    module.Reader = FakeReader  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "easyocr", module)
    return module


@pytest.fixture(autouse=True)
def _no_gpu_by_default(monkeypatch: pytest.MonkeyPatch) -> Any:
    """CI has no GPU; make that explicit rather than host-dependent."""
    accel.reset_probe()
    monkeypatch.setattr(accel, "cuda_available", lambda: False)
    yield
    accel.reset_probe()


def _settings(tmp_path: Path, **ocr_kwargs: Any) -> Any:
    config = pytest.importorskip("lpr.config")
    return config.Settings(
        app=config.AppConfig(data_dir=str(tmp_path / "data"), models_dir=str(tmp_path / "models")),
        ocr=config.OcrConfig(**ocr_kwargs),
    )


def _provision_cache(settings: Any) -> Path:
    """Write plausible weight files so the cache counts as complete."""
    target = settings.paths.ocr_models_dir
    for name in EASYOCR_WEIGHTS:
        (target / name).write_bytes(b"not really a checkpoint")
    return target


# ---------------------------------------------------------------------------
# Device selection
# ---------------------------------------------------------------------------


def test_gpu_auto_resolves_to_cpu_without_a_gpu(tmp_path: Path, fake_easyocr: Any) -> None:
    recognizer = EasyOcrRecognizer(_settings(tmp_path, gpu="auto"))
    assert recognizer.gpu is False
    assert FakeReader.calls[-1]["gpu"] is False


def test_gpu_auto_resolves_to_gpu_with_one(
    tmp_path: Path, fake_easyocr: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(accel, "cuda_available", lambda: True)
    recognizer = EasyOcrRecognizer(_settings(tmp_path, gpu="auto"))
    assert recognizer.gpu is True
    assert FakeReader.calls[-1]["gpu"] is True


def test_explicit_gpu_true_is_downgraded_rather_than_crashing(
    tmp_path: Path, fake_easyocr: Any
) -> None:
    """The mock-fixture / CI case: `gpu: true` committed, no GPU on the runner."""
    recognizer = EasyOcrRecognizer(_settings(tmp_path, gpu=True))
    assert recognizer.gpu is False


# ---------------------------------------------------------------------------
# Weight cache
# ---------------------------------------------------------------------------


def test_weights_are_stored_under_models_dir(tmp_path: Path, fake_easyocr: Any) -> None:
    """Not ~/.EasyOCR: that is a container layer `up --build` throws away."""
    settings = _settings(tmp_path)
    EasyOcrRecognizer(settings)

    expected = str(tmp_path / "models" / "easyocr")
    assert FakeReader.calls[-1]["model_storage_directory"] == expected
    assert FakeReader.calls[-1]["user_network_directory"] == expected


def test_a_complete_cache_disables_the_network_entirely(tmp_path: Path, fake_easyocr: Any) -> None:
    """A provisioned gate box must start with the uplink down."""
    settings = _settings(tmp_path)
    _provision_cache(settings)

    EasyOcrRecognizer(settings)
    assert FakeReader.calls[-1]["download_enabled"] is False


def test_an_empty_cache_allows_the_download(tmp_path: Path, fake_easyocr: Any) -> None:
    EasyOcrRecognizer(_settings(tmp_path))
    assert FakeReader.calls[-1]["download_enabled"] is True


def test_allow_download_false_refuses_even_with_an_empty_cache(
    tmp_path: Path, fake_easyocr: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """Air-gapped sites want a fast, explained failure, not a doomed retry loop."""
    with caplog.at_level("WARNING"):
        EasyOcrRecognizer(_settings(tmp_path, allow_download=False))

    assert FakeReader.calls[-1]["download_enabled"] is False
    assert "fetch_models.py --easyocr" in caplog.text


def test_a_custom_model_dir_is_honoured(tmp_path: Path, fake_easyocr: Any) -> None:
    shared = tmp_path / "shared"
    EasyOcrRecognizer(_settings(tmp_path, model_dir=str(shared)))
    assert FakeReader.calls[-1]["model_storage_directory"] == str(shared.resolve())


# ---------------------------------------------------------------------------
# Startup robustness
# ---------------------------------------------------------------------------


def test_the_download_runs_under_a_socket_deadline(tmp_path: Path, fake_easyocr: Any) -> None:
    """The fix for the hang: EasyOCR's urlretrieve has no timeout of its own."""
    seen: list[float | None] = []
    FakeReader.failure_hook = lambda kwargs: seen.append(socket.getdefaulttimeout()) and None

    before = socket.getdefaulttimeout()
    EasyOcrRecognizer(_settings(tmp_path, download_timeout_s=12.5))

    assert seen == [12.5]
    # ...and it must not leak: the API's own sockets share this global.
    assert socket.getdefaulttimeout() == before


def test_the_deadline_is_restored_even_when_construction_fails(
    tmp_path: Path, fake_easyocr: Any
) -> None:
    FakeReader.failure_hook = lambda kwargs: OSError("connection reset")

    before = socket.getdefaulttimeout()
    with pytest.raises(RuntimeError):
        EasyOcrRecognizer(_settings(tmp_path, download_timeout_s=5.0))
    assert socket.getdefaulttimeout() == before


def test_zero_timeout_leaves_the_global_untouched(tmp_path: Path, fake_easyocr: Any) -> None:
    seen: list[float | None] = []
    FakeReader.failure_hook = lambda kwargs: seen.append(socket.getdefaulttimeout()) and None

    EasyOcrRecognizer(_settings(tmp_path, download_timeout_s=0))
    assert seen == [None]


def test_a_failed_gpu_init_retries_on_cpu(
    tmp_path: Path, fake_easyocr: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 4 GB card can hold YOLO or both OCR networks and not always both."""
    monkeypatch.setattr(accel, "cuda_available", lambda: True)
    FakeReader.failure_hook = lambda kwargs: (
        RuntimeError("CUDA out of memory") if kwargs.get("gpu") else None
    )

    recognizer = EasyOcrRecognizer(_settings(tmp_path, gpu=True))

    assert recognizer.gpu is False
    assert [call["gpu"] for call in FakeReader.calls] == [True, False]


def test_a_failure_on_cpu_names_the_cache_and_the_fix(tmp_path: Path, fake_easyocr: Any) -> None:
    """There is nothing left to retry, so the message has to do the work."""
    FakeReader.failure_hook = lambda kwargs: OSError("timed out")

    with pytest.raises(RuntimeError) as excinfo:
        EasyOcrRecognizer(_settings(tmp_path))

    message = str(excinfo.value)
    assert "fetch_models.py --easyocr" in message
    assert str(tmp_path / "models" / "easyocr") in message
    assert "download_timeout_s" in message
    # The underlying error is chained, not swallowed.
    assert isinstance(excinfo.value.__cause__, OSError)


def test_unsupported_kwargs_are_dropped_for_older_easyocr() -> None:
    """requirements.txt pins >=1.7,<2, and the Reader signature moved inside it.

    ``user_network_directory`` and ``verbose`` arrived in different 1.x
    releases, so passing the full set unconditionally would raise TypeError on
    a legal, pinned version.
    """

    def narrow(langs: list[str], gpu: bool = True) -> None: ...

    assert EasyOcrRecognizer._supported_kwargs(
        narrow, {"gpu": True, "verbose": False, "user_network_directory": "/x"}
    ) == {"gpu": True}


def test_a_reader_taking_kwargs_gets_everything() -> None:
    def permissive(langs: list[str], gpu: bool = True, **rest: Any) -> None: ...

    sent = {"gpu": True, "verbose": False, "user_network_directory": "/x"}
    assert EasyOcrRecognizer._supported_kwargs(permissive, sent) == sent


def test_an_uninspectable_reader_gets_every_kwarg() -> None:
    """A C extension or a Mock has no signature; assume it takes what we send."""
    sentinel = {"gpu": False, "verbose": False}
    assert EasyOcrRecognizer._supported_kwargs(object(), sentinel) == sentinel


# ---------------------------------------------------------------------------
# Direct recognition (bypassing EasyOCR's own detector)
# ---------------------------------------------------------------------------


class RecordingReader(FakeReader):
    """A reader that answers both read paths and records which ran.

    ``recognize_result`` and ``readtext_result`` are set per test; ``seen``
    names the methods called, in order, which is what the tests below assert
    on -- the point of the change is *which* path runs, not only its output.
    """

    recognize_result: list[Any] = []
    readtext_result: list[Any] = []
    seen: list[str] = []
    recognize_raises: Exception | None = None
    recognize_kwargs: dict[str, Any] = {}
    recognize_image: Any = None

    def recognize(
        self,
        image: Any,
        horizontal_list: Any = None,
        free_list: Any = None,
        **kwargs: Any,
    ) -> list[Any]:
        type(self).seen.append("recognize")
        type(self).recognize_image = image
        type(self).recognize_kwargs = {
            "horizontal_list": horizontal_list,
            "free_list": free_list,
            **kwargs,
        }
        if type(self).recognize_raises is not None:
            raise type(self).recognize_raises
        return type(self).recognize_result

    def readtext(self, image: Any, **kwargs: Any) -> list[Any]:
        type(self).seen.append("readtext")
        return type(self).readtext_result


@pytest.fixture
def recording_easyocr(monkeypatch: pytest.MonkeyPatch) -> Any:
    RecordingReader.calls = []
    RecordingReader.failure_hook = None
    RecordingReader.seen = []
    RecordingReader.recognize_result = []
    RecordingReader.readtext_result = []
    RecordingReader.recognize_raises = None
    RecordingReader.recognize_kwargs = {}
    RecordingReader.recognize_image = None
    module = type(sys)("easyocr")
    module.Reader = RecordingReader  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "easyocr", module)
    return module


def _crop() -> Any:
    numpy = pytest.importorskip("numpy")
    return numpy.full((64, 200, 3), 255, dtype=numpy.uint8)


def test_the_crop_goes_straight_to_the_recognition_head(
    tmp_path: Path, recording_easyocr: Any
) -> None:
    """YOLO already localised the plate; CRAFT must not run over it again."""
    RecordingReader.recognize_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "34ABC123", 0.9)]
    recognizer = EasyOcrRecognizer(_settings(tmp_path, direct_recognize=True))

    assert recognizer._read_fragments(_crop()) == [("34ABC123", 0.9)]
    assert RecordingReader.seen == ["recognize"]


def test_an_empty_direct_read_falls_back_to_the_detector(
    tmp_path: Path, recording_easyocr: Any
) -> None:
    """The bypass must not be able to lose a read the old path would have had."""
    RecordingReader.recognize_result = []
    RecordingReader.readtext_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "06BZ1234", 0.8)]
    recognizer = EasyOcrRecognizer(_settings(tmp_path, direct_recognize=True))

    assert recognizer._read_fragments(_crop()) == [("06BZ1234", 0.8)]
    assert RecordingReader.seen == ["recognize", "readtext"]


def test_a_failing_direct_read_falls_back_rather_than_raising(
    tmp_path: Path, recording_easyocr: Any
) -> None:
    """One view the recognition head refuses is not a reason to fail a frame."""
    RecordingReader.recognize_raises = RuntimeError("no")
    RecordingReader.readtext_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "35TR8801", 0.7)]
    recognizer = EasyOcrRecognizer(_settings(tmp_path, direct_recognize=True))

    assert recognizer._read_fragments(_crop()) == [("35TR8801", 0.7)]
    assert RecordingReader.seen == ["recognize", "readtext"]


def test_the_bypass_can_be_switched_off(tmp_path: Path, recording_easyocr: Any) -> None:
    RecordingReader.readtext_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "34ABC12", 0.6)]
    recognizer = EasyOcrRecognizer(_settings(tmp_path, direct_recognize=False))

    assert recognizer._read_fragments(_crop()) == [("34ABC12", 0.6)]
    assert RecordingReader.seen == ["readtext"]


def test_no_box_list_is_offered_so_the_whole_crop_is_one_line(
    tmp_path: Path, recording_easyocr: Any
) -> None:
    """Both box lists must stay None.

    EasyOCR's guard is ``if (horizontal_list==None) and (free_list==None)``,
    and only that branch substitutes a single box covering the whole image.
    Passing empty lists instead makes it iterate over zero boxes and return
    nothing -- silently, on every crop, so the bypass looks like it works
    while every read quietly comes from the fallback.
    """
    RecordingReader.recognize_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "34ABC123", 0.9)]
    recognizer = EasyOcrRecognizer(_settings(tmp_path, direct_recognize=True))
    recognizer._read_fragments(_crop())

    assert RecordingReader.recognize_kwargs["horizontal_list"] is None
    assert RecordingReader.recognize_kwargs["free_list"] is None


def test_the_crop_is_magnified_before_direct_recognition(
    tmp_path: Path, recording_easyocr: Any
) -> None:
    """mag_ratio is a CRAFT parameter, so this path has to apply it itself."""
    RecordingReader.recognize_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "34ABC123", 0.9)]
    recognizer = EasyOcrRecognizer(_settings(tmp_path, direct_recognize=True, mag_ratio=2.0))
    recognizer._read_fragments(_crop())

    height, width = RecordingReader.recognize_image.shape[:2]
    assert (height, width) == (128, 400)


def test_a_magnification_of_one_leaves_the_crop_alone(
    tmp_path: Path, recording_easyocr: Any
) -> None:
    RecordingReader.recognize_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "34ABC123", 0.9)]
    recognizer = EasyOcrRecognizer(_settings(tmp_path, direct_recognize=True, mag_ratio=1.0))
    recognizer._read_fragments(_crop())

    assert RecordingReader.recognize_image.shape[:2] == (64, 200)


def test_the_tuning_parameters_reach_the_reader(tmp_path: Path, recording_easyocr: Any) -> None:
    RecordingReader.recognize_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "34ABC123", 0.9)]
    recognizer = EasyOcrRecognizer(
        _settings(
            tmp_path, direct_recognize=True, decoder="beamsearch", beam_width=7, contrast_ths=0.4
        )
    )
    recognizer._read_fragments(_crop())

    passed = RecordingReader.recognize_kwargs
    assert passed["decoder"] == "beamsearch"
    assert passed["beamWidth"] == 7
    assert passed["contrast_ths"] == pytest.approx(0.4)
    assert passed["allowlist"] == recognizer.allowlist


def test_greedy_decoding_does_not_send_a_beam_width(tmp_path: Path, recording_easyocr: Any) -> None:
    RecordingReader.recognize_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "34ABC123", 0.9)]
    recognizer = EasyOcrRecognizer(_settings(tmp_path, direct_recognize=True, decoder="greedy"))
    recognizer._read_fragments(_crop())

    assert "beamWidth" not in RecordingReader.recognize_kwargs


def test_keywords_a_reader_cannot_take_are_dropped(tmp_path: Path, recording_easyocr: Any) -> None:
    """easyocr>=1.7,<2 moved this surface; an unknown keyword must not raise."""

    class NarrowReader(RecordingReader):
        def recognize(self, image: Any, horizontal_list: Any = None, **kwargs: Any) -> list[Any]:
            # No free_list, and **kwargs still absorbs the rest -- the filter is
            # exercised by the narrower signature on the readtext side below.
            return super().recognize(image, horizontal_list, None, **kwargs)

        def readtext(self, image: Any, allowlist: Any = None) -> list[Any]:
            type(self).seen.append("readtext")
            return type(self).readtext_result

    recording_easyocr.Reader = NarrowReader
    NarrowReader.recognize_result = []
    NarrowReader.readtext_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "06AB123", 0.5)]
    recognizer = EasyOcrRecognizer(_settings(tmp_path, direct_recognize=True))

    # Would be a TypeError if decoder/mag_ratio/width_ths were passed blindly.
    assert recognizer._read_fragments(_crop()) == [("06AB123", 0.5)]


def test_the_bypass_ships_off(tmp_path: Path, recording_easyocr: Any) -> None:
    """The default must reproduce the previous behaviour exactly.

    The bypass measured 59% faster and materially less accurate on the only
    sample available, so it is a capability to evaluate per site, not a new
    default. See the note above OcrConfig.direct_recognize.
    """
    RecordingReader.readtext_result = [([[0, 0], [1, 0], [1, 1], [0, 1]], "34ABC123", 0.9)]
    recognizer = EasyOcrRecognizer(_settings(tmp_path))

    assert recognizer.direct_recognize is False
    recognizer._read_fragments(_crop())
    assert RecordingReader.seen == ["readtext"]


# ---------------------------------------------------------------------------
# PaddleOCR result shapes
# ---------------------------------------------------------------------------


class OCRResult(dict):
    """Mapping-like but not a dict, the way paddlex returns a page."""


def test_a_3x_result_page_is_read() -> None:
    """The shape that made this backend report every frame as empty.

    PaddleOCR 3.x returns parallel `rec_texts` / `rec_scores` lists on a
    mapping. The legacy walk indexed `line[1]` on that mapping, raised
    TypeError, swallowed it per line, and produced nothing at all -- a 100%
    miss rate that looks like an OCR failure and is a parsing one.
    """
    from lpr.ocr.recognizer import _parse_paddle_result

    page = [{"rec_texts": ["34ABC123", "TR"], "rec_scores": [0.97, 0.4], "dt_polys": [[], []]}]
    assert _parse_paddle_result(page) == [("34ABC123", 0.97), ("TR", 0.4)]


def test_a_mapping_subclass_page_is_read() -> None:
    from lpr.ocr.recognizer import _parse_paddle_result

    page = [OCRResult(rec_texts=["06BZ1234"], rec_scores=[0.91])]
    assert _parse_paddle_result(page) == [("06BZ1234", 0.91)]


def test_a_payload_nested_under_res_is_read() -> None:
    from lpr.ocr.recognizer import _parse_paddle_result

    page = [{"res": {"rec_texts": ["35TR8801"], "rec_scores": [0.88]}}]
    assert _parse_paddle_result(page) == [("35TR8801", 0.88)]


def test_a_page_object_exposing_json_is_read() -> None:
    from lpr.ocr.recognizer import _parse_paddle_result

    class Page:
        json = {"res": {"rec_texts": ["09RS2264"], "rec_scores": [0.66]}}

    assert _parse_paddle_result([Page()]) == [("09RS2264", 0.66)]


def test_a_missing_score_does_not_discard_the_text() -> None:
    """Zero confidence still votes; a dropped read cannot."""
    from lpr.ocr.recognizer import _parse_paddle_result

    assert _parse_paddle_result([{"rec_texts": ["34XY99"]}]) == [("34XY99", 0.0)]
    assert _parse_paddle_result([{"rec_texts": ["A", "B"], "rec_scores": [0.5]}]) == [
        ("A", 0.5),
        ("B", 0.0),
    ]


def test_the_legacy_2x_tuple_shape_still_reads() -> None:
    """The 3.x support is an addition; a 2.x install must keep working."""
    from lpr.ocr.recognizer import _parse_paddle_result

    legacy = [[[[[0, 0], [1, 0], [1, 1], [0, 1]], ("34ABC123", 0.93)]]]
    assert _parse_paddle_result(legacy) == [("34ABC123", 0.93)]


@pytest.mark.parametrize("payload", [None, [], [None], [{}], ["nonsense"]])
def test_an_empty_or_odd_result_yields_nothing_rather_than_raising(payload: Any) -> None:
    from lpr.ocr.recognizer import _parse_paddle_result

    assert _parse_paddle_result(payload) == []


def test_blank_text_is_dropped() -> None:
    from lpr.ocr.recognizer import _parse_paddle_result

    page = [{"rec_texts": ["   ", "34AB12"], "rec_scores": [0.9, 0.8]}]
    assert _parse_paddle_result(page) == [("34AB12", 0.8)]


def test_the_constructor_cascades_past_rejected_keyword_sets() -> None:
    """A signature filter cannot do this job.

    ``PaddleOCR.__init__`` takes ``**kwargs``, so every keyword survives an
    inspection-based filter, and 3.7 then refuses the *combination*:
    "`use_angle_cls` and `use_textline_orientation` are mutually exclusive".
    """
    from lpr.ocr.recognizer import PaddleOcrRecognizer

    seen: list[list[str]] = []

    class Fussy:
        def __init__(self, **kwargs: Any) -> None:
            seen.append(sorted(kwargs))
            if "use_textline_orientation" in kwargs:
                raise ValueError("mutually exclusive")
            self.kwargs = kwargs

    built = PaddleOcrRecognizer._build_reader(Fussy)
    assert "use_angle_cls" in built.kwargs
    assert len(seen) == 2  # modern set refused, legacy set accepted


def test_a_reader_that_refuses_everything_is_reported_clearly() -> None:
    from lpr.ocr.recognizer import PaddleOcrRecognizer

    class Hopeless:
        def __init__(self, **kwargs: Any) -> None:
            raise ValueError("nope")

    with pytest.raises(RuntimeError, match="could not be constructed"):
        PaddleOcrRecognizer._build_reader(Hopeless)


def test_an_engine_that_always_raises_is_reported_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Silence is what makes a broken install look like a bad model.

    An engine raising on every call reports a 100% miss rate, which reads as
    "PaddleOCR cannot see these plates" rather than "PaddleOCR never ran".
    """
    import logging

    from lpr.ocr.recognizer import PaddleOcrRecognizer

    class Exploding:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def predict(self, _image: Any) -> list[Any]:
            raise NotImplementedError("ConvertPirAttribute2RuntimeAttribute not support")

    module = type(sys)("paddleocr")
    module.PaddleOCR = Exploding  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "paddleocr", module)

    recognizer = PaddleOcrRecognizer(_settings(tmp_path))
    with caplog.at_level(logging.DEBUG, logger="lpr.ocr.recognizer"):
        for _ in range(3):
            assert recognizer._read_fragments(_crop()) == []

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1, "the diagnosis must be logged once, not per frame"
    assert "matched pair" in errors[0].getMessage()


# ---------------------------------------------------------------------------
# The imports paddleocr makes that this project cannot use
# ---------------------------------------------------------------------------
#
# `paddleocr/paddleocr.py` does, at module scope,
# `from ppstructure.recovery.recovery_to_doc import sorted_layout_boxes,
# convert_info_docx`, which pulls in python-docx and then lxml.etree. On
# Windows 11 with Smart App Control on, that DLL load is blocked and the
# ImportError comes back out of `from paddleocr import PaddleOCR` -- naming
# lxml, a package that is in no requirements file here and has nothing to do
# with plates. Seeding sys.modules short-circuits the import before any finder
# is consulted. See `_stub_unused_paddle_imports`.


@pytest.fixture
def unstubbed_paddle_modules() -> Any:
    """Run with the stubs absent, and put sys.modules back afterwards.

    The stubs are permanent by design -- once installed they stay for the life
    of the process, because paddleocr re-imports lazily and a second recogniser
    must not fall through to the blocked DLL. That is right in production and
    unusable in a test file, where an earlier test would decide what a later
    one observes.
    """
    from lpr.ocr.recognizer import _UNUSED_PADDLE_MODULES

    saved = {name: sys.modules.pop(name, None) for name, _ in _UNUSED_PADDLE_MODULES}
    try:
        yield
    finally:
        for name, module in saved.items():
            sys.modules.pop(name, None)
            if module is not None:
                sys.modules[name] = module


def test_the_blocked_import_paddleocr_makes_now_succeeds(unstubbed_paddle_modules: Any) -> None:
    """The statement under test is the one paddleocr executes, verbatim."""
    from lpr.ocr.recognizer import _stub_unused_paddle_imports

    _stub_unused_paddle_imports()

    from ppstructure.recovery.recovery_to_doc import (  # type: ignore[import-not-found]
        convert_info_docx,
        sorted_layout_boxes,
    )

    # Bound to None deliberately: paddleocr only calls these from PPStructure's
    # recovery path, which this project never reaches. If that ever changed, a
    # TypeError naming the function is the right way to find out.
    assert sorted_layout_boxes is None
    assert convert_info_docx is None


def test_the_stub_keeps_docx_and_lxml_out_of_the_process(unstubbed_paddle_modules: Any) -> None:
    """Short-circuiting the import is the point; importing it quietly is not.

    A stub that still let the real chain load would pass the test above on
    Linux, where lxml imports fine, and fail on exactly the machine it was
    written for.
    """
    from lpr.ocr.recognizer import _stub_unused_paddle_imports

    for name in ("docx", "lxml.etree", "ppstructure", "ppstructure.recovery"):
        sys.modules.pop(name, None)

    _stub_unused_paddle_imports()
    # What `from ppstructure.recovery.recovery_to_doc import ...` compiles to.
    # The form matters: a bare `import a.b.c` binds the top-level name and so
    # still needs the parent, while this one is answered from sys.modules
    # outright. All three of paddleocr's call sites use the `from` form.
    __import__("ppstructure.recovery.recovery_to_doc", fromlist=("sorted_layout_boxes",))

    assert "docx" not in sys.modules
    assert "lxml.etree" not in sys.modules
    # The parents are never walked either -- sys.modules is consulted before
    # any finder, so the import stops at the entry that was seeded.
    assert "ppstructure" not in sys.modules


def test_the_stub_is_a_module_not_a_namespace(unstubbed_paddle_modules: Any) -> None:
    """Anything that walks sys.modules expects modules to be in it.

    A `types.SimpleNamespace` satisfies `from ... import name` and nothing
    else: it carries no `__name__` and no `__spec__`, so importlib's reload
    path, `inspect.getmodule`, pkgutil and pytest's own assertion rewriter all
    have to be defensive about it. `types.ModuleType` costs the same and is
    what the rest of the interpreter is written against.
    """
    import types

    from lpr.ocr.recognizer import _UNUSED_PADDLE_MODULES, _stub_unused_paddle_imports

    _stub_unused_paddle_imports()

    for name, attributes in _UNUSED_PADDLE_MODULES:
        stub = sys.modules[name]
        assert isinstance(stub, types.ModuleType)
        assert stub.__name__ == name
        assert stub.__spec__ is None
        for attribute in attributes:
            assert hasattr(stub, attribute)


def test_a_real_module_already_imported_is_never_replaced(
    unstubbed_paddle_modules: Any,
) -> None:
    """Somebody genuinely using PP-Structure in this process must keep working.

    The stub is a workaround for an import this project does not want, not a
    claim that the real module is unwelcome.
    """
    from lpr.ocr.recognizer import _UNUSED_PADDLE_MODULES, _stub_unused_paddle_imports

    name, _ = _UNUSED_PADDLE_MODULES[0]
    real = type(sys)(name)
    real.sorted_layout_boxes = "the real thing"  # type: ignore[attr-defined]
    sys.modules[name] = real

    _stub_unused_paddle_imports()

    assert sys.modules[name] is real


def test_stubbing_twice_changes_nothing(unstubbed_paddle_modules: Any) -> None:
    """Called once per recogniser, so a second one must not swap the entry out.

    Rebinding it would hand a module object to code that had already imported
    names out of the first -- harmless with these two, and the kind of thing
    that stops being harmless the moment a stub carries state.
    """
    from lpr.ocr.recognizer import _UNUSED_PADDLE_MODULES, _stub_unused_paddle_imports

    name, _ = _UNUSED_PADDLE_MODULES[0]

    _stub_unused_paddle_imports()
    first = sys.modules[name]
    _stub_unused_paddle_imports()

    assert sys.modules[name] is first


def test_the_stubs_are_in_place_before_paddleocr_is_imported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unstubbed_paddle_modules: Any
) -> None:
    """Ordering is the entire fix and it leaves no trace when it is right.

    paddleocr does the offending import at module scope, so the stubs have to
    exist before the interpreter reaches `from paddleocr import PaddleOCR`.
    Installed one line later, the recogniser still fails on the machine this
    was written for, and every other test in this section still passes.
    """
    from lpr.ocr.recognizer import _UNUSED_PADDLE_MODULES, PaddleOcrRecognizer

    stubbed_at_import: list[bool] = []

    class Watching(type(sys)):  # type: ignore[misc]
        def __getattr__(self, attribute: str) -> Any:
            # `from paddleocr import PaddleOCR` resolves the name through here,
            # which is the moment paddleocr's own module body would have run.
            if attribute != "PaddleOCR":
                raise AttributeError(attribute)
            stubbed_at_import.append(
                all(name in sys.modules for name, _ in _UNUSED_PADDLE_MODULES)
            )
            return lambda **_kwargs: None

    monkeypatch.setitem(sys.modules, "paddleocr", Watching("paddleocr"))

    PaddleOcrRecognizer(_settings(tmp_path))

    assert stubbed_at_import == [True]


# ---------------------------------------------------------------------------
# PaddleOCR's own logging
# ---------------------------------------------------------------------------
#
# paddleocr logs two DEBUG lines per inference plus a WARNING about the angle
# classifier. At 30 FPS that is 50+ lines a second onto stdout, and a Windows
# console repaints per line -- the pipeline looks like it is freezing when what
# is slow is the terminal. See `_quieten_paddle_logging`.


@pytest.fixture
def restore_paddle_logger_levels() -> Any:
    """Put the ppocr logger's level back; it is process-wide state."""
    import logging

    from lpr.ocr.recognizer import _PADDLE_LOGGERS

    saved = {name: logging.getLogger(name).level for name in _PADDLE_LOGGERS}
    try:
        yield
    finally:
        for name, level in saved.items():
            logging.getLogger(name).setLevel(level)


def test_the_paddle_loggers_are_silenced_to_error(restore_paddle_logger_levels: Any) -> None:
    import logging

    from lpr.ocr.recognizer import _PADDLE_LOGGERS, _quieten_paddle_logging

    for name in _PADDLE_LOGGERS:
        logging.getLogger(name).setLevel(logging.DEBUG)

    _quieten_paddle_logging()

    for name in _PADDLE_LOGGERS:
        assert logging.getLogger(name).level == logging.ERROR


def test_the_flooding_records_are_dropped_and_a_real_failure_is_not(
    restore_paddle_logger_levels: Any,
) -> None:
    """The three lines from the report, plus the one that must still get out.

    `show_log=False` would only lower the logger to INFO, which silences the
    two DEBUG lines and leaves the angle-classifier WARNING repeating at frame
    rate. ERROR is what covers all three.
    """
    import logging

    from lpr.ocr.recognizer import _quieten_paddle_logging

    _quieten_paddle_logging()
    ppocr = logging.getLogger("ppocr")

    assert not ppocr.isEnabledFor(logging.DEBUG)  # dt_boxes num : 1, elapsed
    assert not ppocr.isEnabledFor(logging.INFO)  # rec_res num : 1, elapsed
    assert not ppocr.isEnabledFor(logging.WARNING)  # angle classifier not initialized
    assert ppocr.isEnabledFor(logging.ERROR)  # an engine that actually broke


def test_our_own_loggers_are_untouched(restore_paddle_logger_levels: Any) -> None:
    """Suppression has to be surgical: the structured log is the product.

    A blunter fix -- raising the root level, or attaching a filter to the root
    handler -- would take `lpr.ocr.voting` and `lpr.pipeline.snapshots` with
    it, which is the log somebody reads after an unexplained restart.
    """
    import logging

    from lpr.ocr.recognizer import _quieten_paddle_logging

    ours = [
        logging.getLogger(name)
        for name in ("lpr", "lpr.ocr.voting", "lpr.pipeline.snapshots", "lpr.ocr.recognizer")
    ]
    # Effective levels, not the levels set on each logger: ours are normally
    # NOTSET and inherit from the root, so a fix that raised the *root* would
    # silence all of them while leaving every `logger.level` at 0 -- the
    # failure this test is here to catch would pass a check on `.level` alone.
    before = [logger.getEffectiveLevel() for logger in ours]
    root_before = logging.getLogger().level

    _quieten_paddle_logging()

    assert [logger.getEffectiveLevel() for logger in ours] == before
    assert logging.getLogger().level == root_before


def test_the_two_x_keyword_set_still_carries_show_log() -> None:
    """Belt and braces: on a release where it arrives, it should still be sent.

    It is not sufficient on its own -- see `_quieten_paddle_logging` -- but a
    2.x install that is handed it prints less during construction too.
    """
    from lpr.ocr.recognizer import PaddleOcrRecognizer

    legacy = [kw for kw in PaddleOcrRecognizer._CONSTRUCTOR_KWARGS if "use_angle_cls" in kw]
    assert any(kw.get("show_log") is False for kw in legacy)


def test_show_log_is_never_offered_to_a_three_x_release() -> None:
    """`ValueError: Unknown argument: show_log` is a hard error on 3.x.

    Putting it in the modern set to "make sure it arrives" would push every 3.x
    install down the cascade onto the legacy keywords.
    """
    from lpr.ocr.recognizer import PaddleOcrRecognizer

    modern = [
        kw for kw in PaddleOcrRecognizer._CONSTRUCTOR_KWARGS if "use_textline_orientation" in kw
    ]
    assert modern, "the 3.x keyword set has gone"
    for kwargs in modern:
        assert "show_log" not in kwargs


def test_the_logger_is_quietened_after_the_reader_is_built(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_paddle_logger_levels: Any
) -> None:
    """Ordering, and it is the opposite of the stub's.

    `PaddleOCR.__init__` runs `logger.setLevel(INFO)` itself when it is handed
    `show_log=False`, so quietening before construction is undone by the
    construction. This has to happen after.
    """
    import logging

    from lpr.ocr.recognizer import PaddleOcrRecognizer

    class Noisy:
        def __init__(self, **_kwargs: Any) -> None:
            # What paddleocr 2.x does to this logger while it is being built.
            logging.getLogger("ppocr").setLevel(logging.INFO)

    module = type(sys)("paddleocr")
    module.PaddleOCR = Noisy  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "paddleocr", module)

    PaddleOcrRecognizer(_settings(tmp_path))

    assert logging.getLogger("ppocr").level == logging.ERROR
