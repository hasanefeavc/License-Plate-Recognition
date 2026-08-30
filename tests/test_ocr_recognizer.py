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
        app=config.AppConfig(
            data_dir=str(tmp_path / "data"), models_dir=str(tmp_path / "models")
        ),
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


def test_a_complete_cache_disables_the_network_entirely(
    tmp_path: Path, fake_easyocr: Any
) -> None:
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


def test_a_failure_on_cpu_names_the_cache_and_the_fix(
    tmp_path: Path, fake_easyocr: Any
) -> None:
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
