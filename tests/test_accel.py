"""Tests for GPU probing and the GPU/model-cache wiring it feeds.

Everything here runs on a CPU-only machine. The probe itself is the one thing
that cannot be asserted about directly -- the answer depends on the host -- so
it is exercised through injected fake torch modules, and the *consumers*
(``detection.device``, ``ocr.gpu``, the EasyOCR reader kwargs) are tested
against a stubbed probe. The point of the suite is that a CI runner with no
GPU, and a gate box with one, both end up correctly configured rather than
merely not crashing.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from lpr import accel


@pytest.fixture(autouse=True)
def _clear_probe_cache() -> Any:
    """The probe is memoised for the process; no test may inherit another's."""
    accel.reset_probe()
    yield
    accel.reset_probe()


class _FakeTorch:
    """Minimal stand-in for the parts of torch that :mod:`lpr.accel` touches."""

    __version__ = "2.5.0"

    def __init__(
        self,
        *,
        is_available: bool = True,
        device_count: int = 1,
        cuda_build: str | None = "12.4",
        alloc_error: Exception | None = None,
    ) -> None:
        self.version = type("version", (), {"cuda": cuda_build})()
        self._alloc_error = alloc_error
        outer = self

        class _Cuda:
            @staticmethod
            def is_available() -> bool:
                return is_available

            @staticmethod
            def device_count() -> int:
                return device_count

            @staticmethod
            def get_device_name(index: int) -> str:
                return "Fake GPU"

            @staticmethod
            def get_device_properties(index: int) -> Any:
                return type("props", (), {"total_memory": 4 * 1024**3})()

        self.cuda = _Cuda()
        self._outer = outer

    def zeros(self, *args: Any, **kwargs: Any) -> Any:
        if self._alloc_error is not None:
            raise self._alloc_error
        return object()


def _install_torch(monkeypatch: pytest.MonkeyPatch, fake: Any | None) -> None:
    """Make ``import torch`` inside :mod:`lpr.accel` resolve to ``fake``."""
    if fake is None:
        monkeypatch.setitem(sys.modules, "torch", None)  # import raises
    else:
        monkeypatch.setitem(sys.modules, "torch", fake)


# ---------------------------------------------------------------------------
# cuda_available
# ---------------------------------------------------------------------------


def test_missing_torch_is_cpu_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """No torch is a supported configuration: the GUI client ships without it."""
    _install_torch(monkeypatch, None)
    assert accel.cuda_available() is False


def test_no_visible_device_is_cpu(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_torch(monkeypatch, _FakeTorch(is_available=False, cuda_build=None))
    assert accel.cuda_available() is False


def test_device_visible_but_zero_count_is_cpu(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_torch(monkeypatch, _FakeTorch(is_available=True, device_count=0))
    assert accel.cuda_available() is False


def test_a_device_that_cannot_launch_a_kernel_is_cpu(monkeypatch: pytest.MonkeyPatch) -> None:
    """The case ``torch.cuda.is_available()`` alone gets wrong.

    A driver older than the wheel's CUDA runtime reports a device and then
    fails on the first kernel launch. Catching that here means the service
    starts on CPU; missing it means the barrier stops mid-shift.
    """
    _install_torch(
        monkeypatch,
        _FakeTorch(alloc_error=RuntimeError("no kernel image is available")),
    )
    assert accel.cuda_available() is False


def test_a_working_device_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_torch(monkeypatch, _FakeTorch())
    assert accel.cuda_available() is True


def test_the_probe_runs_once_per_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """Building a CUDA context is expensive; every component must share one."""
    calls = 0

    class _Counting(_FakeTorch):
        def zeros(self, *args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            return object()

    _install_torch(monkeypatch, _Counting())
    assert accel.cuda_available() is True
    assert accel.cuda_available() is True
    assert calls == 1


# ---------------------------------------------------------------------------
# resolve_torch_device
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", ["auto", "", "  AUTO  ", None, "default"])
def test_auto_follows_the_probe(monkeypatch: pytest.MonkeyPatch, spec: Any) -> None:
    monkeypatch.setattr(accel, "cuda_available", lambda: True)
    assert accel.resolve_torch_device(spec) == "cuda"
    monkeypatch.setattr(accel, "cuda_available", lambda: False)
    assert accel.resolve_torch_device(spec) == "cpu"


def test_explicit_cpu_never_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    """`device: cpu` must not pay for a CUDA context just to be told to ignore it."""

    def _boom() -> bool:
        raise AssertionError("cuda_available() must not be called for device: cpu")

    monkeypatch.setattr(accel, "cuda_available", _boom)
    assert accel.resolve_torch_device("cpu") == "cpu"


def test_ordinals_get_the_cuda_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """ultralytics accepts "0"; torch's own .to() does not."""
    monkeypatch.setattr(accel, "cuda_available", lambda: True)
    assert accel.resolve_torch_device("0") == "cuda:0"
    assert accel.resolve_torch_device("0,1") == "cuda:0,1"
    assert accel.resolve_torch_device("cuda:1") == "cuda:1"


def test_a_gpu_request_without_a_gpu_degrades_to_cpu(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(accel, "cuda_available", lambda: False)
    assert accel.resolve_torch_device("cuda:0") == "cpu"
    assert accel.resolve_torch_device("0") == "cpu"


# ---------------------------------------------------------------------------
# resolve_gpu_flag
# ---------------------------------------------------------------------------


def test_gpu_flag_auto_follows_the_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(accel, "cuda_available", lambda: True)
    assert accel.resolve_gpu_flag("auto") is True
    monkeypatch.setattr(accel, "cuda_available", lambda: False)
    assert accel.resolve_gpu_flag("auto") is False


def test_gpu_flag_false_never_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom() -> bool:
        raise AssertionError("cuda_available() must not be called for gpu: false")

    monkeypatch.setattr(accel, "cuda_available", _boom)
    assert accel.resolve_gpu_flag(False) is False
    assert accel.resolve_gpu_flag("false") is False
    assert accel.resolve_gpu_flag("off") is False


def test_blank_gpu_flag_means_auto_not_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unset value expresses no preference, which is what auto-detect is for.

    Keeps ``ocr.gpu: ""`` and ``detection.device: ""`` meaning the same thing;
    reading blank as "false" would silently pin a GPU box to CPU.
    """
    monkeypatch.setattr(accel, "cuda_available", lambda: True)
    assert accel.resolve_gpu_flag("") is True
    assert accel.resolve_gpu_flag(None) is True


def test_gpu_flag_true_is_downgraded_without_a_gpu(monkeypatch: pytest.MonkeyPatch) -> None:
    """`gpu: true` on a CPU box must not abort the pipeline build.

    ``easyocr.Reader(gpu=True)`` raises when it cannot allocate, and that
    exception propagates out of ``build_pipeline`` -- so honouring the config
    literally would take the whole service down rather than slow it down.
    """
    monkeypatch.setattr(accel, "cuda_available", lambda: False)
    assert accel.resolve_gpu_flag(True) is False
    assert accel.resolve_gpu_flag("true") is False

    monkeypatch.setattr(accel, "cuda_available", lambda: True)
    assert accel.resolve_gpu_flag(True) is True


# ---------------------------------------------------------------------------
# Settings wiring
# ---------------------------------------------------------------------------


def test_ocr_gpu_accepts_bools_and_auto() -> None:
    """One config file has to serve the GPU gate box, a CPU spare, and CI."""
    config = pytest.importorskip("lpr.config")

    assert config.OcrConfig().gpu == "auto"
    assert config.OcrConfig(gpu=True).gpu is True
    assert config.OcrConfig(gpu=False).gpu is False
    # Environment variables and YAML both arrive as strings.
    assert config.OcrConfig(gpu="true").gpu is True
    assert config.OcrConfig(gpu="auto").gpu == "auto"


def test_shipped_config_leaves_both_devices_on_auto() -> None:
    """The committed config.yaml must stay deployable to a CPU-only host."""
    import yaml

    root = Path(__file__).resolve().parents[1]
    data = yaml.safe_load((root / "config.yaml").read_text())
    assert data["ocr"]["gpu"] == "auto"
    assert data["detection"]["device"] == "auto"


def test_ocr_model_dir_defaults_under_models_dir(tmp_path: Path) -> None:
    """EasyOCR's weights belong on the bind-mounted volume, not in $HOME."""
    config = pytest.importorskip("lpr.config")

    settings = config.Settings(app=config.AppConfig(models_dir=str(tmp_path / "models")))
    assert settings.paths.ocr_models_dir == (tmp_path / "models" / "easyocr").resolve()
    assert settings.paths.ocr_models_dir.is_dir()


def test_ocr_model_dir_is_overridable(tmp_path: Path) -> None:
    config = pytest.importorskip("lpr.config")

    shared = tmp_path / "shared-models"
    settings = config.Settings(
        app=config.AppConfig(models_dir=str(tmp_path / "models")),
        ocr=config.OcrConfig(model_dir=str(shared)),
    )
    assert settings.paths.ocr_models_dir == shared.resolve()
