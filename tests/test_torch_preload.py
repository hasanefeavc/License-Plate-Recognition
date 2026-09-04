"""Torch has to enter the process before paddle does, on Windows.

The bug this guards against only reproduces on Windows and only on a *fresh*
start-up, which makes it exactly the kind of regression a refactor reintroduces
silently. On a clean Windows 11 box, ``import torch`` succeeded on its own but
the pipeline died with::

    OSError: [WinError 127] The specified procedure could not be found.
    Error loading "...\\torch\\lib\\shm.dll" or one of its dependencies.

paddlepaddle claims the process's OpenMP/MKL runtime the moment ``paddleocr``
is imported; the torch that paddleocr then pulls in through
``albumentations.pytorch`` binds ``shm.dll`` against the wrong symbols and
fails to link. Whoever loads first wins, and torch is the one that cannot
survive losing -- so :func:`lpr.torch_preload.preload_torch` puts torch in
first.

Ordering is the whole fix, and a correct ordering leaves no trace behind, so
the tests here assert on the ordering itself: that torch is resident at the
instant ``from paddleocr import PaddleOCR`` resolves, and at the instant
``build_pipeline`` reaches the ML imports. The last two tests hold the other
half of the contract -- that buying this ordering did not cost the cheap,
torch-free module import that lets the rest of the suite run with no ML stack
installed.
"""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from lpr.torch_preload import preload_torch


@pytest.fixture
def torch_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``import torch`` fail, whatever is installed on this machine."""
    monkeypatch.delitem(sys.modules, "torch", raising=False)

    class Blocking:
        def find_spec(self, name: str, path: Any = None, target: Any = None) -> None:
            if name == "torch":
                raise ImportError("No module named 'torch'")
            return None

    monkeypatch.setattr(sys, "meta_path", [Blocking(), *sys.meta_path])


@pytest.fixture
def torch_broken(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``import torch`` raise the way a mislinked Windows wheel does."""
    monkeypatch.delitem(sys.modules, "torch", raising=False)

    class Mislinked:
        def find_spec(self, name: str, path: Any = None, target: Any = None) -> None:
            if name == "torch":
                raise OSError(
                    "[WinError 127] The specified procedure could not be found. "
                    'Error loading "torch\\lib\\shm.dll" or one of its dependencies.'
                )
            return None

    monkeypatch.setattr(sys, "meta_path", [Mislinked(), *sys.meta_path])


def _settings(tmp_path: Path) -> Any:
    config = pytest.importorskip("lpr.config")
    return config.Settings(
        app=config.AppConfig(data_dir=str(tmp_path / "data"), models_dir=str(tmp_path / "models")),
    )


# ---------------------------------------------------------------------------
# preload_torch itself
# ---------------------------------------------------------------------------


def test_preload_reports_torch_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "torch", types.ModuleType("torch"))

    assert preload_torch() is True


def test_an_already_imported_torch_is_not_imported_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The call sites are on hot-ish paths and may run more than once.

    Reaching the import statement again would be harmless but wasteful; the
    `sys.modules` check is what makes a second call free.
    """
    already = types.ModuleType("torch")
    monkeypatch.setitem(sys.modules, "torch", already)

    class Exploding:
        def find_spec(self, name: str, path: Any = None, target: Any = None) -> None:
            raise AssertionError(f"the import system was consulted for {name!r}")

    monkeypatch.setattr(sys, "meta_path", [Exploding()])

    assert preload_torch() is True
    assert sys.modules["torch"] is already


def test_a_missing_torch_is_reported_not_raised(torch_absent: None) -> None:
    """No torch is a supported configuration -- the caller degrades on it.

    `preload_torch` owns load order and nothing else, so a machine with no ML
    stack has to come out of it with a False, not an ImportError that would
    turn the composition root's careful degraded-mode handling into a crash.
    """
    assert preload_torch() is False
    assert "torch" not in sys.modules


def test_a_broken_torch_is_reported_not_raised(torch_broken: None) -> None:
    """WinError 127 is an OSError, not an ImportError.

    Catching only ImportError here would let the very error this module exists
    to prevent escape from the function meant to prevent it.
    """
    assert preload_torch() is False


# ---------------------------------------------------------------------------
# The ordering at the paddle import site
# ---------------------------------------------------------------------------


def test_torch_is_resident_before_paddleocr_is_imported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The assertion the Windows fix actually rests on.

    paddleocr imports torch itself, on its way to `albumentations.pytorch`, so
    the only ordering that helps is torch being in the process *before* the
    interpreter reaches `from paddleocr import PaddleOCR`. Moving the preload
    one line later reproduces WinError 127 on the machine this was written for
    and leaves every other test in this file passing.
    """
    from lpr.ocr import recognizer as recognizer_module

    # The preload is instrumented rather than left to put the real torch in
    # `sys.modules`, because torch is normally already resident by the time
    # this file runs -- an assertion on `"torch" in sys.modules` would pass
    # whether or not the preload happened at all.
    preloaded: list[str] = []
    monkeypatch.setattr(
        recognizer_module,
        "preload_torch",
        lambda: (preloaded.append("torch"), True)[1],
    )

    preloaded_at_import: list[bool] = []

    class Watching(types.ModuleType):
        def __getattr__(self, attribute: str) -> Any:
            # `from paddleocr import PaddleOCR` resolves through here, which is
            # where paddleocr's own module body -- and its torch import -- runs.
            if attribute != "PaddleOCR":
                raise AttributeError(attribute)
            preloaded_at_import.append(bool(preloaded))
            return lambda **_kwargs: None

    monkeypatch.setitem(sys.modules, "paddleocr", Watching("paddleocr"))

    recognizer_module.PaddleOcrRecognizer(_settings(tmp_path))

    assert preloaded_at_import == [True]


def test_the_recogniser_still_builds_with_no_torch_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, torch_absent: None
) -> None:
    """The preload must not become a torch dependency for the paddle backend.

    paddleocr on its own does not need torch to exist, and a site running the
    paddle backend on a CPU-only box without torch was working before this fix.
    """
    from lpr.ocr.recognizer import PaddleOcrRecognizer

    module = types.ModuleType("paddleocr")
    module.PaddleOCR = lambda **_kwargs: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "paddleocr", module)

    assert PaddleOcrRecognizer(_settings(tmp_path)) is not None


# ---------------------------------------------------------------------------
# The ordering in the composition root
# ---------------------------------------------------------------------------


def test_the_pipeline_factory_preloads_before_the_ml_imports(
    tmp_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`build_pipeline` is the other door into the ML stack.

    Detection is imported first and drags torch in by itself on most runs, but
    that is a property of ultralytics rather than a guarantee: a lazily
    importing detector, or an `ocr.ensemble_backends` build that reaches paddle
    first, puts paddle in front. The composition root preloads so the ordering
    does not depend on which component happens to import what.
    """
    from lpr.pipeline import factory

    monkeypatch.setattr(factory, "ensure_runtime_dirs", lambda _s: None)
    monkeypatch.setattr(
        factory,
        "ensure_detection_weights",
        lambda _s: types.SimpleNamespace(ready=True, detail="stubbed", notes=()),
    )
    monkeypatch.delitem(sys.modules, "torch", raising=False)

    preloaded: list[str] = []
    monkeypatch.setattr(
        factory,
        "preload_torch",
        lambda: (preloaded.append("torch"), True)[1],
    )

    resident_at_import: list[bool] = []

    class Watching(types.ModuleType):
        def __getattr__(self, attribute: str) -> Any:
            # `from lpr.detect import build_detector, ...` resolves through
            # here. Refusing the name turns into the ImportError the factory
            # already knows how to report, which is enough to run the ordering
            # check without standing a whole ML stack up.
            resident_at_import.append(bool(preloaded))
            raise AttributeError(attribute)

    monkeypatch.setitem(sys.modules, "lpr.detect", Watching("lpr.detect"))

    with pytest.raises(RuntimeError):
        factory.build_pipeline(settings=tmp_settings)

    assert resident_at_import, "the ML imports were never reached"
    assert all(resident_at_import), "torch was not preloaded before the ML imports"


# ---------------------------------------------------------------------------
# What the preload is not allowed to cost
# ---------------------------------------------------------------------------
#
# The obvious spelling of this fix is `import torch` at the top of each entry
# point. It is rejected on purpose: both modules promise an import that costs
# nothing and needs no ML stack, which is what lets the rest of this suite
# build a pipeline out of fakes and run on a machine with no torch at all.
# A subprocess is the only honest way to check it -- by the time this file runs,
# something else in the session has usually imported torch already.


@pytest.mark.parametrize("module", ["lpr.pipeline.factory", "lpr.ocr.recognizer", "lpr.api.main"])
def test_importing_an_entry_point_does_not_pull_in_torch(module: str) -> None:
    source_root = Path(__file__).resolve().parents[1] / "src"
    probe = f"import sys; import {module}; print('torch' in sys.modules)"

    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(source_root), "PATH": "", "SYSTEMROOT": ""},
        timeout=300,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False", (
        f"importing {module} pulled torch into the process; the preload belongs on the "
        "code paths that build the ML stack, not at module scope"
    )
