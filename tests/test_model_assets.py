"""Reporting on the model files, and provisioning them when they are absent.

A fresh clone has an empty ``models/`` -- every ``.pt`` is gitignored -- so the
first run of a new checkout is also the run most likely to be degraded. What
matters is that it *is* only degraded: the service starts, and it says which
file is missing rather than leaving that in a stack trace.
"""

from __future__ import annotations

import sys
import urllib.error
from pathlib import Path
from typing import Any

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on invocation
    sys.path.insert(0, str(SRC))

from lpr import model_assets  # noqa: E402
from lpr.model_assets import (  # noqa: E402
    BASELINE_NAME,
    describe_assets,
    ensure_detection_weights,
    ensure_runtime_dirs,
    is_stock_baseline,
    resolve_detection_weights,
)


def _write_weights(path: Path, content: bytes = b"not really a model") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def test_a_fresh_checkout_reports_the_missing_detection_model(tmp_settings: Any) -> None:
    assets = describe_assets(tmp_settings)
    assert not assets.ready
    assert not assets.detection_present
    assert str(assets.detection_weights) in assets.detail
    assert any("plate_yolov8n" in str(name) for name in assets.missing)


def test_an_installed_model_reports_ready(tmp_settings: Any) -> None:
    _write_weights(resolve_detection_weights(tmp_settings))
    tmp_settings.ocr.backend = "none"  # no EasyOCR cache to look for
    assets = describe_assets(tmp_settings)
    assert assets.ready
    assert assets.detection_present
    assert assets.missing == ()


def test_the_stock_baseline_wearing_the_plate_name_is_not_ready(
    tmp_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact state this repository once shipped in.

    ``yolov8n.pt`` renamed to ``plate_yolov8n.pt`` loads, detects people and
    chairs, and is rejected by ``build_detector`` in favour of contour
    detection. Reporting it as "model installed" is how that survived.
    """
    weights = _write_weights(resolve_detection_weights(tmp_settings), b"coco")
    monkeypatch.setattr(model_assets, "BASELINE_SHA256", model_assets.sha256_of(weights))
    tmp_settings.ocr.backend = "none"

    assets = describe_assets(tmp_settings)
    assert assets.detection_present
    assert assets.detection_is_stock_baseline
    assert not assets.ready
    assert any("COCO" in note for note in assets.notes)


def test_a_missing_easyocr_cache_is_reported_but_only_for_easyocr(
    tmp_settings: Any,
) -> None:
    _write_weights(resolve_detection_weights(tmp_settings))

    tmp_settings.ocr.backend = "easyocr"
    assert describe_assets(tmp_settings).ocr_missing

    tmp_settings.ocr.backend = "tesseract"
    assert describe_assets(tmp_settings).ocr_missing == ()


def test_the_reported_path_is_the_one_the_loader_opens(tmp_settings: Any) -> None:
    """A status endpoint naming a different file than the loader reads would
    be worse than no endpoint at all."""
    from lpr.detect.yolo import YoloPlateDetector

    for configured in ("models/plate_yolov8n.pt", "plate_yolov8n.pt", "custom/x.pt"):
        tmp_settings.detection.model_path = configured
        assert resolve_detection_weights(tmp_settings) == YoloPlateDetector._resolve_weights(
            configured, tmp_settings
        )


def test_the_status_is_json_safe(tmp_settings: Any) -> None:
    import json

    json.dumps(describe_assets(tmp_settings).to_dict())


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------


def test_runtime_directories_are_created(tmp_settings: Any) -> None:
    for path in ensure_runtime_dirs(tmp_settings):
        assert path.is_dir()


def test_being_offline_is_not_an_error(tmp_settings: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Offline is the normal state of a gate box.

    A download that cannot happen is recorded in the status and logged; it
    never raises, because the pipeline behind it is expected to start anyway
    and run on the contour detector.
    """

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(model_assets, "download", refuse)
    assets = ensure_detection_weights(tmp_settings, allow_download=True)
    assert not assets.detection_present
    assert not assets.baseline_present


def test_the_baseline_is_fetched_when_the_plate_model_is_missing(
    tmp_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fetched: list[tuple[str, Path]] = []

    def fake_download(url: str, dest: Path, **kwargs: Any) -> None:
        fetched.append((url, dest))
        _write_weights(dest, b"baseline")

    monkeypatch.setattr(model_assets, "download", fake_download)
    assets = ensure_detection_weights(tmp_settings, allow_download=True)

    assert len(fetched) == 1
    assert fetched[0][1].name == BASELINE_NAME
    assert assets.baseline_present


def test_the_baseline_is_never_installed_as_the_plate_model(
    tmp_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Copying it over ``plate_yolov8n.pt`` would make every check pass while
    the gate read no plates at all -- the failure this module exists to make
    visible."""
    monkeypatch.setattr(
        model_assets, "download", lambda url, dest, **kw: _write_weights(dest, b"baseline")
    )
    assets = ensure_detection_weights(tmp_settings, allow_download=True)

    assert not assets.detection_present, "the plate model must still be reported missing"
    assert not resolve_detection_weights(tmp_settings).exists()
    assert not assets.ready


def test_nothing_is_downloaded_when_the_plate_model_is_present(
    tmp_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_weights(resolve_detection_weights(tmp_settings))
    monkeypatch.setattr(
        model_assets,
        "download",
        lambda *a, **k: pytest.fail("downloaded with a model already installed"),
    )
    ensure_detection_weights(tmp_settings, allow_download=True)


def test_downloads_can_be_switched_off_entirely(
    tmp_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """For a site whose policy is that this box never reaches the network."""
    monkeypatch.setattr(
        model_assets, "download", lambda *a, **k: pytest.fail("reached the network")
    )
    ensure_detection_weights(tmp_settings, allow_download=False)


def test_a_checksum_mismatch_leaves_nothing_on_disk(tmp_path: Path) -> None:
    """A .pt is a pickle; torch.load executes it. A file that failed
    verification must not be left somewhere a loader would find it."""

    class FakeResponse:
        def read(self, size: int = -1) -> bytes:
            return b""

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *exc: Any) -> None:
            return None

    import urllib.request

    dest = tmp_path / "weights.pt"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(urllib.request, "urlopen", lambda *a, **k: FakeResponse())
        with pytest.raises(RuntimeError, match="checksum mismatch"):
            model_assets.download("https://example.invalid/w.pt", dest, expected_sha256="0" * 64)

    assert not dest.exists()
    assert not dest.with_suffix(".pt.part").exists()


def test_is_stock_baseline_answers_false_for_a_missing_file(tmp_path: Path) -> None:
    assert not is_stock_baseline(tmp_path / "nope.pt")
