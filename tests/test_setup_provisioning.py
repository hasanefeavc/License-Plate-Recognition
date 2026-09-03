"""A fresh clone must not have to be told to fetch its own weights.

`models/` is gitignored wholesale, so every clone starts with none. The
pipeline copes -- it falls back to contour detection and says so -- but the
first anybody hears of it is a warning banner at the gate, on the first frame,
which is both the least useful moment and the one where a download is least
welcome. `scripts/setup_dev.py` now asks the question at setup time instead.

What it fetches is the *baseline* (stock COCO `yolov8n.pt`), which is
scaffolding rather than a plate detector: `lpr.model_assets` deliberately
refuses to install it as one, because a gate that passed every readiness check
while reading no plates is the failure that module exists to prevent. So these
tests assert the step is offered and can be refused, not that it makes
detection work.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on invocation
    sys.path.insert(0, str(SRC))


def _load_setup_dev() -> Any:
    """Import scripts/setup_dev.py, which is not on the package path."""
    path = ROOT / "scripts" / "setup_dev.py"
    spec = importlib.util.spec_from_file_location("_setup_dev_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def setup_dev() -> Any:
    return _load_setup_dev()


@pytest.fixture
def recorded_init(setup_dev: Any, monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Capture the argv handed to `lpr init` instead of provisioning anything."""
    seen: list[list[str]] = []

    def fake_cli(argv: list[str]) -> int:
        seen.append(list(argv))
        return 0

    monkeypatch.setattr(setup_dev, "cli_main", fake_cli)
    return seen


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------


def test_missing_weights_add_the_fetch_step(
    setup_dev: Any, monkeypatch: pytest.MonkeyPatch, recorded_init: list[list[str]]
) -> None:
    monkeypatch.setattr(setup_dev, "detection_weights_missing", lambda: True)

    assert setup_dev.main([]) == 0
    assert "--fetch-models" in recorded_init[0]


def test_weights_already_present_cost_no_download(
    setup_dev: Any, monkeypatch: pytest.MonkeyPatch, recorded_init: list[list[str]]
) -> None:
    """Idempotence is the contract this script advertises."""
    monkeypatch.setattr(setup_dev, "detection_weights_missing", lambda: False)

    assert setup_dev.main([]) == 0
    assert "--fetch-models" not in recorded_init[0]


def test_an_offline_site_can_refuse(
    setup_dev: Any, monkeypatch: pytest.MonkeyPatch, recorded_init: list[list[str]]
) -> None:
    """Offline is the normal state of a gate box, not an error.

    `--no-fetch-models` is consumed here rather than forwarded: `lpr init` has
    no such flag, and passing it on would fail argument parsing.
    """
    monkeypatch.setattr(setup_dev, "detection_weights_missing", lambda: True)

    assert setup_dev.main(["--no-fetch-models"]) == 0
    assert "--fetch-models" not in recorded_init[0]
    assert "--no-fetch-models" not in recorded_init[0]


def test_an_explicit_request_is_honoured_even_with_weights_present(
    setup_dev: Any, monkeypatch: pytest.MonkeyPatch, recorded_init: list[list[str]]
) -> None:
    """Asking for it twice must not produce `--fetch-models --fetch-models`."""
    monkeypatch.setattr(setup_dev, "detection_weights_missing", lambda: False)

    assert setup_dev.main(["--fetch-models"]) == 0
    assert recorded_init[0].count("--fetch-models") == 1


def test_the_root_is_still_pinned_to_the_checkout(
    setup_dev: Any, monkeypatch: pytest.MonkeyPatch, recorded_init: list[list[str]]
) -> None:
    """The pre-existing behaviour, guarded while the argv handling changed."""
    monkeypatch.setattr(setup_dev, "detection_weights_missing", lambda: True)

    setup_dev.main([])
    argv = recorded_init[0]
    assert argv[0] == "init"
    assert argv[argv.index("--root") + 1] == str(ROOT)


def test_a_caller_supplied_root_is_not_overridden(
    setup_dev: Any, monkeypatch: pytest.MonkeyPatch, recorded_init: list[list[str]], tmp_path: Path
) -> None:
    monkeypatch.setattr(setup_dev, "detection_weights_missing", lambda: True)

    setup_dev.main(["--root", str(tmp_path)])
    assert recorded_init[0].count("--root") == 1


# ---------------------------------------------------------------------------
# The probe
# ---------------------------------------------------------------------------


def test_the_probe_answers_about_the_configured_path(
    setup_dev: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A site that repointed detection.model_path must be asked about that file.

    Looking for `models/plate_yolov8n.pt` directly would report a missing model
    on every installation that keeps its weights somewhere else.
    """
    weights = tmp_path / "elsewhere" / "custom.pt"
    weights.parent.mkdir(parents=True)

    from lpr import model_assets

    monkeypatch.setattr(model_assets, "resolve_detection_weights", lambda _s: weights)

    assert setup_dev.detection_weights_missing() is True
    weights.write_bytes(b"not really a model, but present")
    assert setup_dev.detection_weights_missing() is False


def test_an_unreadable_configuration_skips_the_download_rather_than_failing(
    setup_dev: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This decides whether to add an optional step, so it must never raise.

    Provisioning directories, keys and a licence is the job that was asked for;
    a config this cannot parse is a reason to skip one optional extra, not to
    abandon the rest.
    """
    from lpr import config

    def explode() -> Any:
        raise RuntimeError("config.yaml is not valid YAML")

    monkeypatch.setattr(config, "get_settings", explode)

    assert setup_dev.detection_weights_missing() is False


# ---------------------------------------------------------------------------
# The launchers reach it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("launcher", ["run.sh", "run.bat"])
def test_both_launchers_run_the_provisioning_step(launcher: str) -> None:
    """The check lives in Python, in one place; the launchers just call it.

    Duplicating a models/ probe into batch *and* bash would be the same
    decision written three times in three languages, and the two shell copies
    are the ones no test can execute.
    """
    text = (ROOT / launcher).read_text(encoding="utf-8")
    assert "setup_dev.py" in text
