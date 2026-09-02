"""Tests for the OCR ground-truth labelling tool.

Two properties carry the weight here, and neither is about the prompt.

The first is that a human's answer is stored as a human gave it. The tool sits
next to :mod:`lpr.ocr.normalize`, whose whole job is bending a string into the
Turkish plate grammar -- exactly the wrong thing to do to a typed label, since
it silently converts a foreign plate into a Turkish one that does not exist and
then every later measurement is scored against that invention.

The second is that work is never lost. A label costs a human a few seconds and
there is no other copy of it, so the file is rewritten after every decision and
the write is atomic: a process killed mid-save must leave the previous complete
file, never a truncated one.
"""

from __future__ import annotations

import builtins
import importlib.util
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
LABELLER = ROOT / "scripts" / "label_ocr_dataset.py"


def load_labeller() -> Any:
    """Import ``scripts/label_ocr_dataset.py`` by path -- scripts/ is not a package.

    Registered in ``sys.modules`` *before* it is executed. ``@dataclass``
    resolves its annotations through ``sys.modules[cls.__module__]``, and under
    ``from __future__ import annotations`` that lookup returns ``None`` for a
    module loaded by path alone -- which fails the decorator, not the import,
    so the traceback points at dataclasses.py and says nothing about why.
    """
    spec = importlib.util.spec_from_file_location("label_ocr_dataset", LABELLER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def labeller() -> Any:
    return load_labeller()


@pytest.fixture()
def snapshots(tmp_path: Path) -> Path:
    """A directory of plausibly-named snapshot files."""
    directory = tmp_path / "snaps"
    directory.mkdir()
    for name in (
        "20260827_141837_31PN7152",
        "20260831_094656_34GN9709",
        "20260902_141812_06CAL39",
    ):
        (directory / f"{name}.jpg").write_bytes(b"\xff\xd8\xff\xe0")
    return directory


def answers(monkeypatch: pytest.MonkeyPatch, replies: list[str]) -> None:
    """Feed ``replies`` to the prompt, then behave like a closed stdin.

    Running out of replies raises ``EOFError``, which is what a real closed
    stdin does -- so a test that under-supplies answers exercises the clean-exit
    path instead of hanging.
    """
    supply: Iterator[str] = iter(replies)

    def fake_input(_prompt: str = "") -> str:
        try:
            return next(supply)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr(builtins, "input", fake_input)


# ---------------------------------------------------------------------------
# The suggestion
# ---------------------------------------------------------------------------


def test_the_plate_is_read_from_the_snapshot_filename(labeller: Any) -> None:
    assert labeller.predicted_plate(Path("20260827_141837_31PN7152.jpg")) == "31PN7152"


def test_a_bare_plate_filename_is_also_understood(labeller: Any) -> None:
    assert labeller.predicted_plate(Path("34ABC123.png")) == "34ABC123"


def test_an_ordinary_filename_offers_no_suggestion(labeller: Any) -> None:
    """Without the province digits, "plain_image.jpg" would suggest "IMAGE".

    One careless Enter would then put it in the truth file, where it is
    indistinguishable from a real label.
    """
    assert labeller.predicted_plate(Path("plain_image.jpg")) == ""
    assert labeller.predicted_plate(Path("photo.jpg")) == ""


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------


def test_a_typed_plate_keeps_only_its_characters(labeller: Any) -> None:
    assert labeller.clean("34 abc 123") == "34ABC123"
    assert labeller.clean(" 06-BZ-1234 ") == "06BZ1234"


def test_a_foreign_plate_is_not_bent_into_the_turkish_grammar(labeller: Any) -> None:
    """The regression this tool must never have.

    ``normalize_plate`` repairs OCR glyph confusions, and applied to a typed
    label it turns the German ``D-AB 1234`` into ``04B1234`` -- a plate that
    does not exist, recorded as ground truth, scored against forever after.
    """
    assert labeller.clean("D-AB 1234") == "DAB1234"


# ---------------------------------------------------------------------------
# The file
# ---------------------------------------------------------------------------


def test_labels_survive_a_reload(labeller: Any, tmp_path: Path) -> None:
    path = tmp_path / "gt.json"
    truth = labeller.TruthFile.load(path)
    truth.record(tmp_path / "a.jpg", "34ABC123", root=tmp_path)
    truth.record(tmp_path / "b.jpg", "", root=tmp_path)

    reloaded = labeller.TruthFile.load(path)
    assert reloaded.labels == {"a.jpg": "34ABC123", "b.jpg": ""}
    assert reloaded.positives == 1
    assert reloaded.negatives == 1


def test_the_file_is_written_after_every_single_decision(labeller: Any, tmp_path: Path) -> None:
    """Not on exit. There is no other copy of a human's twenty minutes."""
    path = tmp_path / "gt.json"
    truth = labeller.TruthFile.load(path)

    truth.record(tmp_path / "a.jpg", "34ABC123", root=tmp_path)
    assert json.loads(path.read_text()) == [{"image_path": "a.jpg", "plate": "34ABC123"}]

    truth.record(tmp_path / "b.jpg", "06BZ1234", root=tmp_path)
    assert len(json.loads(path.read_text())) == 2


def test_a_failed_write_leaves_the_previous_file_intact(
    labeller: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reason the write goes via a temp file and os.replace.

    ``open(path, "w")`` truncates before it writes, so a crash mid-save would
    destroy every label collected so far.
    """
    import os as os_module

    path = tmp_path / "gt.json"
    truth = labeller.TruthFile.load(path)
    truth.record(tmp_path / "a.jpg", "34ABC123", root=tmp_path)
    before = path.read_text()

    monkeypatch.setattr(os_module, "replace", _boom)
    truth.labels["b.jpg"] = "06BZ1234"
    with pytest.raises(RuntimeError):
        truth.save()

    assert path.read_text() == before
    leftovers = [child for child in tmp_path.iterdir() if child.name.endswith(".tmp")]
    assert leftovers == []


def _boom(*_args: Any, **_kwargs: Any) -> None:
    raise RuntimeError("disk went away")


def test_an_unreadable_file_is_refused_rather_than_overwritten(
    labeller: Any, tmp_path: Path
) -> None:
    path = tmp_path / "gt.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(SystemExit):
        labeller.TruthFile.load(path)


# ---------------------------------------------------------------------------
# The prompt loop
# ---------------------------------------------------------------------------


def _run(labeller: Any, snapshots: Path, out: Path) -> Any:
    truth = labeller.TruthFile.load(out)
    images = labeller.find_images(snapshots)
    labeller.run(images, truth, root=snapshots, show=False, assume_yes=True)
    return labeller.TruthFile.load(out)


def test_enter_accepts_the_suggestion(
    labeller: Any, snapshots: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers(monkeypatch, ["", "q"])
    truth = _run(labeller, snapshots, tmp_path / "gt.json")
    assert truth.labels == {"20260827_141837_31PN7152.jpg": "31PN7152"}


def test_typing_a_plate_overrides_the_suggestion(
    labeller: Any, snapshots: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers(monkeypatch, ["34XYZ99", "q"])
    truth = _run(labeller, snapshots, tmp_path / "gt.json")
    assert truth.labels == {"20260827_141837_31PN7152.jpg": "34XYZ99"}


def test_n_records_a_negative_sample(
    labeller: Any, snapshots: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An image with no legible plate is what makes false positives measurable."""
    answers(monkeypatch, ["n", "q"])
    truth = _run(labeller, snapshots, tmp_path / "gt.json")
    assert truth.labels == {"20260827_141837_31PN7152.jpg": ""}


def test_s_skips_without_recording_anything(
    labeller: Any, snapshots: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers(monkeypatch, ["s", "q"])
    truth = _run(labeller, snapshots, tmp_path / "gt.json")
    assert truth.labels == {}


def test_b_goes_back_and_replaces_the_previous_answer(
    labeller: Any, snapshots: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers(monkeypatch, ["34AAA11", "b", "34BBB22", "q"])
    truth = _run(labeller, snapshots, tmp_path / "gt.json")
    assert truth.labels == {"20260827_141837_31PN7152.jpg": "34BBB22"}


def test_a_closed_stdin_stops_cleanly_with_the_work_saved(
    labeller: Any, snapshots: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-D, a closed terminal, a killed pipe: all arrive as EOFError."""
    answers(monkeypatch, [""])
    truth = _run(labeller, snapshots, tmp_path / "gt.json")
    assert truth.labels == {"20260827_141837_31PN7152.jpg": "31PN7152"}


def test_ctrl_c_at_the_prompt_stops_cleanly_with_the_work_saved(
    labeller: Any, snapshots: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supply = iter(["", KeyboardInterrupt()])

    def fake_input(_prompt: str = "") -> str:
        value = next(supply)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(builtins, "input", fake_input)
    truth = _run(labeller, snapshots, tmp_path / "gt.json")
    assert truth.labels == {"20260827_141837_31PN7152.jpg": "31PN7152"}


def test_an_empty_answer_with_no_suggestion_asks_again(
    labeller: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Enter must not be able to store a blank as if it were a negative."""
    directory = tmp_path / "snaps"
    directory.mkdir()
    (directory / "photo.jpg").write_bytes(b"\xff\xd8")
    answers(monkeypatch, ["", "34ABC12", "q"])
    truth = _run(labeller, directory, tmp_path / "gt.json")
    assert truth.labels == {"photo.jpg": "34ABC12"}


def test_an_implausible_label_is_refused_unless_confirmed(
    labeller: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A typo becomes a permanent wrong answer, so it costs one keypress."""
    monkeypatch.setattr(builtins, "input", lambda _prompt="": "n")
    assert labeller.confirm_odd("NOTAPLATE", assume_yes=False) is False

    monkeypatch.setattr(builtins, "input", lambda _prompt="": "y")
    assert labeller.confirm_odd("NOTAPLATE", assume_yes=False) is True


def test_a_valid_plate_is_never_queried(labeller: Any) -> None:
    assert labeller.confirm_odd("34ABC123", assume_yes=False) is True


# ---------------------------------------------------------------------------
# What evaluate.py does with the result
# ---------------------------------------------------------------------------


def test_the_written_file_is_what_the_evaluator_reads(
    labeller: Any, snapshots: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The two halves have to agree, or the labels are collected for nothing."""
    from lpr.evaluation import load_ground_truth

    answers(monkeypatch, ["", "34GN9709", "n", "q"])
    out = tmp_path / "gt.json"
    _run(labeller, snapshots, out)

    assert load_ground_truth(out) == {
        "20260827_141837_31PN7152.jpg": "31PN7152",
        "20260831_094656_34GN9709.jpg": "34GN9709",
        "20260902_141812_06CAL39.jpg": "",
    }
