"""Tests for YOLO dataset validation.

Pure python -- no cv2, no torch, no ultralytics -- because the whole point of
this layer is to run before any of those are needed. Every fixture builds a
dataset on tmp_path out of empty files: the validator reads names, structure
and label text, never pixels, so a zero-byte ``.jpg`` is a perfectly good
stand-in for a photograph.

The assertions that matter are the ones about datasets that *look* fine. An
empty val split, a train/val leak and a label file in pixel coordinates all
produce a training run that completes and reports a number; the number is just
meaningless. Those are the failures this catches, and they are the expensive
ones because they are only discovered after the GPU time is spent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lpr.dataset import (
    DEFAULT_CLASS_NAME,
    describe_layout,
    scaffold_dataset,
    validate_dataset,
)


def write_dataset(
    root: Path,
    *,
    train: int = 4,
    val: int = 2,
    test: int = 0,
    labels: bool = True,
    label_body: str = "0 0.5 0.5 0.2 0.1\n",
    names: str = f"  0: {DEFAULT_CLASS_NAME}\n",
    shared: int = 0,
) -> Path:
    """Build a YOLO tree and return its ``data.yaml``.

    ``shared`` reuses that many train basenames in val, which is how a leaked
    split is written by hand.
    """
    for split, count in (("train", train), ("val", val), ("test", test)):
        images_dir = root / "images" / split
        labels_dir = root / "labels" / split
        images_dir.mkdir(parents=True, exist_ok=True)
        labels_dir.mkdir(parents=True, exist_ok=True)
        for index in range(count):
            leaked = split == "val" and index < shared
            stem = f"train_{index}" if leaked else f"{split}_{index}"
            (images_dir / f"{stem}.jpg").write_bytes(b"")
            if labels:
                (labels_dir / f"{stem}.txt").write_text(label_body, encoding="utf-8")

    data_yaml = root / "data.yaml"
    body = "path: .\ntrain: images/train\nval: images/val\n"
    if test:
        body += "test: images/test\n"
    body += "\nnames:\n" + names
    data_yaml.write_text(body, encoding="utf-8")
    return data_yaml


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_well_formed_dataset_passes(tmp_path: Path) -> None:
    report = validate_dataset(write_dataset(tmp_path))
    assert report.ok, report.summary()
    assert report.class_names == [DEFAULT_CLASS_NAME]
    assert report.splits["train"].images == 4
    assert report.splits["val"].images == 2
    assert report.total_boxes == 6


def test_the_test_split_is_optional(tmp_path: Path) -> None:
    """A held-out split is good practice, not a precondition for training."""
    report = validate_dataset(write_dataset(tmp_path, test=0))
    assert report.ok
    assert not report.splits["test"].present


def test_names_may_be_a_list_or_a_mapping(tmp_path: Path) -> None:
    """Roboflow writes one spelling, hand-written configs the other."""
    as_list = validate_dataset(
        write_dataset(tmp_path / "a", names=f"  - {DEFAULT_CLASS_NAME}\n")
    )
    as_map = validate_dataset(write_dataset(tmp_path / "b"))
    assert as_list.class_names == as_map.class_names == [DEFAULT_CLASS_NAME]


def test_an_unlabelled_image_is_a_negative_not_an_error(tmp_path: Path) -> None:
    """An image with no plate in it is how a false-positive rate is measured."""
    data_yaml = write_dataset(tmp_path)
    (tmp_path / "images" / "train" / "empty_lot.jpg").write_bytes(b"")
    report = validate_dataset(data_yaml)
    assert report.ok
    assert report.splits["train"].unlabelled == 1
    assert report.splits["train"].labelled == 4


# ---------------------------------------------------------------------------
# Datasets that look fine and are not
# ---------------------------------------------------------------------------


def test_an_empty_val_split_is_rejected(tmp_path: Path) -> None:
    """Training against this completes and reports a meaningless mAP."""
    report = validate_dataset(write_dataset(tmp_path, val=0))
    assert not report.ok
    assert any("no images" in message for message in report.splits["val"].errors)


def test_a_split_with_no_labels_at_all_is_rejected(tmp_path: Path) -> None:
    report = validate_dataset(write_dataset(tmp_path, labels=False))
    assert not report.ok
    assert any("no label file" in message for message in report.splits["train"].errors)


def test_a_train_val_leak_is_rejected(tmp_path: Path) -> None:
    """The failure that makes every metric better and is invisible in them.

    A model validated against its own training images scores well and has
    learned nothing transferable. Nothing in the training output says so.
    """
    report = validate_dataset(write_dataset(tmp_path, shared=2))
    assert not report.ok
    assert any("both train and val" in message for message in report.errors)


def test_pixel_coordinates_are_rejected(tmp_path: Path) -> None:
    """The single most common conversion bug: a converter that forgot to divide.

    Ultralytics accepts the file and trains on boxes that are nonsense, which
    surfaces as a model that detects nothing rather than as an error.
    """
    report = validate_dataset(
        write_dataset(tmp_path, label_body="0 640 360 128 64\n")
    )
    assert not report.ok
    assert any("normalised" in message for message in report.splits["train"].errors)


def test_a_class_id_outside_the_declared_range_is_rejected(tmp_path: Path) -> None:
    report = validate_dataset(write_dataset(tmp_path, label_body="3 0.5 0.5 0.2 0.1\n"))
    assert not report.ok
    assert any("class id 3" in message for message in report.splits["train"].errors)


def test_a_zero_area_box_is_rejected(tmp_path: Path) -> None:
    report = validate_dataset(write_dataset(tmp_path, label_body="0 0.5 0.5 0.0 0.1\n"))
    assert not report.ok
    assert any("zero-area" in message for message in report.splits["train"].errors)


def test_a_malformed_row_is_rejected(tmp_path: Path) -> None:
    report = validate_dataset(write_dataset(tmp_path, label_body="0 0.5 0.5\n"))
    assert not report.ok
    assert any("expected 5 fields" in message for message in report.splits["train"].errors)


def test_a_missing_split_directory_is_rejected(tmp_path: Path) -> None:
    data_yaml = write_dataset(tmp_path)
    data_yaml.write_text(
        "path: .\ntrain: images/train\nval: images/nowhere\n\nnames:\n  0: plate\n",
        encoding="utf-8",
    )
    report = validate_dataset(data_yaml)
    assert not report.ok
    assert any("does not resolve" in message for message in report.errors)


def test_a_missing_data_yaml_is_reported_not_raised(tmp_path: Path) -> None:
    report = validate_dataset(tmp_path / "absent.yaml")
    assert not report.ok
    assert any("does not exist" in message for message in report.errors)


def test_unparseable_yaml_is_reported_not_raised(tmp_path: Path) -> None:
    path = tmp_path / "data.yaml"
    path.write_text("this: [is: not: valid", encoding="utf-8")
    report = validate_dataset(path)
    assert not report.ok


# ---------------------------------------------------------------------------
# Class naming
# ---------------------------------------------------------------------------


def test_a_multi_class_dataset_with_no_plate_class_is_rejected(tmp_path: Path) -> None:
    """The dataset equivalent of training on COCO and calling it a plate model.

    A detector built from this hands the recogniser a crop of every object it
    knows, which is both useless and the largest source of wasted OCR time.
    """
    report = validate_dataset(
        write_dataset(tmp_path, names="  0: car\n  1: person\n  2: truck\n")
    )
    assert not report.ok
    assert any("none is named like a plate" in message for message in report.errors)


def test_a_differently_named_single_class_only_warns(tmp_path: Path) -> None:
    """Plenty of good datasets call it `licence-plate`, `LP` or `0`.

    Training works either way; only the runtime's name-based auto-detection
    cares, so this is guidance rather than a refusal.
    """
    report = validate_dataset(write_dataset(tmp_path, names="  0: LP\n"))
    assert report.ok
    assert any("not 'plate'" in message for message in report.warnings)


def test_a_plate_like_class_name_is_accepted(tmp_path: Path) -> None:
    report = validate_dataset(write_dataset(tmp_path, names="  0: license_plate\n"))
    assert report.ok
    assert report.warnings == []


def test_a_dataset_with_no_names_is_rejected(tmp_path: Path) -> None:
    data_yaml = write_dataset(tmp_path)
    data_yaml.write_text("path: .\ntrain: images/train\nval: images/val\n", encoding="utf-8")
    report = validate_dataset(data_yaml)
    assert not report.ok
    assert any("no `names`" in message for message in report.errors)


# ---------------------------------------------------------------------------
# Layout resolution
# ---------------------------------------------------------------------------


def test_a_split_may_point_at_a_directory_holding_images(tmp_path: Path) -> None:
    """Both conventions in the wild: `images/train`, or `train/` with `images/` in it."""
    for split in ("train", "val"):
        (tmp_path / split / "images").mkdir(parents=True)
        (tmp_path / split / "labels").mkdir(parents=True)
        (tmp_path / split / "images" / f"{split}_0.jpg").write_bytes(b"")
        (tmp_path / split / "labels" / f"{split}_0.txt").write_text(
            "0 0.5 0.5 0.2 0.1\n", encoding="utf-8"
        )
    data_yaml = tmp_path / "data.yaml"
    data_yaml.write_text("path: .\ntrain: train\nval: val\n\nnames:\n  0: plate\n", "utf-8")

    report = validate_dataset(data_yaml)
    assert report.ok, report.summary()


def test_only_the_last_images_component_becomes_labels(tmp_path: Path) -> None:
    """A path containing the word higher up must survive intact.

    Replacing every occurrence would turn `/srv/images/plates/images/train`
    into `/srv/labels/plates/labels/train` and find nothing.
    """
    base = tmp_path / "images" / "plates"
    (base / "images" / "train").mkdir(parents=True)
    (base / "labels" / "train").mkdir(parents=True)
    (base / "images" / "val").mkdir(parents=True)
    (base / "labels" / "val").mkdir(parents=True)
    for split in ("train", "val"):
        (base / "images" / split / f"{split}_0.jpg").write_bytes(b"")
        (base / "labels" / split / f"{split}_0.txt").write_text(
            "0 0.5 0.5 0.2 0.1\n", encoding="utf-8"
        )
    data_yaml = base / "data.yaml"
    data_yaml.write_text(
        "path: .\ntrain: images/train\nval: images/val\n\nnames:\n  0: plate\n", "utf-8"
    )

    report = validate_dataset(data_yaml)
    assert report.ok, report.summary()


def test_an_absolute_path_in_data_yaml_is_honoured(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    write_dataset(elsewhere)
    data_yaml = tmp_path / "data.yaml"
    data_yaml.write_text(
        f"path: {elsewhere}\ntrain: images/train\nval: images/val\n\nnames:\n  0: plate\n",
        encoding="utf-8",
    )
    assert validate_dataset(data_yaml).ok


# ---------------------------------------------------------------------------
# Scaffolding
# ---------------------------------------------------------------------------


def test_scaffold_creates_the_expected_tree(tmp_path: Path) -> None:
    data_yaml = scaffold_dataset(tmp_path / "plates")
    assert data_yaml.is_file()
    for split in ("train", "val", "test"):
        assert (tmp_path / "plates" / "images" / split).is_dir()
        assert (tmp_path / "plates" / "labels" / split).is_dir()


def test_a_scaffolded_dataset_is_reported_as_empty_not_valid(tmp_path: Path) -> None:
    """Scaffolding creates a shape, not a dataset. Training on it must not start."""
    data_yaml = scaffold_dataset(tmp_path / "plates")
    report = validate_dataset(data_yaml)
    assert not report.ok
    assert report.class_names == [DEFAULT_CLASS_NAME]


def test_scaffold_is_idempotent_and_never_overwrites(tmp_path: Path) -> None:
    """Safe to re-run against a dataset somebody has started filling in."""
    root = tmp_path / "plates"
    data_yaml = scaffold_dataset(root)
    data_yaml.write_text("# edited by hand\npath: .\n", encoding="utf-8")
    (root / "images" / "train" / "keep.jpg").write_bytes(b"x")

    scaffold_dataset(root)
    assert data_yaml.read_text(encoding="utf-8").startswith("# edited by hand")
    assert (root / "images" / "train" / "keep.jpg").read_bytes() == b"x"


def test_scaffold_accepts_a_custom_class_name(tmp_path: Path) -> None:
    data_yaml = scaffold_dataset(tmp_path / "plates", class_name="plaka")
    assert "plaka" in data_yaml.read_text(encoding="utf-8")


@pytest.mark.parametrize("root", ["datasets/plates", "/srv/lpr/data"])
def test_describe_layout_names_the_actual_directory(root: str) -> None:
    text = describe_layout(root)
    assert root in text
    assert "images/train" in text and "labels/train" in text
