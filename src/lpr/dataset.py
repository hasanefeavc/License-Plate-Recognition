"""YOLO-format dataset layout, validation and scaffolding.

The detector is only ever as good as what it was trained on, and the failure
mode that costs the most is the quiet one: a training run that completes, emits
a ``best.pt`` and reports a respectable mAP against a validation split that was
empty, mislabelled or a copy of the training split. The model installs, the
gate opens for nothing, and the first evidence is a customer phoning about a
barrier that will not lift.

This module is the check that runs *before* the GPU is booked. It is pure
python -- pathlib, and PyYAML only when a ``data.yaml`` is actually read -- so
it imports in CI with no ML wheels installed and is driven directly by
``tests/test_dataset.py``.

What it refuses to let through
------------------------------
* a ``data.yaml`` naming a split that does not exist on disk;
* a split directory with no images, or with images no label file matches;
* a label file whose rows are not ``<class> <cx> <cy> <w> <h>`` with all four
  geometry values normalised into ``[0, 1]`` -- the single most common symptom
  of a converter that emitted pixels instead of fractions;
* a class id outside the range ``names`` declares;
* a train/val split sharing image basenames, which inflates every metric the
  run reports and is invisible in the numbers themselves.

None of these raise. :func:`validate_dataset` returns a report and the caller
decides, because "no labels in val/" is fatal to a training run but merely
interesting to somebody inspecting a dataset they just downloaded.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_CLASS_NAME",
    "IMAGE_SUFFIXES",
    "DatasetReport",
    "SplitReport",
    "describe_layout",
    "scaffold_dataset",
    "validate_dataset",
]

#: Image extensions ultralytics reads. Kept lowercase; comparison folds case.
IMAGE_SUFFIXES: frozenset[str] = frozenset(
    {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff"}
)

#: The single class a plate detector needs. Named rather than left as ``0`` so
#: :func:`lpr.detect.yolo.YoloPlateDetector._resolve_plate_classes` can tell a
#: plate fine-tune from a one-class model of something else entirely.
DEFAULT_CLASS_NAME = "plate"

#: Splits a training run needs, and the one it merely likes to have.
REQUIRED_SPLITS = ("train", "val")
OPTIONAL_SPLITS = ("test",)

#: A geometry value this far outside [0, 1] is a converter bug, not a rounding
#: artefact. Labels drawn right up to the frame edge legitimately land on 1.0
#: and sometimes a hair past it.
_COORD_TOLERANCE = 1e-3

#: Cap on how many rows of one label file are parsed. A corrupt file can be
#: arbitrarily long, and no real plate image has thousands of boxes.
_MAX_ROWS_PER_LABEL = 512


@dataclass(slots=True)
class SplitReport:
    """What one split (``train``, ``val``, ``test``) actually contains."""

    name: str
    images_dir: Path | None = None
    labels_dir: Path | None = None
    images: int = 0
    labels: int = 0
    #: Images with no matching label file. Legal in YOLO -- an image with no
    #: label is a negative example -- but a split that is *entirely* unlabelled
    #: is a broken export, which is why the count is kept rather than ignored.
    unlabelled: int = 0
    #: Label files with no matching image. Always a mistake.
    orphan_labels: int = 0
    boxes: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return self.images_dir is not None and self.images_dir.is_dir()

    @property
    def labelled(self) -> int:
        return self.images - self.unlabelled


@dataclass(slots=True)
class DatasetReport:
    """The verdict on a whole dataset, and everything that informed it."""

    data_yaml: Path
    root: Path | None = None
    class_names: list[str] = field(default_factory=list)
    splits: dict[str, SplitReport] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when nothing found would invalidate a training run."""
        return not self.errors and all(not s.errors for s in self.splits.values())

    @property
    def total_images(self) -> int:
        return sum(s.images for s in self.splits.values())

    @property
    def total_boxes(self) -> int:
        return sum(s.boxes for s in self.splits.values())

    def summary(self) -> str:
        """A few lines fit for a terminal, ordered worst news first."""
        lines: list[str] = []
        for message in self.errors:
            lines.append(f"  ERROR   {message}")
        for name in (*REQUIRED_SPLITS, *OPTIONAL_SPLITS):
            split = self.splits.get(name)
            if split is None or not split.present:
                continue
            for message in split.errors:
                lines.append(f"  ERROR   [{name}] {message}")
        for message in self.warnings:
            lines.append(f"  WARN    {message}")
        for name in (*REQUIRED_SPLITS, *OPTIONAL_SPLITS):
            split = self.splits.get(name)
            if split is None or not split.present:
                continue
            lines.append(
                f"  {name:<7} {split.images:>6} images  "
                f"{split.labelled:>6} labelled  {split.boxes:>6} boxes"
                + (f"  ({split.unlabelled} unlabelled)" if split.unlabelled else "")
            )
        if self.class_names:
            lines.append(f"  classes {len(self.class_names)}: {', '.join(self.class_names)}")
        return "\n".join(lines) if lines else "  (empty dataset)"


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict[str, object] | None:
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML is a hard dependency
        logger.debug("PyYAML unavailable; cannot read %s", path)
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)
    except Exception:
        logger.debug("could not parse %s", path, exc_info=True)
        return None
    return loaded if isinstance(loaded, dict) else None


def _class_names(raw: object) -> list[str]:
    """``names`` as a list, accepting both YOLO spellings.

    Ultralytics has used two: a list (``names: [plate]``) and an id-keyed
    mapping (``names: {0: plate}``). Roboflow emits the first, hand-written
    configs usually the second, and a dataset is not broken for having picked
    either one.
    """
    if isinstance(raw, dict):
        try:
            return [str(raw[key]) for key in sorted(raw, key=lambda k: int(k))]
        except (TypeError, ValueError):
            return [str(value) for value in raw.values()]
    if isinstance(raw, (list, tuple)):
        return [str(value) for value in raw]
    if isinstance(raw, str):
        return [raw]
    return []


def _resolve_split_dir(root: Path, value: object) -> Path | None:
    """Turn a ``train:``/``val:`` entry into a directory of images.

    The field may point at the images directory itself (what Roboflow writes)
    or at a directory holding an ``images/`` subdirectory (what a hand-rolled
    layout often does). Both are accepted; anything else returns ``None`` and
    the caller reports the split as missing.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = Path(value.strip())
    if not candidate.is_absolute():
        candidate = root / candidate
    if (candidate / "images").is_dir():
        return candidate / "images"
    return candidate


def _labels_dir_for(images_dir: Path) -> Path:
    """The ``labels/`` directory matching an ``images/`` directory.

    YOLO's own convention: the *last* ``images`` path component becomes
    ``labels``. Replacing every occurrence would corrupt a path that happens to
    contain the word higher up (``/srv/images/plates/images/train``).
    """
    parts = list(images_dir.parts)
    for index in range(len(parts) - 1, -1, -1):
        if parts[index] == "images":
            parts[index] = "labels"
            return Path(*parts)
    return images_dir.parent / "labels"


def _iter_images(images_dir: Path) -> Iterator[Path]:
    for path in sorted(images_dir.rglob("*")):
        if path.is_file() and path.suffix.lower() in IMAGE_SUFFIXES:
            yield path


def _check_label_file(path: Path, class_count: int) -> tuple[int, list[str]]:
    """Parse one label file. Returns ``(box_count, errors)``.

    Errors name the line so a 4000-image dataset can be repaired rather than
    re-exported.
    """
    errors: list[str] = []
    boxes = 0
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return 0, [f"{path.name}: unreadable ({exc})"]

    for number, line in enumerate(text.splitlines()[:_MAX_ROWS_PER_LABEL], start=1):
        row = line.strip()
        if not row:
            continue
        fields = row.split()
        # 5 fields is a box; more is a segmentation polygon, which ultralytics
        # also accepts and which is not this module's business to police.
        if len(fields) < 5:
            errors.append(f"{path.name}:{number}: expected 5 fields, got {len(fields)}")
            continue
        try:
            class_id = int(float(fields[0]))
            coords = [float(value) for value in fields[1:5]]
        except ValueError:
            errors.append(f"{path.name}:{number}: non-numeric field")
            continue

        if class_count and not (0 <= class_id < class_count):
            errors.append(
                f"{path.name}:{number}: class id {class_id} outside 0..{class_count - 1}"
            )
        low, high = -_COORD_TOLERANCE, 1.0 + _COORD_TOLERANCE
        if any(not (low <= value <= high) for value in coords):
            errors.append(
                f"{path.name}:{number}: coordinates {coords} are not normalised to 0..1 "
                "(a converter that emitted pixels is the usual cause)"
            )
        if coords[2] <= 0 or coords[3] <= 0:
            errors.append(f"{path.name}:{number}: zero-area box")
        boxes += 1

    return boxes, errors


def _check_split(name: str, images_dir: Path | None, max_reported: int) -> SplitReport:
    report = SplitReport(name=name, images_dir=images_dir)
    if images_dir is None or not images_dir.is_dir():
        return report

    report.labels_dir = _labels_dir_for(images_dir)
    images = list(_iter_images(images_dir))
    report.images = len(images)
    if not images:
        report.errors.append(f"{images_dir} contains no images")
        return report

    label_root = report.labels_dir
    seen_labels: set[Path] = set()
    for image in images:
        try:
            relative = image.relative_to(images_dir)
        except ValueError:  # pragma: no cover - rglob cannot produce this
            relative = Path(image.name)
        label = (label_root / relative).with_suffix(".txt")
        if not label.is_file():
            report.unlabelled += 1
            continue
        seen_labels.add(label.resolve())
        report.labels += 1
        boxes, errors = _check_label_file(label, class_count=0)
        report.boxes += boxes
        for message in errors[: max(0, max_reported - len(report.errors))]:
            report.errors.append(message)

    if label_root.is_dir():
        for label in label_root.rglob("*.txt"):
            if label.is_file() and label.resolve() not in seen_labels:
                report.orphan_labels += 1

    if report.labels == 0:
        report.errors.append(
            f"no label file matches any image in {images_dir} -- "
            f"expected them under {label_root}"
        )
    return report


def _basenames(split: SplitReport) -> set[str]:
    if split.images_dir is None or not split.images_dir.is_dir():
        return set()
    return {path.stem for path in _iter_images(split.images_dir)}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_dataset(
    data_yaml: str | Path,
    *,
    max_reported_errors: int = 20,
    require_class_name: str | None = DEFAULT_CLASS_NAME,
) -> DatasetReport:
    """Inspect a YOLO ``data.yaml`` and everything it points at.

    Never raises and never touches the network. ``require_class_name`` demotes
    to a warning rather than an error when the dataset's single class is named
    something else -- plenty of good plate datasets call it ``licence-plate``,
    ``LP`` or ``0`` -- but a *multi*-class dataset with nothing plate-like in
    it is an error, because that is the mistake that produces a detector which
    hands the recogniser a crop of every car in frame.
    """
    path = Path(data_yaml).expanduser()
    report = DatasetReport(data_yaml=path)

    if not path.is_file():
        report.errors.append(f"{path} does not exist")
        return report

    document = _load_yaml(path)
    if document is None:
        report.errors.append(f"{path} is not readable as YAML")
        return report

    # `path:` is relative to the data.yaml itself when it is not absolute.
    declared_root = document.get("path")
    root = path.parent
    if isinstance(declared_root, str) and declared_root.strip():
        candidate = Path(declared_root.strip())
        root = candidate if candidate.is_absolute() else (path.parent / candidate)
    report.root = root

    report.class_names = _class_names(document.get("names"))
    if not report.class_names:
        report.errors.append("data.yaml declares no `names`")

    for name in (*REQUIRED_SPLITS, *OPTIONAL_SPLITS):
        images_dir = _resolve_split_dir(root, document.get(name))
        split = _check_split(name, images_dir, max_reported_errors)
        report.splits[name] = split

        if name in REQUIRED_SPLITS and not split.present:
            if document.get(name) is None:
                report.errors.append(f"data.yaml has no `{name}:` split")
            else:
                report.errors.append(
                    f"`{name}: {document.get(name)}` does not resolve to a directory "
                    f"(looked in {images_dir})"
                )

    # Class ids are validated against the declared count, which needs the names
    # parsed first -- hence a second pass rather than doing it inline above.
    if report.class_names:
        _recheck_class_ids(report, len(report.class_names), max_reported_errors)

    _check_split_overlap(report)
    _check_class_naming(report, require_class_name)
    return report


def _recheck_class_ids(report: DatasetReport, class_count: int, max_reported: int) -> None:
    """Second pass now that ``names`` is known, so ids can be range-checked."""
    for split in report.splits.values():
        if not split.present or split.labels_dir is None or not split.labels_dir.is_dir():
            continue
        room = max_reported - len(split.errors)
        if room <= 0:
            continue
        for label in sorted(split.labels_dir.rglob("*.txt"))[:_MAX_ROWS_PER_LABEL]:
            _, errors = _check_label_file(label, class_count)
            for message in errors:
                if message not in split.errors and len(split.errors) < max_reported:
                    split.errors.append(message)


def _check_split_overlap(report: DatasetReport) -> None:
    """Warn when train and val share images.

    A leaked split does not fail anything -- it makes every number *better*,
    which is exactly why it has to be reported. A model validated against its
    own training images scores well and detects nothing new.
    """
    train = report.splits.get("train")
    val = report.splits.get("val")
    if train is None or val is None or not (train.present and val.present):
        return
    shared = _basenames(train) & _basenames(val)
    if shared:
        sample = ", ".join(sorted(shared)[:5])
        report.errors.append(
            f"{len(shared)} image(s) appear in both train and val ({sample}"
            f"{', ...' if len(shared) > 5 else ''}) -- validation metrics from this "
            "dataset would be measuring memorisation"
        )


def _check_class_naming(report: DatasetReport, expected: str | None) -> None:
    if expected is None or not report.class_names:
        return
    lowered = [name.lower() for name in report.class_names]
    if any(expected in name for name in lowered):
        return
    if len(report.class_names) == 1:
        report.warnings.append(
            f"the single class is named {report.class_names[0]!r}, not {expected!r}. "
            "That is fine for training, but the runtime loader only auto-detects a "
            "plate class by name -- see YoloPlateDetector._resolve_plate_classes."
        )
        return
    report.errors.append(
        f"{len(report.class_names)} classes and none is named like a plate "
        f"({', '.join(report.class_names)}). A detector trained on this would hand "
        "the recogniser a crop of every object it knows."
    )


def scaffold_dataset(root: str | Path, *, class_name: str = DEFAULT_CLASS_NAME) -> Path:
    """Create an empty YOLO dataset tree and its ``data.yaml``. Returns the yaml.

    Idempotent: existing directories are left alone and an existing
    ``data.yaml`` is not overwritten, so this is safe to re-run against a
    dataset somebody has started filling in.
    """
    base = Path(root).expanduser()
    for split in (*REQUIRED_SPLITS, *OPTIONAL_SPLITS):
        (base / "images" / split).mkdir(parents=True, exist_ok=True)
        (base / "labels" / split).mkdir(parents=True, exist_ok=True)

    data_yaml = base / "data.yaml"
    if not data_yaml.exists():
        data_yaml.write_text(
            "# YOLO dataset for Turkish licence plate detection.\n"
            "#\n"
            "# `path` is resolved relative to this file, so the tree can be moved\n"
            "# or mounted somewhere else without editing anything below.\n"
            "path: .\n"
            "train: images/train\n"
            "val: images/val\n"
            "test: images/test\n"
            "\n"
            "names:\n"
            f"  0: {class_name}\n",
            encoding="utf-8",
        )
    return data_yaml


def describe_layout(root: str | Path = "datasets/plates") -> str:
    """The layout note printed by the CLIs, with ``root`` substituted in."""
    base = str(root)
    return f"""YOLO dataset layout (single class "{DEFAULT_CLASS_NAME}")

  {base}/
    images/train/*.jpg      labels/train/*.txt
    images/val/*.jpg        labels/val/*.txt
    images/test/*.jpg       labels/test/*.txt      (optional, held out)
    data.yaml

  Each label row is one box, normalised to 0..1:
      <class_id> <x_center> <y_center> <width> <height>
  With a single class, <class_id> is always 0. An image with no plate gets an
  empty .txt, not a missing one -- that is how a negative example is written.

  Create the tree:
      python scripts/fetch_dataset.py --scaffold {base}
  Check it before booking a GPU:
      python scripts/fetch_dataset.py --check {base}/data.yaml
  Train:
      python scripts/train_plate_detector.py --data {base}/data.yaml"""
