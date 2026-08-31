#!/usr/bin/env python3
"""Fine-tune YOLOv8n on Turkish license plates.

Produces the file the pipeline actually wants: ``models/plate_yolov8n.pt``,
which is what ``detection.model_path`` in config.yaml defaults to. Drop the
result there and the service picks it up with no config changes.

This runs anywhere ultralytics runs, but it is written for a Colab GPU
session -- see README_TRAINING.md for the six lines you paste into a
notebook.

Dataset
-------
Either bring your own YOLO-format dataset and point ``--data`` at its
``data.yaml``, or let the script pull one from Roboflow:

    export ROBOFLOW_API_KEY=...      # required for the Roboflow path
    export ROBOFLOW_WORKSPACE=...
    export ROBOFLOW_PROJECT=...
    export ROBOFLOW_VERSION=1

With no ``--data`` and no ``ROBOFLOW_API_KEY`` the script stops and tells you
what is missing rather than silently training on nothing.

Usage
-----
    python scripts/train_plate_detector.py                      # Roboflow via env vars
    python scripts/train_plate_detector.py --data dataset/data.yaml
    python scripts/train_plate_detector.py --epochs 200 --batch 8 --device 0
    python scripts/train_plate_detector.py --data d/data.yaml --no-install-model

Exit codes:
    0  training finished and the weights were installed
    1  bad configuration, missing dataset, or a failed download/train
    2  ultralytics (or roboflow, when requested) is not installed
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from lpr.dataset import validate_dataset  # noqa: E402  (after the path bootstrap)

# Hyperparameters. The defaults below are tuned for plates specifically:
# small, high-aspect-ratio objects that occupy a fraction of a percent of a
# 720p frame, photographed at an angle, at night, and through motion blur.
DEFAULT_MODEL = "yolov8n.pt"  # nano: the pipeline runs on CPU at the gate
DEFAULT_IMGSZ = 640  # keep it identical to detection.imgsz in config.yaml
DEFAULT_EPOCHS = 100
DEFAULT_BATCH = 16  # fits a Colab T4 at 640px with yolov8n
DEFAULT_PATIENCE = 20  # early-stop after 20 epochs without a mAP gain

#: Augmentations. Plates are *rigid, upright and never mirrored*: a plate is
#: read left-to-right, so horizontal flipping teaches the model to detect
#: mirror-image plates that do not exist. Rotation and shear stay small and
#: model the real variance (camera tilt, approach angle); HSV and scale carry
#: the day/night and distance variance instead.
PLATE_AUGMENTATIONS: dict[str, float] = {
    "fliplr": 0.0,
    "flipud": 0.0,
    "degrees": 5.0,
    "shear": 3.0,
    "perspective": 0.0005,
    "scale": 0.5,
    "translate": 0.1,
    "hsv_h": 0.015,
    "hsv_s": 0.7,
    "hsv_v": 0.4,
    "mosaic": 1.0,
    "close_mosaic": 10,  # last 10 epochs train on un-mosaicked images
}

PLATE_MODEL_NAME = "plate_yolov8n.pt"


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------


def download_roboflow_dataset(destination: Path) -> Path:
    """Download the configured Roboflow dataset, return its ``data.yaml``.

    Reads ROBOFLOW_API_KEY / ROBOFLOW_WORKSPACE / ROBOFLOW_PROJECT /
    ROBOFLOW_VERSION from the environment -- never from a command-line flag,
    so the key does not end up in a notebook's saved output or your shell
    history.
    """
    api_key = os.environ.get("ROBOFLOW_API_KEY", "").strip()
    workspace = os.environ.get("ROBOFLOW_WORKSPACE", "").strip()
    project_name = os.environ.get("ROBOFLOW_PROJECT", "").strip()
    version_raw = os.environ.get("ROBOFLOW_VERSION", "1").strip() or "1"

    missing = [
        name
        for name, value in (
            ("ROBOFLOW_API_KEY", api_key),
            ("ROBOFLOW_WORKSPACE", workspace),
            ("ROBOFLOW_PROJECT", project_name),
        )
        if not value
    ]
    if missing:
        raise SystemExit(
            f"[train] ERROR: {', '.join(missing)} not set. Either export them or "
            "pass --data <path/to/data.yaml> to train on a local dataset."
        )

    try:
        version = int(version_raw)
    except ValueError:
        raise SystemExit(
            f"[train] ERROR: ROBOFLOW_VERSION must be an integer, got {version_raw!r}."
        ) from None

    try:
        from roboflow import Roboflow
    except ImportError:
        print(
            "[train] ERROR: the roboflow package is not installed. Either\n"
            "  pip install roboflow\n"
            "or download the dataset yourself and pass --data <data.yaml>.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    destination.mkdir(parents=True, exist_ok=True)
    print(f"[train] Downloading Roboflow {workspace}/{project_name} v{version} -> {destination}")

    roboflow = Roboflow(api_key=api_key)
    project = roboflow.workspace(workspace).project(project_name)
    # model_format="yolov8" gives the exact directory layout ultralytics wants,
    # data.yaml included.
    dataset = project.version(version).download("yolov8", location=str(destination))

    data_yaml = Path(getattr(dataset, "location", destination)) / "data.yaml"
    if not data_yaml.exists():
        raise SystemExit(
            f"[train] ERROR: Roboflow download finished but {data_yaml} is missing. "
            "Check that the project is an object-detection project."
        )
    return data_yaml


def resolve_dataset(args: argparse.Namespace) -> Path:
    """The ``data.yaml`` to train against: explicit ``--data`` or Roboflow.

    Whichever it came from, it is validated before a GPU is touched. The
    failure this guards against is the expensive-and-silent one: a run that
    completes against an empty or leaked validation split, reports a
    respectable mAP, and installs a model that detects nothing.
    """
    if args.data:
        data_yaml = Path(args.data).expanduser().resolve()
        if not data_yaml.exists():
            raise SystemExit(f"[train] ERROR: dataset config not found: {data_yaml}")
        print(f"[train] Using local dataset {data_yaml}")
    else:
        data_yaml = download_roboflow_dataset(Path(args.dataset_dir).expanduser().resolve())

    if args.skip_dataset_check:
        print("[train] --skip-dataset-check given; training on an unverified dataset.")
        return data_yaml

    report = validate_dataset(data_yaml)
    print(f"[train] Dataset check: {data_yaml}")
    print(report.summary())
    if not report.ok:
        raise SystemExit(
            "[train] ERROR: this dataset would not produce a usable model. Fix the "
            "errors above, or re-run with --skip-dataset-check to train anyway.\n"
            f"[train]   python scripts/fetch_dataset.py --check {data_yaml}"
        )
    return data_yaml


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


def train(args: argparse.Namespace, data_yaml: Path) -> tuple[Path, dict[str, float]]:
    """Run the fine-tune. Returns ``(best.pt, validation metrics)``."""
    try:
        from ultralytics import YOLO
    except ImportError:
        print(
            "[train] ERROR: ultralytics is not installed.\n  pip install ultralytics",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    print(
        f"[train] Fine-tuning {args.model} on {data_yaml.name}: "
        f"imgsz={args.imgsz} epochs={args.epochs} batch={args.batch} "
        f"patience={args.patience} device={args.device or 'auto'}"
    )

    model = YOLO(args.model)
    results = model.train(
        data=str(data_yaml),
        imgsz=args.imgsz,
        epochs=args.epochs,
        batch=args.batch,
        patience=args.patience,
        device=args.device,
        project=str(args.project),
        name=args.name,
        exist_ok=True,
        seed=args.seed,
        pretrained=True,
        optimizer="auto",
        cos_lr=True,  # smoother convergence over a long run than a step schedule
        plots=True,  # confusion matrix + PR curves land in the run directory
        val=True,
        **PLATE_AUGMENTATIONS,
    )

    best = find_best_weights(results, Path(args.project) / args.name)
    if best is None:
        raise SystemExit(
            "[train] ERROR: training finished but no best.pt was produced. "
            f"Look in {Path(args.project) / args.name} for what happened."
        )
    return best, read_metrics(getattr(model, "metrics", None) or results)


def find_best_weights(results: object, fallback_run_dir: Path) -> Path | None:
    """Locate ``best.pt``, preferring what the trainer itself reports.

    ultralytics appends a suffix to the run directory when one already exists
    (``train``, ``train2``, ...), so the hard-coded path in the README is only
    right on a fresh machine. Ask the results object first, and only then fall
    back to the conventional location.
    """
    save_dir = getattr(results, "save_dir", None)
    candidates = []
    if save_dir:
        candidates.append(Path(save_dir) / "weights" / "best.pt")
    candidates.append(fallback_run_dir / "weights" / "best.pt")

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def read_metrics(results: object) -> dict[str, float]:
    """Validation metrics from a finished run, as a plain dict.

    ultralytics has moved these around between versions (``results_dict`` on
    the metrics object, ``box.map50`` on newer ones), so every access is
    defensive and a missing metric is absent rather than zero -- reporting a
    real 0.0 mAP and "we could not read the mAP" as the same number would turn
    the acceptance gate below into a coin toss.
    """
    metrics: dict[str, float] = {}
    source = getattr(results, "results_dict", None)
    if isinstance(source, dict):
        for key, value in source.items():
            try:
                metrics[str(key)] = float(value)
            except (TypeError, ValueError):
                continue

    box = getattr(results, "box", None)
    for attribute, name in (
        ("map50", "mAP50"),
        ("map", "mAP50-95"),
        ("mp", "precision"),
        ("mr", "recall"),
    ):
        value = getattr(box, attribute, None)
        if value is None:
            continue
        try:
            metrics.setdefault(name, float(value))
        except (TypeError, ValueError):
            continue
    return metrics


def _metric(metrics: dict[str, float], *names: str) -> float | None:
    """First metric matching any of ``names``, tolerating ultralytics' spellings."""
    for name in names:
        for key, value in metrics.items():
            if key == name or key.endswith(f"/{name}") or key.endswith(f"({name})"):
                return value
    return None


def report_metrics(metrics: dict[str, float], min_map50: float) -> bool:
    """Print the run's validation numbers and say whether they clear the gate.

    The gate exists because "training finished" and "training produced
    something worth putting on a gate" are different statements, and only the
    first one is obvious from the console output.
    """
    map50 = _metric(metrics, "mAP50", "metrics/mAP50(B)")
    map5095 = _metric(metrics, "mAP50-95", "metrics/mAP50-95(B)")
    precision = _metric(metrics, "precision", "metrics/precision(B)")
    recall = _metric(metrics, "recall", "metrics/recall(B)")

    print("[train] Validation metrics:")
    for label, value in (
        ("mAP@0.5     ", map50),
        ("mAP@0.5:0.95", map5095),
        ("precision   ", precision),
        ("recall      ", recall),
    ):
        rendered = f"{value:.4f}" if value is not None else "(unavailable)"
        print(f"[train]   {label} {rendered}")

    if min_map50 <= 0:
        return True
    if map50 is None:
        print(
            "[train] WARNING: --min-map was given but no mAP@0.5 could be read from "
            "this ultralytics version; the gate is being skipped rather than guessed.",
            file=sys.stderr,
        )
        return True
    if map50 < min_map50:
        print(
            f"[train] REJECTED: mAP@0.5 {map50:.4f} is below the --min-map floor "
            f"{min_map50:.4f}. The weights were NOT installed; they are still in the "
            "run directory if you want to inspect them.",
            file=sys.stderr,
        )
        return False
    print(f"[train] mAP@0.5 {map50:.4f} clears the --min-map floor {min_map50:.4f}.")
    return True


def verify_plate_model(weights: Path) -> None:
    """Refuse to install weights the runtime loader would reject.

    Exactly the check ``YoloPlateDetector`` runs at startup, run here instead
    so a bad model is caught at training time rather than discovered as a gate
    that silently fell back to contour detection. A model whose classes are
    person/car/chair is the stock COCO baseline, which is what a collapsed
    Roboflow download leaves behind.
    """
    try:
        from ultralytics import YOLO

        from lpr.detect.yolo import UnusablePlateWeights, YoloPlateDetector
    except ImportError as exc:  # pragma: no cover - ultralytics checked in train()
        print(f"[train] WARNING: cannot verify the weights ({exc}); installing anyway.")
        return

    try:
        model = YOLO(str(weights))
        YoloPlateDetector._resolve_plate_classes(model)
    except UnusablePlateWeights as exc:
        raise SystemExit(
            f"[train] ERROR: refusing to install {weights} -- {exc}\n"
            "[train] The pipeline would reject these weights at startup and fall back "
            "to contour detection, so installing them would look like success and "
            "behave like failure."
        ) from None
    except Exception as exc:
        print(f"[train] WARNING: could not inspect {weights} ({exc}); installing anyway.")
        return

    names = getattr(model, "names", None) or {}
    listed = list(names.values()) if isinstance(names, dict) else list(names)
    print(f"[train] Weights verified: {len(listed)} class(es) -- {', '.join(map(str, listed))}")


def install_model(best: Path, models_dir: Path) -> Path:
    """Copy ``best.pt`` to ``models/plate_yolov8n.pt``, keeping one backup.

    The previous fine-tune is moved aside rather than overwritten: a training
    run that turns out worse than the one it replaced is a bad afternoon, not
    a lost model.
    """
    models_dir.mkdir(parents=True, exist_ok=True)
    destination = models_dir / PLATE_MODEL_NAME

    if destination.exists():
        backup = destination.with_suffix(".pt.bak")
        shutil.move(str(destination), str(backup))
        print(f"[train] Previous model kept at {backup}")

    shutil.copy2(best, destination)
    size_mb = destination.stat().st_size / (1024 * 1024)
    print(f"[train] Installed {best} -> {destination} ({size_mb:.1f} MB)")
    return destination


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    root = repo_root()
    parser = argparse.ArgumentParser(
        description="Fine-tune YOLOv8n for Turkish license plate detection.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data",
        default=None,
        help="Path to a YOLO data.yaml. Omit to download from Roboflow via the "
        "ROBOFLOW_* environment variables.",
    )
    parser.add_argument(
        "--dataset-dir",
        default=str(root / "datasets" / "plates"),
        help="Where a Roboflow download is unpacked.",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Starting weights.")
    parser.add_argument("--imgsz", type=int, default=DEFAULT_IMGSZ)
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    parser.add_argument(
        "--patience",
        type=int,
        default=DEFAULT_PATIENCE,
        help="Stop early after this many epochs with no validation improvement.",
    )
    parser.add_argument(
        "--device",
        default=None,
        help='Torch device: "0" for the first GPU, "cpu", or unset for auto.',
    )
    parser.add_argument("--seed", type=int, default=0, help="Makes a run reproducible.")
    parser.add_argument(
        "--project",
        default=str(root / "runs" / "detect"),
        help="Root directory for run artefacts.",
    )
    parser.add_argument("--name", default="train", help="Run directory name.")
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=root / "models",
        help="Where the finished plate model is installed.",
    )
    parser.add_argument(
        "--no-install-model",
        action="store_true",
        help="Train, but leave best.pt where it is instead of copying it into models/.",
    )
    parser.add_argument(
        "--min-map",
        type=float,
        default=0.0,
        help="Refuse to install the weights unless validation mAP@0.5 reaches this. "
        "0 disables the gate. 0.85 is a reasonable floor for a single-class "
        "plate detector before it goes anywhere near a barrier.",
    )
    parser.add_argument(
        "--skip-dataset-check",
        action="store_true",
        help="Train without validating the dataset first. You almost never want "
        "this: the check costs seconds and catches the mistakes that cost a "
        "whole training run.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.epochs < 1 or args.batch < 1 or args.imgsz < 32:
        print("[train] ERROR: --epochs and --batch must be >= 1, --imgsz >= 32.", file=sys.stderr)
        return 1

    if args.min_map < 0 or args.min_map > 1:
        print("[train] ERROR: --min-map must be between 0 and 1.", file=sys.stderr)
        return 1

    data_yaml = resolve_dataset(args)
    best, metrics = train(args, data_yaml)

    print(f"[train] Best weights: {best}")
    if not report_metrics(metrics, args.min_map):
        return 1

    if args.no_install_model:
        print(
            f"[train] --no-install-model given; copy it yourself with:\n"
            f"  cp {best} {args.models_dir / PLATE_MODEL_NAME}"
        )
        return 0

    verify_plate_model(best)
    destination = install_model(best, args.models_dir)
    print()
    print("[train] Done. The pipeline will use this model on its next start:")
    print(f"[train]   detection.model_path -> {destination}")
    print("[train] Validate it before putting it on a gate:")
    print(f"[train]   yolo detect val model={destination} data={data_yaml}")
    print("[train] Then measure the whole pipeline, not just the detector:")
    print(f"[train]   python scripts/evaluate.py --data {data_yaml} --split test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
