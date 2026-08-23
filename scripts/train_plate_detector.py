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
    """The ``data.yaml`` to train against: explicit ``--data`` or Roboflow."""
    if args.data:
        data_yaml = Path(args.data).expanduser().resolve()
        if not data_yaml.exists():
            raise SystemExit(f"[train] ERROR: dataset config not found: {data_yaml}")
        print(f"[train] Using local dataset {data_yaml}")
        return data_yaml
    return download_roboflow_dataset(Path(args.dataset_dir).expanduser().resolve())


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


def train(args: argparse.Namespace, data_yaml: Path) -> Path:
    """Run the fine-tune and return the path to ``best.pt``."""
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
    return best


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.epochs < 1 or args.batch < 1 or args.imgsz < 32:
        print("[train] ERROR: --epochs and --batch must be >= 1, --imgsz >= 32.", file=sys.stderr)
        return 1

    data_yaml = resolve_dataset(args)
    best = train(args, data_yaml)

    print(f"[train] Best weights: {best}")
    if args.no_install_model:
        print(
            f"[train] --no-install-model given; copy it yourself with:\n"
            f"  cp {best} {args.models_dir / PLATE_MODEL_NAME}"
        )
        return 0

    destination = install_model(best, args.models_dir)
    print()
    print("[train] Done. The pipeline will use this model on its next start:")
    print(f"[train]   detection.model_path -> {destination}")
    print("[train] Validate it before putting it on a gate:")
    print(f"[train]   yolo detect val model={destination} data={data_yaml}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
