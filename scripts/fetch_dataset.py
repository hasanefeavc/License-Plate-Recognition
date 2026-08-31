#!/usr/bin/env python3
"""Get a Turkish plate dataset onto disk, and check it before it costs GPU time.

Three jobs, one for each way a dataset arrives:

``--scaffold DIR``
    Create an empty YOLO tree you fill in yourself. This is the path for
    footage you shot at your own gate, which is the dataset that matters most:
    a model trained on other people's cameras generalises to other people's
    cameras.

``--roboflow``
    Pull a labelled dataset from Roboflow. Credentials come from the
    environment only -- never from a flag, so the key stays out of shell
    history and out of a notebook's saved output.

``--check DATA_YAML``
    Validate a dataset from either source. Run this *before* booking a GPU.
    The failure this exists for is silent: a run that completes, reports a
    respectable mAP and installs a model that detects nothing, because the
    validation split was empty, mislabelled, or a copy of the training split.

Usage
-----
    python scripts/fetch_dataset.py --scaffold datasets/plates
    python scripts/fetch_dataset.py --check datasets/plates/data.yaml
    export ROBOFLOW_API_KEY=... ROBOFLOW_WORKSPACE=... ROBOFLOW_PROJECT=...
    python scripts/fetch_dataset.py --roboflow

Exit codes:
    0  the requested action succeeded (and, for --check, the dataset is usable)
    1  bad arguments, a failed download, or a dataset that would not train
    2  the roboflow package is not installed
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from lpr.dataset import (  # noqa: E402  (must follow the sys.path bootstrap)
    DEFAULT_CLASS_NAME,
    DatasetReport,
    describe_layout,
    scaffold_dataset,
    validate_dataset,
)

DEFAULT_DATASET_DIR = REPO_ROOT / "datasets" / "plates"

#: Public Roboflow projects that carry Turkish plates, for operators who have
#: no footage of their own yet. Listed rather than hard-coded into a download:
#: licence terms differ per project and are the user's to accept, and a
#: dataset shot in another country is a starting point, not a finished model.
SUGGESTED_SOURCES = """
Where to get labelled Turkish plates
------------------------------------
Roboflow Universe hosts several plate datasets. Search "turkish license plate"
or "turkey plaka" and read each project's licence before downloading -- they
differ, and some forbid commercial use, which matters for this product.

Then export the version in **YOLOv8** format and either:
  * download it here with --roboflow and the ROBOFLOW_* variables, or
  * download the zip yourself, unpack it, and pass its data.yaml to --check.

Whatever you start with, plan to add your own footage. A detector trained
entirely on someone else's cameras inherits their mounting height, their lens,
their lighting and their country's plate design. Several hundred frames from
the gate you are actually installing at is worth more than several thousand
from a public dataset, and it is the difference between a demo and a product.
""".strip("\n")


# ---------------------------------------------------------------------------
# Roboflow
# ---------------------------------------------------------------------------


def download_roboflow(destination: Path) -> Path:
    """Download the configured Roboflow dataset. Returns its ``data.yaml``.

    Reads ROBOFLOW_API_KEY / _WORKSPACE / _PROJECT / _VERSION from the
    environment. Shared with ``train_plate_detector.py`` so there is one
    credential path rather than two that drift.
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
            f"[dataset] ERROR: {', '.join(missing)} not set.\n"
            "  export ROBOFLOW_API_KEY=... ROBOFLOW_WORKSPACE=... ROBOFLOW_PROJECT=...\n"
            "Or download the zip by hand and use --check on its data.yaml."
        )

    try:
        version = int(version_raw)
    except ValueError:
        raise SystemExit(
            f"[dataset] ERROR: ROBOFLOW_VERSION must be an integer, got {version_raw!r}."
        ) from None

    try:
        from roboflow import Roboflow
    except ImportError:
        print(
            "[dataset] ERROR: the roboflow package is not installed.\n"
            "  pip install roboflow\n"
            "Or download the dataset yourself and use --check.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    destination.mkdir(parents=True, exist_ok=True)
    print(f"[dataset] Downloading {workspace}/{project_name} v{version} -> {destination}")

    roboflow = Roboflow(api_key=api_key)
    project = roboflow.workspace(workspace).project(project_name)
    dataset = project.version(version).download("yolov8", location=str(destination))

    location = Path(getattr(dataset, "location", destination))
    data_yaml = location / "data.yaml"
    if not data_yaml.is_file():
        raise SystemExit(
            f"[dataset] ERROR: the download finished but {data_yaml} is missing. "
            "Check that the Roboflow project is an object-detection project."
        )
    return data_yaml


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def print_report(report: DatasetReport) -> None:
    print(f"[dataset] {report.data_yaml}")
    print(report.summary())

    if report.ok:
        train = report.splits.get("train")
        val = report.splits.get("val")
        total = report.total_images
        print(f"[dataset] OK -- {total} images, {report.total_boxes} boxes")
        # Advisory, not a failure: a small dataset trains, it just does not
        # generalise, and saying so here is cheaper than saying it after a
        # disappointing run.
        if train and train.images < 300:
            print(
                f"[dataset] NOTE: {train.images} training images is on the small side. "
                "Several hundred from the target site is the usual floor for a "
                "detector that holds up at night and at an angle."
            )
        if val and train and val.images and train.images:
            ratio = val.images / (train.images + val.images)
            if not 0.08 <= ratio <= 0.35:
                print(
                    f"[dataset] NOTE: val is {ratio:.0%} of train+val. "
                    "10-20% is the usual split; far outside that makes the "
                    "reported metrics noisy or the training set unnecessarily small."
                )
    else:
        print("[dataset] NOT USABLE -- fix the errors above before training.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fetch_dataset.py",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=SUGGESTED_SOURCES,
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--scaffold",
        nargs="?",
        const=str(DEFAULT_DATASET_DIR),
        metavar="DIR",
        help="Create an empty YOLO dataset tree and its data.yaml.",
    )
    action.add_argument(
        "--roboflow",
        action="store_true",
        help="Download from Roboflow using the ROBOFLOW_* environment variables.",
    )
    action.add_argument(
        "--check",
        metavar="DATA_YAML",
        help="Validate an existing dataset and report what would break training.",
    )
    action.add_argument(
        "--layout",
        action="store_true",
        help="Print the expected directory layout and exit.",
    )
    parser.add_argument(
        "--dest",
        default=str(DEFAULT_DATASET_DIR),
        help="Where --roboflow unpacks the download.",
    )
    parser.add_argument(
        "--class-name",
        default=DEFAULT_CLASS_NAME,
        help="Class name written into a scaffolded data.yaml.",
    )
    parser.add_argument(
        "--no-check",
        action="store_true",
        help="Skip the validation pass that normally follows --roboflow.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.layout:
        print(describe_layout(args.dest))
        print()
        print(SUGGESTED_SOURCES)
        return 0

    if args.scaffold:
        root = Path(args.scaffold).expanduser()
        data_yaml = scaffold_dataset(root, class_name=args.class_name)
        print(f"[dataset] Scaffolded {root}")
        print(f"[dataset] Wrote {data_yaml}" if data_yaml.is_file() else "")
        print()
        print(describe_layout(root))
        print()
        print("[dataset] The tree is empty. Fill images/ and labels/, then:")
        print(f"[dataset]   python scripts/fetch_dataset.py --check {data_yaml}")
        return 0

    if args.roboflow:
        data_yaml = download_roboflow(Path(args.dest).expanduser().resolve())
        print(f"[dataset] Downloaded to {data_yaml}")
        if args.no_check:
            return 0
        print()
        report = validate_dataset(data_yaml)
        print_report(report)
        return 0 if report.ok else 1

    report = validate_dataset(Path(args.check).expanduser())
    print_report(report)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
