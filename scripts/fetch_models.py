#!/usr/bin/env python3
"""Fetch the baseline YOLOv8n detection model into models/.

This downloads the generic (COCO-trained) ``yolov8n.pt`` weights published
by Ultralytics -- NOT a plate detector. It exists so a fresh checkout has
*something* to run the pipeline against, and so the container's models/
volume can be provisioned from the host without needing network access
inside the container itself (docker/Dockerfile deliberately does not COPY
models/ -- it's a volume, see docker/docker-compose.yml).

Once a real fine-tune exists at ``models/plate_yolov8n.pt`` this script has
nothing left to do and downloads nothing: the baseline is scaffolding for a
machine that has no plate model yet, and re-fetching it on a provisioned
machine only wastes bandwidth and invites confusion about which file the
pipeline is actually loading. Pass --force to fetch it anyway.

Train the plate model with ``scripts/train_plate_detector.py``; see
README_TRAINING.md.

Usage:
    python scripts/fetch_models.py
    python scripts/fetch_models.py --models-dir /custom/path --force

Exit codes:
    0  download succeeded, was skipped, or a custom plate model is installed
    1  network/download error (offline, DNS failure, HTTP error, ...)
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASELINE_NAME = "yolov8n.pt"
PLATE_MODEL_NAME = "plate_yolov8n.pt"
# Same release Ultralytics itself pulls weights from when auto-downloading.
DOWNLOAD_URL = f"https://github.com/ultralytics/assets/releases/download/v8.3.0/{BASELINE_NAME}"

DATASET_LAYOUT_NOTE = """
Fine-tuning dataset layout (YOLO format, single class "plate")
----------------------------------------------------------------
  dataset/
    images/
      train/*.jpg
      val/*.jpg
    labels/
      train/*.txt   # one .txt per image, same basename
      val/*.txt
    data.yaml

  Each labels/*.txt line is one bounding box, normalised 0-1:
      <class_id> <x_center> <y_center> <width> <height>
  With a single class, <class_id> is always 0.

  data.yaml:
      path: dataset
      train: images/train
      val: images/val
      names:
        0: plate

  Train it (installs the result into models/ for you):
      python scripts/train_plate_detector.py --data dataset/data.yaml

  ...or straight from Roboflow, with ROBOFLOW_API_KEY / _WORKSPACE /
  _PROJECT / _VERSION exported:
      python scripts/train_plate_detector.py

  On a Colab GPU instead of your laptop: see README_TRAINING.md.

  models/plate_yolov8n.pt is the path src/lpr/config.py's
  detection.model_path defaults to -- drop your fine-tune there and the
  pipeline picks it up with no config changes.
""".strip("\n")


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def download(url: str, dest: Path, timeout: float = 30.0) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_dest = dest.with_suffix(dest.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "lpr-fetch-models/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response, tmp_dest.open("wb") as out:
        while True:
            chunk = response.read(1024 * 256)
            if not chunk:
                break
            out.write(chunk)
    tmp_dest.replace(dest)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=_repo_root() / "models",
        help="Directory to save the baseline weights into (default: <repo-root>/models).",
    )
    parser.add_argument(
        "--url",
        default=DOWNLOAD_URL,
        help="Override the download URL (advanced / mirrors / air-gapped setups).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if the baseline weights file already exists.",
    )
    args = parser.parse_args(argv)

    models_dir: Path = args.models_dir
    baseline_path = models_dir / BASELINE_NAME
    plate_path = models_dir / PLATE_MODEL_NAME

    # A plate-specific model makes the generic baseline dead weight: the
    # pipeline loads detection.model_path (this file) and never touches
    # yolov8n.pt. Downloading it here would only be a 6 MB decoy.
    if plate_path.exists() and not args.force:
        size_mb = plate_path.stat().st_size / (1024 * 1024)
        print(f"[fetch_models] Custom plate model found: {plate_path} ({size_mb:.1f} MB)")
        print("[fetch_models] This is what the pipeline loads (detection.model_path).")
        print(f"[fetch_models] Skipping the generic {BASELINE_NAME} download -- nothing to do.")
        print("[fetch_models] Use --force to fetch the baseline anyway.")
        return 0

    if baseline_path.exists() and not args.force:
        print(f"[fetch_models] {baseline_path} already exists, skipping download (use --force to redo).")
    else:
        print(f"[fetch_models] Downloading {args.url} -> {baseline_path}")
        try:
            download(args.url, baseline_path)
        except urllib.error.HTTPError as exc:
            print(f"[fetch_models] ERROR: server returned HTTP {exc.code} for {args.url}", file=sys.stderr)
            return 1
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(
                f"[fetch_models] ERROR: could not download the baseline model "
                f"(are you offline?): {exc}",
                file=sys.stderr,
            )
            print(
                "[fetch_models] The API/pipeline can still start without this file, "
                "but detection will fail until a model is placed at "
                f"{plate_path}.",
                file=sys.stderr,
            )
            return 1
        print(f"[fetch_models] Saved baseline weights to {baseline_path}")

    print()
    print(f"[fetch_models] NOTE: {baseline_path.name} is a generic COCO model, not a plate detector.")
    print(
        f"[fetch_models] Replace it with a plate-specific fine-tune saved at "
        f"{plate_path} before relying on detection accuracy."
    )
    print("[fetch_models] Train one:  python scripts/train_plate_detector.py")
    print("[fetch_models] Colab instructions: README_TRAINING.md")
    print()
    print(DATASET_LAYOUT_NOTE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
