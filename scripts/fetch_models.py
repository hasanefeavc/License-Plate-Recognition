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

It also fetches the **EasyOCR** detection/recognition networks on request
(``--easyocr``). Those are ~100 MB and EasyOCR downloads them lazily on first
use, into ``models/easyocr`` -- another bind-mounted volume. Pre-filling that
directory from the host is what turns a container cold start from "wait for a
100 MB download, and hang if the link drops" into a local file read. Run it
once per machine.

Usage:
    python scripts/fetch_models.py
    python scripts/fetch_models.py --easyocr
    python scripts/fetch_models.py --easyocr --only-easyocr
    python scripts/fetch_models.py --models-dir /custom/path --force

Exit codes:
    0  download succeeded, was skipped, or a custom plate model is installed
    1  network/download error (offline, DNS failure, HTTP error, ...)
    2  --easyocr was asked for but easyocr is not installed here
"""

from __future__ import annotations

import argparse
import socket
import sys
import urllib.error
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


# A checkout that was never ``pip install -e``'d still has to be able to run
# this -- it is one of the first commands on a fresh machine -- so src/ goes on
# the path before lpr is imported.
_SRC = _repo_root() / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# The URL, the pinned digest and the verified download all live in the library,
# so this script and the API's start-up provisioning fetch the same file with
# the same checks rather than two copies that drift apart.
from lpr.model_assets import (  # noqa: E402
    BASELINE_NAME,
    BASELINE_SHA256,
    DOWNLOAD_URL,
    EASYOCR_WEIGHTS,
    PLATE_MODEL_NAME,
    download,
    is_stock_baseline,
)

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


def fetch_easyocr(models_dir: Path, timeout: float = 120.0) -> int:
    """Populate ``models_dir/easyocr`` by constructing a Reader once.

    Deliberately done by *using* EasyOCR rather than by fetching URLs
    ourselves. The download locations, filenames and MD5s are internal to the
    library and have changed between 1.x releases; driving the library means
    this script cannot go stale against the pin in requirements.txt, and what
    lands on disk is by construction exactly what the service will look for.

    The reader is built on CPU whatever the host has. This only writes files --
    a GPU would be claimed, initialised and thrown away for nothing, and on the
    gate box it may well be busy serving the running container.
    """
    target = models_dir / "easyocr"
    target.mkdir(parents=True, exist_ok=True)

    missing = [name for name in EASYOCR_WEIGHTS if not (target / name).is_file()]
    if not missing:
        print(f"[fetch_models] EasyOCR weights already cached in {target} -- nothing to do.")
        return 0

    try:
        import easyocr
    except ImportError:
        print(
            "[fetch_models] ERROR: --easyocr needs the easyocr package installed here.\n"
            "[fetch_models]        pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 2

    print(f"[fetch_models] Fetching EasyOCR weights into {target} (missing: {', '.join(missing)})")
    print("[fetch_models] This is ~100 MB and runs once per machine.")

    # Same reasoning as lpr.ocr.recognizer._bounded_sockets: EasyOCR calls
    # urlretrieve without a timeout, so an interrupted download would otherwise
    # hang this script forever instead of failing and telling you to retry.
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        easyocr.Reader(
            ["en"],
            gpu=False,
            model_storage_directory=str(target),
            user_network_directory=str(target),
            download_enabled=True,
            verbose=False,
        )
    except Exception as exc:
        print(f"[fetch_models] ERROR: EasyOCR weight download failed: {exc}", file=sys.stderr)
        print(
            "[fetch_models] Retry when the network is stable, or raise --easyocr-timeout.",
            file=sys.stderr,
        )
        return 1
    finally:
        socket.setdefaulttimeout(previous)

    still_missing = [name for name in EASYOCR_WEIGHTS if not (target / name).is_file()]
    if still_missing:
        # Not fatal: a future release may rename these, and the reader above
        # constructed successfully, which is the outcome that actually matters.
        print(
            f"[fetch_models] NOTE: expected {', '.join(still_missing)} in {target} but the "
            "reader built successfully; the release may use different filenames."
        )
    else:
        print(f"[fetch_models] EasyOCR weights cached in {target}")
    return 0


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
    parser.add_argument(
        "--easyocr",
        action="store_true",
        help=(
            "Also pre-fetch the EasyOCR networks into <models-dir>/easyocr, so the "
            "container never downloads them at startup."
        ),
    )
    parser.add_argument(
        "--only-easyocr",
        action="store_true",
        help="Fetch the EasyOCR networks and skip the YOLO baseline entirely.",
    )
    parser.add_argument(
        "--easyocr-timeout",
        type=float,
        default=120.0,
        help="Socket timeout, in seconds, for the EasyOCR download (default: 120).",
    )
    args = parser.parse_args(argv)

    models_dir: Path = args.models_dir
    if args.only_easyocr:
        return fetch_easyocr(models_dir, args.easyocr_timeout)
    baseline_path = models_dir / BASELINE_NAME
    plate_path = models_dir / PLATE_MODEL_NAME

    # A plate-specific model makes the generic baseline dead weight: the
    # pipeline loads detection.model_path (this file) and never touches
    # yolov8n.pt. Downloading it here would only be a 6 MB decoy.
    if plate_path.exists() and not args.force:
        size_mb = plate_path.stat().st_size / (1024 * 1024)
        if is_stock_baseline(plate_path):
            # The exact state this repository shipped in: the COCO baseline
            # renamed to satisfy detection.model_path. It loads, it detects
            # people and chairs, the runtime rejects it as unusable weights and
            # falls back to contour detection -- and the old version of this
            # message called it a "custom plate model", which is how the state
            # survived as long as it did.
            print(
                f"[fetch_models] WARNING: {plate_path} is byte-for-byte the stock "
                f"COCO {BASELINE_NAME}, not a plate detector.",
                file=sys.stderr,
            )
            print(
                "[fetch_models] The pipeline will reject it at startup and fall back "
                "to contour detection, which reads far fewer plates.",
                file=sys.stderr,
            )
            print("[fetch_models] Train a real one:")
            print("[fetch_models]   python scripts/fetch_dataset.py --scaffold datasets/plates")
            print(
                "[fetch_models]   python scripts/train_plate_detector.py "
                "--data datasets/plates/data.yaml"
            )
            return fetch_easyocr(models_dir, args.easyocr_timeout) if args.easyocr else 1

        print(f"[fetch_models] Custom plate model found: {plate_path} ({size_mb:.1f} MB)")
        print("[fetch_models] This is what the pipeline loads (detection.model_path).")
        print(f"[fetch_models] Skipping the generic {BASELINE_NAME} download -- nothing to do.")
        print("[fetch_models] Use --force to fetch the baseline anyway.")
        return fetch_easyocr(models_dir, args.easyocr_timeout) if args.easyocr else 0

    if baseline_path.exists() and not args.force:
        print(
            f"[fetch_models] {baseline_path} already exists, skipping download (use --force to redo)."
        )
    else:
        print(f"[fetch_models] Downloading {args.url} -> {baseline_path}")
        # Only the default URL has a pinned digest; see BASELINE_SHA256.
        expected = BASELINE_SHA256 if args.url == DOWNLOAD_URL else None
        if expected is None:
            print("[fetch_models] NOTE: --url overridden, so the checksum is not pinned.")
        try:
            download(args.url, baseline_path, expected_sha256=expected)
        except RuntimeError as exc:
            print(f"[fetch_models] ERROR: {exc}", file=sys.stderr)
            return 1
        except urllib.error.HTTPError as exc:
            print(
                f"[fetch_models] ERROR: server returned HTTP {exc.code} for {args.url}",
                file=sys.stderr,
            )
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

    if args.easyocr:
        print()
        status = fetch_easyocr(models_dir, args.easyocr_timeout)
        if status != 0:
            return status

    print()
    print(
        f"[fetch_models] NOTE: {baseline_path.name} is a generic COCO model, not a plate detector."
    )
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
