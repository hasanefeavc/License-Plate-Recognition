#!/usr/bin/env python3
"""Measure how often the pipeline is right, and how long it takes to be right.

Runs real images through the real detector and the real recogniser, then scores
what came back with :mod:`lpr.evaluation`. This is the script that turns "we
think it works" into a number you can put in front of a customer, and the one
that stops a threshold change from quietly costing accuracy.

What it reports
---------------
* **Plate accuracy** -- exact matches. The only metric the product's behaviour
  maps onto: a plate off by one character is wrong, not 86% right.
* **CER** -- character error rate, for diagnosis.
* **Wrong-plate rate** -- of the reads that emitted something, how many named
  the wrong car. The security number.
* **False-positive rate** -- over images with no plate. Reported as ``n/a``
  rather than 0% when the evaluation set has no negatives, because a test that
  was never run is not a test that passed.
* **Latency** -- mean/p50/p95, per device. ``--device both`` measures CPU and
  CUDA in one run so the difference is measured rather than assumed.

Ground truth
------------
Either name the files after their plates (``34ABC123.jpg``, ``34ABC123_02.jpg``)
or pass ``--truth truth.csv``:

    image,plate
    frame_0001.jpg,34ABC123
    frame_0002.jpg,06XY45
    empty_lot.jpg,

An empty plate marks a **negative** sample -- an image with no plate in it.
Include some. Without them the false-positive rate cannot be measured, and it
is the number that decides whether a barrier opens for a stranger.

Usage
-----
    python scripts/evaluate.py --images datasets/plates/images/test
    python scripts/evaluate.py --images eval/ --truth eval/truth.csv --device both
    python scripts/evaluate.py --images eval/ --json report.json \\
        --min-accuracy 0.95 --max-false-positive 0.005

Exit codes:
    0  evaluation ran and every threshold passed (or none was set)
    1  a threshold failed, or the evaluation could not run
    2  a required package (opencv, torch, ultralytics, easyocr) is missing
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from lpr.dataset import IMAGE_SUFFIXES  # noqa: E402  (after the path bootstrap)
from lpr.evaluation import EvalSample, Metrics, resolve_truth, score  # noqa: E402


def find_images(root: Path) -> tuple[list[Path], list[str]]:
    """Every image under ``root``, deduplicated by basename.

    Returns ``(images, duplicate_basenames)``.

    The search is recursive and the ground-truth map is keyed on basename, so
    a tree holding ``images/train/34ABC12.jpg`` and ``images/val/34ABC12.jpg``
    would otherwise score the same label twice and inflate the sample count
    against a single underlying photograph. Deduplicating silently would be
    just as wrong -- two different cars can share a plate string in a badly
    assembled set -- so the collisions are returned for the caller to report.
    """
    if root.is_file():
        return [root], []

    seen: dict[str, Path] = {}
    duplicates: list[str] = []
    for path in sorted(
        path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in IMAGE_SUFFIXES
    ):
        if path.name in seen:
            duplicates.append(path.name)
            continue
        seen[path.name] = path
    return list(seen.values()), duplicates


# ---------------------------------------------------------------------------
# One evaluation pass
# ---------------------------------------------------------------------------


def build_stack(device: str, settings: object) -> tuple[object, object]:
    """A detector and a recogniser pinned to ``device``.

    Built per device rather than once and moved: ultralytics and EasyOCR both
    decide their execution provider at construction, and mutating that
    afterwards is the kind of thing that appears to work and silently runs on
    the wrong hardware -- which is precisely what a latency benchmark must not
    do.
    """
    from lpr.detect import build_detector
    from lpr.ocr import build_recognizer

    settings.detection.device = device  # type: ignore[attr-defined]
    settings.ocr.gpu = "true" if device not in ("cpu", "") else "false"  # type: ignore[attr-defined]

    detector = build_detector(settings)
    recognizer = build_recognizer(settings)
    return detector, recognizer


def evaluate_one(
    image_path: Path,
    truth: str,
    detector: object,
    recognizer: object,
    min_confidence: float,
) -> EvalSample:
    """Run one image end to end and package the outcome.

    Timing covers detection, cropping and OCR -- the whole path a frame takes
    between arriving from the camera and producing a string. It deliberately
    excludes disk read: a live camera hands over a decoded array, and including
    JPEG decode would flatter or penalise the model depending on the image
    size rather than on the model.
    """
    import cv2

    frame = cv2.imread(str(image_path))
    if frame is None:
        return EvalSample(image=image_path.name, truth=truth, predicted="", latency_ms=0.0)

    started = time.perf_counter()
    predicted = ""
    confidence = 0.0
    try:
        detections = detector.detect(frame)  # type: ignore[attr-defined]
        for detection in detections:
            read = recognizer.recognize(detection.crop)  # type: ignore[attr-defined]
            # `is_usable` is grammar plus non-empty text; the confidence floor
            # is the same one the orchestrator applies, so this measures the
            # pipeline as deployed rather than a more permissive variant.
            if (
                read.is_usable
                and read.confidence >= min_confidence
                and read.confidence > confidence
            ):
                predicted, confidence = read.text, read.confidence
    except Exception as exc:  # a single bad frame must not end the run
        print(f"[eval] WARNING: {image_path.name} failed: {exc}", file=sys.stderr)
        detections = []

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return EvalSample(
        image=image_path.name,
        truth=truth,
        predicted=predicted,
        confidence=confidence,
        latency_ms=elapsed_ms,
        detections=len(detections),
    )


def run_pass(
    images: list[Path],
    truth_map: dict[str, str],
    device: str,
    settings: object,
    min_confidence: float,
    warmup: int,
) -> Metrics:
    """Evaluate every image on one device."""
    detector, recognizer = build_stack(device, settings)

    # Warm-up frames are timed and thrown away. The first inference of a
    # session pays for lazy CUDA context creation, cuDNN autotuning and the
    # allocator's first arena -- on a GPU that is often several hundred
    # milliseconds, which would land entirely in the p95 of a short run.
    if warmup and images:
        print(f"[eval] Warming up on {device} ({warmup} frame(s))...")
        for path in images[:warmup]:
            evaluate_one(path, truth_map.get(path.name, ""), detector, recognizer, min_confidence)

    samples: list[EvalSample] = []
    total = len(images)
    for index, path in enumerate(images, start=1):
        name = path.name
        if name not in truth_map:
            continue  # unlabelled: scoring it either way would invent a result
        samples.append(evaluate_one(path, truth_map[name], detector, recognizer, min_confidence))
        if index % 25 == 0 or index == total:
            print(f"[eval]   {index}/{total}", end="\r", file=sys.stderr)
    print(file=sys.stderr)

    return score(samples)


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


def resolve_devices(requested: str) -> list[str]:
    """Which devices to measure, dropping CUDA when it is not genuinely usable."""
    from lpr.accel import cuda_available

    if requested == "cpu":
        return ["cpu"]
    if requested == "cuda":
        if not cuda_available():
            print(
                "[eval] ERROR: --device cuda was asked for but no usable CUDA device "
                "was found. lpr.accel probes by launching a real kernel, so this "
                "means a driver/runtime mismatch or a CPU-only torch wheel.",
                file=sys.stderr,
            )
            raise SystemExit(1)
        return ["cuda"]
    devices = ["cpu"]
    if cuda_available():
        devices.append("cuda")
    else:
        print("[eval] No usable CUDA device; measuring CPU only.")
    return devices


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------


def check_thresholds(metrics: Metrics, args: argparse.Namespace) -> list[str]:
    """Every threshold this run failed, as printable sentences.

    A metric that is ``None`` -- unmeasurable, because the evaluation set had
    no samples of that kind -- fails its threshold rather than passing it. A
    gate that green-lights a release because the test could not run is worse
    than no gate.
    """
    failures: list[str] = []

    if args.min_accuracy > 0:
        value = metrics.plate_accuracy
        if value is None:
            failures.append(
                f"plate accuracy could not be measured (no positive samples), "
                f"so --min-accuracy {args.min_accuracy:.3f} cannot be satisfied"
            )
        elif value < args.min_accuracy:
            failures.append(
                f"plate accuracy {value:.4f} is below --min-accuracy {args.min_accuracy:.3f}"
            )

    if args.max_cer < 1.0:
        value = metrics.cer
        if value is None:
            failures.append("CER could not be measured (no positive samples)")
        elif value > args.max_cer:
            failures.append(f"CER {value:.4f} exceeds --max-cer {args.max_cer:.3f}")

    if args.max_false_positive < 1.0:
        value = metrics.false_positive_rate
        if value is None:
            failures.append(
                "false-positive rate could not be measured: the evaluation set has no "
                "negative samples. Add images with no plate in them (empty plate "
                "column in the truth file)"
            )
        elif value > args.max_false_positive:
            failures.append(
                f"false-positive rate {value:.4f} exceeds "
                f"--max-false-positive {args.max_false_positive:.3f}"
            )

    if args.max_wrong_plate < 1.0:
        value = metrics.wrong_plate_rate
        if value is None:
            failures.append("wrong-plate rate could not be measured (nothing was emitted)")
        elif value > args.max_wrong_plate:
            failures.append(
                f"wrong-plate rate {value:.4f} exceeds --max-wrong-plate {args.max_wrong_plate:.3f}"
            )

    if args.max_latency_p95 > 0:
        value = metrics.latency_p95
        if value is not None and value > args.max_latency_p95:
            failures.append(
                f"p95 latency {value:.1f} ms exceeds "
                f"--max-latency-p95 {args.max_latency_p95:.1f} ms"
            )

    return failures


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evaluate.py",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--images",
        required=True,
        help="Directory of evaluation images (searched recursively), or one image.",
    )
    parser.add_argument(
        "--truth",
        default=None,
        help="CSV/TSV/JSONL mapping image to plate. Omit to read plates from the "
        "filenames. Entries here win over filenames.",
    )
    parser.add_argument(
        "--device",
        default="cpu",
        choices=("cpu", "cuda", "both"),
        help='Which device(s) to measure. "both" runs the set twice.',
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=3,
        help="Untimed frames before measurement, so lazy CUDA/cuDNN init does not land in the p95.",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=None,
        help="Confidence floor for a read to count. Defaults to ocr.min_confidence, "
        "so the measurement matches the deployed pipeline.",
    )
    parser.add_argument("--json", default=None, help="Write the full report here.")
    parser.add_argument(
        "--show-failures",
        type=int,
        default=10,
        help="How many worst-scoring samples to print. 0 to suppress.",
    )

    gates = parser.add_argument_group("CI gates (exit 1 when breached)")
    gates.add_argument("--min-accuracy", type=float, default=0.0)
    gates.add_argument("--max-cer", type=float, default=1.0)
    gates.add_argument("--max-false-positive", type=float, default=1.0)
    gates.add_argument("--max-wrong-plate", type=float, default=1.0)
    gates.add_argument("--max-latency-p95", type=float, default=0.0, help="Milliseconds.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        import cv2  # noqa: F401
    except ImportError as exc:
        print(f"[eval] ERROR: opencv is required ({exc}).", file=sys.stderr)
        return 2

    images_root = Path(args.images).expanduser()
    if not images_root.exists():
        print(f"[eval] ERROR: {images_root} does not exist.", file=sys.stderr)
        return 1

    images, duplicates = find_images(images_root)
    if not images:
        print(f"[eval] ERROR: no images found under {images_root}.", file=sys.stderr)
        return 1
    if duplicates:
        shown = ", ".join(sorted(set(duplicates))[:5])
        print(
            f"[eval] NOTE: {len(duplicates)} image(s) share a basename with an "
            f"earlier one and were skipped ({shown}"
            f"{', ...' if len(set(duplicates)) > 5 else ''}). Ground truth is keyed "
            "on basename, so counting both would score one label twice."
        )

    truth_map = resolve_truth([str(p) for p in images], args.truth)
    labelled = [p for p in images if p.name in truth_map]
    if not labelled:
        print(
            f"[eval] ERROR: none of the {len(images)} images could be matched to a "
            "plate. Name them after their plates (34ABC123.jpg) or pass --truth.",
            file=sys.stderr,
        )
        return 1

    negatives = sum(1 for name in truth_map.values() if not name)
    print(f"[eval] {len(labelled)} labelled image(s), {negatives} negative")
    if negatives == 0:
        print(
            "[eval] NOTE: no negative samples, so the false-positive rate cannot be "
            "measured. Add images with no plate in them -- that rate is what decides "
            "whether the barrier opens for a stranger."
        )

    from lpr.config import get_settings

    settings = get_settings()
    min_confidence = (
        args.min_confidence
        if args.min_confidence is not None
        else float(settings.ocr.min_confidence)
    )

    try:
        devices = resolve_devices(args.device)
    except SystemExit:
        return 1

    report: dict[str, object] = {
        "images": str(images_root),
        "labelled": len(labelled),
        "negatives": negatives,
        "min_confidence": min_confidence,
        "devices": {},
    }
    failures: list[str] = []

    for device in devices:
        print()
        print(f"[eval] ===== {device.upper()} =====")
        try:
            metrics = run_pass(labelled, truth_map, device, settings, min_confidence, args.warmup)
        except ImportError as exc:
            print(f"[eval] ERROR: a required package is missing ({exc}).", file=sys.stderr)
            return 2

        print(metrics.summary())
        report["devices"][device] = metrics.to_dict()  # type: ignore[index]

        if args.show_failures and metrics.worst:
            print(f"[eval]   worst {min(args.show_failures, len(metrics.worst))}:")
            for sample in metrics.worst[: args.show_failures]:
                got = sample.predicted or "(nothing)"
                print(
                    f"[eval]     {sample.image:<32} want {sample.truth or '(none)':<10} "
                    f"got {got:<10} conf {sample.confidence:.2f} "
                    f"boxes {sample.detections}"
                )

        # Accuracy gates apply once, on CPU, because accuracy is a property of
        # the model and not of the device. Only latency is judged per device.
        if device == devices[0]:
            failures.extend(check_thresholds(metrics, args))
        elif (
            args.max_latency_p95 > 0
            and metrics.latency_p95
            and metrics.latency_p95 > args.max_latency_p95
        ):
            failures.append(
                f"[{device}] p95 latency {metrics.latency_p95:.1f} ms exceeds "
                f"--max-latency-p95 {args.max_latency_p95:.1f} ms"
            )

    if args.json:
        destination = Path(args.json).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[eval] Report written to {destination}")

    if failures:
        print("\n[eval] THRESHOLDS FAILED:", file=sys.stderr)
        for message in failures:
            print(f"[eval]   - {message}", file=sys.stderr)
        return 1

    print("\n[eval] All thresholds passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
