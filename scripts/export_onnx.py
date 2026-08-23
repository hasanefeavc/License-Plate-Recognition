#!/usr/bin/env python3
"""Export the plate detector to ONNX for CPU inference.

Running the detector through ONNX Runtime instead of PyTorch drops the torch
dispatch overhead and lets ORT fuse the graph ahead of time. Nothing else
needs to change afterwards: ``YoloPlateDetector`` prefers a sibling ``.onnx``
next to the configured ``.pt`` automatically (see ``detection.prefer_onnx``),
so exporting is the whole integration step.

**Measure before you deploy it.** ONNX is not automatically faster: against a
oneDNN-enabled torch build on a recent Intel CPU it can be considerably
slower (~2x slower on this project's development machine). This script
therefore benchmarks both backends after exporting and tells you which one
actually wins on the hardware you ran it on. Pass ``--no-benchmark`` to skip.

    python scripts/export_onnx.py                       # models/plate_yolov8n.pt
    python scripts/export_onnx.py --imgsz 960
    python scripts/export_onnx.py --weights /path/to/best.pt --no-benchmark

Match ``--imgsz`` to ``detection.imgsz`` in config.yaml. The export is static
(``dynamic=False``), which is what makes it fast, and a static graph only
accepts the exact resolution it was built for -- the detector checks this at
startup and falls back to the ``.pt`` rather than failing at the gate.

Exit codes:
    0  export succeeded
    1  missing weights, or the export failed
    2  ultralytics / onnx tooling not installed
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

#: Opset 12 is the sweet spot: new enough for the YOLOv8 graph, old enough
#: that every onnxruntime built in the last few years accepts it.
DEFAULT_OPSET = 12
DEFAULT_IMGSZ = 640
DEFAULT_WEIGHTS = "models/plate_yolov8n.pt"


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export a YOLO plate detector to ONNX for CPU inference.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--weights",
        default=str(repo_root() / DEFAULT_WEIGHTS),
        help="PyTorch weights to export.",
    )
    parser.add_argument(
        "--imgsz",
        type=int,
        default=DEFAULT_IMGSZ,
        help="Inference resolution baked into the graph. MUST equal detection.imgsz.",
    )
    parser.add_argument("--opset", type=int, default=DEFAULT_OPSET)
    parser.add_argument(
        "--dynamic",
        action="store_true",
        help="Export with a dynamic batch/shape axis. Slower; only needed if you "
        "intend to run at several resolutions from one file.",
    )
    parser.add_argument(
        "--no-simplify",
        action="store_true",
        help="Skip graph simplification (use if onnxslim is unavailable or fails).",
    )
    parser.add_argument(
        "--half",
        action="store_true",
        help="FP16 weights. A GPU option -- it is slower than FP32 on most CPUs.",
    )
    parser.add_argument(
        "--no-benchmark",
        action="store_true",
        help="Skip the post-export .pt-vs-.onnx timing comparison.",
    )
    return parser


def export(args: argparse.Namespace, weights: Path) -> Path:
    try:
        from ultralytics import YOLO
    except ImportError:
        print(
            "[export] ERROR: ultralytics is not installed.\n  pip install ultralytics",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    print(f"[export] Loading {weights}")
    model = YOLO(str(weights))

    print(
        f"[export] Exporting to ONNX: imgsz={args.imgsz} opset={args.opset} "
        f"dynamic={args.dynamic} simplify={not args.no_simplify} half={args.half}"
    )
    try:
        produced = model.export(
            format="onnx",
            imgsz=args.imgsz,
            dynamic=args.dynamic,
            simplify=not args.no_simplify,
            opset=args.opset,
            half=args.half,
            device="cpu",  # the target is a headless CPU box, not this laptop's GPU
        )
    except ImportError as exc:
        print(
            f"[export] ERROR: the ONNX toolchain is missing ({exc}).\n"
            "  pip install onnx onnxslim onnxruntime",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    except Exception as exc:
        print(f"[export] ERROR: export failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None

    return Path(produced)


def verify(onnx_path: Path, imgsz: int) -> None:
    """Load the exported graph and run one frame through it.

    An .onnx that cannot be loaded is worse than no .onnx at all, so this is
    not optional: it is the same code path the detector will take at startup.
    """
    try:
        import numpy as np
        from ultralytics import YOLO
    except ImportError as exc:  # pragma: no cover - checked in export() already
        print(f"[export] WARNING: cannot verify the export: {exc}", file=sys.stderr)
        return

    print("[export] Verifying the exported graph with one inference...")
    model = YOLO(str(onnx_path))
    frame = np.zeros((imgsz, imgsz, 3), dtype=np.uint8)
    model.predict(source=frame, imgsz=imgsz, device="cpu", verbose=False)
    print("[export] Verification OK")


def benchmark(pt_path: Path, onnx_path: Path, imgsz: int, runs: int = 20) -> float:
    """Time both backends end to end and report the verdict.

    Run by default, because ONNX Runtime is **not** reliably faster than
    PyTorch on CPU: it depends on the ORT build, the torch build (a
    oneDNN/AMX-enabled torch is hard to beat on recent Intel parts), and the
    core count. Measured on the developer machine for this project, ONNX came
    out ~2x *slower*. The only answer that means anything is the one measured
    on the box that will run the gate, so this prints it at export time
    instead of leaving it to be discovered in production.
    """
    import numpy as np
    from ultralytics import YOLO

    frame = np.zeros((720, 1280, 3), dtype=np.uint8)

    def time_model(path: Path) -> float:
        model = YOLO(str(path))
        for _ in range(3):  # warm the graph / allocator up first
            model.predict(source=frame, imgsz=imgsz, device="cpu", verbose=False)
        started = time.perf_counter()
        for _ in range(runs):
            model.predict(source=frame, imgsz=imgsz, device="cpu", verbose=False)
        return (time.perf_counter() - started) / runs * 1000.0

    print(f"[export] Timing both backends on this machine ({runs} frames each)...")
    pt_ms = time_model(pt_path)
    onnx_ms = time_model(onnx_path)
    speedup = (pt_ms / onnx_ms) if onnx_ms > 0 else 0.0

    print()
    print(f"[export] PyTorch : {pt_ms:7.1f} ms/frame")
    print(f"[export] ONNX    : {onnx_ms:7.1f} ms/frame")
    print(f"[export] Speedup : {speedup:7.2f}x")
    if speedup < 1.0:
        print()
        print(
            "[export] WARNING: ONNX is SLOWER than PyTorch on this machine. The "
            "detector prefers the .onnx whenever it exists, so leaving this file "
            "in place would make inference slower.\n"
            f"[export]   Either delete {onnx_path.name}, or set "
            "detection.prefer_onnx: false in config.yaml."
        )
    return speedup


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    weights = Path(args.weights).expanduser().resolve()
    if not weights.exists():
        print(
            f"[export] ERROR: weights not found: {weights}\n"
            "Train a plate model first (see README_TRAINING.md) or pass --weights.",
            file=sys.stderr,
        )
        return 1

    # Ultralytics pip-installs missing extras at runtime by default, and on a
    # machine with a CUDA-capable torch it reaches for the 250 MB
    # onnxruntime-gpu wheel. This script targets CPU, so opt out and let a
    # missing dependency be a clear error instead.
    os.environ.setdefault("YOLO_AUTOINSTALL", "false")

    onnx_path = export(args, weights)
    verify(onnx_path, args.imgsz)

    size_mb = onnx_path.stat().st_size / (1024 * 1024)
    print()
    print(f"[export] Wrote {onnx_path} ({size_mb:.1f} MB)")
    print(
        "[export] The detector picks this up automatically on its next start "
        "(detection.prefer_onnx). Nothing to change in config.yaml."
    )
    if args.imgsz != DEFAULT_IMGSZ:
        print(
            f"[export] NOTE: this graph is fixed at imgsz={args.imgsz}. Set "
            f"detection.imgsz to {args.imgsz} or the detector will keep using the .pt."
        )

    if not args.no_benchmark:
        benchmark(weights, onnx_path, args.imgsz)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
