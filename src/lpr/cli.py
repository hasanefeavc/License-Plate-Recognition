"""``lpr`` -- the command-line front door.

    lpr init                 # provision a fresh checkout
    lpr init --fetch-models  # ...and pull the baseline weights
    lpr status               # what is installed, what is missing
    lpr doctor               # status, plus every check that can fail offline

``init`` is the one that matters. A fresh clone has no ``data/``, no
``models/``, no signing keys, no licence and no ``.env``; before this existed
that was four scripts run in the right order, and the service that came up
after three of them looked like a working service that refused every login.
Running it twice is safe -- nothing is overwritten without ``--force``.

Everything here is deliberately import-light: no torch, no ultralytics, no
OpenCV. These commands have to run *before* the ML stack is installed, because
that is when somebody is running them.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

__all__ = ["build_parser", "main"]


def _print_steps(steps: Sequence[object]) -> None:
    for step in steps:
        print(f"  {step}")


def cmd_init(args: argparse.Namespace) -> int:
    """Provision directories, keys, a developer licence and ``.env``."""
    from lpr.config import get_settings
    from lpr.provisioning import initialise

    settings = get_settings()
    print("[lpr init] Provisioning this checkout")
    steps = initialise(
        settings,
        root=args.root,
        key_dir=args.key_dir,
        license_days=args.license_days,
        force=args.force,
    )
    _print_steps(steps)

    if args.fetch_models:
        print("[lpr init] Fetching detection weights")
        from lpr.model_assets import ensure_detection_weights

        assets = ensure_detection_weights(settings, allow_download=True)
        print(f"  [{'+' if assets.detection_present else '='}] models: {assets.detail}")

    if args.build_css:
        print("[lpr init] Building the dashboard stylesheet")
        code = _build_css(args.root)
        if code != 0:
            print("  [!] stylesheet build reported a problem; see above", file=sys.stderr)

    print()
    print("[lpr init] Done. Next:")
    print("[lpr init]   1. Edit .env -- every secret in it is a placeholder.")
    print(
        "[lpr init]   2. Set LPR_CAMERAS__ENTRY__SOURCE to your camera (a number, or an RTSP URL)."
    )
    print("[lpr init]   3. Train or install a plate model at models/plate_yolov8n.pt")
    print(
        "[lpr init]      (README_TRAINING.md; `python scripts/fetch_models.py` gets the baseline)."
    )
    print("[lpr init]   4. Start it:  uvicorn lpr.api.main:app --host 0.0.0.0 --port 8000")
    print("[lpr init]   5. Open http://localhost:8000/web/ and create the first admin account.")
    return 0


def _build_css(root: Path | None) -> int:
    """Run ``scripts/build_web_css.py`` if this is a checkout that has it.

    Loaded by path rather than imported, because ``scripts/`` is not a package
    and is not shipped in the wheel -- an installed copy has a stylesheet
    already built and nothing to rebuild it from.
    """
    import importlib.util

    from lpr.provisioning import repo_root

    script = (root or repo_root()) / "scripts" / "build_web_css.py"
    if not script.is_file():
        print(f"  [=] stylesheet: {script} not present in this install; skipped")
        return 0

    spec = importlib.util.spec_from_file_location("lpr_build_web_css", script)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        return 0
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return int(module.main([]))


def cmd_status(args: argparse.Namespace) -> int:
    """Print what is installed and what is missing. Exit 1 if anything is."""
    from lpr.config import get_settings
    from lpr.license import LICENSE_FILE_NAME, PUBLIC_KEY_NAME
    from lpr.model_assets import describe_assets
    from lpr.provisioning import PRIVATE_KEY_NAME, resolve_key_dir

    settings = get_settings()
    assets = describe_assets(settings)
    # Same resolution `init` uses, so `status` reports on what `init` wrote.
    key_dir = resolve_key_dir(args.root, args.key_dir)
    root = args.root or Path.cwd()

    checks: list[tuple[str, bool, str]] = [
        ("data directory", settings.paths.data_dir.is_dir(), str(settings.paths.data_dir)),
        ("models directory", settings.paths.models_dir.is_dir(), str(settings.paths.models_dir)),
        (
            "detection weights",
            assets.detection_present and not assets.detection_is_stock_baseline,
            str(assets.detection_weights),
        ),
        ("public key", (key_dir / PUBLIC_KEY_NAME).is_file(), str(key_dir / PUBLIC_KEY_NAME)),
        ("private key", (key_dir / PRIVATE_KEY_NAME).is_file(), str(key_dir / PRIVATE_KEY_NAME)),
        (
            "licence",
            (settings.paths.data_dir / LICENSE_FILE_NAME).is_file(),
            str(settings.paths.data_dir / LICENSE_FILE_NAME),
        ),
        (".env", (root / ".env").is_file(), str(root / ".env")),
        (
            "dashboard stylesheet",
            (root / "web" / "static" / "css" / "app.css").is_file(),
            "web/static/css/app.css",
        ),
    ]
    if assets.ocr_backend == "easyocr":
        checks.append(("EasyOCR weights", not assets.ocr_missing, str(assets.ocr_models_dir)))

    width = max(len(name) for name, _, _ in checks)
    for name, ok, where in checks:
        print(f"  [{'ok' if ok else '  '}] {name.ljust(width)}  {where}")

    for issue in settings.cameras.issues:
        print(f"  [!!] camera {issue.role}: {issue.message}")

    missing = [name for name, ok, _ in checks if not ok]
    print()
    if missing:
        print(f"[lpr status] Missing: {', '.join(missing)}")
        print("[lpr status] Run `lpr init` (and `python scripts/fetch_models.py` for weights).")
        return 1
    print("[lpr status] Everything this installation needs is present.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """``status``, plus the checks that need more than a stat call.

    Kept separate because these import things: the ML stack, the database
    driver. On a box where one of those is what is broken, ``status`` still
    answers and ``doctor`` is what tells you which import failed.
    """
    code = cmd_status(args)
    print()
    print("[lpr doctor] Optional components")

    for label, module in (
        ("OpenCV (cv2)", "cv2"),
        ("ultralytics", "ultralytics"),
        ("torch", "torch"),
        ("easyocr", "easyocr"),
        ("pyserial", "serial"),
    ):
        try:
            __import__(module)
        except Exception as exc:
            print(f"  [  ] {label}: not importable ({type(exc).__name__})")
        else:
            print(f"  [ok] {label}")

    try:
        from lpr.db import init_db

        init_db()
        print("  [ok] database schema")
    except Exception as exc:
        print(f"  [  ] database schema: {exc}")
        code = 1

    from lpr.config import get_settings, unknown_env_names

    unknown = unknown_env_names()
    if unknown:
        print(f"  [!!] unrecognised LPR_ environment variables: {', '.join(sorted(unknown))}")
    else:
        print("  [ok] every LPR_ environment variable maps to a setting")

    settings = get_settings()
    for role in ("entry", "exit"):
        camera = getattr(settings.cameras, role)
        kind = camera.source_kind
        mark = "ok" if kind != "invalid" else "  "
        print(f"  [{mark}] camera {role}: {camera.source!r} ({kind})")
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lpr",
        description="Set up and inspect an LPR installation.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Checkout root. Defaults to the directory this package was installed from.",
    )
    common.add_argument(
        "--key-dir",
        type=Path,
        default=None,
        help="Where the RSA pair lives. Defaults to <root>/keys.",
    )

    init = subparsers.add_parser(
        "init",
        parents=[common],
        help="Provision directories, keys, a developer licence and .env.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    init.add_argument(
        "--license-days",
        type=float,
        default=365.0,
        help="Validity of the developer licence this mints.",
    )
    init.add_argument(
        "--fetch-models",
        action="store_true",
        help="Also download the baseline YOLO weights (needs a network).",
    )
    init.add_argument(
        "--build-css",
        action="store_true",
        help="Also rebuild web/static/css/app.css from the dashboard sources.",
    )
    init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing keys, licence and .env. Invalidates issued licences.",
    )
    init.set_defaults(func=cmd_init)

    status = subparsers.add_parser(
        "status", parents=[common], help="Report what is installed and what is missing."
    )
    status.set_defaults(func=cmd_status)

    doctor = subparsers.add_parser(
        "doctor", parents=[common], help="status, plus import and database checks."
    )
    doctor.set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
