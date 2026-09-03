#!/usr/bin/env python3
"""One-command setup for a fresh checkout. Wrapper around ``lpr init``.

    python scripts/setup_dev.py
    python scripts/setup_dev.py --fetch-models --build-css

This exists so the very first command somebody runs after ``git clone`` does
not require ``pip install -e .`` to have happened first: it puts ``src/`` on
the path itself and then hands over to :mod:`lpr.cli`, which is where the
actual work lives. Once the package is installed, ``lpr init`` is the same
thing typed shorter.

What it does (all of it idempotent -- run it twice, nothing is clobbered):

  1. creates data/, models/, keys/ and data/snapshots/
  2. generates keys/private_key.pem + keys/public_key.pem if absent
  3. mints a local developer licence into data/.license
  4. copies .env.example to .env if there is no .env
  5. fetches the baseline detection weights when none are on disk

Step 5 is added automatically -- a fresh clone has no weights, and finding
that out at the gate, on the first frame, is the wrong time. Pass
``--no-fetch-models`` on a site that must never reach the network. It fetches
the *baseline*, which is scaffolding rather than a plate detector; see
``lpr.model_assets.ensure_detection_weights`` for why nothing installs it as
one.

Exit codes:
    0  everything provisioned (or was already)
    1  a step failed; the message says which
"""

from __future__ import annotations

import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


# A checkout that was never ``pip install -e``'d still has to be able to run
# this -- that is the whole point -- so src/ goes on the path before lpr is
# imported. Same bootstrap as scripts/generate_license.py.
_SRC = repo_root() / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from lpr.cli import main as cli_main  # noqa: E402

#: Opt-out consumed here rather than passed on -- `lpr init` has no such flag,
#: and adding one would mean two spellings of the same decision.
_NO_FETCH = "--no-fetch-models"


def detection_weights_missing() -> bool:
    """True when the configured plate weights are not on disk.

    Asked through :mod:`lpr.model_assets` rather than by looking for
    ``models/plate_yolov8n.pt`` directly, so a site that repointed
    ``detection.model_path`` is answered about the file it actually uses.

    Never raises. This decides whether to *add* an optional step, so a
    configuration this cannot read is a reason to skip the download and carry
    on provisioning, not to fail the setup that was asked for.
    """
    try:
        from lpr.config import get_settings
        from lpr.model_assets import describe_assets

        return not describe_assets(get_settings()).detection_present
    except Exception:  # pragma: no cover - unreadable config or absent deps
        return False


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--root" not in args:
        args += ["--root", str(repo_root())]

    # Only when nothing was said either way: an explicit --fetch-models is
    # already the same request, and --no-fetch-models is the refusal.
    explicit = _NO_FETCH in args or "--fetch-models" in args
    args = [arg for arg in args if arg != _NO_FETCH]
    if not explicit and detection_weights_missing():
        args.append("--fetch-models")

    return cli_main(["init", *args])


if __name__ == "__main__":
    raise SystemExit(main())
