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


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--root" not in args:
        args += ["--root", str(repo_root())]
    return cli_main(["init", *args])


if __name__ == "__main__":
    raise SystemExit(main())
