#!/usr/bin/env python3
"""Generate the RSA key pair the licensing system signs and verifies with.

Run this **once**, on the vendor machine, and then guard the output:

    python scripts/generate_keys.py            # -> keys/private_key.pem, keys/public_key.pem

``private_key.pem``
    The signing key. It belongs on the vendor machine and nowhere else --
    whoever holds it can mint themselves an unlimited licence. It is written
    with mode 0600 and must never be shipped, committed or e-mailed.

``public_key.pem``
    The verifying key. This one is *meant* to be distributed: it is installed
    on every customer site next to the service, and it can only check
    signatures, never produce them. A site that loses it stops verifying; a
    site that leaks it loses nothing.

That asymmetry is the whole point of the RS256 migration. Under the previous
HS256 scheme the verifying key *was* the signing key, so every customer
install shipped with everything needed to forge a licence.

Losing ``private_key.pem`` means you can no longer issue or renew keys for
any site running the matching ``public_key.pem``: back it up offline, and do
not regenerate the pair casually -- new keys invalidate every licence already
in the field.

Exit codes:
    0  keys written
    1  refused (files exist and --force was not given), or a write failed
    2  the ``cryptography`` package is not installed
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


# A checkout that was never ``pip install -e``'d still has to be able to run
# this, so src/ goes on the path before lpr is imported.
_SRC = repo_root() / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# The generation itself lives in the library, so that `lpr init` and this
# script produce the same artefact rather than two implementations that drift.
from lpr.provisioning import (  # noqa: E402
    DEFAULT_KEY_SIZE,
    MINIMUM_KEY_SIZE,
    PRIVATE_KEY_NAME,
    PUBLIC_KEY_NAME,
    default_key_dir,
    generate_keypair,
)

#: Default output directory. Ignored by .gitignore in its entirety, so a
#: private key cannot be committed by reflex.
DEFAULT_KEY_DIR = default_key_dir()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate_keys.py",
        description="Generate the RSA key pair used to sign and verify licence keys.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_KEY_DIR),
        help="Directory the two .pem files are written to.",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=DEFAULT_KEY_SIZE,
        help=f"RSA modulus size in bits (minimum {MINIMUM_KEY_SIZE}).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing keys. This invalidates every licence already issued.",
    )
    return parser


def generate(out_dir: Path, key_size: int = DEFAULT_KEY_SIZE) -> tuple[Path, Path]:
    """Write a fresh key pair into ``out_dir``. Returns ``(private, public)``.

    Kept as a name in this module because it has always been one; the
    implementation is :func:`lpr.provisioning.generate_keypair`.
    """
    return generate_keypair(out_dir, key_size)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.key_size < MINIMUM_KEY_SIZE:
        print(
            f"[keys] --key-size must be at least {MINIMUM_KEY_SIZE} bits.",
            file=sys.stderr,
        )
        return 1

    out_dir = Path(args.out_dir)
    existing = [
        path
        for path in (out_dir / PRIVATE_KEY_NAME, out_dir / PUBLIC_KEY_NAME)
        if path.exists()
    ]
    if existing and not args.force:
        for path in existing:
            print(f"[keys] Refusing to overwrite {path}", file=sys.stderr)
        print(
            "[keys] Regenerating invalidates every licence already issued. "
            "Pass --force only if that is what you want.",
            file=sys.stderr,
        )
        return 1

    try:
        private_path, public_path = generate(out_dir, args.key_size)
    except ImportError:
        print(
            "[keys] The 'cryptography' package is required: pip install cryptography",
            file=sys.stderr,
        )
        return 2
    except OSError as exc:
        print(f"[keys] Could not write the keys: {exc}", file=sys.stderr)
        return 1

    print(f"[keys] private: {private_path}  (mode 0600 -- keep on this machine only)")
    print(f"[keys] public : {public_path}  (install this one on every site)")
    print()
    print("[keys] Next steps:")
    print("[keys]   1. Back up the private key offline. Losing it means no renewals.")
    print("[keys]   2. Ship public_key.pem to each site (data dir, or LPR_LICENSE_PUBLIC_KEY).")
    print("[keys]   3. Mint keys with: python scripts/generate_license.py --days 30 --client ...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
