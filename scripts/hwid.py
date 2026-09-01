#!/usr/bin/env python3
"""Print this machine's licensing fingerprint.

Run this on the **customer's** machine and send the output to the vendor. It is
what turns a bearer licence into a site licence: the vendor pastes the JSON into
``generate_license.py --bind`` and the resulting key works on that box and no
other.

Nothing here is a secret. Every component is already a salted hash, so the
output carries no MAC address and no serial number -- it is safe to paste into
an e-mail or a support ticket, which is exactly where it is going.

Usage
-----
    python scripts/hwid.py                # human-readable
    python scripts/hwid.py --json         # for --bind
    python scripts/hwid.py --json > hwid.json

Exit codes:
    0  a bindable fingerprint was produced
    1  too few components could be read to bind a licence to this machine
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from lpr.machine import (  # noqa: E402  (after the path bootstrap)
    COMPONENTS,
    MATCH_THRESHOLD,
    current_fingerprint,
    describe_environment,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hwid.py", description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the components as JSON, for generate_license.py --bind.",
    )
    args = parser.parse_args(argv)

    fingerprint = current_fingerprint()

    if args.json:
        # Only the components. The hwid itself is a display value and is not
        # what the licence binds to, so including it would invite somebody to
        # paste the wrong half.
        print(json.dumps(fingerprint.to_claims(), indent=2, sort_keys=True))
        return 0 if fingerprint.bindable else 1

    print(f"Machine id (hwid) : {fingerprint.hwid or '(none)'}")
    print(f"Environment       : {describe_environment()}")
    print()
    for name in COMPONENTS:
        value = fingerprint.components.get(name)
        print(f"  {name:<12} {value or '(unreadable)'}")
    print()

    if fingerprint.bindable:
        print(
            f"{len(fingerprint.components)} of {len(COMPONENTS)} components readable "
            f"({MATCH_THRESHOLD} needed). Send the vendor:"
        )
        print("    python scripts/hwid.py --json")
        if len(fingerprint.components) == MATCH_THRESHOLD:
            print()
            print(
                "NOTE: exactly the minimum. With only two components there is no "
                "slack -- replacing the network card will require a rebind. That "
                "is usually the case in a container, where the board serial is "
                "not exposed."
            )
        return 0

    print(
        f"Only {len(fingerprint.components)} component(s) readable; "
        f"{MATCH_THRESHOLD} are needed to bind a licence to this machine. "
        "Ask the vendor for an unbound key."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
