#!/usr/bin/env python3
"""Mint a time-limited licence key for one customer site.

This is the **vendor-side** tool. It never runs on a customer machine: it
signs a JWT with ``keys/private_key.pem`` (RS256) and prints it, and that
string is what the operator pastes into the desktop client (or what you drop
into a ``.license`` file next to the service).

    python scripts/generate_keys.py                       # once, ever
    python scripts/generate_license.py --days 30 --client "Site A"
    python scripts/generate_license.py --days 365 --client "ACME Otopark" --out acme.license
    python scripts/generate_license.py --verify eyJhbGciOi...

Sites verify with ``public_key.pem`` and hold no signing material at all, so
a leaked site install cannot mint licences. ``--secret`` and the
``LPR_LICENSE_SECRET`` environment variable are gone with the HS256 scheme:
the private key file is the only input.

**The history log holds only the last 10 characters of each token.** Records
are for identification -- "which key does this site have, and when does it
run out" -- not for recovery. Writing whole tokens to a file that is
world-readable on the vendor machine, copied into backups and pasted into
support threads was itself the leak: anyone who read it held every live
licence. Use ``--out`` to keep a copy of a key you still need to deliver, and
treat that file like the credential it is; once a key is delivered, re-issue
rather than recover.

Exit codes:
    0  key generated (or verified successfully)
    1  bad arguments, or the private key is missing/unreadable
    2  verification failed
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


# A checkout that was never ``pip install -e``'d still has to be able to run
# this, so src/ goes on the path before lpr is imported.
_SRC = repo_root() / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from lpr.license import PUBLIC_KEY_NAME, validate_token  # noqa: E402

# Signing lives in the library so this script and `lpr init` mint the same
# artefact -- same claims, same algorithm, one implementation.
from lpr.provisioning import PRIVATE_KEY_NAME, default_key_dir, sign_license  # noqa: E402

#: Written by scripts/generate_keys.py. Never leaves the vendor machine.
DEFAULT_KEY_DIR = default_key_dir()

#: Where every generated key is recorded. See the module docstring.
HISTORY_FILENAME = "license_history.log"

#: How much of a token the history log is allowed to hold. Enough to tell two
#: keys apart when a site reads its licence back over the phone; nowhere near
#: enough to reconstruct a signature.
TOKEN_FINGERPRINT_CHARS = 10

HISTORY_HEADER = (
    "# LPR licence history. One record per generated key.\n"
    "# Fields: created<TAB>client<TAB>expires<TAB>days<TAB>jti<TAB>token_tail\n"
    "# token_tail is the LAST 10 CHARACTERS ONLY -- an identifier, not a key.\n"
    "# Full tokens are never written here. Keep delivered keys with --out.\n"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate_license.py",
        description="Generate a signed, time-limited LPR licence key.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--days",
        type=float,
        default=30.0,
        help="Validity period in days, counted from now.",
    )
    parser.add_argument(
        "--client",
        default="",
        help='Customer/site name recorded in the key, e.g. "Site A".',
    )
    parser.add_argument(
        "--note",
        default="",
        help="Free-text note stored in the key and in the history log.",
    )
    parser.add_argument(
        "--private-key",
        default=str(DEFAULT_KEY_DIR / PRIVATE_KEY_NAME),
        help="PEM private key to sign with (from scripts/generate_keys.py).",
    )
    parser.add_argument(
        "--public-key",
        default=None,
        help=f"PEM public key used by --verify. Defaults to the installed {PUBLIC_KEY_NAME}.",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Also write the key to this file (a .license the service can read).",
    )
    parser.add_argument(
        "--history",
        default=str(repo_root() / HISTORY_FILENAME),
        help="Append-only record of every generated key (last 10 chars only).",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Do not record this key at all, not even its last 10 characters.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print only the token, nothing else (for piping).",
    )
    parser.add_argument(
        "--bind",
        default=None,
        metavar="HWID_OR_JSON",
        help="Bind this key to one machine. Takes the JSON the customer's "
        "`lpr-hwid --json` prints. Without it the key works on any machine.",
    )
    parser.add_argument(
        "--bind-here",
        action="store_true",
        help="Bind to the machine running this command. For a vendor-installed "
        "box; on your own laptop it produces a key the customer cannot use.",
    )
    parser.add_argument(
        "--verify",
        metavar="TOKEN",
        default=None,
        help="Verify an existing key instead of generating one.",
    )
    return parser


def load_private_key(path: Path) -> bytes:
    """Read the PEM signing key, or raise ``SystemExit`` with a usable message.

    Refuses a file that is not a private key so a mix-up (handing this script
    the public half) fails immediately with a clear reason rather than an
    opaque PyJWT error.
    """
    try:
        pem = path.read_bytes()
    except OSError as exc:
        raise SystemExit(
            f"[license] Cannot read the signing key {path}: {exc}\n"
            f"[license] Run: python scripts/generate_keys.py"
        ) from exc

    if b"PRIVATE KEY" not in pem:
        raise SystemExit(
            f"[license] {path} is not a PEM private key. Licences are signed "
            f"with private_key.pem; {PUBLIC_KEY_NAME} can only verify."
        )
    return pem


def generate(
    *,
    days: float,
    client: str,
    note: str,
    private_key: bytes | str,
    issued_at: datetime | None = None,
    binding: dict[str, str] | None = None,
) -> tuple[str, dict[str, object]]:
    """Sign one licence. Returns ``(token, claims)``.

    Kept as a name in this module because it has always been one; the
    implementation is :func:`lpr.provisioning.sign_license`.
    """
    return sign_license(
        days=days,
        client=client,
        note=note,
        private_key=private_key,
        issued_at=issued_at,
        binding=binding,
    )


def resolve_binding(args: argparse.Namespace) -> dict[str, str] | None:
    """Turn ``--bind`` / ``--bind-here`` into fingerprint claims.

    ``--bind`` takes what the customer's ``lpr-hwid --json`` printed: an object
    of already-hashed components. It is validated rather than trusted, because
    a mistyped paste that silently produced an unbound key would be a licence
    that works everywhere, and nothing downstream would ever complain.
    """
    if args.bind and args.bind_here:
        raise ValueError("--bind and --bind-here are mutually exclusive.")

    if args.bind_here:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
        from lpr.machine import current_fingerprint

        fingerprint = current_fingerprint()
        if not fingerprint.bindable:
            raise ValueError(
                "This machine exposes too few fingerprint components to bind to "
                f"({fingerprint.describe()}). Issue an unbound key instead."
            )
        print(f"[license] binding to this machine: {fingerprint.describe()}")
        return fingerprint.to_claims()

    if not args.bind:
        return None

    raw = args.bind.strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "--bind expects the JSON object from `lpr-hwid --json`, not a bare "
            f"hwid string ({exc})."
        ) from None

    if not isinstance(parsed, dict):
        raise ValueError("--bind JSON must be an object of fingerprint components.")

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from lpr.machine import COMPONENTS, MATCH_THRESHOLD

    components = {
        name: str(parsed[name]).strip()
        for name in COMPONENTS
        if parsed.get(name) and str(parsed[name]).strip()
    }
    if len(components) < MATCH_THRESHOLD:
        raise ValueError(
            f"--bind needs at least {MATCH_THRESHOLD} of {list(COMPONENTS)}; "
            f"got {sorted(components) or 'none'}. A key bound to fewer could "
            "never satisfy the match rule and would refuse to validate."
        )
    unknown = sorted(set(parsed) - set(COMPONENTS))
    if unknown:
        print(f"[license] ignoring unknown binding fields: {', '.join(unknown)}")
    return components


def token_fingerprint(token: str) -> str:
    """The last :data:`TOKEN_FINGERPRINT_CHARS` characters of a token.

    This is the *only* part of a token that may be written to disk outside a
    deliberate ``--out`` file. Ten trailing base64url characters of an RS256
    signature identify a key among a handful issued to one customer while
    leaving the other ~340 characters -- and the signature itself -- absent.
    """
    return token[-TOKEN_FINGERPRINT_CHARS:]


def append_history(path: Path, token: str, claims: dict[str, object]) -> None:
    """Append one tab-separated record, creating the file with a header.

    Records the key's *identity*, never the key: ``token_tail`` is the last
    ten characters and nothing more. The full token used to be written here,
    which turned an ordinary log file into a bearer-credential store -- every
    licence ever issued, in plaintext, on the vendor machine. It is not a
    recovery mechanism any more; ``jti`` and ``token_tail`` are for matching a
    record to a site that reads its key back to you.

    Append-only and line-oriented so it stays greppable:
    ``grep 'Site A' license_history.log``.
    """
    created = datetime.fromtimestamp(float(claims["iat"]), tz=timezone.utc).isoformat()
    expires = datetime.fromtimestamp(float(claims["exp"]), tz=timezone.utc).isoformat()
    record = "\t".join(
        (
            f"created={created}",
            f"client={claims['client']}",
            f"expires={expires}",
            f"days={claims['days']}",
            f"jti={claims['jti']}",
            f"token_tail=...{token_fingerprint(token)}",
        )
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists()
    with path.open("a", encoding="utf-8") as handle:
        if not exists:
            handle.write(HISTORY_HEADER)
        handle.write(record + "\n")


def _verify(token: str, public_key: str | None) -> int:
    status = validate_token(token, public_key=public_key)
    print(f"valid    : {status.valid}")
    print(f"reason   : {status.reason}")
    print(f"detail   : {status.detail}")
    print(f"client   : {status.client or '-'}")
    print(f"issued   : {status.issued_at or '-'}")
    print(f"expires  : {status.expires_at or '-'}")
    if status.days_remaining is not None:
        print(f"remaining: {status.days_remaining} gün")
    return 0 if status.valid else 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.verify:
        # Verification needs the *public* half only, so this works on a site
        # machine too, where no signing key exists.
        return _verify(args.verify, args.public_key)

    private_key = load_private_key(Path(args.private_key))

    if args.days <= 0:
        print("[license] --days must be greater than zero.", file=sys.stderr)
        return 1
    if not args.client.strip():
        print("[license] --client is required (the site this key is for).", file=sys.stderr)
        return 1

    try:
        binding = resolve_binding(args)
    except ValueError as exc:
        print(f"[license] {exc}", file=sys.stderr)
        return 1

    token, claims = generate(
        days=args.days,
        client=args.client.strip(),
        note=args.note.strip(),
        private_key=private_key,
        binding=binding,
    )

    if not args.no_history:
        history = Path(args.history)
        try:
            append_history(history, token, claims)
        except OSError as exc:
            # Not fatal -- the token is on stdout and the operator needs it --
            # but loud, because an unrecorded key cannot be recovered later.
            print(f"[license] WARNING: could not write {history}: {exc}", file=sys.stderr)

    if args.out:
        out_path = Path(args.out)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(token + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"[license] WARNING: could not write {out_path}: {exc}", file=sys.stderr)

    if args.quiet:
        print(token)
        return 0

    expires = datetime.fromtimestamp(float(claims["exp"]), tz=timezone.utc)
    print(f"[license] client : {claims['client']}")
    print(f"[license] days   : {args.days}")
    print(f"[license] expires: {expires.isoformat()}")
    print(f"[license] jti    : {claims['jti']}")
    if not args.no_history:
        print(f"[license] recorded in {args.history} (last {TOKEN_FINGERPRINT_CHARS} chars only)")
    if args.out:
        print(f"[license] written to {args.out}")
    else:
        print(
            "[license] NOTE: this token is not stored anywhere in full. Copy it "
            "now, or re-run with --out."
        )
    print()
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
