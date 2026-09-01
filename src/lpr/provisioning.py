"""Turn a fresh checkout into a runnable installation, idempotently.

Getting from ``git clone`` to a service that starts used to be four manual
steps in the right order -- create the directories, generate the RSA pair,
mint a licence against it, copy ``.env.example`` -- with nothing checking that
they happened and each one failing differently when skipped. Missing the
licence step, in particular, produced a service that started, served, and
refused every login, which is a long way from the missing step.

Every function here is safe to run twice. Nothing is overwritten without
``force``: this is provisioning for a machine that may already be provisioned,
so "already there" is the expected outcome, not an error. Each returns a
:class:`Step` saying what it did, and :func:`initialise` runs the lot.

The signing helpers are also what ``scripts/generate_keys.py`` and
``scripts/generate_license.py`` call, so a developer licence minted by
``lpr init`` and a customer licence minted by the vendor script are the same
artefact produced by the same code.
"""

from __future__ import annotations

import logging
import os
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lpr.license import ALGORITHM, ISSUER, LICENSE_FILE_NAME, PUBLIC_KEY_NAME

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_DEV_LICENSE_DAYS",
    "PRIVATE_KEY_NAME",
    "PUBLIC_KEY_NAME",
    "Step",
    "ensure_directories",
    "ensure_dev_license",
    "ensure_env_file",
    "ensure_keypair",
    "generate_keypair",
    "initialise",
    "resolve_key_dir",
    "sign_license",
]

#: Written by :func:`generate_keypair`. Never leaves the machine that signs.
PRIVATE_KEY_NAME = "private_key.pem"

#: 2048 is the floor for RS256 and what this project standardises on.
DEFAULT_KEY_SIZE = 2048
MINIMUM_KEY_SIZE = 2048

#: How long a licence minted by ``lpr init`` lasts. A year: long enough that a
#: developer never thinks about it again, short enough that a key which
#: escaped onto a customer box stops working within a support cycle.
DEFAULT_DEV_LICENSE_DAYS = 365.0

#: ``client`` claim on a developer licence. Deliberately conspicuous: if this
#: string ever turns up in a customer's licence report, the key was minted by
#: the wrong tool on the wrong machine.
DEV_LICENSE_CLIENT = "local-development"


@dataclass(frozen=True)
class Step:
    """The outcome of one provisioning action.

    ``changed`` is what separates "created the keys" from "the keys were
    already there", which is the only thing a re-run has to tell you.
    """

    name: str
    changed: bool
    detail: str
    path: Path | None = None

    def __str__(self) -> str:
        mark = "+" if self.changed else "="
        return f"[{mark}] {self.name}: {self.detail}"


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------


def ensure_directories(
    settings: object | None = None, *, key_dir: Path | None = None
) -> list[Step]:
    """Create every directory the service writes into.

    ``data/``, ``models/``, ``data/snapshots/`` and the OCR weight cache all
    come from :mod:`lpr.model_assets`, which resolves them through
    ``settings.paths`` so a repointed data directory moves them together.
    ``keys/`` is separate: it is not a runtime path, it is where the signing
    material lives, and only a machine that mints licences has one.
    """
    from lpr.model_assets import ensure_runtime_dirs

    steps: list[Step] = []
    for path in ensure_runtime_dirs(settings):  # type: ignore[arg-type]
        steps.append(Step("directory", False, f"{path} ready", path))

    target = key_dir or default_key_dir()
    existed = target.is_dir()
    target.mkdir(parents=True, exist_ok=True)
    verb = "ready" if existed else "created"
    steps.append(Step("directory", not existed, f"{target} {verb}", target))
    return steps


def repo_root() -> Path:
    """The checkout root (``<root>/src/lpr/provisioning.py``), or ``/app``."""
    return Path(__file__).resolve().parents[2]


def default_key_dir() -> Path:
    """``<repo>/keys``. Gitignored in its entirety, so a private key cannot be
    committed by reflex.

    ``<repo>`` is the checkout this package was imported from, which is also
    where :func:`lpr.license.public_key_candidates` looks -- so a pair written
    here is one the running service can actually verify against.
    """
    return repo_root() / "keys"


def resolve_key_dir(root: Path | None, key_dir: Path | None) -> Path:
    """Where the signing pair belongs, given optional ``--root``/``--key-dir``.

    An explicit ``key_dir`` wins. Otherwise a caller that named a checkout root
    means *that* checkout's ``keys/``: defaulting to this package's own repo
    root instead would have ``lpr init --root /srv/lpr`` read and write keys
    somewhere else entirely, and report them as present when they are not
    present where it just provisioned.
    """
    if key_dir is not None:
        return key_dir
    if root is not None:
        return root / "keys"
    return default_key_dir()


# ---------------------------------------------------------------------------
# RSA key pair
# ---------------------------------------------------------------------------


def generate_keypair(out_dir: Path, key_size: int = DEFAULT_KEY_SIZE) -> tuple[Path, Path]:
    """Write a fresh RSA pair into ``out_dir``. Returns ``(private, public)``.

    Overwrites unconditionally -- the "should I?" decision belongs to the
    caller, because getting it wrong invalidates every licence already issued
    against the old pair. See :func:`ensure_keypair` for the safe wrapper.
    """
    if key_size < MINIMUM_KEY_SIZE:
        raise ValueError(f"RSA key size must be at least {MINIMUM_KEY_SIZE} bits")

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # Deliberately unencrypted: signing is a non-interactive CLI, and a
        # passphrase typed into a script ends up in a shell history or a CI
        # variable. Protect this file with filesystem permissions and by
        # keeping it off every machine that does not mint keys.
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    private_path = out_dir / PRIVATE_KEY_NAME
    public_path = out_dir / PUBLIC_KEY_NAME

    # Created 0600 from the start rather than written world-readable and
    # tightened afterwards -- the gap between the two is a real window.
    descriptor = os.open(
        private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(private_pem)
    try:
        os.chmod(private_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - filesystem without POSIX modes
        pass

    public_path.write_bytes(public_pem)
    return private_path, public_path


def ensure_keypair(
    key_dir: Path | None = None, *, key_size: int = DEFAULT_KEY_SIZE, force: bool = False
) -> Step:
    """Generate the signing pair if it is not already there.

    Refuses to replace an existing pair without ``force``, and says why: new
    keys invalidate every licence already issued against the old ones, which
    on a customer machine means every site running the matching
    ``public_key.pem`` stops verifying at once.
    """
    target = key_dir or default_key_dir()
    private_path = target / PRIVATE_KEY_NAME
    public_path = target / PUBLIC_KEY_NAME

    if private_path.is_file() and public_path.is_file() and not force:
        return Step("keys", False, f"key pair already present in {target}", private_path)

    private_path, public_path = generate_keypair(target, key_size)
    return Step(
        "keys",
        True,
        f"generated {private_path.name} (mode 0600) and {public_path.name} in {target}",
        private_path,
    )


# ---------------------------------------------------------------------------
# Licence
# ---------------------------------------------------------------------------


def sign_license(
    *,
    days: float,
    client: str,
    note: str,
    private_key: bytes | str,
    issued_at: datetime | None = None,
    binding: dict[str, str] | None = None,
) -> tuple[str, dict[str, object]]:
    """Sign one licence. Returns ``(token, claims)``.

    ``exp`` is the whole mechanism: it is what the offline verifier compares
    the system clock against, and it is inside the signature, so it cannot be
    edited without the private key.

    ``binding`` carries the customer's machine fingerprint components. With it
    the key is a site licence; without it the key is a bearer token that works
    on every machine it is copied to -- the right shape for an evaluation or a
    developer box, and the wrong shape for a sale. The components are already
    hashed by :mod:`lpr.machine` before they reach here, so a licence file
    never carries a MAC address or a serial number in the clear.
    """
    import jwt

    now = issued_at or datetime.now(timezone.utc)
    expires = now + timedelta(days=days)
    claims: dict[str, object] = {
        "iss": ISSUER,
        "sub": client or "unnamed",
        "client": client or "unnamed",
        "note": note,
        "days": days,
        "jti": uuid.uuid4().hex,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires.timestamp()),
    }
    for name, value in (binding or {}).items():
        if value:
            claims[name] = str(value)

    token = jwt.encode(claims, private_key, algorithm=ALGORITHM)
    if isinstance(token, bytes):  # pragma: no cover - PyJWT 1.x
        token = token.decode("utf-8")
    return token, claims


def ensure_dev_license(
    settings: object | None = None,
    *,
    key_dir: Path | None = None,
    days: float = DEFAULT_DEV_LICENSE_DAYS,
    force: bool = False,
) -> Step:
    """Mint an unbound developer licence into ``<data_dir>/.license``.

    Unbound on purpose: a developer licence has to survive being copied to the
    laptop, the CI runner and the container, and hardware binding is a
    property of a *sold* key. It is labelled ``local-development`` so it is
    obvious in a licence report where it came from.

    A no-op when a ``.license`` already exists -- overwriting one would be a
    good way to lose a real key someone had installed for testing.
    """
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()

    target = settings.paths.data_dir / LICENSE_FILE_NAME  # type: ignore[attr-defined]
    if target.is_file() and target.read_text(encoding="utf-8").strip() and not force:
        return Step("license", False, f"licence already present at {target}", target)

    private_path = (key_dir or default_key_dir()) / PRIVATE_KEY_NAME
    if not private_path.is_file():
        return Step(
            "license",
            False,
            f"skipped: no signing key at {private_path} (run the keys step first)",
            target,
        )

    token, claims = sign_license(
        days=days,
        client=DEV_LICENSE_CLIENT,
        note="Minted by `lpr init`. Not for distribution.",
        private_key=private_path.read_bytes(),
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(token + "\n", encoding="utf-8")

    expires = datetime.fromtimestamp(float(str(claims["exp"])), tz=timezone.utc)
    return Step(
        "license",
        True,
        f"minted a {days:g}-day developer licence at {target} (expires {expires:%Y-%m-%d})",
        target,
    )


# ---------------------------------------------------------------------------
# .env
# ---------------------------------------------------------------------------


def ensure_env_file(root: Path | None = None, *, force: bool = False) -> Step:
    """Copy ``.env.example`` to ``.env`` when there is no ``.env``.

    Copied rather than symlinked, and never overwritten: ``.env`` is the
    uncommitted file carrying this machine's secrets, and clobbering it during
    a re-run of a setup script would be the most expensive thing in this
    module.
    """
    base = root or repo_root()
    example = base / ".env.example"
    target = base / ".env"

    if target.exists() and not force:
        return Step("env", False, f"{target} already exists; left untouched", target)
    if not example.is_file():
        return Step("env", False, f"skipped: no {example} to copy from", target)

    target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    return Step(
        "env",
        True,
        f"copied {example.name} -> {target.name}; replace every placeholder secret in it",
        target,
    )


# ---------------------------------------------------------------------------
# The whole thing
# ---------------------------------------------------------------------------


def initialise(
    settings: object | None = None,
    *,
    root: Path | None = None,
    key_dir: Path | None = None,
    license_days: float = DEFAULT_DEV_LICENSE_DAYS,
    force: bool = False,
) -> list[Step]:
    """Run every provisioning step, in dependency order.

    Directories first (everything else writes into them), then the key pair,
    then the licence that has to be signed by it, then ``.env``. Returns one
    :class:`Step` per action so a caller can print them or assert on them.
    """
    key_dir = resolve_key_dir(root, key_dir)
    steps = ensure_directories(settings, key_dir=key_dir)
    steps.append(ensure_keypair(key_dir, force=force))
    steps.append(ensure_dev_license(settings, key_dir=key_dir, days=license_days, force=force))
    steps.append(ensure_env_file(root, force=force))
    return steps
