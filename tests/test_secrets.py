"""Guards against committing a credential.

This file exists because it already happened: a real API/licence signing key
and a live Gmail app password were committed in ``.env.example`` and a mail
password in ``config.yaml``. Both files are meant to be templates, both are
tracked, and both were pushed. The fix for the leak itself is *rotation* --
history keeps what it was given -- but the fix for the next one is a test.

The checks are deliberately shape-based rather than a list of known-bad values.
A denylist only catches the secret you already know about.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: 32+ hex characters in a row. `openssl rand -hex 32` produces 64; nothing a
#: template legitimately contains looks like this.
HEX_SECRET_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")

#: An opaque credential: a run of lowercase alphanumerics with nothing but
#: group separators in it. A Gmail app password is the archetype -- nominally
#: 16 characters in four groups, though the one that actually leaked here was
#: 17, so the length is a range rather than a constant.
#:
#: Applied to assignment *values*, and only after the placeholder filter: a
#: template value like ``your-16-char-app-password`` has the same character
#: classes and is distinguished by being recognisably English, not by shape.
OPAQUE_SECRET_RE = re.compile(r"^[a-z0-9]{14,32}$")


def _compact(value: str) -> str:
    """Strip quotes and group separators, as a credential is usually pasted."""
    return re.sub(r"[\s-]+", "", value.strip().strip("\"'"))


#: Assignments whose value must never be a real credential in a tracked file.
ASSIGNMENT_RE = re.compile(
    r"^\s*[-#]?\s*(?:LPR_\w*(?:SECRET|PASSWORD)\w*|password|secret_key)\s*[:=]\s*(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

#: Values that are obviously placeholders. Anything else in a secret-shaped
#: assignment is treated as real.
PLACEHOLDER_HINTS = (
    "replace",
    "your-",
    "change-me",
    "example",
    "placeholder",
    "dummy",
    "xxx",
    "openssl",
)

TEMPLATE_FILES = (".env.example", "config.yaml", "docker/docker-compose.yml")


def _is_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("\"'").strip()
    if not cleaned or cleaned in ("''", '""'):
        return True
    lowered = cleaned.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


@pytest.mark.parametrize("name", TEMPLATE_FILES)
def test_a_committed_template_holds_no_long_hex_key(name: str) -> None:
    """`openssl rand -hex 32` output in a tracked file is a published key."""
    path = ROOT / name
    if not path.exists():  # pragma: no cover - optional file
        pytest.skip(f"{name} not present")
    found = HEX_SECRET_RE.findall(path.read_text(encoding="utf-8"))
    assert not found, f"{name} contains what looks like a real key: {found[:2]}"


@pytest.mark.parametrize("name", TEMPLATE_FILES)
def test_a_committed_template_holds_no_app_password(name: str) -> None:
    """Four groups of four is the shape Google hands you."""
    path = ROOT / name
    if not path.exists():  # pragma: no cover - optional file
        pytest.skip(f"{name} not present")

    offenders = [
        value
        for value in ASSIGNMENT_RE.findall(path.read_text(encoding="utf-8"))
        if not _is_placeholder(value) and OPAQUE_SECRET_RE.match(_compact(value))
    ]
    assert not offenders, f"{name} contains what looks like an app password"


def test_the_guard_recognises_the_password_that_actually_leaked() -> None:
    """A regression guard nobody has seen fire is a guess.

    This is the exact string that was committed, so the shape check is pinned
    against the real thing rather than against an invented example.
    """
    leaked = "1zlal zlrp kbtk lven"
    assert not _is_placeholder(leaked)
    assert OPAQUE_SECRET_RE.match(_compact(leaked))

    # And the template that replaced it is recognised as a placeholder, which
    # is what keeps this check from firing on the sanitised file.
    assert _is_placeholder('"your-16-char-app-password"')


def test_the_guard_recognises_the_key_that_actually_leaked() -> None:
    leaked = "e8e6f8c10542b950766a39505a822588fbae0d2c79fd9ba9a524ab4a43732d5e"
    assert HEX_SECRET_RE.search(leaked)
    assert not HEX_SECRET_RE.search("replace-with-openssl-rand-hex-32")


@pytest.mark.parametrize("name", TEMPLATE_FILES)
def test_secret_assignments_are_placeholders_or_empty(name: str) -> None:
    """Every password/secret assignment must be blank or obviously fake."""
    path = ROOT / name
    if not path.exists():  # pragma: no cover - optional file
        pytest.skip(f"{name} not present")

    offenders = [
        value
        for value in ASSIGNMENT_RE.findall(path.read_text(encoding="utf-8"))
        if not _is_placeholder(value)
    ]
    assert not offenders, f"{name} assigns a real-looking secret: {offenders}"


def test_the_smtp_password_is_not_set_in_the_committed_config() -> None:
    """It belongs in .env, which is gitignored; config.yaml is published."""
    from lpr.config import Settings

    # Read the YAML the way the app does, so this follows the real precedence.
    assert Settings().smtp.password == ""


def test_the_shipped_api_secret_is_still_the_refuse_to_start_sentinel() -> None:
    """`change-me` is what makes LPR_ENV=production refuse to boot unconfigured.

    Replacing it with a real key in config.yaml would both publish the key and
    disarm that guard, so the sentinel staying put is worth asserting.
    """
    from lpr.config import Settings

    assert Settings().api.secret_key == "change-me"


# ---------------------------------------------------------------------------
# .gitignore
# ---------------------------------------------------------------------------


def _ignored(path: str) -> bool:
    result = subprocess.run(
        ["git", "check-ignore", "-q", path],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


@pytest.mark.parametrize(
    "name",
    [".env", ".env.local", ".env.production", ".env.save", ".env.backup"],
)
def test_every_env_variant_is_ignored(name: str) -> None:
    """`.env` alone is not enough: .env.production carries the same credentials.

    An editor's `.env.save` is the one that gets committed by accident.
    """
    assert _ignored(name), f"{name} is not gitignored"


def test_the_example_template_is_still_committable() -> None:
    """The wildcard must not swallow the one file that is meant to be tracked."""
    assert not _ignored(".env.example")


def test_the_negation_follows_the_wildcard() -> None:
    """Git applies the last matching rule; reversing these silently breaks it."""
    lines = [line.strip() for line in (ROOT / ".gitignore").read_text().splitlines()]
    assert ".env.*" in lines and "!.env.example" in lines
    assert lines.index(".env.*") < lines.index("!.env.example")
