"""Guards against committing a credential.

This file exists because it already happened: a real API/licence signing key
and a live Gmail app password were committed in ``.env.example`` and a mail
password in ``config.yaml``. Both files are meant to be templates, both are
tracked, and both were pushed. The fix for the leak itself is *rotation* --
history keeps what it was given -- but the fix for the next one is a test.

It happened a second time, and worse. The RSA key that signs every deployment
licence was committed as ``keys/private_key.pem`` and pushed to a public
repository -- while ``scripts/generate_keys.py`` carried a comment claiming the
directory was gitignored. It was not: ``.gitignore`` had no ``keys/`` rule at
all. A comment documented a protection nobody had written, and the first
version of this file only ever looked inside three template files, so neither
the comment nor the test noticed.

Hence the two halves below. The template scan is unchanged. The tree scan is
new: it walks *every tracked file* looking for key material by shape, checks
that the ignore rules which should have caught it exist, and asserts that git
history itself is clean -- because rotation fixes a leak, and only a test stops
the next one.

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

#: PEM headers that mean private key material, whatever the file is called.
#:
#: ``BEGIN PUBLIC KEY`` is deliberately absent: a public key is meant to be
#: distributable, and ``tests/test_license.py`` writes one into a tmp_path
#: fixture. The private forms below have no legitimate reason to appear in a
#: tracked file -- not in a test, not in a doc, not as an example.
PRIVATE_KEY_MARKERS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN ENCRYPTED PRIVATE KEY",
)

#: Vendor-issued credentials, matched on their published prefixes. Each of
#: these is self-identifying by design -- that is what makes the shape usable
#: as a test rather than a guess.
API_TOKEN_RES = (
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OpenAI key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("private key in a URL", re.compile(r"://[^/\s:@]+:[^/\s:@]{6,}@")),
)

#: Extensions that are key material by convention. A tracked file with one of
#: these names is a finding regardless of what is inside it.
KEY_MATERIAL_SUFFIXES = (".pem", ".key", ".pfx", ".p12", ".jks", ".keystore")

#: Model weights and databases. These are not secrets, but they are the other
#: thing that must never be committed: ~98 MB of EasyOCR ``.pth`` weights got
#: in through a ``models/*.pt`` rule that did not reach ``models/easyocr/``.
BINARY_SUFFIXES = (".pt", ".pth", ".onnx", ".engine", ".tflite", ".db", ".bin", ".safetensors")

#: Ignore rules this repository must carry. Each one is a leak that has either
#: already happened here or is one directory rename away from happening.
REQUIRED_IGNORE_RULES = (
    "keys/",
    "*.pem",
    "*.key",
    "data/",
    "models/",
    "*.pt",
    "*.pth",
    "*.onnx",
    "*.db",
)


def _tracked_files() -> list[str]:
    """Every path git is tracking, from git itself rather than a directory walk."""
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=False
    )
    if result.returncode != 0:  # pragma: no cover - not a git checkout
        pytest.skip("not a git checkout")
    return [name for name in result.stdout.decode().split("\0") if name]


#: The scanner cannot scan itself. This file necessarily contains every marker
#: and prefix it looks for, so a scan that included it would always fail. The
#: exemption is one named path rather than a pattern, so nothing else can drift
#: into it -- and the positive-control tests below assert that the patterns
#: still match, which is what an exempted file would otherwise stop proving.
SCANNER_SELF = "tests/test_secrets.py"

#: Files that legitimately contain credential-shaped URLs, because testing
#: credential *handling* requires a credential to hand.
#:
#: The exemption is deliberately narrow in two ways. It covers only the
#: "private key in a URL" pattern -- a heuristic, matching any
#: ``user:pass@host`` -- and not the vendor-prefix patterns, which are
#: self-identifying and have no legitimate reason to appear anywhere. And it
#: names individual files rather than a ``tests/`` glob, so a real key pasted
#: into a new test is still caught.
URL_CREDENTIAL_EXEMPT = frozenset(
    {
        "src/lpr/masking.py",  # documents the shape it redacts
        "docs/DEPLOYMENT.md",  # shows an installer what an RTSP URL looks like
        "tests/test_camera.py",  # RTSP masking
        "tests/test_relay.py",  # IP-relay URL masking
    }
)


def _read_text(name: str) -> str:
    """Tracked file as text, or "" when it is binary or unreadable."""
    try:
        return (ROOT / name).read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return ""


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


# ---------------------------------------------------------------------------
# Tree scan: the whole repository, not three template files
# ---------------------------------------------------------------------------


def test_no_tracked_file_carries_private_key_material() -> None:
    """The check that would have caught `keys/private_key.pem`.

    Shape, not filename: renaming the key to `vendor.txt` still trips this,
    which is the point -- the previous leak got in precisely because the
    protection keyed on a path.
    """
    offenders: list[str] = []
    for name in _tracked_files():
        if name == SCANNER_SELF:
            continue
        if any(marker in _read_text(name) for marker in PRIVATE_KEY_MARKERS):
            offenders.append(name)
    assert not offenders, (
        "private key material in tracked files: "
        + ", ".join(offenders)
        + " -- rotate the key, then purge it from history"
    )


def test_no_tracked_file_is_named_like_key_material() -> None:
    """`*.pem` and friends have no business being tracked, whatever they hold."""
    offenders = [
        name
        for name in _tracked_files()
        if Path(name).suffix.lower() in KEY_MATERIAL_SUFFIXES
    ]
    assert not offenders, f"key-material files are tracked: {offenders}"


def test_no_tracked_file_carries_a_vendor_api_token() -> None:
    """AWS, GitHub, Slack, Stripe and friends, matched on their own prefixes."""
    offenders: list[str] = []
    for name in _tracked_files():
        if name == SCANNER_SELF:
            continue
        text = _read_text(name)
        for label, pattern in API_TOKEN_RES:
            if label == "private key in a URL" and name in URL_CREDENTIAL_EXEMPT:
                continue
            if pattern.search(text):
                offenders.append(f"{name} ({label})")
    assert not offenders, f"credential-shaped strings in tracked files: {offenders}"


def test_the_guard_recognises_the_private_key_that_actually_leaked() -> None:
    """A negative test proves nothing unless the positive case is asserted too.

    The body is synthetic -- the header is what the scan keys on, and pasting
    even a fragment of the real key back in would defeat the purge this test
    exists to protect. If a future refactor breaks the scan, this fails rather
    than the scan silently passing everything.
    """
    shaped_like_the_leak = "-----BEGIN PRIVATE KEY-----\nAAAA...redacted...AAAA\n"
    assert any(marker in shaped_like_the_leak for marker in PRIVATE_KEY_MARKERS)


def test_the_guard_recognises_a_credential_bearing_rtsp_url() -> None:
    """Camera passwords arrive embedded in stream URLs, not in assignments."""
    url = "rtsp://admin:Sup3rSecret@10.0.0.5:554/Streaming/Channels/101"
    label, pattern = next(p for p in API_TOKEN_RES if p[0] == "private key in a URL")
    assert pattern.search(url), label


# ---------------------------------------------------------------------------
# Large binaries: the other thing that must never be committed
# ---------------------------------------------------------------------------


def test_no_model_weights_or_databases_are_tracked() -> None:
    """98 MB of EasyOCR weights reached git through a rule that stopped one
    directory short. `models/` is now ignored wholesale; this asserts it."""
    offenders = [
        name
        for name in _tracked_files()
        if Path(name).suffix.lower() in BINARY_SUFFIXES
    ]
    assert not offenders, f"binary artefacts are tracked: {offenders}"


def test_no_tracked_file_is_larger_than_a_megabyte() -> None:
    """A blanket size ceiling, so the next big binary needs no new rule.

    Everything this repository legitimately tracks is source, config or prose.
    A megabyte is generous for all three and far below the point where git
    starts to hurt.
    """
    oversized = []
    for name in _tracked_files():
        path = ROOT / name
        try:
            size = path.stat().st_size
        except OSError:  # pragma: no cover - path removed mid-run
            continue
        if size > 1_048_576:
            oversized.append(f"{name} ({size // 1024} KiB)")
    assert not oversized, f"oversized tracked files: {oversized}"


# ---------------------------------------------------------------------------
# The ignore rules that should have existed
# ---------------------------------------------------------------------------


def _ignore_lines() -> list[str]:
    return [line.strip() for line in (ROOT / ".gitignore").read_text().splitlines()]


@pytest.mark.parametrize("rule", REQUIRED_IGNORE_RULES)
def test_the_required_ignore_rule_is_present(rule: str) -> None:
    """Asserting the rule text, not just its effect.

    `git check-ignore` reports "not ignored" for a file that is already
    tracked, so an effect-only test would pass on exactly the broken state
    this repository was in -- key committed, rule missing.
    """
    assert rule in _ignore_lines(), f"missing .gitignore rule: {rule}"


def _ignored_by_rule(path: str) -> bool:
    """Whether the ignore rules would catch `path`, tracked or not."""
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "-q", path],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


@pytest.mark.parametrize(
    "path",
    [
        "keys/private_key.pem",
        "keys/public_key.pem",
        "secrets/vendor.pem",
        "data/plates.db",
        "data/public_key.pem",
        "models/plate_yolov8n.pt",
        "models/easyocr/craft_mlt_25k.pth",
        "models/easyocr/english_g2.pth",
        "runs/train/weights/best.pt",
    ],
)
def test_key_material_and_weights_are_ignored(path: str) -> None:
    """`--no-index`, so this measures the rules rather than the index."""
    assert _ignored_by_rule(path), f"{path} would not be ignored"


def test_the_public_key_ships_by_installer_not_by_git() -> None:
    """Ignoring the public half too is a deliberate choice, worth pinning.

    Committing it would pin every customer to one key pair for the life of the
    repository: rotating the signing key would then require every site to pull
    a new commit. `lpr.license.public_key_candidates` looks in the data volume
    first precisely so the installer can place it per-site.
    """
    assert _ignored_by_rule("keys/public_key.pem")
    assert _ignored_by_rule("data/public_key.pem")


# ---------------------------------------------------------------------------
# History: rotation fixes the leak, this stops it coming back
# ---------------------------------------------------------------------------


def test_git_history_holds_no_key_material() -> None:
    """Every path in every commit, not just the current tree.

    Removing a file in a later commit does not remove it from the repository;
    a clone still carries the blob. This is the assertion that the history
    purge actually ran.
    """
    result = subprocess.run(
        ["git", "log", "--all", "--pretty=format:", "--name-only", "--diff-filter=A"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:  # pragma: no cover - not a git checkout
        pytest.skip("not a git checkout")

    seen = {line.strip() for line in result.stdout.decode().splitlines() if line.strip()}
    offenders = sorted(
        name
        for name in seen
        if Path(name).suffix.lower() in KEY_MATERIAL_SUFFIXES + BINARY_SUFFIXES
    )
    assert not offenders, (
        "key material or binaries remain in git history: "
        + ", ".join(offenders)
        + " -- rewrite history with git filter-repo"
    )


def test_the_url_exemption_does_not_cover_vendor_tokens() -> None:
    """The narrow half of the exemption, asserted rather than assumed.

    A file that is allowed to contain `user:pass@host` is not allowed to
    contain an AWS key. Those prefixes are self-identifying and have no
    legitimate reason to appear in a test fixture.
    """
    for name in URL_CREDENTIAL_EXEMPT:
        text = _read_text(name)
        for label, pattern in API_TOKEN_RES:
            if label == "private key in a URL":
                continue
            assert not pattern.search(text), f"{name} carries a {label}"


def test_the_exemption_names_files_rather_than_a_directory() -> None:
    """A `tests/` glob would let a real key into any new file under it.

    The rule is "one named file at a time", not "only Python": the deployment
    guide legitimately shows an installer what an RTSP URL looks like. What
    must not appear here is a pattern, a bare directory, or enough entries that
    the scan stops meaning anything -- hence the ceiling.
    """
    for name in URL_CREDENTIAL_EXEMPT:
        assert "*" not in name and "?" not in name, f"{name} is a pattern"
        assert not name.endswith("/"), f"{name} is a directory"
        assert (ROOT / name).is_file(), f"{name} does not exist; stale exemption"

    assert len(URL_CREDENTIAL_EXEMPT) <= 6, (
        "the exemption list is growing. Each entry is a file the credential "
        "heuristic no longer covers, so it is a budget rather than a bucket."
    )


def test_exempt_files_are_still_scanned_for_private_keys() -> None:
    """The exemption covers one pattern, not the file."""
    for name in URL_CREDENTIAL_EXEMPT:
        text = _read_text(name)
        assert not any(marker in text for marker in PRIVATE_KEY_MARKERS)
