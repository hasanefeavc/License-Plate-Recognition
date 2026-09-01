"""`lpr init` -- the one command between `git clone` and a service that starts.

The thing worth testing hardest is not that it provisions, but that running it
a second time destroys nothing. It is the command somebody re-runs when they
are not sure whether they ran it, and the files it touches -- a signing key, a
licence, a ``.env`` full of real secrets -- are the three worst things in the
repository to overwrite.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on invocation
    sys.path.insert(0, str(SRC))

from lpr.license import LICENSE_FILE_NAME, PUBLIC_KEY_NAME, validate_token  # noqa: E402
from lpr.provisioning import (  # noqa: E402
    PRIVATE_KEY_NAME,
    ensure_dev_license,
    ensure_directories,
    ensure_env_file,
    ensure_keypair,
    initialise,
)


@pytest.fixture()
def key_dir(tmp_path: Path) -> Path:
    return tmp_path / "keys"


# ---------------------------------------------------------------------------
# Individual steps
# ---------------------------------------------------------------------------


def test_directories_are_created(tmp_settings: Any, key_dir: Path) -> None:
    steps = ensure_directories(tmp_settings, key_dir=key_dir)
    assert all(step.path is not None and step.path.is_dir() for step in steps)
    assert key_dir.is_dir()
    assert tmp_settings.paths.snapshots_dir.is_dir()


def test_the_key_pair_is_generated_once(key_dir: Path) -> None:
    first = ensure_keypair(key_dir)
    assert first.changed
    assert (key_dir / PRIVATE_KEY_NAME).is_file()
    assert (key_dir / PUBLIC_KEY_NAME).is_file()

    original = (key_dir / PRIVATE_KEY_NAME).read_bytes()
    second = ensure_keypair(key_dir)
    assert not second.changed, "a re-run must not mint new keys"
    assert (key_dir / PRIVATE_KEY_NAME).read_bytes() == original


def test_the_private_key_is_not_world_readable(key_dir: Path) -> None:
    """Anyone holding it can mint themselves an unlimited licence."""
    ensure_keypair(key_dir)
    mode = (key_dir / PRIVATE_KEY_NAME).stat().st_mode & 0o777
    assert mode == 0o600, f"private key is mode {mode:o}"


def test_a_forced_regeneration_replaces_the_pair(key_dir: Path) -> None:
    ensure_keypair(key_dir)
    original = (key_dir / PRIVATE_KEY_NAME).read_bytes()
    assert ensure_keypair(key_dir, force=True).changed
    assert (key_dir / PRIVATE_KEY_NAME).read_bytes() != original


def test_the_minted_licence_actually_validates(
    tmp_settings: Any, key_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the whole step. A licence that does not verify is worse
    than no licence: the service starts and refuses every login."""
    ensure_keypair(key_dir)
    step = ensure_dev_license(tmp_settings, key_dir=key_dir, days=30)
    assert step.changed

    monkeypatch.setenv("LPR_LICENSE_PUBLIC_KEY", str(key_dir / PUBLIC_KEY_NAME))
    token = (tmp_settings.paths.data_dir / LICENSE_FILE_NAME).read_text().strip()
    status = validate_token(token)
    assert status.valid, status.detail
    assert status.client == "local-development"


def test_an_existing_licence_is_never_overwritten(tmp_settings: Any, key_dir: Path) -> None:
    """It may be a real key somebody installed for testing."""
    ensure_keypair(key_dir)
    installed = tmp_settings.paths.data_dir / LICENSE_FILE_NAME
    installed.write_text("a-real-customer-licence\n", encoding="utf-8")

    step = ensure_dev_license(tmp_settings, key_dir=key_dir)
    assert not step.changed
    assert installed.read_text().strip() == "a-real-customer-licence"


def test_minting_is_skipped_with_no_signing_key(tmp_settings: Any, key_dir: Path) -> None:
    step = ensure_dev_license(tmp_settings, key_dir=key_dir)
    assert not step.changed
    assert "no signing key" in step.detail


def test_the_env_file_is_copied_from_the_example(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("LPR_APP__LOG_LEVEL=INFO\n", encoding="utf-8")
    step = ensure_env_file(tmp_path)
    assert step.changed
    assert (tmp_path / ".env").read_text() == "LPR_APP__LOG_LEVEL=INFO\n"


def test_an_existing_env_file_is_never_clobbered(tmp_path: Path) -> None:
    """The single most expensive thing this module could get wrong: .env is
    where the machine's real secrets live and it is not in git."""
    (tmp_path / ".env.example").write_text("LPR_API__SECRET_KEY=placeholder\n", encoding="utf-8")
    (tmp_path / ".env").write_text("LPR_API__SECRET_KEY=the-real-one\n", encoding="utf-8")

    step = ensure_env_file(tmp_path)
    assert not step.changed
    assert "the-real-one" in (tmp_path / ".env").read_text()


def test_a_missing_example_is_reported_not_raised(tmp_path: Path) -> None:
    step = ensure_env_file(tmp_path)
    assert not step.changed
    assert "no" in step.detail and not (tmp_path / ".env").exists()


# ---------------------------------------------------------------------------
# The whole thing
# ---------------------------------------------------------------------------


def test_initialise_provisions_everything(tmp_settings: Any, tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    (root / ".env.example").write_text("LPR_APP__LOG_LEVEL=INFO\n", encoding="utf-8")
    key_dir = root / "keys"

    steps = initialise(tmp_settings, root=root, key_dir=key_dir)
    names = {step.name for step in steps}
    assert names == {"directory", "keys", "license", "env"}

    assert (key_dir / PRIVATE_KEY_NAME).is_file()
    assert (key_dir / PUBLIC_KEY_NAME).is_file()
    assert (tmp_settings.paths.data_dir / LICENSE_FILE_NAME).is_file()
    assert (root / ".env").is_file()


def test_running_it_twice_changes_nothing(tmp_settings: Any, tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    (root / ".env.example").write_text("LPR_APP__LOG_LEVEL=INFO\n", encoding="utf-8")
    key_dir = root / "keys"

    initialise(tmp_settings, root=root, key_dir=key_dir)
    before = {
        path: path.read_bytes()
        for path in (
            key_dir / PRIVATE_KEY_NAME,
            key_dir / PUBLIC_KEY_NAME,
            tmp_settings.paths.data_dir / LICENSE_FILE_NAME,
            root / ".env",
        )
    }

    second = initialise(tmp_settings, root=root, key_dir=key_dir)
    assert not any(step.changed for step in second), [str(s) for s in second]
    for path, content in before.items():
        assert path.read_bytes() == content, f"{path} was rewritten by a re-run"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_status_exits_non_zero_when_something_is_missing(
    tmp_settings: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """So CI and a provisioning script can both gate on it."""
    from lpr.cli import main

    assert main(["status", "--root", str(tmp_path), "--key-dir", str(tmp_path / "keys")]) == 1
    assert "Missing:" in capsys.readouterr().out


def test_init_then_status_agree(
    tmp_settings: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Whatever `init` provisions, `status` must report as present."""
    from lpr.cli import main

    root = tmp_path / "checkout"
    root.mkdir()
    (root / ".env.example").write_text("LPR_APP__LOG_LEVEL=INFO\n", encoding="utf-8")
    args = ["--root", str(root), "--key-dir", str(root / "keys")]

    assert main(["init", *args]) == 0
    capsys.readouterr()

    main(["status", *args])
    out = capsys.readouterr().out
    for line in out.splitlines():
        for provisioned in ("public key", "private key", "licence", ".env"):
            if provisioned in line:
                assert line.strip().startswith("[ok]"), line
