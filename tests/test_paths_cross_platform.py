"""Path handling that has to mean the same thing on Linux and on Windows.

This project is written and tested on Linux and installed on Windows, so the
interesting path bugs are the ones that cannot fail on the machine that runs
the suite. Three of them have a home here:

* a snapshot filename containing a character Windows refuses to put on disk --
  the write fails at a site and never in CI;
* a directory typed into ``config.yaml`` with the other separator, which on
  Windows names the same folder and on Linux does not;
* a containment check written as a string comparison, which quietly accepts a
  sibling directory whose name merely starts with the right prefix.

Nothing here branches on the running platform, and nothing asserts on
``os.sep`` -- that would only restate what this machine already does, which is
the bug rather than the check. Where a genuinely Windows-shaped path has to be
exercised, ``PureWindowsPath`` supplies Windows parsing rules on any host, so
the assertion made here is the one a Windows box would make.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on invocation
    sys.path.insert(0, str(SRC))

from lpr.config import AppConfig, Settings, SnapshotsConfig  # noqa: E402
from lpr.pipeline.snapshots import snapshot_filename  # noqa: E402

#: Characters Windows will not accept in a file name at all. Legal on ext4,
#: which is why a name carrying one of them is written happily here and refused
#: at the site the evidence was meant for.
_WINDOWS_FORBIDDEN = '<>:"/\\|?*'


# ---------------------------------------------------------------------------
# Snapshot file names
# ---------------------------------------------------------------------------


def test_a_snapshot_filename_is_legal_on_a_windows_filesystem() -> None:
    """The ``:`` is the one that matters, and the one a rewrite would add.

    ``YYYYMMDD_HHMMSS`` is deliberately not an ISO-8601 timestamp: the obvious
    "tidy this up" edit is to format the instant as ``2026-08-27T09:14:02``,
    which Linux stores without complaint and Windows rejects outright -- the
    colon opens an NTFS alternate data stream. Every snapshot write would then
    fail at the site, and every one would succeed in CI.
    """
    name = snapshot_filename("34ABC123", datetime(2026, 8, 27, 9, 14, 2, tzinfo=UTC))
    assert not any(char in name for char in _WINDOWS_FORBIDDEN), name


def test_a_plate_full_of_separators_still_names_one_file() -> None:
    """OCR output reaches this function; a stray ``/`` or ``\\`` in it must not
    become a directory level, on either platform's rules."""
    name = snapshot_filename('34/AB\\C:1*"2?3', datetime(2026, 8, 27, 9, 14, 2, tzinfo=UTC))
    assert not any(char in name for char in _WINDOWS_FORBIDDEN), name
    assert PureWindowsPath(name).parts == (name,), "a snapshot name is one path component"
    assert PurePosixPath(name).parts == (name,)


# ---------------------------------------------------------------------------
# Configured directories
# ---------------------------------------------------------------------------


def _settings(tmp_path: Path, **snapshots: Any) -> Settings:
    """Settings whose two path fields are the only thing under test.

    Both are passed explicitly, which is what keeps this off the developer's
    own ``config.yaml`` -- constructor arguments outrank the YAML source, so
    the values asserted on below are the values written here.
    """
    return Settings(
        app=AppConfig(data_dir=str(tmp_path / "data"), models_dir=str(tmp_path / "models")),
        snapshots=SnapshotsConfig(**snapshots),
    )


def test_a_snapshot_directory_typed_with_forward_slashes_resolves_the_same(
    tmp_path: Path,
) -> None:
    """A ``config.yaml`` carried between the two platforms keeps working.

    Forward slashes are the spelling that survives both -- Windows accepts them
    everywhere a backslash goes -- so an operator who writes ``D:/lpr/shots``
    must land in the same directory as one who writes it with backslashes.
    """
    target = tmp_path / "store" / "shots"
    native = _settings(tmp_path, dir=str(target)).paths.snapshots_dir
    posix = _settings(tmp_path, dir=target.as_posix()).paths.snapshots_dir
    assert native == posix


def test_a_data_directory_typed_with_forward_slashes_resolves_the_same(
    tmp_path: Path,
) -> None:
    """The same for ``app.data_dir``, which the database and the snapshot
    directory are both derived from -- getting this one wrong moves the gate
    log as well as the evidence."""
    target = tmp_path / "store" / "data"
    native = Settings(app=AppConfig(data_dir=str(target))).paths.data_dir
    posix = Settings(app=AppConfig(data_dir=target.as_posix())).paths.data_dir
    assert native == posix


def test_a_trailing_separator_and_a_dot_segment_change_nothing(tmp_path: Path) -> None:
    """Hand-edited config files pick these up; they are the same directory."""
    target = tmp_path / "store" / "shots"
    plain = _settings(tmp_path, dir=target.as_posix()).paths.snapshots_dir
    trailing = _settings(tmp_path, dir=f"{target.as_posix()}/").paths.snapshots_dir
    dotted = _settings(tmp_path, dir=f"{target.as_posix()}/./").paths.snapshots_dir
    assert plain == trailing == dotted


def test_a_mixed_separator_directory_is_one_directory_on_windows() -> None:
    """The case that cannot be built through the config layer on Linux.

    A backslash is an ordinary filename character on ext4, so feeding
    ``D:/lpr/data\\snapshots`` to ``Settings`` here would create a folder
    literally called ``data\\snapshots`` and prove nothing about Windows. The
    parsing rule itself is what matters, and ``PureWindowsPath`` applies it on
    any host: both spellings name one directory, so a config file that mixes
    them is not two configurations.
    """
    assert PureWindowsPath("D:/lpr/data\\snapshots") == PureWindowsPath("D:\\lpr\\data\\snapshots")


def test_the_default_snapshot_directory_stays_inside_the_data_directory(
    tmp_path: Path,
) -> None:
    """Asserted as containment rather than as a string, because containment is
    the property retention and the snapshot route both depend on."""
    settings = _settings(tmp_path)
    assert settings.paths.snapshots_dir.is_relative_to(settings.paths.data_dir)


def test_an_explicit_snapshot_directory_may_leave_the_data_directory(
    tmp_path: Path,
) -> None:
    """Documented behaviour, not an oversight: images grow far faster than the
    database and a site is expected to be able to put them on another disk."""
    elsewhere = tmp_path / "other-volume" / "shots"
    settings = _settings(tmp_path, dir=str(elsewhere))
    assert settings.paths.snapshots_dir == elsewhere.resolve()
    assert not settings.paths.snapshots_dir.is_relative_to(settings.paths.data_dir)


# ---------------------------------------------------------------------------
# The containment rule the snapshot route relies on
#
# ``GET /api/logs/{id}/snapshot`` re-resolves the stored path and refuses
# anything outside the snapshot directory with ``candidate.relative_to(root)``.
# These pin the rule that makes that correct; the route is exercised against a
# real filesystem in ``tests/test_api.py``.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pure", [PurePosixPath, PureWindowsPath])
def test_a_sibling_sharing_a_name_prefix_is_not_inside_the_root(pure: Any) -> None:
    """Why the check is ``relative_to`` and not ``startswith``.

    ``.../snapshots-old`` starts with ``.../snapshots`` as text and is not
    inside it as a path. A string comparison serves files out of it; a path
    comparison refuses. The prefix assertion below is deliberate -- it records
    that the cheaper-looking check really would have let this through.
    """
    root = pure("/srv/lpr/data/snapshots")
    sibling = pure("/srv/lpr/data/snapshots-old/evidence.jpg")
    assert str(sibling).startswith(str(root)), "the string comparison would have allowed it"
    assert not sibling.is_relative_to(root)


@pytest.mark.parametrize("pure", [PurePosixPath, PureWindowsPath])
def test_a_traversal_segment_is_only_caught_after_the_path_is_resolved(pure: Any) -> None:
    """Why the route resolves *before* it compares, on both platforms' rules.

    ``pathlib`` does not fold ``..`` away on its own -- it cannot, because a
    symlink makes the answer depend on the filesystem -- so a pure comparison
    reports the escaping path as inside the root. Dropping the ``resolve()``
    from the route would leave exactly this hole, and it looks harmless.

    The refusal itself is exercised against a real filesystem by
    ``test_traversal_out_of_the_snapshot_directory_is_refused`` in
    ``tests/test_api.py``.
    """
    root = pure("/srv/lpr/data/snapshots")
    escaping = pure("/srv/lpr/data/snapshots/../secrets.txt")
    assert escaping.is_relative_to(root), "unresolved, the traversal looks contained"


def test_a_stored_path_written_with_either_separator_is_inside_the_root() -> None:
    """The round trip a Windows install performs on every snapshot request.

    ``logs.snapshot_path`` holds whatever ``str(Path)`` produced when the file
    was written, and the route rebuilds a ``Path`` from it before comparing.
    Under Windows rules both spellings resolve to the same place, so the
    containment check must accept either -- which it does only because it
    compares paths and not text.
    """
    root = PureWindowsPath(r"C:\lpr\data\snapshots")
    for stored in (
        r"C:\lpr\data\snapshots\20260827_091402_34ABC123.jpg",
        "C:/lpr/data/snapshots/20260827_091402_34ABC123.jpg",
    ):
        assert PureWindowsPath(stored).is_relative_to(root), stored
