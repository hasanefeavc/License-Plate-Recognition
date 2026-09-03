"""The install has to succeed on a machine nobody has prepared.

Three fixes live in files no other test looks at -- ``requirements.txt`` and
the two launchers -- and each of them exists because a clean Windows 11 box
refused to reach the point where any other test could have caught it. A pin
silently relaxed, or the PyTorch step reordered to after
``pip install -r requirements.txt``, would restore the original failure and
nothing would notice until somebody sat in front of a fresh machine again.

None of this runs an installer. What is asserted is the intent recorded in
the files: which versions the resolver is allowed to pick, and what the
launcher does in which order.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements.txt"
RUN_BAT = ROOT / "run.bat"
RUN_SH = ROOT / "run.sh"

#: PyTorch's own wheel index. The wheels here bundle the Intel OpenMP runtime
#: that the PyPI win_amd64 wheel links against and does not ship.
TORCH_CPU_INDEX = "https://download.pytorch.org/whl/cpu"


def _requirements() -> dict[str, Requirement]:
    """Parse requirements.txt into name -> Requirement, comments dropped."""
    parsed: dict[str, Requirement] = {}
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        parsed[requirement.name.lower()] = requirement
    return parsed


# ---------------------------------------------------------------------------
# stringzilla: the C++ compiler blocker
# ---------------------------------------------------------------------------


def test_stringzilla_is_pinned_at_all() -> None:
    """It is nothing here imports, which is exactly why it needs a line.

    paddleocr -> albumentations -> albucore -> stringzilla, and albucore's own
    floor is an open ">=3.10.4". Left transitive, pip takes whatever is newest
    and the pin has nowhere to live.
    """
    assert "stringzilla" in _requirements()


def test_the_stringzilla_pin_excludes_the_release_with_no_cp311_windows_wheel() -> None:
    """5.1.2 is the version that stopped a clean install dead.

    Every stringzilla from 4.6.x to 5.1.1 publishes cp310 through cp314
    win_amd64 wheels; 5.1.2 skipped cp311. pip on a Windows 11 machine running
    Python 3.11 -- inside the supported range -- therefore falls back to the
    sdist and tries to compile C++, which fails without the MSVC Build Tools.
    """
    specifier = _requirements()["stringzilla"].specifier
    assert not specifier.contains(Version("5.1.2"), prereleases=True)


def test_the_stringzilla_pin_still_admits_a_usable_release() -> None:
    """A cap that excluded everything would fail the install a different way."""
    specifier = _requirements()["stringzilla"].specifier
    allowed = [v for v in ("3.10.4", "4.6.3", "5.0.7") if specifier.contains(Version(v))]
    assert allowed, "the pin admits no release albucore's own floor would accept"


def test_the_stringzilla_pin_has_a_lower_bound() -> None:
    """albucore needs >=3.10.4; an upper bound alone would let pip go under it."""
    specifier = _requirements()["stringzilla"].specifier
    assert not specifier.contains(Version("3.0.0"))


# ---------------------------------------------------------------------------
# run.bat: PyTorch's Windows DLL problem
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def run_bat() -> str:
    return RUN_BAT.read_text(encoding="utf-8")


#: `set "NAME=value"`, the only form run.bat uses to declare one.
_SET = re.compile(r'^set\s+"([A-Za-z_][A-Za-z0-9_]*)=(.*)"$')


def _command_lines(script: str) -> list[str]:
    """The executable lines of a .bat, `rem` comments and blanks removed.

    ``%NAME%`` references are expanded against the ``set`` lines above them,
    because that is what these assertions are actually about: what pip is
    handed, not which of the two spellings the file happened to use. Without
    it, moving a literal into a variable -- which is the readable thing to do
    with a URL used twice -- silently empties the tests that check for it.
    """
    variables: dict[str, str] = {}
    lines = []
    for raw in script.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.lower().startswith("rem "):
            continue
        for name, value in variables.items():
            stripped = stripped.replace(f"%{name}%", value)
        assignment = _SET.match(stripped)
        if assignment is not None:
            variables[assignment.group(1)] = assignment.group(2)
        lines.append(stripped)
    return lines


def test_windows_installs_torch_from_the_pytorch_cpu_index(run_bat: str) -> None:
    """The PyPI win_amd64 wheel is not self-contained.

    It links libiomp5md.dll and the rest of the Intel OpenMP runtime without
    shipping them, so the first `import torch` on a machine that has never had
    a redistributable installed dies with "[WinError 127] ... shm.dll" -- a
    loader error naming a file that is present. The wheels on
    download.pytorch.org bundle the runtime.
    """
    lines = _command_lines(run_bat)
    assert any(TORCH_CPU_INDEX in line for line in lines)
    installs = [
        line
        for line in lines
        if "pip install" in line and "torch" in line and "-r requirements.txt" not in line
    ]
    assert installs, "run.bat no longer installs torch explicitly"
    for line in installs:
        assert "torchvision" in line, f"torchvision left behind by: {line}"


def test_the_torch_install_precedes_the_requirements_install(run_bat: str) -> None:
    """Order is the whole fix, and it is invisible once it is right.

    torch is pinned in requirements.txt too. Installed from the CPU index
    first, that requirement is already satisfied and pip moves on; the other
    way round, a quarter of a gigabyte comes down from PyPI and the CPU index
    step then finds nothing to do -- an install that looks identical in the log
    and still cannot load the DLL.
    """
    lines = _command_lines(run_bat)
    first_torch = next(
        i for i, line in enumerate(lines) if TORCH_CPU_INDEX in line and "pip install" in line
    )
    requirements = next(i for i, line in enumerate(lines) if "-r requirements.txt" in line)
    assert first_torch < requirements


def test_a_broken_torch_is_reinstalled_rather_than_left_in_place(run_bat: str) -> None:
    """The step above is a no-op on an environment that predates this launcher.

    pip sees the requirement satisfied by the PyPI wheel already installed and
    does nothing, so the install completes and the service fails hours later at
    the first frame. Proving the import and forcing a reinstall when it fails
    is what makes the fix reach machines that were set up before it existed.
    """
    lines = _command_lines(run_bat)
    assert any('-c "import torch' in line for line in lines), "no import check after the install"
    forced = [line for line in lines if "--force-reinstall" in line]
    assert len(forced) == 1, "expected exactly one recovery reinstall"
    assert TORCH_CPU_INDEX in forced[0]


def test_every_goto_in_run_bat_has_a_label(run_bat: str) -> None:
    """cmd reports a missing label at runtime, in Turkish, to an operator.

    The torch fix added two labels and four jumps to a file that is never
    executed in CI, so the cheapest possible check is worth having: a typo here
    surfaces as a launcher that exits mid-install with no message at all.
    """
    labels = set(re.findall(r"(?m)^:([a-z_]+)\b", run_bat))
    targets = set(re.findall(r"(?m)\bgoto\s+:?([a-z_]+)\b", run_bat))
    assert targets - {"eof"} <= labels


def test_run_bat_stays_ascii() -> None:
    """Its own literals are read in the console's code page, not UTF-8.

    cmd.exe reads a .bat in the active code page -- 857 on a Turkish Windows,
    437 on an English one -- so a UTF-8 source byte prints as mojibake. `chcp
    65001` at the top fixes the child process's output, which is what matters,
    but this file's own messages have to be legible whatever the console was
    set to. The new PyTorch messages have to follow the same rule.
    """
    raw = RUN_BAT.read_bytes()
    offenders = [(i, raw[i]) for i in range(len(raw)) if raw[i] > 0x7F]
    assert not offenders, f"non-ASCII bytes in run.bat at {offenders[:5]}"


# ---------------------------------------------------------------------------
# run.sh: unaffected
# ---------------------------------------------------------------------------


def test_linux_does_not_go_near_the_pytorch_index() -> None:
    """The DLL problem is Windows-only and the fix must not follow us over.

    On Linux the PyPI wheel is self-contained, and it is the one that carries
    CUDA support -- pointing this at the CPU index would quietly downgrade
    every GPU host to CPU inference.
    """
    assert "download.pytorch.org" not in RUN_SH.read_text(encoding="utf-8")


def test_linux_still_installs_from_requirements() -> None:
    """A guard on the test above: it would also pass on an empty file."""
    assert "-r requirements.txt" in RUN_SH.read_text(encoding="utf-8")
