"""`.env.example` and the settings models must not drift apart.

``Settings`` is declared ``extra="ignore"``: a variable spelled almost right
is discarded in silence, the setting keeps whatever ``config.yaml`` said, and
the file in front of the operator claims otherwise. ``LPR_SMTP__TO_ADDRS`` for
``to_emails`` is the shape this takes in practice, and it costs an afternoon
to find, because nothing anywhere reports it.

So the committed example is treated as documentation that has to compile:
every variable in it configures something, and everything configurable is in
it. Both directions matter -- a stale name misleads, and a missing one means a
setting nobody knows exists.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on invocation
    sys.path.insert(0, str(SRC))

from lpr.config import (  # noqa: E402
    _NON_FIELD_ENV_NAMES,
    Settings,
    _field_env_names,
)

ENV_EXAMPLE = Path(__file__).resolve().parents[1] / ".env.example"

#: ``LPR_FOO=value`` or ``#LPR_FOO=value``, which are the only two forms the
#: file uses. No space is allowed after the ``#``, and that is load-bearing:
#: prose in a comment mentions variable names too ("[\"*\"] is REFUSED when
#: LPR_ENV=production"), and a looser pattern reads those as declarations.
_ASSIGNMENT = re.compile(r"^#?(LPR_[A-Z0-9_]+)=")


def declared_names() -> list[str]:
    """Every ``LPR_`` name assigned in ``.env.example``, in file order.

    Includes commented-out lines on purpose: a commented default is still the
    documentation for that setting, and a typo in one is exactly as misleading
    as a typo in a live line -- more so, because uncommenting it looks safe.
    """
    names: list[str] = []
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        match = _ASSIGNMENT.match(line.strip())
        if match:
            names.append(match.group(1))
    return names


def settings_leaf_names() -> set[str]:
    """Every ``LPR_`` name that maps to an actual (non-section) setting."""
    known = _field_env_names(Settings)
    # A section name like LPR_SMTP is accepted by pydantic-settings as a JSON
    # blob, but nobody configures a site that way, so only the leaves count.
    return {name for name in known if not any(o.startswith(name + "__") for o in known)}


def test_every_documented_variable_configures_something() -> None:
    unknown = sorted(set(declared_names()) - settings_leaf_names() - _NON_FIELD_ENV_NAMES)
    assert not unknown, (
        "these names appear in .env.example but configure nothing -- they would "
        f"be silently ignored at runtime: {unknown}"
    )


def test_every_setting_is_documented() -> None:
    missing = sorted(settings_leaf_names() - set(declared_names()))
    assert not missing, (
        "these settings exist but .env.example does not mention them; add each "
        f"one (commented out, showing its default): {missing}"
    )


def test_no_variable_is_listed_twice() -> None:
    """A duplicate is a merge artefact, and the *last* one silently wins."""
    names = declared_names()
    duplicates = sorted({name for name in names if names.count(name) > 1})
    assert not duplicates, f"listed more than once in .env.example: {duplicates}"


@pytest.mark.parametrize(
    "name",
    ["LPR_SMTP__TIMEOUT_S", "LPR_SMTP__QUEUE_SIZE", "LPR_SNAPSHOTS__MAX_TOTAL_MB",
     "LPR_SNAPSHOTS__MIN_FREE_MB", "LPR_CAMERAS__ENTRY__SOURCE", "LPR_CAMERAS__EXIT__SOURCE"],
)
def test_the_settings_that_went_missing_are_present(name: str) -> None:
    """Regression: the SMTP and snapshot keys the example had fallen behind on.

    Covered by ``test_every_setting_is_documented`` as well, but named here so
    a failure says which deployment problem came back rather than printing a
    list of a hundred variables.
    """
    assert name in declared_names()


def test_the_example_carries_no_real_secret() -> None:
    """It is committed, so every credential in it must be a placeholder."""
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("LPR_API__SECRET_KEY=") or line.startswith("LPR_LICENSE_SECRET="):
            value = line.split("=", 1)[1].strip().strip('"')
            assert value.startswith("replace-with"), f"{line} looks like a real value"
