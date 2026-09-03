"""Tests for the shipped configuration defaults.

These pin the values the project *ships with*, not the values a given site is
running. Every assertion here goes through the config models directly rather
than through ``Settings``, because ``Settings`` reads the deployment's own
``config.yaml`` through its YAML source -- a test that went that route would
pass or fail depending on how the machine running it happens to be configured,
and a site that legitimately retunes a value would fail its own test suite.

The sliding-gate defaults are the interesting ones. A sliding-gate motor
(*yana kayar kapı*) uses step-by-step pulse logic -- pulse 1 opens, pulse 2
stops mid-travel, pulse 3 closes -- and takes 15-25 seconds per cycle, so a
default that is right for an arm barrier is actively harmful here.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from lpr.config import (
    FastPathConfig,
    OcrConfig,
    RelayConfig,
    Settings,
    VotingConfig,
    _default_config_yaml_path,
    _default_env_file_path,
    unknown_env_names,
    warn_about_unknown_env_names,
)

#: The committed ``config.yaml``, addressed as a file rather than through
#: ``_default_config_yaml_path()``. That helper honours ``LPR_CONFIG_FILE``,
#: so a developer with the variable exported would have the one assertion in
#: this module that is *about* the shipped file quietly read a different one.
SHIPPED_CONFIG_YAML = Path(__file__).resolve().parents[1] / "config.yaml"

# ---------------------------------------------------------------------------
# Voting: the re-trigger window
# ---------------------------------------------------------------------------


def test_the_default_cooldown_outlasts_a_sliding_gate_cycle() -> None:
    """The whole point: a second pulse mid-travel *stops* a sliding gate.

    A car waiting at the camera re-confirms on every pass of the pipeline. If
    the cooldown is shorter than the gate's travel time, the same plate fires
    again while the gate is still opening and the driver watches it halt.
    """
    assert VotingConfig().cooldown_s == 20.0
    assert VotingConfig().cooldown_s >= 15.0, "must cover a full slow open cycle"


def test_the_default_cooldown_is_not_so_long_it_strands_a_second_visit() -> None:
    """Too long only delays a genuine re-entry, but it should still be bounded."""
    assert VotingConfig().cooldown_s <= 60.0


def test_the_cooldown_outlasts_the_vote_window() -> None:
    """Otherwise a plate could re-confirm before its own cooldown lapses.

    ``ttl_s`` bounds how long votes accumulate; if the cooldown were shorter
    than that, a car sitting in frame could assemble a fresh confirmation
    inside the window that is supposed to be suppressing it.
    """
    config = VotingConfig()
    assert config.cooldown_s > config.ttl_s


def test_a_site_can_still_retune_the_cooldown_for_an_arm_barrier() -> None:
    """An idempotent barrier with a ~2 s cycle has no need of 20 s."""
    assert VotingConfig(cooldown_s=3.0).cooldown_s == 3.0


# ---------------------------------------------------------------------------
# Relay: the dry-contact pulse
# ---------------------------------------------------------------------------


def test_the_default_pulse_is_a_one_second_dry_contact() -> None:
    assert RelayConfig().pulse_ms == 1000


def test_the_pulse_clears_debounce_without_reading_as_a_held_button() -> None:
    """Both bounds are real failure modes on a step-by-step controller.

    Too short and the controller's debounce filter swallows the pulse; too long
    and some units read it as a held button, which is a different input mode
    entirely.
    """
    pulse = RelayConfig().pulse_ms
    assert 200 <= pulse <= 2000


def test_the_pulse_is_shorter_than_the_cooldown() -> None:
    """A pulse still closed when the next one is allowed would overlap."""
    assert RelayConfig().pulse_ms / 1000.0 < VotingConfig().cooldown_s


@pytest.mark.parametrize("pulse_ms", [500, 1000, 1500])
def test_a_site_can_retune_the_pulse_for_its_controller(pulse_ms: int) -> None:
    assert RelayConfig(pulse_ms=pulse_ms).pulse_ms == pulse_ms


# ---------------------------------------------------------------------------
# Voting: consensus and the single-frame early exit
# ---------------------------------------------------------------------------


def test_two_agreeing_reads_are_enough() -> None:
    """Lowered from three. See VotingConfig for why the third vote bought little."""
    assert VotingConfig().min_votes == 2


def test_min_votes_still_fits_inside_the_window() -> None:
    """A threshold above the window can never be met; the voter would clamp it."""
    config = VotingConfig()
    assert 1 < config.min_votes <= config.window


def test_the_fast_path_ships_armed() -> None:
    assert VotingConfig().fast_path_enabled is True
    assert VotingConfig().fast_path_confidence == 0.82


def test_the_fast_path_threshold_is_above_the_ocr_floor() -> None:
    """The orchestrator floors one at the other; shipping them inverted would
    mean the shipped configuration relies on that floor to stay honest."""
    assert VotingConfig().fast_path_confidence > OcrConfig().min_confidence


def test_the_fast_path_does_not_open_the_gate_by_default() -> None:
    """The one default here that can move a barrier on uncorroborated evidence.

    Measured on 47 hand-labelled frames from a live site, correct reads score
    0.905-0.999 and the two wrong ones score 0.949 and 0.955: the distributions
    overlap, so no confidence threshold separates a confident read from a
    correct one. The multi-frame vote costs about 130 ms in front of a barrier
    that takes seconds to open, which is the whole price of keeping it.

    The behaviour is covered at the orchestrator in ``test_pipeline.py``; this
    covers the *default*, which is the half a refactor can flip without any of
    those tests noticing -- they build their settings from this model.
    """
    assert VotingConfig().fast_path_opens_gate is False


def test_the_shipped_config_yaml_leaves_the_gate_bypass_off() -> None:
    """The committed file, read as a file, and the one exception in this module.

    Everything else here goes through the models, because ``Settings`` would
    read whatever ``config.yaml`` the machine happens to have. This assertion
    is *about* the committed ``config.yaml``, which is the same on every
    checkout -- and it is needed because the YAML outranks the model default:
    shipping ``true`` here would arm the single-frame bypass on every fresh
    install while the default above still read ``False``.

    A site that has measured its own risk and wants the bypass edits this line
    and sees this test say so, which is the right amount of friction for the
    one setting that can move a barrier on a single unvetted frame.
    """
    import yaml

    shipped = yaml.safe_load(SHIPPED_CONFIG_YAML.read_text(encoding="utf-8"))
    assert shipped["voting"]["fast_path_opens_gate"] is False


# ---------------------------------------------------------------------------
# The fast path moved from its own section onto `voting`
# ---------------------------------------------------------------------------


def _upgraded_in_place(**legacy: object) -> Settings:
    """A ``Settings`` shaped like a deployment that has not migrated its YAML.

    ``voting=VotingConfig()`` is the load-bearing half: passing the section
    explicitly is what keeps this test off the developer's own ``config.yaml``,
    whose ``voting:`` block *has* been migrated and would otherwise (correctly)
    win. An empty ``model_fields_set`` is exactly the "nobody wrote the new
    keys" state the merge exists for.
    """
    return Settings(voting=VotingConfig(), fast_path=FastPathConfig(**legacy))


def test_a_legacy_fast_path_section_still_switches_the_early_exit_off() -> None:
    """An in-place upgrade keeps its old config.yaml, and its old decision.

    Ignoring the section an operator deliberately switched off would re-arm an
    early exit at a live gate on the strength of a rename.
    """
    assert _upgraded_in_place(enabled=False).voting.fast_path_enabled is False


def test_a_legacy_fast_path_section_still_carries_its_threshold() -> None:
    assert _upgraded_in_place(min_confidence=0.97).voting.fast_path_confidence == 0.97


def test_an_untouched_legacy_section_does_not_override_the_defaults() -> None:
    """Only values the operator actually wrote carry over.

    ``fast_path`` exists on every Settings whether or not the YAML mentions it,
    so a merge that copied its *defaults* would pin every site to 0.90 forever
    and quietly undo the new threshold.
    """
    settings = Settings(voting=VotingConfig())
    assert settings.voting.fast_path_confidence == VotingConfig().fast_path_confidence


def test_the_new_keys_beat_the_legacy_section() -> None:
    """Both present means the operator has migrated; the stale one loses."""
    settings = Settings(
        fast_path=FastPathConfig(enabled=True, min_confidence=0.99),
        voting=VotingConfig(fast_path_enabled=False, fast_path_confidence=0.75),
    )
    assert settings.voting.fast_path_enabled is False
    assert settings.voting.fast_path_confidence == 0.75


def test_nothing_is_copied_back_onto_the_legacy_section() -> None:
    """One direction only, so `voting` is the single value the pipeline reads."""
    settings = Settings(voting=VotingConfig(fast_path_confidence=0.7))
    assert settings.voting.fast_path_confidence == 0.7
    assert settings.fast_path.min_confidence == FastPathConfig().min_confidence


# ---------------------------------------------------------------------------
# Where settings come from, and which source wins
# ---------------------------------------------------------------------------
#
# These are the exception to this module's rule about not going through
# ``Settings``: the thing under test *is* the source stack, so it has to be
# exercised end to end. They stay hermetic by pointing both file sources at
# a tmp_path through ``LPR_CONFIG_FILE`` and ``LPR_ENV_FILE``, so they never
# read -- and can never be broken by -- the developer's own configuration.


@pytest.fixture()
def isolated_sources(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Point both file-backed sources at an empty tmp_path.

    Also clears any ``LPR_`` variable already exported into the test runner's
    environment, so a developer who has the real secret in their shell does
    not get a green run that CI cannot reproduce.
    """
    for name in list(os.environ):
        if name.startswith("LPR_"):
            monkeypatch.delenv(name, raising=False)

    config_yaml = tmp_path / "config.yaml"
    env_file = tmp_path / ".env"
    monkeypatch.setenv("LPR_CONFIG_FILE", str(config_yaml))
    monkeypatch.setenv("LPR_ENV_FILE", str(env_file))
    return SimpleNamespace(config_yaml=config_yaml, env_file=env_file, monkeypatch=monkeypatch)


def test_a_dotenv_file_is_actually_read(isolated_sources: Any) -> None:
    """The regression behind ``POST /api/users/{u}/license`` returning 503.

    ``.env`` was listed in the source stack but no ``env_file`` was ever
    configured, so the source read nothing. Under Compose the same file is
    injected as real environment variables and everything worked, which is why
    it survived: only a host run was broken, and only for whoever had not
    exported the variable by hand.
    """
    isolated_sources.env_file.write_text("LPR_LICENSE_SECRET=from-dotenv\n", encoding="utf-8")
    assert Settings().license_secret == "from-dotenv"


def test_a_real_environment_variable_beats_the_dotenv_file(isolated_sources: Any) -> None:
    """`.env` is a stand-in for the environment, not an override of it."""
    isolated_sources.env_file.write_text("LPR_LICENSE_SECRET=from-dotenv\n", encoding="utf-8")
    isolated_sources.monkeypatch.setenv("LPR_LICENSE_SECRET", "from-real-env")
    assert Settings().license_secret == "from-real-env"


def test_the_dotenv_file_beats_config_yaml(isolated_sources: Any) -> None:
    """The uncommitted file carries the secret; the committed one must not win.

    ``config.yaml`` ships ``api.secret_key: change-me`` and an empty
    ``smtp.password`` as *written* values, not as field defaults. With YAML
    ranked above ``.env`` both of the overrides SECURITY.md tells a site to use
    would lose to the placeholder they exist to replace -- silently, and in the
    smtp case leaving alerting switched off while the file said otherwise.
    """
    isolated_sources.config_yaml.write_text(
        "api:\n"
        "  secret_key: change-me\n"
        "smtp:\n"
        "  enabled: true\n"
        "  host: smtp.example.com\n"
        "  user: gate@example.com\n"
        "  password: ''\n"
        "  from_email: gate@example.com\n"
        "  to_emails: ['guard@example.com']\n",
        encoding="utf-8",
    )
    isolated_sources.env_file.write_text(
        "LPR_API__SECRET_KEY=real-secret\nLPR_SMTP__PASSWORD=real-password\n", encoding="utf-8"
    )

    settings = Settings()
    assert settings.api.secret_key == "real-secret"
    assert settings.smtp.password == "real-password"
    # The consequence, not just the value: with YAML on top this reads
    # ["password"] and the notifier is switched on and mute.
    assert settings.smtp.missing_fields == []


def test_config_yaml_still_fills_in_what_the_dotenv_file_does_not(isolated_sources: Any) -> None:
    """Ranking `.env` higher must not stop YAML being the bulk of the config."""
    isolated_sources.config_yaml.write_text("api:\n  port: 9100\n", encoding="utf-8")
    isolated_sources.env_file.write_text("LPR_LICENSE_SECRET=x\n", encoding="utf-8")
    assert Settings().api.port == 9100


def test_an_absent_dotenv_file_is_not_an_error(isolated_sources: Any) -> None:
    """A fresh checkout has no `.env`, and must still start."""
    assert not isolated_sources.env_file.exists()
    assert Settings().license_secret == ""


def test_an_explicit_env_file_path_is_honoured(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A site keeping its secrets under /etc rather than in the checkout."""
    for name in list(os.environ):
        if name.startswith("LPR_"):
            monkeypatch.delenv(name, raising=False)
    elsewhere = tmp_path / "etc" / "lpr.env"
    elsewhere.parent.mkdir(parents=True)
    elsewhere.write_text("LPR_LICENSE_SECRET=from-etc\n", encoding="utf-8")

    monkeypatch.setenv("LPR_CONFIG_FILE", str(tmp_path / "config.yaml"))
    monkeypatch.setenv("LPR_ENV_FILE", str(elsewhere))
    assert Settings().license_secret == "from-etc"


def test_both_config_files_are_looked_for_in_the_same_place(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """`.env` and `config.yaml` must resolve together, and not from the cwd.

    Resolving either one relative to the working directory means the secret is
    present or absent depending on where the process was launched -- the same
    unit file behaving differently from ``make run-api`` in the checkout.
    """
    monkeypatch.delenv("LPR_CONFIG_FILE", raising=False)
    monkeypatch.delenv("LPR_ENV_FILE", raising=False)
    monkeypatch.chdir(tmp_path)

    assert _default_env_file_path().parent == _default_config_yaml_path().parent
    assert _default_env_file_path().name == ".env"


# ---------------------------------------------------------------------------
# Variables that configure nothing
# ---------------------------------------------------------------------------


def test_a_correctly_named_variable_is_not_reported(isolated_sources: Any) -> None:
    isolated_sources.env_file.write_text(
        "LPR_SMTP__TO_EMAILS=['a@example.com']\n", encoding="utf-8"
    )
    assert unknown_env_names() == []


def test_a_plausible_misspelling_is_reported(isolated_sources: Any) -> None:
    """`to_addrs` reads like the setting; the field is called `to_emails`.

    Silently discarded by ``extra="ignore"``, which leaves the alerts going to
    whatever address ``config.yaml`` last named -- with the operator looking at
    a ``.env`` that says otherwise.
    """
    isolated_sources.env_file.write_text(
        "LPR_SMTP__TO_ADDRS=['a@example.com']\nLPR_SMTP__USERNAME=a@example.com\n",
        encoding="utf-8",
    )
    assert unknown_env_names() == ["LPR_SMTP__TO_ADDRS", "LPR_SMTP__USERNAME"]


def test_a_real_environment_variable_is_checked_too(isolated_sources: Any) -> None:
    isolated_sources.monkeypatch.setenv("LPR_DETECTION__CONFIDENZE", "0.4")
    assert "LPR_DETECTION__CONFIDENZE" in unknown_env_names()


def test_deeply_nested_names_are_accepted(isolated_sources: Any) -> None:
    """`cameras.entry.source` is three levels deep and documented in .env.example."""
    isolated_sources.env_file.write_text(
        "LPR_CAMERAS__ENTRY__SOURCE=rtsp://cam/1\n", encoding="utf-8"
    )
    assert unknown_env_names() == []


def test_infrastructure_variables_are_not_reported(isolated_sources: Any) -> None:
    """Compose reads these; they are not settings and never will be.

    Reporting them would make the warning fire on every correct deployment,
    which is how a warning stops being read.
    """
    isolated_sources.env_file.write_text(
        "LPR_ENV=production\n"
        "LPR_BIND=0.0.0.0\n"
        "LPR_PORT=8000\n"
        "LPR_VIDEO_GID=44\n"
        "LPR_DOCKER_SOCK=/var/run/docker.sock\n"
        "LPR_DOMAIN=gate.example.com\n"
        "LPR_ACME_EMAIL=ops@example.com\n"
        "LPR_MEM_LIMIT=6g\n"
        "LPR_LICENSE_PUBLIC_KEY=/etc/lpr/public.pem\n"
        "LPR_API_DOCS=1\n",
        encoding="utf-8",
    )
    assert unknown_env_names() == []


def test_comments_and_blank_lines_are_not_variables(isolated_sources: Any) -> None:
    isolated_sources.env_file.write_text(
        "# LPR_SMTP__NONSENSE=1\n\n   \nLPR_SMTP__HOST=smtp.example.com\n",
        encoding="utf-8",
    )
    assert unknown_env_names() == []


def test_a_non_lpr_variable_is_none_of_our_business(isolated_sources: Any) -> None:
    isolated_sources.env_file.write_text(
        "PATH=/usr/bin\nTORCH_INDEX_URL=https://example.com\n", encoding="utf-8"
    )
    assert unknown_env_names() == []


def test_the_report_is_a_warning_and_not_a_refusal(isolated_sources: Any) -> None:
    """A stale line in an old `.env` must not stop a gate from starting."""
    isolated_sources.env_file.write_text("LPR_SMTP__TO_ADDRS=x\n", encoding="utf-8")
    settings = Settings()  # must not raise
    assert settings.smtp.enabled is False
    assert warn_about_unknown_env_names() == ["LPR_SMTP__TO_ADDRS"]
