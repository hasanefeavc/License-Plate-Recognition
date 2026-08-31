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

import pytest

from lpr.config import FastPathConfig, OcrConfig, RelayConfig, Settings, VotingConfig


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
