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

from lpr.config import RelayConfig, VotingConfig


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
