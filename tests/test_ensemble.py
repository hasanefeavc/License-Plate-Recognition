"""Tests for the per-frame ensemble vote.

This layer is pure python, so it needs no ML stack and no cv2 -- the ballots
stand in for whatever the engines actually saw. What is under test is the
decision rule: agreement across views must outrank a single confident outlier,
grammar must outrank arithmetic, and none of it may manufacture a plate.
"""

from __future__ import annotations

from typing import Any

import pytest

from lpr.contracts import PlateRead
from lpr.ocr.ensemble import Ballot, EnsembleRecognizer, vote

# ---------------------------------------------------------------------------
# vote
# ---------------------------------------------------------------------------


def test_agreeing_views_outvote_a_confident_outlier() -> None:
    """The whole point: an over-confident single view can no longer win outright."""
    winner = vote(
        [
            Ballot("34ABC12", 0.55, "gray"),
            Ballot("34ABC12", 0.60, "binary"),
            Ballot("34ABC12", 0.52, "deskew"),
            Ballot("06MNP99", 0.95, "rectified"),
        ]
    )
    assert winner.text == "34ABC12"
    assert winner.valid is True


def test_a_lone_confident_read_still_wins_against_hesitant_noise() -> None:
    """Confidence-weighted, not raw majority: two weak reads must not sway it."""
    winner = vote(
        [
            Ballot("34ABC12", 0.95, "gray"),
            Ballot("06MNP99", 0.10, "binary"),
            Ballot("06MNP99", 0.12, "deskew"),
        ]
    )
    assert winner.text == "34ABC12"


def test_near_misses_reinforce_the_stronger_spelling() -> None:
    """Two grammatical spellings one edit apart are one plate, not two rivals.

    Individually neither "34ABC12" (0.50) nor "34ABD12" (0.48) outscores the
    rival at 0.60. Merged they do, which is the case that would otherwise split
    the vote and hand the frame to a plate nobody read twice.
    """
    winner = vote(
        [
            Ballot("34ABC12", 0.50, "gray"),
            Ballot("34ABD12", 0.48, "binary"),
            Ballot("06MNP99", 0.60, "rectified"),
        ]
    )
    assert winner.text == "34ABC12"


def test_the_reported_confidence_belongs_to_the_emitted_spelling() -> None:
    """A merged near-miss is evidence, not a confidence transfer.

    ``ocr.min_confidence`` and the multi-frame voter both read this field, so it
    has to keep meaning "how sure was the engine about *this* string".
    """
    winner = vote([Ballot("34ABC12", 0.50, "gray"), Ballot("34ABD12", 0.90, "binary")])
    assert winner.text == "34ABD12"
    assert winner.confidence == pytest.approx(0.90)

    # And the other way round: the winning spelling keeps its own confidence
    # rather than inheriting the louder near-miss's.
    other = vote(
        [
            Ballot("34ABC12", 0.50, "gray"),
            Ballot("34ABC12", 0.55, "binary"),
            Ballot("34ABD12", 0.90, "deskew"),
        ]
    )
    assert other.text == "34ABC12"
    assert other.confidence == pytest.approx(0.55)


def test_a_coercible_misread_lands_in_the_same_group() -> None:
    """ "34A8C12" normalises straight onto "34ABC12" -- one group, not a merge."""
    winner = vote([Ballot("34A8C12", 0.4, "gray"), Ballot("34ABC12", 0.4, "binary")])
    assert winner.text == "34ABC12"


def test_a_grammatical_read_beats_an_ungrammatical_one_whatever_the_arithmetic() -> None:
    winner = vote(
        [
            Ballot("34ABC12", 0.20, "gray"),
            Ballot("HOSGELDINIZ", 0.99, "binary"),
            Ballot("HOSGELDINIZ", 0.99, "deskew"),
        ]
    )
    assert winner.text == "34ABC12"
    assert winner.valid is True


def test_vote_reports_an_invalid_read_when_nothing_parses() -> None:
    winner = vote([Ballot("HOSGELDINIZ", 0.9, "gray")])
    assert winner.valid is False
    assert winner.text == "HOSGELDINIZ"


def test_vote_on_nothing_is_empty_and_invalid() -> None:
    empty = vote([])
    assert empty.valid is False
    assert empty.text == ""


def test_vote_ignores_blank_ballots() -> None:
    winner = vote([Ballot("", 0.9, "gray"), Ballot("34ABC12", 0.4, "binary")])
    assert winner.text == "34ABC12"


def test_vote_clamps_a_backend_reporting_a_nonsense_confidence() -> None:
    winner = vote([Ballot("34ABC12", 7.5, "gray")])
    assert 0.0 <= winner.confidence <= 1.0


def test_vote_never_raises_on_junk_ballots() -> None:
    class Broken:
        text = "34ABC12"

        @property
        def confidence(self) -> float:
            raise RuntimeError("backend exploded")

    assert isinstance(vote([Broken()]), PlateRead)  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# EnsembleRecognizer
# ---------------------------------------------------------------------------


class FakeEngine:
    """A recogniser stand-in that emits fixed ballots and counts its calls."""

    def __init__(self, ballots: list[Ballot], name: str = "fake") -> None:
        self._ballots = ballots
        self.name = name
        self.calls = 0
        self.warmed_up = False

    def ballots(self, crop: Any) -> list[Ballot]:
        self.calls += 1
        return list(self._ballots)

    def recognize(self, crop: Any) -> PlateRead:
        return vote(self.ballots(crop))

    def warmup(self) -> None:
        self.warmed_up = True


def test_the_ensemble_pools_ballots_from_every_member() -> None:
    """Two engines that each half-read the plate should agree on it together."""
    first = FakeEngine([Ballot("34A8C12", 0.40, "easy")])
    second = FakeEngine([Ballot("34ABC12", 0.45, "paddle")])
    assert EnsembleRecognizer([first, second]).recognize(object()).text == "34ABC12"


def test_the_second_engine_is_skipped_once_a_plate_is_confirmed() -> None:
    """The extra engine is a cost paid on hard crops, not on every car."""
    first = FakeEngine([Ballot("34ABC12", 0.9, "easy")])
    second = FakeEngine([Ballot("34ABC12", 0.9, "paddle")])
    EnsembleRecognizer([first, second]).recognize(object())
    assert first.calls == 1
    assert second.calls == 0


def test_the_second_engine_is_consulted_when_the_first_fails() -> None:
    first = FakeEngine([Ballot("HOSGELDINIZ", 0.9, "easy")])
    second = FakeEngine([Ballot("34ABC12", 0.7, "paddle")])
    result = EnsembleRecognizer([first, second]).recognize(object())
    assert second.calls == 1
    assert result.text == "34ABC12"


def test_a_member_that_raises_is_dropped_not_fatal() -> None:
    """Half an ensemble still beats no read at all."""

    class Exploding:
        def ballots(self, crop: Any) -> list[Ballot]:
            raise RuntimeError("engine exploded")

    working = FakeEngine([Ballot("34ABC12", 0.8, "paddle")])
    assert EnsembleRecognizer([Exploding(), working]).recognize(object()).text == "34ABC12"


def test_a_member_offering_only_recognize_still_votes() -> None:
    """A backend predating the ballots interface is admitted, not excluded."""

    class VerdictOnly:
        def recognize(self, crop: Any) -> PlateRead:
            return PlateRead(text="34ABC12", confidence=0.8, raw_text="34ABC12", valid=True)

    assert EnsembleRecognizer([VerdictOnly()]).recognize(object()).text == "34ABC12"


def test_the_ensemble_warms_every_member() -> None:
    first = FakeEngine([], "easy")
    second = FakeEngine([], "paddle")
    EnsembleRecognizer([first, second]).warmup()
    assert first.warmed_up and second.warmed_up


def test_a_member_failing_warmup_does_not_stop_the_others() -> None:
    class BadWarmup:
        def warmup(self) -> None:
            raise RuntimeError("warmup exploded")

    good = FakeEngine([], "easy")
    EnsembleRecognizer([BadWarmup(), good]).warmup()
    assert good.warmed_up is True


def test_an_empty_ensemble_is_refused() -> None:
    with pytest.raises(ValueError):
        EnsembleRecognizer([])
