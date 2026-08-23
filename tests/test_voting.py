"""Tests for multi-frame vote aggregation.

Pure python, no ML packages. Time is injected through the voter's ``clock``
argument so nothing here sleeps.
"""

from __future__ import annotations

import threading

import pytest

from lpr.contracts import PlateRead, TrackAwareVoter, Voter
from lpr.ocr.voting import MultiFrameVoter, build_voter, levenshtein


class FakeClock:
    """A monotonic clock the test drives by hand."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def read(text: str, confidence: float = 0.9) -> PlateRead:
    return PlateRead(text=text, confidence=confidence, raw_text=text, valid=True)


def make_voter(clock: FakeClock, **kwargs: object) -> MultiFrameVoter:
    params: dict[str, object] = {
        "window": 5,
        "min_votes": 3,
        "ttl_s": 4.0,
        "cooldown_s": 10.0,
        "clock": clock,
    }
    params.update(kwargs)
    return MultiFrameVoter(**params)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Threshold behaviour
# ---------------------------------------------------------------------------


def test_no_emission_below_min_votes() -> None:
    voter = make_voter(FakeClock())
    assert voter.submit("entry", read("34ABC12")) is None
    assert voter.submit("entry", read("34ABC12")) is None


def test_emits_exactly_at_the_threshold() -> None:
    voter = make_voter(FakeClock())
    results = [voter.submit("entry", read("34ABC12")) for _ in range(3)]
    assert results == [None, None, "34ABC12"]


def test_disagreeing_reads_never_confirm() -> None:
    voter = make_voter(FakeClock(), merge_distance=0)
    for plate in ["34ABC12", "06BZ1234", "35DEF34", "16AB123"]:
        assert voter.submit("entry", read(plate)) is None


def test_invalid_reads_are_ignored() -> None:
    voter = make_voter(FakeClock())
    junk = PlateRead(text="HOSGELDIN", confidence=0.99, raw_text="HOSGELDIN", valid=False)
    for _ in range(5):
        assert voter.submit("entry", junk) is None
    assert voter.pending("entry") == []


def test_min_votes_is_clamped_to_the_window() -> None:
    """A voter that can never confirm anything is a misconfiguration, not a mode."""
    voter = MultiFrameVoter(window=3, min_votes=10, clock=FakeClock())
    assert voter.min_votes == 3


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def test_ttl_expiry_prevents_emission() -> None:
    clock = FakeClock()
    voter = make_voter(clock, ttl_s=2.0)
    assert voter.submit("entry", read("34ABC12")) is None
    clock.advance(1.0)
    assert voter.submit("entry", read("34ABC12")) is None
    clock.advance(1.5)  # the first vote is now older than ttl_s
    assert voter.submit("entry", read("34ABC12")) is None
    # only two live votes remain, so one more confirms
    assert voter.submit("entry", read("34ABC12")) == "34ABC12"


def test_votes_clustered_in_time_do_confirm() -> None:
    clock = FakeClock()
    voter = make_voter(clock, ttl_s=4.0)
    assert voter.submit("entry", read("34ABC12")) is None
    clock.advance(0.5)
    assert voter.submit("entry", read("34ABC12")) is None
    clock.advance(0.5)
    assert voter.submit("entry", read("34ABC12")) == "34ABC12"


def test_cooldown_suppresses_a_repeat_and_then_lapses() -> None:
    clock = FakeClock()
    voter = make_voter(clock, cooldown_s=10.0, ttl_s=100.0)
    for _ in range(2):
        voter.submit("entry", read("34ABC12"))
    assert voter.submit("entry", read("34ABC12")) == "34ABC12"

    # An idling car keeps producing reads; none of them re-fire the gate.
    for _ in range(6):
        clock.advance(0.5)
        assert voter.submit("entry", read("34ABC12")) is None

    clock.advance(10.0)  # cooldown lapsed: confirmation must be earned again
    assert voter.submit("entry", read("34ABC12")) is None
    assert voter.submit("entry", read("34ABC12")) is None
    assert voter.submit("entry", read("34ABC12")) == "34ABC12"


def test_emission_clears_only_the_winning_plates_votes() -> None:
    clock = FakeClock()
    voter = make_voter(clock, window=6, ttl_s=100.0, merge_distance=0)
    voter.submit("entry", read("06BZ1234", 0.4))
    for _ in range(3):
        voter.submit("entry", read("34ABC12", 0.9))
    pending = dict((text, votes) for text, votes, _ in voter.pending("entry"))
    assert "34ABC12" not in pending
    assert pending.get("06BZ1234") == 1


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


def test_confidence_weighting_beats_raw_count() -> None:
    """Three hesitant reads must not outrank two emphatic ones."""
    clock = FakeClock()
    # min_votes above the window would be clamped, so start high and lower it
    # once the votes are in place; that is the only way two candidates can
    # both qualify on the same submit.
    voter = make_voter(clock, window=6, min_votes=6, ttl_s=100.0)
    for _ in range(3):
        voter.submit("entry", read("34ABC12", 0.2))
    for _ in range(2):
        voter.submit("entry", read("06BZ1234", 0.9))

    ranked = voter.pending("entry")
    assert ranked[0][0] == "06BZ1234"  # fewer votes, more weight

    voter.min_votes = 2
    assert voter.submit("entry", read("34ABC12", 0.2)) == "06BZ1234"


def test_equal_counts_are_broken_by_summed_confidence() -> None:
    clock = FakeClock()
    voter = make_voter(clock, window=6, min_votes=6, ttl_s=100.0)
    voter.submit("entry", read("34ABC12", 0.30))
    voter.submit("entry", read("35DEF34", 0.95))
    voter.submit("entry", read("34ABC12", 0.30))
    voter.submit("entry", read("35DEF34", 0.95))
    assert voter.pending("entry")[0][0] == "35DEF34"


# ---------------------------------------------------------------------------
# Near-miss merging
# ---------------------------------------------------------------------------


def test_levenshtein() -> None:
    assert levenshtein("34ABC12", "34ABC12") == 0
    assert levenshtein("34ABC12", "34ABC13") == 1  # substitution
    assert levenshtein("34ABC12", "34AB12") == 1  # deletion
    assert levenshtein("34ABC12", "34ABCC12") == 1  # insertion
    assert levenshtein("34ABC12", "35ABD12") == 2
    assert levenshtein("34ABC12", "06BZ1234", max_distance=1) > 1
    assert levenshtein("", "34ABC12", max_distance=10) == 7
    # the cap short-circuits instead of computing the true distance
    assert levenshtein("", "34ABC12", max_distance=2) == 3


def test_near_misses_merge_onto_the_higher_confidence_variant() -> None:
    clock = FakeClock()
    voter = make_voter(clock, ttl_s=100.0)
    assert voter.submit("entry", read("34ABC12", 0.95)) is None
    assert voter.submit("entry", read("34ABC13", 0.30)) is None  # one edit away
    # the merged group now has three votes and emits the strong spelling
    assert voter.submit("entry", read("34ABC12", 0.95)) == "34ABC12"


def test_merging_is_limited_to_distance_one() -> None:
    clock = FakeClock()
    voter = make_voter(clock, ttl_s=100.0)
    voter.submit("entry", read("34ABC12", 0.9))
    voter.submit("entry", read("35ABD12", 0.9))  # two edits away
    assert voter.submit("entry", read("35ABD12", 0.9)) is None


def test_merging_can_be_disabled() -> None:
    clock = FakeClock()
    voter = make_voter(clock, ttl_s=100.0, merge_distance=0)
    voter.submit("entry", read("34ABC12", 0.9))
    voter.submit("entry", read("34ABC13", 0.9))
    assert voter.submit("entry", read("34ABC12", 0.9)) is None


# ---------------------------------------------------------------------------
# Per-camera state
# ---------------------------------------------------------------------------


def test_cameras_are_isolated() -> None:
    clock = FakeClock()
    voter = make_voter(clock, min_votes=2, ttl_s=100.0)
    assert voter.submit("entry", read("34ABC12")) is None
    assert voter.submit("exit", read("34ABC12")) is None
    assert voter.submit("exit", read("34ABC12")) == "34ABC12"
    # the entry camera still has only one vote, and its own cooldown state
    assert voter.submit("entry", read("34ABC12")) == "34ABC12"


def test_reset_drops_votes_and_cooldown_for_one_camera_only() -> None:
    clock = FakeClock()
    voter = make_voter(clock, min_votes=2, ttl_s=100.0)
    voter.submit("entry", read("34ABC12"))
    voter.submit("exit", read("06BZ1234"))
    voter.reset("entry")
    assert voter.pending("entry") == []
    assert voter.pending("exit") != []


def test_reset_clears_the_cooldown_too() -> None:
    clock = FakeClock()
    voter = make_voter(clock, min_votes=2, ttl_s=100.0, cooldown_s=100.0)
    voter.submit("entry", read("34ABC12"))
    assert voter.submit("entry", read("34ABC12")) == "34ABC12"
    voter.reset("entry")
    voter.submit("entry", read("34ABC12"))
    assert voter.submit("entry", read("34ABC12")) == "34ABC12"


def test_satisfies_the_voter_protocol() -> None:
    voter = make_voter(FakeClock())
    assert isinstance(voter, Voter)


# ---------------------------------------------------------------------------
# Track awareness
# ---------------------------------------------------------------------------


def test_satisfies_the_track_aware_voter_protocol() -> None:
    assert isinstance(make_voter(FakeClock()), TrackAwareVoter)


def test_reads_sharing_a_track_merge_beyond_the_edit_distance() -> None:
    """Same tracked object = same plate, however badly it was spelled."""
    clock = FakeClock()
    voter = make_voter(clock, min_votes=3, ttl_s=100.0)
    # Three edits apart: the Levenshtein merge (distance 1) cannot join these.
    assert voter.submit("entry", read("34ABC12", 0.9), track_id=7) is None
    assert voter.submit("entry", read("34XYZ12", 0.4), track_id=7) is None
    assert voter.submit("entry", read("34ABC12", 0.9), track_id=7) == "34ABC12"


def test_different_tracks_never_merge() -> None:
    """Two cars in frame stay two candidates, however similar their plates."""
    clock = FakeClock()
    voter = make_voter(clock, min_votes=3, ttl_s=100.0)
    voter.submit("entry", read("34ABC12", 0.9), track_id=1)
    voter.submit("entry", read("34ABC13", 0.9), track_id=2)
    assert voter.submit("entry", read("34ABC13", 0.9), track_id=2) is None
    texts = {text for text, _, _ in voter.pending("entry")}
    assert texts == {"34ABC12", "34ABC13"}


def test_untracked_reads_keep_the_levenshtein_behaviour() -> None:
    clock = FakeClock()
    voter = make_voter(clock, min_votes=3, ttl_s=100.0)
    assert voter.submit("entry", read("34ABC12", 0.95)) is None
    assert voter.submit("entry", read("34ABC13", 0.30)) is None  # one edit away
    assert voter.submit("entry", read("34ABC12", 0.95)) == "34ABC12"


def test_untracked_detections_are_always_recognised() -> None:
    voter = make_voter(FakeClock())
    for _ in range(50):
        assert voter.should_recognize("entry", None) is True
        voter.note_recognized("entry", None)
    voter.note_decision("entry", None, "34ABC12")
    assert voter.should_recognize("entry", None) is True


def test_a_decided_track_stops_costing_ocr() -> None:
    clock = FakeClock()
    voter = make_voter(clock, cooldown_s=10.0)
    assert voter.should_recognize("entry", 3) is True

    voter.note_decision("entry", 3, "34ABC12")
    assert voter.should_recognize("entry", 3) is False

    # Still muted once the cooldown lapses: ByteTrack does not recycle ids, so
    # this track is the same car it was when the gate opened.
    clock.advance(11.0)
    assert voter.should_recognize("entry", 3) is False
    # ... and another camera's track 3 is a different object entirely.
    assert voter.should_recognize("exit", 3) is True


def test_confirmation_mutes_the_winning_track() -> None:
    clock = FakeClock()
    voter = make_voter(clock, min_votes=2, ttl_s=100.0, cooldown_s=10.0)
    voter.submit("entry", read("34ABC12"), track_id=5)
    assert voter.submit("entry", read("34ABC12"), track_id=5) == "34ABC12"
    assert voter.should_recognize("entry", 5) is False
    clock.advance(11.0)
    assert voter.should_recognize("entry", 5) is True


def test_unreadable_track_is_muted_after_the_attempt_cap() -> None:
    """A plate this camera cannot read must not starve the ones it can."""
    clock = FakeClock()
    voter = make_voter(clock, cooldown_s=10.0, max_track_attempts=4)

    for _ in range(4):
        assert voter.should_recognize("entry", 9) is True
        voter.note_recognized("entry", 9)

    assert voter.should_recognize("entry", 9) is False
    clock.advance(11.0)
    # The mute lapses and the budget resets: a bad angle may have improved.
    assert voter.should_recognize("entry", 9) is True


def test_attempt_cap_can_be_disabled() -> None:
    clock = FakeClock()
    voter = make_voter(clock, max_track_attempts=0)
    for _ in range(100):
        assert voter.should_recognize("entry", 1) is True
        voter.note_recognized("entry", 1)


def test_track_state_expires_after_its_ttl() -> None:
    clock = FakeClock()
    voter = make_voter(clock, cooldown_s=10.0, track_ttl_s=30.0)
    voter.note_decision("entry", 4, "34ABC12")
    assert voter.tracked("entry") == [(4, 0, "34ABC12")]

    clock.advance(31.0)
    assert voter.tracked("entry") == []
    # Forgotten, so a recycled id after a restart is readable again.
    assert voter.should_recognize("entry", 4) is True


def test_track_state_survives_while_the_plate_is_still_in_view() -> None:
    clock = FakeClock()
    voter = make_voter(clock, cooldown_s=10.0, track_ttl_s=30.0)
    voter.note_decision("entry", 4, "34ABC12")
    for _ in range(10):
        clock.advance(20.0)
        assert voter.should_recognize("entry", 4) is False


def test_reset_drops_track_state_for_one_camera_only() -> None:
    clock = FakeClock()
    voter = make_voter(clock)
    voter.note_decision("entry", 1, "34ABC12")
    voter.note_decision("exit", 2, "06BZ1234")
    voter.reset("entry")
    assert voter.tracked("entry") == []
    assert voter.tracked("exit") == [(2, 0, "06BZ1234")]
    assert voter.should_recognize("entry", 1) is True


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_concurrent_submits_emit_exactly_once() -> None:
    """Per-camera worker threads must not double-fire the gate."""
    clock = FakeClock()
    voter = make_voter(clock, window=200, min_votes=25, ttl_s=1000.0, cooldown_s=1000.0)
    results: list[str | None] = []
    lock = threading.Lock()
    barrier = threading.Barrier(4)

    def worker() -> None:
        barrier.wait()
        local = [voter.submit("entry", read("06BZ1234", 0.8)) for _ in range(30)]
        with lock:
            results.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == 120
    assert [r for r in results if r is not None] == ["06BZ1234"]


def test_concurrent_submits_across_cameras_do_not_leak() -> None:
    clock = FakeClock()
    voter = make_voter(clock, window=50, min_votes=10, ttl_s=1000.0, cooldown_s=1000.0)
    emitted: dict[str, list[str]] = {"entry": [], "exit": []}
    lock = threading.Lock()

    def worker(camera: str, plate: str) -> None:
        for _ in range(10):
            result = voter.submit(camera, read(plate, 0.8))
            if result is not None:
                with lock:
                    emitted[camera].append(result)

    threads = [
        threading.Thread(target=worker, args=("entry", "34ABC12")),
        threading.Thread(target=worker, args=("exit", "06BZ1234")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert emitted["entry"] == ["34ABC12"]
    assert emitted["exit"] == ["06BZ1234"]


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_build_voter_reads_settings() -> None:
    settings = pytest.importorskip("lpr.config").get_settings()
    voter = build_voter(settings)
    assert voter.window == settings.voting.window
    assert voter.ttl_s == pytest.approx(settings.voting.ttl_s)
    assert voter.cooldown_s == pytest.approx(settings.voting.cooldown_s)
    assert isinstance(voter, Voter)


# ---------------------------------------------------------------------------
# Live vote telemetry
# ---------------------------------------------------------------------------


def test_vote_telemetry_reports_progress_then_confirmation() -> None:
    seen: list[dict] = []
    clock = FakeClock()
    voter = make_voter(clock, min_votes=3, ttl_s=100.0, on_vote=seen.append)

    voter.submit("entry", read("34ABC12", 0.8))
    voter.submit("entry", read("34ABC12", 0.8))
    assert [(e["votes"], e["confirmed"]) for e in seen] == [(1, False), (2, False)]
    assert all(e["needed"] == 3 and e["kind"] == "vote" for e in seen)

    assert voter.submit("entry", read("34ABC12", 0.8)) == "34ABC12"
    assert seen[-1]["confirmed"] is True
    assert seen[-1]["plate"] == "34ABC12"
    assert seen[-1]["camera"] == "entry"


def test_vote_telemetry_carries_the_track_id() -> None:
    seen: list[dict] = []
    voter = make_voter(FakeClock(), min_votes=2, ttl_s=100.0, on_vote=seen.append)
    voter.submit("entry", read("34ABC12"), track_id=11)
    assert seen[-1]["track_id"] == 11


def test_a_broken_telemetry_sink_never_breaks_voting() -> None:
    """Telemetry is never load-bearing: the gate still opens."""

    def explode(payload: dict) -> None:
        raise RuntimeError("consumer is down")

    voter = make_voter(FakeClock(), min_votes=2, ttl_s=100.0, on_vote=explode)
    voter.submit("entry", read("34ABC12"))
    assert voter.submit("entry", read("34ABC12")) == "34ABC12"


def test_unusable_reads_produce_no_telemetry() -> None:
    seen: list[dict] = []
    voter = make_voter(FakeClock(), on_vote=seen.append)
    voter.submit("entry", PlateRead(text="", confidence=0.9, raw_text="?", valid=False))
    assert seen == []
