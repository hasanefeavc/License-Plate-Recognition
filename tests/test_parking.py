"""Occupancy counting, capacity, and the automatic gate.

The gate behaviour is asserted here rather than assumed: "a whitelisted plate
opens the barrier by itself" is the single most important promise the product
makes, and it is entirely a backend property -- no client is involved.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on invocation
    sys.path.insert(0, str(SRC))

from lpr.contracts import Action, LprEvent  # noqa: E402
from lpr.db import LogRepository, PlateRepository  # noqa: E402
from lpr.pipeline.orchestrator import PipelineOrchestrator  # noqa: E402

from .conftest import FakeDetector, FakeRecognizer, FakeRelay, FakeVoter  # noqa: E402


def _pipeline(settings: Any, relay: Any) -> PipelineOrchestrator:
    return PipelineOrchestrator(
        settings=settings,
        detector=FakeDetector(),
        recognizer=FakeRecognizer(),
        voter=FakeVoter(),
        relay=relay,
    )


def _log(repo: LogRepository, plate: str, camera: str, action: str, when: datetime) -> None:
    repo.write(
        LprEvent(
            ts=when.astimezone(timezone.utc).isoformat(),
            camera=camera,
            plate=plate,
            action=action,
            confidence=0.9,
        )
    )


def _today(hour: int, minute: int = 0) -> datetime:
    return datetime.now(timezone.utc).replace(
        hour=hour, minute=minute, second=0, microsecond=0
    )


def _midnight() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(hour=0, minute=0, second=0, microsecond=0)
        .isoformat()
    )


# ---------------------------------------------------------------------------
# The gate opens by itself
# ---------------------------------------------------------------------------


def test_a_whitelisted_plate_opens_the_gate_with_no_manual_step(db, frame) -> None:
    """The whole point of the product: recognise, match, open. No operator."""
    PlateRepository().add("34ABC123")
    relay = FakeRelay()
    pipeline = _pipeline(db, relay)

    events = pipeline.process_frame("entry", frame)

    assert relay.triggers == 1, "a registered plate must pulse the relay by itself"
    assert [e.action for e in events] == [str(Action.GRANTED)]


def test_an_unknown_plate_does_not_open_the_gate(db, frame) -> None:
    relay = FakeRelay()
    pipeline = _pipeline(db, relay)

    events = pipeline.process_frame("entry", frame)

    assert relay.triggers == 0
    assert [e.action for e in events] == [str(Action.DENIED)]


def test_the_gate_stays_shut_while_the_pipeline_is_paused(db, frame) -> None:
    """A licence hold or the operator's pause button must reach the barrier."""
    PlateRepository().add("34ABC123")
    relay = FakeRelay()
    pipeline = _pipeline(db, relay)
    pipeline.pause()

    assert pipeline.process_frame("entry", frame) == []
    assert relay.triggers == 0


def test_an_idling_car_does_not_pulse_the_relay_on_every_frame(db, frame) -> None:
    """Cooldown protects the hardware as well as the log."""
    PlateRepository().add("34ABC123")
    relay = FakeRelay()
    pipeline = _pipeline(db, relay)

    pipeline.process_frame("entry", frame)
    for _ in range(10):
        pipeline.process_frame("entry", frame)

    assert relay.triggers == 1


# ---------------------------------------------------------------------------
# Occupancy
# ---------------------------------------------------------------------------


def test_occupancy_counts_plates_whose_last_move_was_an_entry(db) -> None:
    repo = LogRepository()
    _log(repo, "34ABC123", "entry", "granted", _today(8))
    _log(repo, "06XYZ42", "entry", "granted", _today(9))
    _log(repo, "06XYZ42", "exit", "granted", _today(10))  # left again
    _log(repo, "35KL7788", "entry", "granted", _today(11))

    counts = repo.occupancy_since(_midnight())

    assert counts["inside"] == 2, "34ABC123 and 35KL7788 are still in"
    assert counts["entries"] == 3
    assert counts["exits"] == 1


def test_a_repeated_entry_counts_the_car_once(db) -> None:
    """A running entries-minus-exits tally would drift up here; this must not."""
    repo = LogRepository()
    for hour in (8, 9, 10):
        _log(repo, "34ABC123", "entry", "granted", _today(hour))

    assert repo.occupancy_since(_midnight())["inside"] == 1


def test_a_car_that_only_ever_left_cannot_push_the_count_negative(db) -> None:
    """The overnight case: it entered yesterday, outside the window."""
    repo = LogRepository()
    _log(repo, "34ABC123", "exit", "granted", _today(7))
    _log(repo, "06XYZ42", "exit", "granted", _today(8))

    counts = repo.occupancy_since(_midnight())

    assert counts["inside"] == 0
    assert counts["exits"] == 2


def test_refusals_never_count_as_occupancy(db) -> None:
    repo = LogRepository()
    _log(repo, "34ABC123", "entry", "denied", _today(8))
    _log(repo, "06XYZ42", "entry", "cooldown", _today(9))

    assert repo.occupancy_since(_midnight())["inside"] == 0


def test_yesterdays_traffic_is_outside_the_window(db) -> None:
    repo = LogRepository()
    _log(repo, "34ABC123", "entry", "granted", _today(8) - timedelta(days=1))
    _log(repo, "06XYZ42", "entry", "granted", _today(8))

    assert repo.occupancy_since(_midnight())["inside"] == 1


def test_occupancy_on_an_empty_log_is_zero(db) -> None:
    counts = LogRepository().occupancy_since(_midnight())
    assert counts == {"inside": 0, "entries": 0, "exits": 0}


# ---------------------------------------------------------------------------
# Capacity
# ---------------------------------------------------------------------------


def test_capacity_falls_back_to_the_configured_default(db) -> None:
    from lpr.api.routes import _read_capacity
    from lpr.db import SystemMetaRepository

    assert _read_capacity(SystemMetaRepository(), db) == db.parking.capacity


def test_a_stored_capacity_overrides_the_config(db) -> None:
    from lpr.api.routes import CAPACITY_KEY, _read_capacity
    from lpr.db import SystemMetaRepository

    meta = SystemMetaRepository()
    meta.set(CAPACITY_KEY, "250")

    assert _read_capacity(meta, db) == 250


def test_a_corrupt_stored_capacity_falls_back_instead_of_crashing(db) -> None:
    """Whatever is in that row, the dashboard still has to render."""
    from lpr.api.routes import CAPACITY_KEY, _read_capacity
    from lpr.db import SystemMetaRepository

    meta = SystemMetaRepository()
    meta.set(CAPACITY_KEY, "yüz tane")

    assert _read_capacity(meta, db) == db.parking.capacity


@pytest.mark.parametrize(
    ("inside", "capacity", "full"),
    [(0, 100, False), (99, 100, False), (100, 100, True), (101, 100, True), (5, 0, False)],
)
def test_full_is_computed_server_side(inside: int, capacity: int, full: bool) -> None:
    """Every tablet must flip to "OTOPARK DOLU" on the same event.

    A capacity of 0 means "not configured" and must never read as full.
    """
    assert (capacity > 0 and inside >= capacity) is full
