"""Tests for the nightly OTA check.

Two things are worth testing here and they are separable, which is why the
module splits them: :func:`seconds_until` is pure arithmetic over a clock, and
:meth:`NightlyUpdateJob.run_once` is a decision over an updater. Neither needs
an event loop, a git checkout or a Docker daemon.

The load-bearing assertions are the ones about *not* updating: a job that
installs when it was not authorised to, or that reports "up to date" when it
could not reach the remote, is how a fleet ends up in an unexpected state
overnight with nobody watching.
"""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Any

import pytest

from lpr.scheduler import SOURCE, NightlyUpdateJob, seconds_until
from lpr.updater import RemoteState, UpdateStatus

# ---------------------------------------------------------------------------
# seconds_until
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("now", "expected_hours"),
    [
        (datetime(2026, 8, 27, 2, 0, 0), 1.0),
        (datetime(2026, 8, 27, 23, 30, 0), 3.5),
        (datetime(2026, 8, 27, 3, 30, 0), 23.5),
        (datetime(2026, 8, 27, 12, 0, 0), 15.0),
    ],
)
def test_seconds_until_finds_the_next_occurrence(now: datetime, expected_hours: float) -> None:
    assert seconds_until(3, 0, now) == pytest.approx(expected_hours * 3600)


def test_seconds_until_never_returns_zero() -> None:
    """At exactly the target time the answer is tomorrow, not now.

    A zero would spin the scheduling loop into a tight re-fire cycle for the
    whole of that second.
    """
    at_target = datetime(2026, 8, 27, 3, 0, 0)
    assert seconds_until(3, 0, at_target) == pytest.approx(24 * 3600)
    assert seconds_until(3, 0, at_target) > 0


def test_seconds_until_crosses_midnight() -> None:
    late = datetime(2026, 8, 27, 23, 59, 30)
    # 23:59:30 -> 00:00:00 is 30s, plus 30 minutes to 00:30.
    assert seconds_until(0, 30, late) == pytest.approx(30.5 * 60)


def test_seconds_until_clamps_a_nonsense_time() -> None:
    now = datetime(2026, 8, 27, 12, 0, 0)
    assert seconds_until(99, 99, now) > 0


# ---------------------------------------------------------------------------
# NightlyUpdateJob
# ---------------------------------------------------------------------------


class FakeUpdater:
    def __init__(
        self,
        enabled: bool = True,
        remote: RemoteState | None = None,
        start_error: Exception | None = None,
    ) -> None:
        self.enabled = enabled
        self._remote = remote or RemoteState(checked=True, behind=0, detail="Sistem güncel.")
        self.start_error = start_error
        self.checks = 0
        self.starts = 0

    def check_for_updates(self) -> RemoteState:
        self.checks += 1
        return self._remote

    def start(self) -> UpdateStatus:
        self.starts += 1
        if self.start_error is not None:
            raise self.start_error
        return UpdateStatus(state="running")


class RecordingSink:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def write(
        self, source: str, message: str, level: str = "info", detail: str | None = None
    ) -> int:
        self.rows.append({"source": source, "message": message, "level": level, "detail": detail})
        return len(self.rows)

    @property
    def levels(self) -> list[str]:
        return [row["level"] for row in self.rows]

    def said(self, fragment: str) -> bool:
        return any(fragment.lower() in row["message"].lower() for row in self.rows)


def available(behind: int = 2) -> RemoteState:
    return RemoteState(
        checked=True,
        behind=behind,
        local_commit="aaaaaaa",
        remote_commit="bbbbbbb",
        detail=f"{behind} yeni commit mevcut.",
    )


# -- refusing to act --------------------------------------------------------


def test_a_disabled_updater_is_skipped_silently() -> None:
    """OTA off means the nightly job does nothing and says nothing.

    Writing an audit row every night about a feature nobody enabled would bury
    the rows that matter.
    """
    updater = FakeUpdater(enabled=False)
    sink = RecordingSink()
    assert NightlyUpdateJob(updater, sink).run_once() == "disabled"
    assert updater.checks == 0
    assert sink.rows == []


def test_a_failed_check_is_not_reported_as_up_to_date() -> None:
    """ "Could not tell" and "nothing to do" must never look the same."""
    updater = FakeUpdater(remote=RemoteState(checked=False, detail="Ağ hatası"))
    sink = RecordingSink()

    assert NightlyUpdateJob(updater, sink, auto_update=True).run_once() == "check-failed"
    assert updater.starts == 0
    assert "warning" in sink.levels
    # "güncel" alone would match "Güncelleme denetimi başarısız"; the claim
    # under test is specifically that it never says the system is up to date.
    assert not sink.said("sistem güncel")


def test_an_update_is_not_installed_without_the_auto_update_flag() -> None:
    """Finding an update and installing it are separately authorised."""
    updater = FakeUpdater(remote=available())
    sink = RecordingSink()

    assert NightlyUpdateJob(updater, sink, auto_update=False).run_once() == "available"
    assert updater.starts == 0, "auto_update is off; nothing may be installed"
    assert sink.said("otomatik kurulum kapalı"), "the waiting update must still be reported"


def test_nothing_is_installed_when_the_checkout_is_current() -> None:
    updater = FakeUpdater(remote=RemoteState(checked=True, behind=0, detail="Sistem güncel."))
    assert NightlyUpdateJob(updater, RecordingSink(), auto_update=True).run_once() == "up-to-date"
    assert updater.starts == 0


# -- acting -----------------------------------------------------------------


def test_an_authorised_update_is_started() -> None:
    updater = FakeUpdater(remote=available(behind=3))
    sink = RecordingSink()

    assert NightlyUpdateJob(updater, sink, auto_update=True).run_once() == "started"
    assert updater.starts == 1
    assert sink.said("3 yeni sürüm bulundu")


def test_starting_an_unattended_update_is_recorded_at_warning_level() -> None:
    """An unattended rebuild is not routine; it should stand out in the trail."""
    sink = RecordingSink()
    NightlyUpdateJob(FakeUpdater(remote=available()), sink, auto_update=True).run_once()
    assert "warning" in sink.levels


def test_a_refused_start_is_recorded_not_raised() -> None:
    updater = FakeUpdater(
        remote=available(), start_error=RuntimeError("Zaten devam eden bir güncelleme var.")
    )
    sink = RecordingSink()

    assert NightlyUpdateJob(updater, sink, auto_update=True).run_once() == "start-failed"
    assert sink.said("başlatılamadı")


# -- logging ----------------------------------------------------------------


def test_every_recorded_event_is_tagged_with_the_ota_source() -> None:
    """The admin UI filters on this; an untagged row is an invisible row."""
    sink = RecordingSink()
    NightlyUpdateJob(FakeUpdater(remote=available()), sink, auto_update=True).run_once()
    assert sink.rows
    assert all(row["source"] == SOURCE for row in sink.rows)


def test_the_job_runs_without_an_event_sink() -> None:
    """Logging is a nicety; losing it must not cancel the update."""
    updater = FakeUpdater(remote=available())
    assert NightlyUpdateJob(updater, events=None, auto_update=True).run_once() == "started"
    assert updater.starts == 1


def test_a_sink_that_raises_does_not_stop_the_update() -> None:
    class BrokenSink:
        def write(self, *args: Any, **kwargs: Any) -> int:
            raise RuntimeError("database is locked")

    updater = FakeUpdater(remote=available())
    job = NightlyUpdateJob(updater, BrokenSink(), auto_update=True)
    assert job.run_once() == "started"
    assert updater.starts == 1


def test_a_check_that_raises_is_contained() -> None:
    class ExplodingUpdater(FakeUpdater):
        def check_for_updates(self) -> RemoteState:
            raise RuntimeError("git exploded")

    sink = RecordingSink()
    job = NightlyUpdateJob(ExplodingUpdater(), sink, auto_update=True)
    assert job.run_once() == "check-failed"
    assert "error" in sink.levels


# ---------------------------------------------------------------------------
# Lifespan wiring
# ---------------------------------------------------------------------------


def _app_with(settings: Any) -> Any:
    """A bare app object carrying just what _start_nightly_update reads."""
    import types

    return types.SimpleNamespace(state=types.SimpleNamespace(settings=settings))


def test_no_task_is_started_when_the_nightly_check_is_off(tmp_settings: Any) -> None:
    from lpr.api.main import _start_nightly_update

    tmp_settings.system_update.nightly_check = False
    tmp_settings.system_update.enabled = True
    assert _start_nightly_update(_app_with(tmp_settings), tmp_settings) is None


def test_no_task_is_started_when_ota_itself_is_off(tmp_settings: Any) -> None:
    """The job would refuse every night; not starting it keeps that visible."""
    from lpr.api.main import _start_nightly_update

    tmp_settings.system_update.nightly_check = True
    tmp_settings.system_update.enabled = False
    assert _start_nightly_update(_app_with(tmp_settings), tmp_settings) is None


def test_the_task_starts_when_both_switches_are_on(tmp_settings: Any) -> None:
    """Needs a running loop, so it is driven through asyncio.run."""
    import asyncio

    from lpr.api.main import _start_nightly_update

    tmp_settings.system_update.nightly_check = True
    tmp_settings.system_update.enabled = True
    tmp_settings.system_update.auto_update = False

    async def scenario() -> None:
        app = _app_with(tmp_settings)
        task = _start_nightly_update(app, tmp_settings)
        assert task is not None
        assert task.get_name() == "nightly-update"
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(scenario())


def test_the_scheduled_job_inherits_the_auto_update_flag(tmp_settings: Any) -> None:
    """A misread flag here is the difference between reporting and rebuilding."""
    import asyncio
    from unittest.mock import patch

    from lpr.api.main import _start_nightly_update

    tmp_settings.system_update.nightly_check = True
    tmp_settings.system_update.enabled = True
    tmp_settings.system_update.auto_update = True
    tmp_settings.system_update.check_hour = 4
    tmp_settings.system_update.check_minute = 15

    captured: dict[str, Any] = {}

    async def fake_loop(job: Any, hour: int, minute: int, sleeper: Any = None) -> None:
        captured.update(job=job, hour=hour, minute=minute)

    async def scenario() -> None:
        with patch("lpr.scheduler.nightly_update_loop", fake_loop):
            task = _start_nightly_update(_app_with(tmp_settings), tmp_settings)
            assert task is not None
            await task

    asyncio.run(scenario())
    assert captured["hour"] == 4
    assert captured["minute"] == 15
    assert captured["job"].auto_update is True


def test_the_loop_fires_the_job_and_keeps_going() -> None:
    """One bad night must not silently end the schedule."""
    import asyncio

    from lpr.scheduler import nightly_update_loop

    updater = FakeUpdater(remote=available())
    job = NightlyUpdateJob(updater, RecordingSink(), auto_update=False)
    delays: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        delays.append(seconds)
        if len(delays) >= 3:
            raise asyncio.CancelledError

    async def scenario() -> None:
        with pytest.raises(asyncio.CancelledError):
            await nightly_update_loop(job, 3, 0, sleeper=fake_sleep)

    asyncio.run(scenario())
    assert updater.checks == 2, "the job should have run once per completed sleep"
    assert all(0 < d <= 24 * 3600 for d in delays)


def test_a_job_that_raises_does_not_kill_the_schedule() -> None:
    import asyncio

    from lpr.scheduler import nightly_update_loop

    class ExplodingJob(NightlyUpdateJob):
        def run_once(self) -> str:
            raise RuntimeError("catastrophe")

    job = ExplodingJob(FakeUpdater(), RecordingSink())
    rounds = {"n": 0}

    async def fake_sleep(seconds: float) -> None:
        rounds["n"] += 1
        if rounds["n"] >= 3:
            raise asyncio.CancelledError

    async def scenario() -> None:
        with pytest.raises(asyncio.CancelledError):
            await nightly_update_loop(job, 3, 0, sleeper=fake_sleep)

    asyncio.run(scenario())
    assert rounds["n"] == 3, "the loop must survive a failing job and sleep again"
