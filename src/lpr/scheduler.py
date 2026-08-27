"""Nightly automated OTA check.

Once a day, in the quiet hours, ask the configured git remote whether there is
anything new and -- if automatic updates are switched on -- install it. Every
attempt, skip and failure is written to the ``system_events`` table so an admin
can see in the morning what the machine did at 03:00.

Why a plain asyncio task and not APScheduler
--------------------------------------------
The service already runs exactly this shape of thing: ``_license_watchdog`` is
an ``asyncio`` task that loops, sleeps and never raises out. One scheduled job
does not justify a dependency with its own job store, executor pool and
threading model, and adding one would leave two unrelated scheduling mechanisms
in a codebase that deliberately has one of everything. :func:`seconds_until` is
the entire scheduling calculation, and it is a pure function.

Why this is off by default even when OTA is on
----------------------------------------------
Admin-triggered updating and *unattended* updating are different risks, so they
have separate switches. A human pressing the button is watching the result and
is updating one site. The nightly job updates every site in the fleet at the
same moment, with nobody watching, so a bad commit is a fleet-wide outage
discovered by a phone call rather than a rollback. ``auto_update`` therefore
requires ``enabled`` *and* its own opt-in.

What it will not do
-------------------
It never forces anything. The check is ``git fetch`` (which does not touch the
working tree) and the install is the ordinary :meth:`SystemUpdater.start`
sequence, which is fast-forward-only. A site with local modifications fails the
nightly update in exactly the way it would fail a manual one, and the failure is
recorded rather than worked around.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lpr.updater import SystemUpdater

logger = logging.getLogger(__name__)

__all__ = [
    "NightlyUpdateJob",
    "SOURCE",
    "seconds_until",
]

#: ``system_events.source`` for everything this module records.
SOURCE = "ota"

#: How long to wait between polls of a running update before giving up on
#: seeing it finish. The rebuild normally kills this process long before.
_WATCH_INTERVAL_S = 5.0


class EventSink(Protocol):
    """The slice of :class:`lpr.db.SystemEventRepository` this module uses."""

    def write(
        self, source: str, message: str, level: str = ..., detail: str | None = ...
    ) -> int: ...  # pragma: no cover - protocol


def seconds_until(hour: int, minute: int = 0, now: datetime | None = None) -> float:
    """Seconds from ``now`` until the next local ``hour:minute``.

    Always strictly positive: at exactly 03:00:00 the answer is tomorrow's
    03:00, not zero. A zero would spin the caller's loop into a tight cycle of
    re-firing for the whole of that second.

    Local time on purpose. "Low traffic" is a property of the site's wall
    clock, and an operator setting 03:00 means 03:00 at the barrier, not
    03:00 UTC -- which in Turkey would be 06:00 and a shift change.
    """
    current = now or datetime.now()
    target = current.replace(
        hour=max(0, min(23, int(hour))),
        minute=max(0, min(59, int(minute))),
        second=0,
        microsecond=0,
    )
    if target <= current:
        target += timedelta(days=1)
    return max(1.0, (target - current).total_seconds())


@dataclass(slots=True)
class NightlyUpdateJob:
    """One night's work: check the remote, and install if configured to.

    Split from the loop that schedules it so the decision logic can be tested
    directly -- :meth:`run_once` is an ordinary blocking call with no clock and
    no event loop in it.
    """

    updater: "SystemUpdater"
    events: EventSink | None = None
    auto_update: bool = False

    def record(self, message: str, level: str = "info", detail: str | None = None) -> None:
        """Log to the application log *and* the admin-visible audit trail."""
        log = (
            logger.error
            if level == "error"
            else (logger.warning if level == "warning" else logger.info)
        )
        log("OTA: %s%s", message, f" ({detail})" if detail else "")
        if self.events is None:
            return
        try:
            self.events.write(SOURCE, message, level, detail)
        except Exception:  # pragma: no cover - the sink already swallows
            logger.debug("Sistem olayı yazılamadı", exc_info=True)

    def run_once(self) -> str:
        """Do one night's check. Returns a short outcome tag, for tests and logs.

        Outcomes: ``disabled``, ``check-failed``, ``up-to-date``,
        ``available`` (found, but auto-install is off), ``started``,
        ``start-failed``.
        """
        if not getattr(self.updater, "enabled", False):
            logger.debug("OTA devre dışı, gecelik denetim atlandı")
            return "disabled"

        try:
            remote = self.updater.check_for_updates()
        except Exception as exc:  # pragma: no cover - check_for_updates is total
            self.record("Güncelleme denetimi başarısız.", "error", str(exc))
            return "check-failed"

        if not remote.checked:
            # Could not tell -- which is not the same as "nothing to do", and
            # must not be reported as though the site were up to date.
            self.record("Güncelleme denetimi başarısız.", "warning", remote.detail)
            return "check-failed"

        if not remote.update_available:
            self.record("Gecelik denetim: sistem güncel.", "info", remote.detail)
            return "up-to-date"

        short = (remote.remote_commit or "")[:7]
        found = f"{remote.behind} yeni sürüm bulundu ({short})."

        if not self.auto_update:
            # Found something, but installing it was not authorised. Saying so
            # is the point: an admin should see in the morning that an update
            # is waiting for them.
            self.record(f"{found} Otomatik kurulum kapalı.", "info", remote.detail)
            return "available"

        self.record(f"{found} Otomatik güncelleme başlatılıyor.", "warning")
        try:
            self.updater.start()
        except RuntimeError as exc:
            # Already running, or disabled between the check and here.
            self.record("Otomatik güncelleme başlatılamadı.", "warning", str(exc))
            return "start-failed"
        return "started"


async def nightly_update_loop(
    job: NightlyUpdateJob,
    hour: int,
    minute: int = 0,
    sleeper: Any = None,
) -> None:
    """Run ``job`` every day at ``hour:minute``, forever. Never raises out.

    ``sleeper`` exists for the tests; production passes nothing and gets
    :func:`asyncio.sleep`.
    """
    sleep = sleeper or asyncio.sleep
    while True:
        try:
            await sleep(seconds_until(hour, minute))
            # The job blocks (git, then a rebuild), so it must not run on the
            # event loop -- the API keeps serving right up until compose
            # replaces the container.
            await asyncio.to_thread(job.run_once)
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            raise
        except Exception:  # pragma: no cover - defensive
            logger.exception("Gecelik güncelleme görevi başarısız")
