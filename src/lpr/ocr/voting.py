"""Multi-frame vote aggregation.

A single frame is never trusted. A plate is emitted only once several reads,
clustered in time, agree on it. This is the single highest-value accuracy
component in the pipeline: it removes one-off misreads that no amount of
per-frame tuning can, because a glyph confused on frame *n* is usually read
correctly on frame *n+1*, while the *correct* answer is the one that keeps
recurring.

Like :mod:`lpr.ocr.normalize` this module is **pure python** -- standard
library plus ``lpr.contracts`` only -- so it is testable without any ML
dependency installed.

Design
------
* One bounded deque of recent reads per camera (``voting.window`` entries).
* Track awareness: when the detector supplies a ByteTrack ``track_id``, reads
  that share an id are the *same physical plate* and are merged unconditionally
  -- a stronger and cheaper signal than any string comparison, and one that
  works on spellings too far apart for the Levenshtein merge below. The same
  ids gate OCR: once a track has been decided (or has burned through
  ``max_track_attempts`` reads without confirming anything), the pipeline stops
  paying for EasyOCR on it. Everything degrades cleanly to the text-only
  behaviour when ``track_id`` is ``None``.
* Entries older than ``voting.ttl_s`` expire, so confirmation must come from
  reads clustered in time rather than accumulated across a whole shift.
* Near-miss merging: two candidates one edit apart that both satisfy the
  Turkish grammar are the same plate seen through different noise, so they
  collapse onto the higher-confidence spelling *before* counting. Without
  this, "34ABC12" x1 and "34A8C12" x1 never reach ``min_votes`` together.
* Ranking is by summed confidence among the candidates that reached
  ``min_votes``, not by raw count -- three hesitant reads should not outrank
  two emphatic ones.
* After emitting, the plate is suppressed on that camera for
  ``voting.cooldown_s`` and its votes are dropped, so a car idling at the gate
  does not re-fire the relay every second.
* Every public method takes an internal lock: the orchestrator submits from
  one thread per camera.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from lpr.contracts import PlateRead
from lpr.ocr.normalize import validate

if TYPE_CHECKING:
    from lpr.config import Settings

logger = logging.getLogger(__name__)

__all__ = ["MultiFrameVoter", "levenshtein", "build_voter"]

#: OCR passes a single track may cost before it is muted for ``cooldown_s``.
#: A plate that has been read this many times without ever confirming is a
#: plate this camera cannot read (bad angle, glare, dirt); retrying it every
#: frame only starves the tracks that *can* be read.
DEFAULT_MAX_TRACK_ATTEMPTS = 12

#: How long a track's state outlives its last sighting. Long enough to cover a
#: short occlusion, short enough that a parked car's state is eventually freed.
DEFAULT_TRACK_TTL_S = 30.0


def levenshtein(a: str, b: str, max_distance: int = 2) -> int:
    """Edit distance between ``a`` and ``b``, capped at ``max_distance``.

    Small local implementation so the voter stays dependency-free. Returns
    ``max_distance + 1`` as soon as the true distance is known to exceed the
    cap, which makes the common "these two strings are nothing alike" case
    O(1) on the length check alone.
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        current = [i]
        best_in_row = i
        for j, ch_b in enumerate(b, start=1):
            cost = 0 if ch_a == ch_b else 1
            value = min(
                previous[j] + 1,  # deletion
                current[j - 1] + 1,  # insertion
                previous[j - 1] + cost,  # substitution
            )
            current.append(value)
            best_in_row = min(best_in_row, value)
        if best_in_row > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


@dataclass(frozen=True, slots=True)
class _Vote:
    text: str
    confidence: float
    ts: float
    track_id: int | None = None


@dataclass(slots=True)
class _Candidate:
    """One merged group of near-identical reads."""

    text: str
    votes: int = 0
    weight: float = 0.0
    members: set[str] = None  # type: ignore[assignment]
    tracks: set[int] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.members is None:
            self.members = {self.text}
        if self.tracks is None:
            self.tracks = set()


@dataclass(slots=True)
class _TrackState:
    """What the voter knows about one ``(camera, track_id)`` pair."""

    last_seen: float = 0.0
    attempts: int = 0  # OCR passes spent on this track since the last mute
    muted_until: float = 0.0  # no OCR before this monotonic timestamp
    plate: str | None = None  # set once the track produced a decision


class MultiFrameVoter:
    """Confidence-weighted, time-windowed vote aggregator (a ``Voter``).

    Args:
        window: how many recent reads to keep per camera.
        min_votes: occurrences needed inside the live window before emitting.
            Defaults to 2, matching ``voting.min_votes``; see
            :class:`lpr.config.VotingConfig` for why it is not 3.
        ttl_s: age after which a read stops counting.
        cooldown_s: per (camera, plate) suppression after an emission.
        merge_distance: Levenshtein radius for near-miss merging (1 = the
            classic single-glyph misread; 0 disables merging).
        max_track_attempts: OCR passes one tracked plate may cost before it is
            muted for ``cooldown_s`` (0 disables the cap).
        track_ttl_s: how long a track's state survives after its last sighting.
        clock: injectable monotonic clock, so tests can drive time directly
            instead of sleeping.
    """

    def __init__(
        self,
        window: int = 5,
        min_votes: int = 2,
        ttl_s: float = 4.0,
        cooldown_s: float = 10.0,
        merge_distance: int = 1,
        max_track_attempts: int = DEFAULT_MAX_TRACK_ATTEMPTS,
        track_ttl_s: float = DEFAULT_TRACK_TTL_S,
        clock: Callable[[], float] = time.monotonic,
        on_vote: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.window = max(1, int(window))
        self.min_votes = max(1, int(min_votes))
        self.ttl_s = max(0.0, float(ttl_s))
        self.cooldown_s = max(0.0, float(cooldown_s))
        self.merge_distance = max(0, int(merge_distance))
        self.max_track_attempts = max(0, int(max_track_attempts))
        self.track_ttl_s = max(0.0, float(track_ttl_s))
        self._clock = clock
        #: Optional sink for live vote telemetry, set by the orchestrator so
        #: the GUI can watch a plate accumulate votes in real time. Kept as a
        #: plain callable taking a dict: this module stays pure python and
        #: knows nothing about the API, the WebSocket layer or contracts.
        self.on_vote = on_vote
        self._lock = threading.RLock()
        self._votes: dict[str, deque[_Vote]] = {}
        self._cooldowns: dict[tuple[str, str], float] = {}
        self._tracks: dict[tuple[str, int], _TrackState] = {}

        if self.min_votes > self.window:
            logger.warning(
                "voting.min_votes (%d) exceeds voting.window (%d); no plate can "
                "ever be confirmed. Clamping min_votes to the window size.",
                self.min_votes,
                self.window,
            )
            self.min_votes = self.window

    # -- construction --------------------------------------------------

    @classmethod
    def from_settings(cls, settings: "Settings | None" = None) -> "MultiFrameVoter":
        """Build from ``settings.voting`` (loads the singleton when omitted)."""
        if settings is None:
            from lpr.config import get_settings

            settings = get_settings()
        cfg = settings.voting
        return cls(
            window=cfg.window,
            min_votes=cfg.min_votes,
            ttl_s=cfg.ttl_s,
            cooldown_s=cfg.cooldown_s,
            # getattr: an older config.yaml without the tracking keys still works.
            max_track_attempts=getattr(
                cfg, "max_track_attempts", DEFAULT_MAX_TRACK_ATTEMPTS
            ),
            track_ttl_s=getattr(cfg, "track_ttl_s", DEFAULT_TRACK_TTL_S),
        )

    # -- Voter protocol ------------------------------------------------

    def submit(
        self, camera: str, read: PlateRead, track_id: int | None = None
    ) -> str | None:
        """Record one read; return a plate string only once it is confirmed.

        Unusable reads (invalid grammar or empty text) are dropped without
        being counted -- garbage must not dilute or win a vote. Returns
        ``None`` in every case except a fresh confirmation.

        ``track_id`` is optional: pass the detector's tracker identity to let
        reads of the same physical plate reinforce each other regardless of
        spelling; omit it and the classic text-based voting applies unchanged.
        """
        if read is None or not read.is_usable:
            return None

        text = read.text
        confidence = _clamp(read.confidence)
        track = None if track_id is None else int(track_id)
        now = self._clock()

        with self._lock:
            self._expire_cooldowns(now)

            if (camera, text) in self._cooldowns:
                logger.debug("vote for %s on %s suppressed by cooldown", text, camera)
                return None

            bucket = self._votes.setdefault(camera, deque(maxlen=self.window))
            bucket.append(
                _Vote(text=text, confidence=confidence, ts=now, track_id=track)
            )
            self._prune(bucket, now)

            winner = self._winner(bucket)
            if winner is None:
                leader = next(iter(self._tally(bucket)), None)
                emit = (
                    {
                        "kind": "vote",
                        "camera": camera,
                        "plate": leader.text,
                        "confidence": confidence,
                        "votes": leader.votes,
                        "needed": self.min_votes,
                        "weight": round(leader.weight, 4),
                        "track_id": track,
                        "confirmed": False,
                    }
                    if leader is not None
                    else None
                )
                if emit is not None:
                    self._notify(emit)
                return None

            # Emit, then forget every read that fed this decision so the next
            # confirmation has to be earned again from scratch.
            self._cooldowns[(camera, winner.text)] = now + self.cooldown_s
            remaining = [v for v in bucket if v.text not in winner.members]
            bucket.clear()
            bucket.extend(remaining)

            # The tracks behind the winning group have said all they have to
            # say; mute them so the confirmation does not cost another OCR pass
            # on every following frame while the car is still under the camera.
            for track_key in winner.tracks:
                state = self._tracks.setdefault((camera, track_key), _TrackState())
                state.last_seen = now
                state.muted_until = max(state.muted_until, now + self.cooldown_s)

            logger.info(
                "plate confirmed on %s: %s (%d votes, weight %.2f, tracks %s)",
                camera,
                winner.text,
                winner.votes,
                winner.weight,
                sorted(winner.tracks) or "-",
            )
            self._notify(
                {
                    "kind": "vote",
                    "camera": camera,
                    "plate": winner.text,
                    "confidence": confidence,
                    "votes": winner.votes,
                    "needed": self.min_votes,
                    "weight": round(winner.weight, 4),
                    "track_id": track,
                    "confirmed": True,
                }
            )
            return winner.text

    def _notify(self, payload: dict[str, Any]) -> None:
        """Hand one telemetry event to ``on_vote``, if anyone is listening.

        Called with the voter's lock held (it is an RLock, and the sink is a
        non-blocking queue put), and deliberately swallows everything: a
        broken telemetry consumer must never stop a gate from opening.
        """
        sink = self.on_vote
        if sink is None:
            return
        try:
            sink(payload)
        except Exception:  # pragma: no cover - telemetry is never load-bearing
            logger.debug("vote telemetry sink failed", exc_info=True)

    def reset(self, camera: str) -> None:
        """Drop all state for ``camera`` (votes, cooldowns and tracks)."""
        with self._lock:
            self._votes.pop(camera, None)
            for key in [k for k in self._cooldowns if k[0] == camera]:
                del self._cooldowns[key]
            for track_key in [k for k in self._tracks if k[0] == camera]:
                del self._tracks[track_key]

    # -- TrackAwareVoter protocol ---------------------------------------

    def should_recognize(self, camera: str, track_id: int | None) -> bool:
        """Is it worth running OCR on this track right now?

        ``True`` for every untracked detection, so a detector without tracking
        (or a box the tracker has not associated yet) behaves exactly as
        before. For a tracked plate the answer is ``False`` once it has been
        decided, or while it is muted after a confirmation or after burning
        through ``max_track_attempts`` fruitless reads.

        Also refreshes the track's liveness: a track the pipeline keeps asking
        about is a track that is still in view, and must not be expired.
        """
        if track_id is None:
            return True

        now = self._clock()
        key = (camera, int(track_id))
        with self._lock:
            self._expire_tracks(now)

            state = self._tracks.get(key)
            if state is None:
                self._tracks[key] = _TrackState(last_seen=now)
                return True

            state.last_seen = now

            if state.plate is not None:
                # Already acted on. ByteTrack ids are not recycled while the
                # process runs, so this track cannot be a different car later.
                return False

            if now < state.muted_until:
                return False

            if self.max_track_attempts and state.attempts >= self.max_track_attempts:
                state.muted_until = now + self.cooldown_s
                state.attempts = 0
                logger.debug(
                    "track %s on %s hit %d unproductive reads; muting for %.1fs",
                    track_id,
                    camera,
                    self.max_track_attempts,
                    self.cooldown_s,
                )
                return False

            return True

    def note_recognized(self, camera: str, track_id: int | None) -> None:
        """Charge one OCR pass to this track. No-op when untracked."""
        if track_id is None:
            return
        now = self._clock()
        with self._lock:
            state = self._tracks.setdefault((camera, int(track_id)), _TrackState())
            state.last_seen = now
            state.attempts += 1

    def note_decision(self, camera: str, track_id: int | None, plate: str) -> None:
        """Record that this track produced ``plate`` and needs no more OCR."""
        if track_id is None:
            return
        now = self._clock()
        with self._lock:
            state = self._tracks.setdefault((camera, int(track_id)), _TrackState())
            state.last_seen = now
            state.plate = plate
            state.muted_until = max(state.muted_until, now + self.cooldown_s)
        logger.debug("track %s on %s decided as %s", track_id, camera, plate)

    # -- introspection, used by the API/GUI status views ----------------

    def pending(self, camera: str) -> list[tuple[str, int, float]]:
        """Live candidates for ``camera`` as ``(text, votes, weight)``.

        Sorted best-first using the same ranking ``submit`` applies. Purely
        diagnostic; never mutates the outcome.
        """
        with self._lock:
            bucket = self._votes.get(camera)
            if not bucket:
                return []
            self._prune(bucket, self._clock())
            ranked = self._tally(bucket)
            return [(c.text, c.votes, round(c.weight, 4)) for c in ranked]

    def tracked(self, camera: str) -> list[tuple[int, int, str | None]]:
        """Live tracks for ``camera`` as ``(track_id, ocr_attempts, plate)``.

        Diagnostic only -- how many OCR passes each plate in view has cost and
        whether it has already been decided.
        """
        with self._lock:
            self._expire_tracks(self._clock())
            return sorted(
                (key[1], state.attempts, state.plate)
                for key, state in self._tracks.items()
                if key[0] == camera
            )

    def reset_all(self) -> None:
        """Drop every camera's state."""
        with self._lock:
            self._votes.clear()
            self._cooldowns.clear()
            self._tracks.clear()

    # -- internals -----------------------------------------------------

    def _prune(self, bucket: "deque[_Vote]", now: float) -> None:
        """Drop entries older than the TTL. Called with the lock held."""
        if self.ttl_s <= 0:
            return
        cutoff = now - self.ttl_s
        while bucket and bucket[0].ts < cutoff:
            bucket.popleft()

    def _expire_cooldowns(self, now: float) -> None:
        """Drop elapsed suppressions. Called with the lock held."""
        expired = [key for key, until in self._cooldowns.items() if until <= now]
        for key in expired:
            del self._cooldowns[key]

    def _expire_tracks(self, now: float) -> None:
        """Forget tracks not seen for ``track_ttl_s``. Called with the lock held."""
        if self.track_ttl_s <= 0:
            return
        cutoff = now - self.track_ttl_s
        stale = [key for key, state in self._tracks.items() if state.last_seen < cutoff]
        for key in stale:
            del self._tracks[key]

    def _tally(self, bucket: "deque[_Vote]") -> list[_Candidate]:
        """Merge near-misses and rank candidates best-first.

        Grouping is seeded by total confidence, so the strongest spelling
        becomes the representative and weaker variants fold into it. Two
        spellings merge when either

        * they were read off the *same tracked object* -- ground truth, so it
          wins over any string heuristic and applies at any edit distance; or
        * they are within ``merge_distance`` edits of each other, the
          text-only fallback used when there is no tracking.
        """
        totals: dict[str, tuple[int, float]] = {}
        text_tracks: dict[str, set[int]] = {}
        for vote in bucket:
            count, weight = totals.get(vote.text, (0, 0.0))
            totals[vote.text] = (count + 1, weight + vote.confidence)
            if vote.track_id is not None:
                text_tracks.setdefault(vote.text, set()).add(vote.track_id)

        order = sorted(totals.items(), key=lambda kv: (-kv[1][1], -kv[1][0], kv[0]))

        groups: list[_Candidate] = []
        for text, (count, weight) in order:
            tracks = text_tracks.get(text, set())
            target: _Candidate | None = None

            for group in groups:
                if tracks and group.tracks & tracks:
                    target = group
                    break

            if target is None and self.merge_distance > 0 and validate(text):
                for group in groups:
                    if not validate(group.text):
                        continue
                    # Two candidates with tracks that never overlap are two
                    # different objects in frame. Similar spelling (two cars
                    # from the same fleet, consecutive registrations) must not
                    # collapse them.
                    if tracks and group.tracks and tracks.isdisjoint(group.tracks):
                        continue
                    if levenshtein(group.text, text, self.merge_distance) <= self.merge_distance:
                        target = group
                        break

            if target is None:
                groups.append(
                    _Candidate(
                        text=text,
                        votes=count,
                        weight=weight,
                        members={text},
                        tracks=set(tracks),
                    )
                )
            else:
                target.votes += count
                target.weight += weight
                target.members.add(text)
                target.tracks |= tracks
                logger.debug("merged near-miss %r into %r", text, target.text)

        groups.sort(key=lambda c: (-c.weight, -c.votes, c.text))
        return groups

    def _winner(self, bucket: "deque[_Vote]") -> _Candidate | None:
        """Highest-weight candidate that has reached ``min_votes``, if any."""
        qualified = [c for c in self._tally(bucket) if c.votes >= self.min_votes]
        return qualified[0] if qualified else None


def _clamp(value: float) -> float:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return 0.0
    if num != num:  # NaN
        return 0.0
    return max(0.0, min(1.0, num))


def build_voter(settings: "Settings | None" = None) -> MultiFrameVoter:
    """Construct the configured voter. See :meth:`MultiFrameVoter.from_settings`."""
    return MultiFrameVoter.from_settings(settings)
