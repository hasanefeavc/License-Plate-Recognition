"""Confidence-weighted voting across several reads of the same crop.

Where :mod:`lpr.ocr.voting` aggregates across *frames*, this module aggregates
across the reads produced **within a single frame**: the several enhanced views
of one crop (grayscale, binarised, deskewed, perspective-corrected) and, when
more than one engine is configured, the several engines that saw them.

Why voting rather than argmax
-----------------------------
The recogniser used to keep whichever single candidate scored highest on
``(valid, confidence)``. That throws away the most useful signal available: how
many independent views *agreed*. Glyph confusions are view-dependent -- ``0``
vs ``O`` flips with the binarisation threshold, ``8`` vs ``B`` with the
sharpening -- so the correct reading is the one that keeps recurring across
views, while each particular misreading tends to appear once. A single
over-confident outlier can win an argmax; it cannot win a vote.

Scoring
-------
Ballots are normalised through :func:`lpr.ocr.normalize.normalize_plate`,
grouped by the resulting plate string, and each group scores the **sum of its
members' confidences**. That is a confidence-weighted majority: three agreeing
reads at 0.6 (1.8) beat one emphatic read at 0.9, but three hesitant reads at
0.2 (0.6) do not. Groups one edit apart are merged first, so ``34ABC12`` and
``34A8C12`` reinforce each other instead of splitting the vote.

Grammatical reads always outrank ungrammatical ones, whatever the arithmetic
says -- the same rule the rest of the pipeline uses. This module is **pure
python** (standard library plus ``lpr.contracts``), so it is testable with no
ML stack installed.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from lpr.contracts import PlateRead
from lpr.ocr.normalize import normalize_plate
from lpr.ocr.voting import levenshtein

logger = logging.getLogger(__name__)

__all__ = ["Ballot", "EnsembleRecognizer", "vote"]

_EMPTY = PlateRead(text="", confidence=0.0, raw_text="", valid=False)

#: Two grammatical plates this far apart are the same plate read through
#: different noise, and are merged before counting. One edit only: at distance
#: two the "correction" starts inventing plates that were never on the car.
MERGE_DISTANCE = 1


@dataclass(frozen=True, slots=True)
class Ballot:
    """One raw recogniser output, tagged with where it came from.

    ``source`` identifies the view and engine that produced it (e.g.
    ``"easyocr:gray"``). It exists so one engine reporting the same string from
    four views cannot be mistaken for four independent confirmations when the
    voter reports its telemetry -- and so a debug log can say *which* view read
    the plate that opened the gate.
    """

    text: str
    confidence: float
    source: str = ""


@dataclass(slots=True)
class _Group:
    """Ballots that normalised to the same plate string."""

    read: PlateRead
    score: float = 0.0
    best_confidence: float = 0.0
    sources: list[str] = field(default_factory=list)

    @property
    def votes(self) -> int:
        return len(self.sources)


def _rank(group: _Group) -> tuple[int, float, float]:
    """Ranking key: grammatical first, then summed confidence, then the best single read."""
    return (1 if group.read.valid else 0, group.score, group.best_confidence)


def vote(ballots: Iterable[Ballot]) -> PlateRead:
    """Pick the consensus plate from ``ballots``.

    Returns the winning :class:`~lpr.contracts.PlateRead` with the confidence of
    the strongest single ballot backing it -- not the summed score, which is a
    ranking quantity and not a probability. Downstream thresholds
    (``ocr.min_confidence``) and the multi-frame voter both read that field, so
    it has to keep meaning "how sure was the recogniser about this string".

    Returns an empty, ``valid=False`` read when there is nothing to count.
    Never raises: a failure here would cost a frame, and a frame is not worth
    an exception.
    """
    try:
        groups = _tally(ballots)
    except Exception:  # pragma: no cover - defensive, voting must be total
        logger.debug("ensemble vote failed", exc_info=True)
        return _EMPTY
    if not groups:
        return _EMPTY

    winner = max(groups, key=_rank)
    if len(groups) > 1 and winner.read.valid:
        logger.debug(
            "ensemble: %r won with %.2f over %d rival(s) from %s",
            winner.read.text,
            winner.score,
            len(groups) - 1,
            winner.sources,
        )
    return PlateRead(
        text=winner.read.text,
        confidence=winner.best_confidence,
        raw_text=winner.read.raw_text,
        valid=winner.read.valid,
    )


def _tally(ballots: Iterable[Ballot]) -> list[_Group]:
    """Group ballots by normalised plate string and score each group."""
    groups: dict[str, _Group] = {}

    for index, ballot in enumerate(ballots):
        text = getattr(ballot, "text", "")
        if not text:
            continue
        confidence = _clamp(getattr(ballot, "confidence", 0.0))
        read = normalize_plate(text, confidence)
        # Key ungrammatical reads on their de-noised text too, so repeated junk
        # still aggregates rather than filling the tally with singletons.
        key = read.text or text
        source = getattr(ballot, "source", "") or f"#{index}"

        group = groups.get(key)
        if group is None:
            groups[key] = _Group(
                read=read,
                score=confidence,
                best_confidence=confidence,
                sources=[source],
            )
            continue
        group.score += confidence
        group.best_confidence = max(group.best_confidence, confidence)
        group.sources.append(source)

    return _merge_near_misses(list(groups.values()))


def _merge_near_misses(groups: list[_Group]) -> list[_Group]:
    """Collapse grammatical groups one edit apart onto the stronger spelling.

    Without this, ``34ABC12`` seen twice and ``34A8C12`` seen once are three
    separate one-vote groups and the ensemble has learned nothing. Only
    *grammatical* groups are merged: two ungrammatical strings being similar
    says nothing about which of them is a plate, and merging them would
    manufacture agreement out of noise.
    """
    valid = sorted((g for g in groups if g.read.valid), key=_rank, reverse=True)
    invalid = [g for g in groups if not g.read.valid]

    merged: list[_Group] = []
    for group in valid:
        # Strongest first, so a near-miss always folds into the better spelling.
        host = next(
            (
                candidate
                for candidate in merged
                if levenshtein(candidate.read.text, group.read.text, MERGE_DISTANCE)
                <= MERGE_DISTANCE
            ),
            None,
        )
        if host is None:
            merged.append(group)
            continue
        # Score and sources merge; ``best_confidence`` deliberately does not.
        # The near-miss is evidence that the host spelling is *right*, not
        # evidence about how clearly the host spelling itself was seen, and
        # ``vote`` reports that field as the confidence in the emitted string.
        host.score += group.score
        host.sources.extend(group.sources)

    return merged + invalid


def _clamp(value: float) -> float:
    """Confidence is a probability; keep it in [0, 1] whatever the backend says."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number != number:  # NaN
        return 0.0
    return max(0.0, min(1.0, number))


class EnsembleRecognizer:
    """Pools the ballots of several recognisers into one vote (a ``Recognizer``).

    Each member is asked for its ballots rather than for its verdict, so the
    engines vote on equal footing instead of one being a tie-break for the
    other. A member that raises is dropped for that crop and the vote proceeds
    on the rest: half an ensemble still beats no read at all.

    Members are queried in order and, like the staged views inside a single
    backend, the ensemble stops early once it holds a grammatical read -- so the
    second engine is a cost paid on the hard crops, not on every car.
    """

    def __init__(self, members: Sequence[object], stop_when_valid: bool = True) -> None:
        self._members = [m for m in members if m is not None]
        if not self._members:
            raise ValueError("EnsembleRecognizer needs at least one member recogniser")
        self._stop_when_valid = bool(stop_when_valid)

    @property
    def members(self) -> list[object]:
        return list(self._members)

    def recognize(self, crop: object) -> PlateRead:
        """Best plate read for ``crop``, decided by a vote across the members."""
        ballots: list[Ballot] = []
        for member in self._members:
            ballots.extend(self._ballots_of(member, crop))
            if self._stop_when_valid and ballots and vote(ballots).valid:
                break
        return vote(ballots)

    def warmup(self) -> None:
        """Warm every member; one failing must not stop the others."""
        for member in self._members:
            warmup = getattr(member, "warmup", None)
            if warmup is None:
                continue
            try:
                warmup()
            except Exception:
                logger.warning(
                    "%s warmup failed inside the ensemble", type(member).__name__, exc_info=True
                )

    @staticmethod
    def _ballots_of(member: object, crop: object) -> list[Ballot]:
        """Ballots from one member, falling back to its verdict if it has none.

        A member that predates this interface (or a test double standing in for
        one) only offers ``recognize``; its single answer is admitted as a
        one-ballot contribution rather than being excluded from the vote.
        """
        try:
            ballots_of = getattr(member, "ballots", None)
            if callable(ballots_of):
                return list(ballots_of(crop))
            read = member.recognize(crop)  # type: ignore[attr-defined]
            return [Ballot(read.raw_text or read.text, read.confidence, type(member).__name__)]
        except Exception:
            logger.debug("%s failed on one crop", type(member).__name__, exc_info=True)
            return []

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        names = ", ".join(type(m).__name__ for m in self._members)
        return f"EnsembleRecognizer({names})"
