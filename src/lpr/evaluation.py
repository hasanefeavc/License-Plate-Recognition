"""Accuracy metrics for the recognition pipeline.

The project had 1144 behaviour tests and no way to answer "how often is it
right". Those are different questions, and only the second one can be sold: a
suite that proves the voter emits at ``min_votes`` says nothing about whether
the string it emitted was the plate on the car.

This module is the measurement half. Like :mod:`lpr.ocr.normalize` -- its only
non-stdlib import, and itself pure python -- it needs no ML packages, so the
metrics can be unit-tested and regression-gated in CI on a runner with no
torch, no CUDA and no camera. The
driver that actually runs images through a detector and a recogniser lives in
``scripts/evaluate.py``; everything it needs to *score* what came back is here.

The four numbers, and why these four
------------------------------------
**Plate accuracy** -- exact string match, after normalisation. This is the only
metric that corresponds to what the product does: a plate read as ``34ABC12``
when the car says ``34ABC13`` is not 6/7 correct, it is wrong, and the barrier
either lifts for the wrong vehicle or fails to lift for the right one.

**CER** -- character error rate, edit distance over ground-truth length. Too
forgiving to gate on by itself, and indispensable for diagnosis: it separates
"the OCR is close and one glyph class is confused" from "the detector is
cropping the wrong thing", which look identical in a plate-accuracy number.

**Wrong-plate rate** -- of the reads that produced *something*, how many
produced a grammatical plate that was not the right one. This is the security
metric. A miss is an inconvenience; a confident wrong read that happens to
match a registered plate is a barrier opening for a stranger, which is the
failure the whole voting and whitelist apparatus exists to prevent.

**False-positive rate** -- over images with no plate in them at all, how often
something was emitted anyway. Needs negative samples in the evaluation set to
mean anything, and reports ``None`` rather than ``0.0`` when there are none.
Zero out of zero is not a passing grade.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from lpr.ocr.normalize import validate

__all__ = [
    "GAP",
    "EvalSample",
    "Metrics",
    "Outcome",
    "align",
    "cer",
    "levenshtein",
    "load_ground_truth",
    "plate_from_filename",
    "resolve_truth",
    "score",
]

#: Ground-truth text for an image with deliberately no plate in it. Written in
#: the truth file as an empty value or this sentinel, both accepted.
NEGATIVE = ""

#: Filenames of the shape ``34ABC123.jpg`` or ``34ABC123_002.jpg`` -- the
#: convention nearly every public plate dataset uses. The trailing counter is
#: optional and is not part of the plate.
_FILENAME_PLATE_RE = re.compile(r"^([A-Za-z0-9]{5,9})(?:[_-]\d+)?$")


# ---------------------------------------------------------------------------
# String distance
# ---------------------------------------------------------------------------


def levenshtein(a: str, b: str) -> int:
    """Uncapped edit distance between two strings.

    Deliberately *not* :func:`lpr.ocr.voting.levenshtein`, which stops counting
    at ``max_distance`` because it only ever needs to answer "are these two
    within one edit". A capped distance would silently floor the error rate of
    exactly the bad reads a benchmark exists to surface.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        current = [i]
        for j, ch_b in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,  # deletion
                    current[j - 1] + 1,  # insertion
                    previous[j - 1] + (0 if ch_a == ch_b else 1),  # substitution
                )
            )
        previous = current
    return previous[-1]


#: Stands in for "no character on this side" in an aligned pair: a deletion
#: (a glyph in the truth the reader dropped) or an insertion (a glyph the
#: reader invented). Safe as a sentinel because a normalised plate is only
#: ``A-Z0-9`` -- see :data:`lpr.ocr.normalize.ALLOWLIST` -- so a hyphen can
#: never be a real character on either side.
GAP = "-"


def align(truth: str, predicted: str) -> list[tuple[str, str]]:
    """Character pairs from the cheapest edit script between the two strings.

    Returns ``(truth_char, predicted_char)`` per aligned position, using
    :data:`GAP` on whichever side has no character.

    An edit-script alignment rather than a positional ``zip``, because the two
    strings are routinely different lengths and a zip mis-pairs *everything*
    after the first insertion or deletion: a read that dropped the leading
    ``0`` of ``06BZ1234`` would score as six substitutions instead of the one
    deletion it is, and the resulting confusion table would be noise. Here the
    same read yields exactly ``("0", "-")``.

    Plates are at most nine characters (:data:`lpr.ocr.normalize.MAX_PLATE_LEN`)
    so the full DP table is a few dozen cells; there is no reason to reach for
    the banded variant :func:`levenshtein` uses.
    """
    rows, columns = len(truth), len(predicted)
    # cost[i][j] = edit distance between truth[:i] and predicted[:j]
    cost = [[0] * (columns + 1) for _ in range(rows + 1)]
    for i in range(1, rows + 1):
        cost[i][0] = i
    for j in range(1, columns + 1):
        cost[0][j] = j
    for i in range(1, rows + 1):
        source = truth[i - 1]
        for j in range(1, columns + 1):
            cost[i][j] = min(
                cost[i - 1][j - 1] + (source != predicted[j - 1]),
                cost[i - 1][j] + 1,
                cost[i][j - 1] + 1,
            )

    pairs: list[tuple[str, str]] = []
    i, j = rows, columns
    while i > 0 or j > 0:
        # Substitution/match first, so an equal-cost path prefers pairing two
        # real characters over reporting a deletion next to an insertion.
        if (
            i > 0
            and j > 0
            and cost[i][j] == cost[i - 1][j - 1] + (truth[i - 1] != predicted[j - 1])
        ):
            pairs.append((truth[i - 1], predicted[j - 1]))
            i -= 1
            j -= 1
        elif i > 0 and cost[i][j] == cost[i - 1][j] + 1:
            pairs.append((truth[i - 1], GAP))
            i -= 1
        else:
            pairs.append((GAP, predicted[j - 1]))
            j -= 1
    pairs.reverse()
    return pairs


def cer(predicted: str, truth: str) -> float:
    """Character error rate: edits per ground-truth character.

    Can exceed 1.0 -- a prediction longer than the truth costs one insertion
    per extra character -- and that is left uncapped on purpose. A read that
    returned a whole line of signage instead of a plate should score far worse
    than one that got every character wrong, and clamping to 1.0 would say they
    were equally bad.

    An empty truth (a negative sample) has no characters to be wrong about, so
    it returns 0.0 for an empty prediction and 1.0 per spurious character.
    """
    predicted = predicted or ""
    truth = truth or ""
    if not truth:
        return float(len(predicted))
    return levenshtein(predicted, truth) / len(truth)


# ---------------------------------------------------------------------------
# Samples and outcomes
# ---------------------------------------------------------------------------


class Outcome(StrEnum):
    """What happened on one sample, in the terms the gate cares about.

    A ``StrEnum`` so a report serialises to JSON without a converter and a
    member compares equal to its own value in a test. Requires Python 3.11,
    which ``pyproject.toml`` already floors.
    """

    HIT = "hit"  # positive sample, read correctly
    WRONG = "wrong"  # positive sample, read as a different plate
    MISS = "miss"  # positive sample, nothing emitted
    FALSE_POSITIVE = "false_positive"  # negative sample, something emitted
    CORRECT_REJECT = "correct_reject"  # negative sample, nothing emitted


@dataclass(frozen=True, slots=True)
class EvalSample:
    """One image, what it should read, and what the pipeline said.

    ``predicted`` is the empty string when the pipeline emitted nothing, which
    is a *miss* on a positive sample and a *correct rejection* on a negative
    one. ``truth`` is empty for a negative sample.
    """

    image: str
    truth: str
    predicted: str = ""
    confidence: float = 0.0
    #: Wall time for the whole detect -> OCR -> normalise path, in
    #: milliseconds. Zero when the caller did not time it.
    latency_ms: float = 0.0
    #: How many boxes the detector returned. Diagnostic: a wrong read on a
    #: frame with six detections is a detector problem, not an OCR one.
    detections: int = 0

    @property
    def is_negative(self) -> bool:
        return not self.truth

    @property
    def emitted(self) -> bool:
        return bool(self.predicted)

    @property
    def outcome(self) -> Outcome:
        if self.is_negative:
            return Outcome.FALSE_POSITIVE if self.emitted else Outcome.CORRECT_REJECT
        if not self.emitted:
            return Outcome.MISS
        return Outcome.HIT if self.predicted == self.truth else Outcome.WRONG


@dataclass(slots=True)
class Metrics:
    """Everything :func:`score` measured, ready to print or serialise."""

    total: int = 0
    positives: int = 0
    negatives: int = 0
    hits: int = 0
    wrong: int = 0
    misses: int = 0
    false_positives: int = 0
    correct_rejects: int = 0
    cer_sum: float = 0.0
    latencies_ms: list[float] = field(default_factory=list)
    worst: list[EvalSample] = field(default_factory=list)
    #: ``(truth_char, predicted_char) -> count`` over every misread character
    #: in a positive sample that emitted something. Matches are not counted --
    #: the table is a list of what goes wrong, not a full matrix -- and misses
    #: are excluded entirely: a sample that emitted nothing would contribute
    #: one deletion per character and bury the substitutions that this exists
    #: to rank. Deletions and insertions inside a real read are kept, with
    #: :data:`GAP` on the empty side, because "the reader drops the leading
    #: zero" is a distinct and fixable failure from "the reader confuses O".
    confusions: Counter[tuple[str, str]] = field(default_factory=Counter)

    # -- headline numbers ------------------------------------------------

    @property
    def plate_accuracy(self) -> float | None:
        """Exact matches over positive samples. ``None`` with no positives."""
        return None if not self.positives else self.hits / self.positives

    @property
    def cer(self) -> float | None:
        """Mean character error rate over positive samples."""
        return None if not self.positives else self.cer_sum / self.positives

    @property
    def wrong_plate_rate(self) -> float | None:
        """Wrong reads over the positive samples that emitted anything.

        The denominator is emissions, not samples: a pipeline that stays quiet
        when it cannot read is being careful, and dividing by every sample
        would score that caution as if it were accuracy.
        """
        emitted = self.hits + self.wrong
        return None if not emitted else self.wrong / emitted

    @property
    def false_positive_rate(self) -> float | None:
        """Emissions over negative samples. ``None`` when there are none.

        Not 0.0. An evaluation set with no negatives has not measured this, and
        reporting a perfect score for a test that was never run is how a
        benchmark starts lying.
        """
        return None if not self.negatives else self.false_positives / self.negatives

    @property
    def miss_rate(self) -> float | None:
        return None if not self.positives else self.misses / self.positives

    # -- latency ---------------------------------------------------------

    def _percentile(self, fraction: float) -> float | None:
        if not self.latencies_ms:
            return None
        ordered = sorted(self.latencies_ms)
        if len(ordered) == 1:
            return ordered[0]
        index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
        return ordered[index]

    @property
    def latency_p50(self) -> float | None:
        return self._percentile(0.50)

    @property
    def latency_p95(self) -> float | None:
        return self._percentile(0.95)

    @property
    def latency_mean(self) -> float | None:
        if not self.latencies_ms:
            return None
        return sum(self.latencies_ms) / len(self.latencies_ms)

    # -- character confusion ---------------------------------------------

    def top_confusions(self, limit: int = 20) -> list[tuple[str, str, int]]:
        """The ``limit`` most frequent misreads, as ``(truth, predicted, count)``.

        Ordered by count, then by the pair itself so a tie is stable across
        runs -- a report that reshuffles its own rows between two identical
        evaluations is unusable as a regression baseline.
        """
        ranked = sorted(self.confusions.items(), key=lambda item: (-item[1], item[0]))
        return [(truth, predicted, n) for (truth, predicted), n in ranked[:limit]]

    @property
    def confused_characters(self) -> int:
        """Total misread characters. The denominator for a pair's share."""
        return sum(self.confusions.values())

    # -- output ----------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable, for a CI artefact or a regression baseline."""
        return {
            "total": self.total,
            "positives": self.positives,
            "negatives": self.negatives,
            "hits": self.hits,
            "wrong": self.wrong,
            "misses": self.misses,
            "false_positives": self.false_positives,
            "correct_rejects": self.correct_rejects,
            "plate_accuracy": self.plate_accuracy,
            "cer": self.cer,
            "wrong_plate_rate": self.wrong_plate_rate,
            "false_positive_rate": self.false_positive_rate,
            "miss_rate": self.miss_rate,
            "latency_ms": {
                "mean": self.latency_mean,
                "p50": self.latency_p50,
                "p95": self.latency_p95,
                "samples": len(self.latencies_ms),
            },
            "confusions": [
                {"truth": truth, "predicted": predicted, "count": n}
                for truth, predicted, n in self.top_confusions()
            ],
            "confused_characters": self.confused_characters,
        }

    def summary(self) -> str:
        """A fixed-width block for a terminal or a CI log."""

        def pct(value: float | None) -> str:
            return "  n/a " if value is None else f"{value * 100:6.2f}%"

        def ms(value: float | None) -> str:
            return "   n/a" if value is None else f"{value:6.1f}"

        lines = [
            f"  samples          {self.total}  ({self.positives} positive, "
            f"{self.negatives} negative)",
            f"  plate accuracy  {pct(self.plate_accuracy)}   ({self.hits}/{self.positives} exact)",
            f"  CER             {pct(self.cer)}",
            f"  wrong-plate     {pct(self.wrong_plate_rate)}   "
            f"({self.wrong} of {self.hits + self.wrong} emitted)",
            f"  false positive  {pct(self.false_positive_rate)}   "
            f"({self.false_positives}/{self.negatives} negatives)",
            f"  miss rate       {pct(self.miss_rate)}   ({self.misses}/{self.positives})",
            f"  latency ms      mean {ms(self.latency_mean)}  "
            f"p50 {ms(self.latency_p50)}  p95 {ms(self.latency_p95)}",
        ]

        top = self.top_confusions()
        if top:
            total = self.confused_characters
            lines.append("")
            lines.append(f"  character confusions  (top {len(top)} of {total} misread)")
            for truth, predicted, n in top:
                share = n / total if total else 0.0
                lines.append(f"    {truth} -> {predicted}   {n:5d}   {share * 100:5.1f}%")
        return "\n".join(lines)


def score(samples: Iterable[EvalSample], *, keep_worst: int = 15) -> Metrics:
    """Turn per-image outcomes into the report. Never raises on odd input.

    ``keep_worst`` retains the highest-CER positive samples so the caller can
    print the actual failures. A metric with no examples attached tells you
    that something is wrong and nothing about what.
    """
    metrics = Metrics()
    scored: list[tuple[float, EvalSample]] = []

    for sample in samples:
        metrics.total += 1
        outcome = sample.outcome

        if sample.latency_ms > 0:
            metrics.latencies_ms.append(float(sample.latency_ms))

        if sample.is_negative:
            metrics.negatives += 1
            if outcome is Outcome.FALSE_POSITIVE:
                metrics.false_positives += 1
                scored.append((cer(sample.predicted, sample.truth), sample))
            else:
                metrics.correct_rejects += 1
            continue

        metrics.positives += 1
        error = cer(sample.predicted, sample.truth)
        metrics.cer_sum += error
        if sample.emitted:
            # Only reads that produced something: see Metrics.confusions.
            for truth_char, predicted_char in align(sample.truth, sample.predicted):
                if truth_char != predicted_char:
                    metrics.confusions[(truth_char, predicted_char)] += 1
        if outcome is Outcome.HIT:
            metrics.hits += 1
        elif outcome is Outcome.WRONG:
            metrics.wrong += 1
            scored.append((error, sample))
        else:
            metrics.misses += 1
            scored.append((error, sample))

    scored.sort(key=lambda pair: (-pair[0], pair[1].image))
    metrics.worst = [sample for _, sample in scored[:keep_worst]]
    return metrics


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------


def plate_from_filename(name: str) -> str | None:
    """The plate encoded in an image filename, or ``None``.

    ``34ABC123.jpg`` and ``34ABC123_002.jpg`` both yield ``34ABC123``. This is
    the convention most public plate datasets use, and supporting it means an
    evaluation set can be assembled by naming files correctly rather than by
    maintaining a parallel CSV that drifts out of step with the directory.

    The candidate must satisfy the Turkish plate grammar, not merely look like
    a word with a counter after it. Without that check ``frame_0001.jpg``
    yields ``FRAME`` -- a confident, entirely invented piece of ground truth
    that every correct read would then be scored against and fail. Silently
    manufacturing labels is the worst thing a benchmark can do, because the
    resulting numbers look precise.

    An evaluation set of non-Turkish plates therefore cannot use filenames and
    must pass ``--truth``; that is the right trade for a Turkish ANPR product,
    whose pipeline only ever emits strings this grammar accepts anyway.
    """
    stem = Path(name).stem
    match = _FILENAME_PLATE_RE.match(stem)
    if match is None:
        return None
    candidate = match.group(1).upper()
    return candidate if validate(candidate) else None


def load_ground_truth(path: str | Path) -> dict[str, str]:
    """Read an image -> plate mapping from CSV, TSV or JSONL.

    Three formats, because evaluation sets arrive in all three and converting
    them is a step at which mistakes get made:

    * ``CSV``/``TSV`` -- two columns, ``image`` and ``plate``. A header row is
      detected and skipped.
    * ``JSONL`` -- one ``{"image": ..., "plate": ...}`` object per line.
    * ``JSON`` -- a single object mapping image name to plate.

    An empty plate value marks a **negative** sample: an image with no plate,
    which is what makes the false-positive rate measurable. Only the basename
    is used as the key, so the file survives the directory being moved.
    """
    file_path = Path(path).expanduser()
    text = file_path.read_text(encoding="utf-8-sig", errors="replace")
    mapping: dict[str, str] = {}

    if file_path.suffix.lower() == ".json":
        loaded = json.loads(text)
        if isinstance(loaded, dict):
            for key, value in loaded.items():
                mapping[Path(str(key)).name] = str(value or "").strip().upper()
        return mapping

    for line in text.splitlines():
        row = line.strip()
        if not row or row.startswith("#"):
            continue

        if row.startswith("{"):
            try:
                record = json.loads(row)
            except json.JSONDecodeError:
                continue
            image = record.get("image") or record.get("file") or record.get("filename")
            if image:
                plate = record.get("plate") or record.get("text") or ""
                mapping[Path(str(image)).name] = str(plate).strip().upper()
            continue

        parts = _split_row(row)
        if len(parts) < 2:
            # A one-column file is a list of negatives: images that contain no
            # plate. Useful on its own, and unambiguous -- a positive sample
            # cannot omit the answer.
            mapping[Path(parts[0]).name] = NEGATIVE
            continue

        image, plate = parts[0], parts[1]
        if image.lower() in ("image", "file", "filename", "path"):
            continue  # header row
        mapping[Path(image).name] = plate.strip().strip('"').upper()

    return mapping


def _split_row(row: str) -> list[str]:
    """Split a CSV/TSV row on whichever separator it actually uses."""
    for separator in ("\t", ",", ";"):
        if separator in row:
            return [field.strip() for field in row.split(separator)]
    return [row.strip()]


def resolve_truth(
    images: Sequence[str],
    truth_file: str | Path | None = None,
) -> dict[str, str]:
    """Ground truth for ``images``, from a file or from the filenames.

    The file wins where it has an entry; filenames fill the gaps. That order
    matters: a dataset usually arrives with plate-named files and then acquires
    a corrections file for the ones whose names were wrong, and the corrections
    have to be the ones that count.

    Images with neither a file entry nor a parseable name are omitted rather
    than treated as negatives -- scoring an unlabelled image as "should read
    nothing" would manufacture false positives out of missing labels.
    """
    from_file = load_ground_truth(truth_file) if truth_file else {}
    resolved: dict[str, str] = {}
    for image in images:
        name = Path(image).name
        if name in from_file:
            resolved[name] = from_file[name]
            continue
        derived = plate_from_filename(name)
        if derived is not None:
            resolved[name] = derived
    return resolved
