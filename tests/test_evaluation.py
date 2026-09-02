"""Tests for the accuracy metrics.

Pure python: this module imports nothing heavier than :mod:`lpr.evaluation`, so
the numbers a CI gate depends on are verified on a runner with no torch, no
CUDA and no camera -- which is the whole reason the scoring lives apart from
the script that drives a detector.

The assertions worth reading first are the ones about *not* reporting a number:
a metric that could not be measured must come back ``None``, and a gate must
treat that as a failure. A benchmark that scores an untested property as
perfect is worse than no benchmark, because it is believed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lpr.evaluation import (
    EvalSample,
    Metrics,
    Outcome,
    cer,
    levenshtein,
    load_ground_truth,
    plate_from_filename,
    resolve_truth,
    score,
)


def sample(
    image: str = "a.jpg",
    truth: str = "34ABC123",
    predicted: str = "34ABC123",
    confidence: float = 0.9,
    latency_ms: float = 100.0,
) -> EvalSample:
    return EvalSample(
        image=image,
        truth=truth,
        predicted=predicted,
        confidence=confidence,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# Edit distance and CER
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("34ABC123", "34ABC123", 0),
        ("34ABC123", "34ABC124", 1),
        ("34ABC123", "34ABC12", 1),
        ("34ABC123", "", 8),
        ("", "", 0),
        ("06AB123", "34XY999", 7),
    ],
)
def test_levenshtein(a: str, b: str, expected: int) -> None:
    assert levenshtein(a, b) == expected
    assert levenshtein(b, a) == expected, "edit distance is symmetric"


def test_levenshtein_is_not_capped() -> None:
    """The voter's version stops at max_distance; this one must not.

    A capped distance would floor the error rate of exactly the catastrophic
    reads a benchmark exists to surface -- "GIRIS" read instead of a plate
    would score the same as a one-glyph slip.
    """
    from lpr.ocr.voting import levenshtein as capped

    a, b = "34ABC123", "HOSGELDINIZ"
    assert capped(a, b) == 3, "the voter's version saturates at max_distance + 1"
    assert levenshtein(a, b) == 11


@pytest.mark.parametrize(
    ("predicted", "truth", "expected"),
    [
        ("34ABC123", "34ABC123", 0.0),
        ("34ABC124", "34ABC123", 1 / 8),
        ("", "34ABC123", 1.0),
    ],
)
def test_cer(predicted: str, truth: str, expected: float) -> None:
    assert cer(predicted, truth) == pytest.approx(expected)


def test_cer_can_exceed_one_and_that_is_deliberate() -> None:
    """A read far longer than the plate is worse than every character wrong.

    Clamping to 1.0 would score "the OCR returned the sign above the gate" and
    "the OCR got all seven characters wrong" as equally bad, and they are not:
    the first means the detector cropped the wrong thing.
    """
    assert cer("HOSGELDINIZOTOPARK", "34ABC12") > 1.0
    assert cer("XXXXXXX", "34ABC12") == pytest.approx(1.0)


def test_cer_of_a_negative_sample_counts_spurious_characters() -> None:
    """No truth means no characters to be wrong about -- unless something was
    emitted anyway, and then every character of it is spurious."""
    assert cer("", "") == 0.0
    assert cer("34ABC12", "") == 7.0


# ---------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("truth", "predicted", "expected"),
    [
        ("34ABC12", "34ABC12", Outcome.HIT),
        ("34ABC12", "34ABC13", Outcome.WRONG),
        ("34ABC12", "", Outcome.MISS),
        ("", "34ABC12", Outcome.FALSE_POSITIVE),
        ("", "", Outcome.CORRECT_REJECT),
    ],
)
def test_outcome_classification(truth: str, predicted: str, expected: Outcome) -> None:
    assert sample(truth=truth, predicted=predicted).outcome is expected


def test_a_near_miss_is_wrong_not_partially_right() -> None:
    """The metric that matters is exact match, because the barrier is binary."""
    assert sample(truth="34ABC12", predicted="34ABC13").outcome is Outcome.WRONG
    metrics = score([sample(truth="34ABC12", predicted="34ABC13")])
    assert metrics.plate_accuracy == 0.0
    assert metrics.cer == pytest.approx(1 / 7), "CER still shows it was close"


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def test_score_counts_every_outcome() -> None:
    metrics = score(
        [
            sample("a.jpg", "34ABC12", "34ABC12"),
            sample("b.jpg", "34ABC13", "34ABC13"),
            sample("c.jpg", "06XY123", "06XY124"),
            sample("d.jpg", "35AA11", ""),
            sample("e.jpg", "", "99ZZ99"),
            sample("f.jpg", "", ""),
        ]
    )
    assert (metrics.total, metrics.positives, metrics.negatives) == (6, 4, 2)
    assert (metrics.hits, metrics.wrong, metrics.misses) == (2, 1, 1)
    assert (metrics.false_positives, metrics.correct_rejects) == (1, 1)
    assert metrics.plate_accuracy == pytest.approx(0.5)
    assert metrics.false_positive_rate == pytest.approx(0.5)
    assert metrics.miss_rate == pytest.approx(0.25)


def test_wrong_plate_rate_is_measured_against_emissions_not_samples() -> None:
    """A pipeline that stays quiet when it cannot read is being careful.

    Dividing wrong reads by *every* sample would score that caution as if it
    were accuracy, and would fall as the miss rate rose -- the wrong incentive
    for the one metric that tracks "the barrier opened for the wrong car".
    """
    metrics = score(
        [
            sample("a.jpg", "34ABC12", "34ABC12"),
            sample("b.jpg", "34ABC13", "34XYZ99"),
            sample("c.jpg", "35AA11", ""),
            sample("d.jpg", "36BB22", ""),
        ]
    )
    assert metrics.wrong_plate_rate == pytest.approx(0.5), "1 wrong of 2 emitted"
    assert metrics.plate_accuracy == pytest.approx(0.25), "1 hit of 4 samples"


def test_an_unmeasurable_metric_is_none_not_zero() -> None:
    """The assertion this whole module exists for.

    An evaluation set with no negative samples has not measured the
    false-positive rate. Reporting 0.0 would let a CI gate pass on a test that
    never ran, which is how a benchmark starts lying to the people relying on
    it.
    """
    metrics = score([sample("a.jpg", "34ABC12", "34ABC12")])
    assert metrics.false_positive_rate is None
    assert metrics.negatives == 0

    empty = score([])
    assert empty.plate_accuracy is None
    assert empty.cer is None
    assert empty.wrong_plate_rate is None
    assert empty.latency_p50 is None


def test_worst_samples_are_kept_for_diagnosis() -> None:
    """A metric with no examples attached says something is wrong and not what."""
    metrics = score(
        [
            sample("good.jpg", "34ABC12", "34ABC12"),
            sample("near.jpg", "34ABC13", "34ABC12"),
            sample("awful.jpg", "34ABC14", "HOSGELDINIZ"),
        ],
        keep_worst=2,
    )
    assert len(metrics.worst) == 2
    assert metrics.worst[0].image == "awful.jpg", "worst CER first"


def test_a_perfect_run_keeps_no_failures() -> None:
    metrics = score([sample("a.jpg"), sample("b.jpg", "06XY12", "06XY12")])
    assert metrics.worst == []
    assert metrics.plate_accuracy == 1.0


# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------


def test_latency_percentiles() -> None:
    metrics = score([sample(f"{n}.jpg", latency_ms=float(n)) for n in range(1, 101)])
    assert metrics.latency_mean == pytest.approx(50.5)
    assert metrics.latency_p50 == pytest.approx(50.0)
    assert metrics.latency_p95 == pytest.approx(95.0)


def test_untimed_samples_do_not_drag_the_mean_to_zero() -> None:
    """A frame that failed to load reports 0.0 ms, which is not a measurement."""
    metrics = score([sample("a.jpg", latency_ms=100.0), sample("b.jpg", latency_ms=0.0)])
    assert metrics.latency_mean == pytest.approx(100.0)
    assert len(metrics.latencies_ms) == 1


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def test_metrics_serialise_to_json() -> None:
    """The report is a CI artefact and a regression baseline, so it must round-trip."""
    metrics = score([sample("a.jpg"), sample("b.jpg", "", "34ZZ99")])
    payload = json.loads(json.dumps(metrics.to_dict()))
    assert payload["plate_accuracy"] == 1.0
    assert payload["false_positive_rate"] == 1.0
    assert payload["latency_ms"]["samples"] == 2


def test_unmeasurable_metrics_serialise_as_null() -> None:
    payload = json.loads(json.dumps(score([sample()]).to_dict()))
    assert payload["false_positive_rate"] is None


def test_summary_renders_every_metric() -> None:
    text = score([sample(), sample("b.jpg", "", "")]).summary()
    for label in ("plate accuracy", "CER", "wrong-plate", "false positive", "latency"):
        assert label in text
    assert "n/a" not in text.split("wrong-plate")[0], "measured metrics show numbers"


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("34ABC123.jpg", "34ABC123"),
        ("34ABC123_002.png", "34ABC123"),
        ("34abc123-7.jpeg", "34ABC123"),
        ("06AB12.jpg", "06AB12"),
        # Not plates, and the important half of this table. Without the
        # grammar check `frame_0001.jpg` yields "FRAME": invented ground truth
        # that every correct read is then scored against and fails.
        ("frame_0001.jpg", None),
        ("IMG_1234.jpg", None),
        ("a photo.jpg", None),
        ("2024-05-01T12-00-00.jpg", None),
        # Q, W and X are not on Turkish plates, so this is a bad label too.
        ("06XY12.jpg", None),
        # Province 00 and 82+ do not exist.
        ("00ABC12.jpg", None),
        ("99ABC12.jpg", None),
    ],
)
def test_plate_from_filename(filename: str, expected: str | None) -> None:
    assert plate_from_filename(filename) == expected


def test_a_filename_that_is_not_a_plate_yields_no_label() -> None:
    """The bug this guards: a counter-suffixed word parsed as a plate.

    `frame_0001.jpg` has exactly the shape the pattern looks for -- five to
    nine alphanumerics, an underscore, a number -- and only the Turkish grammar
    separates it from a real plate.
    """
    assert plate_from_filename("frame_0001.jpg") is None
    assert plate_from_filename("plate_0001.jpg") is None
    assert plate_from_filename("34ABC12_0001.jpg") == "34ABC12"


def test_load_ground_truth_csv(tmp_path: Path) -> None:
    path = tmp_path / "truth.csv"
    path.write_text(
        "image,plate\n34ABC12.jpg,34ABC12\nweird_name.jpg,06XY123\nempty.jpg,\n",
        encoding="utf-8",
    )
    truth = load_ground_truth(path)
    assert truth["34ABC12.jpg"] == "34ABC12"
    assert truth["weird_name.jpg"] == "06XY123"
    assert truth["empty.jpg"] == "", "an empty plate is a negative sample"


def test_load_ground_truth_accepts_tsv_and_jsonl(tmp_path: Path) -> None:
    tsv = tmp_path / "truth.tsv"
    tsv.write_text("a.jpg\t34ABC12\nb.jpg\t06XY123\n", encoding="utf-8")
    assert load_ground_truth(tsv) == {"a.jpg": "34ABC12", "b.jpg": "06XY123"}

    jsonl = tmp_path / "truth.jsonl"
    jsonl.write_text(
        '{"image": "a.jpg", "plate": "34ABC12"}\n{"image": "b.jpg", "plate": ""}\n',
        encoding="utf-8",
    )
    assert load_ground_truth(jsonl) == {"a.jpg": "34ABC12", "b.jpg": ""}


def test_load_ground_truth_survives_a_bom_and_a_header(tmp_path: Path) -> None:
    """Excel writes both, and an evaluation set usually passes through Excel."""
    path = tmp_path / "truth.csv"
    path.write_text("﻿image,plate\n34ABC12.jpg,34ABC12\n", encoding="utf-8")
    assert load_ground_truth(path) == {"34ABC12.jpg": "34ABC12"}


def test_ground_truth_keys_on_basename_so_the_set_can_move(tmp_path: Path) -> None:
    path = tmp_path / "truth.csv"
    path.write_text("image,plate\n/old/path/34ABC12.jpg,34ABC12\n", encoding="utf-8")
    assert load_ground_truth(path) == {"34ABC12.jpg": "34ABC12"}


def test_resolve_truth_prefers_the_file_over_the_filename(tmp_path: Path) -> None:
    """A corrections file exists precisely because a filename was wrong."""
    path = tmp_path / "truth.csv"
    path.write_text("image,plate\n34ABC12.jpg,06AB999\n", encoding="utf-8")
    resolved = resolve_truth(["34ABC12.jpg", "35DEF45.jpg"], path)
    assert resolved["34ABC12.jpg"] == "06AB999", "the file wins"
    assert resolved["35DEF45.jpg"] == "35DEF45", "the filename fills the gap"


def test_resolve_truth_omits_unlabelled_images() -> None:
    """Not treated as negatives -- that would manufacture false positives.

    An image nobody labelled has an unknown answer. Scoring it as "should read
    nothing" turns every correct read of it into a false positive and makes the
    security metric worse the more unlabelled data you add.
    """
    resolved = resolve_truth(["34ABC12.jpg", "some photo.jpg"], None)
    assert "34ABC12.jpg" in resolved
    assert "some photo.jpg" not in resolved


# ---------------------------------------------------------------------------
# Regression baseline shape
# ---------------------------------------------------------------------------


def test_a_metrics_object_is_constructible_empty() -> None:
    """CI compares a fresh run against a stored baseline, so the zero state
    must be well defined rather than raising."""
    metrics = Metrics()
    assert metrics.to_dict()["total"] == 0
    assert metrics.summary()


# ---------------------------------------------------------------------------
# Character confusion
# ---------------------------------------------------------------------------


def test_alignment_pairs_characters_by_edit_script_not_position() -> None:
    """A dropped leading zero is one deletion, not a shifted whole string.

    This is the reason the table is aligned rather than zipped: a positional
    pairing would report six substitutions here and bury the one real fault.
    """
    from lpr.evaluation import GAP, align

    assert align("06BZ1234", "6BZ1234") == [
        ("0", GAP),
        ("6", "6"),
        ("B", "B"),
        ("Z", "Z"),
        ("1", "1"),
        ("2", "2"),
        ("3", "3"),
        ("4", "4"),
    ]


def test_alignment_of_two_empty_strings_is_empty() -> None:
    from lpr.evaluation import align

    assert align("", "") == []


def test_a_substitution_is_recorded_in_the_truth_to_prediction_direction() -> None:
    metrics = score([EvalSample("a.jpg", "34ABC12", "34A8C12")])
    assert metrics.confusions[("B", "8")] == 1
    assert ("8", "B") not in metrics.confusions


def test_confusions_rank_by_frequency() -> None:
    metrics = score(
        [
            EvalSample("a.jpg", "06BZ1234", "O6BZ1234"),
            EvalSample("b.jpg", "06AB123", "O6AB123"),
            EvalSample("c.jpg", "34ABC12", "34A8C12"),
        ]
    )
    assert metrics.top_confusions(2) == [("0", "O", 2), ("B", "8", 1)]
    assert metrics.confused_characters == 3


def test_a_miss_contributes_no_confusions() -> None:
    """A read that emitted nothing is not a glyph confusion.

    Counting it would add one deletion per character and swamp the
    substitutions the table exists to rank.
    """
    metrics = score([EvalSample("a.jpg", "34ABC12", "")])
    assert metrics.confusions == {}
    assert metrics.misses == 1


def test_a_negative_sample_contributes_no_confusions() -> None:
    """There is no truth string to align against."""
    metrics = score([EvalSample("a.jpg", "", "34ZZ11")])
    assert metrics.confusions == {}
    assert metrics.false_positives == 1


def test_a_correct_read_contributes_no_confusions() -> None:
    metrics = score([EvalSample("a.jpg", "34ABC12", "34ABC12")])
    assert metrics.confusions == {}
    assert metrics.confused_characters == 0


def test_confusions_are_capped_and_ordered_stably() -> None:
    """Ties break on the pair, so two identical runs print identical reports."""
    metrics = Metrics()
    metrics.confusions.update({("0", "O"): 1, ("1", "I"): 1, ("8", "B"): 1})
    assert metrics.top_confusions(2) == [("0", "O", 1), ("1", "I", 1)]


def test_the_report_serialises_its_confusions() -> None:
    metrics = score([EvalSample("a.jpg", "34ABC12", "34A8C12")])
    payload = json.loads(json.dumps(metrics.to_dict()))
    assert payload["confusions"] == [{"truth": "B", "predicted": "8", "count": 1}]
    assert payload["confused_characters"] == 1


def test_the_summary_names_the_worst_pair() -> None:
    metrics = score(
        [
            EvalSample("a.jpg", "06BZ1234", "O6BZ1234"),
            EvalSample("b.jpg", "06AB123", "O6AB123"),
        ]
    )
    summary = metrics.summary()
    assert "character confusions" in summary
    assert "0 -> O" in summary


def test_a_clean_run_prints_no_confusion_block() -> None:
    metrics = score([EvalSample("a.jpg", "34ABC12", "34ABC12")])
    assert "character confusions" not in metrics.summary()
