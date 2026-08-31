"""Tests for the Turkish plate normalisation layer.

Pure python: this module imports nothing heavier than :mod:`lpr.ocr.normalize`
itself, so it runs in an environment with no ML packages installed.
"""

from __future__ import annotations

import pytest

from lpr.ocr.normalize import (
    CASE_HINTS,
    CONFUSION_MAP,
    TURKISH_LETTERS,
    coerce_positional,
    extract_candidates,
    normalize_plate,
    strip_noise,
    validate,
)

# ---------------------------------------------------------------------------
# Grammar
# ---------------------------------------------------------------------------

# All three real-world formats: 2+1+4, 2+2+3, 2+3+2.
VALID_PLATES = [
    "34A1234",  # province + 1 letter + 4 digits
    "06AB123",  # province + 2 letters + 3 digits
    "35ABC12",  # province + 3 letters + 2 digits
    "01A1234",  # lowest province
    "81Z12",  # highest province, shortest tail
    "16BZ1234",
    "07EFE34",
]

INVALID_PLATES = [
    "",
    "ABC",
    "3412345",  # no letter block
    "34ABCDE",  # no digit block
    "0A1234",  # province is not two digits
    "341234A",  # blocks out of order
    "34ABCD12",  # four letters
    "34A123456",  # five trailing digits
]


@pytest.mark.parametrize("plate", VALID_PLATES)
def test_validate_accepts_real_plates(plate: str) -> None:
    assert validate(plate) is True


@pytest.mark.parametrize("plate", INVALID_PLATES)
def test_validate_rejects_malformed(plate: str) -> None:
    assert validate(plate) is False


@pytest.mark.parametrize(
    ("province", "expected"),
    [
        ("00", False),  # below the range
        ("01", True),  # first province, Adana
        ("34", True),
        ("81", True),  # last province, Duzce
        ("82", False),  # above the range
        ("99", False),
    ],
)
def test_province_bounds(province: str, expected: bool) -> None:
    assert validate(f"{province}ABC12") is expected


@pytest.mark.parametrize("letter", ["Q", "W", "X"])
def test_letters_absent_from_turkish_plates_are_rejected(letter: str) -> None:
    """Q, W and X are not on Turkish plates, so a read containing one is wrong."""
    assert letter not in TURKISH_LETTERS
    assert validate(f"34{letter}12") is False
    assert validate(f"34A{letter}12") is False
    assert normalize_plate(f"34{letter}AB12").valid is False


def test_full_alphabet_is_accepted() -> None:
    for letter in TURKISH_LETTERS:
        assert validate(f"34{letter}1234") is True


# ---------------------------------------------------------------------------
# Noise stripping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("34 ABC 12", "34ABC12"),
        ("34-ABC-12", "34ABC12"),
        ("34.ABC.12", "34ABC12"),
        ("  34abc12  ", "34ABC12"),
        ("TR 34 ABC 12", "34ABC12"),  # euroband country code
        ("TR\n34 ABC 12", "34ABC12"),
        ("34 ABC 12 *", "34ABC12"),
        ("", ""),
        ("!!!", ""),
    ],
)
def test_strip_noise(raw: str, expected: str) -> None:
    assert strip_noise(raw) == expected


def test_strip_noise_keeps_qwx_so_validation_can_reject_them() -> None:
    """Deleting Q/W/X would turn a bad read into a plausible plate."""
    assert strip_noise("34WAB12") == "34WAB12"
    assert normalize_plate("34WAB12").valid is False


def test_strip_noise_folds_turkish_diacritics() -> None:
    assert strip_noise("34 ŞBC 12") == "34SBC12"


# ---------------------------------------------------------------------------
# Positional confusion recovery
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # digit misread as a letter, inside the letter block
        ("34A8C123", "34ABC123"),
        ("34ABC1Z", "34ABC12"),
        ("34ABCIZ", "34ABC12"),
        ("068Z1234", "06BZ1234"),
        # letter misread as a digit, inside the province block
        ("O6BZ1234", "06BZ1234"),
        ("I6S1234", "16S1234"),
        ("S4ABC12", "54ABC12"),
        ("3AABC12", "34ABC12"),
        # letter misread as a digit, inside the tail
        ("34ABCB2", "34ABC82"),
        ("34ABIZ12", "34ABI212"),
        # E/3, the mirror-image pair: E in a digit slot, 3 in a letter slot
        ("34ABC1E", "34ABC13"),
        ("3EABC12", "33ABC12"),
        ("06E1234", "06E1234"),
    ],
)
def test_confusion_map_recovery(raw: str, expected: str) -> None:
    read = normalize_plate(raw, confidence=0.8)
    assert read.text == expected
    assert read.valid is True


def test_confusion_map_is_bidirectional() -> None:
    """Every digit-ward mapping has a letter-ward partner, and vice versa."""
    for source, target in CONFUSION_MAP.items():
        assert len(source) == 1 and len(target) == 1
        assert source.isdigit() != target.isdigit()
    # the canonical pairs both ways round
    for digit, letter in [
        ("0", "O"),
        ("1", "I"),
        ("2", "Z"),
        ("3", "E"),
        ("8", "B"),
        ("5", "S"),
    ]:
        assert CONFUSION_MAP[digit] == letter
        assert CONFUSION_MAP[letter] == digit


@pytest.mark.parametrize(
    ("read", "expected"),
    [
        ("O", "0"),
        ("D", "0"),
        ("Q", "0"),
        ("I", "1"),
        ("L", "1"),
        ("Z", "2"),
        ("E", "3"),
        ("A", "4"),
        ("S", "5"),
        ("G", "6"),
        ("B", "8"),
    ],
)
def test_every_documented_digit_slot_repair_is_available(read: str, expected: str) -> None:
    """The digit-ward half of the table, pinned character by character.

    Both blocks a plate ends in digits -- the province and the tail -- are
    repaired through this map, so a missing entry is a plate the gate silently
    fails to recognise rather than a visible error.
    """
    assert CONFUSION_MAP[read] == expected
    assert coerce_positional(f"{read}4ABC12")[0] == expected
    assert coerce_positional(f"34ABC1{read}")[-1] == expected


@pytest.mark.parametrize(
    ("read", "expected"),
    [("0", "O"), ("1", "I"), ("2", "Z"), ("4", "A"), ("5", "S"), ("6", "G"), ("8", "B")],
)
def test_every_documented_letter_slot_repair_is_available(read: str, expected: str) -> None:
    """And the letter-ward half, in the middle block."""
    assert CONFUSION_MAP[read] == expected
    assert coerce_positional(f"34{read}1234")[2] == expected


# ---------------------------------------------------------------------------
# Case-sensitive hints
# ---------------------------------------------------------------------------


def test_a_lowercase_b_can_be_read_as_a_six() -> None:
    """Upper-casing first would send it down the B -> 8 repair and lose the plate.

    "b4ABC12" upper-cases to "B4ABC12", whose only digit-ward repair is 8, and
    province 84 does not exist -- so the read is discarded. Trying the
    lowercase reading recovers province 64 (Nevsehir).
    """
    assert CASE_HINTS["b"] == "6"
    read = normalize_plate("b4ABC12", confidence=0.9)
    assert read.text == "64ABC12"
    assert read.valid is True


def test_the_hint_never_overrules_a_read_that_already_parses() -> None:
    """The string as the recogniser wrote it always gets the first attempt."""
    # "34ABCb2" parses as-is once b -> B -> 8, so the 6 reading is never reached.
    assert normalize_plate("34ABCb2").text == "34ABC82"
    # And a lowercase b in the *letter* block is simply a letter.
    assert normalize_plate("06bZ1234").text == "06BZ1234"


def test_the_hint_does_not_change_a_read_without_a_lowercase_b() -> None:
    for plate in VALID_PLATES:
        assert normalize_plate(plate.lower()).text == plate


def test_coercion_prefers_the_cheapest_segmentation() -> None:
    """"34A8C123" is one repair away from 2+3+3 but two away from 2+2+4."""
    assert coerce_positional("34A8C123") == "34ABC123"


def test_coercion_never_invents_a_valid_province() -> None:
    """A province outside 01-81 cannot be repaired into a different plate."""
    for bad in ["00ABC12", "82ABC12", "99AB123"]:
        assert normalize_plate(bad).valid is False


def test_coercion_will_not_bend_signage_into_a_plate() -> None:
    """The repair budget is what stops the gate opening for the sign above it.

    Every glyph has a mapping available, so with no cap the coercion turns
    "GIRIS" into "61R15" for four edits and calls it a plate. Real misreads are
    one or two confused glyphs, not four.
    """
    for signage in ["GIRIS", "CIKIS", "OTOPARK", "HOSGELDINIZ", "DIKKAT"]:
        assert normalize_plate(signage).valid is False, signage


def test_coercion_still_repairs_a_genuine_misread() -> None:
    """The budget must not cost us the case it exists to serve."""
    assert normalize_plate("34A8C123").text == "34ABC123"
    assert normalize_plate("34A8C123").valid is True
    assert normalize_plate("O6BZ1234").text == "06BZ1234"
    assert normalize_plate("O6BZ1234").valid is True


def test_coercion_is_idempotent() -> None:
    for plate in VALID_PLATES:
        assert coerce_positional(plate) == plate
        first = normalize_plate(plate)
        second = normalize_plate(first.text)
        assert first.text == plate
        assert second.text == plate
        assert first.valid and second.valid


# ---------------------------------------------------------------------------
# Candidate extraction
# ---------------------------------------------------------------------------


def test_extract_candidates_from_multiline_output() -> None:
    candidates = extract_candidates("TR\n34 ABC 12\nISTANBUL")
    assert "34ABC12" in candidates


def test_extract_candidates_from_run_together_text() -> None:
    candidates = extract_candidates("GIRIS06BZ1234PARK")
    assert "06BZ1234" in candidates


def test_extract_candidates_is_bounded_and_empty_for_junk() -> None:
    assert extract_candidates("") == []
    assert extract_candidates("HOSGELDINIZ") == []
    assert len(extract_candidates("34ABC12 " * 40)) <= 16


def test_normalize_recovers_a_plate_embedded_in_noise() -> None:
    read = normalize_plate("PARK GIRIS\n34 A8C 123\nHOSGELDINIZ", confidence=0.71)
    assert read.text == "34ABC123"
    assert read.valid is True
    assert read.confidence == pytest.approx(0.71)


# ---------------------------------------------------------------------------
# normalize_plate contract
# ---------------------------------------------------------------------------


def test_raw_text_is_never_lost() -> None:
    raw = "  tr 34-a8c-123 \n"
    read = normalize_plate(raw, 0.5)
    assert read.raw_text == raw
    assert read.text == "34ABC123"


def test_failed_read_reports_cleaned_text_and_invalid() -> None:
    read = normalize_plate("HOSGELDINIZ", 0.9)
    assert read.valid is False
    assert read.is_usable is False
    assert read.text == "HOSGELDINIZ"
    assert read.raw_text == "HOSGELDINIZ"


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [(0.5, 0.5), (-1.0, 0.0), (2.0, 1.0), (float("nan"), 0.0)],
)
def test_confidence_is_clamped(confidence: float, expected: float) -> None:
    assert normalize_plate("34ABC12", confidence).confidence == pytest.approx(expected)


@pytest.mark.parametrize("junk", ["", "   ", "\n\n", "!@#$%", "0", "1234567890" * 60])
def test_normalize_never_raises(junk: str) -> None:
    read = normalize_plate(junk)
    assert read.raw_text == junk
    assert isinstance(read.valid, bool)


def test_already_normal_plate_is_a_no_op() -> None:
    read = normalize_plate("34ABC12", 0.99)
    assert read.text == "34ABC12"
    assert read.raw_text == "34ABC12"
    assert read.valid is True
    assert read.is_usable is True
