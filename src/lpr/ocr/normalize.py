"""Turkish plate text normalisation.

This module is the accuracy layer that sits between a raw OCR string and the
rest of the system. It is deliberately **pure python**: no numpy, no cv2, no
ML packages, nothing but the standard library and ``lpr.contracts``. That
keeps it importable (and unit-testable) anywhere -- CI without GPU wheels, the
GUI client, a REPL.

Domain rules implemented here
-----------------------------
A Turkish civilian plate is::

    <province: 01-81> <letters: 1-3> <digits: 2-4>

    34 ABC 12      34 AB 123      34 A 1234

The canonical grammar is :data:`PLATE_RE`. The letter block may only use the
Turkish plate alphabet :data:`TURKISH_LETTERS` -- ``Q``, ``W`` and ``X`` do not
appear on Turkish plates, and neither do the diacritic letters (Ç, Ğ, İ, Ö, Ş,
Ü), so a read containing one of them is either an OCR error or not a plate.

Why positional coercion matters
-------------------------------
OCR engines confuse whole classes of glyphs: ``0``/``O``/``D``/``Q``,
``1``/``I``/``L``, ``8``/``B``, ``5``/``S``, ``2``/``Z``, ``4``/``A``,
``6``/``G``, ``7``/``T``. Applying a global substitution table is
self-defeating -- fixing ``O`` -> ``0`` in the province block breaks the
letter block. Because the plate grammar pins the *class* of every position
(digits, letters, digits) the map can be applied **directionally**, which is
where most real-world recognition error is recovered:

    "O6BZ1234"  ->  "06BZ1234"     (letter O in a digit slot)
    "34A8C123"  ->  "34ABC123"     (digit 8 in a letter slot)

Nothing here ever raises on bad input; the worst case is an unchanged string
and ``valid=False``.
"""

from __future__ import annotations

import logging
import re
import string

from lpr.contracts import PlateRead

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Alphabet and grammar
# ---------------------------------------------------------------------------

#: Letters that can legally appear on a Turkish plate (no Q/W/X, no diacritics).
TURKISH_LETTERS: str = "ABCDEFGHIJKLMNOPRSTUVYZ"

#: Every character the grammar can contain. Matches ``settings.ocr.allowlist``.
ALLOWLIST: str = TURKISH_LETTERS + string.digits

#: Characters kept by :func:`strip_noise`.
#:
#: Note this is *wider* than :data:`ALLOWLIST`: it also keeps Q, W and X.
#: Deleting them would silently turn a bogus read ("34QAB12") into a
#: valid-looking plate ("34AB12"), i.e. manufacture a false positive. They are
#: kept so :func:`validate` can reject them honestly. The narrow
#: :data:`ALLOWLIST` is what constrains the *recogniser* (EasyOCR's
#: ``allowlist=`` argument), which is the right place to suppress them.
_KEEP: frozenset[str] = frozenset(string.ascii_uppercase + string.digits)

#: Canonical grammar, applied to the stripped uppercase string.
PLATE_RE: re.Pattern[str] = re.compile(r"^(0[1-9]|[1-7][0-9]|8[01])([A-Z]{1,3})([0-9]{2,4})$")

#: Looser pattern used when scanning free-form (possibly multi-line) OCR text.
LOOSE_PLATE_RE: re.Pattern[str] = re.compile(r"\b(\d{2}\s?[A-Z]{1,3}\s?\d{1,4})\b")

#: Overlapping scan for plate-shaped substrings inside a de-noised string.
_SUBSTRING_RE: re.Pattern[str] = re.compile(r"(?=(\d{2}[A-Z]{1,3}\d{2,4}))")

#: Euroband / country-code fragments that sit next to the plate number itself.
_BAND_RE: re.Pattern[str] = re.compile(r"\bTR\b")

#: Turkish diacritics folded to their ASCII base before anything else runs.
_FOLD: dict[str, str] = {
    "Ç": "C", "Ğ": "G", "İ": "I", "I": "I", "Ö": "O", "Ş": "S", "Ü": "U",
    "ç": "C", "ğ": "G", "ı": "I", "ö": "O", "ş": "S", "ü": "U",
    "Â": "A", "Î": "I", "Û": "U",
}

# Total length bounds of a plausible plate string: 2 + 1 + 2 = 5 .. 2 + 3 + 4 = 9
MIN_PLATE_LEN = 5
MAX_PLATE_LEN = 9

#: Upper bound on what :func:`extract_candidates` returns, so a wall of OCR
#: text cannot turn into an unbounded candidate list.
MAX_CANDIDATES = 16

# A substring needing more than this many glyph repairs is not a plate we are
# willing to guess at.
_MAX_REPAIR_COST = 2

# ---------------------------------------------------------------------------
# Confusion map
# ---------------------------------------------------------------------------

#: Bidirectional glyph-confusion table, keyed by the character actually read.
#:
#: Letter keys map to the digit they are mistaken for, digit keys map to the
#: letter they are mistaken for. The two key sets are disjoint, so one dict
#: serves both directions and the *position* decides which way it is applied
#: (see :func:`coerce_positional`).
CONFUSION_MAP: dict[str, str] = {
    # letter read where a digit belongs
    "O": "0",
    "D": "0",
    "Q": "0",
    "I": "1",
    "L": "1",
    "Z": "2",
    "A": "4",
    "S": "5",
    "G": "6",
    "T": "7",
    "B": "8",
    # digit read where a letter belongs
    "0": "O",
    "1": "I",
    "2": "Z",
    "4": "A",
    "5": "S",
    "6": "G",
    "7": "T",
    "8": "B",
}

#: Derived one-way views, handy for callers and for tests.
TO_DIGIT: dict[str, str] = {k: v for k, v in CONFUSION_MAP.items() if v.isdigit()}
TO_LETTER: dict[str, str] = {k: v for k, v in CONFUSION_MAP.items() if v.isalpha()}

# Cost model used to pick between competing segmentations. Lower is better.
_COST_EXACT = 0  # character already has the right class
_COST_MAPPED = 1  # character fixed through CONFUSION_MAP
_COST_BAD = 4  # character cannot be repaired at all

__all__ = [
    "ALLOWLIST",
    "CONFUSION_MAP",
    "LOOSE_PLATE_RE",
    "PLATE_RE",
    "TO_DIGIT",
    "TO_LETTER",
    "TURKISH_LETTERS",
    "coerce_positional",
    "extract_candidates",
    "normalize_plate",
    "strip_noise",
    "validate",
]


# ---------------------------------------------------------------------------
# Cleaning
# ---------------------------------------------------------------------------


def strip_noise(raw: str) -> str:
    """Reduce a raw OCR string to bare uppercase ``A-Z0-9``.

    Removes whitespace, hyphens, dots, slashes, the blue euroband's ``TR``
    country code and any other character outside ``A-Z0-9``. Turkish
    diacritics are folded to ASCII first (``Ş`` -> ``S``) so they survive as
    letters instead of vanishing.

    Never raises; a non-string or empty input yields ``""``.
    """
    if not raw:
        return ""
    try:
        text = "".join(_FOLD.get(ch, ch) for ch in str(raw)).upper()
        # Drop the euroband country code only when it stands alone, so a plate
        # whose letter block happens to contain "TR" (e.g. "34TRA12") survives.
        text = _BAND_RE.sub(" ", text)
        return "".join(ch for ch in text if ch in _KEEP)
    except Exception:  # pragma: no cover - defensive, strip_noise must be total
        logger.debug("strip_noise failed for %r", raw, exc_info=True)
        return ""


def validate(text: str) -> bool:
    """True when ``text`` is a well-formed Turkish plate.

    Checks the canonical grammar (province 01-81, 1-3 letters, 2-4 digits) and
    additionally that every letter is in the Turkish plate alphabet, which the
    bare ``[A-Z]`` character class of :data:`PLATE_RE` cannot express.
    """
    if not text:
        return False
    match = PLATE_RE.match(text)
    if match is None:
        return False
    letters = match.group(2)
    return all(ch in TURKISH_LETTERS for ch in letters)


# ---------------------------------------------------------------------------
# Positional coercion
# ---------------------------------------------------------------------------


def _as_digit(ch: str) -> tuple[str, int]:
    """Coerce one character into a digit; returns (character, cost)."""
    if ch.isdigit():
        return ch, _COST_EXACT
    mapped = TO_DIGIT.get(ch)
    if mapped is not None:
        return mapped, _COST_MAPPED
    return ch, _COST_BAD


def _as_letter(ch: str) -> tuple[str, int]:
    """Coerce one character into a Turkish plate letter; returns (char, cost)."""
    if ch in TURKISH_LETTERS:
        return ch, _COST_EXACT
    mapped = TO_LETTER.get(ch)
    if mapped is not None and mapped in TURKISH_LETTERS:
        return mapped, _COST_MAPPED
    return ch, _COST_BAD


def _segmentations(length: int) -> list[tuple[int, int]]:
    """All (letters_len, digits_len) splits of a string of ``length`` chars."""
    splits: list[tuple[int, int]] = []
    for letters_len in (1, 2, 3):
        digits_len = length - 2 - letters_len
        if 2 <= digits_len <= 4:
            splits.append((letters_len, digits_len))
    return splits


def _best_coercion(text: str) -> tuple[str, int]:
    """Cheapest positional repair of ``text`` and what it cost.

    Cost counts characters that had to be substituted (``_COST_MAPPED`` each),
    charges ``_COST_BAD`` for characters that cannot be repaired at all, and
    adds ``_COST_BAD`` when the finished string still fails the grammar. It is
    used both to choose between segmentations and to rank competing substrings
    in :func:`extract_candidates`.
    """
    if not text:
        return "", _COST_BAD
    try:
        candidates = _segmentations(len(text))
        if not candidates:
            return text, _COST_BAD

        best: str | None = None
        best_cost = 1 << 30
        for letters_len, digits_len in candidates:
            province_src = text[:2]
            letters_src = text[2 : 2 + letters_len]
            digits_src = text[2 + letters_len : 2 + letters_len + digits_len]

            cost = 0
            out: list[str] = []
            for ch in province_src:
                fixed, c = _as_digit(ch)
                out.append(fixed)
                cost += c
            for ch in letters_src:
                fixed, c = _as_letter(ch)
                out.append(fixed)
                cost += c
            for ch in digits_src:
                fixed, c = _as_digit(ch)
                out.append(fixed)
                cost += c

            joined = "".join(out)
            # A repair that still fails the grammar (e.g. province "00") is
            # worse than one that passes it, independent of edit count.
            if not validate(joined):
                cost += _COST_BAD
            if cost < best_cost:
                best_cost, best = cost, joined

        if best is None:
            return text, _COST_BAD
        return best, best_cost
    except Exception:  # pragma: no cover - defensive, coercion must be total
        logger.debug("_best_coercion failed for %r", text, exc_info=True)
        return text, _COST_BAD


def coerce_positional(text: str) -> str:
    """Apply :data:`CONFUSION_MAP` **directionally**, per position.

    The province block must be digits, the middle block letters and the tail
    digits. Every legal segmentation of the string is scored by how many
    characters it has to touch, and the cheapest one wins -- so
    ``"34A8C123"`` becomes ``"34ABC123"`` (one repair, ``8`` -> ``B``) rather
    than ``"34AB0123"`` (two repairs), and ``"O6BZ1234"`` becomes
    ``"06BZ1234"``.

    Returns the input unchanged when it has an impossible length or when no
    segmentation can be scored. Already-normal plates are returned untouched
    (the zero-cost segmentation always wins), so this is idempotent. Never
    raises.
    """
    return _best_coercion(text)[0]


# ---------------------------------------------------------------------------
# Candidate extraction
# ---------------------------------------------------------------------------


def extract_candidates(text: str) -> list[str]:
    """Pull every plausible plate substring out of free-form recogniser output.

    Handles the two shapes real OCR produces:

    * multi-line / spaced text  -- ``"TR\\n34 ABC 12"``
    * one run-together blob     -- ``"PARK34ABC12GIRIS"``

    Returns de-duplicated, noise-stripped, uppercase candidates. Plate-shaped
    substrings (those needing no repair at all) come first in the order they
    were found, followed by substrings that only become plates after
    :func:`coerce_positional`, cheapest repair first. Candidates are *not*
    validated here; callers usually feed each one through
    :func:`coerce_positional` and :func:`validate`.

    The repair-based sliding window only runs on text that is *longer* than a
    plate. A read that is already plate-sized but ungrammatical ("00ABC12",
    "34WAB12") is a bad read, and hunting for a sub-window inside it would
    manufacture a plausible-looking plate out of nothing -- exactly the false
    positive that opens a gate for the wrong car.
    """
    if not text:
        return []
    try:
        found: list[str] = []
        seen: set[str] = set()

        def add(value: str) -> str | None:
            cleaned = strip_noise(value)
            if MIN_PLATE_LEN <= len(cleaned) <= MAX_PLATE_LEN and cleaned not in seen:
                seen.add(cleaned)
                found.append(cleaned)
                return cleaned
            return None

        raw = str(text)[:512]
        upper = "".join(_FOLD.get(ch, ch) for ch in raw).upper()

        # 1. loose scan over the original text, which still has its separators
        for match in LOOSE_PLATE_RE.finditer(upper):
            add(match.group(1))

        # 2. strict scan over each de-noised line and over the whole blob
        chunks = [strip_noise(line) for line in upper.splitlines()]
        chunks.append(strip_noise(upper))
        for chunk in chunks:
            for match in _SUBSTRING_RE.finditer(chunk):
                add(match.group(1))

        # 3. sliding window over over-long chunks, for candidates only
        #    reachable after coercion ("34A8C123" is not plate-shaped until
        #    8 -> B). Ranked by repair cost so the window that fits the
        #    grammar most naturally wins over a longer, sloppier one.
        repaired: list[tuple[int, int, str]] = []
        for chunk in chunks:
            if len(chunk) <= MAX_PLATE_LEN or len(chunk) > 128:
                continue
            for size in range(MIN_PLATE_LEN, MAX_PLATE_LEN + 1):
                for start in range(0, len(chunk) - size + 1):
                    window = chunk[start : start + size]
                    if window in seen:
                        continue
                    fixed, cost = _best_coercion(window)
                    if cost <= _MAX_REPAIR_COST and validate(fixed):
                        repaired.append((cost, -size, window))
        for _cost, _neg_size, window in sorted(repaired):
            if len(found) >= MAX_CANDIDATES:
                break
            add(window)

        return found[:MAX_CANDIDATES]
    except Exception:  # pragma: no cover - defensive, extraction must be total
        logger.debug("extract_candidates failed for %r", text, exc_info=True)
        return []


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def normalize_plate(raw: str, confidence: float = 0.0) -> PlateRead:
    """Turn a raw recogniser string into a :class:`~lpr.contracts.PlateRead`.

    Pipeline: :func:`strip_noise` -> uppercase -> direct :func:`validate` ->
    :func:`coerce_positional` -> substring :func:`extract_candidates`. The
    first stage that produces a grammatical plate wins.

    ``PlateRead.raw_text`` always keeps the untouched recogniser string, so no
    information is lost and a human can audit any decision made here. When
    nothing parses, ``text`` holds the de-noised string and ``valid`` is
    ``False`` -- the speculative coercion is deliberately *not* returned,
    because a repair that failed validation is noise, not a plate.
    """
    raw_text = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
    conf = _clamp_confidence(confidence)

    cleaned = strip_noise(raw_text)
    if not cleaned:
        return PlateRead(text="", confidence=conf, raw_text=raw_text, valid=False)

    # 1. already a plate
    if validate(cleaned):
        return PlateRead(text=cleaned, confidence=conf, raw_text=raw_text, valid=True)

    # 2. positional confusion repair
    coerced = coerce_positional(cleaned)
    if validate(coerced):
        logger.debug("coerced %r -> %r", cleaned, coerced)
        return PlateRead(text=coerced, confidence=conf, raw_text=raw_text, valid=True)

    # 3. plate hiding inside a longer / multi-line read
    for candidate in extract_candidates(raw_text):
        if validate(candidate):
            return PlateRead(text=candidate, confidence=conf, raw_text=raw_text, valid=True)
        repaired = coerce_positional(candidate)
        if validate(repaired):
            logger.debug("extracted %r -> %r", candidate, repaired)
            return PlateRead(text=repaired, confidence=conf, raw_text=raw_text, valid=True)

    return PlateRead(text=cleaned, confidence=conf, raw_text=raw_text, valid=False)


def _clamp_confidence(value: float) -> float:
    """Confidence is a probability; keep it in [0, 1] whatever the backend says."""
    try:
        num = float(value)
    except (TypeError, ValueError):
        return 0.0
    if num != num:  # NaN
        return 0.0
    return max(0.0, min(1.0, num))
