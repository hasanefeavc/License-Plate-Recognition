"""CSV import and export for the plate list and the event log.

Pure standard library, no pandas: the whole job is a few thousand rows of text,
and the parsing rules that actually matter here are about *spreadsheets*, not
about dataframes.

What real files look like
-------------------------
The files that arrive at a gate are exported from Excel by a site manager, so
this parser expects the mess that implies and handles it rather than rejecting
it:

* **A UTF-8 BOM.** Excel writes one on every "CSV UTF-8" save. Read with
  ``utf-8-sig`` or the first header becomes ``\\ufeffplate`` and nothing maps.
* **Semicolon delimiters.** Excel on a Turkish (or German, or French) locale
  uses ``;`` because the comma is the decimal separator. Sniffed, not assumed.
* **Turkish headers.** ``plaka``, ``sahibi``, ``daire`` are what a site manager
  actually types. Aliased to the canonical names.
* **Header case and spacing.** ``Plate``, ``PLATE ``, ``expires at`` all land.
* **Latin-1 fallback.** A file saved as plain "CSV" from a Turkish Windows box
  is cp1254, not UTF-8, and would otherwise raise on the first ``ş``.

Export is deliberately plainer: UTF-8 with a BOM and ``\\r\\n`` line endings, so
double-clicking the download opens correctly in Excel without an import wizard.
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import dataclass, field
from typing import Any

from lpr.db import schema
from lpr.ocr.normalize import strip_noise

logger = logging.getLogger(__name__)

__all__ = [
    "EVENT_COLUMNS",
    "ImportReport",
    "PLATE_COLUMNS",
    "export_events_csv",
    "export_plates_csv",
    "parse_plate_csv",
    "sniff_dialect",
]

PLATE_COLUMNS = schema.PLATE_COLUMNS
EVENT_COLUMNS: tuple[str, ...] = ("id", "ts", "camera", "plate", "action", "confidence")

#: Header aliases, normalised key -> canonical column. Turkish first, because
#: that is what the people using this actually write.
_HEADER_ALIASES: dict[str, str] = {
    "plaka": "plate",
    "plate": "plate",
    "plakano": "plate",
    "sahibi": "owner",
    "sahip": "owner",
    "adsoyad": "owner",
    "isim": "owner",
    "owner": "owner",
    "name": "owner",
    "daire": "apartment",
    "daireno": "apartment",
    "apartman": "apartment",
    "apartment": "apartment",
    "flat": "apartment",
    "unit": "apartment",
    "not": "note",
    "notlar": "note",
    "aciklama": "note",
    "note": "note",
    "notes": "note",
    "gecerlilik": "expires_at",
    "sonkullanim": "expires_at",
    "bitis": "expires_at",
    "expiresat": "expires_at",
    "expires": "expires_at",
    "expiry": "expires_at",
    "engelli": "blocked",
    "karaliste": "blocked",
    "blocked": "blocked",
    "blacklisted": "blocked",
}

#: Values that mean "yes" in the ``blocked`` column, across the spellings a
#: spreadsheet produces.
_TRUTHY = {"1", "true", "yes", "y", "evet", "e", "x", "var", "dogru", "doğru"}

#: Hard cap on an uploaded file. A plate list is a few hundred rows; anything
#: past this is a mistake or an attack, and either way should not be parsed
#: into memory row by row.
MAX_IMPORT_BYTES = 5 * 1024 * 1024
MAX_IMPORT_ROWS = 50_000


@dataclass(slots=True)
class ImportReport:
    """What an import did, per row, in terms an operator can act on."""

    added: int = 0
    updated: int = 0
    skipped: int = 0
    invalid: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.added + self.updated + self.skipped + self.invalid

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": self.added,
            "updated": self.updated,
            "skipped": self.skipped,
            "invalid": self.invalid,
            "total": self.total,
            # Bounded: a file where every row is broken must not produce a
            # response bigger than the upload was.
            "errors": self.errors[:50],
        }


def _decode(raw: bytes) -> str:
    """Bytes to text, tolerating what Excel actually writes.

    ``utf-8-sig`` strips the BOM when present and is a plain UTF-8 read when it
    is not. cp1254 is the fallback because a Turkish Windows "CSV" export is
    that, not UTF-8, and failing on the first ``ş`` would be a baffling error
    for the person holding the file.
    """
    for encoding in ("utf-8-sig", "cp1254", "latin-1"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:  # pragma: no cover - latin-1 never fails
        text = raw.decode("utf-8", errors="replace")

    # A file that has been round-tripped through two tools can carry more than
    # one BOM, and the cp1254/latin-1 fallbacks do not strip one at all. Left
    # in place it becomes part of the first header cell, so `plate` never
    # matches and a perfectly good file is rejected for a missing column.
    return text.lstrip("\ufeff")


#: Delimiters worth considering, in preference order for a tie.
_DELIMITERS = (",", ";", "\t", "|")


def sniff_dialect(sample: str) -> type[csv.Dialect] | csv.Dialect:
    """Guess the delimiter from the header row, defaulting to comma.

    Excel on a Turkish locale writes ``;`` because the comma is the decimal
    separator, so guessing wrong collapses every row into one unparseable
    column and the file is rejected for a missing ``plate`` header.

    Counted off the **header line** rather than handed to :class:`csv.Sniffer`
    on the whole sample. The header is the one row guaranteed to be
    well-formed; Sniffer's frequency heuristics are thrown by the things real
    exports contain -- trailing blank lines, ragged short rows, and ISO
    timestamps whose punctuation looks like structure. Sniffer is kept as the
    fallback for the case this cannot decide (a single-column file).
    """
    header = ""
    for line in sample.splitlines():
        if line.strip():
            header = line
            break

    counts = {delimiter: header.count(delimiter) for delimiter in _DELIMITERS}
    best = max(_DELIMITERS, key=lambda d: counts[d])
    if counts[best] > 0:
        return _dialect_for(best)

    try:
        return csv.Sniffer().sniff(sample, delimiters="".join(_DELIMITERS))
    except csv.Error:
        logger.debug("CSV ayırıcısı belirlenemedi, virgül varsayılıyor")
        return csv.excel


def _dialect_for(delimiter: str) -> type[csv.Dialect]:
    class _Dialect(csv.excel):
        pass

    _Dialect.delimiter = delimiter
    return _Dialect


def _canonical_header(name: str) -> str | None:
    """Map one header cell onto a known column, or ``None`` to ignore it."""
    key = "".join(ch for ch in str(name or "").strip().lower() if ch.isalnum())
    return _HEADER_ALIASES.get(key)


def _clean(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def parse_plate_csv(
    raw: bytes,
    overwrite: bool = False,
    plate_repo: Any = None,
) -> ImportReport:
    """Import a plate list, one row at a time, into ``plate_repo``.

    Row-by-row rather than all-or-nothing on purpose. A single mistyped plate
    in row 400 of a resident list should not reject the other 399 -- the
    operator gets the good rows plus a numbered list of what failed, and can
    fix and re-upload just those. Row numbers count from the *file's* first
    line, header included, so they match what the spreadsheet shows.

    ``overwrite`` decides the conflict policy: false skips plates that already
    exist (the safe default -- a re-uploaded list will not silently rewrite
    owners), true updates them in place.
    """
    report = ImportReport()

    if plate_repo is None:
        from lpr.db import PlateRepository

        plate_repo = PlateRepository()

    if not raw:
        report.errors.append("Dosya boş.")
        return report
    if len(raw) > MAX_IMPORT_BYTES:
        report.errors.append(f"Dosya çok büyük ({len(raw)} bayt, en fazla {MAX_IMPORT_BYTES}).")
        return report

    text = _decode(raw)
    if not text.strip():
        report.errors.append("Dosya boş.")
        return report

    reader = csv.reader(io.StringIO(text), dialect=sniff_dialect(text[:4096]))
    try:
        header = next(reader)
    except StopIteration:
        report.errors.append("Dosya boş.")
        return report

    columns = [_canonical_header(cell) for cell in header]
    if "plate" not in columns:
        report.errors.append(
            "Zorunlu 'plate' (plaka) sütunu bulunamadı. "
            f"Bulunan başlıklar: {', '.join(str(h) for h in header[:10])}"
        )
        return report

    for line_number, row in enumerate(reader, start=2):
        if line_number - 1 > MAX_IMPORT_ROWS:
            report.errors.append(f"Satır sınırı aşıldı ({MAX_IMPORT_ROWS}).")
            break
        if not any(str(cell).strip() for cell in row):
            continue  # a blank line, which every spreadsheet leaves at the end

        record: dict[str, str | None] = {}
        for index, column in enumerate(columns):
            if column is None or index >= len(row):
                continue
            record[column] = _clean(row[index])

        plate = strip_noise(record.get("plate") or "")
        if not plate:
            report.invalid += 1
            report.errors.append(f"Satır {line_number}: plaka okunamadı.")
            continue

        blocked_raw = (record.get("blocked") or "").strip().lower()
        try:
            outcome = plate_repo.upsert(
                plate,
                owner=record.get("owner"),
                apartment=record.get("apartment"),
                note=record.get("note"),
                expires_at=record.get("expires_at"),
                blocked=blocked_raw in _TRUTHY,
                overwrite=overwrite,
            )
        except Exception as exc:
            report.invalid += 1
            report.errors.append(f"Satır {line_number}: kaydedilemedi ({exc}).")
            continue

        if outcome == "added":
            report.added += 1
        elif outcome == "updated":
            report.updated += 1
        elif outcome == "skipped":
            report.skipped += 1
        else:
            report.invalid += 1
            report.errors.append(f"Satır {line_number}: geçersiz plaka '{plate}'.")

    logger.info(
        "CSV içe aktarma: %d eklendi, %d güncellendi, %d atlandı, %d geçersiz",
        report.added,
        report.updated,
        report.skipped,
        report.invalid,
    )
    return report


def _write_csv(columns: tuple[str, ...], rows: list[dict[str, Any]]) -> str:
    """Rows to an Excel-friendly CSV string.

    ``\\r\\n`` and a BOM (added by the caller's encoding) are what make a
    double-clicked download open straight into Excel with the columns split and
    Turkish characters intact, rather than landing in the import wizard.
    """
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=list(columns),
        extrasaction="ignore",
        lineterminator="\r\n",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _cell(row.get(key)) for key in columns})
    return buffer.getvalue()


def _cell(value: Any) -> str:
    """One value as a spreadsheet cell. ``None`` becomes empty, not "None"."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def export_plates_csv(rows: list[dict[str, Any]]) -> bytes:
    """The plate list as UTF-8-BOM CSV bytes, ready to stream."""
    return _write_csv(PLATE_COLUMNS, rows).encode("utf-8-sig")


def export_events_csv(rows: list[dict[str, Any]]) -> bytes:
    """The event log as UTF-8-BOM CSV bytes, ready to stream."""
    return _write_csv(EVENT_COLUMNS, rows).encode("utf-8-sig")
