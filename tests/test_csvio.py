"""Tests for CSV import and export.

The interesting cases are all about *spreadsheets*, not about CSV. The files
that arrive at a gate were saved out of Excel by a site manager on a Turkish
Windows machine, so they carry a BOM, semicolon delimiters, cp1254 encoding and
Turkish column headers. A parser that only handles RFC 4180 rejects most real
input, and the operator has no way to tell why.
"""

from __future__ import annotations

from typing import Any

import pytest

from lpr.csvio import (
    MAX_IMPORT_BYTES,
    export_events_csv,
    export_plates_csv,
    parse_plate_csv,
    sniff_dialect,
)


class FakeRepo:
    """Records what the importer asked for, and fakes the conflict policy."""

    def __init__(self, existing: set[str] | None = None) -> None:
        self.existing = set(existing or ())
        self.calls: list[dict[str, Any]] = []

    def upsert(
        self,
        plate: str,
        owner: str | None = None,
        apartment: str | None = None,
        note: str | None = None,
        expires_at: str | None = None,
        blocked: bool = False,
        overwrite: bool = True,
    ) -> str:
        self.calls.append(
            {
                "plate": plate,
                "owner": owner,
                "apartment": apartment,
                "note": note,
                "expires_at": expires_at,
                "blocked": blocked,
                "overwrite": overwrite,
            }
        )
        if plate in self.existing:
            return "updated" if overwrite else "skipped"
        self.existing.add(plate)
        return "added"

    def plate(self, index: int = 0) -> str:
        return self.calls[index]["plate"]


def parse(text: str, *, encoding: str = "utf-8", **kwargs: Any) -> tuple[Any, FakeRepo]:
    repo = kwargs.pop("repo", None) or FakeRepo()
    report = parse_plate_csv(text.encode(encoding), plate_repo=repo, **kwargs)
    return report, repo


# ---------------------------------------------------------------------------
# Delimiters and encodings: what Excel actually writes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("delimiter", [",", ";", "\t", "|"])
def test_the_delimiter_is_detected_not_assumed(delimiter: str) -> None:
    """Excel on a Turkish locale uses ';' -- the comma is the decimal separator.

    Guessing wrong collapses every row into one column and the file is rejected
    for a missing 'plate' header, which is a baffling error to hand someone.
    """
    text = f"plate{delimiter}owner\r\n34ABC123{delimiter}Ali\r\n"
    report, repo = parse(text)
    assert report.added == 1
    assert repo.calls[0]["owner"] == "Ali"


def test_the_delimiter_survives_ragged_rows_and_timestamps() -> None:
    """csv.Sniffer guesses wrong here; the header is the reliable signal."""
    text = (
        "Plaka;Sahibi;Daire;Notlar;Gecerlilik\r\n"
        "34ABC123;Ali;A-12;Kiracı;2027-01-01T00:00:00+00:00\r\n"
        ";;;;\r\n"
        "\r\n"
    )
    assert sniff_dialect(text).delimiter == ";"


def test_a_utf8_bom_does_not_break_the_header() -> None:
    """Excel writes one on every "CSV UTF-8" save."""
    report, repo = parse("plate,owner\r\n34ABC123,Ali\r\n", encoding="utf-8-sig")
    assert report.added == 1
    assert repo.plate() == "34ABC123"


def test_a_doubled_bom_is_also_stripped() -> None:
    """A file round-tripped through two tools can carry more than one."""
    report, _ = parse("﻿plate,owner\r\n34ABC123,Ali\r\n", encoding="utf-8-sig")
    assert report.added == 1


def test_a_cp1254_file_is_read_rather_than_rejected() -> None:
    """A plain "CSV" export from a Turkish Windows box is not UTF-8."""
    report, repo = parse("plate,owner\r\n34ABC123,Ayşe Yıldız\r\n", encoding="cp1254")
    assert report.added == 1
    assert "Ay" in (repo.calls[0]["owner"] or "")


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    ["plate", "Plate", "PLATE", " plate ", "plaka", "Plaka", "Plaka No"],
)
def test_the_plate_column_is_recognised_however_it_is_spelled(header: str) -> None:
    report, _ = parse(f"{header},owner\r\n34ABC123,Ali\r\n")
    assert report.added == 1


def test_turkish_headers_map_to_the_right_columns() -> None:
    """`sahibi`, `daire`, `notlar` are what a site manager actually types."""
    report, repo = parse(
        "plaka;sahibi;daire;notlar;gecerlilik\r\n34ABC123;Ali Şen;A-12;Kiracı;2027-01-01\r\n"
    )
    assert report.added == 1
    call = repo.calls[0]
    assert call["owner"] == "Ali Şen"
    assert call["apartment"] == "A-12"
    assert call["note"] == "Kiracı"
    assert call["expires_at"] == "2027-01-01"


def test_unknown_columns_are_ignored_not_fatal() -> None:
    """A real export carries extra columns nobody asked about."""
    report, repo = parse("plate,owner,telefon,bakiye\r\n34ABC123,Ali,555,0\r\n")
    assert report.added == 1
    assert repo.calls[0]["owner"] == "Ali"


def test_a_file_without_a_plate_column_is_refused_with_a_reason() -> None:
    report, repo = parse("owner,apartment\r\nAli,A-12\r\n")
    assert report.added == 0
    assert repo.calls == []
    assert any("plate" in error for error in report.errors)


def test_only_the_plate_column_is_required() -> None:
    report, _ = parse("plate\r\n34ABC123\r\n")
    assert report.added == 1


# ---------------------------------------------------------------------------
# Row handling
# ---------------------------------------------------------------------------


def test_plates_are_normalised_on_the_way_in() -> None:
    """A spreadsheet holds "34 abc 123"; the gate compares "34ABC123"."""
    _, repo = parse("plate\r\n34 abc 123\r\n")
    assert repo.plate() == "34ABC123"


def test_blank_lines_are_skipped_silently() -> None:
    """Every spreadsheet leaves at least one at the end."""
    report, _ = parse("plate\r\n34ABC123\r\n\r\n,,,\r\n")
    assert report.added == 1
    assert report.invalid == 0


def test_a_bad_row_does_not_reject_the_good_ones() -> None:
    """One mistyped plate in row 400 must not cost the other 399."""
    report, repo = parse("plate,owner\r\n34ABC123,Ali\r\n???,Broken\r\n06MNP99,Ayse\r\n")
    assert report.added == 2
    assert report.invalid == 1
    assert len(repo.calls) == 2


def test_error_rows_are_numbered_as_the_spreadsheet_shows_them() -> None:
    """Row 1 is the header, so the first data row is 2 -- what Excel displays."""
    report, _ = parse("plate\r\n34ABC123\r\n???\r\n")
    assert any("Satır 3" in error for error in report.errors)


def test_short_rows_do_not_raise() -> None:
    """A trailing empty column is trimmed by some exporters."""
    report, repo = parse("plate,owner,apartment\r\n34ABC123,Ali\r\n")
    assert report.added == 1
    assert repo.calls[0]["apartment"] is None


def test_empty_cells_become_none_not_empty_strings() -> None:
    _, repo = parse("plate,owner,note\r\n34ABC123,,\r\n")
    assert repo.calls[0]["owner"] is None
    assert repo.calls[0]["note"] is None


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "evet", "yes", "x", "Var"])
def test_the_blocked_column_accepts_what_a_spreadsheet_contains(value: str) -> None:
    _, repo = parse(f"plate,blocked\r\n34ABC123,{value}\r\n")
    assert repo.calls[0]["blocked"] is True


@pytest.mark.parametrize("value", ["", "0", "hayir", "no", "false"])
def test_anything_else_is_not_blocked(value: str) -> None:
    _, repo = parse(f"plate,blocked\r\n34ABC123,{value}\r\n")
    assert repo.calls[0]["blocked"] is False


# ---------------------------------------------------------------------------
# Conflict policy
# ---------------------------------------------------------------------------


def test_existing_plates_are_skipped_by_default() -> None:
    """Re-uploading last month's list must not rewrite corrected owner data."""
    repo = FakeRepo(existing={"34ABC123"})
    report, _ = parse("plate,owner\r\n34ABC123,Yeni Sahip\r\n", repo=repo)
    assert report.skipped == 1
    assert report.updated == 0


def test_overwrite_updates_an_existing_plate() -> None:
    repo = FakeRepo(existing={"34ABC123"})
    report, _ = parse("plate,owner\r\n34ABC123,Yeni Sahip\r\n", repo=repo, overwrite=True)
    assert report.updated == 1
    assert report.skipped == 0


def test_the_conflict_policy_reaches_the_repository() -> None:
    _, repo = parse("plate\r\n34ABC123\r\n", overwrite=True)
    assert repo.calls[0]["overwrite"] is True


# ---------------------------------------------------------------------------
# Guard rails
# ---------------------------------------------------------------------------


def test_an_empty_file_is_reported_not_crashed() -> None:
    report = parse_plate_csv(b"", plate_repo=FakeRepo())
    assert report.total == 0
    assert report.errors


def test_a_header_only_file_imports_nothing() -> None:
    report, _ = parse("plate,owner\r\n")
    assert report.total == 0


def test_an_oversized_upload_is_refused_without_parsing() -> None:
    repo = FakeRepo()
    report = parse_plate_csv(b"x" * (MAX_IMPORT_BYTES + 1), plate_repo=repo)
    assert repo.calls == []
    assert any("büyük" in error for error in report.errors)


def test_a_repository_failure_is_reported_per_row() -> None:
    class BrokenRepo(FakeRepo):
        def upsert(self, *args: Any, **kwargs: Any) -> str:
            raise RuntimeError("database is locked")

    report = parse_plate_csv(b"plate\r\n34ABC123\r\n", plate_repo=BrokenRepo())
    assert report.invalid == 1
    assert any("kaydedilemedi" in error for error in report.errors)


def test_the_error_list_is_bounded() -> None:
    """A wholly broken file must not produce a response bigger than the upload."""
    rows = "\r\n".join("???" for _ in range(500))
    report, _ = parse(f"plate\r\n{rows}\r\n")
    assert report.invalid == 500
    assert len(report.to_dict()["errors"]) <= 50


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def test_the_plate_export_opens_cleanly_in_excel() -> None:
    """BOM plus CRLF: a double-clicked download must not need an import wizard."""
    payload = export_plates_csv([{"plate": "34ABC123", "owner": "Ali Şen"}])
    assert payload.startswith(b"\xef\xbb\xbf")
    assert b"\r\n" in payload
    assert "Ali Şen" in payload.decode("utf-8-sig")


def test_the_plate_export_round_trips_through_the_importer() -> None:
    """Download, edit in Excel, re-upload is a supported way to bulk-edit."""
    payload = export_plates_csv(
        [{"plate": "34ABC123", "owner": "Ali", "apartment": "A-12", "blocked": 0}]
    )
    repo = FakeRepo()
    report = parse_plate_csv(payload, plate_repo=repo)
    assert report.added == 1
    assert repo.calls[0]["owner"] == "Ali"
    assert repo.calls[0]["apartment"] == "A-12"


def test_none_becomes_an_empty_cell_not_the_word_none() -> None:
    text = export_plates_csv([{"plate": "34ABC123", "owner": None}]).decode("utf-8-sig")
    assert "None" not in text


def test_a_comma_in_a_field_is_quoted() -> None:
    """Otherwise every later column shifts by one and the file is silently wrong."""
    text = export_plates_csv([{"plate": "34ABC123", "owner": "Sen, Ali"}]).decode("utf-8-sig")
    assert '"Sen, Ali"' in text


def test_the_event_export_carries_the_audit_columns() -> None:
    payload = export_events_csv(
        [
            {
                "id": 1,
                "ts": "2026-08-27T03:14:00+00:00",
                "camera": "entry",
                "plate": "34ABC123",
                "action": "denied",
                "confidence": 0.91,
            }
        ]
    )
    text = payload.decode("utf-8-sig")
    assert "id,ts,camera,plate,action,confidence" in text
    assert "denied" in text and "34ABC123" in text


def test_exporting_nothing_still_writes_the_header() -> None:
    """An empty CSV with no header is indistinguishable from a failed download."""
    assert b"plate" in export_plates_csv([])
    assert b"ts" in export_events_csv([])
