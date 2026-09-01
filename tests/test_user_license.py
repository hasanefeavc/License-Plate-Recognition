"""Per-operator licence keys.

Pure key mechanics here; the HTTP enforcement is in ``test_api``. The
assertions worth reading first are the negative ones — a key that verifies when
it should not is the whole failure mode of a licensing scheme.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest

from lpr.user_license import (
    LICENSE_TYP,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_PENDING,
    STATUS_REVOKED,
    STATUS_UNLIMITED,
    activate,
    enforcement_enabled,
    inspect_key,
    issue_key,
    license_for,
    requires_license,
)

SECRET = "s" * 40


@pytest.fixture()
def licensed(tmp_settings: Any) -> Any:
    tmp_settings.license_secret = SECRET
    return tmp_settings


def now_utc() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Who needs a licence
# ---------------------------------------------------------------------------


def test_an_administrator_never_needs_a_licence() -> None:
    """The account that issues keys cannot sensibly be locked out by one.

    An admin holding an expired key could not issue a replacement, and the
    installation would need its database edited by hand to recover.
    """
    assert requires_license("admin") is False
    assert license_for("admin", None).status == STATUS_UNLIMITED
    assert license_for("admin", None).valid is True


def test_an_operator_needs_one() -> None:
    assert requires_license("operator") is True


def test_enforcement_is_off_without_a_secret(tmp_settings: Any) -> None:
    """An upgrade must not lock every operator out of a working barrier."""
    tmp_settings.license_secret = ""
    assert enforcement_enabled(tmp_settings) is False
    assert license_for("operator", {"username": "bekci"}, tmp_settings).valid is True


def test_enforcement_is_on_once_a_secret_is_set(licensed: Any) -> None:
    assert enforcement_enabled(licensed) is True
    assert license_for("operator", {"username": "bekci"}, licensed).valid is False


# ---------------------------------------------------------------------------
# Generation: a key is a duration, not a deadline
# ---------------------------------------------------------------------------


def test_a_key_encodes_a_duration_and_not_an_expiry(licensed: Any) -> None:
    """Generation must not start the clock.

    An admin cutting a 365-day key on Friday for a Monday start would
    otherwise hand over something already three days short.
    """
    key = issue_key("bekci", 365, licensed)
    claims = jwt.decode(key, options={"verify_signature": False})

    assert claims["duration_days"] == 365
    assert claims["sub"] == "bekci"
    assert "exp" not in claims, "an expiry here would be a deadline for collecting it"


def test_inspecting_a_key_reads_it_without_activating(licensed: Any) -> None:
    info = inspect_key(issue_key("bekci", 90, licensed), "bekci", licensed)
    assert info.valid is True
    assert info.username == "bekci"
    assert info.duration_days == 90


def test_a_key_is_bound_to_the_account_it_was_issued_to(licensed: Any) -> None:
    """Without this any operator could enter a colleague's key."""
    key = issue_key("bekci", 30, licensed)
    assert inspect_key(key, "baskasi", licensed).valid is False


def test_a_key_signed_with_another_secret_is_refused(licensed: Any) -> None:
    forged = jwt.encode(
        {"typ": LICENSE_TYP, "sub": "bekci", "duration_days": 365},
        "a-different-secret",
        algorithm="HS256",
    )
    assert inspect_key(forged, "bekci", licensed).valid is False


def test_a_token_without_the_licence_type_is_refused(licensed: Any) -> None:
    """Anything else signed with this secret must not pass as a licence."""
    lookalike = jwt.encode(
        {"sub": "bekci", "role": "admin", "duration_days": 365}, SECRET, algorithm="HS256"
    )
    assert inspect_key(lookalike, "bekci", licensed).valid is False


def test_a_key_without_a_usable_duration_is_refused(licensed: Any) -> None:
    """A zero-day key would activate to an already-expired licence."""
    for duration in (0, -5, "abc", None):
        token = jwt.encode(
            {"typ": LICENSE_TYP, "sub": "bekci", "duration_days": duration},
            SECRET,
            algorithm="HS256",
        )
        assert inspect_key(token, "bekci", licensed).valid is False, duration


def test_garbage_is_refused_rather_than_raising(licensed: Any) -> None:
    for value in ("", "   ", "not-a-token", "a.b.c"):
        assert inspect_key(value, "bekci", licensed).valid is False


def test_issuing_without_a_secret_fails_loudly(tmp_settings: Any) -> None:
    """A key nothing can verify would look like success and fail at activation."""
    tmp_settings.license_secret = ""
    with pytest.raises(RuntimeError):
        issue_key("bekci", 30, tmp_settings)


@pytest.mark.parametrize("days", [1, 30, 90, 365])
def test_the_requested_span_reaches_the_key(licensed: Any, days: int) -> None:
    assert inspect_key(issue_key("bekci", days, licensed), "bekci", licensed).duration_days == days


def test_the_validity_span_is_clamped(licensed: Any) -> None:
    assert inspect_key(issue_key("bekci", 0, licensed), "bekci", licensed).duration_days >= 1
    assert (
        inspect_key(issue_key("bekci", 99_999, licensed), "bekci", licensed).duration_days <= 3650
    )


# ---------------------------------------------------------------------------
# Activation: where the countdown starts
# ---------------------------------------------------------------------------


def test_activation_computes_the_expiry_from_now(licensed: Any) -> None:
    key = issue_key("bekci", 30, licensed)
    moment = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    state = activate(key, "bekci", licensed, now=moment)

    assert state.status == STATUS_ACTIVE
    assert state.valid is True
    assert state.activated_at == moment.isoformat()
    assert state.expires_at == (moment + timedelta(days=30)).isoformat()
    assert state.days_remaining == 30.0
    assert state.duration_days == 30


def test_a_key_generated_long_ago_still_grants_its_full_span(licensed: Any) -> None:
    """The whole point of encoding a duration: the key does not go stale."""
    key = issue_key("bekci", 365, licensed, now=now_utc() - timedelta(days=200))
    state = activate(key, "bekci", licensed)
    assert state.valid is True
    assert 364 < (state.days_remaining or 0) <= 365


def test_activating_someone_elses_key_yields_no_expiry(licensed: Any) -> None:
    state = activate(issue_key("bekci", 30, licensed), "baskasi", licensed)
    assert state.valid is False
    assert state.expires_at is None, "nothing may be written for a refused key"


def test_activating_junk_yields_no_expiry(licensed: Any) -> None:
    state = activate("not-a-key", "bekci", licensed)
    assert state.valid is False
    assert state.status == STATUS_PENDING
    assert state.expires_at is None


# ---------------------------------------------------------------------------
# license_for: read from the stored row, not from the key
# ---------------------------------------------------------------------------


def activated_row(days: int = 30, at: datetime | None = None) -> dict[str, Any]:
    moment = at or now_utc()
    return {
        "username": "bekci",
        "license_key": "irrelevant-once-stored",
        "license_status": STATUS_ACTIVE,
        "license_duration_days": days,
        "license_activated_at": moment.isoformat(),
        "license_expires_at": (moment + timedelta(days=days)).isoformat(),
    }


def test_a_new_operator_is_pending_not_missing(licensed: Any) -> None:
    """A new hire on their first morning is waiting, not in error."""
    state = license_for("operator", {"username": "bekci"}, licensed)
    assert state.status == STATUS_PENDING
    assert state.valid is False


def test_an_activated_row_is_active(licensed: Any) -> None:
    state = license_for("operator", activated_row(30), licensed)
    assert state.status == STATUS_ACTIVE
    assert state.valid is True
    assert 29 < (state.days_remaining or 0) <= 30


def test_the_countdown_comes_from_the_row_not_the_key(licensed: Any) -> None:
    """Re-deriving it from the key would restart the clock on every request.

    The licence would then never run out, which is the bug this ordering
    exists to prevent.
    """
    row = activated_row(30, at=now_utc() - timedelta(days=25))
    state = license_for("operator", row, licensed)
    assert 4 < (state.days_remaining or 0) <= 5


def test_a_lapsed_row_is_expired(licensed: Any) -> None:
    state = license_for("operator", activated_row(30, at=now_utc() - timedelta(days=40)), licensed)
    assert state.status == STATUS_EXPIRED
    assert state.valid is False
    assert state.days_remaining == 0.0


def test_revocation_beats_a_row_that_has_not_expired(licensed: Any) -> None:
    row = activated_row(365)
    row["license_status"] = STATUS_REVOKED
    assert license_for("operator", row, licensed).status == STATUS_REVOKED


def test_an_unreadable_expiry_does_not_grant_access(licensed: Any) -> None:
    """Access must never be granted on a date nothing can parse."""
    row = activated_row(30)
    row["license_expires_at"] = "yesterday-ish"
    state = license_for("operator", row, licensed)
    assert state.valid is False


def test_an_admin_is_unlimited_whatever_the_row_says(licensed: Any) -> None:
    """Role is checked before anything on the row is read."""
    row = activated_row(30, at=now_utc() - timedelta(days=90))
    assert license_for("admin", row, licensed).status == STATUS_UNLIMITED
