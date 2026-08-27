"""Per-operator licence keys.

Pure key mechanics here; the HTTP enforcement is in ``test_api``. The
assertions worth reading first are the negative ones — a key that verifies when
it should not is the whole failure mode of a licensing scheme.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pytest

from lpr.user_license import (
    LICENSE_TYP,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_MISSING,
    STATUS_REVOKED,
    STATUS_UNLIMITED,
    enforcement_enabled,
    issue_key,
    license_for,
    requires_license,
    verify_key,
)

SECRET = "s" * 40


@pytest.fixture()
def licensed(tmp_settings: Any) -> Any:
    tmp_settings.license_secret = SECRET
    return tmp_settings


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


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
# Issuing and verifying
# ---------------------------------------------------------------------------


def test_a_fresh_key_verifies_for_its_owner(licensed: Any) -> None:
    key, expires_at = issue_key("bekci", 30, licensed)
    state = verify_key(key, "bekci", licensed)

    assert state.status == STATUS_ACTIVE
    assert state.valid is True
    assert state.username == "bekci"
    assert state.expires_at == expires_at
    assert 29 < (state.days_remaining or 0) <= 30


def test_a_key_is_bound_to_the_account_it_was_issued_to(licensed: Any) -> None:
    """Without this any operator could activate a colleague's key."""
    key, _ = issue_key("bekci", 30, licensed)
    assert verify_key(key, "baskasi", licensed).valid is False


def test_an_expired_key_reports_as_expired_not_merely_invalid(licensed: Any) -> None:
    """ "Expired" tells the operator to ask for a new one; "invalid" does not."""
    past = now_utc() - timedelta(days=40)
    key, _ = issue_key("bekci", 30, licensed, now=past)
    state = verify_key(key, "bekci", licensed)

    assert state.status == STATUS_EXPIRED
    assert state.valid is False
    assert state.days_remaining == 0.0
    assert state.username == "bekci", "the owner is still reported, for the message"


def test_a_key_signed_with_another_secret_is_refused(licensed: Any) -> None:
    forged = jwt.encode(
        {
            "typ": LICENSE_TYP,
            "sub": "bekci",
            "exp": int((now_utc() + timedelta(days=1)).timestamp()),
        },
        "a-different-secret",
        algorithm="HS256",
    )
    assert verify_key(forged, "bekci", licensed).valid is False


def test_a_token_without_the_licence_type_is_refused(licensed: Any) -> None:
    """Anything else signed with this secret must not pass as a licence."""
    lookalike = jwt.encode(
        {"sub": "bekci", "role": "admin", "exp": int((now_utc() + timedelta(days=1)).timestamp())},
        SECRET,
        algorithm="HS256",
    )
    assert verify_key(lookalike, "bekci", licensed).valid is False


def test_garbage_is_refused_rather_than_raising(licensed: Any) -> None:
    for value in ("", "   ", "not-a-token", "a.b.c"):
        assert verify_key(value, "bekci", licensed).valid is False


def test_issuing_without_a_secret_fails_loudly(tmp_settings: Any) -> None:
    """A key nothing can verify would look like success and fail at activation."""
    tmp_settings.license_secret = ""
    with pytest.raises(RuntimeError):
        issue_key("bekci", 30, tmp_settings)


def test_the_validity_span_is_clamped(licensed: Any) -> None:
    _, short = issue_key("bekci", 0, licensed)
    _, long = issue_key("bekci", 99_999, licensed)
    assert short and long, "both must still produce a usable expiry"


@pytest.mark.parametrize("days", [1, 30, 90, 365])
def test_the_requested_span_reaches_the_key(licensed: Any, days: int) -> None:
    key, _ = issue_key("bekci", days, licensed)
    remaining = verify_key(key, "bekci", licensed).days_remaining or 0
    assert days - 1 < remaining <= days


# ---------------------------------------------------------------------------
# license_for: the policy the API enforces
# ---------------------------------------------------------------------------


def test_an_operator_with_no_key_is_missing_not_expired(licensed: Any) -> None:
    state = license_for("operator", {"username": "bekci"}, licensed)
    assert state.status == STATUS_MISSING
    assert state.valid is False


def test_revocation_beats_a_key_that_still_verifies(licensed: Any) -> None:
    """A signed key cannot be un-signed; the status flag is what withdraws it."""
    key, _ = issue_key("bekci", 365, licensed)
    row = {"username": "bekci", "license_key": key, "license_status": STATUS_REVOKED}

    assert verify_key(key, "bekci", licensed).valid is True
    assert license_for("operator", row, licensed).status == STATUS_REVOKED
    assert license_for("operator", row, licensed).valid is False


def test_a_stored_active_key_passes(licensed: Any) -> None:
    key, expires_at = issue_key("bekci", 10, licensed)
    row = {
        "username": "bekci",
        "license_key": key,
        "license_expires_at": expires_at,
        "license_status": STATUS_ACTIVE,
    }
    assert license_for("operator", row, licensed).valid is True


def test_a_stored_key_belonging_to_someone_else_does_not_pass(licensed: Any) -> None:
    """Copying a colleague's key into your own row must not work either."""
    key, _ = issue_key("bekci", 10, licensed)
    row = {"username": "baskasi", "license_key": key, "license_status": STATUS_ACTIVE}
    assert license_for("operator", row, licensed).valid is False


def test_an_admin_is_unlimited_even_holding_an_expired_key(licensed: Any) -> None:
    """Role is checked before anything is read off the row."""
    past = now_utc() - timedelta(days=40)
    key, _ = issue_key("mudur", 1, licensed, now=past)
    row = {"username": "mudur", "license_key": key, "license_status": STATUS_ACTIVE}
    assert license_for("admin", row, licensed).status == STATUS_UNLIMITED
