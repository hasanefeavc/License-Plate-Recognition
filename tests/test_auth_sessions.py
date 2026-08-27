"""Role-scoped session lengths and token revocation.

Two things are under test and they pull against each other. Administrators get
a session measured in months so they stay signed in; that makes a signed claim
long-lived enough to go stale, which is why the account behind a token is
re-read on every request. Without the second half the first half would mean a
deleted admin keeps their access for a year.
"""

from __future__ import annotations

from typing import Any

import pytest

from lpr.api.security import (
    ADMIN_ROLE,
    OPERATOR_ROLE,
    AuthError,
    AuthUser,
    create_token,
    decode_token,
    resolve_live_user,
    token_ttl_seconds,
)

# ---------------------------------------------------------------------------
# Session length
# ---------------------------------------------------------------------------


def test_an_admin_session_is_measured_in_months() -> None:
    """Staying logged in continuously is the requirement."""
    assert token_ttl_seconds(ADMIN_ROLE) >= 300 * 86400


def test_an_operator_session_is_one_shift() -> None:
    """A session outliving the shift on a shared gate terminal is the risk."""
    assert token_ttl_seconds(OPERATOR_ROLE) == 8 * 3600


def test_an_admin_session_is_longer_than_an_operator_one() -> None:
    assert token_ttl_seconds(ADMIN_ROLE) > token_ttl_seconds(OPERATOR_ROLE)


def test_a_per_account_override_beats_the_role_policy() -> None:
    assert token_ttl_seconds(ADMIN_ROLE, override_min=60) == 3600
    assert token_ttl_seconds(OPERATOR_ROLE, override_min=1440) == 86400


def test_an_unknown_role_falls_back_to_the_generic_policy(tmp_settings: Any) -> None:
    assert token_ttl_seconds("auditor") == tmp_settings.api.token_ttl_min * 60


def test_a_zero_override_is_ignored_rather_than_minting_a_dead_token() -> None:
    """0 means "unset" throughout; it must not resolve to an instant expiry."""
    assert token_ttl_seconds(OPERATOR_ROLE, override_min=0) == 8 * 3600


def test_the_lifetime_reaches_the_issued_token() -> None:
    """The policy is worthless if create_token does not apply it."""
    admin = decode_token(create_token("mudur", ADMIN_ROLE))
    operator = decode_token(create_token("bekci", OPERATOR_ROLE))
    assert admin["exp"] - admin["iat"] > operator["exp"] - operator["iat"]


def test_an_override_reaches_the_issued_token() -> None:
    claims = decode_token(create_token("gece", OPERATOR_ROLE, ttl_minutes=60))
    assert claims["exp"] - claims["iat"] == 3600


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


class Repo:
    def __init__(self, rows: dict[str, str] | None = None) -> None:
        self.rows = dict(rows or {})
        self.lookups = 0

    def get(self, username: str) -> dict[str, Any] | None:
        self.lookups += 1
        role = self.rows.get(username)
        return None if role is None else {"username": username, "role": role}


def test_a_live_account_passes_through() -> None:
    user = AuthUser("mudur", ADMIN_ROLE)
    assert resolve_live_user(user, Repo({"mudur": ADMIN_ROLE})) == user


def test_a_deleted_account_is_rejected_immediately() -> None:
    """Otherwise "delete user" would take up to a year to mean anything."""
    with pytest.raises(AuthError):
        resolve_live_user(AuthUser("silinen", ADMIN_ROLE), Repo())


def test_a_demoted_admin_loses_admin_on_the_next_request() -> None:
    """The token still claims admin; the database is what decides."""
    resolved = resolve_live_user(AuthUser("eski", ADMIN_ROLE), Repo({"eski": OPERATOR_ROLE}))
    assert resolved.role == OPERATOR_ROLE
    assert resolved.is_admin is False


def test_a_promoted_operator_gains_admin_without_signing_in_again() -> None:
    resolved = resolve_live_user(AuthUser("yeni", OPERATOR_ROLE), Repo({"yeni": ADMIN_ROLE}))
    assert resolved.is_admin is True


def test_a_lookup_failure_honours_the_token() -> None:
    """A transient database error must not lock every operator out of a gate.

    This is a revocation layer over a signature that is still valid; failing
    closed here would take the whole API down with the database.
    """

    class Broken:
        def get(self, username: str) -> dict[str, Any] | None:
            raise RuntimeError("database is locked")

    user = AuthUser("bekci", OPERATOR_ROLE)
    assert resolve_live_user(user, Broken()) == user


def test_the_check_is_a_single_lookup_per_call() -> None:
    """It runs on every authenticated request, so its cost is the design."""
    repo = Repo({"mudur": ADMIN_ROLE})
    resolve_live_user(AuthUser("mudur", ADMIN_ROLE), repo)
    assert repo.lookups == 1
