"""Tests for login rate limiting and progressive account lockout.

Pure logic, driven with an injected clock rather than sleeps -- the last
lockout step is ten minutes, and a suite that waited for it would not be run.

The assertions worth reading first are the ones about *not* locking somebody
out: a limiter that is easy to trip is a limiter an operator disables, and then
the login endpoint is unprotected again with a config flag that says otherwise.
"""

from __future__ import annotations

import pytest

from lpr.api.ratelimit import (
    LOCKOUT_STEPS_S,
    LoginLimiter,
    client_address,
)


class FakeClock:
    """A monotonic clock the test drives by hand."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def limiter(clock: FakeClock) -> LoginLimiter:
    return LoginLimiter(address_max=5, address_window_s=60.0, lockout_after=3, clock=clock)


def fail_times(limiter: LoginLimiter, count: int, user: str = "admin") -> None:
    for _ in range(count):
        limiter.record_attempt("10.0.0.1")
        limiter.record_failure("10.0.0.1", user)


# ---------------------------------------------------------------------------
# The normal case: nobody is locked out
# ---------------------------------------------------------------------------


def test_a_first_attempt_is_allowed(limiter: LoginLimiter) -> None:
    assert limiter.check("10.0.0.1", "admin").allowed is True


def test_a_few_typos_do_not_lock_an_account(limiter: LoginLimiter) -> None:
    """A limiter that is easy to trip is a limiter an operator turns off."""
    fail_times(limiter, 2)
    assert limiter.check("10.0.0.1", "admin").allowed is True
    assert limiter.is_locked("admin") is False


def test_a_success_clears_the_failure_count(limiter: LoginLimiter) -> None:
    """Two typos yesterday must not count towards a lockout today."""
    fail_times(limiter, 2)
    limiter.record_success("10.0.0.1", "admin")
    fail_times(limiter, 2)
    assert limiter.is_locked("admin") is False


# ---------------------------------------------------------------------------
# Lockout
# ---------------------------------------------------------------------------


def test_consecutive_failures_lock_the_account(limiter: LoginLimiter) -> None:
    fail_times(limiter, 3)
    decision = limiter.check("10.0.0.1", "admin")
    assert decision.allowed is False
    assert decision.reason == "account_locked"
    assert decision.retry_after_s == pytest.approx(LOCKOUT_STEPS_S[0])


def test_the_lockout_expires(limiter: LoginLimiter, clock: FakeClock) -> None:
    """An unbounded lockout is a denial of service anybody can trigger."""
    fail_times(limiter, 3)
    assert limiter.check("10.0.0.1", "admin").allowed is False

    clock.advance(LOCKOUT_STEPS_S[0] + 1)
    assert limiter.check("10.0.0.1", "admin").allowed is True


def test_lockouts_escalate(limiter: LoginLimiter, clock: FakeClock) -> None:
    """Sustained guessing must cost more than it returns."""
    durations = []
    for _ in range(3):
        fail_times(limiter, 3)
        durations.append(limiter.check("10.0.0.1", "admin").retry_after_s)
        clock.advance(durations[-1] + 1)

    assert durations[0] == pytest.approx(LOCKOUT_STEPS_S[0])
    assert durations[1] == pytest.approx(LOCKOUT_STEPS_S[1])
    assert durations[2] == pytest.approx(LOCKOUT_STEPS_S[2])


def test_escalation_is_capped(limiter: LoginLimiter, clock: FakeClock) -> None:
    for _ in range(len(LOCKOUT_STEPS_S) + 3):
        fail_times(limiter, 3)
        wait = limiter.check("10.0.0.1", "admin").retry_after_s
        clock.advance(wait + 1)
    assert wait == pytest.approx(LOCKOUT_STEPS_S[-1])


def test_a_lockout_does_not_re_lock_on_every_further_attempt(
    limiter: LoginLimiter,
) -> None:
    """Without resetting the counter the steps would reach the cap in seconds."""
    fail_times(limiter, 3)
    first = limiter.check("10.0.0.1", "admin").retry_after_s
    limiter.record_failure("10.0.0.1", "admin")
    assert limiter.check("10.0.0.1", "admin").retry_after_s == pytest.approx(first)


def test_the_escalation_survives_a_successful_guess(
    limiter: LoginLimiter, clock: FakeClock
) -> None:
    """A lockout followed by a success is how a brute force *ends*.

    Resetting the escalation there would let an attacker who found one password
    start the next account from the shortest step.
    """
    fail_times(limiter, 3)
    clock.advance(LOCKOUT_STEPS_S[0] + 1)
    limiter.record_success("10.0.0.1", "admin")

    fail_times(limiter, 3)
    assert limiter.check("10.0.0.1", "admin").retry_after_s == pytest.approx(LOCKOUT_STEPS_S[1]), (
        "the second lockout starts where the first left off"
    )


def test_one_account_lockout_does_not_affect_another(limiter: LoginLimiter) -> None:
    fail_times(limiter, 3, user="admin")
    assert limiter.check("10.0.0.1", "admin").allowed is False
    assert limiter.check("10.0.0.2", "operator").allowed is True


def test_usernames_are_compared_case_insensitively(limiter: LoginLimiter) -> None:
    """`Admin` and `admin` are the same account; the lockout must follow."""
    fail_times(limiter, 3, user="Admin")
    assert limiter.check("10.0.0.1", "admin").allowed is False


# ---------------------------------------------------------------------------
# Address window
# ---------------------------------------------------------------------------


def test_the_address_window_bounds_a_spray(limiter: LoginLimiter) -> None:
    """One host trying many usernames never trips a per-account lockout."""
    for index in range(5):
        limiter.record_attempt("10.0.0.9")
        limiter.record_failure("10.0.0.9", f"user{index}")
    decision = limiter.check("10.0.0.9", "user99")
    assert decision.allowed is False
    assert decision.reason == "too_many_attempts"


def test_the_address_window_slides(limiter: LoginLimiter, clock: FakeClock) -> None:
    for index in range(5):
        limiter.record_attempt("10.0.0.9")
        limiter.record_failure("10.0.0.9", f"user{index}")
    assert limiter.check("10.0.0.9", "x").allowed is False

    clock.advance(61.0)
    assert limiter.check("10.0.0.9", "x").allowed is True


def test_successful_logins_count_towards_the_address_window(
    limiter: LoginLimiter,
) -> None:
    """An attacker who guesses one password has still made the other requests."""
    for _ in range(5):
        limiter.record_attempt("10.0.0.9")
    assert limiter.check("10.0.0.9", "someone").allowed is False


def test_another_address_is_unaffected(limiter: LoginLimiter) -> None:
    for _ in range(5):
        limiter.record_attempt("10.0.0.9")
    assert limiter.check("10.0.0.10", "someone").allowed is True


# ---------------------------------------------------------------------------
# Memory bounds
# ---------------------------------------------------------------------------


def test_tracking_is_bounded(clock: FakeClock) -> None:
    """An attacker cycling addresses must not be able to grow the dictionary."""
    import lpr.api.ratelimit as module

    limiter = LoginLimiter(clock=clock)
    for index in range(module.MAX_TRACKED + 500):
        limiter.record_attempt(f"10.1.{index // 256}.{index % 256}")
        clock.advance(0.001)
        limiter.check("10.0.0.1", "admin")

    assert len(limiter._addresses) <= module.MAX_TRACKED + 1


def test_eviction_never_forgets_a_live_lockout(clock: FakeClock) -> None:
    """Evicting a locked account would turn a memory bound into a bypass."""
    import lpr.api.ratelimit as module

    limiter = LoginLimiter(lockout_after=1, clock=clock)
    limiter.record_failure("10.0.0.1", "victim")
    assert limiter.is_locked("victim")

    for index in range(module.MAX_TRACKED + 100):
        limiter.record_failure("10.0.0.2", f"noise{index}")
        limiter.check("10.0.0.2", "x")

    assert limiter.is_locked("victim"), "the live lockout was swept away"


# ---------------------------------------------------------------------------
# Client address resolution
# ---------------------------------------------------------------------------


class FakeRequest:
    def __init__(self, headers: dict[str, str] | None = None, host: str | None = None) -> None:
        self.headers = headers or {}
        self.client = type("C", (), {"host": host})() if host else None


def test_the_socket_peer_is_used_without_a_proxy() -> None:
    assert client_address(FakeRequest(host="192.168.1.5")) == "192.168.1.5"


def test_x_real_ip_wins_when_the_proxy_sets_it() -> None:
    """Without this every request behind the proxy shares one bucket, and one
    brute-force attempt locks out the whole site."""
    request = FakeRequest(headers={"x-real-ip": "203.0.113.7"}, host="172.18.0.2")
    assert client_address(request) == "203.0.113.7"


def test_the_first_entry_of_a_forwarded_chain_is_the_client() -> None:
    request = FakeRequest(headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1"})
    assert client_address(request) == "203.0.113.7"


def test_an_unknowable_address_does_not_raise() -> None:
    assert client_address(FakeRequest()) == "unknown"
