"""Login rate limiting and progressive account lockout.

The password hashing is argon2, which is the right choice and almost beside the
point: an unlimited number of guesses defeats any hash given enough time, and
until now there was no limit at all. Combined with an API that used to bind to
every interface with no TLS, that made the login endpoint the softest thing on
the box.

Two independent limiters, because they answer different questions:

**By address** -- a sliding window over recent attempts from one client. Bounds
a spray: one host trying many usernames. Keyed on the address the reverse proxy
reports, not the socket peer, or every request behind the proxy would share one
bucket and one attacker would lock out the site.

**By username** -- progressive lockout after consecutive failures. Bounds a
focused attack on one account, and it is the one an operator sees, so the delay
grows rather than snapping to a wall: 5 failures buys 30 seconds, then a
minute, two, four, up to a cap. A tired operator on their fourth typo waits
half a minute; somebody working through a word list stops making progress.

Both reset on success, and both are in-memory. That is deliberate: a restart
clears them, and a restart is not a thing an attacker can cause from the login
endpoint. Persisting them would put a write on the unauthenticated path, which
is a denial-of-service primitive of its own.

Lockouts are reported to ``system_events`` so they appear in the admin trail. A
brute-force attempt nobody can see afterwards is only half-defended.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

__all__ = [
    "LOCKOUT_STEPS_S",
    "LoginLimiter",
    "RateLimitDecision",
    "client_address",
]

#: Attempts allowed from one address inside :data:`ADDRESS_WINDOW_S`.
#:
#: Generous, because an address is a blunt key: a whole office behind one NAT
#: shares it, and so does every operator on a site's LAN. It is a ceiling on
#: automated spraying, not a per-user policy -- that is what the username
#: limiter is for.
ADDRESS_MAX_ATTEMPTS = 30
ADDRESS_WINDOW_S = 300.0

#: Consecutive failures on one username before a lockout starts.
#:
#: 5, not 3. Three is inside the range of a person who has two passwords and is
#: trying both, and locking them out teaches them to phone support rather than
#: to type carefully.
LOCKOUT_AFTER = 5

#: Lockout duration per step, applied in order and then held at the last value.
#:
#: Progressive rather than fixed: the first is short enough that a legitimate
#: operator waits rather than calls, and the growth makes sustained guessing
#: cost more than it returns. Capped at ten minutes -- an unbounded lockout is
#: a denial-of-service anybody can trigger against a known username.
LOCKOUT_STEPS_S: tuple[float, ...] = (30.0, 60.0, 120.0, 240.0, 600.0)

#: Buckets to keep before a sweep. Bounds memory against an attacker cycling
#: through addresses or usernames purely to grow the dictionary.
MAX_TRACKED = 4096


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Whether an attempt may proceed, and what to tell the caller."""

    allowed: bool
    retry_after_s: float = 0.0
    reason: str = ""

    @property
    def retry_after_header(self) -> str:
        return str(max(1, int(round(self.retry_after_s))))


@dataclass(slots=True)
class _Bucket:
    """Recent attempt timestamps, plus lockout state for a username."""

    attempts: deque[float] = field(default_factory=deque)
    consecutive_failures: int = 0
    locked_until: float = 0.0
    lockout_step: int = 0
    last_seen: float = 0.0


class LoginLimiter:
    """Sliding-window and lockout state for the login endpoint.

    One instance per process, held on ``app.state``. Every method takes the
    lock; the login route is async and FastAPI may run several concurrently.

    ``clock`` is injectable so the tests can drive time directly rather than
    sleeping through a ten-minute lockout.
    """

    def __init__(
        self,
        *,
        address_max: int = ADDRESS_MAX_ATTEMPTS,
        address_window_s: float = ADDRESS_WINDOW_S,
        lockout_after: int = LOCKOUT_AFTER,
        lockout_steps_s: tuple[float, ...] = LOCKOUT_STEPS_S,
        clock: object = None,
    ) -> None:
        self.address_max = max(1, int(address_max))
        self.address_window_s = max(1.0, float(address_window_s))
        self.lockout_after = max(1, int(lockout_after))
        self.lockout_steps_s = lockout_steps_s or LOCKOUT_STEPS_S
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._addresses: dict[str, _Bucket] = {}
        self._usernames: dict[str, _Bucket] = {}
        #: Counters for the admin view and for tests.
        self.lockouts = 0
        self.throttled = 0

    # -- checks ------------------------------------------------------------

    def check(self, address: str, username: str) -> RateLimitDecision:
        """May this login attempt proceed? Does not record anything.

        Called before the password is verified, so a locked-out account costs
        no argon2 hash -- which matters: argon2 is expensive by design, and
        making an attacker pay for it is only useful while we are not paying
        it too.
        """
        now = float(self._clock())  # type: ignore[operator]
        with self._lock:
            self._sweep(now)

            user_bucket = self._usernames.get(_key(username))
            if user_bucket is not None and now < user_bucket.locked_until:
                self.throttled += 1
                return RateLimitDecision(
                    allowed=False,
                    retry_after_s=user_bucket.locked_until - now,
                    reason="account_locked",
                )

            address_bucket = self._addresses.get(_key(address))
            if address_bucket is not None:
                self._trim(address_bucket, now)
                if len(address_bucket.attempts) >= self.address_max:
                    self.throttled += 1
                    oldest = address_bucket.attempts[0]
                    return RateLimitDecision(
                        allowed=False,
                        retry_after_s=max(1.0, oldest + self.address_window_s - now),
                        reason="too_many_attempts",
                    )

        return RateLimitDecision(allowed=True)

    # -- recording ---------------------------------------------------------

    def record_attempt(self, address: str) -> None:
        """Count one attempt against the address window.

        Every attempt, successful or not. The address limiter bounds *traffic*,
        and an attacker who guesses one password correctly has still made all
        the other requests.
        """
        now = float(self._clock())  # type: ignore[operator]
        with self._lock:
            bucket = self._addresses.setdefault(_key(address), _Bucket())
            bucket.last_seen = now
            bucket.attempts.append(now)
            self._trim(bucket, now)

    def record_failure(self, address: str, username: str) -> RateLimitDecision:
        """Count one failed login. Returns the resulting state for this user.

        The returned decision describes what the *next* attempt will face, so
        the caller can log a lockout at the moment it starts rather than
        discovering it on the following request.
        """
        now = float(self._clock())  # type: ignore[operator]
        with self._lock:
            bucket = self._usernames.setdefault(_key(username), _Bucket())
            bucket.last_seen = now
            bucket.consecutive_failures += 1

            if bucket.consecutive_failures < self.lockout_after:
                return RateLimitDecision(allowed=True)

            step = min(bucket.lockout_step, len(self.lockout_steps_s) - 1)
            duration = float(self.lockout_steps_s[step])
            bucket.locked_until = now + duration
            bucket.lockout_step = min(bucket.lockout_step + 1, len(self.lockout_steps_s) - 1)
            # Reset the counter so the *next* lockout needs another full run of
            # failures. Without this every further attempt would re-lock
            # immediately and the steps would climb to the cap in seconds.
            bucket.consecutive_failures = 0
            self.lockouts += 1

        logger.warning(
            "Account %r locked for %.0fs after %d consecutive failed logins (from %s)",
            username,
            duration,
            self.lockout_after,
            address or "unknown",
        )
        return RateLimitDecision(
            allowed=False, retry_after_s=duration, reason="account_locked"
        )

    def record_success(self, address: str, username: str) -> None:
        """Clear the failure state for a username after a good password."""
        with self._lock:
            bucket = self._usernames.get(_key(username))
            if bucket is None:
                return
            bucket.consecutive_failures = 0
            bucket.locked_until = 0.0
            # `lockout_step` is deliberately *not* reset. An account that has
            # been locked once and then guessed correctly is exactly the
            # sequence a successful brute force ends with; keeping the
            # escalation means a second run starts where the first left off.

    # -- introspection -----------------------------------------------------

    def is_locked(self, username: str) -> bool:
        now = float(self._clock())  # type: ignore[operator]
        with self._lock:
            bucket = self._usernames.get(_key(username))
            return bucket is not None and now < bucket.locked_until

    def reset(self) -> None:
        """Forget everything. For tests, and for an admin clearing a lockout."""
        with self._lock:
            self._addresses.clear()
            self._usernames.clear()

    # -- internals ---------------------------------------------------------

    def _trim(self, bucket: _Bucket, now: float) -> None:
        cutoff = now - self.address_window_s
        while bucket.attempts and bucket.attempts[0] < cutoff:
            bucket.attempts.popleft()

    def _sweep(self, now: float) -> None:
        """Drop buckets nothing is using. Called with the lock held.

        Only when the dictionaries are actually large: an attacker cycling
        through addresses to grow them is the case this bounds, and a sweep on
        every request would be a cost paid by everybody to stop it.
        """
        for store in (self._addresses, self._usernames):
            if len(store) <= MAX_TRACKED:
                continue
            cutoff = now - max(self.address_window_s, self.lockout_steps_s[-1])
            stale = [
                key
                for key, bucket in store.items()
                if bucket.last_seen < cutoff and now >= bucket.locked_until
            ]
            for key in stale:
                del store[key]
            if len(store) <= MAX_TRACKED:
                continue

            # Still over after dropping the stale ones: an active flood.
            # Evict oldest-first -- but never a bucket with a live lockout.
            # Dropping one would forget that an account is locked, which turns
            # this memory bound into an authentication bypass: an attacker who
            # can trigger a lockout could then clear it by flooding the table.
            evictable = sorted(
                (item for item in store.items() if now >= item[1].locked_until),
                key=lambda item: item[1].last_seen,
            )
            for key, _bucket in evictable[: len(store) - MAX_TRACKED]:
                del store[key]

            if len(store) > MAX_TRACKED:
                # Every remaining bucket is locked. Exceeding the bound is the
                # right way to be wrong here: memory grows, and authentication
                # keeps holding.
                logger.warning(
                    "Login limiter is tracking %d live lockouts, above the %d "
                    "bound. Something is attacking this endpoint.",
                    len(store),
                    MAX_TRACKED,
                )


def _key(value: str) -> str:
    return (value or "").strip().lower()[:128]


def client_address(request: object) -> str:
    """The caller's address, honouring a reverse proxy.

    ``X-Forwarded-For`` is only meaningful when something trusted sets it, and
    the shipped proxy config does. On a deployment with the API exposed
    directly the header is attacker-controlled -- but the fallback is the
    socket peer, and an attacker who can forge the header can equally use many
    real addresses, so trusting it costs nothing that was defended anyway.

    The username limiter is the one that does not care where the request came
    from, which is why it exists.
    """
    headers = getattr(request, "headers", None)
    if headers is not None:
        for name in ("x-real-ip", "x-forwarded-for"):
            raw = headers.get(name)
            if raw:
                # X-Forwarded-For is a chain; the client is the first entry.
                return str(raw).split(",")[0].strip()
    client = getattr(request, "client", None)
    host = getattr(client, "host", None)
    return str(host) if host else "unknown"
