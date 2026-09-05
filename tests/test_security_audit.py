"""Regression guards for the API security audit.

Each test here pins one conclusion from that audit. They fall into two groups:

* **Guards on defects.** These fail against the code as audited and pass once
  the matching remediation lands. They are the executable form of the finding.
* **Guards on things that are already right.** SQL parameterisation, the
  snapshot path-traversal check, ``alg=none`` rejection, the login lockout and
  the constant-cost password check for an unknown user are all correct today.
  They are cheap to break by accident, so each one is nailed down here.

Async tests are driven through :func:`run_async` rather than ``pytest-asyncio``
markers. The suite has no async plugin configured (``asyncio_mode`` is unset in
``pyproject.toml``), and a security regression guard that silently does not run
because a plugin is missing is worse than no guard at all.

The WebSocket handshake is exercised by calling
:func:`lpr.api.ws._authenticate` against a socket double rather than through
``TestClient``. ``TestClient.websocket_connect`` runs the real lifespan, which
builds the pipeline -- torch, weights, a camera -- and none of that is what
these tests are about.
"""

from __future__ import annotations

import asyncio
import queue
import threading
import time
import types
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import httpx  # noqa: E402
import jwt  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from starlette.websockets import WebSocketState  # noqa: E402

from lpr.api import deps  # noqa: E402
from lpr.api.main import create_app  # noqa: E402
from lpr.api.ratelimit import LoginLimiter  # noqa: E402
from lpr.api.security import ALGORITHM, create_token  # noqa: E402


def run_async(coro: Any) -> Any:
    """Run one coroutine to completion. See the module docstring."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Doubles
# ---------------------------------------------------------------------------


class AuditUserRepository:
    """A user repository that implements ``get()``.

    ``tests/test_api.py``'s ``FakeUserRepository`` does not, so
    ``resolve_live_user`` hits its ``except Exception`` branch there and fails
    open on every call -- which means that suite cannot see a revocation bug
    even where one exists. Revocation tests need a repository that can answer
    "is this account still there, and what role does it hold now?".
    """

    def __init__(self, users: dict[str, tuple[str, str]] | None = None) -> None:
        # username -> (password, role)
        self._users: dict[str, tuple[str, str]] = dict(users or {})

    # -- the surface routes.py is allowed to call --------------------------

    def is_first_user(self) -> bool:
        return not self._users

    def exists(self, username: str) -> bool:
        return username in self._users

    def register(self, username: str, password: str, role: str = "operator") -> bool:
        if username in self._users:
            return False
        self._users[username] = (password, role)
        return True

    def verify(self, username: str, password: str) -> bool:
        stored = self._users.get(username)
        return stored is not None and stored[0] == password

    def list_users(self) -> list[dict[str, Any]]:
        return [
            {"username": name, "role": role, "created_at": "2026-05-01"}
            for name, (_pw, role) in self._users.items()
        ]

    def get(self, username: str) -> dict[str, Any] | None:
        stored = self._users.get(username)
        if stored is None:
            return None
        return {"username": username, "role": stored[1]}

    # -- test helpers ------------------------------------------------------

    def demote(self, username: str, role: str) -> None:
        password, _old = self._users[username]
        self._users[username] = (password, role)

    def delete(self, username: str) -> None:
        self._users.pop(username, None)


class AuditPipeline:
    """Only what the stream and WebSocket routes actually touch."""

    running = True

    def stats(self) -> Any:
        return types.SimpleNamespace(
            cameras={
                "entry": types.SimpleNamespace(
                    role="entry",
                    source="0",
                    connected=True,
                    fps=1.0,
                    frames_read=1,
                    frames_dropped=0,
                    motion_skipped=0,
                    last_error=None,
                    last_frame_ts=0.0,
                )
            }
        )

    def latest_frame_jpeg(self, camera: str, quality: int = 80) -> bytes:
        return b"\xff\xd8fake\xff\xd9"

    def subscribe(self, telemetry: bool = False) -> queue.Queue[Any]:
        return queue.Queue()

    def unsubscribe(self, q: Any) -> None:
        return None


class SocketDouble:
    """Enough of ``starlette.websockets.WebSocket`` for ``_authenticate``."""

    def __init__(self, user_repo: Any) -> None:
        self.app = types.SimpleNamespace(state=types.SimpleNamespace(user_repository=user_repo))
        self.client_state = WebSocketState.CONNECTED
        self.accepted = False
        self.sent: list[str] = []
        self.closed: tuple[int, str] | None = None

    async def accept(self) -> None:
        self.accepted = True

    async def send_text(self, text: str) -> None:
        self.sent.append(text)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)


@pytest.fixture()
def no_license_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    """Switch per-user licence enforcement off for the duration of a test.

    The revocation tests must fail for the *right* reason. With a licence
    secret configured, ``license_refusal`` happens to reject a deleted
    operator -- its row is gone, so no valid licence can be read off it -- and
    a revocation test would pass without any revocation check existing. A site
    that never set ``LPR_LICENSE_SECRET`` gets no such accident, and neither
    does an admin, whom ``requires_license`` exempts outright.
    """
    monkeypatch.setattr("lpr.user_license.enforcement_enabled", lambda *a, **k: False)


@pytest.fixture()
def audit_repo() -> AuditUserRepository:
    return AuditUserRepository({"root": ("pw", "admin"), "op": ("pw", "operator")})


@pytest.fixture()
def audit_app(audit_repo: AuditUserRepository) -> Any:
    app = create_app()
    app.state.pipeline = AuditPipeline()
    app.state.user_repository = audit_repo
    app.dependency_overrides[deps.get_user_repository] = lambda: audit_repo
    return app


def asgi_client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://audit.test")


# ---------------------------------------------------------------------------
# HIGH -- revocation is not applied on every authenticated path
# ---------------------------------------------------------------------------


def test_register_refuses_a_demoted_admins_token(
    audit_app: Any, audit_repo: AuditUserRepository
) -> None:
    """``POST /api/auth/register`` must re-check the role against the database.

    The route calls ``user_from_token`` directly instead of going through
    ``current_user``, so it trusts the ``role`` claim frozen into the token.
    An administrator who has since been demoted still holds a signed token
    saying ``admin`` -- and this is the one admin-gated route that never asks
    the database whether that is still true, so it can be used to mint a fresh
    admin account and undo the demotion.

    ``GET /api/users`` is asserted alongside it as the control: it uses
    ``require_admin`` and correctly refuses the same token.
    """
    token = create_token("root", "admin")
    audit_repo.demote("root", "operator")

    async def scenario() -> tuple[int, int]:
        async with asgi_client(audit_app) as client:
            headers = {"Authorization": f"Bearer {token}"}
            control = await client.get("/api/users", headers=headers)
            escalation = await client.post(
                "/api/auth/register",
                headers=headers,
                json={"username": "backdoor", "password": "goodpass", "role": "admin"},
            )
            return control.status_code, escalation.status_code

    control_status, register_status = run_async(scenario())

    assert control_status == 403, "control: require_admin already re-checks the role"
    assert register_status == 403, (
        "a demoted admin's token created a new admin account -- privilege escalation"
    )
    assert not audit_repo.exists("backdoor")


def test_mjpeg_stream_refuses_a_deleted_account(
    audit_app: Any, audit_repo: AuditUserRepository, no_license_enforcement: None
) -> None:
    """A deleted account must lose the live camera feed.

    ``stream_user`` takes its credential from ``?token=`` and calls
    ``user_from_token`` directly, so it never runs the revocation check that
    ``current_user`` runs. The licence check it does run is not a substitute:
    it passes unconditionally for admins and for every role when licence
    enforcement is switched off.
    """
    from lpr.api.routes import stream_user

    token = create_token("op", "operator")
    audit_repo.delete("op")

    with pytest.raises(HTTPException) as excinfo:
        run_async(stream_user(user_repo=audit_repo, token=token, credentials=None))
    assert excinfo.value.status_code in (401, 403)


def test_mjpeg_stream_refuses_a_demoted_admins_token(
    audit_app: Any, audit_repo: AuditUserRepository, no_license_enforcement: None
) -> None:
    """A demoted admin must not keep streaming on the old token.

    Worth its own test because the licence check cannot catch this one at all:
    ``requires_license`` exempts admins, so a token claiming ``admin`` skips
    the only database read on this path.
    """
    from lpr.api.routes import stream_user

    token = create_token("root", "admin")
    audit_repo.demote("root", "viewer")

    user = run_async(stream_user(user_repo=audit_repo, token=token, credentials=None))
    assert user.role == "viewer", (
        "the stream honoured the stale 'admin' claim instead of the stored role"
    )


def test_websocket_refuses_a_deleted_account(
    audit_repo: AuditUserRepository, no_license_enforcement: None
) -> None:
    """The event stream is a standing subscription; deletion must end it."""
    from lpr.api.ws import CLOSE_POLICY_VIOLATION, _authenticate

    token = create_token("op", "operator")
    audit_repo.delete("op")
    socket = SocketDouble(audit_repo)

    user = run_async(_authenticate(socket, token))

    assert user is None, "a deleted account opened the live event stream"
    assert socket.closed is not None
    assert socket.closed[0] == CLOSE_POLICY_VIOLATION


def test_websocket_refuses_a_demoted_admins_token(
    audit_repo: AuditUserRepository, no_license_enforcement: None
) -> None:
    """A demoted admin's socket must carry the stored role, not the claim."""
    from lpr.api.ws import _authenticate

    token = create_token("root", "admin")
    audit_repo.demote("root", "viewer")
    socket = SocketDouble(audit_repo)

    user = run_async(_authenticate(socket, token))

    assert user is not None
    assert user.role == "viewer", "the socket announced role=admin for an account demoted to viewer"


# ---------------------------------------------------------------------------
# HIGH -- the default signing key
# ---------------------------------------------------------------------------


def test_default_secret_key_is_refused_even_when_not_headless() -> None:
    """``change-me`` must never sign tokens in production.

    The guard in ``Settings._check_secret_key_in_production`` is written as
    ``self.app.headless and is_production``. Headlessness is a logging and UI
    concern with no bearing on whether a publicly-known signing key is
    acceptable, and a site running the desktop UI in production gets no guard
    at all -- every token it issues is forgeable by anyone with the source.
    """
    import os

    from lpr.config import ApiConfig, AppConfig, Settings

    previous = os.environ.get("LPR_ENV")
    os.environ["LPR_ENV"] = "production"
    try:
        with pytest.raises(ValueError, match="secret_key"):
            Settings(
                app=AppConfig(headless=False),
                api=ApiConfig(secret_key="change-me"),
            )
    finally:
        if previous is None:
            os.environ.pop("LPR_ENV", None)
        else:
            os.environ["LPR_ENV"] = previous


# ---------------------------------------------------------------------------
# MEDIUM -- robustness
# ---------------------------------------------------------------------------


def test_telemetry_drain_does_not_block_the_event_loop() -> None:
    """The telemetry queue must be drained without waiting on the loop.

    ``events_socket`` reads the event queue through ``run_in_executor`` and
    then reads the telemetry queue inline. While that inline call was
    ``_drain`` -- which blocks for up to ``QUEUE_POLL_S`` on a
    ``queue.Queue`` -- every connected socket parked the whole event loop for
    a second per iteration on an idle gate, which is exactly the failure the
    module docstring says the executor hop exists to prevent.

    Driven through ``ws._drain_nowait``, the name the socket loop calls, so
    the guard follows the code rather than a copy of it.
    """
    from lpr.api import ws

    async def scenario() -> float:
        idle_queue: queue.Queue[Any] = queue.Queue()
        worst = 0.0
        stop = asyncio.Event()

        async def heartbeat() -> None:
            nonlocal worst
            last = time.perf_counter()
            while not stop.is_set():
                await asyncio.sleep(0)
                now = time.perf_counter()
                worst = max(worst, now - last)
                last = now

        beat = asyncio.create_task(heartbeat())
        await asyncio.sleep(0.05)
        ws._drain_nowait(idle_queue)
        stop.set()
        await beat
        return worst

    worst_gap = run_async(scenario())

    assert worst_gap < ws.QUEUE_POLL_S / 2, (
        f"the event loop stalled for {worst_gap:.3f}s draining an idle "
        f"telemetry queue; every other request in the process waits behind it"
    )


def test_telemetry_drain_still_returns_queued_items() -> None:
    """Not blocking must not mean not reading."""
    from lpr.api import ws

    q: queue.Queue[Any] = queue.Queue()
    for index in range(3):
        q.put({"seq": index})

    assert ws._drain_nowait(q) == [{"seq": 0}, {"seq": 1}, {"seq": 2}]
    assert ws._drain_nowait(q) == []


def test_bootstrap_creates_at_most_one_admin() -> None:
    """Two concurrent bootstrap registrations must not both become admin.

    ``register`` reads ``is_first_user()`` and then writes, with an ``await``
    between the two. On a fresh installation both halves of a concurrent pair
    see an empty user table, and both accounts are created with the ``admin``
    role -- so somebody who reaches the box while it is being installed gets
    an administrator account of their own alongside the installer's.
    """
    from lpr.api.routes import register
    from lpr.api.schemas import RegisterIn

    class RacingRepo(AuditUserRepository):
        """Both callers are held inside the first-account check together.

        A ``sleep`` here would make the test flaky -- whether the two threads
        actually overlap is up to the scheduler, and the window closes and
        reopens run to run. The barrier makes the overlap certain, so the test
        reports on the code rather than on thread timing.

        ``create_bootstrap_admin`` is serialised by a lock, standing in for the
        ``BEGIN IMMEDIATE`` the real repository takes. What is under test is
        whether the *route* delegates the decision to one atomic call or takes
        it itself across an ``await``.
        """

        def __init__(self, users: dict[str, tuple[str, str]] | None = None) -> None:
            super().__init__(users)
            self.gate = threading.Barrier(2, timeout=5.0)
            self.lock = threading.Lock()

        def is_first_user(self) -> bool:
            answer = not self._users
            self.gate.wait()
            return answer

        def create_bootstrap_admin(self, username: str, password: str) -> bool:
            self.gate.wait()
            with self.lock:
                if self._users:
                    return False
                return self.register(username, password, "admin")

    repo = RacingRepo({})

    async def scenario() -> None:
        async def attempt(name: str) -> None:
            try:
                await register(RegisterIn(username=name, password="goodpass"), repo, None)
            except HTTPException:
                pass

        await asyncio.gather(attempt("installer"), attempt("attacker"))

    run_async(scenario())

    admins = [row for row in repo.list_users() if row["role"] == "admin"]
    assert len(admins) == 1, (
        f"the bootstrap window created {len(admins)} admin accounts: "
        f"{[row['username'] for row in admins]}"
    )


def test_the_repository_bootstrap_claim_is_atomic(db: Any) -> None:
    """The real ``create_bootstrap_admin`` under genuine concurrency.

    The route-level guard above proves the route delegates; this proves the
    thing it delegates to actually serialises. Driven against a real SQLite
    file, because that is where ``BEGIN IMMEDIATE`` either takes the reserved
    lock or does not.
    """
    from lpr.db import UserRepository

    started = threading.Barrier(4, timeout=10.0)
    results: list[bool] = []
    results_lock = threading.Lock()

    def claim(name: str) -> None:
        repo = UserRepository()
        started.wait()
        try:
            won = repo.create_bootstrap_admin(name, "gizli123")
        except Exception:
            won = False
        with results_lock:
            results.append(won)

    threads = [threading.Thread(target=claim, args=(f"installer{index}",)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10.0)

    assert sum(results) == 1, f"{sum(results)} callers each believed they were first"
    assert UserRepository().count() == 1


def test_bootstrap_admin_password_meets_the_admin_floor() -> None:
    """The first account is an admin and must not accept a weaker password.

    ``UserCreateIn`` (an admin creating an account) requires 8 characters;
    ``RegisterIn`` requires 4, and the route forces ``admin`` for the first
    account regardless of the body. The most privileged account on the
    installation is therefore the one created under the weakest rule.
    """
    from pydantic import ValidationError

    from lpr.api.schemas import RegisterIn, UserCreateIn

    floor = UserCreateIn.model_fields["password"].metadata
    assert floor, "UserCreateIn.password should carry a length constraint"

    with pytest.raises(ValidationError):
        RegisterIn(username="adm", password="1234")


# ---------------------------------------------------------------------------
# Guards on behaviour that is already correct
# ---------------------------------------------------------------------------


def test_unsigned_and_forged_tokens_are_refused(audit_app: Any) -> None:
    """``alg=none`` and a wrong-key signature must both be rejected."""
    claims = {"sub": "mallory", "role": "admin", "exp": 4_102_444_800}
    unsigned = jwt.encode(claims, key="", algorithm="none")
    forged = jwt.encode(claims, "not-the-real-key", algorithm=ALGORITHM)

    async def scenario() -> list[int]:
        async with asgi_client(audit_app) as client:
            out = []
            for token in (unsigned, forged):
                response = await client.get(
                    "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
                )
                out.append(response.status_code)
            return out

    assert run_async(scenario()) == [401, 401]


def test_expired_token_is_refused(audit_app: Any) -> None:
    """An expired signature must not be honoured on the HTTP path."""
    expired = jwt.encode(
        {"sub": "root", "role": "admin", "exp": 1_000_000_000},
        __import__("lpr.config", fromlist=["get_settings"]).get_settings().api.secret_key,
        algorithm=ALGORITHM,
    )

    async def scenario() -> int:
        async with asgi_client(audit_app) as client:
            response = await client.get(
                "/api/auth/me", headers={"Authorization": f"Bearer {expired}"}
            )
            return response.status_code

    assert run_async(scenario()) == 401


def test_log_filters_are_bound_parameters_not_interpolated(db: Any) -> None:
    """A quote-heavy plate filter must be data, never SQL.

    ``LogRepository.query`` and ``count_matching`` build their WHERE clause
    from a fixed list of fragments and bind every value. This drives the real
    repository against a real SQLite file, so the assertion is about SQL that
    actually executed rather than about a fake that recorded its arguments.
    """
    from lpr.db import LogRepository

    repo = LogRepository()
    hostile = "34ABC123'; DROP TABLE logs; --"

    assert repo.query(plate=hostile) == []
    assert repo.count_matching(plate=hostile) == 0
    assert repo.query(camera="entry'; DROP TABLE logs; --") == []
    assert repo.query(since="2026-01-01'); DROP TABLE logs; --") == []

    # The table is still queryable, which is the whole assertion.
    assert repo.query() == []
    assert repo.count_matching() == 0


def test_login_locks_out_after_repeated_failures() -> None:
    """Progressive lockout must engage, and must not be cleared by a flood."""
    clock = {"t": 0.0}
    limiter = LoginLimiter(clock=lambda: clock["t"])

    for _ in range(5):
        limiter.record_attempt("10.0.0.9")
        limiter.record_failure("10.0.0.9", "root")

    assert limiter.is_locked("root")
    assert not limiter.check("10.0.0.9", "root").allowed
    # A different address does not help: the lockout is keyed on the username.
    assert not limiter.check("10.0.0.10", "root").allowed
    # ...and it expires rather than being permanent.
    clock["t"] += 3600.0
    assert not limiter.is_locked("root")


def test_unknown_user_still_costs_a_password_hash() -> None:
    """A missing account must not be measurably faster than a wrong password.

    ``UserRepository.verify`` hashes a dummy value when the row is absent.
    Without that, response time answers "does this username exist?" for free.
    """
    import inspect

    from lpr.db.repository import UserRepository

    source = inspect.getsource(UserRepository.verify)
    row_is_none = source.split("if row is None:", 1)
    assert len(row_is_none) == 2, "verify() no longer has a missing-row branch"
    assert "hash(password)" in row_is_none[1].split("return False", 1)[0], (
        "the missing-user branch of verify() no longer spends a hash; "
        "username enumeration by timing is back"
    )
