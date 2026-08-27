"""Tests for the OTA self-update mechanism.

No git checkout, no Docker daemon and no network are involved: ``SystemUpdater``
takes an injectable command runner, so every branch -- a diverged checkout, a
denied Docker socket, a timeout, a no-op pull -- is driven as a scripted
sequence of command results.

The security-relevant assertions are the ones worth reading first: that the
feature is off unless enabled, that no caller-supplied value can reach a
command, and that the commands are argument lists rather than shell strings.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from lpr.updater import CommandResult, SystemUpdater


class ScriptedRunner:
    """Answers each command from a table, recording everything it was asked."""

    def __init__(self, responses: dict[str, CommandResult] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[tuple[str, ...], Path, float]] = []

    def __call__(self, command: Sequence[str], cwd: Path, timeout: float) -> CommandResult:
        argv = tuple(str(part) for part in command)
        self.calls.append((argv, cwd, timeout))
        for key, result in self.responses.items():
            if key in " ".join(argv):
                return result
        return CommandResult(command=argv, returncode=0, stdout="ok")

    @property
    def commands(self) -> list[str]:
        return [" ".join(argv) for argv, _, _ in self.calls]

    def ran(self, fragment: str) -> bool:
        return any(fragment in command for command in self.commands)


def ok(stdout: str = "") -> CommandResult:
    return CommandResult(command=(), returncode=0, stdout=stdout)


def fail(code: int = 1, stderr: str = "") -> CommandResult:
    return CommandResult(command=(), returncode=code, stderr=stderr)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """A directory that looks enough like a git checkout to proceed."""
    (tmp_path / ".git").mkdir()
    return tmp_path


def build(
    settings: Any,
    repo: Path,
    runner: ScriptedRunner,
    enabled: bool = True,
    **overrides: Any,
) -> SystemUpdater:
    settings.system_update.enabled = enabled
    settings.system_update.repo_dir = str(repo)
    settings.system_update.state_file = str(repo / "last_update.json")
    for key, value in overrides.items():
        setattr(settings.system_update, key, value)
    return SystemUpdater(settings, runner=runner)


class AdvancingRunner(ScriptedRunner):
    """A runner where ``git rev-parse HEAD`` reports a different commit each call.

    That is what makes the updater treat the pull as having moved the checkout
    forward and go on to the rebuild; a runner that answers the same commit
    twice exercises the already-current path instead.
    """

    def __init__(
        self,
        revisions: Sequence[str] = ("aaaaaaa", "bbbbbbb"),
        responses: dict[str, CommandResult] | None = None,
    ) -> None:
        super().__init__(responses)
        self._revisions = list(revisions)
        self._index = 0

    def __call__(self, command: Sequence[str], cwd: Path, timeout: float) -> CommandResult:
        argv = tuple(str(part) for part in command)
        if " ".join(argv) == "git rev-parse HEAD":
            self.calls.append((argv, cwd, timeout))
            value = self._revisions[min(self._index, len(self._revisions) - 1)]
            self._index += 1
            return ok(value)
        return super().__call__(command, cwd, timeout)


def run_to_completion(updater: SystemUpdater) -> Any:
    """Start an update and wait for its thread, so assertions are deterministic."""
    updater.start()
    thread = updater._thread
    assert thread is not None
    thread.join(timeout=10)
    assert not thread.is_alive(), "update thread did not finish"
    return updater.status


# ---------------------------------------------------------------------------
# Gating
# ---------------------------------------------------------------------------


def test_the_updater_is_disabled_by_default(tmp_settings: Any) -> None:
    """Shipping a live self-update endpoint by default would be indefensible."""
    assert SystemUpdater(tmp_settings).enabled is False


def test_a_disabled_updater_refuses_to_start(tmp_settings: Any, repo: Path) -> None:
    updater = build(tmp_settings, repo, ScriptedRunner(), enabled=False)
    with pytest.raises(RuntimeError, match="devre dışı"):
        updater.start()


def test_a_second_concurrent_update_is_refused(tmp_settings: Any, repo: Path) -> None:
    """Two admins pressing the button must not race a build against a checkout."""
    import threading

    release = threading.Event()

    class BlockingRunner(ScriptedRunner):
        def __call__(self, command, cwd, timeout):  # type: ignore[no-untyped-def]
            if "pull" in " ".join(str(p) for p in command):
                release.wait(timeout=5)
            return super().__call__(command, cwd, timeout)

    updater = build(tmp_settings, repo, BlockingRunner())
    updater.start()
    try:
        with pytest.raises(RuntimeError, match="devam eden"):
            updater.start()
    finally:
        release.set()
        if updater._thread:
            updater._thread.join(timeout=10)


# ---------------------------------------------------------------------------
# Command construction (the security-relevant half)
# ---------------------------------------------------------------------------


def test_the_pull_is_fast_forward_only(tmp_settings: Any, repo: Path) -> None:
    """A merge commit or conflict markers on a production box is not recovery."""
    runner = ScriptedRunner({"rev-parse HEAD": ok("aaa")})
    run_to_completion(build(tmp_settings, repo, runner))
    assert runner.ran("git pull --ff-only origin main")


def test_the_remote_and_branch_come_from_config_not_the_caller(
    tmp_settings: Any, repo: Path
) -> None:
    """A stolen admin token must not be able to redirect the pull."""
    runner = ScriptedRunner({"rev-parse HEAD": ok("aaa")})
    run_to_completion(
        build(tmp_settings, repo, runner, git_remote="upstream", git_branch="release")
    )
    assert runner.ran("git pull --ff-only upstream release")


def test_every_command_is_an_argument_list_never_a_shell_string(
    tmp_settings: Any, repo: Path
) -> None:
    """No command may contain a shell metacharacter that could be broken out of."""
    runner = ScriptedRunner({"rev-parse HEAD": ok("aaa")})
    run_to_completion(build(tmp_settings, repo, runner))
    for argv, _, _ in runner.calls:
        assert isinstance(argv, tuple)
        for part in argv:
            assert not any(ch in part for ch in ";|&$`\n"), part


def test_the_compose_file_is_passed_through(tmp_settings: Any, repo: Path) -> None:
    runner = AdvancingRunner()
    run_to_completion(build(tmp_settings, repo, runner, compose_file="docker/docker-compose.yml"))
    assert any(
        "up -d --build" in command and "docker/docker-compose.yml" in command
        for command in runner.commands
    )


def test_each_step_is_given_a_timeout(tmp_settings: Any, repo: Path) -> None:
    """A hung fetch must not pin a thread for the life of the process."""
    runner = ScriptedRunner({"rev-parse HEAD": ok("aaa")})
    run_to_completion(build(tmp_settings, repo, runner))
    assert all(timeout > 0 for _, _, timeout in runner.calls)


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_a_successful_update_rebuilds_and_reports_both_commits(
    tmp_settings: Any, repo: Path
) -> None:
    runner = AdvancingRunner()
    status = run_to_completion(build(tmp_settings, repo, runner))
    assert status.state == "succeeded"
    assert status.commit_before == "aaaaaaa"
    assert status.commit_after == "bbbbbbb"
    assert runner.ran("up -d --build")


def test_an_already_current_checkout_skips_the_rebuild(tmp_settings: Any, repo: Path) -> None:
    """Rebuilding for no reason means an unnecessary outage at the gate."""
    runner = ScriptedRunner({"rev-parse HEAD": ok("samecommit")})
    status = run_to_completion(build(tmp_settings, repo, runner))
    assert status.state == "succeeded"
    assert "zaten güncel" in status.detail.lower()
    assert not runner.ran("up -d --build")


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


def test_a_directory_that_is_not_a_checkout_fails_cleanly(
    tmp_settings: Any, tmp_path: Path
) -> None:
    runner = ScriptedRunner()
    updater = build(tmp_settings, tmp_path / "plain", runner)
    (tmp_path / "plain").mkdir(exist_ok=True)
    status = run_to_completion(updater)
    assert status.state == "failed"
    assert not runner.ran("git pull")


def test_a_diverged_checkout_is_explained_not_forced(tmp_settings: Any, repo: Path) -> None:
    runner = ScriptedRunner(
        {
            "rev-parse HEAD": ok("aaa"),
            "git pull": fail(128, "fatal: Not possible to fast-forward, aborting."),
        }
    )
    status = run_to_completion(build(tmp_settings, repo, runner))
    assert status.state == "failed"
    assert status.step == "pull"
    assert "ayrışmış" in status.detail
    assert not runner.ran("up -d --build"), "a failed pull must never reach the rebuild"


def test_local_changes_are_reported_as_such(tmp_settings: Any, repo: Path) -> None:
    runner = ScriptedRunner(
        {
            "rev-parse HEAD": ok("aaa"),
            "git pull": fail(1, "error: Your local changes would be overwritten"),
        }
    )
    status = run_to_completion(build(tmp_settings, repo, runner))
    assert status.state == "failed"
    assert "yerel değişiklikler" in status.detail.lower()


def test_a_denied_docker_socket_is_explained(tmp_settings: Any, repo: Path) -> None:
    """The most common real-world failure deserves an actionable message."""
    runner = AdvancingRunner(
        responses={
            "up -d --build": fail(
                1,
                "permission denied while trying to connect to the Docker "
                "daemon socket at unix:///var/run/docker.sock",
            )
        }
    )
    status = run_to_completion(build(tmp_settings, repo, runner))
    assert status.state == "failed"
    assert status.step == "build"
    assert "docker soketine erişim reddedildi" in status.detail.lower()


def test_a_missing_binary_is_explained(tmp_settings: Any, repo: Path) -> None:
    runner = ScriptedRunner({"rev-parse HEAD": ok("aaa"), "git pull": fail(127, "not found")})
    status = run_to_completion(build(tmp_settings, repo, runner))
    assert status.state == "failed"
    assert "git bulunamadı" in status.detail


def test_a_build_timeout_is_explained(tmp_settings: Any, repo: Path) -> None:
    runner = AdvancingRunner(responses={"up -d --build": fail(124, "timeout")})
    status = run_to_completion(build(tmp_settings, repo, runner))
    assert status.state == "failed"
    assert "zaman aşımı" in status.detail.lower()


# ---------------------------------------------------------------------------
# State persistence across the restart
# ---------------------------------------------------------------------------


def test_the_outcome_is_written_before_the_rebuild_starts(tmp_settings: Any, repo: Path) -> None:
    """compose kills this container mid-call; the breadcrumb must precede it."""
    state_file = repo / "last_update.json"
    seen: dict[str, Any] = {}

    class Runner(AdvancingRunner):
        def __call__(self, command, cwd, timeout):  # type: ignore[no-untyped-def]
            if "up -d --build" in " ".join(str(p) for p in command):
                # Snapshot what a container killed mid-rebuild would leave behind.
                seen["state"] = json.loads(state_file.read_text())["state"]
            return super().__call__(command, cwd, timeout)

    run_to_completion(build(tmp_settings, repo, Runner()))
    assert seen["state"] == "restarting"


def test_a_restarted_container_reports_the_update_as_finished(
    tmp_settings: Any, repo: Path
) -> None:
    """Reaching __init__ at all is the evidence the rebuild worked."""
    state_file = repo / "last_update.json"
    state_file.write_text(
        json.dumps(
            {
                "state": "restarting",
                "step": "build",
                "started_at": 1.0,
                "commit_before": "aaa",
                "commit_after": "bbb",
                "log": ["$ git pull"],
            }
        )
    )
    updater = build(tmp_settings, repo, ScriptedRunner())
    assert updater.status.state == "succeeded"
    assert updater.status.commit_after == "bbb"


def test_a_corrupt_state_file_is_ignored(tmp_settings: Any, repo: Path) -> None:
    (repo / "last_update.json").write_text("{not json")
    updater = build(tmp_settings, repo, ScriptedRunner())
    assert updater.status.state == "idle"


# ---------------------------------------------------------------------------
# Version reporting
# ---------------------------------------------------------------------------


def test_version_reports_the_commit_and_branch(tmp_settings: Any, repo: Path) -> None:
    runner = ScriptedRunner(
        {
            "rev-parse --short HEAD": ok("e46933f"),
            "rev-parse --abbrev-ref": ok("main"),
            "rev-parse HEAD": ok("e46933f0c2a1b8d4"),
            "status --porcelain": ok(""),
        }
    )
    info = build(tmp_settings, repo, runner).version()
    assert info.commit == "e46933f0c2a1b8d4"
    assert info.short_commit == "e46933f"
    assert info.branch == "main"
    assert info.dirty is False


def test_version_flags_a_dirty_checkout(tmp_settings: Any, repo: Path) -> None:
    """A dirty tree is exactly what will make the --ff-only pull fail."""
    runner = ScriptedRunner(
        {
            "rev-parse --short HEAD": ok("e46933f"),
            "rev-parse --abbrev-ref": ok("main"),
            "rev-parse HEAD": ok("e46933f0"),
            "status --porcelain": ok(" M src/lpr/config.py"),
        }
    )
    assert build(tmp_settings, repo, runner).version().dirty is True


def test_version_falls_back_when_git_says_nothing(tmp_settings: Any, repo: Path) -> None:
    """An image built from a tarball must still answer 'what am I running'."""
    runner = ScriptedRunner({"rev-parse": fail(128, "not a git repository")})
    info = build(tmp_settings, repo, runner).version()
    assert info.commit is None
    assert info.version


# ---------------------------------------------------------------------------
# check_for_updates
# ---------------------------------------------------------------------------


def test_the_check_fetches_without_touching_the_working_tree(
    tmp_settings: Any, repo: Path
) -> None:
    """It runs on a schedule against a live site, so it must be read-only."""
    runner = ScriptedRunner({"rev-list": ok("0")})
    build(tmp_settings, repo, runner).check_for_updates()

    assert runner.ran("git fetch origin main")
    for command in runner.commands:
        assert "pull" not in command
        assert "reset" not in command
        assert "checkout" not in command
        assert "merge" not in command


def test_the_check_counts_commits_rather_than_parsing_status(
    tmp_settings: Any, repo: Path
) -> None:
    """Porcelain status text is localised and shifts between git versions."""
    runner = ScriptedRunner({"rev-list": ok("3")})
    state = build(tmp_settings, repo, runner).check_for_updates()

    assert runner.ran("git rev-list --count HEAD..origin/main")
    assert state.behind == 3
    assert state.update_available is True


def test_the_check_reports_a_current_checkout(tmp_settings: Any, repo: Path) -> None:
    state = build(tmp_settings, repo, ScriptedRunner({"rev-list": ok("0")})).check_for_updates()
    assert state.checked is True
    assert state.behind == 0
    assert state.update_available is False


def test_a_failed_fetch_is_distinguishable_from_being_current(
    tmp_settings: Any, repo: Path
) -> None:
    """The scheduler must never read a network failure as 'nothing to do'."""
    runner = ScriptedRunner({"git fetch": fail(128, "could not resolve host")})
    state = build(tmp_settings, repo, runner).check_for_updates()

    assert state.checked is False
    assert state.update_available is False
    assert "ağ" in state.detail.lower()


def test_the_check_uses_the_configured_remote_branch(
    tmp_settings: Any, repo: Path
) -> None:
    runner = ScriptedRunner({"rev-list": ok("1")})
    build(
        tmp_settings, repo, runner, git_remote="upstream", git_branch="stable"
    ).check_for_updates()

    assert runner.ran("git fetch upstream stable")
    assert runner.ran("HEAD..upstream/stable")


def test_the_check_declines_outside_a_checkout(tmp_settings: Any, tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    state = build(tmp_settings, plain, ScriptedRunner()).check_for_updates()
    assert state.checked is False


def test_an_unparseable_count_is_not_treated_as_an_update(
    tmp_settings: Any, repo: Path
) -> None:
    runner = ScriptedRunner({"rev-list": ok("not-a-number")})
    state = build(tmp_settings, repo, runner).check_for_updates()
    assert state.checked is False
    assert state.update_available is False
