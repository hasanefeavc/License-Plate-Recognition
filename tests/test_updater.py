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
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from lpr.updater import CommandResult, SystemUpdater


class ScriptedRunner:
    """Answers each command from a table, recording everything it was asked."""

    def __init__(self, responses: dict[str, CommandResult] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[tuple[str, ...], Path, float]] = []
        #: The environment each command was given, by command string. Only the
        #: compose step gets one; the git steps inherit the process's own.
        self.envs: dict[str, Mapping[str, str] | None] = {}

    def __call__(
        self,
        command: Sequence[str],
        cwd: Path,
        timeout: float,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        argv = tuple(str(part) for part in command)
        self.calls.append((argv, cwd, timeout))
        self.envs[" ".join(argv)] = env
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

    def __call__(
        self,
        command: Sequence[str],
        cwd: Path,
        timeout: float,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        argv = tuple(str(part) for part in command)
        if " ".join(argv) == "git rev-parse HEAD":
            self.calls.append((argv, cwd, timeout))
            value = self._revisions[min(self._index, len(self._revisions) - 1)]
            self._index += 1
            return ok(value)
        return super().__call__(command, cwd, timeout, env)


def run_to_completion(updater: SystemUpdater, force: bool = False) -> Any:
    """Start an update and wait for its thread, so assertions are deterministic."""
    updater.start(force=force)
    thread = updater._thread
    assert thread is not None
    thread.join(timeout=10)
    assert not thread.is_alive(), "update thread did not finish"
    return updater.status


# ---------------------------------------------------------------------------
# Gating
# ---------------------------------------------------------------------------


def test_the_updater_is_disabled_by_default() -> None:
    """Shipping a live self-update endpoint by default would be indefensible.

    Asserted against the config *model*, not against a ``Settings`` built by
    the fixture. ``Settings`` reads the developer's ``config.yaml`` through its
    YAML source, so going via the fixture would make this test pass or fail
    depending on whether whoever ran it happens to have OTA switched on -- and
    a deployment that legitimately enables the feature would fail its own test
    suite. The claim here is about the shipped default, so it is the default
    that gets asserted.
    """
    from lpr.config import SystemUpdateConfig

    assert SystemUpdateConfig().enabled is False
    assert SystemUpdateConfig().auto_update is False


def test_the_updater_honours_the_configured_flag(tmp_settings: Any, repo: Path) -> None:
    """And the flag on Settings is what the updater actually reads."""
    tmp_settings.system_update.enabled = True
    assert SystemUpdater(tmp_settings, runner=ScriptedRunner()).enabled is True
    tmp_settings.system_update.enabled = False
    assert SystemUpdater(tmp_settings, runner=ScriptedRunner()).enabled is False


def test_a_disabled_updater_refuses_to_start(tmp_settings: Any, repo: Path) -> None:
    updater = build(tmp_settings, repo, ScriptedRunner(), enabled=False)
    with pytest.raises(RuntimeError, match="devre dışı"):
        updater.start()


def test_a_second_concurrent_update_is_refused(tmp_settings: Any, repo: Path) -> None:
    """Two admins pressing the button must not race a build against a checkout."""
    import threading

    release = threading.Event()

    class BlockingRunner(ScriptedRunner):
        def __call__(self, command, cwd, timeout, env=None):  # type: ignore[no-untyped-def]
            if "pull" in " ".join(str(p) for p in command):
                release.wait(timeout=5)
            return super().__call__(command, cwd, timeout, env)

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
# Forced rebuilds
#
# The ordinary path treats "nothing new to pull" as a reason not to rebuild,
# because a rebuild is a few minutes of outage at the barrier. `force` says the
# operator wants that outage anyway -- for a container stuck on a stale image,
# an edited .env, or a checkout that cannot fast-forward. These tests pin the
# inversion: every gate that normally *stops* the run must, under force, let it
# reach the build instead.
# ---------------------------------------------------------------------------


def test_a_forced_run_rebuilds_even_with_nothing_new_to_pull(tmp_settings: Any, repo: Path) -> None:
    """The whole point of the flag: the same commit must still reach compose."""
    runner = ScriptedRunner({"rev-parse HEAD": ok("samecommit")})
    status = run_to_completion(build(tmp_settings, repo, runner), force=True)

    assert status.state == "succeeded"
    assert runner.ran("up -d --build"), "force must bypass the already-current exit"
    assert "zaten güncel" not in status.detail.lower()


def test_the_same_run_without_force_stops_before_the_build(tmp_settings: Any, repo: Path) -> None:
    """The control for the test above -- only the flag differs."""
    runner = ScriptedRunner({"rev-parse HEAD": ok("samecommit")})
    status = run_to_completion(build(tmp_settings, repo, runner), force=False)

    assert status.state == "succeeded"
    assert not runner.ran("up -d --build")
    assert "zaten güncel" in status.detail.lower()


def test_a_forced_run_says_it_rebuilt_rather_than_updated(tmp_settings: Any, repo: Path) -> None:
    """Reporting an upgrade that did not happen is how support calls start."""
    runner = ScriptedRunner({"rev-parse HEAD": ok("samecommit")})
    status = run_to_completion(build(tmp_settings, repo, runner), force=True)

    assert status.forced is True
    assert "yeniden derleme" in status.detail.lower()
    assert "güncelleme tamamlandı" not in status.detail.lower()


def test_a_forced_run_is_flagged_from_the_moment_it_is_accepted(
    tmp_settings: Any, repo: Path
) -> None:
    """The UI reads `forced` off the POST reply, before any polling begins."""
    updater = build(tmp_settings, repo, ScriptedRunner({"rev-parse HEAD": ok("same")}))
    accepted = updater.start(force=True)
    assert accepted.forced is True
    assert accepted.to_dict()["forced"] is True

    thread = updater._thread
    assert thread is not None
    thread.join(timeout=10)


def test_an_ordinary_run_is_not_flagged_as_forced(tmp_settings: Any, repo: Path) -> None:
    status = run_to_completion(build(tmp_settings, repo, AdvancingRunner()))
    assert status.forced is False


def test_a_forced_run_rebuilds_a_checkout_that_cannot_fast_forward(
    tmp_settings: Any, repo: Path
) -> None:
    """A diverged checkout is a reason somebody needs a rebuild, not a refusal.

    The pull still runs and still fails -- nothing is merged or discarded --
    but the working tree that is already on disk is perfectly buildable, and
    that is what the operator asked to rebuild.
    """
    runner = ScriptedRunner(
        {
            "rev-parse HEAD": ok("aaa"),
            "git pull": fail(128, "fatal: Not possible to fast-forward, aborting."),
        }
    )
    status = run_to_completion(build(tmp_settings, repo, runner), force=True)

    assert status.state == "succeeded"
    assert runner.ran("up -d --build")
    assert any("ayrışmış" in line for line in status.log), "the failure must still be visible"


def test_a_failed_pull_still_aborts_an_unforced_run(tmp_settings: Any, repo: Path) -> None:
    """Force is what relaxes this; the default must not have moved."""
    runner = ScriptedRunner(
        {
            "rev-parse HEAD": ok("aaa"),
            "git pull": fail(128, "fatal: Not possible to fast-forward, aborting."),
        }
    )
    status = run_to_completion(build(tmp_settings, repo, runner), force=False)
    assert status.state == "failed"
    assert not runner.ran("up -d --build")


def test_a_forced_run_rebuilds_outside_a_git_checkout(tmp_settings: Any, tmp_path: Path) -> None:
    """Rebuilding needs a compose file, not a repository."""
    plain = tmp_path / "plain"
    plain.mkdir()
    runner = ScriptedRunner()
    status = run_to_completion(build(tmp_settings, plain, runner), force=True)

    assert status.state == "succeeded"
    assert runner.ran("up -d --build")
    assert not runner.ran("git pull"), "there is no remote to pull from here"


def test_a_forced_build_failure_is_still_a_failure(tmp_settings: Any, repo: Path) -> None:
    """Force skips the reasons not to build -- never the result of building."""
    runner = ScriptedRunner(
        {
            "rev-parse HEAD": ok("samecommit"),
            "up -d --build": fail(1, "cannot connect to the Docker daemon"),
        }
    )
    status = run_to_completion(build(tmp_settings, repo, runner), force=True)
    assert status.state == "failed"
    assert status.step == "build"


def test_a_forced_run_cannot_bypass_the_disabled_switch(tmp_settings: Any, repo: Path) -> None:
    """`force` reorders the update's own gates, not the deployment's consent."""
    updater = build(tmp_settings, repo, ScriptedRunner(), enabled=False)
    with pytest.raises(RuntimeError, match="devre dışı"):
        updater.start(force=True)


def test_a_forced_run_cannot_bypass_the_single_flight_guard(tmp_settings: Any, repo: Path) -> None:
    """Two rebuilds at once would race a compose against a compose."""
    gate = threading.Event()

    class BlockingRunner(ScriptedRunner):
        def __call__(self, command, cwd, timeout, env=None):  # type: ignore[no-untyped-def]
            if "up -d --build" in " ".join(str(p) for p in command):
                gate.wait(timeout=10)
            return super().__call__(command, cwd, timeout, env)

    updater = build(tmp_settings, repo, BlockingRunner({"rev-parse HEAD": ok("same")}))
    updater.start(force=True)
    try:
        with pytest.raises(RuntimeError, match="devam eden"):
            updater.start(force=True)
    finally:
        gate.set()
        thread = updater._thread
        assert thread is not None
        thread.join(timeout=10)


def test_a_forced_run_never_reaches_a_command_line(tmp_settings: Any, repo: Path) -> None:
    """The flag selects a code path; it must not appear as an argument.

    This is the security-relevant half of the feature: `force` is the first
    value the HTTP layer forwards to the updater at all, so it is worth
    pinning that it stays a branch rather than becoming a word in an argv.
    """
    runner = ScriptedRunner({"rev-parse HEAD": ok("samecommit")})
    run_to_completion(build(tmp_settings, repo, runner), force=True)

    for argv, _, _ in runner.calls:
        assert not any("force" in part.lower() for part in argv), argv
    assert runner.ran("git pull --ff-only origin main"), "the pull is unchanged by force"


def test_a_forced_rebuild_survives_the_restart_as_a_rebuild(tmp_settings: Any, repo: Path) -> None:
    """The container that comes back must not claim it upgraded anything."""
    state_file = repo / "last_update.json"
    state_file.write_text(
        json.dumps(
            {
                "state": "restarting",
                "step": "build",
                "started_at": 1.0,
                "commit_before": "aaa",
                "commit_after": "aaa",
                "forced": True,
                "log": ["$ git pull"],
            }
        )
    )
    updater = build(tmp_settings, repo, ScriptedRunner())

    assert updater.status.state == "succeeded"
    assert updater.status.forced is True
    assert "yeniden derleme" in updater.status.detail.lower()


def test_an_interrupted_ordinary_update_still_reports_an_update(
    tmp_settings: Any, repo: Path
) -> None:
    """The control for the test above: no `forced` key, no change in wording."""
    (repo / "last_update.json").write_text(
        json.dumps({"state": "restarting", "step": "build", "commit_after": "bbb"})
    )
    updater = build(tmp_settings, repo, ScriptedRunner())

    assert updater.status.forced is False
    assert "güncelleme tamamlandı" in updater.status.detail.lower()


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
    # Actionable, not just accurate: the fix is a different socket, and the
    # message has to say which one and where to set it.
    assert "LPR_DOCKER_SOCK" in status.detail
    assert "podman" in status.detail.lower()


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
        def __call__(self, command, cwd, timeout, env=None):  # type: ignore[no-untyped-def]
            if "up -d --build" in " ".join(str(p) for p in command):
                # Snapshot what a container killed mid-rebuild would leave behind.
                seen["state"] = json.loads(state_file.read_text())["state"]
            return super().__call__(command, cwd, timeout, env)

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


def version_runner(describe: CommandResult | None = None, **extra: CommandResult) -> ScriptedRunner:
    """A runner answering the four git calls ``version()`` makes."""
    responses = {
        "rev-parse --short HEAD": ok("6845136"),
        "rev-parse --abbrev-ref": ok("main"),
        "rev-parse HEAD": ok("6845136fc5071a3e0bdd11d1"),
        "status --porcelain": ok(""),
        "describe": describe if describe is not None else ok("v1.0.0-2-g6845136"),
    }
    responses.update(extra)
    return ScriptedRunner(responses)


def test_version_reports_the_commit_and_branch(tmp_settings: Any, repo: Path) -> None:
    info = build(tmp_settings, repo, version_runner()).version()
    assert info.commit == "6845136fc5071a3e0bdd11d1"
    assert info.short_commit == "6845136"
    assert info.branch == "main"
    assert info.dirty is False


def test_version_prefers_a_readable_tag_over_a_raw_hash(tmp_settings: Any, repo: Path) -> None:
    """The point of the whole exercise: `v1.0.0` reads, `6845136` does not."""
    info = build(tmp_settings, repo, version_runner(describe=ok("v1.0.0"))).version()
    assert info.version == "v1.0.0"


def test_version_describes_a_build_between_releases(tmp_settings: Any, repo: Path) -> None:
    """Still says *which* release it is ahead of, and by how much."""
    info = build(tmp_settings, repo, version_runner()).version()
    assert info.version == "v1.0.0-2-g6845136"


def test_version_asks_git_to_include_lightweight_tags(tmp_settings: Any, repo: Path) -> None:
    """A release cut with plain `git tag v1.0.0` is not annotated.

    Without --tags, `git describe` ignores it and the UI silently goes back to
    showing a hash on exactly the builds that were supposed to be readable.
    """
    runner = version_runner()
    build(tmp_settings, repo, runner).version()
    assert runner.ran("git describe --tags --always")


def test_version_falls_back_to_the_hash_when_nothing_is_tagged(
    tmp_settings: Any, repo: Path
) -> None:
    """`--always` yields a bare hash, which is honest rather than empty."""
    info = build(tmp_settings, repo, version_runner(describe=ok("6845136"))).version()
    assert info.version == "6845136"


def test_version_falls_back_to_the_short_commit_when_describe_fails(
    tmp_settings: Any, repo: Path
) -> None:
    """An empty repository, or a git too old for the flags, must not blank out."""
    runner = version_runner(describe=fail(128, "fatal: bad revision"))
    info = build(tmp_settings, repo, runner).version()
    assert info.version == "6845136"
    assert info.commit == "6845136fc5071a3e0bdd11d1"


def test_version_is_never_empty(tmp_settings: Any, repo: Path) -> None:
    """Whatever git does, the UI always has something to print."""
    runner = ScriptedRunner({"git": fail(1, "everything is broken")})
    assert build(tmp_settings, repo, runner).version().version


def test_version_flags_a_dirty_checkout(tmp_settings: Any, repo: Path) -> None:
    """A dirty tree is exactly what will make the --ff-only pull fail."""
    runner = version_runner(**{"status --porcelain": ok(" M src/lpr/config.py")})
    assert build(tmp_settings, repo, runner).version().dirty is True


def test_the_version_label_is_not_the_build_identity(tmp_settings: Any, repo: Path) -> None:
    """Tagging an already-deployed commit changes the label, not the build.

    The dashboard detects a completed OTA update by watching ``commit``. If it
    watched ``version`` instead, adding a tag to a running deployment would
    look like a successful update that never happened.
    """
    before = build(tmp_settings, repo, version_runner(describe=ok("v1.0.0-2-g6845136")))
    after = build(tmp_settings, repo, version_runner(describe=ok("v2.0.0")))

    assert before.version().version != after.version().version
    assert before.version().commit == after.version().commit


def test_version_falls_back_when_git_says_nothing(tmp_settings: Any, repo: Path) -> None:
    """An image built from a tarball must still answer 'what am I running'."""
    runner = ScriptedRunner({"rev-parse": fail(128, "not a git repository")})
    info = build(tmp_settings, repo, runner).version()
    assert info.commit is None
    assert info.version


# ---------------------------------------------------------------------------
# check_for_updates
# ---------------------------------------------------------------------------


def test_the_check_fetches_without_touching_the_working_tree(tmp_settings: Any, repo: Path) -> None:
    """It runs on a schedule against a live site, so it must be read-only."""
    runner = ScriptedRunner({"rev-list": ok("0")})
    build(tmp_settings, repo, runner).check_for_updates()

    assert runner.ran("git fetch origin main")
    for command in runner.commands:
        assert "pull" not in command
        assert "reset" not in command
        assert "checkout" not in command
        assert "merge" not in command


def test_the_check_counts_commits_rather_than_parsing_status(tmp_settings: Any, repo: Path) -> None:
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


def test_the_check_uses_the_configured_remote_branch(tmp_settings: Any, repo: Path) -> None:
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


def test_an_unparseable_count_is_not_treated_as_an_update(tmp_settings: Any, repo: Path) -> None:
    runner = ScriptedRunner({"rev-list": ok("not-a-number")})
    state = build(tmp_settings, repo, runner).check_for_updates()
    assert state.checked is False
    assert state.update_available is False


def test_compose_overrides_become_extra_dash_f_flags(tmp_settings) -> None:
    """The overlay an operator passes by hand has to survive an OTA rebuild.

    This module is what brings the service back up, so an overlay named only
    on the operator's command line is dropped on every update. On a CDI host
    that is the GPU passthrough, and the container comes back healthy on CPU --
    the failure that looks like nothing happened.
    """
    from lpr.updater import SystemUpdater

    tmp_settings.system_update.compose_file = "docker/docker-compose.yml"
    tmp_settings.system_update.compose_overrides = ["docker/docker-compose.cdi.yml"]
    command = SystemUpdater(tmp_settings)._compose_command()

    assert command[-3:] == ["up", "-d", "--build"]
    assert command.count("-f") == 2
    base = command.index("docker/docker-compose.yml")
    overlay = command.index("docker/docker-compose.cdi.yml")
    assert base < overlay, "compose merges in order; the overlay must come second"


def test_no_overrides_leaves_the_command_exactly_as_it_was(tmp_settings) -> None:
    """The default path is untouched: one file, one -f."""
    from lpr.updater import SystemUpdater

    command = SystemUpdater(tmp_settings)._compose_command()
    assert command.count("-f") == 1


# ---------------------------------------------------------------------------
# The image has to carry the client the rebuild step calls
# ---------------------------------------------------------------------------


def test_the_runtime_image_ships_the_client_the_rebuild_needs() -> None:
    """`_compose_command` runs *inside* the container, against the host engine.

    Without a docker CLI in the image the updater falls back to the v1
    `docker-compose` binary, does not find that either, and fails at the build
    step having already advanced the checkout -- new code on disk, stale image
    running. That is a worse state than not updating at all, and it is silent
    apart from one line in the update log, so it is worth a test that fails at
    build time instead of at 03:00 on the gate box.
    """
    dockerfile = (Path(__file__).resolve().parents[1] / "docker" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    assert "docker-ce-cli" in dockerfile
    assert "docker-compose-plugin" in dockerfile, "`docker compose` is a plugin, not a binary"


def test_the_engine_socket_is_parameterised() -> None:
    """Rootless Podman does not listen on /var/run/docker.sock.

    Hard-coding it hands the container a different engine from the one running
    the service, so the rebuild would replace an image nothing is using.
    """
    compose = (Path(__file__).resolve().parents[1] / "docker" / "docker-compose.ota.yml").read_text(
        encoding="utf-8"
    )
    assert (
        "${LPR_DOCKER_SOCK:-/run/user/1000/podman/podman.sock}:/var/run/docker.sock:rw" in compose
    )
    # The CLI's end of the same bind. It is the container-side path, so it does
    # not vary with the host socket -- and saying so in the environment is what
    # keeps `docker inspect` honest when an update fails.
    assert "DOCKER_HOST: unix:///var/run/docker.sock" in compose


# ---------------------------------------------------------------------------
# The engine socket: which one, and what to say when it cannot be opened
# ---------------------------------------------------------------------------


def test_the_rebuild_runs_with_docker_host_pointed_at_the_mounted_socket(
    tmp_settings: Any, repo: Path, monkeypatch: Any
) -> None:
    """An update that inherits no DOCKER_HOST reaches the CLI's own default,
    which on this deployment is a different engine rather than none."""
    from lpr.updater import CONTAINER_DOCKER_HOST

    # The developer's own shell exports DOCKER_HOST on a Podman box, and this
    # test is about what happens when nothing has.
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    runner = AdvancingRunner()
    run_to_completion(build(tmp_settings, repo, runner))

    compose_call = next(cmd for cmd in runner.envs if "up -d --build" in cmd)
    env = runner.envs[compose_call]
    assert env is not None, "the compose step must be given an environment"
    assert env["DOCKER_HOST"] == CONTAINER_DOCKER_HOST
    # A complete environment, not just the one variable: `env=` replaces the
    # child's whole environment, so PATH has to survive or nothing runs.
    assert "PATH" in env


def test_the_git_steps_are_left_on_the_inherited_environment(tmp_settings: Any, repo: Path) -> None:
    """Only the step that talks to the engine needs the override."""
    runner = AdvancingRunner()
    run_to_completion(build(tmp_settings, repo, runner))

    for command, env in runner.envs.items():
        if command.startswith("git "):
            assert env is None, f"{command} should inherit this process's environment"


def test_an_operators_own_docker_host_is_not_overridden(monkeypatch: Any) -> None:
    """A default, not an override.

    A site pointing at a remote engine or a differently-mounted socket has
    already solved this problem; forcing our value would break exactly the
    deployment that configured it properly.
    """
    from lpr.updater import _compose_env

    monkeypatch.setenv("DOCKER_HOST", "tcp://build-host:2375")
    assert _compose_env()["DOCKER_HOST"] == "tcp://build-host:2375"


def test_a_missing_socket_is_not_reported_as_a_permission_problem(
    tmp_settings: Any, repo: Path
) -> None:
    """The two failures need opposite fixes, so one message cannot serve both.

    "Permission denied" sends an operator looking at groups and ownership; the
    socket not being mounted at all is a compose problem, and being told to
    check permissions on a path that does not exist wastes the call-out.
    """
    runner = AdvancingRunner(
        responses={
            "up -d --build": fail(
                1,
                "Cannot connect to the Docker daemon at "
                "unix:///var/run/docker.sock. Is the docker daemon running?",
            )
        }
    )
    status = run_to_completion(build(tmp_settings, repo, runner))

    assert status.state == "failed" and status.step == "build"
    assert "bulunamadı" in status.detail
    assert "erişim reddedildi" not in status.detail.lower()


def test_the_permission_message_names_the_socket_the_cli_actually_uses(
    tmp_settings: Any, repo: Path
) -> None:
    """The real error text from a rootless Podman host, verbatim."""
    runner = AdvancingRunner(
        responses={
            "up -d --build": fail(
                1,
                "permission denied while trying to connect to the Docker API "
                "at unix:///var/run/docker.sock",
            )
        }
    )
    status = run_to_completion(build(tmp_settings, repo, runner))

    assert "erişim reddedildi" in status.detail.lower()
    assert "/var/run/docker.sock" in status.detail


def test_an_ordinary_build_failure_is_still_an_ordinary_build_failure(
    tmp_settings: Any, repo: Path
) -> None:
    """The socket wording must not swallow a compile error that mentions docker."""
    runner = AdvancingRunner(
        responses={"up -d --build": fail(1, "failed to solve: process did not complete")}
    )
    status = run_to_completion(build(tmp_settings, repo, runner))

    assert "docker compose başarısız" in status.detail


# ---------------------------------------------------------------------------
# Rollback and the health gate
# ---------------------------------------------------------------------------


def test_a_failed_build_rolls_the_checkout_back(tmp_settings: Any, repo: Path) -> None:
    """The one failure that can be handled synchronously.

    The build broke, so compose never replaced this container and this thread
    is still alive to undo the checkout. Leaving the repo on the new commit
    would mean the next restart -- or the next forced rebuild -- retried the
    same broken code.
    """
    runner = AdvancingRunner(responses={"up -d --build": fail(1, "no space left on device")})
    updater = build(tmp_settings, repo, runner)

    updater.start()
    _wait_for_idle(updater)

    assert runner.ran("git reset --hard aaaaaaa"), "the checkout was not restored"
    assert updater.status.state == "failed"
    assert "geri alındı" in updater.status.detail
    assert updater.status.rollback_commit is None, "the rollback was consumed"


def test_a_rollback_that_itself_fails_is_reported(tmp_settings: Any, repo: Path) -> None:
    runner = AdvancingRunner(
        responses={
            "up -d --build": fail(1, "build error"),
            "reset --hard": fail(1, "index.lock exists"),
        }
    )
    updater = build(tmp_settings, repo, runner)

    updater.start()
    _wait_for_idle(updater)

    assert updater.status.state == "failed"
    assert "geri alındı" not in updater.status.detail, "it must not claim a rollback"


def test_the_rebuild_arms_a_rollback_before_it_starts(tmp_settings: Any, repo: Path) -> None:
    """Arming after the build would be too late -- compose destroys the
    container that would do the arming."""
    state_file = repo / "last_update.json"
    seen: dict[str, Any] = {}

    class Watcher(AdvancingRunner):
        def __call__(self, command, cwd, timeout, env=None):  # type: ignore[no-untyped-def]
            if "up -d --build" in " ".join(command):
                seen.update(json.loads(state_file.read_text()))
            return super().__call__(command, cwd, timeout, env)

    updater = build(tmp_settings, repo, Watcher())
    updater.start()
    _wait_for_idle(updater)

    assert seen.get("rollback_commit") == "aaaaaaa"
    assert seen.get("state") == "restarting"


def test_a_clean_start_has_nothing_to_verify(tmp_settings: Any, repo: Path) -> None:
    updater = build(tmp_settings, repo, ScriptedRunner())
    assert updater.verify_after_restart() == "clean"


def test_the_first_boot_after_an_update_is_on_trial(tmp_settings: Any, repo: Path) -> None:
    """Reaching the gate proves the interpreter and the config are sound.

    It does not prove the API serves, so the rollback stays armed until
    `confirm_healthy` says otherwise.
    """
    (repo / "last_update.json").write_text(
        json.dumps({"state": "restarting", "rollback_commit": "aaaaaaa", "boot_attempts": 0}),
        encoding="utf-8",
    )
    updater = build(tmp_settings, repo, ScriptedRunner())

    assert updater.verify_after_restart() == "pending"
    assert updater.status.boot_attempts == 1
    assert updater.status.rollback_commit == "aaaaaaa", "still armed"


def test_confirming_health_disarms_the_rollback(tmp_settings: Any, repo: Path) -> None:
    (repo / "last_update.json").write_text(
        json.dumps({"state": "restarting", "rollback_commit": "aaaaaaa", "boot_attempts": 0}),
        encoding="utf-8",
    )
    updater = build(tmp_settings, repo, ScriptedRunner())
    updater.verify_after_restart()

    assert updater.confirm_healthy() is True
    assert updater.status.rollback_commit is None
    assert updater.status.boot_attempts == 0

    stored = json.loads((repo / "last_update.json").read_text())
    assert stored["rollback_commit"] is None, "the disarm was persisted"


def test_a_second_boot_with_the_rollback_still_armed_reverts(tmp_settings: Any, repo: Path) -> None:
    """The core of the health gate.

    A first boot got far enough to run the gate and then never reached
    `confirm_healthy` -- it crashed afterwards, or wedged before serving.
    Retrying the identical image would only keep the gate down longer.
    """
    (repo / "last_update.json").write_text(
        json.dumps({"state": "restarting", "rollback_commit": "aaaaaaa", "boot_attempts": 1}),
        encoding="utf-8",
    )
    runner = ScriptedRunner()
    updater = build(tmp_settings, repo, runner)

    assert updater.verify_after_restart() == "rolled-back"
    assert runner.ran("git reset --hard aaaaaaa")
    assert updater.status.state == "failed"
    assert updater.status.rolled_back is True
    assert updater.status.rollback_commit is None


def test_a_failed_automatic_rollback_says_what_to_do_by_hand(tmp_settings: Any, repo: Path) -> None:
    (repo / "last_update.json").write_text(
        json.dumps({"state": "restarting", "rollback_commit": "aaaaaaa", "boot_attempts": 1}),
        encoding="utf-8",
    )
    updater = build(
        tmp_settings, repo, ScriptedRunner({"reset --hard": fail(1, "permission denied")})
    )

    assert updater.verify_after_restart() == "rollback-failed"
    assert "git reset --hard aaaaaaa" in updater.status.detail


def test_confirm_healthy_is_a_no_op_when_nothing_is_armed(tmp_settings: Any, repo: Path) -> None:
    updater = build(tmp_settings, repo, ScriptedRunner())
    assert updater.confirm_healthy() is False


def test_rollback_is_refused_outside_a_git_checkout(tmp_settings: Any, tmp_path: Path) -> None:
    """A rebuild-only deployment has no checkout to reset."""
    updater = build(tmp_settings, tmp_path, ScriptedRunner())
    assert updater._rollback_checkout("aaaaaaa", "test") is False


def _wait_for_idle(updater: SystemUpdater, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while updater.status.running and time.monotonic() < deadline:
        time.sleep(0.02)
