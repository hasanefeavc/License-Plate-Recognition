"""Over-the-air self-update: git pull + docker compose rebuild.

This module is the whole of the update mechanism. The HTTP layer in
:mod:`lpr.api.routes` only authenticates the caller and calls :meth:`SystemUpdater.start`;
everything about *how* an update runs lives here, so it can be unit-tested with a
fake runner and without FastAPI, Docker or a git checkout.

Security posture
----------------
This feature is remote code execution by design -- that is what an OTA updater
*is* -- so the safety comes from constraining it, not from hiding it:

* **Disabled by default.** ``system_update.enabled`` must be turned on
  deliberately. A commercial build that ships with a live self-update endpoint
  is one leaked admin password away from arbitrary code on every client site.
* **Nothing from the request reaches a command.** The remote, branch, repo
  directory and compose file all come from configuration. A caller cannot ask
  this endpoint to pull from *their* repository, so a stolen admin token cannot
  be escalated into "run my code" -- only into "run whatever the operator's own
  configured remote already contains". The single flag the HTTP layer does
  forward, ``force``, selects between two fixed code paths and is never
  interpolated into anything; it changes *whether* the configured build runs,
  never *what* it builds.
* **No shell, ever.** Every command is a fixed ``list[str]`` passed to
  :func:`subprocess.run` without ``shell=True``, so there is no string for an
  argument to break out of.
* **``git pull --ff-only``.** A diverged checkout or a local modification makes
  the pull *fail* rather than produce a merge commit or leave conflict markers
  in a file the service then imports.
* **Single-flight.** Two admins pressing the button at once would race a build
  against a checkout; the second call is refused, not queued.
* **Timeouts** on every step, so a hung network fetch cannot pin a thread for
  the life of the process.

The operator still has to accept the two risks this cannot remove: whoever
controls the configured git remote controls these machines, and rebuilding the
stack from inside it requires a Docker socket, which is host-root access. Both
are documented in the README next to the enable flag.

The restart paradox
-------------------
``docker compose up -d --build`` recreates the container this code is running
in. The process is killed partway through its own subprocess call, so the
update *cannot* report its own success over the connection that requested it.
Hence: the endpoint returns as soon as the work is accepted, the work runs on a
detached thread, and the outcome is written to a small JSON file **before** the
compose step starts. The container that comes up afterwards reads that file and
reports what happened, which is also what lets the UI tell "rebuilding" apart
from "crashed on startup".
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lpr.config import Settings

logger = logging.getLogger(__name__)

__all__ = [
    "CommandResult",
    "RemoteState",
    "SystemUpdater",
    "UpdateState",
    "UpdateStatus",
    "VersionInfo",
]

UpdateState = Literal["idle", "running", "restarting", "succeeded", "failed"]
_VALID_STATES = ("idle", "running", "restarting", "succeeded", "failed")

#: Steps are reported to the UI by name so a failure can say which one broke.
STEP_REVISION = "revision"
STEP_PULL = "pull"
STEP_BUILD = "build"


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Outcome of one subprocess invocation."""

    command: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        """Combined output, trimmed -- what a human needs to see on failure."""
        joined = "\n".join(part for part in (self.stdout.strip(), self.stderr.strip()) if part)
        return joined.strip()


@dataclass(frozen=True, slots=True)
class VersionInfo:
    """What is currently deployed."""

    version: str
    commit: str | None = None
    short_commit: str | None = None
    branch: str | None = None
    dirty: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "commit": self.commit,
            "short_commit": self.short_commit,
            "branch": self.branch,
            "dirty": self.dirty,
        }


@dataclass(frozen=True, slots=True)
class RemoteState:
    """How far the local checkout is behind the configured remote branch."""

    behind: int = 0
    local_commit: str | None = None
    remote_commit: str | None = None
    checked: bool = False
    detail: str = ""

    @property
    def update_available(self) -> bool:
        return self.checked and self.behind > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "behind": self.behind,
            "local_commit": self.local_commit,
            "remote_commit": self.remote_commit,
            "checked": self.checked,
            "update_available": self.update_available,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class UpdateStatus:
    """Where the last (or current) update got to."""

    state: UpdateState = "idle"
    step: str | None = None
    detail: str = ""
    started_at: float | None = None
    finished_at: float | None = None
    commit_before: str | None = None
    commit_after: str | None = None
    #: True when this run was a forced rebuild -- one the operator asked for
    #: explicitly, which rebuilds even with nothing new to pull. Reported so
    #: the UI can say "yeniden derlendi" rather than claiming an upgrade that
    #: did not happen, and so the restored post-restart status keeps saying it.
    forced: bool = False
    log: tuple[str, ...] = field(default_factory=tuple)

    @property
    def running(self) -> bool:
        return self.state in ("running", "restarting")

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "step": self.step,
            "detail": self.detail,
            "running": self.running,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "commit_before": self.commit_before,
            "commit_after": self.commit_after,
            "forced": self.forced,
            "log": list(self.log),
        }


def _run_command(
    command: Sequence[str],
    cwd: Path,
    timeout: float,
) -> CommandResult:
    """Run one command with no shell, capturing both streams.

    Never raises: a missing binary, a non-zero exit and a timeout all come back
    as a :class:`CommandResult` with a non-zero ``returncode``, because the
    caller's job is to report *which step failed and why*, not to unwind a
    traceback into an HTTP 500.
    """
    argv = [str(part) for part in command]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, never shell=True
            argv,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            command=tuple(argv),
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            command=tuple(argv),
            returncode=124,
            stderr=f"Komut {timeout:.0f} saniye içinde tamamlanmadı",
        )
    except FileNotFoundError:
        return CommandResult(
            command=tuple(argv),
            returncode=127,
            stderr=f"Komut bulunamadı: {argv[0]}",
        )
    except OSError as exc:  # permission denied on the docker socket lands here
        return CommandResult(command=tuple(argv), returncode=126, stderr=str(exc))


class SystemUpdater:
    """Runs the OTA update, one at a time, off the request thread.

    ``runner`` is injectable purely so the tests can drive every branch --
    conflict, permission denial, timeout -- without a git checkout or a Docker
    daemon anywhere near them.
    """

    def __init__(
        self,
        settings: "Settings | None" = None,
        runner: Callable[[Sequence[str], Path, float], CommandResult] | None = None,
    ) -> None:
        if settings is None:
            from lpr.config import get_settings

            settings = get_settings()
        self._settings = settings
        self._run = runner or _run_command

        cfg = getattr(settings, "system_update", None)
        self.enabled = bool(getattr(cfg, "enabled", False))
        self.remote = str(getattr(cfg, "git_remote", "origin") or "origin")
        self.branch = str(getattr(cfg, "git_branch", "main") or "main")
        self.git_timeout = float(getattr(cfg, "git_timeout_s", 120.0))
        self.build_timeout = float(getattr(cfg, "build_timeout_s", 900.0))
        self._repo_dir = Path(str(getattr(cfg, "repo_dir", "."))).expanduser()
        self._compose_file = str(getattr(cfg, "compose_file", "docker/docker-compose.yml"))
        self._compose_overrides = [
            str(item).strip()
            for item in (getattr(cfg, "compose_overrides", None) or ())
            if str(item).strip()
        ]

        self._lock = threading.Lock()
        self._status = UpdateStatus()
        self._thread: threading.Thread | None = None
        self._state_path = self._resolve_state_path(cfg, settings)
        self._restore_status()

    # -- configuration ---------------------------------------------------

    @property
    def repo_dir(self) -> Path:
        try:
            return self._repo_dir.resolve()
        except OSError:  # pragma: no cover - unresolvable path
            return self._repo_dir

    def _resolve_state_path(self, cfg: Any, settings: "Settings") -> Path | None:
        """Where the outcome is persisted across the restart, or None."""
        configured = str(getattr(cfg, "state_file", "") or "").strip()
        try:
            if configured:
                return Path(configured).expanduser()
            return settings.paths.data_dir / "last_update.json"
        except Exception:  # pragma: no cover - unwritable data dir
            logger.debug("Güncelleme durum dosyası çözümlenemedi", exc_info=True)
            return None

    # -- version ---------------------------------------------------------

    def version(self) -> VersionInfo:
        """What is deployed right now.

        ``version`` is the string a human reads. It comes from
        ``git describe --tags --always``, which returns the most meaningful
        name the repository can offer for this exact commit:

        ==========================  ===========================================
        Repository state            ``version``
        ==========================  ===========================================
        HEAD is tagged              ``v1.0.0``
        two commits past a tag      ``v1.0.0-2-g6845136``
        no tags anywhere            ``6845136``  (``--always``, a bare hash)
        no git / not a checkout     the packaged version, e.g. ``0.1.0``
        ==========================  ===========================================

        A release build therefore shows ``v1.0.0`` instead of a hash, and a
        build between releases still shows *which* release it is ahead of --
        far more use to somebody reading it over the phone than ``6845136``.

        The raw hashes stay available in ``commit`` and ``short_commit``.
        They are facts about identity rather than labels for display, and two
        things depend on that distinction: support wants the exact hash, and
        the dashboard detects that an OTA update actually replaced the process
        by watching ``commit`` change. A describe string is the wrong signal
        for that -- tagging an already-deployed commit changes the describe
        output without deploying anything.

        Every step degrades independently: no tags still yields a hash, no git
        still yields the packaged version. There is no repository state in
        which this raises or returns an empty ``version``.
        """
        base = self._package_version()
        if not self._git_available():
            return VersionInfo(version=base)

        commit = self._git_value(["git", "rev-parse", "HEAD"])
        if commit is None:
            # Not a checkout, or a repository with no commits yet.
            return VersionInfo(version=base)

        short = self._git_value(["git", "rev-parse", "--short", "HEAD"]) or commit[:7]
        branch = self._git_value(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        dirty = self._git_value(["git", "status", "--porcelain"])

        # --tags so lightweight tags count (a release tagged with `git tag
        # v1.0.0` is not annotated, and plain --describe would ignore it);
        # --always so a repository that has never been tagged degrades to a
        # hash instead of failing.
        described = self._git_value(["git", "describe", "--tags", "--always"])

        return VersionInfo(
            version=described or short or base,
            commit=commit,
            short_commit=short,
            branch=branch,
            dirty=bool(dirty),
        )

    @staticmethod
    def _package_version() -> str:
        """Version from the installed package metadata; ``0.1.0`` in a checkout.

        Imported from the API layer lazily and behind a broad except: this
        module is below the API in the dependency order, and a version string
        is never worth an ImportError at startup.
        """
        try:
            from lpr.api.routes import app_version

            return app_version()
        except Exception:  # pragma: no cover - defensive
            logger.debug("Paket sürümü okunamadı", exc_info=True)
            return "0.1.0"

    def _git_available(self) -> bool:
        return shutil.which("git") is not None

    def _git_value(self, command: Sequence[str]) -> str | None:
        """One-line git output, or None when the command fails."""
        result = self._run(command, self.repo_dir, min(30.0, self.git_timeout))
        if not result.ok:
            logger.debug("git komutu başarısız: %s -> %s", command, result.output)
            return None
        return result.stdout.strip() or None

    # -- status ----------------------------------------------------------

    @property
    def status(self) -> UpdateStatus:
        with self._lock:
            return self._status

    def _set(self, **changes: Any) -> UpdateStatus:
        with self._lock:
            self._status = replace(self._status, **changes)
            return self._status

    def _append_log(self, line: str) -> None:
        with self._lock:
            trimmed = (self._status.log + (line,))[-40:]
            self._status = replace(self._status, log=trimmed)

    def _persist(self) -> None:
        """Write the current status so the *next* container can report it."""
        if self._state_path is None:
            return
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = self.status.to_dict()
            payload["persisted_at"] = time.time()
            self._state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            # Losing the breadcrumb must not fail the update itself.
            logger.debug("Güncelleme durumu yazılamadı", exc_info=True)

    def _restore_status(self) -> None:
        """Read the outcome the previous container left behind, if any."""
        if self._state_path is None or not self._state_path.exists():
            return
        try:
            payload = json.loads(self._state_path.read_text(encoding="utf-8"))
            state = str(payload.get("state") or "idle")
            if state not in _VALID_STATES:
                return
            # A "running"/"restarting" record means the previous container was
            # replaced mid-update, which is the *expected* ending -- this
            # process starting at all is the evidence the rebuild worked.
            interrupted = state in ("running", "restarting")
            resolved = cast(UpdateState, "succeeded" if interrupted else state)
            forced = bool(payload.get("forced"))
            self._status = UpdateStatus(
                state=resolved,
                step=payload.get("step"),
                detail=(
                    self._restart_detail(forced)
                    if interrupted
                    else str(payload.get("detail") or "")
                ),
                started_at=payload.get("started_at"),
                finished_at=payload.get("finished_at") or time.time(),
                commit_before=payload.get("commit_before"),
                commit_after=payload.get("commit_after"),
                forced=forced,
                log=tuple(str(line) for line in payload.get("log") or ())[-40:],
            )
        except Exception:
            logger.debug("Önceki güncelleme durumu okunamadı", exc_info=True)

    @staticmethod
    def _restart_detail(forced: bool) -> str:
        """What to say about a run that was cut short by its own rebuild.

        A forced rebuild must not claim an upgrade: the commit is very often
        unchanged, and "Güncelleme tamamlandı" on a machine that pulled nothing
        is the kind of message that ends in a phone call.
        """
        return (
            "Yeniden derleme tamamlandı, servis yeniden başlatıldı."
            if forced
            else "Güncelleme tamamlandı, servis yeniden başlatıldı."
        )

    # -- the update ------------------------------------------------------

    def check_for_updates(self) -> RemoteState:
        """Fetch the remote branch and report how far behind the checkout is.

        Read-only: ``git fetch`` updates the remote-tracking ref, it does not
        touch the working tree, so this is safe to run on a schedule against a
        machine that is mid-shift.

        The comparison is ``git rev-list --count HEAD..<remote>/<branch>``
        rather than parsing ``git status``: porcelain status text is localised
        and reformatted between git versions, whereas rev-list answers the
        actual question ("how many commits am I missing") as a single integer.

        Never raises; a failed fetch comes back as ``checked=False`` with the
        reason in ``detail``, because a scheduler must be able to distinguish
        "no updates" from "could not tell".
        """
        repo = self.repo_dir
        if not (repo / ".git").exists():
            return RemoteState(detail=f"{repo} bir git deposu değil.")

        fetch = self._run(["git", "fetch", self.remote, self.branch], repo, self.git_timeout)
        if not fetch.ok:
            return RemoteState(detail=self._explain_pull_failure(fetch))

        local = self._git_value(["git", "rev-parse", "HEAD"])
        remote_ref = f"{self.remote}/{self.branch}"
        remote = self._git_value(["git", "rev-parse", remote_ref])
        if local is None or remote is None:
            return RemoteState(
                local_commit=local,
                remote_commit=remote,
                detail=f"{remote_ref} çözümlenemedi.",
            )

        counted = self._git_value(["git", "rev-list", "--count", f"HEAD..{remote_ref}"])
        try:
            behind = int((counted or "0").strip())
        except ValueError:
            return RemoteState(
                local_commit=local,
                remote_commit=remote,
                detail="Uzak dal ile karşılaştırma okunamadı.",
            )

        return RemoteState(
            behind=behind,
            local_commit=local,
            remote_commit=remote,
            checked=True,
            detail=(f"{behind} yeni commit mevcut." if behind else "Sistem güncel."),
        )

    def start(self, force: bool = False) -> UpdateStatus:
        """Accept an update and return immediately.

        ``force`` turns this into a *rebuild* rather than an upgrade: the
        checkout is still pulled, but a pull that brings nothing new no longer
        ends the run, and a pull that outright fails no longer aborts it. That
        is deliberately the only knob the HTTP layer exposes -- it selects
        between two fixed behaviours and never reaches a command line, so it
        cannot widen what an authenticated caller is able to execute.

        Operators need it because "restart the stack" and "pick up the newest
        commit" are different requests, and only the second one was reachable
        from the UI: a container wedged on a stale image, a changed .env or a
        half-applied config had no button at all.

        Raises ``RuntimeError`` when the feature is disabled or an update is
        already in flight; the HTTP layer maps those onto 503 and 409.
        """
        if not self.enabled:
            raise RuntimeError(
                "Sistem güncellemesi devre dışı. Etkinleştirmek için "
                "config.yaml içinde system_update.enabled: true yapın."
            )

        forced = bool(force)
        with self._lock:
            if self._status.running:
                raise RuntimeError("Zaten devam eden bir güncelleme var.")
            self._status = UpdateStatus(
                state="running",
                step=STEP_REVISION,
                detail=(
                    "Zorla yeniden derleme başlatıldı."
                    if forced
                    else "Güncelleme başlatıldı."
                ),
                started_at=time.time(),
                forced=forced,
            )
            thread = threading.Thread(
                target=self._run_update,
                name="lpr-system-update",
                kwargs={"force": forced},
                daemon=True,
            )
            self._thread = thread

        thread.start()
        logger.warning(
            "Sistem %s başlatıldı (remote=%s branch=%s repo=%s)",
            "yeniden derlemesi (zorla)" if forced else "güncellemesi",
            self.remote,
            self.branch,
            self.repo_dir,
        )
        return self.status

    def _fail(self, step: str, detail: str) -> None:
        logger.error("Sistem güncellemesi başarısız (%s): %s", step, detail)
        self._set(state="failed", step=step, detail=detail, finished_at=time.time())
        self._persist()

    def _run_update(self, force: bool = False) -> None:
        """The update itself. Runs on its own thread; never raises out of it."""
        try:
            self._update_steps(force=force)
        except Exception as exc:  # pragma: no cover - belt and braces
            logger.exception("Sistem güncellemesi beklenmedik şekilde başarısız oldu")
            self._fail(self._status.step or STEP_PULL, f"Beklenmeyen hata: {exc}")

    def _update_steps(self, force: bool = False) -> None:
        if not self._advance_checkout(force):
            return

        # Persisted *before* the rebuild: compose is about to kill this
        # container, so this is the last chance to leave a breadcrumb.
        self._set(
            step=STEP_BUILD,
            state="restarting",
            detail="Yeniden derleniyor ve başlatılıyor...",
        )
        self._persist()

        build = self._run(self._compose_command(), self.repo_dir, self.build_timeout)
        self._append_log(f"$ {' '.join(build.command)}")
        if build.output:
            self._append_log(build.output)
        if not build.ok:
            self._fail(STEP_BUILD, self._explain_build_failure(build))
            return

        status = self.status
        self._set(
            state="succeeded",
            step=STEP_BUILD,
            detail=("Yeniden derleme tamamlandı." if force else "Güncelleme tamamlandı."),
            finished_at=time.time(),
        )
        self._persist()
        logger.info(
            "Sistem %s tamamlandı: %s -> %s",
            "yeniden derlemesi" if force else "güncellemesi",
            status.commit_before,
            status.commit_after,
        )

    def _advance_checkout(self, force: bool) -> bool:
        """Bring the checkout up to date, and say whether a rebuild follows.

        Returns ``False`` when the run is already over -- it failed, or the
        checkout was current and there was nothing worth an outage for. Either
        way the terminal status has been set and persisted before returning.

        ``force`` reverses the burden of proof at every one of these gates.
        Normally the git half decides whether the rebuild is justified, and
        anything unexpected stops the run; under a forced rebuild the operator
        has already decided, and git only gets to *annotate* the run. That is
        the whole point of the button: a container wedged on a stale image, a
        changed ``.env`` or a checkout that will not fast-forward are exactly
        the states in which somebody needs a rebuild most, and exactly the
        states the normal path refuses.
        """
        repo = self.repo_dir
        if not (repo / ".git").exists():
            if not force:
                self._fail(
                    STEP_REVISION,
                    f"{repo} bir git deposu değil; güncelleme yalnızca git ile kurulmuş "
                    "sistemlerde çalışır.",
                )
                return False
            # Rebuilding needs a compose file, not a checkout.
            self._append_log(f"{repo} bir git deposu değil; yalnızca yeniden derleniyor.")
            return True

        before = self._git_value(["git", "rev-parse", "HEAD"])
        self._set(step=STEP_PULL, commit_before=before, detail="Değişiklikler alınıyor...")

        # --ff-only: a diverged or locally-modified checkout must fail loudly
        # here rather than leave conflict markers in a file the service imports.
        pull = self._run(
            ["git", "pull", "--ff-only", self.remote, self.branch],
            repo,
            self.git_timeout,
        )
        self._append_log(f"$ {' '.join(pull.command)}")
        if pull.output:
            self._append_log(pull.output)
        if not pull.ok:
            reason = self._explain_pull_failure(pull)
            if not force:
                self._fail(STEP_PULL, reason)
                return False
            # Recorded, not fatal: the operator asked for a rebuild of what is
            # on disk, and what is on disk is still perfectly buildable.
            logger.warning("Zorla yeniden derleme: git pull başarısız (%s)", reason)
            self._append_log(f"UYARI: {reason} Mevcut kopya yeniden derleniyor.")

        after = self._git_value(["git", "rev-parse", "HEAD"])
        self._set(commit_after=after)

        if not force and before and after and before == after:
            self._set(
                state="succeeded",
                step=STEP_PULL,
                detail="Sistem zaten güncel; yeniden derleme yapılmadı.",
                finished_at=time.time(),
            )
            self._persist()
            logger.info("Sistem güncellemesi: değişiklik yok (%s)", after)
            return False

        return True

    def _compose_command(self) -> list[str]:
        """``docker compose -f <file> [-f <overlay>...] up -d --build``.

        Every ``system_update.compose_overrides`` entry becomes another ``-f``,
        in order, exactly as an operator would type it. That list is not a
        convenience: this module is what brings the service back up after an
        update, so an overlay the operator normally passes by hand is otherwise
        dropped on every rebuild. On a Podman or CDI host that means the GPU
        stops being passed through -- and the container comes up healthy on
        CPU, which is the failure nobody notices.
        """
        files: list[str] = ["-f", self._compose_file]
        for override in self._compose_overrides:
            files += ["-f", override]
        if shutil.which("docker"):
            return ["docker", "compose", *files, "up", "-d", "--build"]
        # Older hosts only have the standalone binary.
        return ["docker-compose", *files, "up", "-d", "--build"]

    @staticmethod
    def _explain_pull_failure(result: CommandResult) -> str:
        """Turn a git failure into something an operator can act on."""
        text = result.output.lower()
        if result.returncode == 127:
            return "git bulunamadı. Güncelleme için git kurulu olmalı."
        if "not possible to fast-forward" in text or "diverged" in text:
            return (
                "Yerel kopya uzak dalla ayrışmış (fast-forward mümkün değil). "
                "Sunucuda yerel değişiklikler var; elle çözülmeli."
            )
        if "local changes" in text or "would be overwritten" in text:
            return (
                "Yerel değişiklikler güncellemeyi engelliyor. Sunucudaki "
                "değişiklikleri geri alın veya saklayın."
            )
        if "could not resolve host" in text or "network" in text or "timed out" in text:
            return "Uzak depoya ulaşılamadı. Ağ bağlantısını kontrol edin."
        if "permission denied" in text or "authentication failed" in text:
            return "Uzak depoya erişim reddedildi. Dağıtım anahtarını kontrol edin."
        return f"git pull başarısız (kod {result.returncode}): {result.output[:400]}"

    @staticmethod
    def _explain_build_failure(result: CommandResult) -> str:
        text = result.output.lower()
        if result.returncode == 127:
            return "docker bulunamadı. Güncelleme için Docker kurulu olmalı."
        if "permission denied" in text and "docker.sock" in text:
            return (
                "Docker soketine erişim reddedildi. Güncellemeyi çalıştıran "
                "sürecin docker grubunda olması veya /var/run/docker.sock "
                "bağlanmış olması gerekir."
            )
        if "cannot connect to the docker daemon" in text:
            return "Docker arka plan servisine bağlanılamadı. Docker çalışıyor mu?"
        if result.returncode == 124:
            return "Yeniden derleme zaman aşımına uğradı."
        return f"docker compose başarısız (kod {result.returncode}): {result.output[:400]}"
