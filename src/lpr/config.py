"""Typed, layered configuration for the LPR service.

Precedence, lowest to highest:

    config.yaml  <  environment variables (LPR_ prefix, "__" nesting)  <  explicit constructor args

i.e. an explicit ``Settings(api=ApiConfig(port=9000))`` always wins, an
environment variable like ``LPR_API__PORT=9000`` beats whatever is in
``config.yaml``, and ``config.yaml`` fills in anything neither of those
touched. Field defaults (below) are the last resort if a key is missing
everywhere.

Usage:

    from lpr.config import get_settings

    settings = get_settings()
    settings.detection.confidence
    settings.paths.data_dir  # absolute Path, created on first access
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from lpr.platform_compat import default_serial_port

# ---------------------------------------------------------------------------
# Section models
# ---------------------------------------------------------------------------


class AppConfig(BaseModel):
    name: str = "lpr"
    headless: bool = True
    log_level: str = "INFO"
    data_dir: str = "data"
    models_dir: str = "models"
    #: Browser dashboard served at ``/web``. Unlike the other two this is
    #: read-only content that ships with the source, so it is never created
    #: -- a missing directory just means the web UI is not served.
    web_dir: str = "web"


class CameraConfig(BaseModel):
    """One camera feed. ``source`` is kept as a string so it can hold either
    a numeric device index ("0") or an RTSP/HTTP URL.
    """

    source: str = "0"
    width: int = 1280
    height: int = 720
    fps_limit: int = 15
    reconnect_delay_s: float = 5.0
    queue_size: int = 2

    @property
    def resolved_source(self) -> int | str:
        """``source`` as an int device index when it is all-digits, else the
        raw string (URL or device path) unchanged.
        """
        if self.source.isdigit():
            return int(self.source)
        return self.source


class MotionConfig(BaseModel):
    """Motion gating: skip ML inference on a scene where nothing is happening.

    A gate camera is idle almost all day. Running YOLO on an empty driveway
    costs the same as running it on a car, so a ~0.1 ms frame-difference check
    in the capture thread removes the overwhelming majority of that work.
    """

    enabled: bool = True
    #: Minimum area of the largest moving contour, in **full-frame pixels**,
    #: for a frame to be worth an inference pass. Measured on a downscaled
    #: image and scaled back up, so this number stays meaningful no matter
    #: what internal resolution the check runs at. 5000 ~= a 70x70 blob.
    threshold: int = 5000
    #: Pass a frame through at least this often even when the scene is still.
    #: Keeps the tracker's frame counter advancing so stale ByteTrack ids age
    #: out, and keeps a wholly-static failure mode (frozen feed, wrong
    #: background) from silently blinding the pipeline forever. 0 disables the
    #: heartbeat, leaving motion as the only way a frame reaches inference.
    heartbeat_s: float = 3.0


class CamerasConfig(BaseModel):
    entry: CameraConfig = Field(default_factory=CameraConfig)
    exit: CameraConfig = Field(default_factory=CameraConfig)
    motion: MotionConfig = Field(default_factory=MotionConfig)


class DetectionConfig(BaseModel):
    model_path: str = "models/plate_yolov8n.pt"
    confidence: float = 0.35
    iou: float = 0.5
    device: str = "auto"
    imgsz: int = 640
    frame_stride: int = 3
    #: Run the detector through a multi-object tracker so each plate keeps a
    #: stable id across frames. Off = one independent detection per frame, and
    #: the pipeline falls back to text-only voting.
    track: bool = True
    #: Tracker config passed to ultralytics. "bytetrack.yaml" and
    #: "botsort.yaml" ship inside the ultralytics wheel; an absolute path to
    #: your own YAML also works.
    tracker: str = "bytetrack.yaml"
    #: Prefer an ``.onnx`` sitting next to ``model_path`` over the ``.pt``.
    #: Only takes effect once an export exists, so it costs nothing by
    #: default, and the export is verified at startup before it is adopted.
    #: Note that ONNX Runtime is *not* automatically faster than PyTorch on
    #: CPU -- benchmark your own hardware with ``scripts/export_onnx.py``,
    #: which reports both, and set this to false if the .pt wins.
    prefer_onnx: bool = True


class PreprocessConfig(BaseModel):
    """Software-level image enhancement, applied before detection and OCR.

    The crop-level settings (``crop_*``, ``rectify_perspective``) are on by
    default: they only ever affect what the *recogniser* sees, and the
    recogniser keeps the best read across several variants, so a variant that
    an enhancement made worse simply loses.

    ``frame_enhance`` is different and therefore defaults to off. It changes
    what the *detector* sees, and the detector is a trained CNN with no
    corresponding voting fallback -- a frame it fails to fire on is a plate
    that never reaches OCR at all. Mild CLAHE usually helps in low light and
    can cost recall in good light, so turn it on only after checking detection
    counts against your own footage.
    """

    #: Run CLAHE + unsharp over the whole frame before the detector sees it.
    frame_enhance: bool = False
    #: CLAHE clip limit for the whole-frame pass. Higher lifts shadows harder
    #: and amplifies sensor noise with them.
    frame_clahe_clip: float = Field(default=2.0, ge=0.1, le=10.0)
    #: Unsharp strength for the whole-frame pass. Kept below the crop-level
    #: amount: the detector wants a natural-looking frame, not a crisp one.
    frame_unsharp_amount: float = Field(default=0.5, ge=0.0, le=3.0)
    #: Unsharp strength inside the OCR crop pre-pass. 0 disables sharpening.
    crop_unsharp_amount: float = Field(default=0.6, ge=0.0, le=3.0)
    #: Dynamic gamma + percentile contrast stretch on the crop, ahead of CLAHE.
    #: Rescues plates shot under a headlight or in deep shadow. Self-limiting:
    #: a normally-exposed crop is passed through untouched.
    normalize_lighting: bool = True
    #: Retry a failed read on a perspective-corrected copy of the crop. Costs
    #: an extra OCR pass, but only on crops that produced no valid plate.
    rectify_perspective: bool = True


class OcrConfig(BaseModel):
    backend: str = "easyocr"
    gpu: bool = False
    min_confidence: float = 0.5
    allowlist: str = "ABCDEFGHIJKLMNOPRSTUVYZ0123456789"
    #: Extra engines pooled into the per-frame ensemble vote alongside
    #: ``backend``. Empty by default: the ensemble already votes across the
    #: several enhanced views of each crop, which recovers most view-dependent
    #: glyph confusions at no extra model cost. A second *engine* adds a
    #: genuinely independent opinion but also its own memory and warmup, so it
    #: is opt-in -- e.g. ``["paddleocr"]`` alongside the default easyocr.
    #: Engines are queried in order and the ensemble stops as soon as it holds
    #: a grammatical read, so the second one is a cost paid on hard crops only.
    ensemble_backends: list[str] = Field(default_factory=list)


class VotingConfig(BaseModel):
    """Multi-frame consensus, and how long a confirmed plate stays confirmed.

    Sliding-gate deployments
    ------------------------
    ``cooldown_s`` is the setting that matters for an electric sliding gate
    (*yana kayar kapı*), and it matters for a reason that does not apply to an
    arm barrier. A sliding-gate motor is usually driven by **step-by-step pulse
    logic**: pulse 1 opens, pulse 2 *stops mid-travel*, pulse 3 closes. The
    cycle takes 15-25 seconds.

    A car waiting at the camera is read on every pass of the pipeline. Without
    a cooldown longer than the gate's travel time, the second confirmation of
    the *same plate* sends a second pulse into a gate that is still opening --
    and the driver watches it stop halfway. The default is therefore 20.0 s,
    chosen to cover a typical full open cycle rather than to be a round number.

    Tune it to your own gate: time the motor from closed to fully open and set
    this at or just above that. Too short re-triggers mid-travel; too long only
    delays a legitimate second entry by the same vehicle, which is the far
    cheaper mistake.

    An arm barrier has no such constraint -- its pulse is idempotent and the
    cycle is ~2 s -- so a barrier site can safely run this down at 3-5 s.
    """

    window: int = 5
    min_votes: int = 3
    ttl_s: float = 4.0
    #: How long a confirmed plate is suppressed on the same camera. See the
    #: class docstring: on a sliding gate this must exceed the motor's travel
    #: time, or the second confirmation stops the gate mid-open.
    cooldown_s: float = 20.0
    #: OCR passes one tracked plate may cost before it is muted for
    #: ``cooldown_s``. 0 disables the cap (every visible plate is re-read until
    #: it confirms). Only applies when ``detection.track`` is on.
    max_track_attempts: int = 12
    #: How long a track's state survives after the plate was last seen.
    track_ttl_s: float = 30.0


class RelayConfig(BaseModel):
    """The dry-contact gate relay.

    Sliding-gate deployments
    ------------------------
    ``pulse_ms`` is a **momentary dry-contact closure**, not a hold. The relay
    closes the circuit for this long and opens it again; the motor controller
    reads that closure as one press of its own button. 1000 ms is the default
    because it is comfortably above the debounce window of every step-by-step
    controller in common use, while staying short enough that the controller
    cannot read it as a held button (which some units treat as a separate
    "hold to run" mode).

    Do not raise this to try to keep a sliding gate open longer -- it has no
    such effect. The gate's open duration is set on the motor controller, not
    here. What governs re-triggering from this side is
    ``voting.cooldown_s``; see :class:`VotingConfig`.
    """

    enabled: bool = True
    port: str = "auto"
    baud: int = 9600
    open_byte: str = "A"
    close_byte: str = "a"
    #: Dry-contact closure length in milliseconds. One pulse = one button
    #: press at the motor controller.
    pulse_ms: int = 1000
    mock: bool = False

    @property
    def resolved_port(self) -> str | None:
        """The concrete serial device to open.

        ``port="auto"`` is resolved per-OS via ``platform_compat`` (first
        existing /dev/ttyUSB0 / ttyACM0 / serial0 on Linux, "COM3" on
        Windows). Any other value is returned unchanged.
        """
        if self.port == "auto":
            return default_serial_port()
        return self.port


class SmtpConfig(BaseModel):
    """Outbound email alerts, with the event snapshot attached.

    Off by default. Enabling it means the service reaches out to a third-party
    mail server on its own initiative and puts a **photograph of a vehicle** in
    the message, so it is worth being deliberate about two things:

    * ``password`` in a YAML file is a credential at rest. Prefer the
      environment variable ``LPR_SMTP__PASSWORD``, which overrides the file and
      keeps the secret out of the repository and out of any config backup.
    * The snapshot is personal data in most jurisdictions. Send it to a mailbox
      the site operator controls, not to a shared or personal address, and keep
      ``to_emails`` short.

    Nothing here throttles: the pipeline's own ``voting.cooldown_s`` already
    stops a car idling at the gate from re-deciding, so one refused vehicle
    produces one email rather than one per frame.
    """

    enabled: bool = False
    host: str = ""
    port: int = Field(default=587, ge=1, le=65535)
    user: str = ""
    password: str = ""
    #: Envelope sender. Falls back to ``user`` when blank, which is what most
    #: providers require anyway.
    from_email: str = ""
    to_emails: list[str] = Field(default_factory=list)
    #: A plate that is not on the list at all.
    notify_on_unauthorized: bool = True
    #: A plate that *is* on the list but flagged ``blocked``.
    notify_on_blacklisted: bool = True
    #: STARTTLS on a submission port (587). Set false only for an internal
    #: relay on 25 that does not offer TLS; port 465 is detected as implicit
    #: TLS and connects over SMTP_SSL regardless of this flag.
    use_tls: bool = True
    #: Seconds to wait on the SMTP conversation before giving up. A mail server
    #: that has gone away must not pin the sender thread.
    timeout_s: float = Field(default=15.0, gt=0, le=300)
    #: Bound on the pending-email queue. Full means the mail server cannot keep
    #: up with the gate; the oldest alert is dropped rather than the newest,
    #: because an operator wants the most recent refusal.
    queue_size: int = Field(default=64, ge=1, le=4096)

    @property
    def sender(self) -> str:
        """Envelope sender: ``from_email``, or ``user`` when it is blank."""
        return (self.from_email or self.user or "").strip()

    @property
    def recipients(self) -> list[str]:
        """Non-empty, whitespace-trimmed recipient list."""
        return [address.strip() for address in self.to_emails if address and address.strip()]

    @property
    def usable(self) -> bool:
        """True when the settings are complete enough to attempt a send.

        Checked before the worker thread is even started, so a half-filled
        configuration is one warning at startup rather than a failed connection
        per event for the life of the process.
        """
        return bool(self.enabled and self.host.strip() and self.sender and self.recipients)


class DatabaseConfig(BaseModel):
    path: str = "data/plates.db"
    log_retention_days: int = 10


class SnapshotsConfig(BaseModel):
    """Event snapshots: one JPEG per gate decision, on a rolling window."""

    enabled: bool = True
    #: Empty means ``<app.data_dir>/snapshots``. Set an absolute (or
    #: cwd-relative) path to put the images -- which grow far faster than the
    #: database -- on another disk.
    dir: str = ""
    #: Days of evidence to keep. Matches ``database.log_retention_days`` by
    #: default so an image and its log row expire together.
    retention_days: int = 10
    jpeg_quality: int = 85
    #: Frames awaiting encoding. Beyond this the writer drops rather than
    #: letting a slow disk push back on the recognition threads.
    queue_size: int = 64


class ParkingConfig(BaseModel):
    """Site capacity, used for the "vehicles inside / capacity" counter."""

    #: Default only. An admin can change it at runtime through
    #: ``PUT /api/parking``, which stores the value in the ``system_meta``
    #: table so every browser and tablet on the site agrees on one number.
    capacity: int = Field(default=100, ge=0, le=100000)


class SystemUpdateConfig(BaseModel):
    """Remote over-the-air update (git pull + docker compose rebuild).

    **Off by default, deliberately.** Turning this on gives anyone holding an
    admin token the ability to make the host run whatever the configured git
    remote currently contains, and rebuilding the stack from inside it needs a
    mounted Docker socket, which is root on the host. That is an acceptable
    trade for a fleet you control and a terrible default for a product that
    ships to sites you do not.

    Note what is *not* here: nothing in this model is settable per-request. The
    remote, branch, working directory and compose file are operator
    configuration, so a stolen admin token cannot redirect the update at an
    attacker's repository -- it can only re-run the operator's own.
    """

    #: Master switch for POST /api/system/update. GET /api/system/version keeps
    #: working either way, so the UI can still show what is deployed.
    enabled: bool = False
    #: Working directory for the git and compose commands; the repo root.
    repo_dir: str = "."
    git_remote: str = "origin"
    git_branch: str = "main"
    compose_file: str = "docker/docker-compose.yml"
    #: Fetching is quick; building an ML image is not.
    git_timeout_s: float = Field(default=120.0, gt=0, le=3600)
    build_timeout_s: float = Field(default=900.0, gt=0, le=21600)
    #: Where the outcome is left for the container that comes up after the
    #: rebuild. Empty = ``<data_dir>/last_update.json``.
    state_file: str = ""

    #: Check the remote for new commits once a night. Read-only on its own:
    #: with ``auto_update`` off it only *reports* that an update is waiting,
    #: which is a safe thing to leave on.
    nightly_check: bool = True
    #: Install what the nightly check finds, unattended.
    #:
    #: Separate from ``enabled`` because they are different risks. A human
    #: pressing the button watches the result and updates one site; this
    #: updates the whole fleet at once with nobody looking, so a bad commit
    #: becomes a fleet-wide outage discovered by a phone call. Requires
    #: ``enabled`` as well -- both must be true.
    auto_update: bool = False
    #: Local wall-clock time of the nightly check. "Low traffic" is a property
    #: of the site's clock, not of UTC.
    check_hour: int = Field(default=3, ge=0, le=23)
    check_minute: int = Field(default=0, ge=0, le=59)
    #: Retention for the ``system_events`` audit rows.
    event_retention_days: int = Field(default=90, ge=0, le=3650)


class ApiConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    token_ttl_min: int = 720
    secret_key: str = "change-me"


class SecurityConfig(BaseModel):
    password_hasher: str = "argon2"


# ---------------------------------------------------------------------------
# YAML source
# ---------------------------------------------------------------------------


def _default_config_yaml_path() -> Path:
    """Locate ``config.yaml``.

    Honours ``LPR_CONFIG_FILE`` if set, otherwise assumes the conventional
    layout: this file lives at ``<repo-root>/src/lpr/config.py`` (or, in the
    container image, ``/app/src/lpr/config.py`` next to ``/app/config.yaml``)
    so the repo/app root is two parents up. Falls back to
    ``<cwd>/config.yaml`` if that guess doesn't exist.
    """
    env_path = os.environ.get("LPR_CONFIG_FILE")
    if env_path:
        return Path(env_path)

    guess = Path(__file__).resolve().parents[2] / "config.yaml"
    if guess.exists():
        return guess

    return Path.cwd() / "config.yaml"


class _YamlSettingsSource(PydanticBaseSettingsSource):
    """Reads the whole YAML document as the base layer of settings.

    Missing file -> empty layer (defaults / env still apply). This is a
    hand-rolled source (rather than relying on a specific pydantic-settings
    minor version's built-in YAML source) so behaviour stays stable across
    the pinned dependency range.
    """

    def __init__(self, settings_cls: type[BaseSettings], yaml_path: Path) -> None:
        super().__init__(settings_cls)
        self._yaml_path = yaml_path

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        # Required by the abstract base; unused because __call__ is overridden
        # to return the full parsed document in one shot.
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        if not self._yaml_path.exists():
            return {}
        with self._yaml_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# Root settings
# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LPR_",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    app: AppConfig = Field(default_factory=AppConfig)
    cameras: CamerasConfig = Field(default_factory=CamerasConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    preprocess: PreprocessConfig = Field(default_factory=PreprocessConfig)
    ocr: OcrConfig = Field(default_factory=OcrConfig)
    voting: VotingConfig = Field(default_factory=VotingConfig)
    relay: RelayConfig = Field(default_factory=RelayConfig)
    smtp: SmtpConfig = Field(default_factory=SmtpConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    snapshots: SnapshotsConfig = Field(default_factory=SnapshotsConfig)
    parking: ParkingConfig = Field(default_factory=ParkingConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    system_update: SystemUpdateConfig = Field(default_factory=SystemUpdateConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Order = lowest priority first, wins-over relation flows left->right
        # in the sense that *earlier* sources are overridden by *later* ones
        # is backwards for pydantic-settings: the FIRST source in this tuple
        # has the HIGHEST priority. So: init args > env > yaml > dotenv > secrets.
        yaml_source = _YamlSettingsSource(settings_cls, _default_config_yaml_path())
        return (
            init_settings,
            env_settings,
            yaml_source,
            dotenv_settings,
            file_secret_settings,
        )

    @model_validator(mode="after")
    def _check_secret_key_in_production(self) -> "Settings":
        is_production = os.environ.get("LPR_ENV", "").strip().lower() == "production"
        if self.app.headless and is_production and self.api.secret_key == "change-me":
            raise ValueError(
                "api.secret_key is still the default 'change-me'. Set it via "
                "config.yaml (api.secret_key) or the LPR_API__SECRET_KEY "
                "environment variable before running with LPR_ENV=production."
            )
        return self

    @property
    def paths(self) -> "ResolvedPaths":
        """Absolute, existing paths derived from ``app.*`` and ``database.path``.

        Directories are created (mkdir -p) the first time each attribute is
        accessed, so a fresh checkout / fresh container volume works without
        a separate provisioning step.
        """
        return ResolvedPaths(self)


class ResolvedPaths:
    """Lazily resolves config-relative paths to absolute ``Path`` objects.

    Relative paths are resolved against the current working directory,
    which in the container is ``/app`` (WORKDIR) and in local dev is
    expected to be the repo root.
    """

    __slots__ = ("_settings",)

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def data_dir(self) -> Path:
        p = Path(self._settings.app.data_dir).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def models_dir(self) -> Path:
        p = Path(self._settings.app.models_dir).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def database(self) -> Path:
        p = Path(self._settings.database.path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def snapshots_dir(self) -> Path:
        """Where event snapshots are written; ``<data_dir>/snapshots`` by default.

        Derived from ``data_dir`` rather than hard-coded so that anything
        repointing the data directory -- a test fixture, a container volume --
        moves the images with it.
        """
        configured = str(self._settings.snapshots.dir).strip()
        p = Path(configured).expanduser().resolve() if configured else self.data_dir / "snapshots"
        p.mkdir(parents=True, exist_ok=True)
        return p


# ---------------------------------------------------------------------------
# Cached accessors
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide ``Settings`` singleton, building it on first call.

    Use ``reload_settings()`` (not a second ``get_settings()`` call) to pick
    up changed environment variables or a rewritten ``config.yaml``.
    """
    return Settings()


def reload_settings() -> Settings:
    """Clear the cached ``Settings`` and rebuild it from current sources."""
    get_settings.cache_clear()
    return get_settings()
