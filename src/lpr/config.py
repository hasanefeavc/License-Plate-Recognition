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


class OcrConfig(BaseModel):
    backend: str = "easyocr"
    gpu: bool = False
    min_confidence: float = 0.5
    allowlist: str = "ABCDEFGHIJKLMNOPRSTUVYZ0123456789"


class VotingConfig(BaseModel):
    window: int = 5
    min_votes: int = 3
    ttl_s: float = 4.0
    cooldown_s: float = 10.0
    #: OCR passes one tracked plate may cost before it is muted for
    #: ``cooldown_s``. 0 disables the cap (every visible plate is re-read until
    #: it confirms). Only applies when ``detection.track`` is on.
    max_track_attempts: int = 12
    #: How long a track's state survives after the plate was last seen.
    track_ttl_s: float = 30.0


class RelayConfig(BaseModel):
    enabled: bool = True
    port: str = "auto"
    baud: int = 9600
    open_byte: str = "A"
    close_byte: str = "a"
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


class DatabaseConfig(BaseModel):
    path: str = "data/plates.db"
    log_retention_days: int = 10


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
    ocr: OcrConfig = Field(default_factory=OcrConfig)
    voting: VotingConfig = Field(default_factory=VotingConfig)
    relay: RelayConfig = Field(default_factory=RelayConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
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
