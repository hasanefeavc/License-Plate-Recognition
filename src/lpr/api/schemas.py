"""Pydantic v2 request/response models for the LPR HTTP API.

These models are the *wire contract*. They mirror the dataclasses in
:mod:`lpr.contracts` but stay separate from them: the dataclasses are the
in-process contract between the pipeline, the database and the UI, while these
are what FastAPI validates and serialises. Keeping the two apart means a
storage/pipeline refactor never silently changes the public JSON.

Every plate-carrying field is normalised on the way in (strip, remove inner
whitespace and dashes, uppercase) so ``" 34 abc 123 "`` and ``"34ABC123"``
are the same plate as far as the API is concerned.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "CameraSourceIn",
    "CameraStatusOut",
    "ErrorOut",
    "HealthOut",
    "LogOut",
    "LogQuery",
    "LoginIn",
    "PlateIn",
    "PlateListOut",
    "PlateOut",
    "PipelineStateOut",
    "RegisterIn",
    "RelayTriggerOut",
    "StatsOut",
    "TokenOut",
    "UserOut",
    "normalize_plate",
]

# Anything that is not a letter or a digit is noise in a plate string:
# separators ("34-ABC-123"), thin spaces pasted from a spreadsheet, etc.
_PLATE_NOISE_RE = re.compile(r"[^A-Z0-9]+")

CameraRoleLiteral = Literal["entry", "exit"]


def normalize_plate(value: str) -> str:
    """Canonical plate form: uppercase, alphanumeric only, no whitespace.

    Turkish plates have no lowercase form and no internal punctuation, so this
    is lossless for valid input and merely forgiving for sloppy input.
    """
    return _PLATE_NOISE_RE.sub("", value.strip().upper())


PlateStr = Annotated[str, Field(min_length=2, max_length=16, examples=["34ABC123"])]


# ---------------------------------------------------------------------------
# Plates
# ---------------------------------------------------------------------------


class PlateIn(BaseModel):
    """Body of ``POST /api/plates``."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"plate": "34ABC123", "note": "Müdür aracı"}]},
    )

    plate: PlateStr
    note: str | None = Field(default=None, max_length=200, examples=["Müdür aracı"])

    @field_validator("plate", mode="before")
    @classmethod
    def _normalize(cls, value: Any) -> Any:
        if isinstance(value, str):
            return normalize_plate(value)
        return value

    @field_validator("note", mode="before")
    @classmethod
    def _strip_note(cls, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value


class PlateOut(BaseModel):
    """A single registered plate."""

    model_config = ConfigDict(
        json_schema_extra={"examples": [{"plate": "34ABC123", "registered": True}]}
    )

    plate: PlateStr
    registered: bool = Field(default=True, examples=[True])

    @field_validator("plate", mode="before")
    @classmethod
    def _normalize(cls, value: Any) -> Any:
        if isinstance(value, str):
            return normalize_plate(value)
        return value


class PlateListOut(BaseModel):
    """Response of ``GET /api/plates``."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"plates": ["06XYZ42", "34ABC123"], "count": 2}]
        }
    )

    plates: list[str] = Field(default_factory=list, examples=[["06XYZ42", "34ABC123"]])
    count: int = Field(default=0, ge=0, examples=[2])

    @field_validator("plates", mode="before")
    @classmethod
    def _normalize_all(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [normalize_plate(v) if isinstance(v, str) else v for v in value]
        return value


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


class LogOut(BaseModel):
    """One log row. Field-for-field mirror of ``LprEvent.to_dict()``."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "id": 512,
                    "ts": "2026-05-01T09:15:00+00:00",
                    "camera": "entry",
                    "plate": "34ABC123",
                    "action": "granted",
                    "confidence": 0.9712,
                }
            ]
        }
    )

    id: int | None = Field(default=None, examples=[512])
    ts: str = Field(examples=["2026-05-01T09:15:00+00:00"])
    camera: str = Field(examples=["entry"])
    plate: str = Field(examples=["34ABC123"])
    action: str = Field(examples=["granted"])
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, examples=[0.9712])

    @classmethod
    def from_event(cls, event: Any) -> "LogOut":
        """Build from anything exposing ``to_dict()`` (i.e. ``LprEvent``)."""
        return cls.model_validate(event.to_dict())


class LogQuery(BaseModel):
    """Validated form of the ``GET /api/logs`` query string."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "since": "2026-05-01",
                    "until": "2026-05-02",
                    "camera": "entry",
                    "plate": "34ABC123",
                    "limit": 200,
                    "offset": 0,
                }
            ]
        },
    )

    since: str | None = Field(default=None, examples=["2026-05-01"])
    until: str | None = Field(default=None, examples=["2026-05-02"])
    camera: CameraRoleLiteral | None = Field(default=None, examples=["entry"])
    plate: str | None = Field(default=None, examples=["34ABC123"])
    limit: int = Field(default=200, ge=1, le=1000, examples=[200])
    offset: int = Field(default=0, ge=0, examples=[0])

    @field_validator("plate", mode="before")
    @classmethod
    def _normalize_plate(cls, value: Any) -> Any:
        if isinstance(value, str):
            return normalize_plate(value) or None
        return value

    @field_validator("since", "until", mode="before")
    @classmethod
    def _strip_dates(cls, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value


# ---------------------------------------------------------------------------
# Cameras / pipeline / health
# ---------------------------------------------------------------------------


class CameraStatusOut(BaseModel):
    """Health of one capture worker. Mirrors ``contracts.CameraStatus``."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "role": "entry",
                    "source": "rtsp://10.0.0.5/stream",
                    "connected": True,
                    "fps": 14.8,
                    "frames_read": 12045,
                    "frames_dropped": 12,
                    "motion_skipped": 98311,
                    "last_error": None,
                    "last_frame_ts": 1777000000.0,
                }
            ]
        }
    )

    role: str = Field(examples=["entry"])
    source: str = Field(default="", examples=["rtsp://10.0.0.5/stream"])
    connected: bool = Field(default=False, examples=[True])
    fps: float = Field(default=0.0, ge=0.0, examples=[14.8])
    frames_read: int = Field(default=0, ge=0, examples=[12045])
    frames_dropped: int = Field(default=0, ge=0, examples=[12])
    #: Frames skipped by the motion gate before any inference ran.
    motion_skipped: int = Field(default=0, ge=0, examples=[98311])
    last_error: str | None = Field(default=None, examples=[None])
    last_frame_ts: float = Field(default=0.0, examples=[1777000000.0])


class StatsOut(BaseModel):
    """Response of ``GET /api/stats``."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "running": True,
                    "started_at": 1776999000.0,
                    "uptime_s": 1000.0,
                    "plates_read": 87,
                    "grants": 61,
                    "denials": 26,
                    "ocr_skipped": 412,
                    "cameras": [],
                }
            ]
        }
    )

    running: bool = Field(default=False, examples=[True])
    started_at: float = Field(default=0.0, examples=[1776999000.0])
    uptime_s: float = Field(default=0.0, ge=0.0, examples=[1000.0])
    plates_read: int = Field(default=0, ge=0, examples=[87])
    grants: int = Field(default=0, ge=0, examples=[61])
    denials: int = Field(default=0, ge=0, examples=[26])
    #: OCR passes skipped because the plate's track had already been decided.
    ocr_skipped: int = Field(default=0, ge=0, examples=[412])
    cameras: list[CameraStatusOut] = Field(default_factory=list)


class MetricsOut(BaseModel):
    """Response of ``GET /api/metrics``.

    The operational summary a dashboard or a scrape job wants, flat and
    cheap: how long the service has been up, how much work it has done, and
    how much work it *avoided* -- ``motion_skipped`` frames never reached the
    detector and ``ocr_skipped`` crops never reached the recogniser, which is
    the pair that explains the CPU load.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "running": True,
                    "uptime_s": 86400.0,
                    "plates_read": 87,
                    "grants": 61,
                    "denials": 26,
                    "ocr_skipped": 412,
                    "motion_skipped": 1284510,
                    "frames_read": 1296100,
                    "frames_dropped": 42,
                    "cameras_connected": 2,
                    "cameras_total": 2,
                    "websocket_clients": 1,
                }
            ]
        }
    )

    running: bool = Field(default=False, examples=[True])
    uptime_s: float = Field(default=0.0, ge=0.0, examples=[86400.0])
    plates_read: int = Field(default=0, ge=0, examples=[87])
    grants: int = Field(default=0, ge=0, examples=[61])
    denials: int = Field(default=0, ge=0, examples=[26])
    ocr_skipped: int = Field(default=0, ge=0, examples=[412])
    motion_skipped: int = Field(default=0, ge=0, examples=[1284510])
    frames_read: int = Field(default=0, ge=0, examples=[1296100])
    frames_dropped: int = Field(default=0, ge=0, examples=[42])
    cameras_connected: int = Field(default=0, ge=0, examples=[2])
    cameras_total: int = Field(default=0, ge=0, examples=[2])
    websocket_clients: int = Field(default=0, ge=0, examples=[1])


class HealthOut(BaseModel):
    """Response of ``GET /health``. Never requires auth, never 500s."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "status": "ok",
                    "version": "0.1.0",
                    "pipeline_running": True,
                    "cameras": {"entry": True, "exit": False},
                    "detail": None,
                }
            ]
        }
    )

    status: Literal["ok", "degraded"] = Field(default="ok", examples=["ok"])
    version: str = Field(default="0.0.0", examples=["0.1.0"])
    pipeline_running: bool = Field(default=False, examples=[True])
    cameras: dict[str, bool] = Field(
        default_factory=dict, examples=[{"entry": True, "exit": False}]
    )
    detail: str | None = Field(default=None, examples=[None])


class PipelineStateOut(BaseModel):
    """Response of the pause/resume endpoints."""

    model_config = ConfigDict(
        json_schema_extra={"examples": [{"paused": True, "running": True}]}
    )

    paused: bool = Field(examples=[True])
    running: bool = Field(default=False, examples=[True])


class CameraSourceIn(BaseModel):
    """Body of ``POST /api/cameras/{role}/source`` -- runtime source change."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"source": "rtsp://10.0.0.5/stream"}]},
    )

    source: str = Field(
        min_length=1, max_length=512, examples=["rtsp://10.0.0.5/stream", "0"]
    )

    @field_validator("source", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip()
        return value


class RelayTriggerOut(BaseModel):
    """Response of ``POST /api/relay/trigger``."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "triggered": True,
                    "plate": "MANUAL",
                    "ts": "2026-05-01T09:15:00+00:00",
                    "detail": None,
                }
            ]
        }
    )

    triggered: bool = Field(examples=[True])
    plate: str = Field(default="MANUAL", examples=["MANUAL"])
    ts: str = Field(examples=["2026-05-01T09:15:00+00:00"])
    detail: str | None = Field(default=None, examples=[None])


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class LoginIn(BaseModel):
    """Body of ``POST /api/auth/login``."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"username": "admin", "password": "s3cret!"}]},
    )

    username: str = Field(min_length=1, max_length=64, examples=["admin"])
    password: str = Field(min_length=1, max_length=256, examples=["s3cret!"])

    @field_validator("username", mode="before")
    @classmethod
    def _strip_username(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip()
        return value


class RegisterIn(BaseModel):
    """Body of ``POST /api/auth/register``."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {"username": "operator1", "password": "s3cret!", "role": "operator"}
            ]
        },
    )

    username: str = Field(min_length=3, max_length=64, examples=["operator1"])
    password: str = Field(min_length=4, max_length=256, examples=["s3cret!"])
    role: Literal["admin", "operator"] = Field(default="operator", examples=["operator"])

    @field_validator("username", mode="before")
    @classmethod
    def _strip_username(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip()
        return value


class TokenOut(BaseModel):
    """Response of login/registration: an HS256 bearer token."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "token_type": "bearer",
                    "expires_in": 43200,
                    "username": "admin",
                    "role": "admin",
                }
            ]
        }
    )

    access_token: str = Field(examples=["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig"])
    token_type: Literal["bearer"] = Field(default="bearer", examples=["bearer"])
    expires_in: int = Field(examples=[43200], description="Token lifetime in seconds")
    username: str = Field(examples=["admin"])
    role: str = Field(examples=["admin"])


class UserOut(BaseModel):
    """A user account as exposed by the API (never carries a password hash)."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"username": "admin", "role": "admin", "created_at": "2026-05-01"}
            ]
        }
    )

    username: str = Field(examples=["admin"])
    role: str = Field(default="operator", examples=["admin"])
    created_at: str | None = Field(default=None, examples=["2026-05-01"])


class ErrorOut(BaseModel):
    """Uniform error envelope emitted by the shared exception handlers."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "error": {
                        "status": 404,
                        "title": "Not Found",
                        "detail": "Plaka bulunamadı: 34ABC123",
                    }
                }
            ]
        }
    )

    error: dict[str, Any] = Field(
        examples=[{"status": 404, "title": "Not Found", "detail": "Bulunamadı"}]
    )
