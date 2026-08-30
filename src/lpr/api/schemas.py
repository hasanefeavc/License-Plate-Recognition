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

from lpr.contracts import utc_now_iso

__all__ = [
    "CameraSourceIn",
    "CameraStatusOut",
    "ErrorOut",
    "HealthOut",
    "LogOut",
    "LicenseIn",
    "LicenseOut",
    "LogQuery",
    "LoginIn",
    "PlateDetailOut",
    "PlateIn",
    "PlateListOut",
    "PlateOut",
    "PlateUpdateIn",
    "PipelineStateOut",
    "RegisterIn",
    "RelayTriggerOut",
    "PlateImportOut",
    "StatsOut",
    "SystemEventOut",
    "SystemUpdateIn",
    "SystemUpdateOut",
    "TokenOut",
    "LicenseKeyIn",
    "UserCreateIn",
    "UserLicenseIn",
    "UserLicenseOut",
    "UserOut",
    "VersionOut",
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

#: A bare calendar date, as an ``<input type="date">`` submits it.
_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _end_of_day(value: str | None) -> str | None:
    """Widen a bare ``YYYY-MM-DD`` to the last instant of that day, in UTC.

    A date picker submits ``2027-01-01``. Stored as-is it compares equal to
    midnight, so a permit "valid until 1 January" would expire as 31 December
    ended -- a full day early, and the resident is refused at the gate on the
    day their sticker says they are fine. Anything already carrying a time is
    left exactly as the caller sent it.
    """
    if not value or not _DATE_ONLY_RE.match(value):
        return value
    return f"{value}T23:59:59+00:00"


def plate_status(row: dict[str, Any], now: str | None = None) -> str:
    """Classify one plate row for display: active / blocked / expired / guest.

    The order of these checks is the same policy
    :meth:`lpr.db.repository.PlateRepository.authorization` applies at the
    barrier, and it has to stay that way: a badge that says "expired" for a car
    the gate refuses as "blocked" sends an operator to fix the wrong thing.

    ``blocked`` outranks expiry: a barred plate whose permit also lapsed is
    still barred, and that is the more important thing to show. A plate with a
    future end date is a *guest* (a temporary permit) rather than merely
    active, because those are the rows a manager reviews.

    The owning account's licence is deliberately absent from this: it governs
    that person's access to the dashboard, not their car's access to the gate,
    so it must not colour a badge about the car.
    """
    if row.get("blocked"):
        return "blocked"
    expires = str(row.get("expires_at") or "").strip()
    if not expires:
        return "active"
    # Lexical comparison on fixed-width ISO-8601 UTC, as everywhere else here.
    return "expired" if expires <= (now or utc_now_iso()) else "guest"


# ---------------------------------------------------------------------------
# Plates
# ---------------------------------------------------------------------------


class PlateIn(BaseModel):
    """Body of ``POST /api/plates``.

    Everything past ``plate`` is optional, so the one-field form an operator
    uses at the gate ("just let this car in") still works unchanged; the
    resident fields are for the management screen.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "plate": "34ABC123",
                    "owner": "Ahmet Yılmaz",
                    "apartment": "B Blok D:12",
                    "note": "Müdür aracı",
                    "expires_at": "2027-01-01",
                    "blocked": False,
                }
            ]
        },
    )

    plate: PlateStr
    note: str | None = Field(default=None, max_length=200, examples=["Müdür aracı"])
    owner: str | None = Field(default=None, max_length=120, examples=["Ahmet Yılmaz"])
    apartment: str | None = Field(default=None, max_length=60, examples=["B Blok D:12"])
    #: Permit end date. A bare ``YYYY-MM-DD`` from a date picker is widened to
    #: the end of that day, so a permit dated today is valid all of today.
    expires_at: str | None = Field(default=None, max_length=40, examples=["2027-01-01"])
    blocked: bool = Field(default=False, examples=[False])
    #: The account this car belongs to. ``None`` -- the default -- means no
    #: subscriber, i.e. a plate no licence governs, which is what every plate
    #: registered before this field existed remains.
    username: str | None = Field(default=None, max_length=40, examples=["ahmet"])

    @field_validator("owner", "apartment", "expires_at", "username", mode="before")
    @classmethod
    def _strip_optional(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("expires_at", mode="after")
    @classmethod
    def _widen_date(cls, value: str | None) -> str | None:
        return _end_of_day(value)

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


class PlateUpdateIn(BaseModel):
    """Body of ``PATCH /api/plates/{plate}`` -- a partial update.

    Only the fields actually present in the request are written. That is what
    lets the dashboard's block toggle send ``{"blocked": true}`` without
    blanking the owner and expiry it never asked about.
    """

    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [{"blocked": True}]})

    note: str | None = Field(default=None, max_length=200)
    owner: str | None = Field(default=None, max_length=120)
    apartment: str | None = Field(default=None, max_length=60)
    expires_at: str | None = Field(default=None, max_length=40)
    blocked: bool | None = Field(default=None, examples=[True])
    username: str | None = Field(default=None, max_length=40)

    @field_validator("owner", "apartment", "expires_at", "note", "username", mode="before")
    @classmethod
    def _strip_optional(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("expires_at", mode="after")
    @classmethod
    def _widen_date(cls, value: str | None) -> str | None:
        return _end_of_day(value)

    def changes(self) -> dict[str, Any]:
        """Only the fields the caller actually sent."""
        return {name: getattr(self, name) for name in self.model_fields_set}


class PlateDetailOut(BaseModel):
    """One resident record, as the management screen renders it."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "plate": "34ABC123",
                    "owner": "Ahmet Yılmaz",
                    "apartment": "B Blok D:12",
                    "note": "Müdür aracı",
                    "expires_at": "2027-01-01T23:59:59+00:00",
                    "blocked": False,
                    "added_at": "2026-08-27T09:14:02+00:00",
                    "status": "active",
                }
            ]
        }
    )

    plate: PlateStr
    owner: str | None = None
    apartment: str | None = None
    note: str | None = None
    expires_at: str | None = None
    blocked: bool = False
    added_at: str | None = None
    username: str | None = None
    #: Derived here rather than in the browser, deliberately. Expiry decides
    #: whether the gate opens, and that comparison is made against the
    #: *server's* clock -- a dashboard on a machine with a wrong clock must not
    #: show a badge that contradicts what the barrier will do.
    status: Literal["active", "blocked", "expired", "guest"] = "active"


class PlateListOut(BaseModel):
    """Response of ``GET /api/plates``."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"plates": ["06XYZ42", "34ABC123"], "count": 2}]
        }
    )

    plates: list[str] = Field(default_factory=list, examples=[["06XYZ42", "34ABC123"]])
    #: The same plates with their resident data. Additive: ``plates`` stays a
    #: bare list of strings so the desktop client, which only ever wanted the
    #: strings, keeps working against this endpoint unchanged.
    records: list[PlateDetailOut] = Field(default_factory=list)
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
                    "fast_path_hits": 87,
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
    #: Gate decisions taken on the first confident read of a registered
    #: plate. Against ``grants``, the fast path's hit rate.
    fast_path_hits: int = Field(default=0, ge=0, examples=[87])
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
                    "fast_path_hits": 87,
                    "motion_skipped": 1284510,
                    "frames_read": 1296100,
                    "frames_dropped": 42,
                    "cameras_connected": 2,
                    "cameras_total": 2,
                    "websocket_clients": 1,
                    "license_valid": True,
                    "license_reason": "ok",
                    "license_client": "Site A",
                    "license_expires_at": "2026-09-24T16:42:47+00:00",
                    "license_days_remaining": 29.7,
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
    #: Gate decisions taken on the first confident read of a registered
    #: plate. Against ``grants``, the fast path's hit rate.
    fast_path_hits: int = Field(default=0, ge=0, examples=[87])
    motion_skipped: int = Field(default=0, ge=0, examples=[1284510])
    frames_read: int = Field(default=0, ge=0, examples=[1296100])
    frames_dropped: int = Field(default=0, ge=0, examples=[42])
    cameras_connected: int = Field(default=0, ge=0, examples=[2])
    cameras_total: int = Field(default=0, ge=0, examples=[2])
    websocket_clients: int = Field(default=0, ge=0, examples=[1])

    # -- licence ---------------------------------------------------------
    # Reported here because this is the endpoint a dashboard already scrapes:
    # a site whose key expires in three days should show up on the same panel
    # as its frame counters, not in a place nobody looks.
    license_valid: bool = Field(default=False, examples=[True])
    license_reason: str = Field(default="missing", examples=["ok"])
    license_client: str | None = Field(default=None, examples=["Site A"])
    license_expires_at: str | None = Field(
        default=None, examples=["2026-09-24T16:42:47+00:00"]
    )
    license_days_remaining: float | None = Field(default=None, examples=[29.7])


class LicenseIn(BaseModel):
    """Body of ``POST /api/license``: the key the operator pasted in."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}]},
    )

    key: str = Field(
        min_length=16,
        max_length=4096,
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."],
    )

    @field_validator("key", mode="before")
    @classmethod
    def _clean(cls, value: Any) -> Any:
        """Strip whatever the paste brought with it.

        Operators paste from an e-mail or a chat window, so the key arrives
        wrapped across lines and padded with spaces. A JWT contains no
        whitespace at all, which makes removing every whitespace character
        unambiguous rather than merely convenient.
        """
        if isinstance(value, str):
            return "".join(value.split())
        return value


class LicenseOut(BaseModel):
    """Licence state: response of ``GET`` and ``POST /api/license``.

    ``reason`` is the stable machine code the desktop client switches on
    (``ok``, ``missing``, ``expired``, ``invalid``, ``clock_rollback``,
    ``not_yet_valid``, ``no_secret``); ``detail`` is the sentence shown to
    the operator. The key itself is never echoed back.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "valid": True,
                    "reason": "ok",
                    "detail": "Lisans geçerli.",
                    "client": "Site A",
                    "issued_at": "2026-08-25T16:42:47+00:00",
                    "expires_at": "2026-09-24T16:42:47+00:00",
                    "seconds_remaining": 2566800.0,
                    "days_remaining": 29.7,
                    "pipeline_halted": False,
                }
            ]
        }
    )

    valid: bool = Field(default=False, examples=[True])
    reason: str = Field(default="missing", examples=["ok"])
    detail: str = Field(default="", examples=["Lisans geçerli."])
    client: str | None = Field(default=None, examples=["Site A"])
    issued_at: str | None = Field(default=None, examples=["2026-08-25T16:42:47+00:00"])
    expires_at: str | None = Field(default=None, examples=["2026-09-24T16:42:47+00:00"])
    seconds_remaining: float | None = Field(default=None, examples=[2566800.0])
    days_remaining: float | None = Field(default=None, examples=[29.7])
    #: True while the pipeline is held paused *because* of the licence, so the
    #: client can tell "expired" apart from "an operator pressed pause".
    pipeline_halted: bool = Field(default=False, examples=[False])


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
    #: True only while no account exists at all. The login screen reads this to
    #: decide whether to offer "Kaydol" (which creates the bootstrap admin) or
    #: just the sign-in form. Safe to expose unauthenticated: an installation
    #: with no accounts is open by construction, and saying so is what lets the
    #: UI stop advertising public registration once it is not.
    setup_required: bool = Field(default=False, examples=[False])


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


class ParkingOut(BaseModel):
    """Response of ``GET``/``PUT /api/parking``: live occupancy vs capacity."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "inside": 12,
                    "capacity": 100,
                    "full": False,
                    "entries": 48,
                    "exits": 36,
                    "since": "2026-08-27T00:00:00+00:00",
                }
            ]
        }
    )

    inside: int = Field(default=0, ge=0, examples=[12])
    capacity: int = Field(default=0, ge=0, examples=[100])
    #: True once ``inside`` reaches ``capacity``. Computed server-side so every
    #: client shows the "OTOPARK DOLU" warning at the same moment.
    full: bool = Field(default=False, examples=[False])
    entries: int = Field(default=0, ge=0, examples=[48])
    exits: int = Field(default=0, ge=0, examples=[36])
    since: str = Field(default="", examples=["2026-08-27T00:00:00+00:00"])


class ParkingIn(BaseModel):
    """Body of ``PUT /api/parking``."""

    model_config = ConfigDict(extra="forbid")

    capacity: int = Field(ge=0, le=100000, examples=[100])


class LoginIn(BaseModel):
    """Body of ``POST /api/auth/login``."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"username": "admin", "password": "s3cret!"}]},
    )

    username: str = Field(min_length=1, max_length=64, examples=["admin"])
    password: str = Field(min_length=1, max_length=256, examples=["s3cret!"])
    #: Optional licence key, activated as part of signing in.
    #:
    #: An account whose licence has lapsed is refused at login, and activation
    #: normally needs a session -- so without this an operator holding a valid
    #: replacement key would have no way to use it. Sending it here activates
    #: first and admits the same request. Ordinary logins leave it unset.
    license_key: str | None = Field(default=None, max_length=2048)

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
    #: Session length for this account in minutes; ``None`` means it inherits
    #: the policy for its role.
    token_ttl_min: int | None = Field(default=None, examples=[480])
    #: Licence state, so the admin table can show it without a call per row.
    license_status: str | None = Field(default=None, examples=["active"])
    license_expires_at: str | None = Field(default=None)
    #: The activated key, present only once the operator has entered it.
    #: Admin-only, like this whole endpoint.
    license_key: str | None = Field(default=None)
    license_activated_at: str | None = Field(default=None)
    license_duration_days: int | None = Field(default=None)


class VersionOut(BaseModel):
    """Response of ``GET /api/system/version`` -- what is deployed right now."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "version": "v1.0.0-2-g6845136",
                    "commit": "6845136fc5071a3e0bdd11d112182c4917bd6f39",
                    "short_commit": "6845136",
                    "branch": "main",
                    "dirty": False,
                    "update_enabled": True,
                }
            ]
        }
    )

    #: Human-readable, from ``git describe --tags --always``: ``v1.0.0`` on a
    #: tagged release, ``v1.0.0-2-g6845136`` between releases, a bare short
    #: hash in a repository that has never been tagged, and the packaged
    #: version when the deployment is not a git checkout at all. This is the
    #: field to display; it is a label, not an identity.
    version: str = Field(examples=["v1.0.0-2-g6845136", "v1.0.0", "0.1.0"])
    #: ``None`` when the deployment is not a git checkout (image built from a
    #: tarball, git binary absent).
    #:
    #: This, not ``version``, identifies the running build -- tagging a commit
    #: that is already deployed changes the version string without deploying
    #: anything, so the dashboard watches this to tell that an OTA update
    #: really did replace the process.
    commit: str | None = Field(default=None, examples=["6845136fc5071a3e0bdd11d1"])
    short_commit: str | None = Field(default=None, examples=["6845136"])
    branch: str | None = Field(default=None, examples=["main"])
    #: Uncommitted local changes are present, which will block a --ff-only pull.
    dirty: bool = Field(default=False, examples=[False])
    #: Whether ``POST /api/system/update`` will do anything, so the UI can
    #: disable the button instead of offering an action that always 503s.
    update_enabled: bool = Field(default=False, examples=[True])


class SystemUpdateIn(BaseModel):
    """Body of ``POST /api/system/update``. Entirely optional.

    The body carries exactly one flag and nothing else. That is a deliberate
    limit rather than an oversight: the remote, branch, repository directory
    and compose file are configuration, so there is nowhere in this model for
    a caller to name *what* gets pulled or built. Unknown keys are ignored,
    which keeps an older client that posts no body -- or a curious one that
    posts a ``remote`` -- working and harmless respectively.
    """

    model_config = ConfigDict(json_schema_extra={"examples": [{"force": True}]})

    #: Rebuild and restart even when the pull brings nothing new.
    #:
    #: The default path treats "already on the newest commit" as a reason
    #: *not* to rebuild, because a rebuild takes the cameras and the barrier
    #: down for a few minutes. ``force`` says the operator wants that outage
    #: anyway -- the usual reasons being a container running a stale image, an
    #: edited ``.env`` that only a recreate will pick up, or a checkout that
    #: cannot fast-forward and therefore never reaches the build at all.
    force: bool = Field(default=False, examples=[True])


class SystemUpdateOut(BaseModel):
    """Response of ``POST /api/system/update`` and ``GET /api/system/update``.

    The POST returns as soon as the work is *accepted*, not when it finishes:
    the rebuild kills the container serving the request, so success can never
    be reported over that connection. The UI polls the GET (and then the
    version endpoint) to find out how it ended.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "state": "running",
                    "step": "pull",
                    "detail": "Güncelleme başlatıldı.",
                    "running": True,
                    "accepted": True,
                }
            ]
        }
    )

    state: Literal["idle", "running", "restarting", "succeeded", "failed"] = Field(
        examples=["running"]
    )
    step: str | None = Field(default=None, examples=["pull"])
    detail: str = Field(default="", examples=["Güncelleme başlatıldı."])
    running: bool = Field(default=False, examples=[True])
    #: True only on the POST that actually started an update.
    accepted: bool = Field(default=False, examples=[True])
    started_at: float | None = Field(default=None)
    finished_at: float | None = Field(default=None)
    commit_before: str | None = Field(default=None)
    commit_after: str | None = Field(default=None)
    #: This run was a forced rebuild, so the commit very probably did not move.
    #: The UI needs it to avoid reporting "güncellendi" for a run that
    #: deliberately upgraded nothing, and to stop waiting for a commit change
    #: that is never coming.
    forced: bool = Field(default=False, examples=[True])
    #: Tail of the git/compose output, for the operator to read on failure.
    log: list[str] = Field(default_factory=list)


class SystemEventOut(BaseModel):
    """One row of ``GET /api/system/events`` -- the operational audit trail.

    Distinct from ``LogOut``: that is plate traffic at a barrier, this is what
    the machine did to itself. Sharing a model would mean sharing a table.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "id": 12,
                    "ts": "2026-08-27T03:00:04+00:00",
                    "source": "ota",
                    "level": "warning",
                    "message": "2 yeni sürüm bulundu (e46933f). Otomatik güncelleme başlatılıyor.",
                    "detail": None,
                }
            ]
        }
    )

    id: int = Field(examples=[12])
    ts: str = Field(examples=["2026-08-27T03:00:04+00:00"])
    source: str = Field(examples=["ota"])
    level: Literal["info", "warning", "error"] = Field(examples=["warning"])
    message: str = Field(examples=["Gecelik denetim: sistem güncel."])
    detail: str | None = Field(default=None)


class PlateImportOut(BaseModel):
    """Result of ``POST /api/plates/import``, counted per row.

    Rows are processed independently: one bad plate in a 400-row resident list
    does not reject the other 399. The counts are what the operator needs to
    decide whether to re-upload, and ``errors`` names the rows to fix by their
    line number in the original file.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "added": 12,
                    "updated": 3,
                    "skipped": 1,
                    "invalid": 1,
                    "total": 17,
                    "errors": ["Satır 9: plaka okunamadı."],
                }
            ]
        }
    )

    added: int = Field(default=0, examples=[12])
    updated: int = Field(default=0, examples=[3])
    #: Already present, and the request asked not to overwrite.
    skipped: int = Field(default=0, examples=[1])
    invalid: int = Field(default=0, examples=[1])
    total: int = Field(default=0, examples=[17])
    #: Capped at 50 entries so a wholly broken file cannot produce a response
    #: larger than the upload.
    errors: list[str] = Field(default_factory=list)


class UserCreateIn(BaseModel):
    """Body of ``POST /api/users`` -- an admin creating an account."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "username": "bekci",
                    "password": "en-az-8-karakter",
                    "role": "operator",
                    "token_ttl_min": 480,
                }
            ]
        },
    )

    username: str = Field(min_length=3, max_length=40, examples=["bekci"])
    password: str = Field(min_length=8, max_length=128)
    role: Literal["admin", "operator"] = Field(default="operator")
    #: Session length for this account, in minutes. ``None`` inherits the
    #: policy for the role (365 days for an admin, one 8-hour shift for an
    #: operator), which is what makes the policy retunable centrally.
    token_ttl_min: int | None = Field(default=None, ge=1, le=1_051_200)

    @field_validator("username", mode="before")
    @classmethod
    def _clean_username(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip()
        return value


class UserLicenseIn(BaseModel):
    """Body of ``POST /api/users/{username}/license`` -- generate a key."""

    model_config = ConfigDict(
        extra="forbid", json_schema_extra={"examples": [{"days": 90}]}
    )

    #: Validity in days. **Required**, deliberately: this used to default to
    #: 365, so a caller that omitted the field -- or sent a typo'd one, since
    #: unknown keys are forbidden but a missing one was not -- was silently
    #: handed a one-year licence instead of an error. The span a licence grants
    #: is not something to guess at on the operator's behalf.
    #:
    #: The dashboard offers 30 / 90 / 365 and a free field, and confirms the
    #: number per user before it posts.
    days: int = Field(ge=1, le=3650, examples=[90])


class LicenseKeyIn(BaseModel):
    """Body of ``POST /api/license/activate`` -- an operator entering their key."""

    model_config = ConfigDict(
        extra="forbid", json_schema_extra={"examples": [{"key": "eyJhbGciOiJIUzI1NiJ9..."}]}
    )

    key: str = Field(min_length=16, max_length=4096)

    @field_validator("key", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        if isinstance(value, str):
            # Pasted keys pick up wrapping whitespace from every mail client.
            return "".join(value.split())
        return value


class UserLicenseOut(BaseModel):
    """One account's licence state, as the badge and the gate both read it."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "status": "active",
                    "username": "bekci",
                    "expires_at": "2026-11-25T00:00:00+00:00",
                    "days_remaining": 89.4,
                    "valid": True,
                    "unlimited": False,
                    "detail": "Lisans geçerli",
                }
            ]
        }
    )

    status: Literal[
        "active", "expired", "pending_activation", "revoked", "unlimited"
    ] = "pending_activation"
    username: str | None = None
    #: Set at activation, not at generation. ``None`` until the operator enters
    #: their key -- which is what ``pending_activation`` means.
    expires_at: str | None = None
    days_remaining: float | None = None
    valid: bool = False
    #: True for administrators, who hold no key by design.
    unlimited: bool = False
    detail: str = ""
    #: When the operator entered the key that started the countdown.
    activated_at: str | None = None
    #: The span the key granted, in days.
    duration_days: int | None = None
    #: Returned only by the generation endpoint, so an admin can hand it to the
    #: operator. Shown once and never stored: the account is untouched until
    #: the operator activates it, so there is nothing to read back.
    key: str | None = None


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
