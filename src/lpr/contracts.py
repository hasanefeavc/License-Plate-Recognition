"""Shared data contracts and protocols.

Every module in the package codes against this file. Nothing here imports from
sibling packages, so it stays free of circular-import problems and can be
imported by detectors, recognizers, the pipeline, the API and the UI alike.

Heavy third-party types (numpy arrays, torch tensors) are intentionally kept
behind ``TYPE_CHECKING`` so that importing contracts stays cheap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    import numpy as np

    Frame = np.ndarray
else:
    Frame = Any


def utc_now_iso() -> str:
    """Timestamp format used everywhere: ISO-8601, UTC, second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class CameraRole(StrEnum):
    ENTRY = "entry"
    EXIT = "exit"


class Action(StrEnum):
    """What the pipeline decided to do about a plate read."""

    DETECTED = "detected"
    GRANTED = "granted"
    DENIED = "denied"
    COOLDOWN = "cooldown"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class PlateDetection:
    """One plate-shaped region located in a frame."""

    bbox: tuple[int, int, int, int]  # x1, y1, x2, y2 in source-frame pixels
    confidence: float
    crop: Frame  # BGR uint8 crop of the plate region
    #: Multi-object-tracker identity of the physical plate this box belongs to,
    #: stable across frames for as long as the tracker keeps hold of it.
    #: ``None`` means "untracked" -- a detector without tracking, or a box the
    #: tracker has not associated yet -- and every consumer must still work in
    #: that case (see ``TrackAwareVoter``).
    track_id: int | None = None


@dataclass(frozen=True, slots=True)
class PlateRead:
    """Result of recognising (and normalising) a single plate crop."""

    text: str  # normalised, uppercase, no whitespace, e.g. "34ABC123"
    confidence: float  # 0.0 - 1.0
    raw_text: str  # recogniser output before normalisation
    valid: bool  # matches the Turkish plate grammar

    @property
    def is_usable(self) -> bool:
        return self.valid and bool(self.text)


@dataclass(frozen=True, slots=True)
class LprEvent:
    """A single row in the ``logs`` table and one WebSocket message."""

    ts: str  # ISO-8601 UTC, see utc_now_iso()
    camera: str  # CameraRole value
    plate: str
    action: str  # Action value
    confidence: float = 0.0
    id: int | None = None  # set by the database on read-back

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "camera": self.camera,
            "plate": self.plate,
            "action": self.action,
            "confidence": round(self.confidence, 4),
        }


@dataclass(slots=True)
class CameraStatus:
    """Health of one capture worker, polled by the API and the GUI."""

    role: str
    source: str
    connected: bool = False
    fps: float = 0.0
    frames_read: int = 0
    frames_dropped: int = 0
    #: Frames captured but never queued for inference because nothing moved.
    #: High relative to frames_read is the motion gate working as intended.
    motion_skipped: int = 0
    last_error: str | None = None
    last_frame_ts: float = 0.0


@dataclass(slots=True)
class PipelineStats:
    started_at: float = 0.0
    plates_read: int = 0
    grants: int = 0
    denials: int = 0
    #: OCR passes skipped because the plate's track had already been decided.
    #: The headline number for "how much did tracking save us".
    ocr_skipped: int = 0
    cameras: dict[str, CameraStatus] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Protocols: the pipeline depends on these, never on concrete ML classes.
# ---------------------------------------------------------------------------


@runtime_checkable
class Detector(Protocol):
    """Locates plate regions in a full frame."""

    def detect(self, frame: Frame) -> list[PlateDetection]: ...

    def warmup(self) -> None: ...


@runtime_checkable
class TrackingDetector(Protocol):
    """A :class:`Detector` that also keeps identities across frames.

    Optional capability, discovered with ``isinstance(detector,
    TrackingDetector)``. ``stream_id`` isolates the tracker state of one video
    source from another's, so a single detector instance can serve the entry
    and exit cameras without their track ids colliding.
    """

    def detect_tracked(self, frame: Frame, stream_id: str) -> list[PlateDetection]: ...


@runtime_checkable
class Recognizer(Protocol):
    """Turns a plate crop into normalised text."""

    def recognize(self, crop: Frame) -> PlateRead: ...

    def warmup(self) -> None: ...


@runtime_checkable
class Voter(Protocol):
    """Buffers repeated reads and only emits a plate once it is confirmed."""

    def submit(self, camera: str, read: PlateRead) -> str | None: ...

    def reset(self, camera: str) -> None: ...


@runtime_checkable
class TrackAwareVoter(Protocol):
    """A :class:`Voter` that can also gate OCR per tracked object.

    Optional capability, discovered with ``isinstance(voter, TrackAwareVoter)``.
    A voter that does not implement it keeps receiving plain two-argument
    ``submit`` calls and the pipeline runs OCR on every detection, exactly as
    it did before tracking existed.

    ``track_id`` is always allowed to be ``None`` (untracked detection); the
    implementation must then fall back to text-based behaviour.
    """

    def submit(
        self, camera: str, read: PlateRead, track_id: int | None = None
    ) -> str | None: ...

    def should_recognize(self, camera: str, track_id: int | None) -> bool: ...

    def note_recognized(self, camera: str, track_id: int | None) -> None: ...

    def note_decision(self, camera: str, track_id: int | None, plate: str) -> None: ...


@runtime_checkable
class Relay(Protocol):
    """Gate hardware. Implementations must never block the caller."""

    def trigger(self) -> None: ...

    def close(self) -> None: ...

    @property
    def available(self) -> bool: ...
