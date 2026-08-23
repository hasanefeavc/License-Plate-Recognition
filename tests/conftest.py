"""Shared pytest fixtures.

Everything here is designed so the test suite runs on a machine with no
camera, no serial port, no GPU and no ML stack:

* ``tmp_settings`` points the whole application at a throwaway SQLite file in
  ``tmp_path`` and clears the ``lru_cache`` behind ``get_settings``.
* ``db`` gives you that database with the schema already applied.
* ``fake_detector`` / ``fake_recognizer`` / ``fake_voter`` / ``fake_relay``
  implement the Protocols from ``lpr.contracts`` with canned output.
* ``frame`` is a synthetic numpy image, so nothing needs a real capture
  device.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on how pytest is invoked
    sys.path.insert(0, str(SRC))

from lpr.contracts import (  # noqa: E402
    Action,
    CameraRole,
    LprEvent,
    PlateDetection,
    PlateRead,
    utc_now_iso,
)

#: Every module that binds ``get_settings`` at import time and therefore has
#: to be repointed when the fixture swaps the settings object.
_SETTINGS_CONSUMERS = (
    "lpr.config",
    "lpr.db.connection",
    "lpr.hardware.relay",
    "lpr.pipeline.factory",
    "lpr.pipeline.orchestrator",
    "lpr.api.deps",
    "lpr.api.main",
)


# ---------------------------------------------------------------------------
# Settings / database
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """A ``Settings`` object backed entirely by ``tmp_path``.

    Patches ``get_settings`` everywhere it has been imported so no test ever
    touches the developer's real ``data/plates.db``.
    """
    import lpr.db.connection as connection
    from lpr.config import (
        AppConfig,
        CameraConfig,
        CamerasConfig,
        DatabaseConfig,
        RelayConfig,
        Settings,
        get_settings,
    )

    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    settings = Settings(
        app=AppConfig(data_dir=str(data_dir), models_dir=str(tmp_path / "models")),
        database=DatabaseConfig(path=str(data_dir / "test.db"), log_retention_days=10),
        cameras=CamerasConfig(
            entry=CameraConfig(source="0", queue_size=2, fps_limit=0),
            exit=CameraConfig(source="1", queue_size=2, fps_limit=0),
        ),
        relay=RelayConfig(enabled=False, mock=True, pulse_ms=50),
    )

    get_settings.cache_clear()
    for module_name in _SETTINGS_CONSUMERS:
        module = sys.modules.get(module_name)
        if module is not None and hasattr(module, "get_settings"):
            monkeypatch.setattr(module, "get_settings", lambda: settings, raising=False)

    # Anything imported *after* this point picks the patched value up too.
    import lpr.config as config_module

    monkeypatch.setattr(config_module, "get_settings", lambda: settings, raising=False)

    connection.shutdown()
    try:
        yield settings
    finally:
        connection.shutdown()
        get_settings.cache_clear()


@pytest.fixture
def db(tmp_settings: Any) -> Iterator[Any]:
    """An initialised, empty database for the duration of one test."""
    from lpr.db import init_db

    init_db()
    yield tmp_settings


# ---------------------------------------------------------------------------
# Synthetic frames
# ---------------------------------------------------------------------------


@pytest.fixture
def frame() -> Any:
    """A blank 720p BGR frame - stands in for a real camera image."""
    import numpy as np

    return np.zeros((720, 1280, 3), dtype=np.uint8)


@pytest.fixture
def crop() -> Any:
    """A blank plate-sized BGR crop."""
    import numpy as np

    return np.zeros((40, 160, 3), dtype=np.uint8)


# ---------------------------------------------------------------------------
# Protocol fakes
# ---------------------------------------------------------------------------


class FakeDetector:
    """Returns one canned detection per frame and counts its calls.

    ``calls`` is what ``test_pipeline`` asserts on to prove
    ``detection.frame_stride`` is honoured.
    """

    def __init__(self, detections: list[PlateDetection] | None = None) -> None:
        self._detections = detections
        self.calls = 0
        self.warmed_up = False

    def detect(self, frame: Any) -> list[PlateDetection]:
        self.calls += 1
        if self._detections is not None:
            return list(self._detections)
        crop = frame[0:40, 0:160] if getattr(frame, "shape", None) else frame
        return [PlateDetection(bbox=(0, 0, 160, 40), confidence=0.9, crop=crop)]

    def warmup(self) -> None:
        self.warmed_up = True


class FakeTrackingDetector(FakeDetector):
    """A ``TrackingDetector``: every detection carries a track id.

    ``streams`` records the ``stream_id`` of each call, which is what proves
    the two cameras are kept on separate tracker states.
    """

    def __init__(
        self, track_ids: list[int | None] | None = None, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self._track_ids = list(track_ids) if track_ids else [1]
        self.streams: list[str] = []

    def detect_tracked(
        self, frame: Any, stream_id: str = "default"
    ) -> list[PlateDetection]:
        self.streams.append(stream_id)
        track_id = self._track_ids[min(self.calls, len(self._track_ids) - 1)]
        return [
            PlateDetection(
                bbox=d.bbox, confidence=d.confidence, crop=d.crop, track_id=track_id
            )
            for d in self.detect(frame)
        ]


class FakeRecognizer:
    """Emits a fixed :class:`PlateRead`, or cycles through a scripted list."""

    def __init__(
        self,
        text: str = "34ABC123",
        confidence: float = 0.95,
        valid: bool = True,
        reads: list[PlateRead] | None = None,
    ) -> None:
        self._read = PlateRead(
            text=text, confidence=confidence, raw_text=text, valid=valid
        )
        self._reads = list(reads) if reads else None
        self.calls = 0
        self.warmed_up = False

    def recognize(self, crop: Any) -> PlateRead:
        self.calls += 1
        if self._reads:
            return self._reads[(self.calls - 1) % len(self._reads)]
        return self._read

    def warmup(self) -> None:
        self.warmed_up = True


class FakeVoter:
    """Confirms every read immediately (or never, with ``confirm=False``)."""

    def __init__(self, confirm: bool = True) -> None:
        self.confirm = confirm
        self.submissions: list[tuple[str, PlateRead]] = []
        self.resets: list[str] = []

    def submit(self, camera: str, read: PlateRead) -> str | None:
        self.submissions.append((camera, read))
        return read.text if self.confirm else None

    def reset(self, camera: str) -> None:
        self.resets.append(camera)


class FakeRelay:
    """Records triggers instead of driving hardware. Always non-blocking."""

    def __init__(self) -> None:
        self.triggers = 0
        self.closed = False

    def trigger(self) -> None:
        self.triggers += 1

    def close(self) -> None:
        self.closed = True

    @property
    def available(self) -> bool:
        return not self.closed


@pytest.fixture
def fake_detector() -> FakeDetector:
    return FakeDetector()


@pytest.fixture
def fake_recognizer() -> FakeRecognizer:
    return FakeRecognizer()


@pytest.fixture
def fake_voter() -> FakeVoter:
    return FakeVoter()


@pytest.fixture
def fake_relay() -> FakeRelay:
    return FakeRelay()


@pytest.fixture
def sample_event() -> LprEvent:
    return LprEvent(
        ts=utc_now_iso(),
        camera=str(CameraRole.ENTRY),
        plate="34ABC123",
        action=str(Action.GRANTED),
        confidence=0.91,
    )
