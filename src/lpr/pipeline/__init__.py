"""Capture and recognition pipeline.

    from lpr.pipeline import build_pipeline

    pipeline = build_pipeline()
    pipeline.start()
    events = pipeline.subscribe()      # bounded queue of LprEvent
    ...
    pipeline.stop()

Importing this package is cheap: it pulls in neither OpenCV nor the ML
stack. ``build_pipeline`` imports those lazily, so tests can build an
orchestrator from fakes without them.
"""

from __future__ import annotations

from lpr.pipeline.camera import CameraWorker
from lpr.pipeline.factory import build_pipeline
from lpr.pipeline.orchestrator import (
    RETENTION_INTERVAL_S,
    SUBSCRIBER_QUEUE_SIZE,
    PipelineOrchestrator,
)

__all__ = [
    "RETENTION_INTERVAL_S",
    "SUBSCRIBER_QUEUE_SIZE",
    "CameraWorker",
    "PipelineOrchestrator",
    "build_pipeline",
]
