"""Composition root for the pipeline.

This is the **only** module allowed to import :mod:`lpr.detect` and
:mod:`lpr.ocr`, and it does so *inside* :func:`build_pipeline` rather than at
module scope. Two consequences, both deliberate:

* ``import lpr.pipeline`` stays cheap and dependency-free, so unit tests can
  construct a :class:`~lpr.pipeline.orchestrator.PipelineOrchestrator` with
  fake detector/recognizer/voter/relay objects on a machine with no torch,
  no ultralytics and no easyocr installed.
* The multi-second torch import only happens when somebody actually asks for
  a real pipeline.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from lpr.hardware.relay import build_relay
from lpr.pipeline.orchestrator import PipelineOrchestrator

if TYPE_CHECKING:  # pragma: no cover
    from lpr.config import Settings

logger = logging.getLogger(__name__)

#: pip extra to suggest when the ML stack cannot be imported.
_ML_HINT = (
    "the machine-learning dependencies are missing or broken. Install them with: "
    "pip install -r requirements.txt   (ultralytics, torch, torchvision, easyocr)"
)


def build_pipeline(settings: Settings | None = None) -> PipelineOrchestrator:
    """Wire the real detector, recognizer, voter and relay into a pipeline.

    Raises
    ------
    RuntimeError
        If the ML stack cannot be imported or a component fails to build.
        The message names the extra to install; the original exception is
        chained so the real ImportError is still visible in the traceback.
    """
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()

    # Imported here, never at module scope -- see the module docstring.
    try:
        from lpr.detect import build_detector
        from lpr.ocr import build_recognizer, build_voter
    except ImportError as exc:
        logger.error("Cannot build the pipeline: %s (%s)", _ML_HINT, exc)
        raise RuntimeError(f"Cannot build the LPR pipeline: {_ML_HINT}") from exc

    try:
        detector = build_detector(settings)
        recognizer = build_recognizer(settings)
        voter = build_voter(settings)
    except ImportError as exc:
        # A lazy import inside the ML packages themselves (torch is often
        # only pulled in when the model is first constructed).
        logger.error("Cannot build the pipeline: %s (%s)", _ML_HINT, exc)
        raise RuntimeError(f"Cannot build the LPR pipeline: {_ML_HINT}") from exc
    except Exception as exc:
        logger.error("Cannot build the pipeline components: %s", exc)
        raise RuntimeError(f"Cannot build the LPR pipeline: {exc}") from exc

    # build_relay never raises: a missing barrier degrades to MockRelay so
    # recognition still runs.
    relay = build_relay(settings)

    logger.info(
        "Pipeline built (detector=%s, recognizer=%s, voter=%s, relay=%s)",
        type(detector).__name__,
        type(recognizer).__name__,
        type(voter).__name__,
        type(relay).__name__,
    )
    return PipelineOrchestrator(
        settings=settings,
        detector=detector,
        recognizer=recognizer,
        voter=voter,
        relay=relay,
    )
