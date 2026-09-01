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
from lpr.model_assets import ensure_detection_weights, ensure_runtime_dirs
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

    Runtime directories are created and the detection weights are checked (and,
    when missing and reachable, the baseline is fetched) before any of the ML
    stack is imported -- see :mod:`lpr.model_assets`. Neither step can fail the
    build: a missing model degrades detection, it does not stop the service.

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

    # Provisioning, before the expensive imports and before anything tries to
    # write. A fresh clone has no data/, no models/ and no weights; creating
    # the first two and reporting on the third here means the failure is one
    # named line at the top of the log rather than an OSError from whichever
    # component happened to write first.
    ensure_runtime_dirs(settings)
    assets = ensure_detection_weights(settings)
    if assets.ready:
        logger.info("%s", assets.detail)
    else:
        logger.warning("%s", assets.detail)
        for note in assets.notes:
            logger.warning("%s", note)

    # Imported here, never at module scope -- see the module docstring.
    try:
        from lpr.detect import build_detector, build_frame_preprocessor
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

    # None unless preprocess.frame_enhance is on. This is the one place that
    # may hand the orchestrator something from lpr.detect, which is how the
    # orchestrator gets whole-frame enhancement without importing cv2 itself.
    frame_preprocessor = build_frame_preprocessor(settings)

    # Never raises: a misconfigured mail server yields a disabled notifier and
    # a warning, not a pipeline that refuses to start.
    from lpr.notify import build_notifier

    notifier = build_notifier(settings)

    logger.info(
        "Pipeline built (detector=%s, recognizer=%s, voter=%s, relay=%s, "
        "frame_enhance=%s, email=%s, models_ready=%s)",
        type(detector).__name__,
        type(recognizer).__name__,
        type(voter).__name__,
        type(relay).__name__,
        frame_preprocessor is not None,
        notifier.enabled,
        assets.ready,
    )
    return PipelineOrchestrator(
        settings=settings,
        detector=detector,
        recognizer=recognizer,
        voter=voter,
        relay=relay,
        frame_preprocessor=frame_preprocessor,
        notifier=notifier,
    )
