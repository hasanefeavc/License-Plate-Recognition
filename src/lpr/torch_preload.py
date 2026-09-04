"""Load torch into the process before paddle can, on Windows.

A single function, called from the two places that are about to pull in the
machine-learning stack, for one reason: on Windows the order in which torch and
paddlepaddle enter the process decides whether torch loads at all.

The failure it prevents
-----------------------
On a fresh Windows 11 install, ``import torch`` works perfectly on its own, but
the pipeline died at start-up with::

    OSError: [WinError 127] The specified procedure could not be found.
    Error loading "...\\torch\\lib\\shm.dll" or one of its dependencies.

paddlepaddle loads its own OpenMP/MKL runtime (``libiomp5md.dll``) into the
process the moment ``paddleocr`` is imported. When paddleocr then reaches
``albumentations.pytorch`` and that imports torch, ``torch/lib/shm.dll`` binds
against the OpenMP and C-runtime symbols paddle has already claimed, finds the
wrong ones, and fails to link. Windows resolves DLL dependencies per process in
load order, so whichever runtime arrives first wins -- and torch is the one that
cannot survive losing.

Importing torch first makes its runtime the resident one; paddle then loads
alongside it without complaint. This is the documented mitigation for the
OpenMP-collision family of errors and it is what was verified on the clean
``LPR-Clean-Test`` box.

Why a function and not ``import torch`` at module scope
-------------------------------------------------------
Both call sites -- :mod:`lpr.pipeline.factory` and :mod:`lpr.ocr.recognizer` --
promise in their module docstrings that importing them costs nothing and needs
no torch installed, which is what lets the test suite build a pipeline out of
fakes on a machine with no ML stack at all. A top-level ``import torch`` in
either module would break that for every caller in order to help the one that
is about to load paddle anyway.

Calling this at the top of the code paths that build the ML stack gives the
identical guarantee -- torch is resident before anything paddle-shaped is
imported -- without making a torch install a condition of importing the
package. It never raises: a machine with no torch, or a broken torch, is a
supported configuration here (the caller degrades or reports it), and this
function's only job is ordering.
"""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)


def preload_torch() -> bool:
    """Import torch now, so it is resident before paddle loads.

    Returns ``True`` when torch is in :data:`sys.modules` afterwards. Never
    raises -- see the module docstring for why a missing torch is not this
    function's problem to report.
    """
    if "torch" in sys.modules:
        return True

    try:
        import torch  # noqa: F401  -- imported for its DLL side effects, not its API
    except Exception:
        # No torch, a half-installed wheel, or torch itself failing to load.
        # All three are the caller's to diagnose; ordering is moot either way.
        logger.debug("torch could not be pre-imported", exc_info=True)
        return False

    logger.debug("torch pre-imported ahead of the paddle runtime")
    return True
