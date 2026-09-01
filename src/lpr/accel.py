"""Hardware-acceleration probing, shared by the detector and the recogniser.

Both halves of the ML stack need the same answer to "is there a usable GPU
here?", and they must not disagree: a detector on CUDA feeding a recogniser on
CPU is the worst of both worlds, and the reverse cannot happen at all because
EasyOCR would fail to allocate. Putting the probe in one module also means it
runs **once** per process -- ``torch.cuda.is_available()`` builds a CUDA
context on first call, which costs a second or two and is not something to pay
again for every component that asks.

The probe is deliberately stronger than ``torch.cuda.is_available()``. That
call only checks that a driver and a device are visible; it still returns True
on the two configurations that break this service at the gate:

* a CPU-only torch wheel that nonetheless sees the driver (rare, but the
  container image shipped exactly this for a long time -- see
  ``docker/Dockerfile``'s ``TORCH_INDEX_URL``), and
* a driver too old for the CUDA runtime the wheel was built against, which
  reports a device and then raises on the first kernel launch.

So :func:`cuda_available` allocates a one-element tensor on the device. If that
works, everything downstream will; if it raises, we log why and fall back to
CPU **at startup**, instead of taking the barrier down mid-shift with a
``CUDA error: no kernel image is available for execution on the device``.
"""

from __future__ import annotations

import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

__all__ = [
    "cuda_available",
    "describe_accelerator",
    "reset_probe",
    "resolve_gpu_flag",
    "resolve_torch_device",
]

#: Strings accepted for a boolean-ish config value, alongside real booleans.
_TRUE_WORDS = frozenset({"1", "true", "yes", "on", "y", "t"})
_FALSE_WORDS = frozenset({"0", "false", "no", "off", "n", "f", "none"})
#: Spellings that mean "work it out for me". Blank belongs here rather than
#: with the false words: an unset value means "no preference expressed", which
#: is what auto-detection is for, and it keeps ``ocr.gpu`` and
#: ``detection.device`` agreeing on what an empty string means.
_AUTO_WORDS = frozenset({"", "auto", "default"})


@lru_cache(maxsize=1)
def cuda_available() -> bool:
    """True when this process can actually *run* torch kernels on a GPU.

    Cached: the answer cannot change within a process, and the first call pays
    for CUDA context creation. Never raises -- every failure mode (no torch, a
    CPU-only wheel, no device, a driver/runtime mismatch) is logged and
    answered with ``False``, because "no GPU" is a supported configuration and
    must not be an error.
    """
    try:
        import torch
    except Exception:
        logger.info("torch is not importable; OCR and detection will run on CPU")
        return False

    try:
        if not torch.cuda.is_available() or torch.cuda.device_count() < 1:
            logger.info(
                "no CUDA device visible to torch %s (CUDA build: %s); running on CPU",
                getattr(torch, "__version__", "?"),
                getattr(getattr(torch, "version", None), "cuda", None) or "cpu-only wheel",
            )
            return False
    except Exception:
        logger.warning("the torch CUDA probe failed; running on CPU", exc_info=True)
        return False

    # is_available() is necessary but not sufficient: it answers "is a driver
    # and a device there", not "will a kernel launch". Force a real allocation.
    try:
        torch.zeros(1, device="cuda")
    except Exception as exc:
        logger.warning(
            "a CUDA device is visible but unusable (%s); falling back to CPU. This is "
            "normally a CPU-only torch wheel or a driver older than the wheel's CUDA "
            'runtime -- check `nvidia-smi` against `python -c "import torch; '
            'print(torch.version.cuda)"`.',
            exc,
        )
        return False

    logger.info("CUDA acceleration available: %s", describe_accelerator())
    return True


def describe_accelerator() -> str:
    """Human-readable name of the active GPU, for logs and ``/health``."""
    try:
        import torch

        name = torch.cuda.get_device_name(0)
        total = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        return f"{name} ({total:.1f} GiB, CUDA {torch.version.cuda})"
    except Exception:
        return "cpu"


def resolve_torch_device(spec: str | None) -> str:
    """Turn a configured ``detection.device`` into a device string torch accepts.

    ``"auto"`` (and blank) resolve to ``"cuda"`` or ``"cpu"`` by probing. An
    explicit spelling -- ``"cuda"``, ``"cuda:0"``, ``"0"`` -- is honoured when a
    GPU is genuinely usable and **downgraded to CPU with a warning when it is
    not**. That downgrade is the point: a config asking for CUDA on a CPU-only
    box used to blow up inside ultralytics at load time, and
    :func:`lpr.detect.build_detector` caught the failure and quietly handed the
    pipeline the contour detector instead. Losing GPU speed is a performance
    problem; losing the YOLO detector is an accuracy problem, and a much worse
    one.
    """
    wanted = (spec or "").strip().lower()
    if wanted in _AUTO_WORDS:
        return "cuda" if cuda_available() else "cpu"
    if wanted in {"cpu", "mps"}:
        return wanted
    if cuda_available():
        # "0" and "0,1" are ultralytics spellings for CUDA ordinals; torch's
        # own `.to()` needs the "cuda:" prefix, and both accept the long form.
        if wanted.replace(",", "").isdigit():
            return f"cuda:{wanted}"
        return wanted
    logger.warning(
        "detection.device is %r but no usable CUDA device was found; running the detector on CPU",
        spec,
    )
    return "cpu"


def resolve_gpu_flag(spec: bool | str | None) -> bool:
    """Turn a configured ``ocr.gpu`` into the boolean EasyOCR wants.

    Accepts ``True``/``False`` and the string ``"auto"`` (the default), so a
    single ``config.yaml`` can be deployed to both the GPU gate box and a
    CPU-only test runner. An explicit ``true`` on a machine with no usable GPU
    is downgraded rather than honoured -- EasyOCR would otherwise raise out of
    ``Reader.__init__`` and take the whole pipeline build down with it.
    """
    if isinstance(spec, bool):
        wanted = spec
    else:
        text = str(spec or "").strip().lower()
        if text in _AUTO_WORDS:
            return cuda_available()
        if text in _FALSE_WORDS:
            return False
        wanted = text in _TRUE_WORDS

    if not wanted:
        return False
    if cuda_available():
        return True
    logger.warning("ocr.gpu requested a GPU but none is usable; running EasyOCR on CPU")
    return False


def reset_probe() -> None:
    """Forget the cached probe result. For tests only.

    Tolerates :func:`cuda_available` having been monkeypatched with a plain
    function: a fixture that both stubs the probe and resets it around the test
    would otherwise fail in teardown depending on fixture ordering, which is a
    confusing way to learn nothing about the code under test.
    """
    clear = getattr(cuda_available, "cache_clear", None)
    if clear is not None:
        clear()
