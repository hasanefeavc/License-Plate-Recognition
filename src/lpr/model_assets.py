"""Where the model weights are, whether they are there, and how to get them.

A fresh clone has an empty ``models/``: every ``.pt`` is gitignored, because
weights are tens of megabytes and do not belong in git history. That is the
right call for the repository and a bad first five minutes for whoever cloned
it -- the pipeline builds, the detector finds nothing to load, and the only
evidence is a warning several hundred lines into the startup log.

This module is the single place that answers "what is missing?" without
importing torch, ultralytics or easyocr. Two callers depend on that:

* :func:`lpr.pipeline.factory.build_pipeline`, which reports the answer before
  it spends thirty seconds importing the ML stack, and
* ``GET /api/system/assets``, which has to answer on a box where the ML stack
  is not installed at all -- exactly the box where somebody is asking.

Nothing here ever raises for a missing file. A missing model is a state to
report, not an exception to propagate: the service is expected to start,
serve, and say what it needs.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lpr.config import Settings

logger = logging.getLogger(__name__)

__all__ = [
    "BASELINE_NAME",
    "BASELINE_SHA256",
    "DOWNLOAD_URL",
    "EASYOCR_WEIGHTS",
    "ModelAssets",
    "describe_assets",
    "download",
    "ensure_detection_weights",
    "is_stock_baseline",
    "sha256_of",
]

#: The generic COCO-trained YOLOv8 nano weights. **Not** a plate detector --
#: see :func:`ensure_detection_weights` for why it is fetched anyway.
BASELINE_NAME = "yolov8n.pt"

#: What ``detection.model_path`` defaults to: the plate fine-tune.
PLATE_MODEL_NAME = "plate_yolov8n.pt"

#: Same release Ultralytics itself pulls weights from when auto-downloading.
DOWNLOAD_URL = f"https://github.com/ultralytics/assets/releases/download/v8.3.0/{BASELINE_NAME}"

#: SHA-256 of the official v8.3.0 ``yolov8n.pt``. A ``.pt`` is a pickle:
#: ``torch.load`` executes what is inside it, so an unverified download from a
#: redirected or poisoned mirror is arbitrary code on the gate box. Checked on
#: every download; a mismatch discards the file rather than leaving something
#: plausible-looking on disk.
BASELINE_SHA256 = "f59b3d833e2ff32e194b5bb8e08d211dc7c5bdf144b90d2c8412c47ccfc83b36"

#: Weight files a default ``easyocr.Reader(["en"])`` needs on disk. Used only
#: to report what the cache is missing; EasyOCR decides what to download.
EASYOCR_WEIGHTS = ("craft_mlt_25k.pth", "english_g2.pth")

#: Directories that must exist before anything writes into them. Resolving the
#: matching ``settings.paths`` attribute creates each one, which is why this is
#: a list of attribute names rather than of paths.
RUNTIME_PATH_ATTRS = ("data_dir", "models_dir", "snapshots_dir", "ocr_models_dir")


# ---------------------------------------------------------------------------
# Hashing / download primitives
# ---------------------------------------------------------------------------


def sha256_of(path: Path) -> str:
    """Hex digest of a file, read in chunks so a 100 MB weight file is cheap."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 256), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(
    url: str,
    dest: Path,
    timeout: float = 30.0,
    expected_sha256: str | None = None,
) -> None:
    """Fetch ``url`` to ``dest``, verifying the digest before it lands.

    The download goes to a ``.part`` file and is renamed into place only after
    the hash matches, so an interrupted or tampered fetch can never leave
    behind something the loader would happily execute.

    Raises on any failure -- callers that must survive being offline catch it.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_dest = dest.with_suffix(dest.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "lpr-model-assets/1"})
    try:
        with (
            urllib.request.urlopen(request, timeout=timeout) as response,
            tmp_dest.open("wb") as out,
        ):
            shutil.copyfileobj(response, out, length=1024 * 256)

        if expected_sha256:
            actual = sha256_of(tmp_dest)
            if actual != expected_sha256:
                raise RuntimeError(
                    f"checksum mismatch for {url}\n"
                    f"  expected {expected_sha256}\n"
                    f"  got      {actual}\n"
                    "The download was discarded. This is either a corrupted transfer "
                    "or a substituted file; a .pt is executed by torch.load, so it is "
                    "not being kept either way."
                )
        tmp_dest.replace(dest)
    finally:
        tmp_dest.unlink(missing_ok=True)


def is_stock_baseline(path: Path) -> bool:
    """True when ``path`` is the stock COCO baseline wearing another name.

    Hash comparison rather than class-name inspection, so it answers without
    importing torch -- this has to work on a box that has not installed the ML
    wheels yet, which is exactly when somebody asks.
    """
    try:
        return path.is_file() and sha256_of(path) == BASELINE_SHA256
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelAssets:
    """What the configured model files are, and which of them exist.

    ``ready`` means detection can run at full strength. It is deliberately
    False for a *present* file that is the stock COCO baseline renamed: those
    weights load, detect people and chairs, and are rejected by
    :func:`lpr.detect.build_detector` in favour of contour detection. Reporting
    that as "model installed" is how the state survived undiagnosed once
    already.
    """

    #: ``detection.model_path`` as configured, verbatim.
    configured_path: str
    #: Where that resolves to on this machine.
    detection_weights: Path
    detection_present: bool
    #: The configured weights exist but are the stock COCO model.
    detection_is_stock_baseline: bool
    baseline_weights: Path
    baseline_present: bool
    ocr_backend: str
    ocr_models_dir: Path
    #: EasyOCR networks not yet cached. Empty for a non-EasyOCR backend.
    ocr_missing: tuple[str, ...] = ()
    #: Human-readable names of everything absent, for logs and the API.
    missing: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ready(self) -> bool:
        """True when detection and OCR can both run as configured."""
        return (
            self.detection_present and not self.detection_is_stock_baseline and not self.ocr_missing
        )

    @property
    def detail(self) -> str:
        """One sentence naming the exact state, for a log line or an API body."""
        if self.ready:
            return f"Model dosyaları hazır ({self.detection_weights.name})."
        return "Eksik model dosyaları: " + ", ".join(self.missing)

    def to_dict(self) -> dict[str, object]:
        """JSON-safe form, as the API returns it."""
        return {
            "ready": self.ready,
            "detail": self.detail,
            "configured_path": self.configured_path,
            "detection_weights": str(self.detection_weights),
            "detection_present": self.detection_present,
            "detection_is_stock_baseline": self.detection_is_stock_baseline,
            "baseline_weights": str(self.baseline_weights),
            "baseline_present": self.baseline_present,
            "ocr_backend": self.ocr_backend,
            "ocr_models_dir": str(self.ocr_models_dir),
            "ocr_missing": list(self.ocr_missing),
            "missing": list(self.missing),
            "notes": list(self.notes),
        }


def resolve_detection_weights(settings: Settings) -> Path:
    """Absolute path to the configured detection weights.

    Mirrors :meth:`lpr.detect.yolo.YoloPlateDetector._resolve_weights` exactly
    -- a relative path lives under ``models_dir``, and a leading ``models/``
    segment is not doubled -- but without importing anything that pulls torch.
    A status endpoint that reported a different path from the one the loader
    opens would be worse than no endpoint.
    """
    configured = str(settings.detection.model_path or "").strip() or PLATE_MODEL_NAME
    raw = Path(configured).expanduser()
    if raw.is_absolute():
        return raw
    models_dir = settings.paths.models_dir
    if raw.parts and raw.parts[0] == models_dir.name:
        raw = Path(*raw.parts[1:]) if len(raw.parts) > 1 else raw
    return (models_dir / raw).resolve()


def describe_assets(settings: Settings | None = None) -> ModelAssets:
    """Inspect the filesystem and report what is present. Never raises."""
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()

    weights = resolve_detection_weights(settings)
    models_dir = settings.paths.models_dir
    baseline = models_dir / BASELINE_NAME

    present = weights.is_file()
    stock = is_stock_baseline(weights) if present else False

    backend = str(getattr(settings.ocr, "backend", "") or "").strip().lower()
    ocr_dir = settings.paths.ocr_models_dir
    ocr_missing: tuple[str, ...] = ()
    if backend == "easyocr":
        ocr_missing = tuple(name for name in EASYOCR_WEIGHTS if not (ocr_dir / name).is_file())

    missing: list[str] = []
    notes: list[str] = []
    if not present:
        missing.append(f"tespit modeli ({weights})")
        notes.append(
            "Detection weights are missing. The pipeline still starts, on the much "
            "weaker contour detector. Install a plate fine-tune at "
            f"{weights}, or train one with scripts/train_plate_detector.py."
        )
    elif stock:
        missing.append(f"gerçek plaka modeli ({weights} stok COCO modeli)")
        notes.append(
            f"{weights} is byte-for-byte the stock COCO {BASELINE_NAME}, not a plate "
            "detector. Its 80 classes contain no licence plate, so the pipeline "
            "rejects it and falls back to contour detection."
        )
    if ocr_missing:
        missing.append(f"EasyOCR ağırlıkları ({', '.join(ocr_missing)})")
        notes.append(
            f"EasyOCR will download {', '.join(ocr_missing)} into {ocr_dir} on first "
            "use, which needs about 100 MB and an internet connection. Pre-fetch "
            "them with `python scripts/fetch_models.py --easyocr`."
        )

    return ModelAssets(
        configured_path=str(settings.detection.model_path or ""),
        detection_weights=weights,
        detection_present=present,
        detection_is_stock_baseline=stock,
        baseline_weights=baseline,
        baseline_present=baseline.is_file(),
        ocr_backend=backend,
        ocr_models_dir=ocr_dir,
        ocr_missing=ocr_missing,
        missing=tuple(missing),
        notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------


def ensure_detection_weights(
    settings: Settings | None = None,
    *,
    allow_download: bool = True,
    timeout: float = 30.0,
) -> ModelAssets:
    """Make sure *something* is on disk for the detector, and report the result.

    When the configured plate weights are missing, the generic COCO baseline is
    fetched into ``models/yolov8n.pt`` -- if a download is allowed and the
    network answers. Two things it deliberately does **not** do:

    * **It never installs the baseline as the plate model.** Copying
      ``yolov8n.pt`` over ``plate_yolov8n.pt`` would make every check on this
      page pass while the gate read no plates at all, which is the failure this
      module exists to make visible. The baseline is scaffolding: it proves the
      ML stack loads and gives ``scripts/export_onnx.py`` and the training
      script something to start from.
    * **It never fails.** Offline is the normal state of a gate box. A download
      that cannot happen is recorded in the returned status and logged once;
      the pipeline goes on to build on the contour detector, which is what the
      degraded-mode contract in :mod:`lpr.api.main` promises.

    Set ``allow_download=False`` for a site that must never reach the network.
    """
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()

    assets = describe_assets(settings)
    if assets.detection_present or not allow_download or assets.baseline_present:
        return assets

    destination = assets.baseline_weights
    logger.info(
        "Detection weights not found at %s; fetching the %s baseline into %s",
        assets.detection_weights,
        BASELINE_NAME,
        destination,
    )
    try:
        download(DOWNLOAD_URL, destination, timeout=timeout, expected_sha256=BASELINE_SHA256)
    except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as exc:
        logger.warning(
            "Could not fetch the %s baseline (%s). This is expected on an offline "
            "site; detection will run on the contour fallback until a plate model "
            "is installed at %s.",
            BASELINE_NAME,
            exc,
            assets.detection_weights,
        )
        return describe_assets(settings)

    logger.info("Baseline weights saved to %s", destination)
    return describe_assets(settings)


def ensure_runtime_dirs(settings: Settings | None = None) -> list[Path]:
    """Create every directory the service writes into. Returns them.

    Each ``settings.paths`` attribute mkdirs on access, so this is really a
    list of which ones to touch -- named here so provisioning is one call
    rather than four incidental property reads scattered across start-up.
    """
    if settings is None:
        from lpr.config import get_settings

        settings = get_settings()

    created: list[Path] = []
    for attr in RUNTIME_PATH_ATTRS:
        try:
            created.append(getattr(settings.paths, attr))
        except OSError as exc:  # pragma: no cover - read-only filesystem
            logger.warning("Could not create the %s directory: %s", attr, exc)
    return created
