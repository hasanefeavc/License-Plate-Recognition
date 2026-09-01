"""Plate detectors.

Two implementations of the :class:`~lpr.contracts.Detector` protocol:

:class:`YoloPlateDetector`
    The real one. A YOLOv8 fine-tune that has learned what a plate looks like,
    so it survives the cases that sink classical vision: plates at an angle, at
    night, partially occluded by a tow bar, or without a clean rectangular
    border.

:class:`ContourPlateDetector`
    The legacy Canny/contour approach, refactored to the same protocol. It is
    **materially less accurate** and exists only so a fresh checkout or a
    container without weights can still run end to end. It needs a clean,
    unoccluded, near-frontal quadrilateral and fails on anything else -- which
    is precisely why the pipeline was rebuilt around YOLO.

``ultralytics`` (and therefore torch) is imported lazily *inside*
``YoloPlateDetector.__init__``. Importing this module must stay cheap: the
test-suite and the Tkinter client both import it and neither has, or wants,
torch.
"""

from __future__ import annotations

import inspect
import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

import cv2
import numpy as np

from lpr.contracts import PlateDetection
from lpr.detect.preprocess import crop_with_padding, sharpness

if TYPE_CHECKING:
    from lpr.config import Settings

logger = logging.getLogger(__name__)

__all__ = [
    "ContourPlateDetector",
    "YoloPlateDetector",
    "plausible_box",
]

# --- plausibility gates ----------------------------------------------------
# A Turkish plate is 520x110 mm (ratio ~4.7); the shorter commercial/moto
# formats and perspective foreshortening pull that down towards ~1.5, and a
# grazing angle stretches it towards ~6.5. Anything outside is a headlight, a
# grille slat or a billboard.
MIN_ASPECT = 1.5
MAX_ASPECT = 6.5

#: Minimum fraction of the frame a plate must occupy. Below this the crop has
#: too few pixels per character for any recogniser to be trusted.
MIN_AREA_RATIO = 0.0002

#: Minimum absolute box size in pixels.
MIN_BOX_WIDTH = 40
MIN_BOX_HEIGHT = 12

#: Variance-of-Laplacian floor. Motion-blurred crops are dropped before OCR
#: rather than being allowed to produce confident nonsense.
MIN_SHARPNESS = 25.0

#: Crop margin around a detector box, see ``preprocess.crop_with_padding``.
CROP_PAD_RATIO = 0.06

#: Weights file assumed when ``detection.model_path`` is blank. Relative to
#: ``app.models_dir``, like every other relative model path.
DEFAULT_WEIGHTS_NAME = "plate_yolov8n.pt"

#: Tracker config handed to ultralytics when ``detection.tracker`` is unset.
#: Ships inside the ultralytics wheel, so it resolves offline in the container.
DEFAULT_TRACKER = "bytetrack.yaml"

#: Stream key used by the plain ``detect()`` entry point, i.e. by callers that
#: have not told us which camera the frame came from.
DEFAULT_STREAM_ID = "default"

#: Consecutive tracked-inference failures tolerated before the detector gives
#: up on tracking and degrades to stateless prediction for the rest of the run.
MAX_TRACK_FAILURES = 3


def _downscale(frame: np.ndarray, target_width: int) -> tuple[np.ndarray, float]:
    """``(image, scale)`` -- ``frame`` no wider than ``target_width``.

    ``scale`` is the factor the returned image was multiplied by, so a box
    found on it maps back to full-frame coordinates by dividing through. A
    frame already at or below the target, or a target of 0, is returned
    untouched with ``scale == 1.0`` and costs nothing.

    ``INTER_AREA`` rather than the default bilinear: it averages the pixels
    it discards, which preserves the plate's edges -- the one feature both
    detectors key on -- instead of aliasing them away.
    """
    if target_width <= 0 or not isinstance(frame, np.ndarray) or frame.size == 0:
        return frame, 1.0
    width = int(frame.shape[1])
    if width <= target_width:
        return frame, 1.0
    scale = target_width / float(width)
    height = max(1, int(round(frame.shape[0] * scale)))
    try:
        resized = cv2.resize(frame, (target_width, height), interpolation=cv2.INTER_AREA)
    except Exception:  # pragma: no cover - defensive
        logger.debug("downscale failed; detecting at full resolution", exc_info=True)
        return frame, 1.0
    return resized, scale


def plausible_box(
    bbox: tuple[int, int, int, int],
    frame_shape: tuple[int, ...],
    min_aspect: float = MIN_ASPECT,
    max_aspect: float = MAX_ASPECT,
    min_area_ratio: float = MIN_AREA_RATIO,
) -> bool:
    """Cheap geometric sanity check on a candidate box.

    Rejects degenerate boxes, boxes whose aspect ratio cannot be a plate, and
    boxes too small (relative to the frame, and absolutely) to hold readable
    characters. Pure geometry -- no image data touched, so it is safe to call
    on every raw model output.
    """
    try:
        x1, y1, x2, y2 = (int(v) for v in bbox)
    except (TypeError, ValueError):
        return False

    width = x2 - x1
    height = y2 - y1
    if width <= 0 or height <= 0:
        return False
    if width < MIN_BOX_WIDTH or height < MIN_BOX_HEIGHT:
        return False

    aspect = width / height
    if not (min_aspect <= aspect <= max_aspect):
        return False

    if len(frame_shape) >= 2:
        frame_area = float(frame_shape[0]) * float(frame_shape[1])
        if frame_area > 0 and (width * height) / frame_area < min_area_ratio:
            return False
    return True


class UnusablePlateWeights(RuntimeError):
    """The weights loaded fine but cannot detect plates.

    Raised for a multi-class model with no plate-like class -- in practice the
    stock COCO ``yolov8n.pt``, which is what you get when a fine-tune download
    silently fell back to the baseline, or when a baseline file was renamed to
    ``plate_yolov8n.pt`` to satisfy the config. Its 80 classes are person, car,
    chair and so on; none of them is a licence plate.

    Distinguished from a plain ``RuntimeError`` so :func:`lpr.detect.build_detector`
    can fall back to the contour detector, which -- weak as it is -- at least
    looks for plate-shaped things, instead of handing the recogniser a crop of
    every car and pot plant in frame.
    """


class YoloPlateDetector:
    """YOLOv8-based plate detector (satisfies ``Detector`` and ``TrackingDetector``).

    Inference runs through ultralytics' ``model.track(persist=True)`` rather
    than ``model.predict``, so every box carries a ByteTrack identity that is
    stable for as long as the plate stays in view. Downstream that identity is
    worth more than the box itself: it lets the pipeline recognise a plate once
    per *car* instead of once per *frame*.

    Backend
    -------
    On a **CPU** host, an ``.onnx`` export sitting next to the configured
    ``.pt`` is used instead: ONNX Runtime is materially faster than PyTorch for
    this model there. The swap is invisible to everything downstream --
    ultralytics runs tracking as a predictor callback, so ByteTrack,
    ``persist=True`` and the per-stream state below all behave identically on
    either backend. Produce the export with ``scripts/export_onnx.py``; disable
    the preference with ``detection.prefer_onnx: false``.

    On a **CUDA** host the export is ignored and the ``.pt`` runs on the GPU --
    see :meth:`_onnx_wanted`. The device itself comes from
    ``detection.device`` via :func:`lpr.accel.resolve_torch_device`, which
    resolves ``"auto"`` by probing and degrades to CPU rather than raising when
    a requested GPU is not usable.

    Per-stream isolation
    --------------------
    ultralytics keeps its tracker state on the predictor, one model instance =
    one tracker state. This detector is shared by the entry and exit cameras
    and called from both processing threads, so ``detect_tracked`` serialises
    inference and swaps each stream's tracker objects in and out around the
    call. Without that, the two cameras would feed one ByteTrack instance and
    every id would flip-flop between them.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        min_sharpness: float = MIN_SHARPNESS,
    ) -> None:
        if settings is None:
            from lpr.config import get_settings

            settings = get_settings()
        self._settings = settings
        cfg = settings.detection

        self.confidence = float(cfg.confidence)
        self.iou = float(cfg.iou)
        self.imgsz = int(cfg.imgsz)
        self.min_sharpness = float(min_sharpness)
        self.weights_path = self._resolve_weights(cfg.model_path, settings)

        # getattr keeps an older config.yaml (no tracking keys) working.
        self.tracking_enabled = bool(getattr(cfg, "track", True))
        self.tracker = str(getattr(cfg, "tracker", "") or DEFAULT_TRACKER)
        self._track_lock = threading.Lock()
        self._tracker_states: dict[str, Any] = {}
        self._track_failures = 0

        if not self.weights_path.is_file():
            raise RuntimeError(
                f"Detection weights not found at {self.weights_path}. Fetch the "
                "baseline model with `python scripts/fetch_models.py`, then point "
                "detection.model_path at your plate fine-tune."
            )

        # Lazy import: keeps `import lpr.detect.yolo` free of torch.
        try:
            from ultralytics import YOLO
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "ultralytics is not installed, so YoloPlateDetector cannot run. "
                "Install the detection dependencies with `pip install -r "
                "requirements.txt` (or `pip install ultralytics`)."
            ) from exc

        self.device = self._resolve_device(cfg.device)
        self.prefer_onnx = bool(getattr(cfg, "prefer_onnx", True))
        self._model, self.loaded_path = self._load_model(YOLO)
        # After _load_model, never before: reading .names on an exported model
        # builds a predictor, and it must be the one _verify built with an
        # explicit device. See _verify.
        self._plate_classes = self._resolve_plate_classes(self._model)

    # -- model loading -------------------------------------------------

    def _load_model(self, yolo_cls: Any) -> tuple[Any, Path]:
        """Load the fastest usable weights, preferring a sibling ONNX export.

        ONNX Runtime beats PyTorch comfortably for this model on CPU, which is
        what the gate box runs, so an ``.onnx`` next to the configured ``.pt``
        is used automatically. The catch is that a static export (the fast
        kind) accepts exactly the resolution it was built for and raises a raw
        ``InvalidArgument`` from ORT otherwise -- so the export is not trusted
        on the strength of its file extension. It is loaded, run once at
        ``detection.imgsz``, and only adopted if that works. Anything wrong
        with it (wrong imgsz, corrupt graph, no onnxruntime installed) falls
        back to the ``.pt`` with a warning instead of taking the gate down.
        """
        candidate = self._onnx_candidate(self.weights_path) if self._onnx_wanted() else None

        if candidate is not None:
            logger.info("found ONNX export %s; verifying it before use", candidate.name)
            try:
                model = yolo_cls(str(candidate))
                self._verify(model)
            except Exception as exc:
                logger.warning(
                    "ONNX export %s is unusable (%s); falling back to %s. Re-export "
                    "it with `python scripts/export_onnx.py --imgsz %d`.",
                    candidate.name,
                    exc,
                    self.weights_path.name,
                    self.imgsz,
                )
            else:
                logger.info(
                    "detector using ONNX Runtime: %s (imgsz=%d, device=%s)",
                    candidate,
                    self.imgsz,
                    self.device,
                )
                return model, candidate

        logger.info("loading detector weights %s on %s", self.weights_path, self.device)
        model = yolo_cls(str(self.weights_path))
        if self.weights_path.suffix.lower() == ".pt":
            # Only PyTorch checkpoints have a .to(); exported backends raise,
            # and take their device from the predict call instead.
            try:
                model.to(self.device)
            except Exception:  # pragma: no cover - some backends ignore .to()
                logger.debug("model.to(%s) failed; using the model's default device", self.device)
        return model, self.weights_path

    def _onnx_wanted(self) -> bool:
        """Whether to look for an ONNX export at all.

        ``prefer_onnx`` exists because ONNX Runtime beats PyTorch on the *CPU*
        gate boxes. On CUDA that reasoning inverts: requirements.txt installs
        the CPU ``onnxruntime`` wheel deliberately (the GPU build is a 250 MB
        download ultralytics would otherwise AutoUpdate into the container at
        runtime), so adopting the export here would quietly move detection off
        the GPU and onto the CPU -- slower than the ``.pt`` it replaced, and
        invisible apart from one INFO line. Install ``onnxruntime-gpu``
        explicitly if you want the export on a CUDA host.
        """
        if not self.prefer_onnx:
            return False
        if self.device.startswith("cuda"):
            logger.info(
                "running on %s, so the .pt is used directly; the ONNX preference is "
                "ignored because this image ships the CPU onnxruntime wheel",
                self.device,
            )
            return False
        return True

    @staticmethod
    def _onnx_candidate(weights_path: Path) -> Path | None:
        """A sibling ``.onnx`` for a ``.pt``, if one exists."""
        if weights_path.suffix.lower() != ".pt":
            return None
        candidate = weights_path.with_suffix(".onnx")
        return candidate if candidate.exists() else None

    def _verify(self, model: Any) -> None:
        """Prove a model actually runs here, at the configured resolution.

        Two inference passes, deliberately. While setting the predictor up,
        ultralytics replaces the requested ``imgsz`` with the one recorded in
        the export's own metadata, so the *first* call through a static ONNX
        graph runs at the exported size and succeeds whatever
        ``detection.imgsz`` says. Only the second call goes through at our
        resolution -- and it is the one that fails on a mismatched export.
        The explicit metadata check in between exists to turn that failure
        into a message that names the actual problem, instead of ONNX
        Runtime's "Got invalid dimensions for input: images".

        Passing ``device`` explicitly matters beyond correctness: ultralytics
        picks its ONNX Runtime package by whether *torch* sees a CUDA device,
        so letting it default on a CUDA-capable build makes it try to pip
        install the 250 MB onnxruntime-gpu wheel at runtime.
        """
        blank = np.zeros((self.imgsz, self.imgsz, 3), dtype=np.uint8)

        def run_once() -> None:
            model.predict(
                source=blank,
                imgsz=self.imgsz,
                conf=self.confidence,
                iou=self.iou,
                device=self.device,
                verbose=False,
            )

        run_once()
        self._check_static_imgsz(model)
        run_once()

    def _check_static_imgsz(self, model: Any) -> None:
        """Raise if a fixed-shape export was built for another resolution."""
        backend = getattr(getattr(model, "predictor", None), "model", None)
        if backend is None:
            return
        if getattr(backend, "dynamic", False):
            return  # a dynamic graph takes whatever we give it

        exported = getattr(backend, "imgsz", None)
        if not exported:
            return  # nothing declared: the second inference pass is the check
        sizes = exported if isinstance(exported, (list, tuple)) else [exported, exported]
        if any(int(side) != self.imgsz for side in sizes[:2]):
            raise RuntimeError(
                f"the export is fixed at imgsz={list(sizes[:2])} but detection.imgsz "
                f"is {self.imgsz}"
            )

    # -- setup helpers -------------------------------------------------

    @staticmethod
    def _resolve_weights(model_path: str, settings: Settings) -> Path:
        """Absolute path to the weights, relative paths resolved under models_dir.

        A blank ``model_path`` means "the default weights file". Without this
        branch ``Path("")`` is ``Path(".")``, which resolves to the models
        *directory* -- and a directory passes the ``.exists()`` check below, so
        the failure surfaced much later as an opaque error out of ultralytics
        instead of the "weights not found" message that triggers the fallback.
        """
        model_path = (model_path or "").strip() or DEFAULT_WEIGHTS_NAME
        raw = Path(model_path).expanduser()
        if raw.is_absolute():
            return raw
        # "models/plate_yolov8n.pt" and "plate_yolov8n.pt" both mean the same
        # file inside the configured models directory.
        models_dir = settings.paths.models_dir
        if raw.parts and raw.parts[0] == models_dir.name:
            raw = Path(*raw.parts[1:]) if len(raw.parts) > 1 else raw
        return (models_dir / raw).resolve()

    @staticmethod
    def _resolve_device(device: str) -> str:
        """Turn a configured device into a concrete torch device string.

        Delegates to :func:`lpr.accel.resolve_torch_device` so the detector and
        the OCR backend cannot disagree about whether this machine has a GPU,
        and so the probe (which builds a CUDA context) is paid once per process
        rather than once per component.

        Note that an *explicit* ``cuda`` on a machine without one is downgraded
        to CPU rather than passed through. It used to be passed through, and
        the failure that produced was badly misleading: ultralytics raised
        while loading the weights, :func:`lpr.detect.build_detector` caught it,
        and the pipeline came up on the contour detector -- so a device typo
        showed up as an accuracy collapse, not as a device error.
        """
        from lpr.accel import resolve_torch_device

        return resolve_torch_device(device)

    @staticmethod
    def _resolve_plate_classes(model: Any) -> set[int] | None:
        """Class ids that mean "plate", or ``None`` to accept every class.

        A dedicated fine-tune usually has one class and needs no filter; a
        multi-class model (or the COCO baseline) is filtered by name so a
        person or a car never reaches the recogniser.
        """
        try:
            names = getattr(model, "names", None)
            if not names:
                return None
            items = names.items() if isinstance(names, dict) else enumerate(names)
            plate_ids = {int(idx) for idx, name in items if "plate" in str(name).lower()}
            if plate_ids:
                return plate_ids
            if len(list(names)) == 1:
                return None
        except UnusablePlateWeights:
            raise
        except Exception:
            logger.debug("could not inspect model class names", exc_info=True)
            return None

        # Multi-class weights with nothing plate-like in them. Treating every
        # class as a plate candidate (which is what this used to do) is the
        # worst of the options: the recogniser is handed a crop of every
        # person, car and chair COCO knows about, which is both useless and
        # the single largest source of wasted OCR time on a CPU box.
        raise UnusablePlateWeights(
            f"the detection weights expose {len(list(names))} classes and none is "
            "named like a licence plate -- this looks like the stock COCO model, "
            "not a plate fine-tune. Point detection.model_path at real plate "
            "weights; until then the pipeline falls back to contour detection."
        )

    # -- Detector protocol ---------------------------------------------

    def detect(self, frame: np.ndarray) -> list[PlateDetection]:
        """Locate plates in ``frame``, best first, on the default stream.

        Convenience entry point for callers with a single video source. Multi
        camera callers should use :meth:`detect_tracked` so each source gets
        its own tracker state.
        """
        return self.detect_tracked(frame, DEFAULT_STREAM_ID)

    def detect_tracked(
        self, frame: np.ndarray, stream_id: str = DEFAULT_STREAM_ID
    ) -> list[PlateDetection]:
        """Locate plates in ``frame`` and attach their track ids, best first.

        Ultralytics does its own letterboxing and returns boxes already mapped
        back to source-frame pixels, so no manual unmapping is needed here.
        Implausible and blurred boxes are dropped before they can cost an OCR
        pass. Never raises: an inference failure yields an empty list.
        """
        if not isinstance(frame, np.ndarray) or frame.size == 0:
            return []

        results = self._infer(frame, str(stream_id or DEFAULT_STREAM_ID))

        detections: list[PlateDetection] = []
        for result in results or []:
            boxes = getattr(result, "boxes", None)
            if boxes is None:
                continue
            for box in boxes:
                detection = self._to_detection(box, frame)
                if detection is not None:
                    detections.append(detection)

        detections.sort(key=lambda d: d.confidence, reverse=True)
        return detections

    # -- inference -----------------------------------------------------

    def _infer(self, frame: np.ndarray, stream_id: str) -> Any:
        """Run one inference pass, tracked when tracking is available.

        Falls back to stateless prediction -- permanently, after
        ``MAX_TRACK_FAILURES`` consecutive failures -- if ``model.track`` does
        not work in this environment. A pipeline that detects plates without
        track ids is degraded; one that stops detecting is broken.
        """
        if self.tracking_enabled:
            with self._track_lock:
                try:
                    self._restore_tracker_state(stream_id)
                    results = self._model.track(
                        source=frame,
                        imgsz=self.imgsz,
                        conf=self.confidence,
                        iou=self.iou,
                        device=self.device,
                        persist=True,
                        tracker=self.tracker,
                        verbose=False,
                    )
                    self._store_tracker_state(stream_id)
                    self._track_failures = 0
                    return results
                except Exception:
                    self._track_failures += 1
                    logger.exception(
                        "tracked inference failed on stream %r (%d/%d)",
                        stream_id,
                        self._track_failures,
                        MAX_TRACK_FAILURES,
                    )
                    if self._track_failures >= MAX_TRACK_FAILURES:
                        self.tracking_enabled = False
                        self._tracker_states.clear()
                        logger.error(
                            "disabling ByteTrack after %d consecutive failures; "
                            "detection continues without track ids and the "
                            "pipeline falls back to text-only voting",
                            self._track_failures,
                        )

        try:
            return self._model.predict(
                source=frame,
                imgsz=self.imgsz,
                conf=self.confidence,
                iou=self.iou,
                device=self.device,
                verbose=False,
            )
        except Exception:
            logger.exception("detector inference failed")
            return []

    def _restore_tracker_state(self, stream_id: str) -> None:
        """Make ``stream_id``'s trackers the live ones. Lock held by caller.

        Three cases:

        * we have state for this stream -> put it back;
        * no predictor yet, or a predictor with no trackers -> let ultralytics
          build the first set on this call (``persist=True`` keeps them);
        * a *different* stream's trackers are live -> clone a fresh, empty set
          of the same type so this stream starts its own id space.
        """
        predictor = getattr(self._model, "predictor", None)
        if predictor is None:
            return

        state = self._tracker_states.get(stream_id)
        if state is not None:
            predictor.trackers = state
            return

        live = getattr(predictor, "trackers", None)
        if not live:
            return

        fresh = self._clone_trackers(live)
        if fresh is not None:
            predictor.trackers = fresh
        else:
            logger.warning(
                "could not give stream %r its own tracker state; track ids may "
                "be shared between cameras",
                stream_id,
            )

    def _store_tracker_state(self, stream_id: str) -> None:
        """Remember the trackers this stream just used. Lock held by caller."""
        predictor = getattr(self._model, "predictor", None)
        trackers = getattr(predictor, "trackers", None) if predictor else None
        if trackers:
            self._tracker_states[stream_id] = trackers

    @staticmethod
    def _clone_trackers(trackers: Any) -> list[Any] | None:
        """Empty trackers of the same class/config, or None if that is not possible.

        Rebuilt from each tracker's own ``args`` rather than copied, so the new
        stream starts with an empty track list and its own id counter.
        """
        fresh: list[Any] = []
        for tracker in trackers:
            args = getattr(tracker, "args", None)
            if args is None:
                return None
            tracker_cls = type(tracker)
            # ultralytics <= 8.3 took BYTETracker(args, frame_rate=30); 8.4
            # dropped the second parameter. Support both rather than pinning.
            kwargs: dict[str, Any] = {"args": args}
            try:
                if "frame_rate" in inspect.signature(tracker_cls).parameters:
                    kwargs["frame_rate"] = getattr(tracker, "frame_rate", 30)
                fresh.append(tracker_cls(**kwargs))
            except Exception:
                logger.debug("cannot rebuild tracker %s", tracker_cls.__name__, exc_info=True)
                return None
        return fresh or None

    def _to_detection(self, box: Any, frame: np.ndarray) -> PlateDetection | None:
        """Convert one ultralytics box into a validated ``PlateDetection``."""
        try:
            if self._plate_classes is not None:
                cls_id = int(box.cls[0])
                if cls_id not in self._plate_classes:
                    return None

            confidence = float(box.conf[0])
            xyxy = box.xyxy[0].tolist()
            height, width = frame.shape[:2]
            x1 = int(round(max(0.0, min(float(width), xyxy[0]))))
            y1 = int(round(max(0.0, min(float(height), xyxy[1]))))
            x2 = int(round(max(0.0, min(float(width), xyxy[2]))))
            y2 = int(round(max(0.0, min(float(height), xyxy[3]))))
            bbox = (x1, y1, x2, y2)

            if not plausible_box(bbox, frame.shape):
                logger.debug("dropping implausible box %s", bbox)
                return None

            crop = crop_with_padding(frame, bbox, CROP_PAD_RATIO)
            if crop.size == 0:
                return None

            focus = sharpness(crop)
            if focus < self.min_sharpness:
                logger.debug("dropping blurred crop %s (sharpness %.1f)", bbox, focus)
                return None

            return PlateDetection(
                bbox=bbox,
                confidence=confidence,
                crop=crop,
                track_id=self._track_id(box),
            )
        except Exception:
            logger.debug("failed to convert a detector box", exc_info=True)
            return None

    @staticmethod
    def _track_id(box: Any) -> int | None:
        """Track id of one ultralytics box, or None if it has none.

        ``box.id`` is absent under ``predict``, and is ``None`` under ``track``
        for a detection the tracker has not yet associated with a track (a new
        object still in its confirmation window), so both are normal.
        """
        raw = getattr(box, "id", None)
        if raw is None:
            return None
        try:
            return int(raw[0])
        except (TypeError, ValueError, IndexError):
            logger.debug("unreadable track id %r", raw, exc_info=True)
            return None

    def warmup(self) -> None:
        """Run one inference on a synthetic frame.

        The first real inference allocates CUDA context and cuDNN workspaces
        and can take seconds. Paying that during startup keeps the first car at
        the gate from waiting for it.

        Deliberately ``predict`` and not ``track``: a synthetic frame must not
        create tracker state, and the real first ``track`` call is what builds
        the first stream's trackers.
        """
        try:
            self._verify(self._model)
            logger.info("detector warmup complete (%s on %s)", self.loaded_path.name, self.device)
        except Exception:
            logger.warning("detector warmup failed; first frame may be slow", exc_info=True)


class ContourPlateDetector:
    """Classical Canny/contour plate finder (satisfies ``Detector``).

    **This is the fallback, not the product.** It is the pre-YOLO pipeline
    refactored behind the same protocol: grayscale -> bilateral filter ->
    Canny -> contours -> the largest 4-vertex polygon with a plate-like aspect
    ratio. It requires a clean, well-lit, near-frontal, unoccluded plate border
    and silently finds nothing (or the wrong thing) otherwise. Expect a large
    accuracy drop versus :class:`YoloPlateDetector`; use it only until real
    weights are in place.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        max_candidates: int = 10,
        min_sharpness: float = MIN_SHARPNESS,
    ) -> None:
        if settings is None:
            from lpr.config import get_settings

            settings = get_settings()
        self._settings = settings
        self.max_candidates = int(max_candidates)
        self.min_sharpness = float(min_sharpness)
        #: Longest edge the edge-detection pass runs at. The chain below is
        #: dominated by ``bilateralFilter``, whose cost is proportional to the
        #: pixel count: at 1280x720 it is ~40 ms a frame on a laptop CPU, at
        #: 640 it is ~10 ms. Plate-sized quadrilaterals survive the downscale
        #: comfortably, and crops are still cut from the full-resolution frame.
        self.downscale_width = max(0, int(getattr(settings.detection, "downscale_width", 0)))

    def detect(self, frame: np.ndarray) -> list[PlateDetection]:
        """Find plate-shaped quadrilaterals, best (largest) first."""
        if not isinstance(frame, np.ndarray) or frame.size == 0:
            return []
        try:
            work, scale = _downscale(frame, self.downscale_width)
            gray = work if work.ndim == 2 else cv2.cvtColor(work, cv2.COLOR_BGR2GRAY)
            filtered = cv2.bilateralFilter(gray, 11, 17, 17)
            edges = cv2.Canny(filtered, 30, 200)
            contours, _ = cv2.findContours(edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
        except Exception:
            logger.debug("contour detection failed", exc_info=True)
            return []

        ranked = sorted(contours, key=cv2.contourArea, reverse=True)[: self.max_candidates]
        frame_area = float(frame.shape[0]) * float(frame.shape[1])

        detections: list[PlateDetection] = []
        for contour in ranked:
            try:
                perimeter = cv2.arcLength(contour, True)
                approx = cv2.approxPolyDP(contour, 0.018 * perimeter, True)
                if len(approx) != 4:
                    continue
                box_x, box_y, box_w, box_h = cv2.boundingRect(approx)
                # Back to full-frame coordinates before anything downstream
                # (plausibility, cropping) sees the box.
                x, y, w, h = (float(v) / scale for v in (box_x, box_y, box_w, box_h))
                bbox = (int(x), int(y), int(x + w), int(y + h))
                if not plausible_box(bbox, frame.shape):
                    continue

                crop = crop_with_padding(frame, bbox, CROP_PAD_RATIO)
                if crop.size == 0 or sharpness(crop) < self.min_sharpness:
                    continue

                # No model score exists here. Use the fraction of the frame the
                # candidate covers, squashed into a deliberately modest range,
                # so downstream confidence gates cannot mistake a contour guess
                # for a confident detection.
                area_ratio = float(w * h) / frame_area if frame_area else 0.0
                confidence = float(min(0.60, 0.25 + area_ratio * 8.0))
                detections.append(PlateDetection(bbox=bbox, confidence=confidence, crop=crop))
            except Exception:
                logger.debug("skipping a malformed contour", exc_info=True)
                continue

        detections.sort(key=lambda d: d.confidence, reverse=True)
        return detections

    def warmup(self) -> None:
        """Run the filter chain once so OpenCV's kernels are already resident."""
        try:
            self.detect(np.zeros((240, 320, 3), dtype=np.uint8))
        except Exception:  # pragma: no cover - warmup must never break startup
            logger.debug("contour detector warmup failed", exc_info=True)
