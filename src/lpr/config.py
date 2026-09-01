"""Typed, layered configuration for the LPR service.

Precedence, lowest to highest:

    config.yaml  <  .env  <  environment (LPR_ prefix, "__" nesting)  <  constructor args

i.e. an explicit ``Settings(api=ApiConfig(port=9000))`` always wins, an
environment variable like ``LPR_API__PORT=9000`` beats whatever is in
``config.yaml``, and ``config.yaml`` fills in anything neither of those
touched. Field defaults (below) are the last resort if a key is missing
everywhere.

``.env`` sits directly beneath the real environment because that is what it
stands in for: Compose loads it with ``env_file:`` and hands the values to the
process as ordinary variables, so a host run must resolve it the same way or
the same file means two different things depending on how the service was
started. It is above ``config.yaml`` for the same reason -- ``config.yaml`` is
committed and ``.env`` is not, so the uncommitted file is the one carrying the
secret, and the committed one must not be able to overwrite it.

Usage:

    from lpr.config import get_settings

    settings = get_settings()
    settings.detection.confidence
    settings.paths.data_dir  # absolute Path, created on first access
"""

from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar, Literal

import yaml
from pydantic import BaseModel, Field, PrivateAttr, model_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from lpr.platform_compat import IS_WINDOWS, default_serial_port

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Section models
# ---------------------------------------------------------------------------


class AppConfig(BaseModel):
    name: str = "lpr"
    headless: bool = True
    log_level: str = "INFO"
    data_dir: str = "data"
    models_dir: str = "models"
    #: Browser dashboard served at ``/web``. Unlike the other two this is
    #: read-only content that ships with the source, so it is never created
    #: -- a missing directory just means the web UI is not served.
    web_dir: str = "web"


class CameraConfig(BaseModel):
    """One camera feed. ``source`` is kept as a string so it can hold either
    a numeric device index ("0") or an RTSP/HTTP URL.

    A **blank** ``source`` means "this camera is not fitted on this site".
    That is the normal single-camera setup, not an error: the orchestrator
    skips the role entirely rather than spawning a capture thread that
    reconnects to nothing forever.
    """

    source: str = "0"
    width: int = 1280
    height: int = 720
    fps_limit: int = 15
    #: First reconnect delay. Subsequent attempts back off exponentially up to
    #: ``reconnect_max_delay_s``, so a camera that is off for the night stops
    #: retrying every five seconds for eight hours.
    reconnect_delay_s: float = 5.0
    #: Ceiling on the backoff. A camera that comes back must be picked up
    #: within about this long, so it is minutes rather than hours.
    reconnect_max_delay_s: float = 60.0
    queue_size: int = 2

    #: Seconds without a frame before the watchdog forces a reconnect. 0
    #: disables it.
    #:
    #: This is the failure that took a gate offline silently: a TCP connection
    #: that stays open while the camera stops sending. ``VideoCapture.read()``
    #: blocks with no timeout of its own, so the capture thread parks forever,
    #: the process stays alive, ``/health`` keeps answering 200, and the
    #: barrier simply never opens again. Nothing in the logs says so, because
    #: nothing happened.
    #:
    #: 15 s is comfortably longer than the FFmpeg socket timeout below (which
    #: should catch this first) and shorter than a driver arriving at a
    #: barrier is willing to wait.
    stall_timeout_s: float = 15.0

    #: RTSP transport. ``tcp`` or ``udp``; anything else is passed through.
    #:
    #: FFmpeg defaults to UDP, which on a busy or wifi-bridged site drops
    #: packets and produces torn frames and half-decoded plates -- read errors
    #: that look like OCR errors. TCP costs a little latency and removes that
    #: whole class of failure, which is the right trade at a gate.
    rtsp_transport: str = "tcp"

    #: Socket timeout handed to FFmpeg, in seconds. 0 leaves FFmpeg's default
    #: (no timeout), which is what allows the indefinite block described above.
    #: Applied to network sources only; a V4L2 device ignores it.
    open_timeout_s: float = 5.0

    #: ``/dev/videoN`` -- a Linux device node. Recognised on every platform so
    #: a config written on Linux can be *understood* on Windows rather than
    #: handed to a capture backend that can only fail with it.
    _V4L2_PATH: ClassVar[re.Pattern[str]] = re.compile(r"/dev/video(\d+)\Z")

    #: DirectShow's ``video=<friendly name>`` form, as ``ffmpeg -f dshow``
    #: takes it. Windows-only, and matched case-insensitively because the
    #: Device Manager spelling is whatever the vendor chose.
    _DSHOW_NAME: ClassVar[re.Pattern[str]] = re.compile(r"video=(.+)\Z", re.IGNORECASE)

    @property
    def source_kind(self) -> str:
        """What kind of thing ``source`` names, on *this* machine.

        One of ``"disabled"`` (blank), ``"index"`` (a camera number),
        ``"device"`` (an OS device node or DirectShow name), ``"url"`` (RTSP /
        HTTP), ``"file"`` (a video file that exists), or ``"invalid"``.

        The last one is the point of the property. A capture backend answers a
        nonsense source the same way it answers an unplugged camera -- by
        failing to open -- so without this the reconnect loop is the only
        symptom, and it looks identical to a cable problem. Classifying the
        string up front lets :class:`CamerasConfig` disable the role and say
        which of the two it is.
        """
        source = (self.source or "").strip()
        if not source:
            return "disabled"
        if "://" in source:
            return "url"
        if source.lstrip("+").isdigit():
            return "index"
        if self._V4L2_PATH.fullmatch(source):
            # Meaningful on Linux; on Windows it is still understood, because
            # `normalised_source` rewrites it to the bare index.
            return "device"
        if IS_WINDOWS and self._DSHOW_NAME.fullmatch(source):
            return "device"
        if not IS_WINDOWS and source.startswith("/dev/"):
            return "device"
        try:
            if Path(source).expanduser().is_file():
                return "file"
        except OSError:  # pragma: no cover - unrepresentable path on this OS
            return "invalid"
        return "invalid"

    @property
    def normalised_source(self) -> str:
        """``source`` rewritten into the spelling this OS can actually open.

        The only rewrite that happens today is the cross-platform one:
        ``/dev/video1`` on Windows becomes ``"1"``. A Linux device node cannot
        be opened by DirectShow at all, and the two spellings already mean the
        same camera everywhere else in this file (see :attr:`device_key`), so
        translating it is strictly better than watching the role fail to open
        on a machine where that path can never exist.

        Everything else is returned stripped and otherwise untouched.
        """
        source = (self.source or "").strip()
        if not source:
            return ""
        if IS_WINDOWS:
            match = self._V4L2_PATH.fullmatch(source)
            if match:
                return str(int(match.group(1)))
        if source.lstrip("+").isdigit():
            # "00", " 0 " and "+0" are all camera 0. Windows configs written by
            # hand pick up stray whitespace from the Device Manager dialog.
            return str(int(source))
        return source

    @property
    def is_network_source(self) -> bool:
        """True for a URL rather than a local device index or path.

        Only network sources get the FFmpeg options: passing them to a V4L2
        capture is harmless but misleading, and the watchdog's forced release
        is a different proposition on a local device (see
        :meth:`~lpr.pipeline.camera.CameraWorker._force_release`).
        """
        source = (self.source or "").strip().lower()
        return "://" in source

    @property
    def enabled(self) -> bool:
        """False when ``source`` is blank, i.e. the role is not fitted."""
        return bool((self.source or "").strip())

    @property
    def resolved_source(self) -> int | str | None:
        """``source`` as an int device index when it is all-digits, else the
        raw string (URL or device path) unchanged. ``None`` when blank.

        ``None`` is what tells :class:`~lpr.pipeline.camera.CameraWorker` and
        the orchestrator that there is nothing to open here.
        """
        source = self.normalised_source
        if not source:
            return None
        if source.isdigit():
            return int(source)
        return source

    @property
    def device_key(self) -> str | None:
        """A stable identity for the *physical* device this camera opens.

        ``"0"`` and ``"/dev/video0"`` are the same webcam addressed two ways.
        V4L2 hands the second opener ``VIDIOC_QBUF: Bad file descriptor``
        rather than a second stream, so the orchestrator has to recognise the
        collision before it opens anything -- by the time OpenCV reports it,
        one of the two cameras is already in a reconnect loop. Both spellings
        normalise to ``"v4l2:0"`` here. Network sources normalise to their URL,
        which is genuinely shareable but still worth reporting when duplicated.

        ``None`` for a disabled camera, which collides with nothing.
        """
        source = self.normalised_source
        if not source:
            return None
        if source.isdigit():
            return f"v4l2:{int(source)}"
        match = self._V4L2_PATH.fullmatch(source)
        if match:
            return f"v4l2:{int(match.group(1))}"
        return source.lower()


class MotionConfig(BaseModel):
    """Motion gating: skip ML inference on a scene where nothing is happening.

    A gate camera is idle almost all day. Running YOLO on an empty driveway
    costs the same as running it on a car, so a ~0.1 ms frame-difference check
    in the capture thread removes the overwhelming majority of that work.
    """

    enabled: bool = True
    #: Minimum area of the largest moving contour, in **full-frame pixels**,
    #: for a frame to be worth an inference pass. Measured on a downscaled
    #: image and scaled back up, so this number stays meaningful no matter
    #: what internal resolution the check runs at. 5000 ~= a 70x70 blob.
    threshold: int = 5000
    #: Pass a frame through at least this often even when the scene is still.
    #: Keeps the tracker's frame counter advancing so stale ByteTrack ids age
    #: out, and keeps a wholly-static failure mode (frozen feed, wrong
    #: background) from silently blinding the pipeline forever. 0 disables the
    #: heartbeat, leaving motion as the only way a frame reaches inference.
    heartbeat_s: float = 3.0


class CameraIssue(BaseModel):
    """One camera role that was switched off, and why.

    Kept as data rather than only a log line so the API can show an operator
    the same sentence the log holds. "The exit camera is disabled because it
    names the same device as the entry camera" is a five-second fix if it
    reaches the screen and an afternoon if it only reaches a log file nobody
    is tailing.
    """

    role: str
    source: str
    #: ``"duplicate"`` or ``"invalid"``.
    reason: str
    message: str


class CamerasConfig(BaseModel):
    entry: CameraConfig = Field(default_factory=CameraConfig)
    exit: CameraConfig = Field(default_factory=CameraConfig)
    motion: MotionConfig = Field(default_factory=MotionConfig)

    #: Roles disabled by :meth:`_validate_sources`, in the order they were hit.
    #: A private attribute so it is neither settable from the environment nor
    #: part of the serialised config; read it through :attr:`issues`.
    _issues: list[CameraIssue] = PrivateAttr(default_factory=list)

    #: The roles this model validates, in priority order. The first role to
    #: name a device keeps it, so this order is what decides the winner of a
    #: collision -- deterministically, which is the whole point.
    ROLES: ClassVar[tuple[str, ...]] = ("entry", "exit")

    @model_validator(mode="after")
    def _validate_sources(self) -> "CamerasConfig":
        """Disable any role that cannot work, and record why.

        Two failures are caught here rather than at open time, because at open
        time they are indistinguishable from an unplugged camera -- a
        reconnect loop and nothing else:

        **Duplicate device.** Entry and exit pointed at the same camera. On
        Linux, V4L2 gives exclusive access and the loser gets
        ``VIDIOC_QBUF: Bad file descriptor``; on Windows, DirectShow locks the
        device outright and the second ``VideoCapture`` takes the capture
        pipeline down with it. Which role loses depends on thread scheduling,
        so the symptom moves between cameras run to run. ``entry: "0"`` with
        ``exit: "/dev/video0"`` is one webcam spelled two ways -- see
        :attr:`CameraConfig.device_key`.

        **Unopenable source.** A string that is not an index, a device, a URL
        or an existing file. Usually a typo, or a ``/dev/video0`` carried to a
        machine that has no such path (that one is rewritten rather than
        refused -- see :attr:`CameraConfig.normalised_source`).

        In both cases the role is switched off: blanking ``source`` is exactly
        what "this camera is not fitted" already means everywhere else, so the
        orchestrator skips it, the API reports it as disconnected, and the
        *other* camera keeps working. A site with one good camera and one
        misconfigured one runs on the good one.
        """
        self._issues = []
        claimed: dict[str, str] = {}

        for role in self.ROLES:
            camera: CameraConfig = getattr(self, role)
            kind = camera.source_kind
            if kind == "disabled":
                continue

            if kind == "invalid":
                self._disable(
                    role,
                    camera,
                    "invalid",
                    f"Camera {role} source {camera.source!r} is not a camera index, "
                    "device, URL or existing file; the role has been disabled. "
                    "Use a number (\"0\"), an RTSP/HTTP URL, or leave it blank.",
                )
                continue

            key = camera.device_key
            owner = claimed.get(key) if key is not None else None
            if owner is not None:
                self._disable(
                    role,
                    camera,
                    "duplicate",
                    f"Camera {role} source {camera.source!r} is the same device as "
                    f"camera {owner} ({getattr(self, owner).source!r}); {role} has "
                    "been disabled. One capture backend cannot hand the same "
                    "device to two readers -- give each role its own camera, or "
                    "leave one source blank.",
                )
                continue

            if key is not None:
                claimed[key] = role

        return self

    def _disable(self, role: str, camera: CameraConfig, reason: str, message: str) -> None:
        """Blank one role's source and record the reason. Logs at WARNING."""
        issue = CameraIssue(role=role, source=camera.source, reason=reason, message=message)
        self._issues.append(issue)
        logger.warning("%s", message)
        camera.source = ""

    @property
    def issues(self) -> list[CameraIssue]:
        """Roles disabled during validation. Empty on a healthy configuration."""
        return list(self._issues)


class DetectionConfig(BaseModel):
    model_path: str = "models/plate_yolov8n.pt"
    confidence: float = 0.35
    iou: float = 0.5
    device: str = "auto"
    imgsz: int = 640
    frame_stride: int = 3
    #: Run the detector through a multi-object tracker so each plate keeps a
    #: stable id across frames. Off = one independent detection per frame, and
    #: the pipeline falls back to text-only voting.
    track: bool = True
    #: Tracker config passed to ultralytics. "bytetrack.yaml" and
    #: "botsort.yaml" ship inside the ultralytics wheel; an absolute path to
    #: your own YAML also works.
    tracker: str = "bytetrack.yaml"
    #: Prefer an ``.onnx`` sitting next to ``model_path`` over the ``.pt``.
    #: Only takes effect once an export exists, so it costs nothing by
    #: default, and the export is verified at startup before it is adopted.
    #: Note that ONNX Runtime is *not* automatically faster than PyTorch on
    #: CPU -- benchmark your own hardware with ``scripts/export_onnx.py``,
    #: which reports both, and set this to false if the .pt wins.
    prefer_onnx: bool = True
    #: Frame width, in pixels, that the **contour** detector runs its edge pass
    #: at. 0 detects at capture resolution.
    #:
    #: Only the contour detector reads this. YOLO has its own equivalent in
    #: ``imgsz`` above and letterboxes internally, so pre-shrinking its input
    #: would just add a resize -- and would cost crop quality, since crops are
    #: cut from whatever frame the detector was handed.
    #:
    #: The contour chain is dominated by ``bilateralFilter``, whose cost scales
    #: with the pixel count: ~40 ms a frame at 1280x720 against ~10 ms at 640 on
    #: a laptop CPU. Boxes are scaled back to full-frame coordinates and crops
    #: are still taken from the original frame, so the recogniser reads the
    #: plate at full resolution and OCR accuracy is unaffected.
    downscale_width: int = 640
    #: Most crops from one frame that are allowed to reach OCR, best-scoring
    #: first. OCR is by far the most expensive stage (hundreds of ms per crop
    #: on CPU), and a frame with a genuine plate in it needs one or two passes
    #: -- a frame producing ten candidates is a detector that is firing on
    #: things that are not plates, and OCR'ing all of them is what turns a
    #: slow frame into a stalled pipeline. 0 = no cap.
    max_ocr_candidates: int = 3


class PreprocessConfig(BaseModel):
    """Software-level image enhancement, applied before detection and OCR.

    The crop-level settings (``crop_*``, ``rectify_perspective``) are on by
    default: they only ever affect what the *recogniser* sees, and the
    recogniser keeps the best read across several variants, so a variant that
    an enhancement made worse simply loses.

    ``frame_enhance`` is different and therefore defaults to off. It changes
    what the *detector* sees, and the detector is a trained CNN with no
    corresponding voting fallback -- a frame it fails to fire on is a plate
    that never reaches OCR at all. Mild CLAHE usually helps in low light and
    can cost recall in good light, so turn it on only after checking detection
    counts against your own footage.
    """

    #: Run CLAHE + unsharp over the whole frame before the detector sees it.
    frame_enhance: bool = False
    #: CLAHE clip limit for the whole-frame pass. Higher lifts shadows harder
    #: and amplifies sensor noise with them.
    frame_clahe_clip: float = Field(default=2.0, ge=0.1, le=10.0)
    #: Unsharp strength for the whole-frame pass. Kept below the crop-level
    #: amount: the detector wants a natural-looking frame, not a crisp one.
    frame_unsharp_amount: float = Field(default=0.5, ge=0.0, le=3.0)
    #: Unsharp strength inside the OCR crop pre-pass. 0 disables sharpening.
    crop_unsharp_amount: float = Field(default=0.6, ge=0.0, le=3.0)
    #: Dynamic gamma + percentile contrast stretch on the crop, ahead of CLAHE.
    #: Rescues plates shot under a headlight or in deep shadow. Self-limiting:
    #: a normally-exposed crop is passed through untouched.
    normalize_lighting: bool = True
    #: Retry a failed read on a perspective-corrected copy of the crop. Costs
    #: an extra OCR pass, but only on crops that produced no valid plate.
    rectify_perspective: bool = True
    #: Last-resort views for a crop nothing else could read: an Otsu
    #: binarisation for the uniformly dark night crops that defeat the adaptive
    #: threshold, plus polarity-inverted copies for plates lit by an IR
    #: illuminator. Same bargain as ``rectify_perspective`` -- an extra OCR
    #: pass, paid only on crops that have already failed.
    hard_case_variants: bool = True
    #: Keep escalating to the harder views while the best read so far scores
    #: below this.
    #:
    #: Without it a *grammatical but unconvincing* read ends the search -- and
    #: since the pipeline then rejects anything under ``ocr.min_confidence``,
    #: the crop is thrown away having never been shown the views most likely to
    #: rescue it. The default matches the ``ocr.min_confidence`` default, so
    #: out of the box the recogniser keeps trying exactly as long as its best
    #: read would still be refused downstream. 0 restores the old behaviour of
    #: stopping at the first grammatical read whatever its confidence.
    escalate_below_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    #: Offer the recogniser a fourth view of each crop: the binarisation with
    #: the ink bridges between tightly-set characters prised apart
    #: (:func:`lpr.detect.preprocess.separate_characters`).
    #:
    #: This is the fix for the bold, tightly-spaced plates whose adjacent
    #: glyphs merge into one blob at binarisation and read as a dropped or
    #: invented character. It is an *additional* view rather than a
    #: replacement, because the same repair applied to a delicate font thins
    #: its strokes into gaps -- so both go to the ensemble and agreement
    #: between views decides, which is how every other variant here works.
    #:
    #: Nearly free on plates that do not need it: a crop whose ink coverage
    #: says there is no bridge, or whose view the repair would not change,
    #: produces no extra view and therefore no extra OCR pass.
    tight_font_variant: bool = True
    #: ``(width, height)`` of the structuring element used for that repair.
    #: Vertical and odd for the reasons in
    #: :data:`lpr.detect.preprocess.TIGHT_FONT_KERNEL`; raise the height to 5
    #: to clear thicker bridges, at the cost of eating the horizontal bar of
    #: an E or F on a short crop.
    tight_font_kernel: tuple[int, int] = (1, 3)


class OcrConfig(BaseModel):
    backend: str = "easyocr"
    #: ``true``, ``false``, or ``"auto"`` (the default): probe for a usable
    #: CUDA device and use it when there is one.
    #:
    #: "auto" rather than a hard ``true`` because the same ``config.yaml`` is
    #: deployed to the GPU gate box, to CPU-only spares, and to CI. An explicit
    #: ``true`` on a machine with no GPU is downgraded to CPU with a warning
    #: rather than honoured, because EasyOCR raises out of its constructor in
    #: that case and would take the whole pipeline build down with it. See
    #: :func:`lpr.accel.resolve_gpu_flag`.
    gpu: bool | Literal["auto"] = "auto"
    min_confidence: float = 0.5
    allowlist: str = "ABCDEFGHIJKLMNOPRSTUVYZ0123456789"
    #: EasyOCR's horizontal box-merging threshold. Two detected boxes on the
    #: same line are merged when the gap between them is smaller than
    #: ``width_ths * box_height`` (easyocr/utils.py, ``group_text_box``).
    #:
    #: **The direction is the opposite of what it sounds like: higher merges
    #: more.** Raising it to 0.6-0.7 makes EasyOCR *more* willing to glue
    #: adjacent boxes together, not less. To have the plate split into more,
    #: smaller boxes, lower it -- 0.3 is a reasonable first try.
    #:
    #: Left at EasyOCR's own 0.5 by default because this knob is worth much
    #: less here than it looks. It groups *boxes*, and the characters that
    #: merge on a bold APP plate merge inside a single box at binarisation,
    #: which no grouping threshold can undo -- that is what
    #: ``preprocess.tight_font_variant`` is for. It also cannot lose a read:
    #: the recogniser already votes on each fragment separately *and* on their
    #: concatenation, so a plate split across two boxes is scored both ways.
    width_ths: float = Field(default=0.5, ge=0.0, le=5.0)
    #: Where EasyOCR keeps its detection/recognition weights. Blank means
    #: ``<app.models_dir>/easyocr``.
    #:
    #: EasyOCR defaults to ``~/.EasyOCR``, which inside a container is a layer
    #: of the container filesystem -- so every ``docker compose up --build``
    #: threw the weights away and re-downloaded ~100 MB on the next start,
    #: and a flaky link at that moment hung or failed startup. models/ is a
    #: bind-mounted host volume, so pointing the cache there makes the download
    #: a once-per-machine cost instead of a once-per-container one.
    model_dir: str = ""
    #: Allow EasyOCR to fetch missing weights over the network at startup.
    #: Set false on a locked-down gate box: the service then fails fast with a
    #: message naming ``scripts/fetch_models.py`` instead of hanging on a
    #: connection that will never complete.
    allow_download: bool = True
    #: Socket timeout, in seconds, applied while the reader is being built.
    #:
    #: EasyOCR downloads its weights with ``urllib`` and no timeout, so a
    #: half-open connection (captive portal, dropped VPN, a NAT that blackholes
    #: instead of resetting) leaves the container hanging in ``__init__``
    #: forever -- past the compose healthcheck, with no log line explaining
    #: why. Bounding the socket turns that into a prompt, diagnosable failure.
    #: 0 restores the unbounded default.
    download_timeout_s: float = Field(default=60.0, ge=0.0)
    #: Extra engines pooled into the per-frame ensemble vote alongside
    #: ``backend``. Empty by default: the ensemble already votes across the
    #: several enhanced views of each crop, which recovers most view-dependent
    #: glyph confusions at no extra model cost. A second *engine* adds a
    #: genuinely independent opinion but also its own memory and warmup, so it
    #: is opt-in -- e.g. ``["paddleocr"]`` alongside the default easyocr.
    #: Engines are queried in order and the ensemble stops as soon as it holds
    #: a grammatical read, so the second one is a cost paid on hard crops only.
    ensemble_backends: list[str] = Field(default_factory=list)


class FastPathConfig(BaseModel):
    """Open the gate on the first confident read of a **registered** plate.

    The slow path is deliberately thorough: every crop is read through a ladder
    of enhanced views (gamma, unsharp, rectification, then the hard-case
    binarisations), and the winning string has to be confirmed by
    ``voting.min_votes`` separate frames before the barrier moves. That is the
    right default for a stranger at the gate, where a misread is a security
    event.

    It is over-cautious for the common case. A resident's car, in daylight,
    reads cleanly on the first view -- and then pays for the whole ladder and
    waits several more frames for a verdict that never changes. This section
    short-circuits exactly that case: when the running vote is already above
    ``min_confidence`` *and* names a plate that
    :meth:`~lpr.db.repository.PlateRepository.authorization` clears right now,
    the remaining views are not computed and the gate opens on that frame.

    **What is being traded.** The escalation saving is free -- the later views
    exist to rescue an unreadable crop, and this one was read. The multi-frame
    confirmation is not free: a single confident misread that happens to spell
    a registered plate opens the barrier, where today it would need
    ``voting.min_votes`` frames to agree on the same wrong string. That is why
    the threshold defaults high and why the check is against the whitelist
    rather than against grammar: the misread has to land on a plate that is
    actually registered at this site.

    Set ``enabled: false`` to keep every read on the slow path; the escalation
    saving goes with it, because the two are the same early exit.

    .. deprecated::
       These two settings now live on :class:`VotingConfig` as
       ``voting.fast_path_enabled`` and ``voting.fast_path_confidence``, next
       to the ``min_votes`` they short-circuit. This section is still read so
       an existing ``config.yaml`` (or an ``LPR_FAST_PATH__*`` environment
       variable) keeps working: :meth:`Settings._merge_legacy_fast_path` copies
       it onto ``voting`` *only* when the operator has not set the newer keys,
       so there is exactly one value in play at runtime and it is never the
       stale one.
    """

    #: Whether the early exit is armed at all.
    enabled: bool = True
    #: How confident the running vote must be before the gate may open on it.
    #: Floored at ``ocr.min_confidence`` in the orchestrator: a fast path that
    #: accepted reads the ordinary path would discard would be a downgrade in
    #: accuracy wearing the word "optimisation".
    min_confidence: float = Field(default=0.9, ge=0.0, le=1.0)


class VotingConfig(BaseModel):
    """Multi-frame consensus, and how long a confirmed plate stays confirmed.

    Sliding-gate deployments
    ------------------------
    ``cooldown_s`` is the setting that matters for an electric sliding gate
    (*yana kayar kapı*), and it matters for a reason that does not apply to an
    arm barrier. A sliding-gate motor is usually driven by **step-by-step pulse
    logic**: pulse 1 opens, pulse 2 *stops mid-travel*, pulse 3 closes. The
    cycle takes 15-25 seconds.

    A car waiting at the camera is read on every pass of the pipeline. Without
    a cooldown longer than the gate's travel time, the second confirmation of
    the *same plate* sends a second pulse into a gate that is still opening --
    and the driver watches it stop halfway. The default is therefore 20.0 s,
    chosen to cover a typical full open cycle rather than to be a round number.

    Tune it to your own gate: time the motor from closed to fully open and set
    this at or just above that. Too short re-triggers mid-travel; too long only
    delays a legitimate second entry by the same vehicle, which is the far
    cheaper mistake.

    An arm barrier has no such constraint -- its pulse is idempotent and the
    cycle is ~2 s -- so a barrier site can safely run this down at 3-5 s.
    """

    window: int = 5
    #: Reads that must agree inside the live window before the barrier moves.
    #:
    #: Two, not three. The third vote was buying less than it looked: by the
    #: time two reads inside ``ttl_s`` agree on a grammatical plate -- after
    #: the positional repair in :mod:`lpr.ocr.normalize` and the near-miss
    #: merge in :mod:`lpr.ocr.voting` -- a third read almost never changes the
    #: answer, it just costs another pass of the detector's ``frame_stride``
    #: and leaves a car sitting at a closed gate. What actually guards against
    #: a misread is that the plate has to be *registered*; agreement between
    #: frames is the cheaper, secondary check.
    min_votes: int = 2
    ttl_s: float = 4.0
    #: How long a confirmed plate is suppressed on the same camera. See the
    #: class docstring: on a sliding gate this must exceed the motor's travel
    #: time, or the second confirmation stops the gate mid-open.
    cooldown_s: float = 20.0
    #: OCR passes one tracked plate may cost before it is muted for
    #: ``cooldown_s``. 0 disables the cap (every visible plate is re-read until
    #: it confirms). Only applies when ``detection.track`` is on.
    max_track_attempts: int = 12
    #: How long a track's state survives after the plate was last seen.
    track_ttl_s: float = 30.0
    #: Arm the single-frame early exit for already-registered plates. See
    #: :class:`FastPathConfig` for what is being traded.
    fast_path_enabled: bool = True
    #: How confident that single read must be. Floored at ``ocr.min_confidence``
    #: in the orchestrator: a fast path that accepted reads the ordinary path
    #: would discard would be a downgrade in accuracy wearing the word
    #: "optimisation".
    fast_path_confidence: float = Field(default=0.82, ge=0.0, le=1.0)


class RelayConfig(BaseModel):
    """The dry-contact gate relay.

    Sliding-gate deployments
    ------------------------
    ``pulse_ms`` is a **momentary dry-contact closure**, not a hold. The relay
    closes the circuit for this long and opens it again; the motor controller
    reads that closure as one press of its own button. 1000 ms is the default
    because it is comfortably above the debounce window of every step-by-step
    controller in common use, while staying short enough that the controller
    cannot read it as a held button (which some units treat as a separate
    "hold to run" mode).

    Do not raise this to try to keep a sliding gate open longer -- it has no
    such effect. The gate's open duration is set on the motor controller, not
    here. What governs re-triggering from this side is
    ``voting.cooldown_s``; see :class:`VotingConfig`.
    """

    enabled: bool = True
    #: Which driver to use. ``serial`` (the default, a USB/RS-232 board),
    #: ``gpio`` (a Raspberry Pi pin), ``modbus`` (an RTU or TCP coil),
    #: ``http`` (a networked IP relay), or ``mock``.
    #:
    #: ``auto`` keeps the historical behaviour: serial when a port resolves,
    #: mock otherwise. That fallback is convenient for a bench and dangerous on
    #: a site -- see ``require_hardware``.
    driver: str = "auto"
    #: Refuse to fall back to MockRelay. With this on, a relay that cannot be
    #: opened is a loud failure at start-up instead of a gate that logs every
    #: plate as "granted" while no barrier moves.
    #:
    #: Off by default so a developer's checkout still runs, and turned on by
    #: every real deployment. ``LPR_ENV=production`` turns it on regardless.
    require_hardware: bool = False
    port: str = "auto"
    baud: int = 9600
    open_byte: str = "A"
    close_byte: str = "a"
    #: Dry-contact closure length in milliseconds. One pulse = one button
    #: press at the motor controller.
    pulse_ms: int = 1000
    mock: bool = False

    @property
    def resolved_port(self) -> str | None:
        """The concrete serial device to open.

        ``port="auto"`` is resolved per-OS via ``platform_compat`` (first
        existing /dev/ttyUSB0 / ttyACM0 / serial0 on Linux, "COM3" on
        Windows). Any other value is returned unchanged.
        """
        if self.port == "auto":
            return default_serial_port()
        return self.port

    # -- GPIO -------------------------------------------------------------

    #: BCM pin number driven for a ``gpio`` relay.
    gpio_pin: int = Field(default=17, ge=0, le=63)
    #: True when the relay board closes on a LOW signal, which most cheap
    #: opto-isolated boards do. Getting this backwards holds the gate open for
    #: the life of the process instead of pulsing it, so it is explicit rather
    #: than guessed.
    gpio_active_low: bool = True

    # -- Modbus -----------------------------------------------------------

    #: ``rtu`` (serial) or ``tcp``.
    modbus_mode: str = "tcp"
    modbus_host: str = "192.168.1.100"
    modbus_port: int = Field(default=502, ge=1, le=65535)
    #: Slave/unit id on the bus.
    modbus_unit: int = Field(default=1, ge=0, le=247)
    #: Coil address toggled for one pulse.
    modbus_coil: int = Field(default=0, ge=0)

    # -- IP / HTTP relay ---------------------------------------------------

    #: URL hit to close the contact. ``{pulse_ms}`` in the string is
    #: substituted, which is what boards with a built-in timer want.
    http_open_url: str = ""
    #: URL hit to open it again. Blank means the board self-releases, which is
    #: the normal case for a timer board -- and then ``pulse_ms`` is set on the
    #: board, not here.
    http_close_url: str = ""
    http_method: str = "GET"
    http_timeout_s: float = Field(default=5.0, gt=0, le=60)
    #: Optional HTTP basic auth for the board's web interface.
    http_user: str = ""
    http_password: str = ""


class SmtpConfig(BaseModel):
    """Outbound email alerts, with the event snapshot attached.

    Off by default. Enabling it means the service reaches out to a third-party
    mail server on its own initiative and puts a **photograph of a vehicle** in
    the message, so it is worth being deliberate about two things:

    * ``password`` in a YAML file is a credential at rest. Prefer the
      environment variable ``LPR_SMTP__PASSWORD``, which overrides the file and
      keeps the secret out of the repository and out of any config backup.
    * The snapshot is personal data in most jurisdictions. Send it to a mailbox
      the site operator controls, not to a shared or personal address, and keep
      ``to_emails`` short.

    Nothing here throttles: the pipeline's own ``voting.cooldown_s`` already
    stops a car idling at the gate from re-deciding, so one refused vehicle
    produces one email rather than one per frame.
    """

    enabled: bool = False
    host: str = ""
    port: int = Field(default=587, ge=1, le=65535)
    user: str = ""
    password: str = ""
    #: Envelope sender. Falls back to ``user`` when blank, which is what most
    #: providers require anyway.
    from_email: str = ""
    to_emails: list[str] = Field(default_factory=list)
    #: A plate that is not on the list at all.
    notify_on_unauthorized: bool = True
    #: A plate that *is* on the list but flagged ``blocked``.
    notify_on_blacklisted: bool = True
    #: STARTTLS on a submission port (587). Set false only for an internal
    #: relay on 25 that does not offer TLS; port 465 is detected as implicit
    #: TLS and connects over SMTP_SSL regardless of this flag.
    use_tls: bool = True
    #: Seconds to wait on the SMTP conversation before giving up. A mail server
    #: that has gone away must not pin the sender thread.
    timeout_s: float = Field(default=15.0, gt=0, le=300)
    #: Bound on the pending-email queue. Full means the mail server cannot keep
    #: up with the gate; the oldest alert is dropped rather than the newest,
    #: because an operator wants the most recent refusal.
    queue_size: int = Field(default=64, ge=1, le=4096)

    @property
    def sender(self) -> str:
        """Envelope sender: ``from_email``, or ``user`` when it is blank."""
        return (self.from_email or self.user or "").strip()

    @property
    def recipients(self) -> list[str]:
        """Non-empty, whitespace-trimmed recipient list."""
        return [address.strip() for address in self.to_emails if address and address.strip()]

    @property
    def usable(self) -> bool:
        """True when the settings are complete enough to attempt a send.

        Checked before the worker thread is even started, so a half-filled
        configuration is one warning at startup rather than a failed connection
        per event for the life of the process.

        A configured ``user`` with no ``password`` counts as half-filled. That
        is the shape a deployment lands in after the credential is moved out of
        ``config.yaml`` and ``LPR_SMTP__PASSWORD`` has not been set in ``.env``
        yet -- every send would fail authentication, one per refused vehicle.
        An empty ``user`` is a different thing: an internal relay that wants no
        authentication at all, and that is left alone.
        """
        return self.enabled and not self.missing_fields

    @property
    def missing_fields(self) -> list[str]:
        """The settings that stand between this config and a working send.

        Named individually rather than answered as one boolean so the startup
        warning can say *which* key is empty. The failure this exists for is
        the quiet one: ``config.yaml`` ships ``user`` filled and ``password``
        blank, so a site that never set ``LPR_SMTP__PASSWORD`` gets a notifier
        that is switched on, reports no error, and sends nothing -- and the
        operator has no way to tell that from a gate nobody drove up to.

        Empty when ``enabled`` is false: an operator who turned e-mail off is
        not missing anything.
        """
        if not self.enabled:
            return []
        gaps: list[str] = []
        if not self.host.strip():
            gaps.append("host")
        if not self.sender:
            gaps.append("from_email")
        if not self.recipients:
            gaps.append("to_emails")
        # A configured user with no password is half-filled, and it is the
        # shape a deployment lands in once the credential moves out of
        # config.yaml. An *empty* user is a different thing -- an internal
        # relay that wants no authentication at all -- and is left alone.
        if self.user.strip() and not self.password:
            gaps.append("password")
        return gaps


class DatabaseConfig(BaseModel):
    path: str = "data/plates.db"
    log_retention_days: int = 10


class SnapshotsConfig(BaseModel):
    """Event snapshots: one JPEG per gate decision, on a rolling window.

    Retention has three limits and the tightest one wins. Age alone is not
    enough: ``retention_days`` bounds *how old* the evidence gets, not how much
    of it there is, and a busy site produces far more of it than a quiet one.
    A gate handling a few thousand vehicles a day writes tens of gigabytes
    inside a ten-day window.

    That matters more than a full disk usually does, because of what fills up
    with it. The snapshot directory and the SQLite database normally share a
    volume, so the disk that snapshots fill is the disk the gate log is written
    to -- and SQLite writes start failing. The barrier keeps working and stops
    being able to say what it did, which is the one failure an operator cannot
    reconstruct afterwards.
    """

    enabled: bool = True
    #: Empty means ``<app.data_dir>/snapshots``. Set an absolute (or
    #: cwd-relative) path to put the images -- which grow far faster than the
    #: database -- on another disk.
    dir: str = ""
    #: Days of evidence to keep. Matches ``database.log_retention_days`` by
    #: default so an image and its log row expire together.
    retention_days: int = 10
    jpeg_quality: int = 85
    #: Frames awaiting encoding. Beyond this the writer drops rather than
    #: letting a slow disk push back on the recognition threads.
    queue_size: int = 64
    #: Total size ceiling for the snapshot directory, in megabytes. 0 disables
    #: it and leaves age as the only limit. Enforced oldest-first, so what
    #: survives is always the most recent evidence -- which is what an
    #: operator investigating an incident is looking for.
    max_total_mb: int = Field(default=20_000, ge=0)
    #: Keep at least this many megabytes free on the snapshot volume. 0
    #: disables the check.
    #:
    #: Distinct from ``max_total_mb`` and not redundant with it: the size
    #: ceiling bounds what *this* service writes, while the free-space floor
    #: notices the disk filling for any other reason -- logs, a database that
    #: grew, another service on the same volume -- and still protects the gate
    #: log by giving back space.
    min_free_mb: int = Field(default=2_000, ge=0)

    @property
    def max_total_bytes(self) -> int:
        return int(self.max_total_mb) * 1024 * 1024

    @property
    def min_free_bytes(self) -> int:
        return int(self.min_free_mb) * 1024 * 1024


class AntiPassbackConfig(BaseModel):
    """Refuse a second entry for a vehicle that never logged an exit.

    The abuse this stops is the oldest one in access control: a resident drives
    in, hands their car (or their plate) to somebody at the kerb, and a second
    vehicle enters on the same permit. Nothing in the plate list can see it --
    the plate is genuinely registered both times.

    **This never blocks an exit.** Not as a policy choice, as a safety rule: a
    vehicle that cannot leave is a vehicle trapped behind a barrier, and in a
    fire that is the failure that matters. The rule is only ever consulted at
    the entry camera, and :meth:`~lpr.pipeline.orchestrator.PipelineOrchestrator.decide`
    is written so an exit cannot reach it.

    It also needs both cameras to be fitted. On the single-camera site the
    shipped config describes, no exit is ever recorded, so every vehicle would
    look permanently inside and its second visit would be refused -- which is
    why this is off by default and why the orchestrator says so at start-up
    rather than silently doing nothing.
    """

    enabled: bool = False
    #: How long a vehicle is considered inside without an exit.
    #:
    #: A missed exit read -- a plate obscured by a following car, a camera
    #: cleaning its lens -- must not strand a resident for ever, so the state
    #: expires. 12 hours covers a working day and clears overnight, which is
    #: the shape of an office or residential site. A long-stay car park wants
    #: this longer; a retail one wants it shorter.
    window_s: float = Field(default=43_200.0, gt=0)
    #: Master override. Turning this on suspends the rule without losing its
    #: configuration -- for an event, an evacuation, or an operator working
    #: through a queue of vehicles the system has got wrong.
    #:
    #: Separate from ``enabled`` on purpose: an operator flipping this in a
    #: hurry must not have to remember what the site's settings were in order
    #: to put them back.
    emergency_bypass: bool = False
    #: Plates the rule never applies to: service vehicles, the site manager,
    #: anything that legitimately comes and goes without a clean pairing.
    exempt_plates: list[str] = Field(default_factory=list)

    @property
    def exempt(self) -> frozenset[str]:
        """``exempt_plates`` normalised the way the database stores plates."""
        return frozenset(
            "".join(str(plate).split()).upper()
            for plate in self.exempt_plates
            if str(plate).strip()
        )


class ParkingConfig(BaseModel):
    """Site capacity, used for the "vehicles inside / capacity" counter."""

    #: Default only. An admin can change it at runtime through
    #: ``PUT /api/parking``, which stores the value in the ``system_meta``
    #: table so every browser and tablet on the site agrees on one number.
    capacity: int = Field(default=100, ge=0, le=100000)


class SystemUpdateConfig(BaseModel):
    """Remote over-the-air update (git pull + docker compose rebuild).

    **Off by default, deliberately.** Turning this on gives anyone holding an
    admin token the ability to make the host run whatever the configured git
    remote currently contains, and rebuilding the stack from inside it needs a
    mounted Docker socket, which is root on the host. That is an acceptable
    trade for a fleet you control and a terrible default for a product that
    ships to sites you do not.

    Note what is *not* here: nothing in this model is settable per-request. The
    remote, branch, working directory and compose file are operator
    configuration, so a stolen admin token cannot redirect the update at an
    attacker's repository -- it can only re-run the operator's own.
    """

    #: Master switch for POST /api/system/update. GET /api/system/version keeps
    #: working either way, so the UI can still show what is deployed.
    enabled: bool = False
    #: Working directory for the git and compose commands; the repo root.
    repo_dir: str = "."
    git_remote: str = "origin"
    git_branch: str = "main"
    compose_file: str = "docker/docker-compose.yml"
    #: Overlay compose files merged over ``compose_file``, in order, each
    #: passed as another ``-f``. Exactly what an operator would type by hand.
    #:
    #: This exists because an OTA rebuild is the one place a host-specific
    #: overlay gets silently dropped. The service is brought back up by this
    #: module, not by the operator, so anything they normally add on the
    #: command line -- most importantly ``docker-compose.cdi.yml``, which is
    #: what passes the GPU through on a Podman or CDI host -- has to be named
    #: here or every update quietly returns the site to CPU.
    compose_overrides: list[str] = Field(default_factory=list)
    #: Fetching is quick; building an ML image is not.
    git_timeout_s: float = Field(default=120.0, gt=0, le=3600)
    build_timeout_s: float = Field(default=900.0, gt=0, le=21600)
    #: Where the outcome is left for the container that comes up after the
    #: rebuild. Empty = ``<data_dir>/last_update.json``.
    state_file: str = ""

    #: Check the remote for new commits once a night. Read-only on its own:
    #: with ``auto_update`` off it only *reports* that an update is waiting,
    #: which is a safe thing to leave on.
    nightly_check: bool = True
    #: Install what the nightly check finds, unattended.
    #:
    #: Separate from ``enabled`` because they are different risks. A human
    #: pressing the button watches the result and updates one site; this
    #: updates the whole fleet at once with nobody looking, so a bad commit
    #: becomes a fleet-wide outage discovered by a phone call. Requires
    #: ``enabled`` as well -- both must be true.
    auto_update: bool = False
    #: Local wall-clock time of the nightly check. "Low traffic" is a property
    #: of the site's clock, not of UTC.
    check_hour: int = Field(default=3, ge=0, le=23)
    check_minute: int = Field(default=0, ge=0, le=59)
    #: Retention for the ``system_events`` audit rows.
    event_retention_days: int = Field(default=90, ge=0, le=3650)


class ApiConfig(BaseModel):
    """The HTTP service, and how long the sessions it issues last.

    Session length is per role because the two roles are used differently. An
    administrator manages the site from their own machine, where being logged
    out mid-task is friction with no security payoff; an operator logs in on a
    shared terminal at the gate, where a session outliving the shift is the
    actual risk.

    Note what a long admin session costs. These are stateless JWTs, so the only
    thing that ends one early is the account being deleted --
    :func:`lpr.api.security.current_user` re-checks that on every request
    precisely because ``admin_token_ttl_min`` defaults to a year. A stolen
    laptop with a live token is otherwise good for that year, so shorten this
    if administrators sign in from machines you do not control.
    """

    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    #: Fallback session length, for a role with no policy of its own.
    token_ttl_min: int = 720
    #: Administrators: 365 days, i.e. "stays logged in".
    admin_token_ttl_min: int = Field(default=525_600, ge=1, le=1_051_200)
    #: Operators: 8 hours, i.e. one shift.
    operator_token_ttl_min: int = Field(default=480, ge=1, le=1_051_200)
    secret_key: str = "change-me"


class SecurityConfig(BaseModel):
    password_hasher: str = "argon2"


# ---------------------------------------------------------------------------
# YAML source
# ---------------------------------------------------------------------------


def _default_config_yaml_path() -> Path:
    """Locate ``config.yaml``.

    Honours ``LPR_CONFIG_FILE`` if set, otherwise assumes the conventional
    layout: this file lives at ``<repo-root>/src/lpr/config.py`` (or, in the
    container image, ``/app/src/lpr/config.py`` next to ``/app/config.yaml``)
    so the repo/app root is two parents up. Falls back to
    ``<cwd>/config.yaml`` if that guess doesn't exist.
    """
    env_path = os.environ.get("LPR_CONFIG_FILE")
    if env_path:
        return Path(env_path)

    guess = Path(__file__).resolve().parents[2] / "config.yaml"
    if guess.exists():
        return guess

    return Path.cwd() / "config.yaml"


def _default_env_file_path() -> Path:
    """Locate ``.env``, by the same rules as :func:`_default_config_yaml_path`.

    Resolved from the repo root rather than the working directory, because the
    working directory is not something an operator thinks about. ``lpr-api``
    started from a systemd unit, or from ``/``, has to find the same ``.env``
    that ``make run-api`` finds from the checkout -- otherwise the secret is
    present or absent depending on where the process happened to be launched,
    which is the hardest class of configuration bug to see.

    Honours ``LPR_ENV_FILE`` for a file kept outside the checkout entirely,
    which is what a site putting secrets under ``/etc`` wants.
    """
    env_path = os.environ.get("LPR_ENV_FILE")
    if env_path:
        return Path(env_path)

    guess = Path(__file__).resolve().parents[2] / ".env"
    if guess.exists():
        return guess

    return Path.cwd() / ".env"


class _YamlSettingsSource(PydanticBaseSettingsSource):
    """Reads the whole YAML document as the base layer of settings.

    Missing file -> empty layer (defaults / env still apply). This is a
    hand-rolled source (rather than relying on a specific pydantic-settings
    minor version's built-in YAML source) so behaviour stays stable across
    the pinned dependency range.
    """

    def __init__(self, settings_cls: type[BaseSettings], yaml_path: Path) -> None:
        super().__init__(settings_cls)
        self._yaml_path = yaml_path

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        # Required by the abstract base; unused because __call__ is overridden
        # to return the full parsed document in one shot.
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        if not self._yaml_path.exists():
            return {}
        with self._yaml_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# Root settings
# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LPR_",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    app: AppConfig = Field(default_factory=AppConfig)
    cameras: CamerasConfig = Field(default_factory=CamerasConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    preprocess: PreprocessConfig = Field(default_factory=PreprocessConfig)
    ocr: OcrConfig = Field(default_factory=OcrConfig)
    voting: VotingConfig = Field(default_factory=VotingConfig)
    fast_path: FastPathConfig = Field(default_factory=FastPathConfig)
    relay: RelayConfig = Field(default_factory=RelayConfig)
    smtp: SmtpConfig = Field(default_factory=SmtpConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    snapshots: SnapshotsConfig = Field(default_factory=SnapshotsConfig)
    parking: ParkingConfig = Field(default_factory=ParkingConfig)
    anti_passback: AntiPassbackConfig = Field(default_factory=AntiPassbackConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    #: HMAC secret for **per-operator** licence keys, from ``LPR_LICENSE_SECRET``.
    #:
    #: Distinct from the deployment licence in :mod:`lpr.license`, which is
    #: RS256 against a vendor public key and gates the *installation*. These
    #: keys are signed and verified by this server for its own operators, so a
    #: shared secret is the right shape and no private key ever leaves the box.
    #:
    #: Empty disables per-operator licensing entirely -- see
    #: :func:`lpr.user_license.enforcement_enabled`. That default is deliberate:
    #: an upgrade must not lock every operator out of a working gate because a
    #: new secret had not been set yet.
    license_secret: str = ""
    system_update: SystemUpdateConfig = Field(default_factory=SystemUpdateConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # The FIRST source in this tuple has the HIGHEST priority.
        # So: init args > env > .env > yaml > secrets.
        #
        # Both file-backed sources are rebuilt here rather than taken from the
        # arguments. `model_config` is evaluated once at class-definition time,
        # so a path baked in there would freeze whatever LPR_ENV_FILE happened
        # to say at import; resolving per instantiation keeps the two file
        # sources behaving identically and keeps them testable.
        #
        # In particular `dotenv_settings` as passed in reads nothing at all:
        # it is constructed from `model_config`, which names no env_file. That
        # is why a `.env` in the repo root was inert on a host run while
        # working under Compose -- Compose injects the same file as real
        # environment variables, so only the host path was broken, and only
        # for whoever had not exported the variable by hand.
        yaml_source = _YamlSettingsSource(settings_cls, _default_config_yaml_path())
        env_file_source = DotEnvSettingsSource(
            settings_cls,
            env_file=_default_env_file_path(),
            env_file_encoding="utf-8",
        )
        return (
            init_settings,
            env_settings,
            env_file_source,
            yaml_source,
            file_secret_settings,
        )

    @model_validator(mode="after")
    def _merge_legacy_fast_path(self) -> "Settings":
        """Fold a legacy ``fast_path:`` section onto ``voting``.

        The fast path used to be its own top-level section. It reads better
        beside the ``voting.min_votes`` it exists to skip, so it moved -- but a
        deployment upgrading in place still has the old section in its
        ``config.yaml``, and silently ignoring it would re-arm an early exit
        the operator had deliberately switched off.

        The newer keys win whenever they were actually written down;
        ``model_fields_set`` is what distinguishes "the operator chose 0.82"
        from "nobody said, so it defaulted to 0.82". Only when they are absent
        does the legacy value carry over. Nothing is copied the other way: one
        direction means ``voting`` is the single value the pipeline reads.
        """
        legacy = self.fast_path.model_fields_set
        chosen = self.voting.model_fields_set
        if "enabled" in legacy and "fast_path_enabled" not in chosen:
            self.voting.fast_path_enabled = self.fast_path.enabled
        if "min_confidence" in legacy and "fast_path_confidence" not in chosen:
            self.voting.fast_path_confidence = self.fast_path.min_confidence
        return self

    @model_validator(mode="after")
    def _check_secret_key_in_production(self) -> "Settings":
        is_production = os.environ.get("LPR_ENV", "").strip().lower() == "production"
        if self.app.headless and is_production and self.api.secret_key == "change-me":
            raise ValueError(
                "api.secret_key is still the default 'change-me'. Set it via "
                "config.yaml (api.secret_key) or the LPR_API__SECRET_KEY "
                "environment variable before running with LPR_ENV=production."
            )
        return self

    @property
    def paths(self) -> "ResolvedPaths":
        """Absolute, existing paths derived from ``app.*`` and ``database.path``.

        Directories are created (mkdir -p) the first time each attribute is
        accessed, so a fresh checkout / fresh container volume works without
        a separate provisioning step.
        """
        return ResolvedPaths(self)


class ResolvedPaths:
    """Lazily resolves config-relative paths to absolute ``Path`` objects.

    Relative paths are resolved against the current working directory,
    which in the container is ``/app`` (WORKDIR) and in local dev is
    expected to be the repo root.
    """

    __slots__ = ("_settings",)

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def data_dir(self) -> Path:
        p = Path(self._settings.app.data_dir).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def models_dir(self) -> Path:
        p = Path(self._settings.app.models_dir).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def ocr_models_dir(self) -> Path:
        """Where the OCR backend caches its weights; ``<models_dir>/easyocr``.

        Derived from ``models_dir`` rather than from ``$HOME`` so the weights
        land on the same bind-mounted volume as the detector's, and survive
        container recreation. Overridable with ``ocr.model_dir`` for a shared
        read-only model store.
        """
        configured = str(getattr(self._settings.ocr, "model_dir", "") or "").strip()
        p = Path(configured).expanduser().resolve() if configured else self.models_dir / "easyocr"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def database(self) -> Path:
        p = Path(self._settings.database.path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def snapshots_dir(self) -> Path:
        """Where event snapshots are written; ``<data_dir>/snapshots`` by default.

        Derived from ``data_dir`` rather than hard-coded so that anything
        repointing the data directory -- a test fixture, a container volume --
        moves the images with it.
        """
        configured = str(self._settings.snapshots.dir).strip()
        p = Path(configured).expanduser().resolve() if configured else self.data_dir / "snapshots"
        p.mkdir(parents=True, exist_ok=True)
        return p


# ---------------------------------------------------------------------------
# Cached accessors
# ---------------------------------------------------------------------------


#: ``LPR_`` variables that are deliberately not settings fields.
#:
#: Some are read straight from the environment by a module that runs before, or
#: independently of, ``Settings`` (``LPR_ENV`` gates production checks in two
#: places; ``LPR_LICENSE_PUBLIC_KEY`` is read by :mod:`lpr.license`). The rest
#: are consumed by Compose itself and never reach Python at all. Both kinds
#: have to be listed, or :func:`unknown_env_names` reports the whole deployment
#: as misconfigured and the warning becomes something people learn to ignore.
_NON_FIELD_ENV_NAMES: frozenset[str] = frozenset(
    {
        # read directly from os.environ by application code
        "LPR_ENV",
        "LPR_CONFIG_FILE",
        "LPR_ENV_FILE",
        "LPR_API_DOCS",
        "LPR_LICENSE_PUBLIC_KEY",
        # consumed by docker compose, never by the application
        "LPR_BIND",
        "LPR_PORT",
        "LPR_VIDEO_GID",
        "LPR_DOCKER_GID",
        "LPR_DOCKER_SOCK",
        "LPR_MEM_LIMIT",
        "LPR_DOMAIN",
        "LPR_ACME_EMAIL",
    }
)


def _field_env_names(model: type[BaseModel], prefix: str = "LPR_") -> set[str]:
    """Every ``LPR_``-prefixed variable name this model would accept."""
    names: set[str] = set()
    for field_name, field in model.model_fields.items():
        env_name = f"{prefix}{field_name.upper()}"
        names.add(env_name)
        annotation = field.annotation
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            names |= _field_env_names(annotation, f"{env_name}__")
    return names


def unknown_env_names() -> list[str]:
    """``LPR_`` names, from the environment or ``.env``, that configure nothing.

    ``Settings`` is declared ``extra="ignore"``, which is the right behaviour
    for a process whose environment it does not own -- but it means a typo, or
    a plausible-looking name that is not the field's actual name, is discarded
    in silence. ``LPR_SMTP__TO_ADDRS`` is the shape this takes in practice: it
    reads like the setting it is meant to be, the field is called ``to_emails``,
    and the alerts keep going to whatever address ``config.yaml`` last named.

    Reported rather than rejected. An unknown name is far more often a stale
    line in an old ``.env`` than an emergency, and refusing to start a gate
    over one would be the more expensive mistake.
    """
    known = _field_env_names(Settings) | _NON_FIELD_ENV_NAMES

    candidates: set[str] = {name for name in os.environ if name.startswith("LPR_")}

    env_file = _default_env_file_path()
    if env_file.is_file():
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:  # pragma: no cover - unreadable .env is its own problem
            text = ""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name = line.split("=", 1)[0].strip().removeprefix("export ").strip()
            if name.startswith("LPR_"):
                candidates.add(name)

    return sorted(name for name in candidates if name not in known)


def warn_about_unknown_env_names() -> list[str]:
    """Log one warning naming every ``LPR_`` variable that configures nothing."""
    unknown = unknown_env_names()
    if unknown:
        logger.warning(
            "Bu ortam değişkenleri hiçbir ayara karşılık gelmiyor ve yok sayıldı: "
            "%s. Ad birebir eşleşmelidir (örn. smtp.to_emails -> "
            "LPR_SMTP__TO_EMAILS); yakın bir yazım sessizce göz ardı edilir ve "
            "ayar config.yaml'daki değerinde kalır.",
            ", ".join(unknown),
        )
    return unknown


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide ``Settings`` singleton, building it on first call.

    Use ``reload_settings()`` (not a second ``get_settings()`` call) to pick
    up changed environment variables or a rewritten ``config.yaml``.
    """
    settings = Settings()
    warn_about_unknown_env_names()
    return settings


def reload_settings() -> Settings:
    """Clear the cached ``Settings`` and rebuild it from current sources."""
    get_settings.cache_clear()
    return get_settings()
