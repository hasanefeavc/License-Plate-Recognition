"""OCR backends.

Two interchangeable implementations of the :class:`~lpr.contracts.Recognizer`
protocol, EasyOCR and PaddleOCR, selected by ``settings.ocr.backend``. Both
share the same strategy, which is where the accuracy comes from:

1. Build several views of the same crop -- CLAHE'd and sharpened grayscale, an
   adaptive-threshold binarisation, and a deskewed version. These fail in
   different ways, so a plate that one view garbles another usually reads
   cleanly. While the best read so far is missing or unconvincing, escalate
   through two further stages: a perspective-corrected copy of the crop, which
   recovers a plate photographed from the side, and then Otsu-binarised and
   polarity-inverted views, which recover the dark and IR-lit night crops.
   Both later stages are skipped entirely on the plates the cheap views
   already read, so the common case costs what it always did.

   "Unconvincing" is a confidence floor, not just a grammar check
   (``preprocess.escalate_below_confidence``). A grammatical read at 0.3 used
   to end the search, and the pipeline would then reject it for being under
   ``ocr.min_confidence`` -- so the crop was discarded without ever being shown
   the views most likely to save it.
2. Run the recogniser over every view, parse *each* text fragment as well as
   the concatenation of them (plates are frequently split into two boxes at
   the province/letters boundary).
3. Pool every candidate from every view into one confidence-weighted vote
   (:mod:`lpr.ocr.ensemble`). Candidates are normalised through
   :func:`lpr.ocr.normalize.normalize_plate`, grouped by the plate string they
   produce, and each group scores the sum of its members' confidences -- so
   agreement across views outranks any single view's certainty, while a
   grammatical read still always beats an ungrammatical one.

Both backends are imported lazily inside ``__init__`` so that importing this
module never drags in torch or paddle, and both **always return a PlateRead**;
failures surface as ``valid=False`` rather than exceptions or ``None``, because
a single unreadable frame is normal operation, not an error.

``settings.ocr.min_confidence`` is deliberately *not* applied here. This layer
reports what it saw as faithfully as it can; the pipeline owns the accept/
reject threshold, and the voter owns the "was it seen repeatedly" question.
"""

from __future__ import annotations

import contextlib
import inspect
import logging
import socket
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np

from lpr.accel import resolve_gpu_flag
from lpr.contracts import PlateRead
from lpr.detect.preprocess import (
    TIGHT_FONT_KERNEL,
    UNSHARP_AMOUNT,
    deskew,
    enhance_plate,
    hard_case_variants,
    rectify_perspective,
)
from lpr.ocr.ensemble import Ballot, vote

if TYPE_CHECKING:
    from lpr.config import Settings

logger = logging.getLogger(__name__)

__all__ = ["EasyOcrRecognizer", "PaddleOcrRecognizer"]


def _synthetic_crop() -> np.ndarray:
    """A small blank BGR crop, used to warm the backends up."""
    return np.full((64, 200, 3), 255, dtype=np.uint8)


@contextlib.contextmanager
def _bounded_sockets(timeout_s: float) -> Iterator[None]:
    """Give every socket opened in this block a deadline, then restore.

    EasyOCR fetches its weights through ``urllib.request.urlretrieve`` with no
    timeout argument, so the only lever that reaches it is the process-wide
    default. Without one, a connection that is accepted and then goes silent --
    a captive portal, a dropped VPN, a NAT that blackholes instead of
    resetting -- parks the service inside ``Reader.__init__`` indefinitely:
    past the compose healthcheck's start period, with the last log line being
    "initialising EasyOCR" and nothing after it.

    Scoped to the constructor and restored in a ``finally`` because this *is* a
    global: the API's own sockets must not inherit it. Nothing else is
    connecting yet at this point in startup -- the pipeline is built before the
    server begins serving.
    """
    if timeout_s <= 0:
        yield
        return
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_s)
    try:
        yield
    finally:
        socket.setdefaulttimeout(previous)


def _usable(images: list[np.ndarray | None]) -> list[np.ndarray]:
    """Drop anything that is not a non-empty array."""
    return [img for img in images if isinstance(img, np.ndarray) and img.size > 0]


def _crop_variants(
    crop: np.ndarray,
    unsharp_amount: float = UNSHARP_AMOUNT,
    normalize_light: bool = True,
    tight_font: bool = True,
    tight_font_kernel: tuple[int, int] = TIGHT_FONT_KERNEL,
) -> list[np.ndarray]:
    """Grayscale, binarised, de-bridged and deskewed views of one plate crop."""
    enhanced = enhance_plate(
        crop,
        unsharp_amount=unsharp_amount,
        normalize_light=normalize_light,
        tight_font=tight_font,
        tight_font_kernel=tight_font_kernel,
    )
    variants: list[np.ndarray | None] = list(enhanced.variants)
    straightened = deskew(enhanced.gray)
    if straightened is not enhanced.gray:
        variants.append(straightened)
    return _usable(variants)


def _rectified_variants(
    crop: np.ndarray,
    unsharp_amount: float = UNSHARP_AMOUNT,
    normalize_light: bool = True,
    tight_font: bool = True,
    tight_font_kernel: tuple[int, int] = TIGHT_FONT_KERNEL,
) -> list[np.ndarray]:
    """Perspective-corrected views of one plate crop, or ``[]`` if it has none.

    Rectification finds the plate's four-corner outline and warps it back to a
    head-on rectangle, which is the one correction :func:`deskew` cannot make:
    deskew rotates, and a plate photographed from the side needs its
    foreshortened far edge stretched, not turned. Running the standard
    enhancement over the flattened crop afterwards gives the recogniser the
    same grayscale/binarised pair it gets on the first pass.
    """
    flattened = rectify_perspective(crop)
    if flattened is None:
        return []
    enhanced = enhance_plate(
        flattened,
        unsharp_amount=unsharp_amount,
        normalize_light=normalize_light,
        tight_font=tight_font,
        tight_font_kernel=tight_font_kernel,
    )
    return _usable(list(enhanced.variants))


def _fallback_variants(
    crop: np.ndarray,
    unsharp_amount: float = UNSHARP_AMOUNT,
    normalize_light: bool = True,
) -> list[np.ndarray]:
    """Otsu and polarity-inverted views, for a crop the earlier stages failed.

    These are the two failure modes the standard pass cannot serve. A
    uniformly dark night crop defeats the adaptive threshold, which decides per
    neighbourhood and so thresholds flat noise against itself; Otsu takes one
    global cut instead. And a plate under an IR illuminator comes back with its
    polarity reversed -- bright field, dark glyphs inverted to the opposite of
    what both recognisers were trained on -- which only an inverted copy fixes.

    Built from the *enhanced* grayscale rather than the raw crop, so the
    exposure normalisation and CLAHE that precede them still apply.
    """
    enhanced = enhance_plate(crop, unsharp_amount=unsharp_amount, normalize_light=normalize_light)
    return _usable(list(hard_case_variants(enhanced.gray)))


def _weighted_confidence(fragments: list[tuple[str, float]]) -> float:
    """Character-weighted mean confidence over the fragments of one read.

    Backends score whole detections, not characters. Weighting each score by
    its fragment length approximates a per-character average, so a confident
    two-character fragment cannot outweigh a shaky six-character one.
    """
    total_chars = sum(len(text) for text, _ in fragments)
    if total_chars <= 0:
        return 0.0
    weighted = sum(conf * len(text) for text, conf in fragments)
    return max(0.0, min(1.0, weighted / total_chars))


class _BaseRecognizer:
    """Shared candidate-selection logic for the concrete backends."""

    #: Overridden per instance from ``settings.preprocess`` by each backend's
    #: ``__init__``. Class-level defaults keep the base class usable on its own,
    #: which is what the tests subclass.
    _unsharp_amount: float = UNSHARP_AMOUNT
    _rectify_enabled: bool = True
    _normalize_light: bool = True
    _hard_cases_enabled: bool = True
    _escalate_below: float = 0.5
    _tight_font: bool = True
    _tight_font_kernel: tuple[int, int] = TIGHT_FONT_KERNEL

    def _configure_preprocessing(self, settings: Settings) -> None:
        """Read the crop-preprocessing knobs off ``settings``.

        ``getattr`` throughout, so a Settings object predating the
        ``preprocess`` section (or a test double standing in for one) keeps the
        built-in defaults instead of raising.
        """
        cfg = getattr(settings, "preprocess", None)
        self._unsharp_amount = float(getattr(cfg, "crop_unsharp_amount", UNSHARP_AMOUNT))
        self._rectify_enabled = bool(getattr(cfg, "rectify_perspective", True))
        self._normalize_light = bool(getattr(cfg, "normalize_lighting", True))
        self._hard_cases_enabled = bool(getattr(cfg, "hard_case_variants", True))
        self._escalate_below = float(getattr(cfg, "escalate_below_confidence", 0.5))
        self._tight_font = bool(getattr(cfg, "tight_font_variant", True))
        kernel = getattr(cfg, "tight_font_kernel", None) or TIGHT_FONT_KERNEL
        try:
            self._tight_font_kernel = (int(kernel[0]), int(kernel[1]))
        except (TypeError, ValueError, IndexError):
            self._tight_font_kernel = TIGHT_FONT_KERNEL

    def _read_fragments(self, image: np.ndarray) -> list[tuple[str, float]]:  # pragma: no cover
        raise NotImplementedError

    def recognize(
        self, crop: np.ndarray, accept: Callable[[PlateRead], bool] | None = None
    ) -> PlateRead:
        """Best plate read for ``crop``; ``valid=False`` when nothing parses.

        The verdict is a confidence-weighted vote across every view that read
        anything (:func:`lpr.ocr.ensemble.vote`), not the single highest-scoring
        candidate. Which glyphs a view confuses depends on the view -- ``0``/``O``
        flips with the binarisation threshold, ``8``/``B`` with the sharpening --
        so agreement between views is stronger evidence than any one view's
        confidence, and an over-confident outlier can no longer win outright.

        ``accept`` is the caller's early exit: see :meth:`ballots`.
        """
        return vote(self.ballots(crop, accept=accept))

    def ballots(
        self, crop: np.ndarray, accept: Callable[[PlateRead], bool] | None = None
    ) -> list[Ballot]:
        """Every candidate string this recogniser can produce for ``crop``.

        Exposed alongside :meth:`recognize` so an
        :class:`~lpr.ocr.ensemble.EnsembleRecognizer` can pool the raw
        candidates of several engines into a single vote. Returning the
        verdicts instead would make the second engine a tie-breaker for the
        first rather than an equal voter.
        """
        if not isinstance(crop, np.ndarray) or crop.size == 0:
            return []

        ballots: list[Ballot] = []
        engine = type(self).__name__
        for stage_index, stage in enumerate(self._variant_stages(crop)):
            for view_index, image in enumerate(stage):
                ballots.extend(self._ballots_for(image, f"{engine}:s{stage_index}v{view_index}"))
                # The caller's early exit, checked per *view* rather than per
                # stage: the first stage is itself several OCR passes, and a
                # plate that read cleanly on the plain view should not pay for
                # the sharpened one. Only the caller can judge this -- the
                # recogniser knows how confident a read is, not whether the
                # string is a car that may come in -- so the predicate comes
                # from outside. Re-voting per view is string arithmetic against
                # an OCR pass, which is the cost this is here to avoid.
                if accept is not None and ballots and accept(vote(ballots)):
                    return ballots
            # Escalate only while the answer is still missing or unconvincing.
            # The later stages exist for the crops the cheap views could not
            # read; running them on a plate that already parsed confidently
            # would multiply the OCR cost of every ordinary car at the gate for
            # no gain.
            if ballots and self._is_settled(vote(ballots)):
                break

        return ballots

    def _is_settled(self, verdict: PlateRead) -> bool:
        """True when ``verdict`` is good enough to stop looking.

        Grammar alone is not enough. A read that parses as a plate but scores
        below ``preprocess.escalate_below_confidence`` is one the pipeline will
        discard anyway, so stopping on it spends the crop's last chance on
        nothing. Escalating instead costs an OCR pass on a crop that was
        heading for the bin, and every extra ballot also feeds the same vote --
        so a genuinely correct low-confidence read is more likely to be
        *confirmed* by the harder views than overturned by them.
        """
        if not verdict.valid:
            return False
        return verdict.confidence >= self._escalate_below

    def _variant_stages(self, crop: np.ndarray) -> Iterator[list[np.ndarray]]:
        """Views of ``crop`` to try, in order, cheapest and likeliest first.

        A generator rather than a list: the caller stops pulling as soon as it
        has a valid read, so a stage nobody asks for is never computed.
        """
        try:
            standard = _crop_variants(
                crop,
                self._unsharp_amount,
                self._normalize_light,
                self._tight_font,
                self._tight_font_kernel,
            )
        except Exception:
            logger.debug("crop preprocessing failed; using the raw crop", exc_info=True)
            standard = []
        yield standard or [crop]

        if self._rectify_enabled:
            try:
                rectified = _rectified_variants(
                    crop,
                    self._unsharp_amount,
                    self._normalize_light,
                    self._tight_font,
                    self._tight_font_kernel,
                )
            except Exception:
                logger.debug("perspective rectification failed for one crop", exc_info=True)
                rectified = []
            if rectified:
                logger.debug(
                    "%s: no usable read from the standard views, retrying perspective-corrected",
                    type(self).__name__,
                )
                yield rectified

        if not self._hard_cases_enabled:
            return
        try:
            fallback = _fallback_variants(crop, self._unsharp_amount, self._normalize_light)
        except Exception:
            logger.debug("hard-case variants failed for one crop", exc_info=True)
            return
        if fallback:
            logger.debug(
                "%s: still nothing usable, retrying Otsu and inverted views",
                type(self).__name__,
            )
            yield fallback

    def _ballots_for(self, image: np.ndarray, source: str) -> list[Ballot]:
        """Read one crop variant and turn its fragments into ballots."""
        try:
            fragments = self._read_fragments(image)
        except Exception:
            logger.debug("%s failed on one crop variant", type(self).__name__, exc_info=True)
            return []
        if not fragments:
            return []

        ballots: list[Ballot] = []
        # The joined fragments: a plate split across two boxes.
        joined = " ".join(text for text, _ in fragments if text)
        if joined:
            ballots.append(Ballot(joined, _weighted_confidence(fragments), f"{source}:joined"))
        # And each fragment on its own: the plate plus surrounding noise.
        for index, (text, conf) in enumerate(fragments):
            if text:
                ballots.append(Ballot(text, conf, f"{source}:f{index}"))
        return ballots

    def warmup(self) -> None:
        """Run one recognition on a synthetic crop to pay the lazy-init cost."""
        try:
            self.recognize(_synthetic_crop())
            logger.info("%s warmup complete", type(self).__name__)
        except Exception:
            logger.warning("%s warmup failed", type(self).__name__, exc_info=True)


#: Weight files EasyOCR needs for ``Reader(["en"])`` with the default networks.
#: Used only to decide whether the cache looks provisioned, so a missing entry
#: costs a log line, never a failure.
EASYOCR_WEIGHTS = ("craft_mlt_25k.pth", "english_g2.pth")


class EasyOcrRecognizer(_BaseRecognizer):
    """EasyOCR backend (satisfies ``Recognizer``).

    Three things happen in ``__init__`` beyond constructing the reader, and all
    three exist because this runs unattended at a gate:

    **The GPU decision is a probe, not a config read.** ``ocr.gpu`` defaults to
    ``"auto"`` and is resolved through :func:`lpr.accel.resolve_gpu_flag`, which
    launches a real kernel before answering yes. An explicit ``gpu: true`` on a
    box whose GPU turns out to be unusable is downgraded rather than obeyed,
    because ``Reader(gpu=True)`` raises when it cannot allocate and that
    exception propagates all the way out of ``build_pipeline``.

    **The weights live on a bind-mounted volume.** EasyOCR's default cache is
    ``~/.EasyOCR``, which in a container is a writable layer that
    ``docker compose up --build`` discards -- so every rebuild re-downloaded
    ~100 MB before the service could accept its first frame. Pointing
    ``model_storage_directory`` at ``models/easyocr`` (see
    :attr:`lpr.config.Paths.ocr_models_dir`) makes that a once-per-machine cost.

    **Startup cannot hang.** The download is bounded by
    :func:`_bounded_sockets`, and a fully provisioned cache disables the
    network path outright, so a gate box with a flaky uplink starts from disk
    and never waits on a socket at all.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        if settings is None:
            from lpr.config import get_settings

            settings = get_settings()
        self._settings = settings
        self._configure_preprocessing(settings)
        cfg = settings.ocr
        self.allowlist = cfg.allowlist
        self.width_ths = float(getattr(cfg, "width_ths", 0.5))
        self.gpu = resolve_gpu_flag(getattr(cfg, "gpu", "auto"))
        self.model_dir = self._resolve_model_dir(settings)

        try:
            import easyocr
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "easyocr is not installed but ocr.backend is 'easyocr'. Install "
                "it with `pip install -r requirements.txt` (or `pip install "
                "easyocr`), or set ocr.backend to 'paddleocr'."
            ) from exc

        self._reader = self._build_reader(easyocr, cfg)

    # -- construction helpers -------------------------------------------

    @staticmethod
    def _resolve_model_dir(settings: Settings) -> Path | None:
        """The weight cache directory, or ``None`` to leave EasyOCR's default.

        ``None`` only when the settings object has no ``paths`` helper -- which
        in practice means a test double, and those must not be forced to grow a
        filesystem just to construct a recogniser.
        """
        paths = getattr(settings, "paths", None)
        try:
            return Path(paths.ocr_models_dir)  # type: ignore[union-attr]
        except Exception:
            logger.debug("no OCR model directory available; using EasyOCR's default")
            return None

    def _cache_is_complete(self) -> bool:
        """True when every weight EasyOCR will ask for is already on disk."""
        if self.model_dir is None:
            return False
        return all((self.model_dir / name).is_file() for name in EASYOCR_WEIGHTS)

    def _reader_kwargs(self, cfg: Any) -> dict[str, Any]:
        """Keyword arguments for ``easyocr.Reader``, cache and network included.

        ``download_enabled`` is switched **off** once the cache is complete.
        EasyOCR would otherwise still stat and MD5 each file over the network
        path on every start; with it off, a provisioned box opens no socket at
        all, which is the difference between a gate that comes back after a
        power cut with the uplink down and one that does not.
        """
        cached = self._cache_is_complete()
        allow_download = bool(getattr(cfg, "allow_download", True)) and not cached
        kwargs: dict[str, Any] = {
            "gpu": self.gpu,
            "download_enabled": allow_download,
            "verbose": False,
        }
        if self.model_dir is not None:
            kwargs["model_storage_directory"] = str(self.model_dir)
            kwargs["user_network_directory"] = str(self.model_dir)

        if not cached and not allow_download:
            logger.warning(
                "EasyOCR weights are missing from %s and ocr.allow_download is false. "
                "Fetch them on the host with `python scripts/fetch_models.py --easyocr` "
                "(models/ is a bind-mounted volume), or set ocr.allow_download true.",
                self.model_dir,
            )
        return kwargs

    def _build_reader(self, easyocr: Any, cfg: Any) -> Any:
        """Construct the reader, on CPU if the GPU attempt does not survive.

        The CPU retry is not defensive padding. ``resolve_gpu_flag`` proves a
        kernel *launches*; it cannot prove the card has room for the detection
        and recognition networks alongside YOLO, and a 4 GB laptop card running
        both is genuinely close to the line. Falling back costs throughput;
        propagating would cost the gate.
        """
        kwargs = self._reader_kwargs(cfg)
        timeout_s = float(getattr(cfg, "download_timeout_s", 60.0) or 0.0)
        supported = self._supported_kwargs(easyocr.Reader, kwargs)

        logger.info(
            "initialising EasyOCR (gpu=%s, model_dir=%s, download_enabled=%s)",
            kwargs["gpu"],
            self.model_dir,
            kwargs["download_enabled"],
        )
        try:
            with _bounded_sockets(timeout_s):
                return easyocr.Reader(["en"], **supported)
        except Exception as exc:
            if not kwargs["gpu"]:
                raise RuntimeError(self._init_failure_message(exc)) from exc
            logger.warning("EasyOCR failed to initialise on the GPU (%s); retrying on CPU", exc)

        self.gpu = False
        supported["gpu"] = False
        try:
            with _bounded_sockets(timeout_s):
                return easyocr.Reader(["en"], **supported)
        except Exception as exc:
            raise RuntimeError(self._init_failure_message(exc)) from exc

    def _init_failure_message(self, exc: Exception) -> str:
        """Explain a failed reader construction in terms of what to do next."""
        return (
            f"EasyOCR could not initialise ({exc}). Its weights are cached in "
            f"{self.model_dir}; if that directory is empty the download did not "
            "complete -- run `python scripts/fetch_models.py --easyocr` on the host "
            "(models/ is a bind-mounted volume) and restart, or raise "
            "ocr.download_timeout_s if the link is merely slow."
        )

    @staticmethod
    def _supported_kwargs(reader_cls: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
        """Drop keywords this installed EasyOCR does not accept.

        ``user_network_directory`` and ``verbose`` arrived in different 1.x
        releases, and requirements.txt pins the whole ``>=1.7,<2`` range. A
        signature that cannot be inspected (a C extension, a test double) is
        assumed to take everything.
        """
        try:
            parameters = inspect.signature(reader_cls).parameters
        except (TypeError, ValueError):
            return dict(kwargs)
        if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
            return dict(kwargs)
        return {name: value for name, value in kwargs.items() if name in parameters}

    def _read_fragments(self, image: np.ndarray) -> list[tuple[str, float]]:
        # width_ths controls how eagerly EasyOCR glues horizontally adjacent
        # boxes into one before recognising them. Configurable because the
        # right value depends on the plate format at the site; see
        # ``OcrConfig.width_ths`` for which way it points.
        results = self._reader.readtext(
            image,
            allowlist=self.allowlist,
            detail=1,
            paragraph=False,
            width_ths=self.width_ths,
        )
        fragments: list[tuple[str, float]] = []
        for item in results or []:
            try:
                # (bbox, text, confidence)
                text = str(item[1])
                confidence = float(item[2]) if len(item) > 2 else 0.0
            except (IndexError, TypeError, ValueError):
                continue
            if text.strip():
                fragments.append((text, confidence))
        return fragments


class PaddleOcrRecognizer(_BaseRecognizer):
    """PaddleOCR backend (satisfies ``Recognizer``).

    PaddleOCR has no allowlist parameter, so the Turkish alphabet restriction
    is enforced downstream by :mod:`lpr.ocr.normalize` instead of at the
    decoder.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        if settings is None:
            from lpr.config import get_settings

            settings = get_settings()
        self._settings = settings
        self._configure_preprocessing(settings)

        try:
            from paddleocr import PaddleOCR
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "paddleocr is not installed but ocr.backend is 'paddleocr'. "
                "Install it with `pip install paddleocr paddlepaddle`, or set "
                "ocr.backend to 'easyocr'."
            ) from exc

        logger.info("initialising PaddleOCR")
        try:
            self._ocr = PaddleOCR(use_angle_cls=True, lang="en", show_log=False)
        except (TypeError, ValueError):
            # `show_log` was removed in newer paddleocr releases.
            self._ocr = PaddleOCR(use_angle_cls=True, lang="en")

    def _read_fragments(self, image: np.ndarray) -> list[tuple[str, float]]:
        try:
            results = self._ocr.ocr(image, cls=True)
        except TypeError:
            # Newer releases dropped the `cls` keyword.
            results = self._ocr.ocr(image)
        return _parse_paddle_result(results)


def _parse_paddle_result(results: Any) -> list[tuple[str, float]]:
    """Flatten PaddleOCR output into ``(text, confidence)`` pairs.

    The shape has changed across releases (``[[ [box, (text, conf)], ... ]]``,
    and a ``None`` page when nothing is found), so this walks the structure
    defensively rather than indexing blindly.
    """
    fragments: list[tuple[str, float]] = []
    if not results:
        return fragments
    for page in results:
        if not page:
            continue
        for line in page:
            try:
                payload = line[1]
                text = str(payload[0])
                confidence = float(payload[1])
            except (IndexError, TypeError, ValueError):
                continue
            if text.strip():
                fragments.append((text, confidence))
    return fragments
