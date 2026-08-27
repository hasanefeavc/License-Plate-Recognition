# 🚗 License Plate Recognition (LPR)

Turkish license-plate recognition for gate/barrier control. A headless FastAPI service
runs the vision pipeline in Docker; the Tkinter desktop app is now a thin client that
talks to it over HTTP + WebSocket.

Targets **Ubuntu 24.04 LTS** and **Windows 11**.

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   RTSP / USB    │  headless core  (Docker, no display needed)  │
   cameras ─────▶│                                              │
                 │  CameraWorker ──▶ YOLOv8n ──▶ EasyOCR ──▶     │
                 │   (1 thread     detect      recognise        │
                 │    per camera)                 │             │
                 │                                ▼             │
                 │                    normalise → multi-frame   │
                 │                       vote → decide          │
                 │                          │                   │
                 │            ┌─────────────┼─────────────┐     │
                 │            ▼             ▼             ▼     │
                 │        SQLite/WAL    relay thread   FastAPI  │
                 └────────────────────────────┬─────────────────┘
                                              │ HTTP + WS + MJPEG
                        ┌─────────────────────┴──────────────────┐
                        ▼                                        ▼
                 Tkinter client                            any other client
                 (lpr-gui)                                 (browser, mobile)
```

Every stage is decoupled through the protocols in `src/lpr/contracts.py`
(`Detector`, `Recognizer`, `Voter`, `Relay`), so the pipeline never imports a
concrete ML class and can be unit-tested with fakes and no GPU.

### Layout

```
src/lpr/
├── contracts.py        shared dataclasses + protocols (the integration seam)
├── config.py           pydantic-settings: config.yaml ← env (LPR_*) ← args
├── platform_compat.py  the ONLY place with sys.platform branching
├── logging_conf.py     human logs on a TTY, single-line JSON in the container
├── db/                 thread-local SQLite (WAL), repositories, legacy migrator
├── hardware/relay.py   queue-driven serial relay + MockRelay fallback
├── pipeline/           per-camera capture threads, orchestrator, DI factory
│   └── snapshots.py    one JPEG per gate decision, written off the hot path
├── detect/             YOLOv8n detector, contour fallback
│   └── preprocess.py   gamma/contrast, CLAHE, unsharp, deskew, perspective warp
├── ocr/                EasyOCR/PaddleOCR backends
│   ├── ensemble.py     per-frame confidence-weighted vote across views + engines
│   ├── normalize.py    Turkish plate grammar, positional repair, edit-cost cap
│   └── voting.py       multi-frame temporal consensus
├── api/                FastAPI routes, JWT auth, MJPEG stream, WS events
└── ui/                 Tkinter client + transport-only API/WS client
web/                    browser dashboard (static HTML/JS, served at /web)
docker/                 Dockerfile, compose, entrypoint
scripts/fetch_models.py model bootstrap
legacy/main_legacy.py   the original 836-line single-file app, kept for reference
```

---

## Quick start

### Docker (headless core — recommended)

```bash
cp .env.example docker/.env          # then set LPR_API__SECRET_KEY
python scripts/fetch_models.py       # downloads baseline weights into models/
docker compose -f docker/docker-compose.yml up --build
curl http://localhost:8000/health
```

`data/`, `models/` and `config.yaml` are bind-mounted, so the database, weights and
settings live on the host and survive rebuilds.

### Native

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e ".[gui]"                               # only for the desktop client
lpr-api                                               # http://127.0.0.1:8000/docs
lpr-gui --api-url http://127.0.0.1:8000               # separate process/machine
```

---

## Configuration

`config.yaml` holds the defaults; environment variables override it and win.
Nested keys use a double underscore:

```bash
LPR_CAMERAS__ENTRY__SOURCE=rtsp://user:pass@10.0.0.5:554/stream1
LPR_RELAY__PORT=/dev/ttyUSB0      # COM3 on Windows, "auto" resolves per-OS
LPR_DETECTION__DEVICE=cuda
```

See `.env.example` for the full annotated list.

---

## Two front ends

The recognition service has no UI of its own. Both clients speak the same
public API over HTTP and WebSocket, so either can be used, both at once, and
neither is privileged:

| | `lpr-gui` (Tkinter) | Browser dashboard |
|---|---|---|
| Runs on | the operator's machine | anything on the LAN |
| Install | `pip install -e '.[gui]'` | nothing |
| Reach | one desk | any phone/tablet/PC |

**Browser** — start `lpr-api` and open `http://<host>:8000/`, which redirects
to `/web/`. The page is plain HTML and vanilla JS from `web/`, mounted with
`StaticFiles`; it adds no endpoints and holds no privileges of its own. Log in
with the same account the desktop client uses (on a fresh install, "Kaydol"
creates the first account, which becomes the admin).

Two details make it work in a browser: an `<img>` cannot send an
`Authorization` header and neither can a WebSocket handshake, so the MJPEG and
event endpoints also accept the bearer token as `?token=`. That was already in
the API before the web UI existed.

Styling is Tailwind from the CDN, so a site with no internet gets a plain but
working page and an on-screen warning saying why. Vendor `tailwind.css` into
`web/` if that matters for your deployment.

**Desktop** — `lpr-gui` is unchanged and remains the fallback for a control
room with no browser, or where the operator wants a native window.

---

### Event snapshots

Every gate decision (granted, denied, error — not the cooldown suppressions
of an idling car) saves the full frame behind it to `data/snapshots/` as
`YYYYMMDD_HHMMSS_<PLATE>.jpg`. The timestamp is UTC, matching the `ts` on the
matching `logs` row, so an image and its record line up without timezone
arithmetic.

Encoding and writing happen on a dedicated thread: the recognition path only
puts the frame on a bounded queue and returns, so a slow or full disk costs
dropped evidence rather than a delayed barrier or a stuttering MJPEG stream.
The pipeline's retention thread deletes snapshots older than
`snapshots.retention_days` at startup and once a day after, alongside the
`logs` table purge.

```yaml
snapshots:
  enabled: true
  dir: ""              # empty = <app.data_dir>/snapshots
  retention_days: 10   # matched to database.log_retention_days
  jpeg_quality: 85
  queue_size: 64       # frames awaiting encode before the writer drops
```

---

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | liveness; reports `degraded` when the pipeline is down |
| `POST /api/auth/login` · `/register` | none · first-user-or-admin | JWT bearer token |
| `GET/POST /api/plates` · `DELETE /api/plates/{plate}` | user · admin | allow-list CRUD |
| `GET /api/logs` · `/api/logs/dates` | user | history, filterable by camera/plate/date |
| `GET /api/stats` · `/api/cameras` | user | pipeline and per-camera health |
| `POST /api/relay/trigger` · `/api/pipeline/pause` · `/resume` | admin | manual control |
| `GET /api/license` · `POST /api/license` | user · admin | licence state; install a new key |
| `GET /api/stream/{camera}` | bearer | MJPEG preview (capped ~10 fps) |
| `GET /api/system/version` | user | deployed version (`git describe`), commit and branch |
| `GET/POST /api/system/update` | admin | OTA update status; trigger an update (202) |
| `GET /api/system/events` | admin | operational audit trail (nightly OTA activity) |
| `WS /ws/events?token=` | token | live plate events as JSON |

Interactive docs at `/docs`.

---

## Accuracy design

The legacy pipeline was Canny edge detection → contour search → a four-point warp →
Tesseract `--psm 8`. It needed a clean quadrilateral, so it failed on angled, blurred,
night and partially-occluded plates.

The replacement stacks six independent accuracy layers:

1. **YOLOv8n detection** — learned plate localisation, plus plausibility filters on
   aspect ratio, area, and Laplacian sharpness so blurred crops never reach OCR.
2. **Crop enhancement** — upscale, dynamic gamma + percentile contrast stretch, CLAHE,
   bilateral denoise, unsharp mask, deskew; the recogniser builds the grayscale,
   thresholded and deskewed variants. If none of them yields a *grammatical* plate, it
   escalates to a **perspective-rectified** copy of the crop — the plate's four corners
   are located and warped back to a head-on rectangle — and tries again. That second
   stage is what reads a plate photographed from the side, which deskew (rotation only)
   cannot correct, and it is skipped entirely on the plates the cheap variants read.
3. **Per-frame ensemble vote** — the variants are not ranked by confidence and topped;
   they *vote*. Every candidate is normalised, grouped by the plate string it produces,
   and each group scores the sum of its members' confidences. Which glyphs a view
   confuses depends on the view — `0`/`O` flips with the binarisation threshold, `8`/`B`
   with the sharpening — so agreement across views is stronger evidence than any one
   view's certainty, and an over-confident outlier can no longer win outright. Set
   `ocr.ensemble_backends: [paddleocr]` to add a second engine as an equal voter.
4. **Turkish normalisation** — `^(0[1-9]|[1-7][0-9]|8[01])([A-Z]{1,3})([0-9]{2,4})$`,
   with a *positional* confusion map (`0↔O`, `1↔I`, `8↔B`, `5↔S`, …) applied per block:
   digits in the province code, letters in the middle, digits in the tail. Q/W/X and
   the diacritic letters are rejected — they never appear on Turkish plates. Repairs are
   capped at **two edits**: every glyph has a mapping available, so without a cap the
   coercion is powerful enough to bend "GIRIS" (the sign above the gate) into "61R15"
   and call it a plate.
5. **ByteTrack tracking** — detection runs through `model.track(persist=True)`, so each
   plate keeps a stable `track_id` while it is in view (one tracker state per camera).
   Reads sharing an id are the same physical plate and reinforce each other regardless
   of spelling, and reads from *different* ids are never merged.
6. **Multi-frame voting** — a plate must win `min_votes` of the last `window` reads
   inside a `ttl_s` time window before the relay fires, with confidence weighting,
   Levenshtein-1 candidate merging, and a per-plate cooldown.

Before any of that runs, the capture thread applies **motion gating**: each frame is
subsampled by an integer stride to ~320 px, blurred, differenced against a running-average
background (`cv2.accumulateWeighted`), and dropped unless the largest moving contour clears
`cameras.motion.threshold` (in full-frame pixels). It costs ~0.09 ms/frame against a
30–100 ms inference pass, and on a still scene with sensor noise and JPEG artefacts it
removes ~99% of frames. `cameras.motion.heartbeat_s` forces one through periodically so
tracker state still ages out, and the gate fails open — a broken motion check means *more*
inference, never a blind pipeline. Skipped frames are counted per camera as
`motion_skipped`, and `latest()` keeps updating so the live preview never freezes.

Tracking also caps the OCR bill: once a track has opened (or been refused at) the gate,
or has burned `voting.max_track_attempts` reads without confirming anything, EasyOCR is
skipped for that track entirely — the pipeline recognises a *car*, not a *frame*. The
saving shows up as `ocr_skipped` in `GET /api/stats`. Set `detection.track: false` to
go back to stateless per-frame detection; everything downstream falls back to the
text-only voting path when a detection has no `track_id`.

### Crop preprocessing

`src/lpr/detect/preprocess.py`

Every function in this module is *total*: it validates its own input, catches its own
exceptions, and falls back to returning the input unchanged. A preprocessing failure
costs one frame a slightly worse read — it never takes down a capture thread.

The OCR pre-pass (`enhance_plate`) runs these stages in this order, and the order is
load-bearing:

| # | Stage | Why here |
| --- | --- | --- |
| 1 | **Upscale** to a 64 px character height (cubic, capped at 4×) | A 20–30 px crop wastes most of the recogniser's capability. Capped because interpolating 6 px to 64 px invents detail rather than revealing it. |
| 2 | **Dynamic gamma** (`auto_gamma` / `apply_gamma`) | Global exposure must be fixed before anything local runs. |
| 3 | **Percentile contrast stretch** (`stretch_contrast`) | Spreads what survives gamma across the full range. |
| 4 | **CLAHE** (clip 2.0, 8×8 tiles) | Local contrast, to separate characters from a dirty plate. |
| 5 | **Bilateral denoise** | Edge-preserving: a plain Gaussian would soften the strokes the recogniser needs. |
| 6 | **Unsharp mask** (`unsharp_mask`) | Puts back the stroke edges the bilateral filter softened. |
| 7 | **Adaptive threshold** | Binarised variant, produced *last* so it thresholds a crisp image. |

#### Dynamic gamma correction

Aimed at night headlights, overexposed plates and deep shadow. A plate is bimodal by
construction — dark glyphs on a light field — so a correctly exposed one sits around 0.7
mean luminance, and its exact mean says more about how many characters it carries than
about its exposure. Driving that towards mid-grey would "correct" every well-lit plate in
the country.

Instead `auto_gamma` defines a **healthy band** (0.35–0.78 normalised). A crop inside it
is returned untouched. A crop outside it is pulled back to the *nearest edge* of the band
by solving `mean ** gamma == target`, so the correction scales with the severity of the
problem: a plate at 0.80 is nudged, a plate at 0.95 is rescued, and the two do not get
identical treatment merely because both are "too bright". The exponent is clamped to
0.4–2.5, and a crop clipped to solid black or solid white is declined outright — there is
no exposure left in it to recover.

`stretch_contrast` then rescales the 2nd–98th percentile range to full scale. Percentiles
rather than min/max: one specular highlight off a rivet pins a min/max stretch to the
extremes and achieves nothing. It declines both when the range is already wide (nothing to
gain) and when it is nearly flat (no signal — stretching would multiply sensor noise into
fake structure).

Measured on synthetic crops (std before → after): deep shadow 17 → 109, headlight glare
36 → 109, well-exposed plate unchanged. Cost ≈ 0.4 ms/crop.

#### Unsharp masking

`sharp = image + amount * (image - blur(image))`, in saturating uint8 arithmetic so a
highlight clips to white instead of wrapping to black. A contrast threshold skips pixels
whose local contrast is already below it, which keeps flat plate background — and the
sensor noise living in it — from being amplified into texture the binariser would read as
strokes. Cost ≈ 0.03 ms/crop.

#### Perspective rectification

`deskew` can only **rotate**, which straightens a tilted camera but does nothing for a
plate photographed from the side: there the near edge is longer than the far one and every
character is trapezoidal. `rectify_perspective` locates the plate's four-corner outline
(Canny → morphological close → `approxPolyDP`) and warps that quadrilateral back to a
rectangle, sizing the output from the *near* edge so the foreshortened far edge is
stretched up to it.

It is deliberately conservative, because a wrong warp does not degrade a crop gracefully —
it destroys it. A quad is rejected when it is too small (< 25% of the crop), non-convex,
would rectify to a non-plate aspect ratio, or is merely the crop's own border (a no-op
warp that edge detection readily finds on a noisy crop). Any rejection returns `None` and
the caller keeps what it had. Cost ≈ 0.6 ms when it runs.

Rectification is an **escalation**, not a default stage: it runs only when no cheap variant
produced a grammatical plate, so ordinary plates never pay for the extra OCR pass.

#### Configuration

Everything in this section is software-level — it changes what the models are *shown*,
never what they learned, so none of it requires the detector retrained.

| Knob | Default | What it does |
| --- | --- | --- |
| `preprocess.normalize_lighting` | `true` | Dynamic gamma + percentile contrast stretch, ahead of CLAHE. Runs before CLAHE deliberately: CLAHE equalises per 8×8 tile and will amplify the noise inside a black tile to full scale if the crop arrives globally underexposed. Self-limiting — a normally-exposed plate passes through untouched. |
| `preprocess.crop_unsharp_amount` | `0.6` | Unsharp strength in the crop pre-pass. `0` disables it. |
| `preprocess.rectify_perspective` | `true` | Retry a failed read on a perspective-corrected crop. One extra OCR pass, only on crops that already produced nothing grammatical. |
| `ocr.ensemble_backends` | `[]` | Extra OCR engines pooled into the per-frame vote as equal voters, e.g. `[paddleocr]`. |
| `preprocess.frame_enhance` | `false` | Whole-frame CLAHE (on the LAB lightness channel, so hue is left alone) plus a mild unsharp mask, applied **before the detector**. ≈ 12 ms per 720p frame. |

The crop-level settings are on by default because they can only ever affect what the
*recogniser* sees, and the recogniser votes across several variants — a variant that an
enhancement made worse simply loses.

`frame_enhance` is off by default because it is the one setting here that can make things
worse. It changes what the *detector* sees, and there is no "best of several tries"
fallback behind the detector: a frame it fails to fire on is a plate that never reaches
OCR at all. Mild CLAHE usually helps at night and can cost recall in good light. Turn it
on only after comparing detection counts on your own footage.

Where it runs matters as much as what it does. Frame enhancement happens on the
per-camera **processing** thread, never on the capture thread, and only on frames that
have already survived motion gating and `detection.frame_stride` decimation — so it is
paid on the handful of frames per second that are actually going to be looked at, and the
capture loop keeps draining the camera at full rate regardless. The enhanced frame goes
to the detector only: `latest_frame()`, the MJPEG preview and the evidence snapshot all
keep the untouched frame, so what gets recorded stays what the camera saw.

### Ensemble OCR voting

`src/lpr/ocr/ensemble.py`

Each plate crop produces several *views* — CLAHE'd grayscale, adaptive-threshold
binarisation, deskewed, and (on escalation) perspective-rectified. Earlier revisions kept
whichever single candidate scored highest on `(valid, confidence)`. That discards the most
useful signal available: **how many independent views agreed**.

Which glyphs a view confuses is a property of the view. `0` vs `O` flips with the
binarisation threshold; `8` vs `B` flips with the sharpening. So the correct reading is
the one that keeps recurring across views, while each particular misreading tends to
appear once. A single over-confident outlier can win an argmax; it cannot win a vote.

**Scoring.** Ballots are normalised through `normalize_plate`, grouped by the resulting
plate string, and each group scores the **sum of its members' confidences** — a
confidence-weighted majority:

- Three agreeing reads at 0.6 (Σ 1.8) beat one emphatic read at 0.9.
- Three hesitant reads at 0.2 (Σ 0.6) do **not**.
- A grammatical read always outranks an ungrammatical one, whatever the arithmetic says.

**Near-miss merging.** Two grammatical spellings one Levenshtein edit apart are the same
plate seen through different noise, so they are merged onto the stronger spelling before
the winner is picked. Without this, `34ABC12` seen twice and `34ABD12` seen once are three
separate one-vote groups and the ensemble has learned nothing. Only *grammatical* groups
merge — two similar pieces of junk say nothing about which is a plate, and merging them
would manufacture agreement out of noise.

**Reported confidence.** The winner carries the confidence of the strongest single ballot
that spelled *that exact string* — not the summed score (a ranking quantity, not a
probability) and not a merged near-miss's confidence. `ocr.min_confidence` and the
multi-frame voter both read this field, so it has to keep meaning "how sure was the engine
about this string".

**Multi-engine.** `EnsembleRecognizer` pools members' raw *ballots* rather than their
verdicts, so engines vote on equal footing instead of one being a tie-break for the other.
Members are queried in order and the vote stops as soon as it holds a grammatical read, so
a second engine is a cost paid on hard crops, not on every car. A member that raises is
dropped for that crop and the vote proceeds on the rest — half an ensemble still beats no
read. Enable with `ocr.ensemble_backends: [paddleocr]`; a configured engine that is not
installed logs a warning and is skipped rather than failing the pipeline.

The module is pure Python (standard library + `lpr.contracts`), so it is unit-testable with
no ML stack present.

### Turkish plate grammar and repair budget

`src/lpr/ocr/normalize.py` — also pure Python, no numpy, no cv2.

**Grammar.** A Turkish civilian plate is `<province 01–81> <1–3 letters> <2–4 digits>`,
expressed as:

```
^(0[1-9]|[1-7][0-9]|8[01])([A-Z]{1,3})([0-9]{2,4})$
```

The letter block is additionally restricted to the Turkish plate alphabet
(`ABCDEFGHIJKLMNOPRSTUVYZ`). `Q`, `W`, `X` and the diacritic letters (Ç, Ğ, İ, Ö, Ş, Ü)
never appear on Turkish plates, so a read containing one is an OCR error or not a plate —
a constraint plain `[A-Z]` cannot express.

**Positional repair.** OCR engines confuse whole glyph classes: `0`/`O`/`D`/`Q`,
`1`/`I`/`L`, `8`/`B`, `5`/`S`, `2`/`Z`, `4`/`A`, `6`/`G`, `7`/`T`. A *global* substitution
table is self-defeating — fixing `O` → `0` in the province block breaks the letter block.
Because the grammar pins the character *class* of every position, the map is applied
**directionally**, and every legal segmentation is scored by how many characters it must
touch, cheapest winning:

```
"O6BZ1234"  →  "06BZ1234"     letter O in a digit slot     (1 edit)
"34A8C123"  →  "34ABC123"     digit 8 in a letter slot     (1 edit)
```

**Edit-cost cap.** Repairs are capped at **two edits**. This is what keeps the coercion
from being too good at its job: every glyph has a mapping available, so with no cap almost
any 5–9 character word can be bent into something the grammar accepts. Uncapped, `GIRIS` —
the sign above the gate — becomes `61R15` for four edits, and the barrier opens for a wall.

| Input | Result | Why |
| --- | --- | --- |
| `34A8C123` | `34ABC123`, valid | 1 edit — a genuine glyph confusion |
| `O6BZ1234` | `06BZ1234`, valid | 1 edit |
| `GIRIS` | rejected | 4 edits — over budget |
| `CIKIS`, `OTOPARK`, `HOSGELDINIZ`, `DIKKAT` | rejected | over budget |
| `34WAB12` | rejected | `W` is not a Turkish plate letter |
| `00ABC12`, `82ABC12` | rejected | province outside 01–81 |

`PlateRead.raw_text` always retains the untouched recogniser string, so no information is
lost and any decision made here can be audited after the fact. When nothing parses, the
speculative repair is deliberately *not* returned — a repair that failed validation is
noise, not a plate.

### Two voting layers, and why they are separate

| | `lpr.ocr.ensemble` | `lpr.ocr.voting` |
| --- | --- | --- |
| Votes across | views of **one crop** (and engines) | reads across **frames** |
| Window | a single frame | `voting.ttl_s` sliding window |
| Recovers | view-dependent glyph confusion (`0`/`O`, `8`/`B`) | one-off misreads, momentary occlusion |
| Output | one `PlateRead` | a confirmed plate, or nothing |

They compose: the ensemble decides what this frame saw, the multi-frame voter decides
whether the gate may move. Both weight by confidence and both merge spellings one edit
apart, but at different scales — a plate confused the same way in every view of one frame
is still only *one* vote at the temporal layer.

### Gate hardware: sliding gate vs arm barrier

The two need different timing, and the difference is not cosmetic.

An **arm barrier** takes ~2 seconds and its open pulse is idempotent — a second
pulse while it is rising does nothing.

An **electric sliding gate** (*yana kayar kapı*) takes **15–25 seconds** and is
usually driven by **step-by-step pulse logic**:

```
pulse 1 → open        pulse 2 → STOP mid-travel        pulse 3 → close
```

A car waiting at the camera is re-read on every pass of the pipeline. If the
re-trigger window is shorter than the gate's travel time, the same plate
confirms a second time while the gate is still opening, a second pulse goes
out, and the gate halts with the driver sitting under it.

| Setting | Shipped default | Why |
|---|---|---|
| `voting.cooldown_s` | **20.0** | Must exceed the motor's full open cycle. Time your own gate from closed to fully open and set this at or just above it. Too short re-triggers mid-travel; too long only delays a genuine second entry by the same car — much the cheaper mistake. An arm barrier can run at 3–5 s. |
| `relay.pulse_ms` | **1000** | A *momentary* dry-contact closure — one pulse equals one press of the controller's own button. 1000 ms clears the debounce filter of every step-by-step controller in common use while staying short enough not to register as a held button. |

Raising `pulse_ms` does **not** hold a sliding gate open longer. The open
duration lives on the motor controller; `pulse_ms` only sets how long the
contact is closed.

**What the cooldown does and does not cover.** It is keyed on
*(camera, plate)*, so it stops the same vehicle re-triggering — the case that
actually happens at a gate. It does **not** lock the gate out globally: a
*different* plate confirming while the gate is moving, or an operator pressing
the manual button, will still send a pulse. That is deliberate (a second car
must not be stranded behind the first car's window, and an operator may need to
stop the gate on purpose), but if your site needs a hardware-level lockout it
has to sit in the relay layer, not here.

### Manual gate control

`POST /api/relay/trigger` (admin, licence-gated) sends one pulse and records it
as a `granted` event for plate `MANUAL`, so the audit trail shows who opened
the gate and when.

The dashboard's **Kapıyı Aç** button goes busy *before* the request is sent —
the accidental double-press happens in the second or two while the POST is
still in flight, not after it returns — and counts down for the gate's travel
time (`GATE_BUSY_MS` in `web/app.js`, kept in step with `voting.cooldown_s`).
A failed trigger releases the button immediately, since no pulse went out and
the gate is not moving.

Note that this means the dashboard will not send a second pulse for ~20 s,
so it cannot be used to *stop* a sliding gate mid-travel. If you want that,
lower `GATE_BUSY_MS`; the endpoint itself is not rate-limited.

The temporal layer is tuned by `voting.window` (how many reads are retained),
`voting.min_votes` (how many must agree) and `voting.ttl_s` (how long a vote survives).
Shipped defaults are 5 / 3 / 4.0s. **Shortening `ttl_s` makes confirmation stricter, not
better** — three reads must then land within a narrower window, so a car crossing slowly
or a plate briefly occluded confirms less often. Raise `min_votes` if you want fewer false
opens; shorten `ttl_s` only if you want the gate to forget a car faster.

### ONNX (optional)

```bash
python scripts/export_onnx.py    # writes models/plate_yolov8n.onnx, then benchmarks both
```

The detector prefers a sibling `.onnx` over the configured `.pt` automatically
(`detection.prefer_onnx`), verifying it at startup and falling back to the `.pt` if the
export is corrupt or was built for a different `imgsz`. ByteTrack works identically on
either backend.

**Benchmark before deploying it.** ONNX Runtime is not automatically faster than a
oneDNN-enabled PyTorch build on recent Intel CPUs — on this project's development machine
it measured ~2× *slower* (53 ms vs 23 ms per frame). The export script prints both numbers
and warns you if the `.pt` wins; if it does, delete the `.onnx` or set
`detection.prefer_onnx: false`.

### Model weights

`scripts/fetch_models.py` fetches the generic `yolov8n.pt` baseline so the stack runs
immediately. **It is not plate-specific.** For production accuracy, fine-tune on a
plate dataset (single class `plate`, YOLO format) and drop the result at
`models/plate_yolov8n.pt`. Without weights the system falls back to the legacy contour
detector and logs a loud warning — it works, but it is materially less accurate.

```bash
python scripts/train_plate_detector.py --data dataset/data.yaml   # installs models/plate_yolov8n.pt
```

`scripts/train_plate_detector.py` fine-tunes YOLOv8n (imgsz 640, 100 epochs, batch 16,
early-stop patience 20, horizontal flip disabled) and installs the result where the
pipeline expects it. It can pull the dataset straight from Roboflow via `ROBOFLOW_*`
env vars. Colab instructions: **[README_TRAINING.md](README_TRAINING.md)**. Once a
custom model exists, `fetch_models.py` stops downloading the baseline and says so.

---

## Remote updates (OTA)

An admin can pull the latest code and rebuild the stack from the dashboard —
**Ayarlar → Sistem Güncellemesi** — instead of SSHing into every site.

### Read this before enabling it

This feature is remote code execution. That is not a flaw in the
implementation; it is what an OTA updater *does*. It is therefore **disabled by
default**, and turning it on has two consequences that no amount of code can
remove:

1. **Whoever controls the git remote controls every machine running this.** A
   compromised maintainer account, or a compromised forge, becomes arbitrary
   code on every deployed site the next time an admin presses the button.
2. **Rebuilding the stack from inside a container requires the Docker socket.**
   Mounting `/var/run/docker.sock` lets that container start any container on
   the host, with any mount, as root — which is host root, laundered through
   the API process.

That is a reasonable trade for a fleet you operate. It is a bad one for a
product shipped to sites you do not control, or for an API reachable from an
untrusted network. The alternative that avoids both risks is a host-side
`systemd` timer polling `git fetch`, with no endpoint at all.

### What is constrained

Given the feature is enabled, the implementation narrows the blast radius as
far as it can:

| Control | Effect |
|---|---|
| Off by default (`system_update.enabled`) | No endpoint surface until an operator opts in |
| Admin-only JWT (`require_admin`) | Operators get 403; the updater is never reached |
| **No caller-supplied target** | Remote, branch, repo dir and compose file come from config only — a stolen admin token can re-run *your* repo, never point at theirs |
| No shell, ever | Every command is a fixed `list[str]`; `shell=True` appears nowhere |
| `git pull --ff-only` | A diverged or locally-modified checkout fails loudly instead of producing a merge commit or leaving conflict markers in a file the service imports |
| Single-flight lock | Two admins cannot race a rebuild against a checkout; the second call gets 409 |
| Per-step timeouts | A hung fetch cannot pin a thread for the life of the process |
| No-op detection | An already-current checkout skips the rebuild, so the gate does not go down for nothing |

### Enabling it

```yaml
# config.yaml
system_update:
  enabled: true
  git_remote: origin
  git_branch: main
  compose_file: docker/docker-compose.yml
```

Then uncomment the OTA block in `docker/docker-compose.yml`, which mounts the
repo (so `git pull` has a checkout — the image itself has no `.git`) and the
Docker socket (so the container can rebuild its own stack).

Without those mounts the endpoint still answers; the update just fails with a
specific message rather than a traceback — *"… bir git deposu değil"* or
*"Docker soketine erişim reddedildi"*.

### How the deployed version is named

`GET /api/system/version` reports two different things, and the difference
matters:

| Field | From | For |
|---|---|---|
| `version` | `git describe --tags --always` | **Display.** A label a human can read out over the phone. |
| `commit` / `short_commit` | `git rev-parse HEAD` | **Identity.** Which build is actually running. |

`git describe --tags --always` returns the most meaningful name the repository
can offer for the current commit, degrading one step at a time:

| Repository state | `version` |
|---|---|
| HEAD is tagged | `v1.0.0` |
| two commits past a tag | `v1.0.0-2-g6845136` |
| never tagged | `6845136` — a bare hash, via `--always` |
| not a git checkout | the packaged version, e.g. `0.1.0` |

`--tags` is load-bearing: a release cut with plain `git tag v1.0.0` is a
*lightweight* tag, and `git describe` without it silently ignores lightweight
tags — which would put a hash back on exactly the builds that were supposed to
read nicely. `--always` is what keeps an untagged repository from failing the
call outright. There is no repository state in which `version` comes back empty.

The dashboard detects a completed OTA update by watching **`commit`**, never
`version`. Tagging a commit that is already deployed changes the describe
string without deploying anything; a client watching the label would report a
successful update that never happened.

### Why the POST returns 202, not 200

`docker compose up -d --build` recreates the container that is serving the
request. The process is killed partway through its own subprocess call, so the
update **cannot** report its own success over the connection that asked for it.

Hence the shape of the thing:

1. `POST /api/system/update` validates, starts a detached worker thread, and
   returns **202 Accepted** immediately.
2. The worker writes its status to `<data_dir>/last_update.json` *before*
   starting the rebuild — the last chance to leave a breadcrumb.
3. The container dies and is replaced.
4. The new container reads that file on startup. A record still saying
   "restarting" means the previous container was replaced mid-update, which is
   the *expected* ending: this process running at all is the evidence the
   rebuild worked.
5. The browser polls `GET /api/system/version` through the outage — connection
   errors during a rebuild are expected, not fatal — until a different commit
   answers, then reports the new version. A 10-minute deadline bounds the wait.

Failures land in `GET /api/system/update` with a `log` tail of the git and
compose output, which the dashboard shows verbatim under the button.

### Nightly check (03:00)

Once a night the service asks the remote whether anything new has landed. It is
an `asyncio` task started from the lifespan, alongside the licence watchdog —
not APScheduler. One scheduled job does not justify a dependency with its own
job store, executor pool and threading model, and adding one would leave two
unrelated scheduling mechanisms in a codebase that deliberately has one of
everything. The whole scheduling calculation is `seconds_until()`, a pure
function over a clock.

**Two switches, because these are two different risks:**

| Setting | Default | What it does |
|---|---|---|
| `system_update.nightly_check` | `true` | Ask the remote what is available, once a night. **Read-only** — `git fetch` updates a remote-tracking ref and does not touch the working tree. It only records *"an update is waiting"* where an admin will see it. |
| `system_update.auto_update` | `false` | Install what the check finds, unattended. Requires `enabled` as well. |
| `system_update.check_hour` / `check_minute` | `3` / `0` | Local wall-clock time. "Low traffic" is a property of the site's clock, not UTC — 03:00 UTC is 06:00 in Turkey, which is a shift change. |

Checking is safe to leave on; **installing unattended is not the same decision
as pressing the button**. An admin pressing the button is watching the result
and is updating one site. The nightly job updates every site in the fleet at the
same moment with nobody looking, so a bad commit becomes a fleet-wide outage
discovered by a phone call rather than a rollback. Hence the separate opt-in.

The check is `git fetch` followed by
`git rev-list --count HEAD..origin/main`, not `git status` parsing: porcelain
status text is localised and gets reformatted between git versions, whereas
rev-list answers the actual question — "how many commits am I missing" — as a
single integer. A failed fetch is reported as **"could not tell"**, never as
"up to date"; conflating those is how a fleet silently stops updating.

Installing uses the same `SystemUpdater.start()` path as the button, so it is
fast-forward-only and shares the same single-flight lock. A site with local
modifications fails the nightly update exactly as it would fail a manual one,
and the failure is recorded rather than worked around.

### Where the nightly job reports

Every attempt, skip and failure is written to the **`system_events`** table
(schema v3) and shown in the dashboard under the update button, newest first.

`system_events` is deliberately *not* the `logs` table. `logs` is plate
traffic — it drives the history view, the CSV export and the occupancy
arithmetic — so an "update installed at 03:00" row in there would appear in an
operator's vehicle history as a car and be counted as one. The two histories
share a database, never a table.

```
[warning] 27.08 03:00  2 yeni sürüm bulundu (e46933f). Otomatik güncelleme başlatılıyor.
[info]    26.08 03:00  Gecelik denetim: sistem güncel.
[error]   25.08 03:00  Güncelleme denetimi başarısız.
```

Rows are retained for `system_update.event_retention_days` (90 by default) and
trimmed by the existing retention thread. That is longer than the plate log
because it is a handful of rows a day, and "what did this machine do to itself
last quarter" outlives "which cars came through last week".

---

## Licensing (time-limited deployments)

Sites are licensed offline with a signed JWT whose `exp` claim *is* the expiry
date. There is no activation server to call: the key carries its own proof, so
a site with no internet access still stops on time.

Mint a key on the **vendor** machine:

```bash
export LPR_LICENSE_SECRET=$(openssl rand -hex 32)   # same value on both sides
python scripts/generate_license.py --days 30 --client "Site A"
```

Every generated key is appended to `license_history.log` in the repo root —
token, creation date, expiry date and client name — which is the only way to
recover a key you have already handed out. Treat that file (and the secret) as
secrets: both are ignored by git.

Install the key on the **site**: paste it into the desktop client's *Lisans Gir*
dialog (`POST /api/license`), or drop it in a `.license` file in the data
directory. It is stored in `system_meta` *and* mirrored to `.license`, so it
survives either one being lost.

What happens when it lapses: the API keeps running and `PipelineOrchestrator`
is paused — no detection, no OCR, no relay, and `POST /api/relay/trigger`
answers `402`. Cameras stay connected and the live view keeps working, so
entering a new key resumes processing instantly, without a restart. The
desktop client freezes its camera panes and opens the key dialog. Nothing
crashes; the service simply waits.

Three defences, in the order an attacker meets them:

1. **Signature** — HS256 over `LPR_LICENSE_SECRET`; editing `exp` invalidates
   the key, and re-signing needs the secret. An API session token is *not* a
   licence: licences carry an `iss` claim that is verified.
2. **Anti-rollback** — every check records the wall clock in
   `system_meta.last_run_time`; time moving backwards by more than 5 minutes
   reads as tampering and invalidates the licence until the clock catches up.
   Winding the clock back buys nothing.
3. **Two-place storage** — restoring an old database copy or deleting
   `.license` does not clear the recorded high-water mark.

---

## Migrating an existing `plates.db`

The old schema stored one table per day (`logs_YYYY_MM_DD`) and unsalted SHA-256
passwords. The migrator folds those into the new indexed `logs` table:

```bash
python -m lpr.db.migrate path/to/plates.db
```

It is idempotent and transactional. Legacy password hashes are imported with a
`sha256$` marker and transparently upgraded to argon2 on each user's next login.

---

## What changed from the legacy app

| Legacy | Now |
|---|---|
| One 836-line `main.py` | `src/lpr` package, protocol-separated modules |
| One global SQLite connection, `check_same_thread=False` | thread-local connections, WAL, busy-timeout |
| One table per day, f-string SQL | single `logs` table, indexed on `ts`, parameterised |
| `time.sleep(1)` in the capture loop on every gate open | relay pulse on its own thread; `trigger()` returns immediately |
| Both cameras read serially in one loop | one capture thread per camera, bounded drop-oldest queues |
| Worker threads mutating Tkinter widgets | queue + single `root.after` drain on the main thread |
| Unsalted SHA-256 passwords | argon2, with legacy verify-then-rehash |
| `ctypes.windll` at import (crashed on Linux) | guarded in `platform_compat` |
| 123 MB vendored `Tesseract-OCR/` in git | untracked; OCR via EasyOCR/PaddleOCR |
| OCR on every frame of both cameras | `frame_stride` gating + detector plausibility filters |
| YOLO on an empty driveway all day | motion gating in the capture thread: a ~0.09 ms frame-difference check drops ~99% of idle frames before inference |

---

## Development

```bash
pip install -r requirements-dev.txt
make test      # pytest
make lint      # ruff + mypy
make fmt
```

### Test suite

**582 passing tests** across 18 modules (584 collected: 582 pass, 1 skipped, 1 known
failure — see below). Tests run without torch, a GPU or a camera: ML-dependent modules are
`importorskip`-guarded and the pipeline tests drive the orchestrator through protocol
fakes, so the suite is fully collectable in a CI job with no ML wheels installed.

| Module | Tests | Covers |
| --- | ---: | --- |
| `test_detect.py` | 83 | Box plausibility, letterbox round-trips, crop padding, gamma/contrast, unsharp, perspective rectification, sharpness gating |
| `test_normalize.py` | 69 | Turkish grammar, positional repair, edit-cost cap, candidate extraction |
| `test_api.py` | 62 | Routes, JWT auth, MJPEG stream, WebSocket events, OTA authorisation |
| `test_voting.py` | 38 | Multi-frame consensus, TTL expiry, cooldown, track-aware merging |
| `test_pipeline.py` | 39 | Queue semantics, frame stride, thread lifecycle, subscriber fan-out, sliding-gate cooldown |
| `test_license.py` | 30 | Signature validation, anti-rollback, expiry |
| `test_db.py` | 35 | Repositories, migrations, retention, system-event trail |
| `test_ui_client.py` | 26 | Transport-only API/WS client |
| `test_web_ui.py` | 33 | Browser dashboard endpoints, update panel gating, manual gate button |
| `test_ui_app.py` | 19 | Tkinter queue drain, widget thread safety |
| `test_ensemble.py` | 19 | Confidence-weighted vote, near-miss merging, multi-engine pooling |
| `test_parking.py` | 18 | Occupancy accounting |
| `test_snapshots.py` | 17 | Evidence writer, retention, off-hot-path encoding |
| `test_updater.py` | 37 | OTA: command construction, conflict/permission/timeout paths, restart state, remote check, version naming |
| `test_scheduler.py` | 24 | Nightly job: clock arithmetic, refusal-to-act paths, loop resilience |
| `test_relay.py` | 14 | Serial pulse queue, MockRelay fallback |
| `test_config.py` | 10 | Shipped defaults: sliding-gate cooldown and pulse width |
| `test_preprocess_pipeline.py` | 11 | Preprocessing wiring: escalation staging, frame-hook injection |

The accuracy layers are deliberately the most heavily tested: `test_detect.py`,
`test_normalize.py`, `test_voting.py`, `test_ensemble.py` and
`test_preprocess_pipeline.py` together account for 220 of the 584 collected tests. Every
preprocessing primitive is additionally asserted to be *total* — it must return its input
unchanged rather than raise, on `None`, on an empty array, and on a degenerate crop.

> **Known failure:** `test_license.py::test_an_hs256_token_signed_with_the_public_key_is_rejected`
> currently fails against recent `pyjwt` releases. The test forges an HS256 token using an
> RSA public key; newer `pyjwt` refuses that at *signing* time, so the failure occurs in
> the test's own setup rather than in the code under test. The licence check itself is
> unaffected. The test needs rewriting to construct the forged token directly.

---

## License

MIT — see [LICENSE](LICENSE).
