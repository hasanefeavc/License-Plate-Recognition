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
├── detect/             YOLOv8n detector, crop preprocessing, contour fallback
├── ocr/                EasyOCR/PaddleOCR backends, TR normaliser, voting
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
| `WS /ws/events?token=` | token | live plate events as JSON |

Interactive docs at `/docs`.

---

## Accuracy design

The legacy pipeline was Canny edge detection → contour search → a four-point warp →
Tesseract `--psm 8`. It needed a clean quadrilateral, so it failed on angled, blurred,
night and partially-occluded plates.

The replacement stacks five independent accuracy layers:

1. **YOLOv8n detection** — learned plate localisation, plus plausibility filters on
   aspect ratio, area, and Laplacian sharpness so blurred crops never reach OCR.
2. **Crop enhancement** — upscale, CLAHE, bilateral denoise, unsharp mask, deskew; the
   recogniser tries the grayscale, thresholded and deskewed variants and keeps the best
   candidate. If none of them yields a *grammatical* plate, it escalates to a
   **perspective-rectified** copy of the crop — the plate's four corners are located and
   warped back to a head-on rectangle — and tries again. That second stage is what reads
   a plate photographed from the side, which deskew (rotation only) cannot correct, and
   it is skipped entirely on the plates the cheap variants already read.
3. **Turkish normalisation** — `^(0[1-9]|[1-7][0-9]|8[01])([A-Z]{1,3})([0-9]{2,4})$`,
   with a *positional* confusion map (`0↔O`, `1↔I`, `8↔B`, `5↔S`, …) applied per block:
   digits in the province code, letters in the middle, digits in the tail. Q/W/X and
   the diacritic letters are rejected — they never appear on Turkish plates.
4. **ByteTrack tracking** — detection runs through `model.track(persist=True)`, so each
   plate keeps a stable `track_id` while it is in view (one tracker state per camera).
   Reads sharing an id are the same physical plate and reinforce each other regardless
   of spelling, and reads from *different* ids are never merged.
5. **Multi-frame voting** — a plate must win `min_votes` of the last `window` reads
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

### Angled and low-light plates

Everything in this section is software-level: it changes what the models are *shown*,
never what they learned, so none of it needs the detector retrained.

| Knob | Default | What it does |
| --- | --- | --- |
| `preprocess.crop_unsharp_amount` | `0.6` | Unsharp mask inside the OCR crop pre-pass, applied after CLAHE and denoise. Puts back the stroke edges the bilateral filter softens, which is what separates a character from its own shadow on a plate lit from the side. `0` disables it. |
| `preprocess.rectify_perspective` | `true` | Retry a failed read on a perspective-corrected crop (see above). Costs one extra OCR pass, and only on crops that already produced nothing grammatical. ~0.6 ms to find the outline; a quad that is too small, non-convex, or that would rectify to a non-plate aspect ratio is rejected rather than guessed at. |
| `preprocess.frame_enhance` | `false` | Whole-frame CLAHE (on the LAB lightness channel, so hue is left alone) plus a mild unsharp mask, applied **before the detector**. ~12 ms per 720p frame. |

The crop-level settings are on by default because they can only ever affect what the
*recogniser* sees, and the recogniser keeps the best read across several variants — a
variant that an enhancement made worse simply loses.

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

Tests run without torch, OpenCV or a camera: the ML-dependent modules are
`importorskip`-guarded and the pipeline tests use protocol fakes.

---

## License

MIT — see [LICENSE](LICENSE).
