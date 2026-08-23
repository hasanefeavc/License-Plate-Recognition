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
├── detect/             YOLOv8n detector, crop preprocessing, contour fallback
├── ocr/                EasyOCR/PaddleOCR backends, TR normaliser, voting
├── api/                FastAPI routes, JWT auth, MJPEG stream, WS events
└── ui/                 Tkinter client + transport-only API/WS client
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

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | liveness; reports `degraded` when the pipeline is down |
| `POST /api/auth/login` · `/register` | none · first-user-or-admin | JWT bearer token |
| `GET/POST /api/plates` · `DELETE /api/plates/{plate}` | user · admin | allow-list CRUD |
| `GET /api/logs` · `/api/logs/dates` | user | history, filterable by camera/plate/date |
| `GET /api/stats` · `/api/cameras` | user | pipeline and per-camera health |
| `POST /api/relay/trigger` · `/api/pipeline/pause` · `/resume` | admin | manual control |
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
2. **Crop enhancement** — upscale, CLAHE, deskew; the recogniser tries the grayscale,
   thresholded and deskewed variants and keeps the best candidate.
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
