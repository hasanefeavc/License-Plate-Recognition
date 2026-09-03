# 🚗 License Plate Recognition (LPR)

Turkish license-plate recognition for gate/barrier control. A headless FastAPI service
runs the vision pipeline in Docker; the Tkinter desktop app is now a thin client that
talks to it over HTTP + WebSocket.

Targets **Ubuntu 24.04 LTS** and **Windows 11**.

| | |
|---|---|
| **Just want it running?** | [⚡ Quick start (one click)](#-quick-start-one-click) — `run.bat` on Windows, `./run.sh` on Linux/macOS |
| **Installing this at a site?** | [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — the field guide, start to finish |
| **Training the detector?** | [`README_TRAINING.md`](README_TRAINING.md) |
| **Reporting a vulnerability?** | [`SECURITY.md`](SECURITY.md) |
| **Licensing / commercial use?** | [`COMMERCIAL.md`](COMMERCIAL.md) |
| **What changed?** | [`CHANGELOG.md`](CHANGELOG.md) |

> **Before commissioning a gate:** run `python scripts/fetch_models.py` and read
> its output. The repository ships **no trained plate detector** — `models/`
> holds the stock COCO baseline, and the pipeline falls back to contour
> detection, which misses angled, blurred and night plates entirely. See
> [`README_TRAINING.md`](README_TRAINING.md).

---

## ⚡ Quick start (one click)

Two different people run this for the first time, and they want different
things. Somebody commissioning a gate wants the service up with as few
decisions as possible, on a box that may never have had Python on it. Somebody
working on the code wants a virtualenv they chose and control. The launchers in
the repository root serve the first; the Docker and virtualenv paths below
serve the second. All three end at the same service on the same port, so
nothing is given up by starting with the easiest one.

### Option 1 — the one-click launchers

**Windows** — double-click **`run.bat`**. From a terminal it is the same file:

```bat
run.bat
```

In PowerShell that has to be `.\run.bat`: PowerShell will not run a program
from the current directory without the leading `.\`. See
[Troubleshooting](#troubleshooting) if you were expecting an execution-policy
problem — there isn't one, and the reason is worth knowing.

**Linux and macOS** —

```bash
./run.sh          # or: make launch
```

**Then open <http://localhost:8000>** — plate list, live preview, history, and
the manual gate button.

`run.sh` and `run.bat` are the same script written twice and kept deliberately
in step, so a site can be talked through a first start over the phone with one
set of instructions whatever it is running. Neither needs `make`, an activated
virtualenv, or any idea of what a virtualenv is. Both are idempotent: run them
again any time you are unsure whether something completed.

### What the first run does

Both launchers do the same five things in the same order, and each one stops
with a message naming the step that failed rather than a traceback:

1. **Find a usable interpreter.** Python **3.11 – 3.13** — which is
   `requires-python = ">=3.11,<3.14"` in `pyproject.toml` spelled out. *Both*
   ends are enforced, because both ends break: too old and the install fails in
   the resolver, too new and the ML wheels (torch, and easyocr's dependency
   chain) are not published yet. Checking here rather than letting pip refuse
   means the error names the real problem instead of arriving forty lines into
   an install log. On Windows the `py` launcher is tried first
   (`py -3.13`, `-3.12`, `-3.11`, `-3`) and bare `python` last; on Linux and
   macOS, `python3` first, then the versioned names.
2. **Create the virtualenv.** An existing `venv/` wins, because that is the
   name the Makefile hardcodes (`VENV ?= venv`) and a checkout already set up
   with `make setup` must not silently grow a second, half-installed
   environment beside the first. Anything else gets `.venv/`, which editors and
   tooling autodetect. Both are gitignored.
3. **Install the dependencies — but only when they are stale.** The sentinel
   `<venv>/.deps_installed` holds a SHA-256 over `requirements.txt` and
   `pyproject.toml`, so "stale" is answered by content rather than by a
   timestamp; git does not preserve mtimes, and a mtime comparison on a fresh
   clone answers either "always stale" or "never stale" depending on checkout
   order. **Expect the first run to take a few minutes** (torch and the OCR
   stack are most of it). Every run after that skips straight to the server,
   and a `git pull` that touches either file reinstalls without being asked.
4. **Provision the checkout**, on the same trigger as step 3 — a first
   install, or a dependency refresh: `scripts/setup_dev.py`
   creates `data/`, `models/`, `keys/` and `data/snapshots/`, generates the RSA
   licence-signing pair, mints a local developer licence into `data/.license`,
   and copies `.env.example` to `.env` if there is no `.env`. Nothing existing
   is overwritten without `--force`, which matters most for `.env` — that is
   the uncommitted file holding this machine's real secrets. A failure here is
   deliberately *not* fatal: the service starts degraded and reports what is
   missing, which is more use to somebody standing at the gate than a launcher
   that refuses to run.
5. **Start the service** — `python -m lpr.api.main`, after making sure `data/`
   and `data/snapshots/` exist so a permission problem on the data volume
   surfaces now, with a path in the message, instead of an hour later as a
   swallowed warning on the snapshot writer's thread. Host and port come from
   `config.yaml` / `.env` (`api.host`, `api.port`; `0.0.0.0:8000` as shipped).
   Ctrl+C stops it, and uvicorn's graceful shutdown stops the pipeline and
   joins the camera threads on the way out.

### Signing in for the first time

**No default username or password ships with this project**, and none is
generated — a gate controller with a known factory login is a gate that opens
for anyone who read the README.

The first account is created from the dashboard itself. The login screen reads
`setup_required` from the unauthenticated `/health` and shows the **Yönetici
Oluştur** button only while the user table is empty; the account created there
is made an admin. After that the button disappears, `POST /api/auth/register`
requires an admin token, and `POST /api/users` is the ordinary way to add
people. The full rules, and why the button is hidden by default rather than
shown permanently, are under [Bootstrap](#bootstrap).

One thing to change before this box is anything but a test bench:
`api.secret_key` ships as `change-me`, and running with `LPR_ENV=production`
refuses to boot while it still says that. Set `LPR_API__SECRET_KEY` in the
`.env` the launcher wrote — see [Secrets](#secrets).

### What has to be in place

| | |
|---|---|
| **Python 3.11 – 3.13** | The only hard prerequisite. On Debian/Ubuntu `python3-venv` is a separate package and the launcher says so if it is missing. |
| **A camera, or an RTSP URL** | `cameras.entry.source` ships as `"0"` — the first webcam on the machine. Exit ships blank, which means "this camera is not fitted", not an error: that is the normal single-camera site. Point either at an RTSP stream with `LPR_CAMERAS__ENTRY__SOURCE=rtsp://user:pass@host:554/stream1` in `.env`, or edit `config.yaml`. |
| **Detector weights** | A fresh clone has none — every `.pt` is gitignored. |

**None of these stop the service from starting**, and that is on purpose. With
no camera reachable, `/health` still answers 200 with `status: "degraded"` and
a `detail` naming the problem — and it distinguishes a role that configuration
validation switched off (a duplicate device, a source that is not an index, a
device, a URL or an existing file) from a camera that is simply not answering,
because the first is one line of `.env` and the second is a cable. With no
detection weights the pipeline falls back to the much weaker contour detector,
says so, and `GET /api/system/assets` names the exact file it is waiting for.
Fetch the baseline with `python scripts/fetch_models.py`; train the real plate
model per **[README_TRAINING.md](README_TRAINING.md)**. Until you do, treat any
plate it reads as a demonstration rather than a result.

### Option 2 — Docker (recommended for a permanent install)

The one-click launchers run the service directly on the host, which is the
right shape for a first look and for a developer machine. For a box that has to
come back up by itself after a power cut, the headless core in a container is
the better answer: the image pins the whole ML stack at a known version,
`restart: unless-stopped` brings the service back after a reboot, and a
healthcheck catches the wedged-but-alive process that a bare restart policy
cannot see. Provisioning still runs on the host — `scripts/setup_dev.py` is
import-light and needs only a Python, not the ML stack — because the `.env`,
the keys and the licence it writes are exactly the state that has to survive
the container being rebuilt.

```bash
python scripts/setup_dev.py               # .env, keys, licence, directories
# ...then set LPR_API__SECRET_KEY in the .env it just wrote
python scripts/fetch_models.py --easyocr  # baseline detector + OCR weights into models/
docker compose -f docker/docker-compose.yml up --build
curl http://localhost:8000/health
```

**The `.env` goes in the repo root, not in `docker/`.** That is the file the
compose stack injects (`env_file: ../.env`) and the file the application reads
directly when you run it on the host. A `.env` inside `docker/` is loaded by
Compose for `${...}` substitution *only* — and since nothing in the compose
files substitutes `LPR_API__SECRET_KEY`, a secret put there reaches neither the
container nor the app.

`data/`, `models/` and `config.yaml` are bind-mounted, so the database, weights and
settings live on the host and survive rebuilds. `--easyocr` pre-fills
`models/easyocr` with the ~100 MB of OCR networks; without it the first container
start downloads them itself, which is slow and is the step that fails on a flaky
link.

The compose file requests an NVIDIA GPU — see **[GPU acceleration](#gpu-acceleration)**
below for the toolkit it needs and how to run without one.

### Option 3 — a virtualenv you control (development)

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e ".[gui]"                               # only for the desktop client
lpr init                                              # directories, keys, licence, .env
lpr-api                                               # http://127.0.0.1:8000/docs
lpr-gui --api-url http://127.0.0.1:8000               # separate process/machine
```

`lpr init` is `python scripts/setup_dev.py` typed shorter — the script exists so
the very first command after `git clone` does not require `pip install -e .` to
have happened first. `make setup` is `install` followed by `init`, which is the
whole of a fresh checkout in one target.

**`make run` and `make launch` are not the same path, and the difference is
deliberate.** `make launch` is exactly `./run.sh`: the site path, no reload,
host and port from `config.yaml`. `make run` is the developer path — uvicorn
with `--reload`, forced onto `0.0.0.0:8000` whatever the config says. Reload
watches the source tree and restarts the process on every save, which is
exactly wrong at a gate, where a restart drops the camera threads mid-shift. So
neither target delegates to the other; making `run` call `run.sh` would have
silently taken the developer's reload away.

### What is missing, and why

```bash
make status    # what is installed, what is not; exits non-zero if anything is
make doctor    # ...plus torch/cv2/easyocr imports, the database, and stray LPR_ vars
```

Both are import-light on purpose: on a box where the ML stack is what is
broken, `status` still answers and `doctor` is what tells you which import
failed.

One wrinkle if you started with `./run.sh` on a fresh clone: every Makefile
target except `launch` runs the interpreter at `$(VENV)/bin/python`, and `VENV`
defaults to `venv` — while the launcher, finding no `venv/`, will have created
`.venv/`. Point make at it for the session, or export it once:

```bash
make status VENV=.venv
```

`make launch` is unaffected, because it hands straight over to `run.sh`, which
finds the environment itself.

---

## Troubleshooting

Everything here is a first-run failure — the launcher stopped, or it started
and the gate did nothing. Failures *after* a working install (a camera that
drops out, an OTA update that will not apply) are covered in their own sections
below and in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

### "Python was not found", or a Store page opens

Windows ships a stub `python.exe` on `PATH` that exists only to advertise the
Microsoft Store. That is why every probe in `run.bat` *runs* the candidate
interpreter instead of testing for the file: the stub exits non-zero without
opening the Store, so it is skipped rather than picked and failed on later.

When nothing usable is found you get one of two messages, and they mean
different things:

| Message | Means | Fix |
|---|---|---|
| `Python bulunamadi.` | No interpreter answered at all | Install from [python.org](https://www.python.org/downloads/) and **tick "Add Python to PATH"** during setup |
| `Kurulu Python surumu uygun degil.` | There is a Python, it is outside 3.11 – 3.13 | Install a supported version *alongside* the one you have — `py -3.12` will find it whether or not it is on `PATH` |

The second case is the common one on a machine that has kept up with releases,
and "install Python" is unhelpful advice to somebody who already has one, which
is why the launcher separates them.

### PowerShell "cannot be loaded because running scripts is disabled"

**`run.bat` is a batch file.** It is executed by `cmd.exe`, and PowerShell's
`ExecutionPolicy` governs `.ps1` files only — it does not and cannot block a
`.bat`. Almost everybody assumes otherwise and reaches for
`Set-ExecutionPolicy`; you do not need it here, and weakening it is a real
change to a machine's security posture made for no reason.

What *does* stop a batch file on Windows is the **mark of the web**. A file
extracted from a ZIP that a browser downloaded carries an alternate data stream
saying it came from the internet, and Windows then warns or refuses. Clear it:

```powershell
Unblock-File .\run.bat            # one file
Get-ChildItem -Recurse | Unblock-File   # the whole extracted tree
```

...or right-click the file, Properties → General → **Unblock**. Cloning with
`git` instead of downloading a ZIP avoids the mark entirely, which is the
better habit for something you will be pulling updates into anyway.

The other PowerShell surprise is not an error at all: `run.bat` alone is "not
recognized", because PowerShell does not search the current directory. Type
`.\run.bat`.

### Forcing a dependency reinstall

The launchers install only when the sentinel disagrees with the content of
`requirements.txt` + `pyproject.toml`, so an edit to either is noticed by
itself. Delete the sentinel when the environment was damaged by something
*else* — an interrupted `pip`, a half-deleted `site-packages`, a wheel
installed by hand and regretted:

```bash
rm .venv/.deps_installed          # or venv/.deps_installed
```

```bat
del .venv\.deps_installed
```

The next launch reinstalls everything and re-runs `scripts/setup_dev.py`.
Deleting the whole `.venv/` (or `venv/`) directory is the bigger hammer for the
case where the interpreter inside it is wrong — which the launcher will tell
you about by name, since it version-checks the environment that is actually
going to run the service rather than the system Python that would not.

### Port 8000 is already in use

The service will not bind and says so. Either free the port:

```bash
make stop                     # fuser -k 8000/tcp
ss -lptn 'sport = :8000'      # ...or find out what is holding it first
```

```bat
netstat -ano | findstr :8000
taskkill /PID <pid> /F
```

...or move the service, which is usually the right answer when something else
legitimately owns 8000:

```bash
LPR_API__PORT=8080            # in .env — the environment wins over config.yaml
```

`config.yaml`'s `api.port` is the other place to set it. Note that this only
affects `run.sh` / `run.bat` / `lpr-api`, which read the setting: `make run`
passes `--host 0.0.0.0 --port 8000` to uvicorn explicitly and ignores both
files.

### The camera does not open

`/health` answers `degraded` with a `detail` naming the cause, and
`GET /api/cameras` reports per-role state — start there, because the message
already distinguishes a role that configuration validation disabled from one
that is configured fine and not answering.

- **Linux, USB.** `ls -l /dev/video*` — the nodes are group-owned by `video`,
  so an account outside that group opens nothing at all. `sudo usermod -aG
  video $USER`, then log out and back in (group membership is granted at login,
  so a fresh shell is not enough). Prove the camera outside this project with
  `v4l2-ctl --list-devices` or `ffplay /dev/video0` before touching the config.
- **macOS.** The first capture attempt raises the system camera-permission
  prompt for the *terminal application*, not for this project. If it was ever
  denied, no amount of restarting helps until it is re-granted in System
  Settings → Privacy & Security → Camera.
- **Windows.** Settings → Privacy & security → Camera → "Let desktop apps
  access your camera". DirectShow also gives exclusive access, so a Teams,
  Zoom or Camera-app window holding the webcam is enough to keep the pipeline
  out of it.
- **Both roles on one device.** Entry and exit must not name the same camera —
  `"0"` and `/dev/video0` are one webcam spelled two ways. The second role is
  disabled with a warning naming the first; see
  [Camera sources](#camera-sources) for why that is refused at startup rather
  than left to fail at open time.

### RTSP: the stream is unreachable, or opens and then stops

Prove the URL outside the application first — it is the fastest way to tell a
credential problem from a network one:

```bash
ffplay -rtsp_transport tcp "rtsp://user:pass@10.0.0.5:554/stream1"
```

Then, in order of how often each one is the answer: a password containing `@`,
`:` or `/` must be percent-encoded or it truncates the URL; `rtsp_transport`
stays `tcp` (the default here, and not FFmpeg's) because udp on a congested or
wifi-bridged link produces torn frames that surface as OCR errors rather than
as network errors; `open_timeout_s` bounds the connect so a black-holed address
fails fast instead of hanging startup. A stream that opens and later goes quiet
is the failure the `stall_timeout_s` watchdog exists for — a TCP connection
that stays open while the camera stops sending, which otherwise parks the
capture thread forever while `/health` keeps answering 200.

### It starts, the dashboard works, and no plate is ever recognised

Almost always the missing detector. A fresh clone ships no trained weights, the
pipeline falls back to contour detection, and that misses angled, blurred and
night plates entirely. `GET /api/system/assets` names the file it wants; `make
status` prints the same thing from the command line. See
[README_TRAINING.md](README_TRAINING.md).

If the detector *is* in place, check that motion gating is not eating
everything (`motion_skipped` in `GET /api/stats`) and that the reads are
arriving but not clearing the vote (`grants` and `fast_path_hits` in the same
response).

### Where to look next

The launcher's own output is the first place; after that, `data/lpr.log`, which
is the rotating log file the service writes alongside its console output. In
Docker, `docker compose -f docker/docker-compose.yml logs -f` gives the same
records as single-line JSON.

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   RTSP / USB    │  headless core  (Docker, no display needed)  │
   cameras ─────▶│                                              │
                 │  CameraWorker ──▶ YOLOv8n ──▶ PaddleOCR ──▶   │
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
├── ocr/                PaddleOCR (default) and EasyOCR backends
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

## Secrets

Nothing tracked in this repository contains a real credential. Three files are
committed and all three are templates:

| File | Holds | Rule |
|---|---|---|
| `config.yaml` | Operational settings | No secrets. `smtp.password` stays `""`; `api.secret_key` stays `change-me`, which is what makes `LPR_ENV=production` refuse to boot unconfigured. |
| `.env.example` | Variable names and placeholders | Every value is a placeholder. Copy to `.env` **in the repo root** and fill that in. |
| `docker/docker-compose.yml` | Service definition | Injects the root `.env` with `env_file: ../.env`; carries no values of its own. |

Settings resolve in this order, lowest to highest:

```
config.yaml  <  .env  <  environment variables  <  constructor arguments
```

`.env` sits above `config.yaml` because `config.yaml` is committed and `.env`
is not — the uncommitted file is the one carrying the secret, so the committed
one must not be able to overwrite it. It sits below the real environment
because that is what it stands in for.

`.gitignore` ignores `.env` **and** `.env.*` while keeping `!.env.example`. The
wildcard matters as much as the plain name — `.env.production`, `.env.local`
and the `.env.save` an editor leaves behind all carry live credentials, and the
last of those is the one that gets committed by accident. The negation must
come *after* the wildcard: git applies the last matching rule, so reversing the
two lines would silently ignore the template as well.

`LPR_API__SECRET_KEY` and `LPR_LICENSE_SECRET` must be **different values**.
The first signs API sessions, the second signs deployment licences; sharing one
secret means a single leak forges both, and rotating either forces you to
rotate the other.

`tests/test_secrets.py` enforces all of this. The checks are shape-based rather
than a denylist — a long hex run, an opaque credential-shaped value, a
non-placeholder assignment to anything named `*SECRET*` or `*PASSWORD*` — because
a denylist only catches the secret you already know about.

### If a secret does get committed

Scrubbing the file does not help: the value is in the history and on every
clone and fork. **Rotate it.** Revoke a Gmail app password at
[myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords);
regenerate a signing key with `openssl rand -hex 32`. Rewriting history with
`git filter-repo` is optional cleanup afterwards, not the fix.

---

## Configuration

`config.yaml` holds the defaults; environment variables override it and win.
Nested keys use a double underscore:

```bash
LPR_CAMERAS__ENTRY__SOURCE=rtsp://user:pass@10.0.0.5:554/stream1
LPR_RELAY__PORT=/dev/ttyUSB0      # COM3 on Windows, "auto" resolves per-OS
LPR_DETECTION__DEVICE=cuda
```

`.env.example` lists **every** setting, spelled the way `Settings` declares it,
with its default. That completeness is enforced: `Settings` is declared
`extra="ignore"`, so a near miss (`LPR_SMTP__TO_ADDRS` for `to_emails`) is
silently discarded and the setting keeps whatever `config.yaml` said —
`tests/test_env_example.py` fails if the file and the models ever disagree, the
service warns at startup about any `LPR_` variable that configures nothing, and
`make doctor` lists them on demand.

### Camera sources

A source is a device index (`"0"`, `"1"`), an RTSP/HTTP URL, a device node
(`/dev/video0`), or a video file. **Blank means "this camera is not fitted"** —
that is the normal single-camera site, not an error.

Two configurations are refused at startup rather than left to fail at open
time, because at open time both look exactly like an unplugged camera:

| Configuration | What happens | Why |
|---|---|---|
| Entry and exit naming the same device — including `"0"` and `/dev/video0`, which are one webcam spelled two ways | The **second** role is disabled, with a warning naming the first | V4L2 gives exclusive access and hands the loser `VIDIOC_QBUF: Bad file descriptor`; DirectShow on Windows locks the device outright and takes the capture pipeline down with it. Which role loses depends on thread scheduling, so the symptom moves between cameras run to run |
| A source that is not an index, a device, a URL or an existing file | That role is disabled, with a warning quoting what was configured | Otherwise it is an endless reconnect loop indistinguishable from a cable fault |

Either way the *other* camera keeps working: a site with one good camera and
one misconfigured one runs on the good one. `GET /api/system/assets` and
`/health` both report which role was disabled and why.

Cross-platform: `"0"` works everywhere, and string integers are accepted in any
spelling a hand-edited file produces (`" 0 "`, `"00"`, `"+0"`). A `/dev/videoN`
path is rewritten to the bare index on Windows, so a config written on the
Linux box still opens the right camera when it is carried over.

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
with the same account the desktop client uses (on a fresh install, **Yönetici
Oluştur** creates the first account, which becomes the admin).

Two details make it work in a browser: an `<img>` cannot send an
`Authorization` header and neither can a WebSocket handshake, so the MJPEG and
event endpoints also accept the bearer token as `?token=`. That was already in
the API before the web UI existed.

Styling is a pre-compiled local bundle at `web/static/css/app.css`, served
from the same `/web` mount as the page, so the dashboard renders identically on
a gate box with no route to the internet — which is most of them. Fonts are OS
stacks and every icon is a Unicode glyph or an inline `<svg>`, so nothing on
the page is fetched from a remote host at all.

The bundle is generated, not hand-written: `scripts/build_web_css.py` scans
`web/index.html` and `web/app.js` for utility class names and compiles each one
against a Tailwind-compatible rule table. Regenerate it after editing either
file:

```bash
make css          # rebuild web/static/css/app.css
make css-check    # fail if the committed file is stale (CI and `make test` run this)
```

A class the markup uses and the table cannot compile is reported rather than
skipped, so a new utility cannot ship as a silently unstyled element.

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

#### The image is attached to the row, not just filed beside it

Matching timestamps make an image and its record *line up*; they do not make
either one point at the other. Reading a decision out of the history and then
reconstructing a filename from its `ts` and plate is an operation that works
until a plate contains a character the filesystem spells differently, or the
snapshot lands a second either side of the row, or somebody moves the directory
— and it fails silently every time, by finding nothing.

So the link is stored. `logs.snapshot_path` (schema v9) holds the path the
writer actually wrote, filled in after the fact by the writer thread, so the
decision is never delayed waiting for a JPEG to encode. From there:

- `GET /api/logs` returns `has_snapshot` on every row, resolved for the whole
  page in one query rather than one stat call per row.
- `GET /api/logs/{id}/snapshot` serves the image, behind the same
  `LicensedUser` dependency as `GET /api/logs` itself — the picture is more
  sensitive than the row that points at it, so it can never be the easier of
  the two to reach.
- The dashboard's history table shows a thumbnail indicator on the rows that
  have one and previews it inline; a row with no image simply does not offer
  the control, which is the honest answer to "was anything captured here".

**Every kind of absence is the same 404**, deliberately: an unknown row, a row
with nothing linked, snapshots switched off, a frame the writer dropped, a file
the retention sweep removed. They are one answer to the client — there is no
picture here — and separating them would let a caller probe which log ids exist.

The stored path is re-resolved against the configured snapshot directory before
anything is served. That column was written by this application, but it is still
a filesystem path arriving from the database, and a path resolving outside the
snapshot directory is refused rather than read: the check costs one `resolve()`
and removes the whole class.

### Vehicle sessions: who is inside, and for how long

The `logs` table answers "what happened at the gate". It does not answer "how
long has that car been in here", which is the question a car park is actually
run on — and deriving it per query means walking the log backwards looking for
a matching entry, once per vehicle, every time anybody opens the dashboard.

The `sessions` table (schema v9, written through `SessionRepository`) keeps that
answer as a fact rather than a computation: one row per stay, with `plate`,
`entry_ts`, `exit_ts`, the `logs` ids at both ends, a `status`, and
`duration_seconds`. Rows are written **from granted decisions only** — a refused
car did not enter, and a stay ledger built from attempts would count it as
though it had.

Three cases decide the shape of the table, and each is recorded rather than
smoothed over:

| Situation | What is written | Why |
|---|---|---|
| Entry for a plate with no open stay | A new `open` row | The ordinary case |
| A second entry for a plate already inside | Nothing — the open stay is kept | Two cameras seeing one car, or a driver who reversed and came back in, must not become two overlapping stays for one vehicle. The first entry is the true one |
| An exit with no open stay | A row with `status = 'orphan_exit'`, `entry_ts` NULL and NULL duration | The car was inside before this table existed, or its entry was missed. Inventing an entry time would put a fabricated number into the record; a NULL says exactly what is known |

Duration is computed on read for a stay that is still open, so "so far" is
measured when the request is served rather than by a background job that has to
be running for the number to be right.

`GET /api/sessions/active` lists the vehicles inside, longest stay first;
`GET /api/sessions/history` pages through completed and open stays, newest
first, filterable by plate — paged like `GET /api/logs`.

**The dashboard shows this beside the occupancy counter, not instead of it.**
The two numbers are derived independently — occupancy from the gate log,
the active-stay counter from the sessions ledger — and they are put next to each
other precisely so a disagreement is visible. A counter that reconciled itself
against the other would hide the one thing worth knowing: that the site's record
of who is inside has drifted from the site's record of what came through the
gate. Note also that they measure over different windows by design — the
occupancy tally resets at 00:00 UTC, because a gate log is not a parking
contract, while a stay stays open until its car leaves.

---

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | liveness; reports `degraded` when the pipeline is down |
| `POST /api/auth/login` · `/register` | none · first-user-or-admin | JWT bearer token |
| `GET/POST /api/plates` · `PATCH`/`DELETE /api/plates/{plate}` | user · admin | allow-list CRUD, partial edit |
| `POST /api/plates/import` · `GET /api/plates/export` | admin | bulk CSV in/out |
| `GET /api/events/export` | user | access history as CSV |
| `GET /api/logs` · `/api/logs/dates` | user | history, filterable by camera/plate/date; rows carry `has_snapshot` |
| `GET /api/logs/{id}/snapshot` | user | the evidence JPEG behind one decision; 404 for every kind of absence |
| `GET /api/sessions/active` · `/api/sessions/history` | user | vehicles currently inside; completed and open stays |
| `GET /api/stats` · `/api/cameras` | user | pipeline and per-camera health |
| `POST /api/relay/trigger` · `/api/pipeline/pause` · `/resume` | admin | manual control |
| `GET /api/license` · `POST /api/license` | user · admin | licence state; install a new key |
| `GET /api/stream/{camera}` | bearer | MJPEG preview (capped ~10 fps) |
| `GET /api/users` · `POST /api/users` · `DELETE /api/users/{username}` | admin | account management |
| `POST`/`DELETE /api/users/{username}/license` | admin | issue / revoke an operator licence |
| `GET /api/license/me` · `POST /api/license/activate` | user | own licence state; enter a key |
| `GET /api/system/version` | user | deployed version (`git describe`), commit and branch |
| `GET/POST /api/system/update` | admin | OTA update status; trigger an update, optionally `{"force": true}` to rebuild anyway (202) |
| `GET /api/system/events` | admin | operational audit trail (nightly OTA activity) |
| `WS /ws/events?token=` | token | live plate events as JSON |

Interactive docs at `/docs`.

---

## Accuracy design

The legacy pipeline was Canny edge detection → contour search → a four-point warp →
Tesseract `--psm 8`. It needed a clean quadrilateral, so it failed on angled, blurred,
night and partially-occluded plates.

### Where it currently stands

Measured on the 47 hand-labelled frames in `data/ocr_ground_truth.json`, with
the default PaddleOCR backend on CUDA:

| | |
|---|---|
| Plate accuracy | **95.74 %** — 45 of 47 read exactly right |
| Character error rate | **0.57 %** |
| Wrong plate | **4.26 %** (the 2 remaining errors) |
| Miss rate | **0.00 %** — every frame produced a read |
| Latency | mean **106.5 ms**, p50 **99.1 ms**, p95 **136.0 ms** |

Reproduce it, or re-measure on your own footage, with:

```bash
python scripts/evaluate.py --images <dir> --truth data/ocr_ground_truth.json \
       --backend paddleocr --device cuda
```

`--device` defaults to `cpu`, so leaving it off measures a different machine
from the one the latencies above came from. `--compare-backends` runs every
supported engine over the same images and prints them side by side, which is
the measurement to make before switching one.

Two numbers there deserve more than a table cell. **The miss rate is zero and the
error rate is not**, which is the harder of the two shapes to live with: the
pipeline always answers, so a wrong answer arrives looking exactly like a right
one, and everything downstream — the multi-frame vote, the whitelist check — is
there to stop a confident wrong string from moving a barrier. And **both
remaining errors are the same kind of mistake**, M read as H and M read as N.
That is a glyph-shape confusion, not a preprocessing failure: the positional
repair map cannot help, because all three are legal letters in the letter block,
so the read is grammatical and wrong. It is the case a second engine in the
ensemble is for.

This is a small, single-site set. It says what this installation's cameras
produce, not what a plate recogniser scores in general, and the point of
`scripts/evaluate.py` shipping with the project is that a new site measures its
own rather than inheriting these.

### The engine underneath

The recognition backend is **PaddleOCR**, and it is the default by measurement
rather than by preference: on the same 47 labelled frames it read 89.4 % of
plates exactly against EasyOCR's 25.5 %, at comparable latency, before the
margin-trimming work below took it to where it is now. EasyOCR stays installed
beside it — it is the fallback for a box where paddle will not build, it is the
second opinion `ocr.ensemble_backends` pools in, and it needs no system
libraries of its own. Switching is one line (`ocr.backend`), and
`scripts/evaluate.py --compare-backends` is how that choice should be made.

The version is capped below 3.0 deliberately. PaddleOCR 3.x moved to PIR-format
model files through paddlex, and a `paddlepaddle` that cannot execute them fails
at *inference* with `ConvertPirAttribute2RuntimeAttribute not support` — every
read comes back empty, which looks exactly like a model that cannot see the
plates rather than a version mismatch. `paddleocr>=2.10,<3` with
`paddlepaddle>=3.0,<3.1` is the pair this was validated on.

### The six layers

The replacement stacks six independent accuracy layers:

1. **YOLOv8n detection** — learned plate localisation, plus plausibility filters on
   aspect ratio, area, and Laplacian sharpness so blurred crops never reach OCR.
2. **Crop enhancement** — trim whatever sits left of the number (the blue band by
   colour, a dark margin by luminance), then upscale, dynamic gamma + percentile
   contrast stretch, CLAHE, bilateral denoise, unsharp mask, deskew; the recogniser builds the grayscale,
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
   `ocr.ensemble_backends: [easyocr]` to add the second engine as an equal voter
   alongside the default PaddleOCR.
4. **Turkish normalisation** — `^(0[1-9]|[1-7][0-9]|8[01])([A-Z]{1,3})([0-9]{2,4})$`,
   with a *positional* confusion map (`0↔O`, `1↔I`, `8↔B`, `5↔S`, `3↔E`, …) applied per
   block: digits in the province code, letters in the middle, digits in the tail. Case is
   consulted where upper-casing would lose information — a lowercase `b` is the classic
   misread of `6` where an uppercase `B` is the classic misread of `8`, so the lowercase
   reading is tried as a fallback when the read as written does not parse. Q/W/X and
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
or has burned `voting.max_track_attempts` reads without confirming anything, OCR is
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
| 0 | **Left-margin trim** (`strip_euroband`, then `trim_dark_margin`) | Before `to_gray`, because the first of the two works by colour and grayscale has none. Whatever sits left of the number — the blue EU/TR band, a frame, a bumper, a shadow — is not part of the plate but is part of the picture the recogniser is shown, and it reads as a character. |
| 1 | **Upscale** to a 64 px character height (cubic, capped at 4×) | A 20–30 px crop wastes most of the recogniser's capability. Capped because interpolating 6 px to 64 px invents detail rather than revealing it. |
| 2 | **Dynamic gamma** (`auto_gamma` / `apply_gamma`) | Global exposure must be fixed before anything local runs. |
| 3 | **Percentile contrast stretch** (`stretch_contrast`) | Spreads what survives gamma across the full range. |
| 4 | **CLAHE** (clip 2.0, 8×8 tiles) | Local contrast, to separate characters from a dirty plate. |
| 5 | **Bilateral denoise** | Edge-preserving: a plain Gaussian would soften the strokes the recogniser needs. |
| 6 | **Unsharp mask** (`unsharp_mask`) | Puts back the stroke edges the bilateral filter softened. |
| 7 | **Adaptive threshold** | Binarised variant, produced *last* so it thresholds a crisp image. |

#### Trimming what is not the plate

A phantom *leading* character is worse than a wrong one. It shifts every position
after it, so the province coercion in `normalize_plate` then repairs the wrong
slots and one bad glyph becomes a bad plate: `34TE6456` came back as `23LTE6458`,
`34HKD338` as `03LH3381`. Over the 47 labelled frames, 11 of 71 character errors
were insertions of this kind, and they clustered at the front of the string.

`strip_euroband` removes the blue band — **detected, never assumed**. The obvious
implementation, always dropping the leftmost 12 %, is wrong on this project's own
data: a detector box is often tight around the number with no band inside it at
all, and a blind crop then eats the province digit and *creates* the error it was
meant to remove. So a band has to be found — contiguous from the left edge, blue,
and the right width — or the crop is returned untouched.

`trim_dark_margin` is its companion, and it is the one that works at night. Hue
cannot separate a band from the bodywork around it on a blue-cast frame; measured
on this project's own failures, the whole left fifth of such a crop reads as band
blue and the colour detector correctly refuses. Luminance still separates
cleanly, because whatever is left of the number is dark and the printed plate is
white. Three of the five errors remaining at 89 % accuracy were a fabricated
digit in front of an otherwise perfect read — `34HB4082` returned as `13AHB4082`
— and all three were fixed by this stage.

It is guarded so it cannot eat a plate: a crop with no real dynamic range is left
alone (there is no margin to find in a uniformly grey picture, only noise to trip
over), the bright region has to be *sustained* rather than one column so a
specular highlight on a bumper is not mistaken for the plate, and nothing is
trimmed unless the margin is wide enough to hold a character and never more than
`DARK_MARGIN_MAX_FRACTION` of the width. Both functions return the crop object
itself when there is nothing to remove, so a caller can tell "no band" from "band
removed" by identity.

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

When no contour collapses to a clean quadrilateral — a dirty, cluttered or partly
occluded border — it falls back to `minAreaRect` → `boxPoints`, which always yields four.
That is a weaker correction by construction: a rectangle cannot express the trapezoid of a
true side-on view, so warping one back is a rotation and a scale rather than a perspective
fix. It earns its place on the case nothing else covers — a plate rotated past
`MAX_DESKEW_DEGREES` (15°), where `deskew` refuses the angle as implausible and the
polygon fit cannot find the outline, so the crop previously got no geometric correction at
all. The guard is a fill ratio: `minAreaRect` returns a rectangle for *any* contour,
including an L-shaped shadow edge, so the contour must fill ≥ 60% of its own bounding
rectangle before that rectangle is trusted.

It is deliberately conservative, because a wrong warp does not degrade a crop gracefully —
it destroys it. A quad is rejected when it is too small (< 25% of the crop), non-convex,
would rectify to a non-plate aspect ratio, or is merely the crop's own border (a no-op
warp that edge detection readily finds on a noisy crop). Any rejection returns `None` and
the caller keeps what it had. Cost ≈ 0.6 ms when it runs.

Rectification is an **escalation**, not a default stage: it runs only when no cheap variant
produced a grammatical plate, so ordinary plates never pay for the extra OCR pass.

#### Low light: Otsu and reversed polarity

A third and last stage covers the two night failures the standard views cannot.

**Otsu.** The crop pre-pass binarises with an *adaptive* threshold, which decides per
neighbourhood — exactly right for a plate lit from one side. On a uniformly dark crop it is
exactly wrong: every neighbourhood is flat, so each is thresholded against its own sensor
noise and the result is speckle. `otsu_binarize` takes a single global cut from the whole
histogram, which is what that crop actually needs. It declines when the 5th–95th percentile
spread is under 12 grey levels, because the "two modes" it would split are then the noise
floor and itself.

**Inversion.** Both recognisers are trained on dark glyphs over a light field. An IR
illuminator against a retroreflective plate inverts that, and a negative is the only thing
that fixes it. `hard_case_variants` supplies the Otsu image, the negative of the grayscale,
and the negative of the Otsu image.

These views are *wrong* for an ordinary daylight plate — inverting a perfectly readable crop
invites a confident misread — so like rectification they are an escalation, reached only
after the earlier stages have failed.

#### When escalation stops

The recogniser stops climbing the stages as soon as it holds a read that is **grammatical
and confident enough**, the floor being `preprocess.escalate_below_confidence`.

The confidence half of that test matters more than it looks. Grammar alone used to end the
search, so a read that parsed at 0.3 stopped it — and the pipeline then discarded that read
for being under `ocr.min_confidence`. The crop was thrown away having never been shown the
views most likely to rescue it, which are precisely the angled and low-light crops the later
stages exist for. The default matches the `ocr.min_confidence` default, so out of the box
the recogniser keeps trying exactly as long as its best read would still be refused
downstream. Every extra ballot also feeds the same vote, so a correct-but-unsure read is
more likely to be *confirmed* by the harder views than overturned by them.

#### Configuration

Everything in this section is software-level — it changes what the models are *shown*,
never what they learned, so none of it requires the detector retrained.

| Knob | Default | What it does |
| --- | --- | --- |
| `preprocess.normalize_lighting` | `true` | Dynamic gamma + percentile contrast stretch, ahead of CLAHE. Runs before CLAHE deliberately: CLAHE equalises per 8×8 tile and will amplify the noise inside a black tile to full scale if the crop arrives globally underexposed. Self-limiting — a normally-exposed plate passes through untouched. |
| `preprocess.crop_unsharp_amount` | `0.6` | Unsharp strength in the crop pre-pass. `0` disables it. |
| `preprocess.rectify_perspective` | `true` | Retry a failed read on a perspective-corrected crop. One extra OCR pass, only on crops that already produced nothing grammatical. |
| `preprocess.hard_case_variants` | `true` | Last-resort Otsu and polarity-inverted views for dark and IR-lit crops. Same bargain as rectification — an extra OCR pass, paid only on crops that already failed. |
| `preprocess.escalate_below_confidence` | `0.5` | Keep escalating while the best read scores below this. `0` restores stopping at the first grammatical read whatever its confidence. |
| `ocr.backend` | `paddleocr` | The recognition engine. PaddleOCR is the default; `easyocr` is the supported fallback for a box where paddle will not install. |
| `ocr.ensemble_backends` | `[]` | Extra OCR engines pooled into the per-frame vote as equal voters, e.g. `[easyocr]` alongside the default PaddleOCR. |
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

### Fast path: the first confident read of a registered plate

The accuracy machinery below is built for the hard case — a dirty plate at
night, at an angle, where the answer is worth several OCR passes and several
frames of agreement. A resident's car in daylight is not that case, and until
this existed it paid the same bill: the full escalation ladder, then
`voting.min_votes` frames before the barrier moved.

The fast path short-circuits the *OCR* half of it. After **every view** — not
every stage, since the first stage is itself several OCR passes — the running
vote is offered to the pipeline. If it is above `voting.fast_path_confidence`
*and* names a plate `PlateRepository.authorization` clears at that instant, the
remaining views are never computed. The finished read is offered one last time
after the ladder has run, so a crop that only became legible on its final view
still exits early rather than paying for views it no longer needs.

Whether that early exit may also **open the barrier on that single frame** is a
separate switch, and it ships off:

```yaml
voting:
  fast_path_enabled: true      # skip the remaining OCR views on a confident hit
  fast_path_confidence: 0.82
  fast_path_opens_gate: false  # ...but still require the multi-frame vote
```

`fast_path_opens_gate: false` is the shipped default because the confidence
score cannot carry the weight the earlier design put on it. Measured on the 47
labelled frames, the correct reads scored 0.905–0.999 and the *wrong* ones
scored 0.949 and 0.955 — inside the same band. There is no threshold that
separates them, so a single-frame gate opening is not a confident decision with
a small error rate; it is an unguarded one. With the switch off, a fast-path hit
still saves the escalation ladder — the part that was always free — and the
plate still has to win `voting.min_votes` of the last `voting.window` reads
inside `voting.ttl_s` before the relay fires.

A site that has measured its own footage and wants the last frame of latency
back sets it to `true` knowingly. Nothing else in the configuration is a
one-line change with that much reach.

These two used to be a top-level `fast_path:` section with the keys `enabled`
and `min_confidence`. That section is still read — an in-place upgrade keeps
its old `config.yaml` and its old decision — but it is only consulted when the
newer keys are absent, so there is exactly one value in play at runtime.

What is skipped, and what that costs:

| | Slow path | Fast path |
|---|---|---|
| Enhanced views (gamma, unsharp, rectify, Otsu) | computed as needed | never computed once the vote holds |
| Frames before the gate moves | `voting.min_votes` (default 2) | the same 2, unless `fast_path_opens_gate` is on |
| Applies to | every read | reads that clear the whitelist *now* |

The escalation saving is free: those views exist to rescue a crop that did not
read, and this one did. **The multi-frame saving is not free**, which is why it
is now behind `fast_path_opens_gate` and off. Turned on, a single confident
misread that happens to spell a *registered* plate opens the barrier, where the
ordinary path would need `voting.min_votes` frames to agree on the same wrong
string. Two bounds are left holding it, and only one of them is load-bearing:
the misread has to land on a plate actually registered at this site rather than
on something merely plate-shaped. The confidence threshold is the softer bound —
softer than it looks, since the measurement above found wrong reads scoring
higher than correct ones — and at 0.82 it is deliberately softer still than the
0.90 this shipped with — a clean, well-lit plate reads in the 0.82–0.90 band
often enough that the higher bar sent most registered cars round the full
voting path anyway, which is the latency the fast path exists to remove. A site
that wants no early exit at all sets `voting.fast_path_enabled: false`, which
gives up the escalation saving too — that one switch controls both halves,
whereas `fast_path_opens_gate` controls only the half that touches the relay.

Everything that is not a live permit keeps the full path: an unknown plate, a
blocked one, and an expired permit are exactly the cases the enhanced views and
the multi-frame vote were built for. `voting.fast_path_confidence` is floored at
`ocr.min_confidence`, so it can never admit a read the ordinary path would have
discarded.

`GET /api/stats` reports `fast_path_hits` alongside `grants`, which is the hit
rate — if it stays near zero, the threshold is above what your cameras
actually produce.

Recognisers are not required to support it. The orchestrator probes for the
`accept` parameter once at construction; a recogniser implementing only the
one-argument `Recognizer` protocol loses the *ladder* half of the early exit —
there is no predicate to stop the escalation — but keeps the half that matters
at the barrier, because the finished read is checked against the whitelist
either way.

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
read. Enable with `ocr.ensemble_backends: [easyocr]` (the second engine beside the
default PaddleOCR); a configured engine that is not
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
Shipped defaults are 5 / 2 / 4.0s. **Shortening `ttl_s` makes confirmation stricter, not
better** — the agreeing reads must then land within a narrower window, so a car crossing
slowly or a plate briefly occluded confirms less often. Raise `min_votes` if you want
fewer false opens; shorten `ttl_s` only if you want the gate to forget a car faster.

`min_votes` was lowered from 3 to 2. Past two agreeing reads inside `ttl_s` — after the
positional repair in `lpr.ocr.normalize` and the Levenshtein merge below — a third read
almost never changes the answer; it just costs another `detection.frame_stride` with a
car waiting at a closed gate. What actually guards the barrier is that the plate has to
be registered, and agreement between frames is the cheaper, secondary check.

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

### GPU acceleration

Both halves of the ML stack run on CUDA when a usable GPU is present. One probe in
`src/lpr/accel.py` decides for both, so the detector and the recogniser cannot end up
on different devices, and it runs once per process rather than once per component.

The probe is deliberately stronger than `torch.cuda.is_available()`: it allocates a
tensor on the device before answering yes. That call alone returns true for a driver
older than the wheel's CUDA runtime, which then raises on the first kernel launch —
i.e. at the gate, mid-shift, rather than at startup.

Both settings default to auto-detect, so the same `config.yaml` deploys to the GPU box,
a CPU-only spare and CI:

```yaml
detection:
  device: auto      # or "cpu", "cuda:0", "0" to pin a specific card
ocr:
  gpu: auto         # or true / false
```

A device that is asked for but not usable is **downgraded to CPU with a warning**,
never honoured. That matters more than it sounds: `detection.device: cuda` on a CPU box
used to raise inside ultralytics, which `build_detector` caught and answered by
substituting the far weaker contour detector — so a device error surfaced as an
accuracy collapse.

**Container requirements.** Two things have to line up, and only one of them is the
compose file:

1. The [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
   on the host, which passes the device through:
   ```bash
   sudo apt install nvidia-container-toolkit
   sudo nvidia-ctk runtime configure --runtime=docker && sudo systemctl restart docker
   docker compose -f docker/docker-compose.yml run --rm lpr-api nvidia-smi   # verify
   ```
2. A **CUDA-enabled torch wheel inside the image**. The Dockerfile defaults to the CPU
   index so a plain `docker build` stays small (~800 MB against ~2.5 GB); compose
   overrides it via the `TORCH_INDEX_URL` build arg. Missing this is the classic
   failure: the GPU is passed through correctly, `nvidia-smi` works in the container,
   and the service still logs `EasyOCR (gpu=False)` — because the torch that was
   installed cannot use it. Override the CUDA version for an older driver:
   ```bash
   TORCH_INDEX_URL=https://download.pytorch.org/whl/cu121 \
     docker compose -f docker/docker-compose.yml build
   ```
   The wheel's CUDA version has to be **no newer than the host driver supports**.
   `nvidia-smi` prints the driver's ceiling in its header (`CUDA Version: 13.2`); a
   cu130 wheel on a driver that tops out at 12.x reports no device at all, which looks
   identical in the log to a GPU that was never passed through.

No `nvidia/cuda` base image is needed — the CUDA runtime libraries ship inside the
torch wheels and the host driver is injected at runtime.

**Which engine is behind the `docker` command?** This decides how the device is
requested, and the CLI does not tell you — a Docker CLI can be talking to a Podman
socket. `docker version` reports the client; `docker info | grep "Server Version"`
reports what is actually running the container (Podman answers with its own version,
e.g. `5.7.0`).

| Engine | How to request the GPU | What happens if you use the other one |
|---|---|---|
| Docker Engine | `deploy.resources.reservations.devices` (in `docker-compose.yml`) | A CDI name fails at container-create unless CDI is enabled |
| Podman, or Docker ≥ 25 with CDI | `devices: ["nvidia.com/gpu=all"]` (in `docker-compose.cdi.yml`) | **The reservation is accepted and silently ignored** |

That second failure is the nasty one, and it is what
`no CUDA device visible to torch 2.13.0+cu130; running on CPU` in the logs means when
the driver and the wheel are both fine: Podman's Docker-compatible API takes the
`deploy` block, passes no device, returns no error, and the container comes up healthy
on CPU. The reservation block exists to make a missing GPU loud, and on that engine it
cannot. Run the overlay instead:

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.cdi.yml up -d
```

The overlay needs a CDI spec on the host, generated once (`nvidia-ctk cdi list` shows
the device names it may use):

```bash
sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml
```

**Verify the device, not the container.** A container that started proves nothing —
that is the whole trap:

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.cdi.yml \
  run --rm lpr-api python -c "import torch; print(torch.cuda.is_available())"
```

On Docker Engine the reservation stays a hard requirement: without the toolkit, `up`
fails at container-create rather than starting silently on CPU. That is the right
default for the gate box, but a CPU-only host needs it dropped, most cleanly through an
uncommitted `docker/docker-compose.override.yml`:

```yaml
services: {lpr-api: {deploy: {resources: {reservations: {devices: []}}}}}
```

On CUDA the detector also ignores any `.onnx` export and runs the `.pt` directly, since
requirements.txt installs the **CPU** `onnxruntime` wheel on purpose — adopting the
export would quietly move detection off the GPU and end up slower than the `.pt` it
replaced.

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

**OCR weights.** EasyOCR needs ~100 MB of its own (a CRAFT detector and an English
recogniser) and fetches them lazily on first use. They are cached in `models/easyocr`
— a bind-mounted volume — rather than in EasyOCR's default `~/.EasyOCR`, which inside
a container is a layer that `docker compose up --build` throws away; that is why every
rebuild used to re-download them before the service could process a frame.

```bash
python scripts/fetch_models.py --only-easyocr    # run once per machine
```

Once the cache is complete the service passes `download_enabled=False`, so a
provisioned box opens no socket at startup and comes back after a power cut with the
uplink down. Until then the download is bounded by `ocr.download_timeout_s` (60 s
default) — EasyOCR calls `urlretrieve` with no timeout of its own, so a half-open
connection would otherwise hang startup indefinitely, past the compose healthcheck and
with no log line saying why. Set `ocr.allow_download: false` on an air-gapped site to
refuse the download outright and fail fast with a message naming the fix instead.

---

## Email alerts

When a vehicle is refused at the gate, the service can send an email with the
event snapshot attached. Off by default (`smtp.enabled`).

Two situations, separately switchable, because they mean different things to an
operator — an unknown car at 3 a.m. is a question, a barred one is an answer:

| Setting | Fires when |
|---|---|
| `smtp.notify_on_unauthorized` | the plate is not on the list at all |
| `smtp.notify_on_blacklisted` | the plate **is** on the list but flagged `blocked` |

Nothing about this is on the recognition path. `notify()` puts the alert on a
bounded queue and returns; one daemon worker owns the SMTP conversation — the
same shape as the relay and the snapshot writer, and for the same reason. A
refused connection, a rejected recipient or a full queue is logged and dropped:
the decision it is reporting on has already been made, recorded in `logs` and
photographed before this module was asked to do anything.

The attachment is the very JPEG `snapshots.py` wrote, not a second encode of
the same frame — `SnapshotWriter.submit()` takes an `on_saved` callback that
fires on the writer thread once the file is down. It fires on *failure* too, so
a full disk costs the photograph but never the alert.

Two things worth being deliberate about before enabling it:

- **`smtp.password` must stay empty in `config.yaml`.** That file is committed,
  so a value written there is published to everyone with repository access —
  and it stays in the git history after you delete it. Set
  `LPR_SMTP__PASSWORD` in `.env` (gitignored), which overrides the file. A
  configured `user` with no password is treated as *unusable*: the notifier
  refuses to start with one warning rather than failing authentication once per
  refused vehicle.
- **The snapshot is personal data in most jurisdictions.** Send it to a mailbox
  the site operator controls, and keep `to_emails` short.

Repeat alerts are already bounded by `voting.cooldown_s`: a car idling at the
gate re-confirms constantly but decides once, so one refused vehicle is one
email, not one per frame.

---

## Roles and per-operator licences

### What each role may do

| | Operator | Admin |
|---|---|---|
| Plates: add, edit, block, delete, import, export | ✅ | ✅ |
| Gate (`/api/relay/trigger`), pause/resume, camera source | ✅ | ✅ |
| Parking capacity, stream quality | ✅ | ✅ |
| OTA: status **and trigger** | ✅ | ✅ |
| **Kullanıcılar** (accounts, licences) | ❌ | ✅ |

Only account management is admin-only. Everything that *operates* the site is
an operator's job — they are the ones standing at the barrier.

> **Operators can trigger OTA updates on this deployment.** That runs
> `git pull` and a `docker compose` rebuild, so it is code execution on the
> host for anyone holding an operator session. If that is not what you want,
> `/api/system/update` is one dependency change (`LicensedUser` → `AdminUser`)
> away from being admin-only again.

### Vehicle access versus application access

Two licences live in this system and they must never be conflated.

| | `users.license_expires_at` | `plates.expires_at` |
|---|---|---|
| What it is | One account's subscription to the **application** — the dashboard, `/web`, `/api` | One vehicle's **permit** at the barrier |
| Who it refuses | The person signing in | The car at the gate |
| How it refuses | 403 + `Kullanıcı lisans süresi dolmuştur` | `DENIED`, relay untouched |
| Where it is enforced | `lpr.api.security.require_license` | `PlateRepository.authorization` |

A registered plate opens the gate whenever it exists, is not blocked, and its
own `expires_at` (if it has one) is still in the future. **The barrier never
reads `plates.username`, and never consults the licence of the account a car is
recorded against.** An operator or tenant whose dashboard subscription lapsed
still has residents, and those residents still have cars.

The reasoning is about blast radius, not tidiness. A lapsed dashboard licence
is a billing matter between a vendor and a customer; a resident sitting at a
closed barrier at midnight is a physical access failure. Wiring the first into
the second means an unpaid invoice strands people in the street, so the
dependency must not exist in that direction. `test_pipeline` asserts it at the
relay — a plate owned by an expired account still pulses it and still logs
`registered, gate opened` — and `test_db` asserts it at the repository.

Note that `plates` has no `is_active` column: "active" here means *not blocked*
and *not past its own expiry*, which is what `lpr.api.schemas.plate_status`
derives for the management screen.

### Per-operator licences

Access control is **entirely** the per-user model. The deployment licence
(`lpr.license`, RS256 from a vendor public key) is still read and still
reported by `GET /api/license`, but it no longer halts the pipeline, refuses
the gate, or appears in the header. An installation-wide expiry that leaves an
administrator standing at their own barrier unable to restart it is an outage,
not a commercial control. Re-enabling the hold is one edit in
`deps.apply_license_state`.

These are HS256 keys the server issues to its own operators. They cannot be
confused with the deployment licence — different algorithm, different key
material, and a `typ` claim checked on the way in.

### Generation and activation are separate events

A key encodes a **duration**, not a deadline: `duration_days` plus the username
it was issued to, and no `exp`.

| | Generation (admin) | Activation (operator) |
|---|---|---|
| Endpoint | `POST /api/users/{username}/license` | `POST /api/license/activate` |
| Writes to the account | **nothing** | key, expiry, duration, `activated_at` |
| Status after | unchanged (`pending_activation`) | `active` |
| Countdown | not started | starts *now* |

An admin can cut a 365-day key on Friday for a Monday start and the operator
still gets a full year. Starting the clock at generation would burn the weekend
— and the days it spends in an inbox — off the licence.

Once activated the **database** holds the expiry, and `license_for()` reads it
from there. Re-deriving it from the key on each request would restart the
countdown every time and the licence would never run out.

The trade-off worth knowing: an un-activated key does not go stale. It is bound
to one account and grants exactly the span written into it, but it stays usable
until somebody uses it. Treat a generated key like the password it effectively
is until the operator has activated it.

**Administrators are exempt by construction.** The account that issues keys
cannot sensibly be locked out by one: an admin holding an expired key could not
issue a replacement, and the installation would need its database edited by
hand to recover. Admins carry a permanent **Sınırsız Yönetici Lisansı** badge.

**Disabled until configured.** With `LPR_LICENSE_SECRET` unset there is nothing
to sign with and every operator passes. That is deliberate rather than
fail-closed — an upgrade that silently locked every operator out of a working
barrier, at a site never told to set a new secret, is the worse failure.

| State | Header badge | Meaning |
|---|---|---|
| `unlimited` | **Yönetici (Sınırsız)** | An administrator, or enforcement switched off |
| `active` | **Lisanslı (XX gün kaldı)** | Activated and still within its span |
| `pending_activation` | **Lisans Bekliyor** | A new account, or a key not yet entered |
| `expired` | **Lisans Süresi Doldu** | The recorded expiry has passed |
| `revoked` | **Lisans İptal Edildi** | Withdrawn by an admin |

A new operator starts at `pending_activation` — named for what it is waiting
on, because a new hire on their first morning is not an error. Clicking any
non-unlimited badge opens the activation dialog, as does the first refusal.

Revocation keeps the key and the dates and changes the *status*. A signed key
cannot be un-signed, so the status flag is the only thing that can actually
withdraw it — and keeping the rest lets an admin see what was revoked and when
it had been due to end.

Keys are bound to the account they were issued to. Without that, any operator
could activate a colleague's key and inherit its validity.

### Where the licence checks run

Both the revocation check and the licence check read SQLite, and both sit on
every authenticated request. They run through `asyncio.to_thread`, not inline:
a synchronous read on the event loop is a millisecond when the database is
idle, but under write contention it waits on the busy-timeout and stalls *every*
concurrent request rather than only its own.

They also resolve the repository as a **real FastAPI dependency**
(`Depends(get_user_repository)`) rather than calling the provider directly.
`app.dependency_overrides` is keyed on the callable's identity, so a direct call
— or a thin local wrapper — silently bypasses any override and reaches the
process's real database.

### Enforcement

`require_license` gates every authenticated endpoint — operating the site and
reading it alike — and answers **403 Forbidden** with the detail
`Kullanıcı lisans süresi dolmuştur`. A role refusal is a 403 too, so the
*detail* is what separates them: the dashboard matches that exact string and
opens the licence dialog on it, once per lapse. `web/app.js` keeps the string
in one constant (`LICENSE_LAPSED`) and a test asserts it still matches the
server's.

The same check runs at three other doors, because an account refused in one
place and admitted in another is not refused at all:

* **`POST /api/auth/login`** — a lapsed account never receives a token.
* **`GET /api/stream/{camera}`** — it takes its token in the query string, so
  it cannot use the dependency; a live camera feed is exactly the access a
  lapsed account must not keep.
* **`WS /api/ws/events`** — closed with `1008`, after an `error` frame naming
  the reason, because browsers do not reliably expose the close reason.

Four endpoints are deliberately never gated, because they are how an operator
learns about the lapse and undoes it: `GET /api/auth/me`, `GET /api/license`
(the deployment licence, i.e. "why did the system stop"), `GET /api/license/me`
and `POST /api/license/activate`.

Refusing the login would otherwise be a trap — activation needs a session, and
the session is what has just been refused. So `POST /api/auth/login` accepts an
optional `license_key` alongside the credentials: it is activated first (after
the password is checked, never before) and the same request is admitted. The
login screen reveals the key box once the server has named the lapse.

The browser dashboard itself is static files and is still served to anyone at
`/web`, because the login screen has to be reachable before anyone is
authenticated. Everything it then asks for is gated, so a lapsed account gets
the licence dialog and an otherwise empty page.

**None of this reaches the barrier.** `users.license_expires_at` is one
account's subscription to the application. Whether the gate opens is decided by
the `plates` row alone — see
[Vehicle access versus application access](#vehicle-access-versus-application-access).

A failure to *read* the licence lets the request through, like the revocation
check it sits beside: this is a layer on top of an already-valid session, and a
database hiccup must not close a working barrier.

### Issuing a key

**Kullanıcılar → Lisans Üret**, with 30 / 90 / 365 days or a custom span. The
key is shown once, for the admin to copy and send — it is *not* stored, because
the account is untouched until the operator activates it. The operator pastes it
into **Lisans Anahtarı Girin**, and that is when the countdown starts.

---

## Users and sessions

### Session length follows the role

The two roles are used differently, so they get different session lengths. An
administrator works from their own machine, where being logged out mid-task is
friction with no security payoff. An operator signs in on a shared terminal at
the gate, where a session that outlives the shift is the actual risk.

| Setting | Default | For |
|---|---|---|
| `api.admin_token_ttl_min` | 525600 (365 days) | Administrators — "stays logged in" |
| `api.operator_token_ttl_min` | 480 (8 hours) | Operators — one shift |
| `api.token_ttl_min` | 720 | Fallback for any other role |

An admin can also set a per-account length when creating a user
(`token_ttl_min`), which beats the role policy. Leaving it unset inherits the
role default, so the policy stays retunable centrally.

### Why deletion takes effect immediately

These are stateless JWTs, and a year is long enough for a signed claim to go
badly stale. Two things must not wait for expiry:

- **Deletion.** If removing an account did not end its sessions, "delete user"
  would be theatre — a dismissed operator would keep their access for the rest
  of the token's life.
- **Demotion.** An account moved from admin to operator carries a token that
  still says `admin`.

So `resolve_live_user()` re-reads the account behind every token: one indexed
primary-key lookup per authenticated request, and the database role is the
authoritative one. A *lookup failure* is deliberately not treated as deletion —
it is logged and the token honoured, because this is a revocation layer over a
signature that is still valid, and a transient database error should not lock
every operator out of a running gate.

**What this does not protect against.** A year-long admin token on a stolen
laptop is valid for that year unless the account is deleted. Shorten
`admin_token_ttl_min` if administrators sign in from machines you do not
control.

### Managing accounts

**Kullanıcılar** in the navbar — admin only, and hidden outright for operators
rather than opening a modal whose every request returns 403. The table shows
the username, a role chip (**Yönetici** purple / **Operatör** teal), the
session length, the creation date and a delete button.

`DELETE /api/users/{username}` refuses two things, checked in this order:

1. **The last admin.** There is no recovery path — with no admin left, nobody
   can create one, and the installation needs its database edited by hand.
   `POST /api/auth/register` will not help: it only bootstraps when the user
   table is *entirely* empty.
2. **Your own account.** The request would succeed and then invalidate the
   token that made it, which reads as the dashboard breaking.

The order matters. When the sole administrator deletes their own account both
rules apply, and only the first says what to do about it — create another admin
first. Answering "ask another admin" on an installation with no other admin
would be useless.

### Bootstrap

`POST /api/auth/register` is unauthenticated for exactly one account: the first
one on a fresh installation, which is always made an admin. After that it
requires an admin token, and `POST /api/users` is the ordinary path.

The login screen reads `setup_required` from the unauthenticated `/health` and
only shows **Yönetici Oluştur** while the user table is empty. Leaving that
button up permanently would advertise an action that can only fail, and read
like open sign-up on a gate controller. It defaults to hidden and is revealed
on proof — a server that cannot answer gets the sign-in form alone.

---

## Dashboard: sessions and plate management

### Signing in

Username and password only — nobody is ever asked to paste a token. The JWT
comes back from `POST /api/auth/login`, goes into `localStorage`, and is
replayed on the next visit against `GET /api/auth/me`: a stored token is a
*claim*, and the server decides whether it is still good. A rejected token is
cleared and the login screen returns, so an expired session cannot leave the
dashboard half-alive.

The navbar carries the username and a role chip (**Yönetici** / **Operatör**),
which is the fastest answer to "why can't I press that?".

Beside it, in the same counter row so it costs no vertical space — the dashboard
is locked to one viewport — sit two numbers that should agree: **İÇERİDEKİ ARAÇ**
(occupancy, counted from the gate log against the configured capacity) and
**AKTİF PARK** (open stays, counted from the sessions ledger, with the longest
one alongside). They are computed from different sources on purpose; see
[Vehicle sessions](#vehicle-sessions-who-is-inside-and-for-how-long).

**What an operator does not see.** Role gating is mirrored in the UI so an
operator sees why a control is inert rather than collecting 403s — the add
form, the CSV import/export row, and every row action are hidden or disabled;
the OTA update panel is hidden outright; the capacity block in Ayarlar is
hidden while the stream-quality selector beside it stays, because that is a
per-device preference an operator legitimately sets. This is presentation
only: every one of those endpoints re-checks the role server-side.

### Plate management

`GET /api/plates` returns both shapes in one request — `plates` as bare strings
(what the desktop client has always consumed) and `records` with the schema-v4
resident data. Additive, so nothing that predates it breaks.

The table renders a plate badge, owner and apartment on one line with the note
beneath, a status badge, the expiry date (or *Süresiz*), and row actions:

| Badge | Meaning |
|---|---|
| **Aktif** (green) | On the list, no expiry |
| **Misafir** (blue) | Temporary permit, still valid |
| **Süresi Doldu** (orange) | Permit lapsed — the gate refuses it |
| **Engelli** (red) | Barred deliberately; outranks expiry |

**Status is derived server-side**, in `plate_status()`. Expiry decides whether
the barrier opens, and that comparison is made against the *server's* clock — a
dashboard on a machine with a wrong clock must not show a badge that
contradicts what the gate will do.

**Search** filters on plate, owner, apartment and note, over the records
already loaded rather than a request per keystroke: a resident list is hundreds
of rows, so filtering locally is both faster and more reliable. Plate matching
ignores spacing, so typing `34ABC` finds the row displayed as `34 ABC 123`.

**The block toggle is a partial write.** `PATCH /api/plates/{plate}` with
`{"blocked": true}` changes the flag and nothing else. A full-overwrite PUT
would blank the owner, apartment, note and expiry the toggle never asked about,
which is why `PlateRepository.update()` exists alongside `upsert()` — the
latter writes every column by design, and that is exactly wrong here.

Deletion asks for confirmation; blocking does not, because blocking is
reversible from the same button and deletion is not. A blocked plate stays
visible and auditable rather than vanishing and being silently re-addable by
the next CSV import.

**Date pickers submit `YYYY-MM-DD`**, which is widened to `T23:59:59+00:00` on
the way in. Stored as bare midnight, a permit "valid until 1 January" would
lapse as 31 December ended — a full day early, refusing a resident on the day
their sticker says they are fine.

---

## Bulk plate lists (CSV)

The `plates` table carries resident data as of schema v4 — `owner`,
`apartment`, `expires_at` and `blocked` alongside the plate. Existing databases
are migrated in place on startup by additive `ALTER TABLE ADD COLUMN`
statements; `CREATE TABLE IF NOT EXISTS` alone would leave a pre-v4 table
untouched and every query naming `owner` would fail.

Two of those columns are access rules, not decoration:

- **`expires_at`** in the past — a temporary permit that has run out. The gate
  refuses it and it reports as *unauthorized*.
- **`blocked`** — listed deliberately, to be refused. A resident who has moved
  out stays visible and auditable instead of being deleted and silently
  re-addable by the next import. Refusals report as *blacklisted*.

### Import

`POST /api/plates/import` (admin, multipart) takes a CSV with a `plate` column;
`owner`, `apartment`, `notes`, `expires_at` and `blocked` are optional.

`?overwrite=false` (the default) **skips** plates that already exist;
`?overwrite=true` updates them in place. Skipping is the default because
re-uploading last month's list is a normal thing for a site manager to do, and
it must not silently overwrite owner and expiry data corrected since.

Rows are processed independently. One mistyped plate in row 400 of a resident
list does not reject the other 399 — the response carries per-row counts and a
numbered error list, and row numbers count from the file's first line so they
match what the spreadsheet shows.

**The parser expects what Excel actually writes**, because that is what arrives
at a gate:

| Reality | Handled by |
|---|---|
| UTF-8 BOM on every "CSV UTF-8" save | `utf-8-sig` decode, plus stripping a second BOM from a double round-trip |
| `;` delimiter on a Turkish/German/French locale | delimiter counted off the header row |
| cp1254 encoding from a plain "CSV" save | encoding fallback chain |
| Turkish headers (`plaka`, `sahibi`, `daire`, `notlar`) | alias table |
| Header case and spacing, extra columns, blank trailing lines | normalised / ignored |

The delimiter is counted off the **header line** rather than handed to
`csv.Sniffer`. The header is the one row guaranteed well-formed; Sniffer's
frequency heuristics are thrown by the ragged short rows and ISO timestamps a
real export contains, and guessing wrong collapses every row into one column
and rejects the file for a missing `plate` header.

### Export

`GET /api/plates/export` (admin) and `GET /api/events/export` (any
authenticated user) return UTF-8-BOM CSV with CRLF line endings, so a
double-clicked download opens straight into Excel rather than the import
wizard. The event export takes the same filters as `GET /api/logs`, so the file
matches what the operator is looking at — and it is built server-side, covering
the whole filtered range rather than the page currently on screen.

The plate export round-trips: download, edit in Excel, re-upload with
`overwrite=true` is a supported way to bulk-edit residents.

In the dashboard both live where the data does — **İçe Aktar (CSV)** and
**Dışa Aktar (CSV)** in Plaka Yönetimi (admin only, hidden for operators), and
**Dışa Aktar (CSV)** in Geçmiş.

---

## Remote updates (OTA)

The **Sistem Güncellemesi** card in Ayarlar (`#settings-ota-section`) is always
rendered, for both roles. What varies is whether its three buttons —
**Güncellemeleri Kontrol Et**, **Sistemi Güncelle** and **Zorla Yeniden Derle /
Yeniden Başlat** — are live:

| Server state | Card | Buttons |
|---|---|---|
| `system_update.enabled: true` | shown | enabled |
| `system_update.enabled: false` | shown | disabled, naming the setting |
| `/api/system/version` fails | shown | disabled, with the error |
| Endpoint absent (older build) | shown | disabled, saying so |

It used to start hidden and be revealed only on a successful version call with
`update_enabled`. That lost the card in two ways: a server with updates off
showed nothing at all, and *any* error before the reveal left it hidden with
the reason swallowed. Fetching the update status and history is best-effort —
neither can take the card down.


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
  # Whatever you pass by hand, pass here too — see below.
  compose_overrides: []
```

Then uncomment the OTA block in `docker/docker-compose.yml`, which mounts the
repo (so `git pull` has a checkout — the image itself has no `.git`) and the
engine socket (so the container can rebuild its own stack).

Without those mounts the endpoint still answers; the update just fails with a
specific message rather than a traceback — *"… bir git deposu değil"* or
*"Docker soketine erişim reddedildi"*.

**Three things have to line up, and two of them fail silently.**

1. **A client in the image.** `docker compose … up -d --build` runs *inside*
   the container, so the image needs the Docker CLI and the compose plugin —
   the daemon stays on the host. The Dockerfile installs both (build with
   `OTA_CLIENT=0` to skip them, ~90 MB, on a site that updates by hand).
   Without them the update pulls the new code, *then* fails at the build step
   with `Komut bulunamadı: docker-compose`, leaving new code on disk and the
   old image running — worse than not updating at all.

2. **The right socket.** `/var/run/docker.sock` is not universal, and the
   compose file therefore defaults to the rootless-Podman path
   (`/run/user/1000/podman/podman.sock`), mounted read-write onto
   `/var/run/docker.sock` inside the container with
   `DOCKER_HOST=unix:///var/run/docker.sock` set alongside it.

   Get this wrong and it fails in one of two ways, which need opposite fixes
   and are reported separately:

   | Symptom | Meaning |
   |---|---|
   | `permission denied while trying to connect to the Docker API` | The socket is there and the container may not open it — on a rootless Podman host, `/var/run/docker.sock` is a *different*, root-owned engine |
   | `Cannot connect to the Docker daemon` | Nothing is listening at that path — the bind mount is absent or points somewhere the engine is not |

   Set `LPR_DOCKER_SOCK` in `.env` to whatever `echo $DOCKER_HOST` prints on
   the host — `/var/run/docker.sock` on Docker Engine, a different uid's path
   on another rootless box. Verify it from inside a container before trusting
   it, because a mount that *looks* right can still be unopenable:

   ```bash
   docker run --rm -v ${LPR_DOCKER_SOCK}:/var/run/docker.sock:rw curlimages/curl \
     -s --unix-socket /var/run/docker.sock http://localhost/_ping    # -> OK
   ```

3. **Every compose file you normally pass.** This module is what brings the
   service back up, so an overlay named only on your command line is dropped
   on every rebuild. On a Podman or CDI host that overlay is the GPU
   passthrough, and the container comes back healthy on CPU:

   ```yaml
   system_update:
     compose_overrides: ["docker/docker-compose.cdi.yml"]
   ```

`GET /api/system/update` replays the last attempt's command log, which is where
all three of these show up as the exact command that failed.

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
   When the commit does *not* move (a forced rebuild, or nothing to pull), the
   client falls back to `GET /api/system/update`: a status that is no longer
   `running` is the ending.

Failures land in `GET /api/system/update` with a `log` tail of the git and
compose output, which the dashboard shows verbatim under the button.

### Forcing a rebuild with nothing to pull

By default, a pull that brings no new commit ends the run with *"Sistem zaten
güncel; yeniden derleme yapılmadı."* and never reaches `docker compose`. That is
the right default — a rebuild costs a few minutes of outage at the barrier, and
spending it to redeploy the identical commit is a cost with no benefit.

It is also the wrong answer for the cases operators actually hit: a container
still running a stale image, an edited `.env` or `config.yaml` that only a
recreate picks up, or a checkout that cannot fast-forward and so never reaches
the build step at all. None of those had a button.

**Zorla Yeniden Derle / Yeniden Başlat** posts `{"force": true}`, which inverts
the gates in `SystemUpdater._advance_checkout`:

| Situation | Default | `force: true` |
|---|---|---|
| Pull brings a new commit | rebuild | rebuild |
| Pull brings nothing new | stop, "zaten güncel" | rebuild anyway |
| Pull fails (diverged, local changes, no network) | fail, no rebuild | log the reason, rebuild what is on disk |
| Directory is not a git checkout | fail | rebuild anyway (compose needs a compose file, not a repo) |
| Build itself fails | fail | fail |
| `system_update.enabled: false` | 503 | 503 |
| Another update in flight | 409 | 409 |

Two limits are worth stating plainly, because "force" is a word that invites
assumptions. It does **not** override the deployment's own consent — the enable
flag and the single-flight guard are untouched — and it does **not** make a
failed build succeed. It only removes the reasons *not to start* one.

`force` is also the first and only value the HTTP layer forwards to the
updater. It selects between two fixed code paths and is never interpolated into
a command, so it changes *whether* the configured build runs, never *what* gets
built; the remote, branch, repo directory and compose file remain configuration
only.

A forced run is flagged `forced: true` all the way through — in the 202 reply,
in the polled status, and in `last_update.json`, so the container that comes up
afterwards still reports *"Yeniden derleme tamamlandı"* rather than claiming an
upgrade that never happened.

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

What happens when it lapses: **nothing stops.** The state is recorded, logged
and reported by `GET /api/license`, and that is all — recognition keeps
running, the relay keeps working and the gate keeps opening for registered
plates. Access control is entirely the per-user model above; an
installation-wide expiry that left an administrator standing at their own
barrier would be an outage, not a commercial control. Re-enabling the hold is
one edit in `deps.apply_license_state`, which is why it is still a function.

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
| 123 MB vendored `Tesseract-OCR/` in git | untracked; OCR via PaddleOCR by default, EasyOCR as the fallback and second voter |
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

**1688 passing tests** across 40 modules, with no skips and no expected
failures. Tests run without torch, a GPU or a camera: ML-dependent modules are
`importorskip`-guarded and the pipeline tests drive the orchestrator through protocol
fakes, so the suite is fully collectable in a CI job with no ML wheels installed.

| Module | Tests | Covers |
| --- | ---: | --- |
| `test_api.py` | 223 | Routes, JWT auth, MJPEG stream, WebSocket events, OTA authorisation, CSV endpoints, plate records, the snapshot route |
| `test_web_ui.py` | 134 | Dashboard endpoints, role gating, gate button, CSV controls, plate table redesign |
| `test_detect.py` | 109 | Box plausibility, letterbox round-trips, crop padding, gamma/contrast, unsharp, perspective rectification, sharpness gating |
| `test_normalize.py` | 93 | Turkish grammar, positional repair, edit-cost cap, candidate extraction |
| `test_pipeline.py` | 90 | Queue semantics, frame stride, thread lifecycle, sliding-gate cooldown, alert wiring, vehicle sessions |
| `test_db.py` | 77 | Repositories, migrations, retention, system-event trail, partial plate updates |
| `test_updater.py` | 71 | OTA: command construction, conflict/permission/timeout paths, restart state, remote check, version naming |
| `test_evaluation.py` | 62 | Plate accuracy, CER, wrong-plate and false-positive rates |
| `test_csvio.py` | 51 | CSV parsing: BOM, delimiters, encodings, Turkish headers, conflict policy |
| `test_secrets.py` | 50 | No credentials in tracked templates; `.env*` ignore rules |
| `test_preprocess_pipeline.py` | 46 | Preprocessing wiring: escalation staging, frame-hook injection |
| `test_ocr_recognizer.py` | 42 | OCR backend construction: which device it claims, where the weights are cached, a bad network wedging startup |
| `test_notify.py` | 40 | SMTP dispatch (mocked), attachment handling, failure containment |
| `test_voting.py` | 38 | Multi-frame consensus, TTL expiry, cooldown, track-aware merging |
| `test_config.py` | 36 | Shipped defaults: sliding-gate cooldown, pulse width, voting threshold, single-frame gate bypass off, fast-path key migration |
| `test_camera.py` | 35 | RTSP hardening: FFmpeg options, stall watchdog, backoff, credential masking, a source that never opens |
| `test_license.py` | 30 | Signature validation, anti-rollback, expiry |
| `test_relay.py` | 30 | Serial pulse queue, MockRelay fallback |
| `test_snapshots.py` | 28 | Evidence writer, retention, off-hot-path encoding |
| `test_user_license.py` | 28 | Key issue/verify, binding, expiry, revocation precedence |
| `test_dataset.py` | 27 | YOLO dataset validation: empty splits, train/val leaks, pixel labels |
| `test_camera_sources.py` | 26 | Camera source classification; duplicate and unopenable sources refused while the string is still a string |
| `test_ui_client.py` | 26 | Transport-only API/WS client |
| `test_scheduler.py` | 24 | Nightly job: clock arithmetic, refusal-to-act paths, loop resilience |
| `test_accel.py` | 22 | GPU probing and the device/model-cache wiring it feeds, asserted from a CPU-only host |
| `test_machine.py` | 22 | Machine fingerprinting, tolerant matching, hardware-bound licences |
| `test_ratelimit.py` | 21 | Login rate limiting, progressive lockout, eviction safety |
| `test_label_ocr_dataset.py` | 20 | OCR ground-truth labelling tool: a human's label is stored as typed, never normalised |
| `test_web_assets.py` | 20 | The dashboard is fully styled with no network access; the generated stylesheet stays in step with the markup |
| `test_backup.py` | 19 | SQLite backup consistency, restore, pre-migration safety net |
| `test_ensemble.py` | 19 | Confidence-weighted vote, near-miss merging, multi-engine pooling |
| `test_ui_app.py` | 19 | Tkinter queue drain, widget thread safety |
| `test_parking.py` | 18 | Occupancy accounting |
| `test_auth_sessions.py` | 14 | Role-scoped session lengths, token revocation on delete/demote |
| `test_model_assets.py` | 14 | Model-file reporting and provisioning: a fresh clone is degraded, not broken |
| `test_pipeline_streaming.py` | 14 | Camera selection and live-view decoupling: an unsourced role is skipped, two roles never share a device |
| `test_provisioning.py` | 14 | `lpr init`: a second run destroys nothing — not the signing key, the licence, nor the `.env` |
| `test_degraded_reporting.py` | 13 | What `/health` and `/api/stats` say when the weights, the pipeline or a camera is missing |
| `test_paths_cross_platform.py` | 13 | Paths that must mean the same on Linux and Windows: snapshot filenames, configured directories, containment |
| `test_env_example.py` | 10 | `.env.example` and the settings models must not drift apart |

The accuracy layers are deliberately the most heavily tested: `test_detect.py`,
`test_normalize.py`, `test_voting.py`, `test_ensemble.py`,
`test_preprocess_pipeline.py`, `test_evaluation.py` and `test_dataset.py`
together account for 394 of the 1688 collected tests. Every
preprocessing primitive is additionally asserted to be *total* — it must return its input
unchanged rather than raise, on `None`, on an empty array, and on a degenerate crop.

---

## License

Dual-licensed: **AGPL-3.0-or-later** ([LICENSE](LICENSE)) **or** a commercial
licence ([COMMERCIAL.md](COMMERCIAL.md)).

Running it on your own site for your own vehicles asks nothing of you. The AGPL
bites when you distribute it, host it for other people, or want to keep your
modifications closed — those are the cases the commercial licence exists for.
The table in `COMMERCIAL.md` says which side of the line a given deployment
falls on.

Two things worth knowing:

- **`ultralytics` is itself AGPL-3.0.** A commercial licence for this project
  does not relicense it, so a commercial deployment that ships YOLO needs an
  arrangement with Ultralytics too.
- **Revisions up to `8da39ec` were released under MIT.** That grant cannot be
  withdrawn — anyone who took those revisions under MIT keeps those rights to
  *those* revisions. The relicensing applies from the commit that changed
  `LICENSE` onward. See [NOTICE](NOTICE).
