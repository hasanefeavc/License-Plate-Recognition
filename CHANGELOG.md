# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries say what changed **and what it means for a running site**, because the
audience is somebody deciding whether to take an update onto a gate that people
are currently driving through.

---

## [Unreleased]

### Security

- **BREAKING — `role` now defaults to `viewer` when a request omits it.**
  Affects `POST /api/users` and `POST /api/auth/register`. It previously
  defaulted to `operator`, which carries eleven write endpoints including
  `POST /api/relay/trigger`, the manual gate-open button — so an account
  created without anyone choosing a role received the one privilege the
  `viewer` role had just been added to withhold.

  The two failure directions are not symmetric. A viewer who should have been
  an operator is refused with a 403 and an admin corrects the role in seconds;
  an operator who should have been a viewer is invisible until the wrong person
  opens the barrier.

  **What to check before upgrading:** any client or script that creates
  accounts *without* naming a role and expects them to be able to write. Add
  `"role": "operator"` to those calls — the role remains fully selectable, this
  changes only what happens when nobody chooses. The bootstrap path is
  unaffected: the first account on an empty installation is forced to `admin`
  regardless of the request body.

### Fixed

- **`.env` was never read outside Docker**, so `POST /api/users/{username}/license`
  answered 503 (`LPR_LICENSE_SECRET tanımlı değil`) on any host run.
  `Settings` listed a dotenv source in its precedence chain but configured no
  `env_file` for it to read — it looked configured and did nothing. Under
  Compose the same file is injected as real environment variables by
  `env_file: ../.env`, which is why only host runs were affected, and only for
  anyone who had not exported the variable by hand.
- **`config.yaml` outranked `.env`.** Once the dotenv source read anything, the
  two overrides the documentation tells a site to use would still have lost to
  the placeholders they exist to replace: `config.yaml` ships
  `api.secret_key: change-me` and `smtp.password: ''` as *written* values, so
  `LPR_API__SECRET_KEY` stayed `change-me` and the mail notifier stayed on and
  mute. `.env` now sits directly beneath the real environment — the
  uncommitted file carries the secret, and the committed one cannot overwrite
  it.
- **`.env` is resolved from the repo root, not the working directory**, so a
  systemd unit and `make run-api` find the same file. `LPR_ENV_FILE` relocates
  it for a site keeping secrets outside the checkout.
- **README told you to put `.env` in `docker/`.** Compose reads a file there
  for `${...}` substitution only, and nothing substitutes `LPR_API__SECRET_KEY`
  — a secret placed there reached neither the container nor the application.
- **E-mail alerts were silently off on any host run**, for the same reason: the
  password arrives through `LPR_SMTP__PASSWORD` in `.env`, so `smtp.usable` was
  false, `notify()` refused every alert and the counters read
  `sent=0 failed=0 suppressed=n`. No exception was raised because nothing was
  attempted — which is why it did not look like a failure.

### Added

- **`scripts/test_email.py`** — sends one real alert end to end and reports
  `sent` / `failed` / `dropped` / `suppressed`. `tests/test_notify.py` drives
  every branch of the notifier with an injected sender and deliberately opens
  no socket, so this covers the one link those tests cannot: whether this
  site's credentials, port and TLS settings actually deliver. It prints which
  source supplied each SMTP value first, because "I set it in config.yaml and
  nothing happened" is usually answered by something further up the chain.
  `--dry-run` exercises the whole path without a socket.
- **Unrecognised `LPR_*` variables are named in a warning at startup.**
  `Settings` is `extra="ignore"`, so a plausible near-miss — `LPR_SMTP__TO_ADDRS`
  for `to_emails`, `LPR_SMTP__USERNAME` for `user` — was discarded in silence
  and the setting stayed at whatever `config.yaml` said, with the operator
  looking at a `.env` that claimed otherwise. Reported, not rejected: a stale
  line in an old `.env` must not stop a gate from starting. `.env.example` now
  spells out the SMTP names that are easiest to guess wrong.

---

## [1.0.0] — 2026-09-01

The commercial readiness release. Four phases of an external audit, from a
repository that was a good pipeline into one that can be installed at a
customer site and charged for.

**This release contains breaking changes and a mandatory security action.**
Read [Upgrading to 1.0.0](#upgrading-to-100) before deploying it.

### Security

- **The licence signing key was rotated.** The previous RSA private key was
  committed to a public repository and must be treated as compromised. Every
  licence issued under it is void; reissue from the new key.
  ([BLK-02](#audit-references))
- **Licences are now bound to hardware.** A key names the machine it was issued
  for, so a copy no longer works on a second site. Binding is opt-in per key —
  existing unbound keys keep working. ([BLK-04](#audit-references))
- **The container no longer runs as root.** `user: "0:0"` overrode the image's
  unprivileged user; camera access now comes from a supplementary group.
  ([BLK-05](#audit-references))
- **The Docker socket moved out of the default stack.** In-app updates require
  `docker-compose.ota.yml`, which grants host-root access and says so.
- **`network_mode: host` is gone.** One port, published to loopback by default.
- **Login is rate limited** by address, with progressive per-account lockout.
  There was previously no limit of any kind. ([HP-01](#audit-references))
- **CORS no longer ships wildcard-with-credentials** — a combination browsers
  reject outright, so the deployment looked configured and behaved as though it
  had no CORS at all. ([HP-02](#audit-references))
- **TLS is supported and documented** via `docker-compose.proxy.yml` (Caddy,
  automatic certificates, HSTS, CSP, `X-Frame-Options`). ([HP-03](#audit-references))
- **The OpenAPI schema is off in production** unless `LPR_API_DOCS=1`.
- **Camera credentials are masked** in logs, status objects and API responses.
  RTSP passwords were reaching support log bundles in clear text.
  ([HP-09](#audit-references))
- **`system_update.enabled` now ships `false`.** The module documented itself as
  "disabled by default" while the shipped `config.yaml` said `true`, so every
  site installing it as-is got a live remote-code-execution endpoint.

### Added

- **`viewer` role** — read-only access to the live view, the pass log and the
  occupancy count. An attendant who needed to read a log previously had to be
  given `operator`, which carries the manual gate-open button.
  ([HP-04](#audit-references))
- **Anti-passback** — refuses a second entry for a vehicle the log says never
  left. Off by default; never blocks an exit. ([HP-07](#audit-references))
- **RTSP hardening** — TCP transport, FFmpeg socket timeout, and a watchdog
  thread that breaks a stalled read. A stream that stopped sending used to park
  the capture thread forever while `/health` kept answering 200.
  ([BLK-06](#audit-references))
- **Exponential reconnect backoff with jitter**, reset only by a delivered
  frame.
- **Database backups** — nightly `VACUUM INTO`, plus a mandatory copy before any
  schema change, with automatic rollback when a migration fails.
  ([HP-10](#audit-references), [BLK-07](#audit-references))
- **OTA rollback and health gate** — a failed build is reverted synchronously; a
  build that starts but never becomes healthy is reverted on the next boot.
  ([BLK-07](#audit-references))
- **Snapshot disk-pressure limits** — a total size ceiling and a free-space
  floor, enforced oldest-first, raising a system event. Retention was
  age-only, which bounds how old the evidence gets and not how much of it there
  is. ([HP-05](#audit-references))
- **Relay drivers** for GPIO (Raspberry Pi), Modbus RTU/TCP and HTTP/IP relays,
  alongside the existing serial board. ([HP-06](#audit-references))
- **`relay.require_hardware`** — refuses to start on a mock relay. A mocked
  relay logs every vehicle as granted while no barrier moves, which looks like
  success everywhere except at the gate.
- **Accuracy evaluation** — `scripts/evaluate.py` reports plate accuracy, CER,
  wrong-plate rate, false-positive rate and CPU-vs-CUDA latency, with CI gates.
  ([HP-08](#audit-references))
- **Dataset tooling** — `scripts/fetch_dataset.py` scaffolds, downloads and
  validates a YOLO dataset before a GPU is booked.
- **`scripts/hwid.py`** — prints a machine's licensing fingerprint for a
  binding request.
- **CI** (`.github/workflows/ci.yml`) — secret scan, lint, unit tests, full
  suite, optional accuracy gate.
- **`SECURITY.md`**, **`COMMERCIAL.md`**, **`NOTICE`**, this file, and
  `docs/DEPLOYMENT.md`.

### Changed

- **Licence: MIT → AGPL-3.0-or-later with a commercial exception.** MIT
  permitted anyone to strip the licence check and resell, which cancelled the
  RS256 signing, the rollback clock and the operator keys.
  ([BLK-03](#audit-references))
  Revisions up to `8da39ec` remain MIT for whoever obtained them; see `NOTICE`.
- **`voting.min_votes` 3 → 2.** After the positional repair and the near-miss
  merge, a third frame almost never changes the answer — it costs another
  detection stride with a car waiting at a closed gate.
- **Fast-path confidence 0.90 → 0.82**, and the setting moved to
  `voting.fast_path_confidence`. The old top-level `fast_path:` section is
  still read for an in-place upgrade.
- **The fast path now works with any recogniser.** It previously required
  `accept` predicate support, so a third-party engine lost the early exit
  entirely.
- **Turkish plate normalisation** gained the `3`/`E` confusion pair and a
  case-aware fallback for lowercase `b` (a `6`, where uppercase `B` is an `8`).
- **USB camera devices moved to `docker-compose.usb.yml`.** The base stack
  hard-coded `/dev/video0` and `/dev/video1`, so an RTSP-only site could not
  start at all.
- **Container resource limits and a healthcheck** are now set in Compose.

### Fixed

- **Email alerts were silently disabled.** `config.yaml` ships `user` set and
  `password` blank, so the notifier was unusable and said so only in one vague
  warning that did not name the missing field. Dropped alerts are now counted
  and reported.
- **`plate_from_filename` invented ground truth.** `frame_0001.jpg` parsed as
  the plate `FRAME`; filename-derived labels must now satisfy the Turkish
  grammar.
- **`evaluate.py` scored one label twice** when a recursive scan found the same
  basename in two directories.
- **`fetch_models.py` called the stock COCO model a "custom plate model"** — a
  large part of why that state survived as long as it did. It now compares
  SHA-256 and says so, and verifies the baseline download against a pinned
  digest (`.pt` is a pickle; `torch.load` executes it).
- **The login limiter's overflow eviction could drop a live lockout**, turning
  a memory bound into an authentication bypass triggerable by flooding.
- **`last_granted_camera` ordered by timestamp alone.** Timestamps have
  one-second resolution, so a vehicle that drove in and straight back out left
  two rows SQLite could return in either order — a coin toss whose losing side
  refuses a resident at the barrier.
- **`require_hardware` could not detect a missing serial port**, because
  `SerialRelay` opens lazily and its constructor succeeded either way. The port
  is now probed when the guard is on.
- **`test_license.py` HS256 confusion test** failed against recent PyJWT, which
  refuses a PEM as an HMAC secret — the failure was in the test's own setup, not
  in the verifier. The forged token is now assembled by hand.
- **98 MB of EasyOCR weights and a stray `plates.db` were purged from git
  history**, and `.gitignore` now covers `keys/`, `*.pem`, `models/` and every
  weight extension. ([BLK-08](#audit-references))

### Known limitations

Stated because a release note that implies more than it delivers is worse than
none:

- **There is still no trained plate detector.** `models/plate_yolov8n.pt` is the
  stock COCO baseline, so the pipeline runs on the contour fallback. Every tool
  needed to fix this ships in this release (`make dataset-scaffold`,
  `make train`, `make evaluate`); the missing input is labelled data.
  ([BLK-01](#audit-references))
- **`min_votes: 2` and fast-path `0.82` are unvalidated.** Both lower latency
  and widen the false-positive surface. Run `scripts/evaluate.py` against your
  own footage before trusting them.
- **A container that crashes before the interpreter reaches our code cannot be
  rolled back from inside it.** That needs a supervisor on the host.
- **Hardware binding has no slack on a two-component host** — the normal
  container case. Replacing a NIC there requires a rebind.

### Upgrading to 1.0.0

**1. Reissue every licence.** The old signing key is compromised.

```bash
python scripts/generate_keys.py --force     # vendor machine only
# customer runs:  python scripts/hwid.py --json
python scripts/generate_license.py --client "Site A" --days 365 --bind "$(cat hwid.json)"
```

Ship the new `public_key.pem` to each site (`data/public_key.pem`).

**2. Update your Compose invocation.** The base stack no longer includes USB
devices, the engine socket or host networking:

```bash
docker compose -f docker/docker-compose.yml \
               -f docker/docker-compose.usb.yml \
               -f docker/docker-compose.proxy.yml up -d
```

Add `-f docker/docker-compose.ota.yml` only if you accept that mounting the
engine socket grants host-root access.

**3. Check the new configuration keys.** `config.yaml` gained
`anti_passback`, `snapshots.max_total_mb` / `min_free_mb`,
`cameras.*.stall_timeout_s` / `rtsp_transport` / `open_timeout_s`,
`relay.driver` / `require_hardware`, and `voting.fast_path_*`. Every one has a
safe default, so an unchanged file still starts.

**4. Set `LPR_ENV=production`.** It refuses the default API secret, forces
`relay.require_hardware`, hides the OpenAPI schema and refuses a wildcard CORS
origin.

**5. The first start will back up and migrate the database.** If the backup
fails the upgrade is refused rather than attempted — free some disk and retry.

---

## [0.1.0] — 2026-08-31 and earlier

Pre-commercial development. Not versioned; see `git log`. The pipeline reached
its current architecture over this period: per-camera capture threads, motion
gating, ByteTrack, ensemble OCR with Turkish plate normalisation, multi-frame
voting, the sliding-gate relay, event snapshots, email alerts, the FastAPI
service and dashboard, the Tkinter client, deployment and per-operator
licensing, and the OTA updater.

---

## Audit references

Identifiers used above come from the commercial readiness audit that produced
this release. Blockers (`BLK-`) were rated as stopping a customer deployment
outright; high-priority items (`HP-`) as producing a support call, a security
incident or a wrongly opened barrier at the first real site.

| ID | Finding |
|---|---|
| BLK-01 | No trained plate detector — running on the contour fallback |
| BLK-02 | Licence signing key committed to a public repository |
| BLK-03 | MIT licence cancelled the commercial licensing model |
| BLK-04 | No hardware binding — one key worked on unlimited sites |
| BLK-05 | Root container + Docker socket + host networking |
| BLK-06 | No RTSP hardening or stall watchdog |
| BLK-07 | No OTA rollback, no pre-migration backup |
| BLK-08 | 98 MB of model weights in git without LFS |
| HP-01 | No login rate limiting or lockout |
| HP-02 | Wildcard CORS with credentials; unprotected OpenAPI |
| HP-03 | No TLS |
| HP-04 | No read-only role |
| HP-05 | No disk-pressure protection |
| HP-06 | One relay driver, no feedback, silent mock fallback |
| HP-07 | No anti-passback |
| HP-08 | No accuracy measurement |
| HP-09 | Camera credentials logged in clear text |
| HP-10 | No database backup |

[Unreleased]: https://github.com/hasanefeavc/License-Plate-Recognition/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/hasanefeavc/License-Plate-Recognition/releases/tag/v1.0.0
