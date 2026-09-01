# Security Policy

This software controls a physical barrier and stores photographs of vehicles.
A fault here is not a crashed web page — it is a gate that opens for the wrong
car, or a camera password in somebody's inbox. Reports are taken seriously and
answered.

## Reporting a vulnerability

**Do not open a public issue.**

Email **hasanefeavc@gmail.com** with `SECURITY` in the subject. Include:

- what you found, and the version or commit you found it on;
- how to reproduce it — a minimal case is worth more than a long description;
- what an attacker gets from it.

You will get an acknowledgement within **72 hours** and an assessment within
**7 days**. If a fix is warranted, you will be told when it ships and credited
in the release notes unless you would rather not be.

Please give us 90 days before publishing, or less if a fix is already out.
That window is a request, not a demand — you found it, and it is yours to
disclose.

## Supported versions

Only the latest release on `main` receives security fixes. This is a
single-branch project; there is no long-term support line, and running an old
commit means running its known issues.

## Scope

**In scope**

- Authentication and session handling (`src/lpr/api/security.py`, `ratelimit.py`)
- The licensing system (`src/lpr/license.py`, `user_license.py`, `machine.py`)
- The OTA updater (`src/lpr/updater.py`)
- Anything that can move the barrier without authorisation
- Credential or personal-data disclosure (camera passwords, snapshots, plate lists)
- The shipped container and proxy configuration under `docker/`

**Out of scope**

- Findings that require an attacker who already has root on the gate host.
  Mounting the engine socket for OTA grants host root *by design* — see the
  warning in `docker/docker-compose.ota.yml`. That is a documented trade, not
  a vulnerability.
- Missing TLS on a deployment that chose not to use `docker-compose.proxy.yml`.
  We ship the proxy; running the API on plain HTTP is a decision the operator
  makes and one the documentation argues against.
- Rate-limit bypass by an attacker who controls `X-Forwarded-For` on a
  deployment with no reverse proxy in front. Documented in `ratelimit.py`: the
  per-username lockout is the defence that does not care where a request came
  from.
- Denial of service by flooding a public endpoint. Real, and the answer is a
  proxy or a firewall, not application code.
- Anything in `legacy/`. It is kept for reference and is not deployed.

## Known trade-offs

These are deliberate, documented at the point of decision, and not bugs. If you
disagree with one, the argument is welcome — as an issue, not a CVE.

| Decision | Why | Where |
|---|---|---|
| Mock relay falls back silently unless `relay.require_hardware` | A developer's checkout has no relay. Production is expected to set the flag, and `LPR_ENV=production` sets it regardless. | `hardware/relay.py` |
| A licence whose fingerprint cannot be read is **accepted** | An unreadable sysfs after a kernel upgrade is not evidence of a copy, and closing a customer's gate over one is the worse failure. | `license.py` |
| Anti-passback never blocks an exit | A vehicle that cannot leave is trapped behind a barrier. | `pipeline/orchestrator.py` |
| The camera watchdog releases a capture handle from another thread | OpenCV does not document that as safe. The alternative is a capture thread parked forever on a dead stream — a gate that is silently blind. | `pipeline/camera.py` |
| Rate-limit state is in memory and clears on restart | Persisting it would put a write on the unauthenticated path, which is a denial-of-service primitive of its own. | `api/ratelimit.py` |
| A failed pre-migration backup **stops** the upgrade | SQLite has no downgrade path. A gate that will not start is a service call; a database migrated with no copy is a lost site. | `db/connection.py` |

## Hardening checklist for a deployment

The shipped defaults are safe for a developer's checkout. A site needs more.
None of this is optional on a real installation:

```bash
# 1. Secrets. Both must be set, and must differ from each other.
LPR_API__SECRET_KEY=$(openssl rand -hex 32)
LPR_LICENSE_SECRET=$(openssl rand -hex 32)

# 2. Production mode. Refuses the default secret, forces relay.require_hardware,
#    turns off the OpenAPI schema, and refuses a wildcard CORS origin.
LPR_ENV=production
```

- [ ] `api.secret_key` is not `change-me`
- [ ] `api.cors_origins` names the real dashboard origin, or is empty
- [ ] TLS is terminated — `docker-compose.proxy.yml`, or your own proxy
- [ ] `relay.require_hardware: true`
- [ ] `system_update.enabled` is **false** unless you accept host-root access
- [ ] The `docker-compose.ota.yml` overlay is *not* in use unless the above is accepted
- [ ] `smtp.password` comes from `LPR_SMTP__PASSWORD`, not `config.yaml`
- [ ] `keys/private_key.pem` exists only on the vendor machine
- [ ] Database backups are running (`data/backups/`) and have been restored once as a test
- [ ] Snapshot retention limits fit the disk (`snapshots.max_total_mb`, `min_free_mb`)

Verify the first four with:

```bash
pytest tests/test_secrets.py -q     # no credential in the tree or its history
```

## What is not defended

Stated plainly, because a security document that implies more than it delivers
is worse than none:

- **Physical access to the gate host.** Anyone with the box has the database,
  the snapshots and the relay.
- **A compromised camera.** A camera that can be made to send a chosen image
  can be made to send a picture of a plate. The whitelist bounds what that
  achieves; it does not prevent it.
- **The plate itself.** A printed copy of a registered plate opens the gate.
  This is true of every ANPR system, and it is why anti-passback and the
  snapshot trail exist.
- **A build that fails before the interpreter reaches our code.** The OTA
  rollback needs to run to roll back. That case needs a supervisor outside
  the container; the state file is written so one can read it.

## Cryptography

- **Deployment licences** — RS256. The private key never leaves the vendor
  machine; sites get `public_key.pem`, which can only verify. The verifier
  pins `algorithms=["RS256"]`, which is what stops a token asking to be checked
  with the public key as an HMAC secret.
- **Operator keys** — HMAC-SHA256 against `LPR_LICENSE_SECRET`. Signed and
  verified by the same server for its own accounts, so a shared secret is the
  right shape and no private key leaves the box.
- **Sessions** — HS256 JWT against `api.secret_key`. Role-scoped lifetimes;
  revocation is checked against the database on every request, so "delete
  user" and "change role" take effect rather than being advisory.
- **Passwords** — argon2id via `argon2-cffi`.

`LPR_LICENSE_SECRET` and `LPR_API__SECRET_KEY` must be different values.
Reusing one means a single leak forges both sessions and operator licences,
and rotating either forces you to rotate both.
