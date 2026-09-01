# Deployment Guide

Installing this on a real gate, start to finish. Written for the person
standing at the site with a laptop, not for the person who wrote the code — if
a step needs a decision, the decision is here rather than in a docstring.

`README.md` explains *how the system works*. This explains *how to install it*.

**Estimated time:** half a day for a first installation, an hour once you have
done one.

---

## Before you go

Bring these. Discovering one is missing on site costs a second visit.

| Item | Notes |
|---|---|
| Licence key | Requires the site's hardware id — see [step 6](#6-licence) |
| `public_key.pem` | From the vendor. Not in the repository. |
| Camera credentials | RTSP URL, username, password, per camera |
| Relay wiring details | Serial port / GPIO pin / Modbus coil / relay URL |
| Barrier controller manual | For the pulse width its input expects |
| A laptop with SSH | You will not want to type on the gate box |

### Host requirements

| | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores x86-64 | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 128 GB SSD | 512 GB SSD |
| GPU | none (CPU ~1.5 s/frame) | NVIDIA, 4 GB+ (~0.2 s/frame) |
| OS | Debian 12 / Ubuntu 22.04 | same |
| Docker | Engine 24+ or Podman 4+ | Engine 25+ |

Disk is the one people under-buy. Snapshots are the bulk of it: roughly
200 KB per vehicle, so a site handling 2 000 vehicles a day writes ~4 GB a week.
The defaults keep 10 days or 20 GB, whichever comes first.

---

## 1. Get the code

```bash
sudo mkdir -p /opt/lpr && sudo chown "$USER" /opt/lpr
git clone https://github.com/hasanefeavc/License-Plate-Recognition /opt/lpr
cd /opt/lpr
```

## 2. Secrets

Two, and they **must differ**. Reusing one means a single leak forges both
sessions and operator licences.

```bash
cp .env.example .env
cat >> .env <<EOF
LPR_ENV=production
LPR_API__SECRET_KEY=$(openssl rand -hex 32)
LPR_LICENSE_SECRET=$(openssl rand -hex 32)
EOF
chmod 600 .env
```

`LPR_ENV=production` is not cosmetic. It refuses the default API secret,
forces `relay.require_hardware`, hides the OpenAPI schema, and refuses a
wildcard CORS origin.

For email alerts, add the SMTP password here — never in `config.yaml`, which is
committed:

```bash
echo 'LPR_SMTP__PASSWORD=your-16-char-app-password' >> .env
```

> Gmail needs an **app password** (16 characters), not the account password,
> and only once 2-step verification is on.

## 3. Cameras

Get each stream working with `ffprobe` **before** touching `config.yaml`. A
camera that will not play here will not play in the container either, and
debugging it through two layers wastes an hour.

```bash
ffprobe -rtsp_transport tcp "rtsp://admin:PASSWORD@192.168.1.64:554/Streaming/Channels/101"
```

Then edit `config.yaml`:

```yaml
cameras:
  entry:
    source: "rtsp://admin:PASSWORD@192.168.1.64:554/Streaming/Channels/101"
    width: 1280
    height: 720
    fps_limit: 15
  exit:
    source: "rtsp://admin:PASSWORD@192.168.1.65:554/Streaming/Channels/101"
```

**Leave `exit.source` blank if there is only one camera.** A blank source means
"not fitted", which is a supported configuration — the orchestrator skips the
role. It also means anti-passback and the occupancy count cannot work; see
[step 9](#9-optional-anti-passback).

The RTSP defaults (`rtsp_transport: tcp`, `open_timeout_s: 5`,
`stall_timeout_s: 15`) suit almost every site. Change them only if you have
measured a reason.

### Camera placement

The single biggest factor in accuracy, and the one you cannot fix in software:

- **Height** 1.0–1.5 m, roughly plate height. A camera on the roof reads a
  foreshortened plate.
- **Angle** within 30° of head-on, horizontally and vertically.
- **Distance** so the plate is **at least 100 px wide** in frame. Measure it,
  do not estimate it.
- **Lighting** — IR illumination for night. A plate is retroreflective, which
  helps, but only if something is illuminating it.
- **Avoid** pointing into the sun at any hour of the year, and avoid framing
  the barrier's own signage; the normaliser refuses to read signage as a plate,
  but a detector that keeps cropping it wastes OCR passes.

## 4. Model weights

```bash
python scripts/fetch_models.py --easyocr
```

> **Read the output.** If it says `plate_yolov8n.pt is byte-for-byte the stock
> COCO yolov8n.pt`, this site has **no plate detector** and will run on the
> contour fallback — which needs a clean, well-lit, near-frontal plate and
> misses angled, blurred and night plates entirely. Do not commission a gate in
> that state. See `README_TRAINING.md`.

## 5. Relay

Pick the driver that matches the wiring, and set `require_hardware: true`.
Without it a relay that cannot be opened falls back to a mock, which logs every
vehicle as granted while no barrier moves — success everywhere except at the
gate.

```yaml
relay:
  enabled: true
  driver: serial        # serial | gpio | modbus | http
  require_hardware: true
  pulse_ms: 1000
```

| Driver | Key settings |
|---|---|
| `serial` | `port` (`auto` probes `/dev/ttyUSB0`, `ttyACM0`, `serial0`), `baud`, `open_byte`, `close_byte` |
| `gpio` | `gpio_pin` (BCM), `gpio_active_low` — **check this against the board** |
| `modbus` | `modbus_mode` (`tcp`/`rtu`), `modbus_host`, `modbus_port`, `modbus_unit`, `modbus_coil` |
| `http` | `http_open_url`, `http_close_url` (blank if the board self-releases), `http_user`, `http_password` |

`gpio_active_low` getting it backwards does not fail — it holds the contact
closed for the life of the process, which holds the barrier **open**. Most
cheap opto-isolated boards are active-low, which is the default.

### Sliding gates

A sliding-gate motor usually uses step-by-step pulse logic: pulse 1 opens,
pulse 2 *stops mid-travel*, pulse 3 closes. Time the motor from closed to fully
open and set `voting.cooldown_s` at or just above that (default 20 s). Too
short re-triggers mid-travel and the driver watches the gate stop halfway.

## 6. Licence

On the **gate box**:

```bash
python scripts/hwid.py --json > hwid.json
```

Send `hwid.json` to the vendor. It contains no MAC address and no serial
number — every component is already hashed — so it is safe to e-mail.

The vendor returns a key. Install `public_key.pem` and the key:

```bash
cp public_key.pem data/public_key.pem
# then paste the key into the dashboard's licence dialog, or:
echo "eyJhbGci..." > .license && chmod 600 .license
```

> If `hwid.py` warns that **only two components are readable** — the normal
> case in a container — the licence has no slack: replacing the network card
> will require a rebind. Tell the customer now rather than during a repair.

## 7. Start it

```bash
docker compose -f docker/docker-compose.yml \
               -f docker/docker-compose.usb.yml \
               -f docker/docker-compose.proxy.yml up -d
```

Drop `-f docker/docker-compose.usb.yml` on an RTSP-only site. Add
`-f docker/docker-compose.cdi.yml` on a Podman host with a GPU.

**Do not add `-f docker/docker-compose.ota.yml`** unless the customer accepts
that mounting the engine socket grants host-root access. Updating over SSH does
the same job with no standing grant.

For TLS, set the hostname first:

```bash
echo 'LPR_DOMAIN=gate.example.com' >> .env
echo 'LPR_ACME_EMAIL=ops@example.com' >> .env
```

A name that does not resolve publicly (`gate.local`) gets a certificate from
Caddy's own CA; install its root on the operator machines once:

```bash
docker compose ... exec proxy \
  cat /data/caddy/pki/authorities/local/root.crt > root.crt
```

## 8. Commissioning checks

Do all of these. Each has caught a real installation fault.

```bash
# 1. Service is up
curl -fsS http://127.0.0.1:8000/health | jq

# 2. GPU actually reached the container -- a container that started proves nothing
docker compose -f docker/docker-compose.yml exec lpr-api \
  python -c "import torch; print(torch.cuda.is_available())"

# 3. The detector is real, not the contour fallback
docker compose -f docker/docker-compose.yml logs lpr-api | grep -i "contour"
#    Any hit here means no plate model. Stop and fix it.

# 4. Both cameras are connected
curl -fsS http://127.0.0.1:8000/api/cameras -H "Authorization: Bearer $TOKEN" | jq
```

Then, physically:

- [ ] Drive a **registered** vehicle to the entry camera — barrier opens
- [ ] Drive an **unregistered** vehicle — barrier stays shut, alert e-mail arrives
- [ ] Check the snapshot for both is in the dashboard
- [ ] Unplug the entry camera for 30 s, plug it back in — it reconnects on its
      own (watch the log for `stalled` then `connected`)
- [ ] Reboot the host — the stack comes back without intervention
- [ ] Confirm the barrier's own safety loop still stops it on an obstruction.
      **The software has no part in this**, and it is the one check that
      matters most.

## 9. Optional: anti-passback

Only with **both cameras fitted**. On a single-camera site no exit is ever
recorded, so every vehicle would look permanently inside — the orchestrator
detects that and disables the rule with a warning rather than refusing
everybody's second visit.

```yaml
anti_passback:
  enabled: true
  window_s: 43200          # 12 h; a long-stay car park wants longer
  emergency_bypass: false
  exempt_plates: ["34SRV01"]   # service vehicles
```

It never blocks an exit. `emergency_bypass: true` suspends it without losing
the configuration — for an event, an evacuation, or an operator working through
vehicles the system has got wrong.

## 10. Backups

Nightly backups run on their own into `data/backups/`. Verify one restores
**before you leave the site** — an untested backup is a hope, not a backup.

```bash
ls -la data/backups/
sqlite3 data/backups/plates-*.db.bak "SELECT COUNT(*) FROM plates;"
```

Copy them off the box. A backup on the disk that fails is not a backup.

---

## Operating

### Daily

Nothing. The system runs unattended. Watch for alert e-mails.

### Weekly

```bash
curl -fsS http://127.0.0.1:8000/api/stats -H "Authorization: Bearer $TOKEN" | jq
df -h /opt/lpr
```

`fast_path_hits` near zero means the confidence threshold is above what the
cameras produce — worth investigating rather than ignoring.

### Updating

Over SSH, which needs no standing grant:

```bash
cd /opt/lpr && git pull && docker compose -f docker/docker-compose.yml up -d --build
```

The first start after a schema change backs the database up and migrates it,
rolling back automatically if the migration fails. If the backup itself fails
the upgrade is **refused** — free some disk and retry.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Barrier never opens, log says `granted` | Mock relay | Set `relay.require_hardware: true`, check wiring |
| Barrier opens once then stops halfway | Sliding gate re-triggered mid-travel | Raise `voting.cooldown_s` above the motor's travel time |
| Plates read but never confirmed | `min_votes` above what the camera delivers | Check `frame_stride`, plate width in frame |
| Nothing detected at all | No plate model — contour fallback | `python scripts/fetch_models.py`, read the warning |
| Camera connects then goes quiet | Stalled RTSP | The watchdog handles it; if it recurs, check the switch and `rtsp_transport` |
| `machine_mismatch` at startup | Hardware changed, or the licence was copied | `python scripts/hwid.py --json`, request a rebind |
| No alert e-mails | SMTP incomplete | Check the startup warning — it names the missing field |
| Disk filling | Retention above what fits | Lower `snapshots.max_total_mb` |
| Gate opens for the wrong car | Misread that matched a registered plate | Raise `voting.min_votes`, raise `voting.fast_path_confidence`, and measure with `scripts/evaluate.py` |

### Getting logs to support

```bash
docker compose -f docker/docker-compose.yml logs --since 24h > lpr-logs.txt
```

Camera passwords are masked in these. Check before sending anyway.

---

## Data protection (KVKK / GDPR)

The system stores photographs of vehicles, which is personal data in Turkey
and the EU. The site operator is the data controller — not the vendor, and not
whoever installed it. At minimum:

- Post a notice at the entrance stating that ANPR is in use and who operates it.
- Keep `snapshots.retention_days` and `database.log_retention_days` no longer
  than the stated purpose needs. The defaults are 10 days.
- Restrict dashboard access. This is what the `viewer` role is for: an
  attendant who needs to look up a pass does not need the gate-open button.
- In Turkey, register with VERBİS where the operator's size or sector requires
  it.

This is a checklist, not legal advice. The operator's own counsel decides what
their obligations are.
