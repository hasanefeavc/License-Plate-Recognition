/*
 * Browser dashboard for lpr-api.
 *
 * Talks to exactly the same endpoints as the Tkinter client, so the two are
 * interchangeable and neither is privileged:
 *
 *   POST /api/auth/login            -> bearer token
 *   GET  /api/auth/me               -> validate a stored token
 *   GET  /api/stream/{role}?token=  -> MJPEG, straight into an <img>
 *   WS   /api/ws/events?token=      -> events, telemetry, camera + licence state
 *   POST /api/relay/trigger         -> open the barrier   (admin)
 *   POST /api/pipeline/pause|resume -> hold recognition   (admin)
 *   GET  /api/stats                 -> counters
 *   GET  /api/plates                -> registered plates
 *   POST /api/plates                -> register one       (admin)
 *   DEL  /api/plates/{plate}        -> unregister one     (admin)
 *   GET  /api/logs, /api/logs/dates -> history + CSV export
 *   GET  /api/parking               -> vehicles inside / capacity
 *   PUT  /api/parking               -> set capacity       (admin)
 *
 * The gate opens itself: `PipelineOrchestrator.decide()` pulses the relay the
 * moment a recognised plate matches the whitelist, on the pipeline thread.
 * This page must never trigger it on a `granted` event -- every open browser
 * would fire its own extra pulse for the same car. "Bariyeri Aç" is the
 * manual override for a vehicle the cameras could not read, nothing more.
 *
 * A browser cannot put an Authorization header on an <img> or a WebSocket
 * handshake, which is why those two take the token as a query parameter --
 * the API supports that specifically for this client. Everything else uses
 * the header.
 *
 * All URLs are relative to wherever the page was served from, so the same
 * files work on localhost and over the LAN with no rebuild.
 */
"use strict";

(function () {
  // -----------------------------------------------------------------------
  // Constants
  // -----------------------------------------------------------------------

  const TOKEN_KEY = "lpr.token";
  /** Per-device display preference, so it belongs on the device. A phone on
   *  mobile data and the control-room PC talk to the same server and want
   *  different stream weights. */
  const QUALITY_KEY = "lpr.streamQuality";
  const DEFAULT_QUALITY = 75;
  const ALLOWED_QUALITY = [90, 75, 45];
  const PARKING_INTERVAL_MS = 15000;
  const MAX_FEED_CARDS = 80;
  const STATS_INTERVAL_MS = 5000;
  const WS_RETRY_MIN_MS = 1000;
  const WS_RETRY_MAX_MS = 15000;
  const STREAM_RETRY_MS = 3000;
  const TOAST_MS = 4000;
  /** The API caps /api/logs at 1000 rows per call; the export asks for all of
   *  them so the CSV is not silently a truncated view of the day. */
  const HISTORY_LIMIT = 1000;
  const CSV_FILENAME = "otopark_gecmis.csv";
  /** Cooldown events are the same plate re-confirming while a car idles under
   *  the camera. The backend keeps them out of the log table; we keep them out
   *  of the feed for the same reason. */
  const HIDDEN_ACTIONS = new Set(["cooldown"]);

  const ACTION_COLORS = {
    granted: "ok",
    denied: "bad",
    detected: "accent",
    cooldown: "warn",
    error: "bad",
  };
  const ACTION_LABELS = {
    granted: "İZİN VERİLDİ",
    denied: "REDDEDİLDİ",
    detected: "TESPİT",
    cooldown: "BEKLEMEDE",
    error: "HATA",
  };
  const CAMERA_LABELS = { entry: "GİRİŞ", exit: "ÇIKIŞ" };

  // Tailwind cannot see class names we build at runtime, so the stripe and
  // text colours are written as literals it can find in this file.
  const STRIPE_CLASSES = {
    ok: "border-ok",
    bad: "border-bad",
    accent: "border-accent",
    warn: "border-warn",
  };
  const TEXT_CLASSES = {
    ok: "text-ok",
    bad: "text-bad",
    accent: "text-accent",
    warn: "text-warn",
    muted: "text-muted",
  };

  // -----------------------------------------------------------------------
  // State
  // -----------------------------------------------------------------------

  const state = {
    token: null,
    username: "",
    role: "",
    socket: null,
    wsRetryMs: WS_RETRY_MIN_MS,
    wsTimer: null,
    statsTimer: null,
    parkingTimer: null,
    uptimeTimer: null,
    toastTimer: null,
    uptimeSeconds: 0,
    /** False until a stats read succeeds. The clock must not invent an
     *  uptime while the API is unreachable or the pipeline is down. */
    uptimeKnown: false,
    paused: false,
    feedCount: 0,
    licenceValid: true,
    closing: false,
    /** Short commit of the running server, used to detect that an OTA update
     *  actually replaced the process rather than merely restarting it. */
    version: "",
    /** Last rows fetched into the history modal. The CSV is built from
     *  exactly what the operator is looking at, not from a second query that
     *  could return something else. */
    historyRows: [],
    openModal: null,
    lastFocus: null,
    /** Mirror of GET /api/parking. `inside` is nudged locally on each granted
     *  event so the counter moves with the barrier, and re-synced from the
     *  server on a timer so drift cannot accumulate. */
    parking: { inside: 0, capacity: 0, full: false },
    quality: DEFAULT_QUALITY,
  };

  const $ = (id) => document.getElementById(id);
  const el = {};
  [
    "login-screen", "login-form", "login-username", "login-password",
    "login-error", "login-submit", "login-register", "dashboard", "banner",
    "cdn-warning",
    "uptime", "user-label", "conn-dot", "conn-label", "feed", "feed-empty",
    "feed-count", "activity", "stat-read", "stat-grant", "stat-deny",
    "license-label", "btn-gate", "btn-pause", "btn-history", "btn-logout",
    "toast", "cam-entry", "cam-exit",
    // Plate-management modal
    "modal-plates", "btn-plates", "plate-form", "plate-input", "note-input",
    "plate-add", "plate-rows", "plates-empty", "plates-count", "plates-status",
    // History modal
    "modal-history", "history-day", "history-camera", "history-refresh",
    "history-csv", "history-rows", "history-empty", "history-count",
    "history-status",
    // Settings modal + capacity
    "modal-settings", "btn-settings", "settings-form", "settings-save",
    "settings-status", "capacity-input", "capacity-hint", "quality-select",
    "occupancy", "capacity", "full-banner",
    // System update (inside the settings modal)
    "update-section", "update-version", "update-branch", "update-dirty-row",
    "update-run", "update-run-label", "update-spinner", "update-status",
    "update-log", "update-history", "update-history-wrap",
  ].forEach((id) => { el[id] = $(id); });

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  /** `34ABC123` -> `34 ABC 123`; anything unexpected is shown verbatim. */
  function formatPlate(plate) {
    const text = String(plate || "").toUpperCase().replace(/\s+/g, "");
    const match = /^(\d{2})([A-ZÇĞİÖŞÜ]{1,3})(\d{2,5})$/.exec(text);
    return match ? `${match[1]} ${match[2]} ${match[3]}` : text || "-";
  }

  function formatConfidence(value) {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? `${Math.round(n * 100)}%` : "-";
  }

  /** Wall-clock part of the event's UTC timestamp, matching the log table. */
  function formatClock(ts) {
    const text = String(ts || "").replace("T", " ").replace("+00:00", "").trim();
    if (!text) return "--:--:--";
    return text.split(" ").pop().slice(0, 8);
  }

  function formatUptime(seconds) {
    const total = Math.max(0, Math.floor(seconds));
    const pad = (n) => String(n).padStart(2, "0");
    return `${pad(Math.floor(total / 3600))}:${pad(Math.floor((total % 3600) / 60))}:${pad(total % 60)}`;
  }

  function setText(node, text) { if (node) node.textContent = text; }

  function toast(message, tone = "muted") {
    if (!el.toast) return;
    el.toast.textContent = message;
    el.toast.className = `text-sm font-bold ${TEXT_CLASSES[tone] || TEXT_CLASSES.muted}`;
    clearTimeout(state.toastTimer);
    if (message) state.toastTimer = setTimeout(() => toast(""), TOAST_MS);
  }

  function setBanner(message) {
    if (!el.banner) return;
    el.banner.textContent = message || "";
    el.banner.hidden = !message;
  }

  function setConnected(online) {
    if (el["conn-dot"]) el["conn-dot"].className =
      `h-2.5 w-2.5 rounded-full transition-colors ${online ? "bg-ok" : "bg-bad"}`;
    if (el["conn-label"]) {
      el["conn-label"].textContent = online ? "Bağlı" : "Bağlı Değil";
      el["conn-label"].className = `text-sm font-bold ${online ? TEXT_CLASSES.ok : TEXT_CLASSES.bad}`;
    }
  }

  // -----------------------------------------------------------------------
  // Transport
  // -----------------------------------------------------------------------

  /** fetch() with the bearer header attached and errors unwrapped.
   *  The API's error envelope is `{error: {status, title, detail}}`. */
  async function api(path, options = {}) {
    const headers = Object.assign({}, options.headers);
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    if (options.body !== undefined) headers["Content-Type"] = "application/json";

    const response = await fetch(path, Object.assign({}, options, { headers }));
    let payload = null;
    try { payload = await response.json(); } catch (_) { /* 204, or not JSON */ }

    if (!response.ok) {
      const detail = payload && payload.error ? payload.error.detail : null;
      const error = new Error(
        typeof detail === "string" && detail ? detail : `HTTP ${response.status}`
      );
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  function streamUrl(role) {
    // Cache-busted so a reconnect is never served the dead response.
    return `/api/stream/${role}?token=${encodeURIComponent(state.token)}` +
           `&quality=${state.quality}&_=${Date.now()}`;
  }

  /** Re-point both <img> tags, e.g. after the quality setting changed. */
  function restartStreams() {
    ["entry", "exit"].forEach((role) => {
      const img = el[`cam-${role}`];
      if (img && state.token && !state.closing) img.src = streamUrl(role);
    });
  }

  function socketUrl() {
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    return `${scheme}//${location.host}/api/ws/events?token=${encodeURIComponent(state.token)}`;
  }

  // -----------------------------------------------------------------------
  // Camera streams
  // -----------------------------------------------------------------------

  /** Point one <img> at its MJPEG endpoint and keep it pointed there.
   *  The server closes an idle stream on purpose, so `error` is a normal
   *  event, not a failure: back off briefly and ask again. */
  function attachStream(role) {
    const img = el[`cam-${role}`];
    const placeholder = $(`ph-${role}`);
    if (!img) return;

    let retry = null;
    const reconnect = () => {
      clearTimeout(retry);
      retry = setTimeout(() => {
        if (state.token && !state.closing) img.src = streamUrl(role);
      }, STREAM_RETRY_MS);
    };

    img.addEventListener("load", () => {
      img.hidden = false;
      if (placeholder) placeholder.hidden = true;
    });
    img.addEventListener("error", () => {
      img.hidden = true;
      if (placeholder) placeholder.hidden = false;
      reconnect();
    });
    img.src = streamUrl(role);
  }

  function detachStreams() {
    ["entry", "exit"].forEach((role) => {
      const img = el[`cam-${role}`];
      const placeholder = $(`ph-${role}`);
      // Clearing src stops the browser holding the connection open.
      if (img) { img.removeAttribute("src"); img.hidden = true; }
      if (placeholder) placeholder.hidden = false;
    });
  }

  function setCameraStatus(cameras) {
    const seen = new Set();
    (cameras || []).forEach((camera) => {
      const role = String(camera.role || "");
      if (!["entry", "exit"].includes(role)) return;
      seen.add(role);
      const connected = Boolean(camera.connected);
      const dot = $(`dot-${role}`);
      const badge = $(`badge-${role}`);
      const fps = $(`fps-${role}`);
      if (dot) dot.className =
        `h-2.5 w-2.5 rounded-full transition-colors ${connected ? "bg-ok" : "bg-bad"}`;
      if (badge) {
        badge.textContent = connected ? "Bağlı" : "Bağlı Değil";
        badge.className = `text-xs font-bold ${connected ? TEXT_CLASSES.ok : TEXT_CLASSES.bad}`;
      }
      if (fps) fps.textContent = connected && camera.fps ? `${Number(camera.fps).toFixed(1)} FPS` : "";
    });
  }

  // -----------------------------------------------------------------------
  // Live plate feed
  // -----------------------------------------------------------------------

  /** One plate card. Status is carried by the left and right borders, the
   *  same language the desktop client uses, so the text stays plain and a
   *  wall of cards reads as a list rather than five competing colours. */
  function buildCard(event) {
    const action = String(event.action || "");
    const tone = ACTION_COLORS[action] || "accent";

    const card = document.createElement("article");
    card.className =
      `feed-in rounded border-l-4 border-r-4 bg-row px-2.5 py-2 ${STRIPE_CLASSES[tone] || STRIPE_CLASSES.accent}`;

    const top = document.createElement("div");
    top.className = "flex items-baseline justify-between gap-2";
    const plate = document.createElement("span");
    plate.className = "font-mono text-lg font-bold tracking-wide";
    plate.textContent = formatPlate(event.plate);
    const confidence = document.createElement("span");
    confidence.className = "text-base font-bold tabular-nums";
    confidence.textContent = formatConfidence(event.confidence);
    top.append(plate, confidence);

    const bottom = document.createElement("div");
    bottom.className = "mt-1 flex items-center justify-between gap-2 text-[10px] font-bold tracking-wider text-muted";
    const left = document.createElement("span");
    const camera = String(event.camera || "");
    left.textContent = `${CAMERA_LABELS[camera] || camera.toUpperCase()}  ·  ${ACTION_LABELS[action] || action.toUpperCase()}`;
    const clock = document.createElement("span");
    clock.className = "font-mono";
    clock.textContent = formatClock(event.ts);
    bottom.append(left, clock);

    card.append(top, bottom);
    return card;
  }

  function addEvent(event) {
    if (!el.feed || HIDDEN_ACTIONS.has(String(event.action || ""))) return;
    if (el["feed-empty"]) el["feed-empty"].hidden = true;

    // Only follow the newest read when the operator has not scrolled away to
    // study an older one.
    const atTop = el.feed.scrollTop <= 8;
    el.feed.prepend(buildCard(event));
    state.feedCount += 1;

    while (el.feed.querySelectorAll("article").length > MAX_FEED_CARDS) {
      el.feed.querySelector("article:last-of-type").remove();
    }
    setText(el["feed-count"], String(el.feed.querySelectorAll("article").length));
    if (atTop) el.feed.scrollTop = 0;
  }

  function setEvents(events) {
    if (!el.feed) return;
    el.feed.querySelectorAll("article").forEach((node) => node.remove());
    const rows = (events || []).filter((e) => !HIDDEN_ACTIONS.has(String(e.action || "")));
    if (el["feed-empty"]) el["feed-empty"].hidden = rows.length > 0;
    rows.slice(0, MAX_FEED_CARDS).forEach((event) => el.feed.append(buildCard(event)));
    setText(el["feed-count"], String(el.feed.querySelectorAll("article").length));
    el.feed.scrollTop = 0;
  }

  // -----------------------------------------------------------------------
  // WebSocket
  // -----------------------------------------------------------------------

  function connectSocket() {
    if (!state.token || state.closing) return;
    let socket;
    try {
      socket = new WebSocket(socketUrl());
    } catch (err) {
      scheduleReconnect();
      return;
    }
    state.socket = socket;

    socket.addEventListener("open", () => {
      state.wsRetryMs = WS_RETRY_MIN_MS;
      setConnected(true);
      if (state.licenceValid) setBanner("");
    });

    socket.addEventListener("message", (message) => {
      let payload;
      try { payload = JSON.parse(message.data); } catch (_) { return; }
      handleMessage(payload);
    });

    socket.addEventListener("close", (event) => {
      setConnected(false);
      state.socket = null;
      if (state.closing) return;
      // 1008 is the server's policy-violation code: the token is no good, so
      // reconnecting with the same one would just loop.
      if (event.code === 1008) {
        logout("Oturumunuzun süresi doldu. Lütfen tekrar giriş yapın.");
        return;
      }
      setBanner("Sunucuya bağlanılamıyor - yeniden deneniyor...");
      scheduleReconnect();
    });

    socket.addEventListener("error", () => { /* close follows; handled there */ });
  }

  function scheduleReconnect() {
    clearTimeout(state.wsTimer);
    state.wsTimer = setTimeout(connectSocket, state.wsRetryMs);
    state.wsRetryMs = Math.min(state.wsRetryMs * 2, WS_RETRY_MAX_MS);
  }

  function handleMessage(message) {
    switch (message.type) {
      case "hello":
        state.username = message.username || state.username;
        state.role = message.role || state.role;
        applyRole();
        if (!message.pipeline) setBanner("İşlem hattı çalışmıyor.");
        break;
      case "event":
        if (message.data) {
          addEvent(message.data);
          // The gate has already opened itself server-side; this only moves
          // the counter to match. Never trigger the relay from here.
          noteMovement(message.data);
        }
        break;
      case "telemetry":
        setText(el.activity, activityText(message.data || {}));
        break;
      case "camera_status":
        setCameraStatus(message.cameras);
        break;
      case "license":
        applyLicense(message.license || {});
        break;
      case "error":
        setBanner(String(message.detail || "Bilinmeyen hata"));
        break;
      case "ping":
      default:
        break;
    }
  }

  function activityText(data) {
    const camera = data.camera || "?";
    const plate = formatPlate(data.plate) || "?";
    if (data.kind === "vote") {
      const status = data.confirmed ? "onaylandı" : `${data.votes || 0}/${data.needed || 0} oy`;
      return `${camera}: ${plate} - ${status}`;
    }
    const confidence = Number(data.confidence);
    const suffix = Number.isFinite(confidence) ? ` (${Math.round(confidence * 100)}%)` : "";
    return `${camera}: ${plate} okundu${suffix}`;
  }

  function applyLicense(license) {
    state.licenceValid = Boolean(license.valid);
    const detail = String(license.detail || "");
    if (state.licenceValid) {
      const parts = ["Lisans"];
      if (license.client) parts.push(String(license.client));
      if (typeof license.days_remaining === "number") {
        parts.push(`${Math.round(license.days_remaining)} gün kaldı`);
      }
      setText(el["license-label"], parts.join(" - "));
      el["license-label"].className = "font-mono text-xs text-muted";
      setBanner("");
    } else {
      setText(el["license-label"], detail || "Lisans geçersiz");
      el["license-label"].className = "font-mono text-xs font-bold text-bad";
      setBanner("Lisans geçersiz - görüntü işleme durduruldu. Yeni bir lisans anahtarı girin.");
    }
    updateControls();
  }

  // -----------------------------------------------------------------------
  // Polled state
  // -----------------------------------------------------------------------

  async function refreshStats() {
    try {
      const stats = await api("/api/stats");
      setText(el["stat-read"], String(stats.plates_read ?? 0));
      setText(el["stat-grant"], String(stats.grants ?? 0));
      setText(el["stat-deny"], String(stats.denials ?? 0));
      state.uptimeSeconds = Number(stats.uptime_s) || 0;
      state.uptimeKnown = true;
      setText(el.uptime, formatUptime(state.uptimeSeconds));
      setCameraStatus(stats.cameras);
    } catch (err) {
      state.uptimeKnown = false;
      setText(el.uptime, "--:--:--");
      if (err.status === 401) logout("Oturumunuzun süresi doldu. Lütfen tekrar giriş yapın.");
    }
  }

  async function refreshLicense() {
    try { applyLicense(await api("/api/license")); } catch (_) { /* banner covers it */ }
  }

  /** Backfill the live feed on login so the panel is not empty until the
   *  next car arrives. The history modal is the place to actually browse. */
  async function loadRecentLogs() {
    try {
      setEvents(await api("/api/logs?limit=80"));
    } catch (err) {
      toast(err.message, "bad");
    }
  }

  // -----------------------------------------------------------------------
  // Controls
  // -----------------------------------------------------------------------

  /** Relay and pause are admin-only server-side; reflect that in the UI so an
   *  operator sees a disabled button instead of collecting 403s. */
  function applyRole() {
    setText(el["user-label"], state.username ? `${state.username} (${state.role})` : "");
    updateControls();
    applyPlatePermissions();
    el["capacity-input"].disabled = state.role !== "admin";
  }

  function updateControls() {
    const isAdmin = state.role === "admin";
    const gateBlocked = !isAdmin || !state.licenceValid;
    if (el["btn-gate"]) {
      el["btn-gate"].disabled = gateBlocked;
      el["btn-gate"].title = !isAdmin
        ? "Bariyeri yalnızca yönetici açabilir"
        : (!state.licenceValid ? "Lisans geçersiz" : "");
    }
    if (el["btn-pause"]) {
      el["btn-pause"].disabled = !isAdmin;
      el["btn-pause"].textContent = state.paused ? "Devam Et" : "Duraklat";
    }
  }

  async function openGate() {
    el["btn-gate"].disabled = true;
    try {
      await api("/api/relay/trigger", { method: "POST" });
      toast("Bariyer açıldı.", "ok");
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      updateControls();
    }
  }

  async function togglePause() {
    const target = !state.paused;
    // Written out rather than interpolated so both paths are greppable and a
    // typo shows up in a search instead of at runtime.
    const path = target ? "/api/pipeline/pause" : "/api/pipeline/resume";
    el["btn-pause"].disabled = true;
    try {
      const result = await api(path, { method: "POST" });
      state.paused = Boolean(result.paused);
      toast(state.paused ? "İşlem hattı duraklatıldı." : "İşlem hattı devam ediyor.", "accent");
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      updateControls();
    }
  }

  // -----------------------------------------------------------------------
  // Occupancy and capacity
  // -----------------------------------------------------------------------

  function renderParking() {
    const { inside, capacity, full } = state.parking;
    setText(el.occupancy, String(inside));
    // A capacity of 0 means "not configured", never "permanently full".
    setText(el.capacity, capacity > 0 ? String(capacity) : "—");
    el.occupancy.className = full ? "text-warn" : "text-accent";
    el["full-banner"].hidden = !full;
  }

  function applyParking(data) {
    state.parking = {
      inside: Math.max(0, Number(data.inside) || 0),
      capacity: Math.max(0, Number(data.capacity) || 0),
      full: Boolean(data.full),
    };
    renderParking();
  }

  async function refreshParking() {
    try {
      applyParking(await api("/api/parking"));
    } catch (err) {
      if (err.status === 401) logout("Oturumunuzun süresi doldu. Lütfen tekrar giriş yapın.");
    }
  }

  /** Nudge the counter the instant the barrier moves, rather than waiting for
   *  the next poll. The server stays the source of truth: refreshParking()
   *  overwrites this on its own timer, so a missed or duplicated event
   *  self-corrects within one interval. */
  function noteMovement(event) {
    if (String(event.action || "") !== "granted") return;
    const camera = String(event.camera || "");
    if (camera !== "entry" && camera !== "exit") return;

    const capacity = state.parking.capacity;
    const inside = Math.max(0, state.parking.inside + (camera === "entry" ? 1 : -1));
    state.parking.inside = inside;
    state.parking.full = capacity > 0 && inside >= capacity;
    renderParking();
  }

  // -----------------------------------------------------------------------
  // Settings
  // -----------------------------------------------------------------------

  function loadQuality() {
    const stored = Number(localStorage.getItem(QUALITY_KEY));
    state.quality = ALLOWED_QUALITY.includes(stored) ? stored : DEFAULT_QUALITY;
    el["quality-select"].value = String(state.quality);
  }

  function openSettings() {
    openModal("modal-settings");
    const isAdmin = state.role === "admin";
    el["capacity-input"].value = state.parking.capacity ? String(state.parking.capacity) : "0";
    el["capacity-input"].disabled = !isAdmin;
    el["quality-select"].value = String(state.quality);
    setText(
      el["capacity-hint"],
      isAdmin ? `Şu an içeride: ${state.parking.inside}` : "Değiştirmek için yönetici yetkisi gerekli"
    );
    modalStatus(el["settings-status"], "");
    refreshUpdatePanel();
  }

  async function saveSettings(event) {
    event.preventDefault();

    // Quality first: it is local, cannot fail, and must stick even if the
    // capacity call is rejected.
    const quality = Number(el["quality-select"].value);
    const changed = ALLOWED_QUALITY.includes(quality) && quality !== state.quality;
    if (ALLOWED_QUALITY.includes(quality)) {
      state.quality = quality;
      localStorage.setItem(QUALITY_KEY, String(quality));
    }
    if (changed) restartStreams();

    if (state.role !== "admin") {
      modalStatus(el["settings-status"], "Görüntü kalitesi kaydedildi.", "ok");
      return;
    }

    const capacity = Number(el["capacity-input"].value);
    if (!Number.isFinite(capacity) || capacity < 0) {
      modalStatus(el["settings-status"], "Kapasite 0 veya daha büyük olmalı.", "bad");
      return;
    }

    el["settings-save"].disabled = true;
    modalStatus(el["settings-status"], "Kaydediliyor...", "muted");
    try {
      applyParking(await api("/api/parking", {
        method: "PUT",
        body: JSON.stringify({ capacity: Math.round(capacity) }),
      }));
      modalStatus(el["settings-status"], "Ayarlar kaydedildi.", "ok");
      setText(el["capacity-hint"], `Şu an içeride: ${state.parking.inside}`);
    } catch (err) {
      modalStatus(el["settings-status"], err.message, "bad");
    } finally {
      el["settings-save"].disabled = false;
    }
  }

  // -----------------------------------------------------------------------
  // Modal shell
  // -----------------------------------------------------------------------

  /** One modal at a time, closable by X, "Kapat", Escape or the backdrop.
   *  Focus is moved in on open and handed back on close so keyboard users are
   *  not dumped at the top of the page. */
  const FOCUSABLE = "a[href], button:not([disabled]), input:not([disabled]), " +
                    "select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex=\"-1\"])";

  function openModal(id) {
    if (state.openModal) closeModal();
    const modal = el[id];
    if (!modal) return;
    state.lastFocus = document.activeElement;
    state.openModal = id;
    modal.hidden = false;
    // The first control the operator actually wants, not whichever focusable
    // element happens to come first in the markup (which is the close "X").
    const target = modal.querySelector("[data-autofocus]") || modal.querySelector(FOCUSABLE);
    if (target) target.focus();
  }

  /** Keep Tab inside the open dialog. Without this, tabbing walks onto the
   *  dashboard behind the backdrop, where the focus ring is invisible. */
  function trapFocus(event) {
    if (event.key !== "Tab" || !state.openModal) return;
    const modal = el[state.openModal];
    const items = Array.from(modal.querySelectorAll(FOCUSABLE)).filter(
      (node) => node.offsetParent !== null
    );
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function closeModal() {
    const modal = state.openModal && el[state.openModal];
    state.openModal = null;
    if (modal) modal.hidden = true;
    if (state.lastFocus && document.contains(state.lastFocus)) state.lastFocus.focus();
    state.lastFocus = null;
  }

  function wireModal(id) {
    const modal = el[id];
    if (!modal) return;
    modal.querySelectorAll("[data-close], [data-backdrop]").forEach((node) => {
      node.addEventListener("click", closeModal);
    });
  }

  function modalStatus(node, message, tone = "muted") {
    if (!node) return;
    node.textContent = message || "";
    node.className = `flex-1 truncate text-sm font-semibold ${TEXT_CLASSES[tone] || TEXT_CLASSES.muted}`;
  }

  // -----------------------------------------------------------------------
  // System update (OTA)
  //
  // The server cannot report its own success: `docker compose up --build`
  // recreates the container that is serving the request, so POST only ever
  // returns 202 "accepted". Everything after that is this client polling the
  // version endpoint through the outage until a *different* commit answers.
  // -----------------------------------------------------------------------

  /** How long to keep polling for the rebuilt server before giving up. */
  const UPDATE_POLL_TIMEOUT_MS = 10 * 60 * 1000;
  const UPDATE_POLL_INTERVAL_MS = 4000;

  function updateStatusText(message, tone = "muted") {
    const node = el["update-status"];
    if (!node) return;
    node.textContent = message || "";
    node.className = `mt-2 text-xs font-semibold ${TEXT_CLASSES[tone] || TEXT_CLASSES.muted}`;
  }

  function updateLog(lines) {
    const node = el["update-log"];
    if (!node) return;
    const text = (lines || []).join("\n").trim();
    node.textContent = text;
    node.hidden = !text;
  }

  function setUpdateBusy(busy, label) {
    if (el["update-run"]) el["update-run"].disabled = busy;
    if (el["update-spinner"]) el["update-spinner"].hidden = !busy;
    setText(el["update-run-label"], label || "Güncellemeyi Denetle & Uygula");
  }

  /** Show the current version, and reveal the panel only for an admin on a
   *  server that actually has the feature enabled. */
  async function refreshUpdatePanel() {
    const section = el["update-section"];
    if (!section) return;
    section.hidden = true;
    updateLog([]);

    if (state.role !== "admin") return;

    try {
      const info = await api("/api/system/version");
      section.hidden = !info.update_enabled;

      setText(el["update-version"], info.short_commit || info.version || "—");
      setText(el["update-branch"], info.branch || "—");
      if (el["update-dirty-row"]) el["update-dirty-row"].hidden = !info.dirty;

      state.version = info.short_commit || info.version || "";
      if (!info.update_enabled) return;

      setUpdateBusy(false);
      // A previous update -- or last night's scheduled one -- may have
      // finished while nobody was looking.
      await refreshUpdateState();
      await refreshUpdateHistory();
    } catch (err) {
      // A server too old to know these endpoints simply has no update panel.
      if (err.status !== 404) updateStatusText(err.message, "bad");
    }
  }

  const EVENT_TONES = { error: "bad", warning: "warn", info: "muted" };

  /** Render the OTA audit trail: what the nightly job did, newest first. */
  async function refreshUpdateHistory() {
    const list = el["update-history"];
    const wrap = el["update-history-wrap"];
    if (!list || !wrap) return;

    let rows = [];
    try {
      rows = await api("/api/system/events?limit=8&source=ota");
    } catch (_) {
      wrap.hidden = true;
      return;
    }

    list.replaceChildren();
    wrap.hidden = !rows.length;

    rows.forEach((row) => {
      const item = document.createElement("li");
      item.className = "flex gap-2";

      const when = document.createElement("span");
      when.className = "shrink-0 font-mono text-muted";
      when.textContent = shortTimestamp(row.ts);

      const text = document.createElement("span");
      text.className = TEXT_CLASSES[EVENT_TONES[row.level]] || TEXT_CLASSES.muted;
      text.textContent = row.message;
      if (row.detail) text.title = row.detail;

      item.append(when, text);
      list.appendChild(item);
    });
  }

  /** `2026-08-27T03:00:04+00:00` -> `27.08 03:00`; unparseable input verbatim. */
  function shortTimestamp(value) {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value || "");
    const pad = (n) => String(n).padStart(2, "0");
    return `${pad(parsed.getDate())}.${pad(parsed.getMonth() + 1)} ` +
           `${pad(parsed.getHours())}:${pad(parsed.getMinutes())}`;
  }

  /** Read the last/current update outcome and render it. */
  async function refreshUpdateState() {
    try {
      const status = await api("/api/system/update");
      if (!status || status.state === "idle") return;
      const tone = { succeeded: "ok", failed: "bad" }[status.state] || "accent";
      updateStatusText(status.detail || status.state, tone);
      if (status.state === "failed") updateLog(status.log);
    } catch (_) { /* status is a nicety; never block the panel on it */ }
  }

  async function runUpdate() {
    const confirmed = window.confirm(
      "Sistem güncellenecek.\n\n" +
      "Sunucu en son sürümü indirip kendini yeniden başlatacak. " +
      "Bu sırada kameralar ve bariyer birkaç dakika devre dışı kalır.\n\n" +
      "Devam edilsin mi?"
    );
    if (!confirmed) return;

    const before = state.version;
    setUpdateBusy(true, "Güncelleniyor...");
    updateStatusText("Güncelleme başlatılıyor...", "accent");
    updateLog([]);

    try {
      const accepted = await api("/api/system/update", { method: "POST" });
      updateStatusText(accepted.detail || "Güncelleme başlatıldı.", "accent");
    } catch (err) {
      setUpdateBusy(false);
      updateStatusText(err.message, "bad");
      return;
    }

    updateStatusText("Sunucu yeniden derleniyor, lütfen bekleyin...", "accent");
    await pollForRestart(before);
  }

  /** Poll until the server answers with a different commit, or time out.
   *
   *  Connection errors here are expected, not exceptional: the container is
   *  being replaced, so the socket *should* fail for a while. Only the clock
   *  ends this loop. */
  async function pollForRestart(before) {
    const deadline = Date.now() + UPDATE_POLL_TIMEOUT_MS;

    while (Date.now() < deadline) {
      await sleep(UPDATE_POLL_INTERVAL_MS);
      if (state.closing) return;

      let info = null;
      try {
        info = await api("/api/system/version");
      } catch (_) {
        updateStatusText("Sunucu yeniden başlatılıyor...", "accent");
        continue;
      }

      const now = info.short_commit || info.version || "";
      if (before && now && now !== before) {
        setUpdateBusy(false);
        state.version = now;
        setText(el["update-version"], now);
        setText(el["update-branch"], info.branch || "—");
        updateStatusText(`Güncelleme tamamlandı. Yeni sürüm: ${now}`, "ok");
        refreshUpdateHistory();
        return;
      }

      // Same commit and the server is answering again: either nothing to pull
      // or the update failed. The status endpoint knows which.
      const status = await api("/api/system/update").catch(() => null);
      if (status && !status.running) {
        setUpdateBusy(false);
        if (status.state === "failed") {
          updateStatusText(status.detail || "Güncelleme başarısız.", "bad");
          updateLog(status.log);
        } else {
          updateStatusText(status.detail || "Sistem zaten güncel.", "ok");
        }
        return;
      }
    }

    setUpdateBusy(false);
    updateStatusText(
      "Güncelleme durumu doğrulanamadı. Sayfayı yenileyip sürümü kontrol edin.",
      "warn"
    );
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // -----------------------------------------------------------------------
  // Plate management
  // -----------------------------------------------------------------------

  /** Adding and removing are admin-only server-side. Reflect that here so an
   *  operator sees why the controls are inert instead of collecting 403s. */
  function applyPlatePermissions() {
    const isAdmin = state.role === "admin";
    const reason = isAdmin ? "" : "Plaka eklemek/silmek için yönetici yetkisi gerekli";
    el["plate-add"].disabled = !isAdmin;
    el["plate-add"].title = reason;
    el["plate-input"].disabled = !isAdmin;
    el["note-input"].disabled = !isAdmin;
    el["plate-rows"].querySelectorAll("button[data-plate]").forEach((button) => {
      button.disabled = !isAdmin;
      button.title = reason;
    });
  }

  function renderPlates(plates) {
    const body = el["plate-rows"];
    body.textContent = "";
    plates.forEach((plate, index) => {
      const row = document.createElement("tr");
      row.className = "text-sm";

      const number = document.createElement("td");
      number.className = "px-6 py-2.5 font-mono text-muted";
      number.textContent = String(index + 1);

      const name = document.createElement("td");
      name.className = "px-3 py-2.5 font-mono text-base font-bold tracking-wide";
      name.textContent = formatPlate(plate);

      const actions = document.createElement("td");
      actions.className = "px-6 py-2.5 text-right";
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className =
        "rounded-md border border-bad/50 px-3 py-1 text-xs font-bold text-bad transition hover:bg-bad hover:text-white disabled:cursor-not-allowed disabled:opacity-40";
      remove.textContent = "Sil";
      // The raw plate, not the spaced display form: it goes into the URL.
      remove.dataset.plate = plate;
      actions.append(remove);

      row.append(number, name, actions);
      body.append(row);
    });

    el["plates-empty"].hidden = plates.length > 0;
    setText(el["plates-count"], String(plates.length));
    applyPlatePermissions();
  }

  async function loadPlates() {
    modalStatus(el["plates-status"], "Yükleniyor...", "muted");
    try {
      const result = await api("/api/plates");
      renderPlates(result.plates || []);
      modalStatus(el["plates-status"], "");
    } catch (err) {
      modalStatus(el["plates-status"], err.message, "bad");
    }
  }

  async function addPlate(event) {
    event.preventDefault();
    const plate = el["plate-input"].value.trim().toUpperCase();
    if (!plate) return;
    const note = el["note-input"].value.trim();

    el["plate-add"].disabled = true;
    modalStatus(el["plates-status"], "Ekleniyor...", "muted");
    try {
      // `PlateIn` forbids extra keys, so `note` is omitted rather than null
      // when the operator left it blank.
      const body = note ? { plate, note } : { plate };
      const result = await api("/api/plates", { method: "POST", body: JSON.stringify(body) });
      el["plate-input"].value = "";
      el["note-input"].value = "";
      await loadPlates();
      modalStatus(el["plates-status"], `${formatPlate(result.plate)} eklendi.`, "ok");
    } catch (err) {
      modalStatus(el["plates-status"], err.message, "bad");
    } finally {
      applyPlatePermissions();
      el["plate-input"].focus();
    }
  }

  async function removePlate(plate) {
    modalStatus(el["plates-status"], "Siliniyor...", "muted");
    try {
      await api(`/api/plates/${encodeURIComponent(plate)}`, { method: "DELETE" });
      await loadPlates();
      modalStatus(el["plates-status"], `${formatPlate(plate)} silindi.`, "ok");
    } catch (err) {
      modalStatus(el["plates-status"], err.message, "bad");
    }
  }

  function openPlates() {
    openModal("modal-plates");
    loadPlates();
  }

  // -----------------------------------------------------------------------
  // History
  // -----------------------------------------------------------------------

  function renderHistory(rows) {
    const body = el["history-rows"];
    body.textContent = "";
    rows.forEach((row) => {
      const action = String(row.action || "");
      const tone = ACTION_COLORS[action] || "accent";
      const tr = document.createElement("tr");
      tr.className = "text-sm";

      const cell = (text, className) => {
        const td = document.createElement("td");
        td.className = className;
        td.textContent = text;
        return td;
      };

      const camera = String(row.camera || "");
      tr.append(
        cell(String(row.ts || "").replace("T", " ").replace("+00:00", ""),
             "px-6 py-2 font-mono text-xs text-muted"),
        cell(CAMERA_LABELS[camera] || camera, "px-3 py-2 text-xs font-bold text-muted"),
        cell(formatPlate(row.plate), "px-3 py-2 font-mono font-bold"),
        cell(ACTION_LABELS[action] || action.toUpperCase(),
             `px-3 py-2 text-xs font-bold ${TEXT_CLASSES[tone]}`),
        cell(formatConfidence(row.confidence), "px-6 py-2 text-right font-mono tabular-nums")
      );
      body.append(tr);
    });

    el["history-empty"].hidden = rows.length > 0;
    setText(el["history-count"], String(rows.length));
    el["history-csv"].disabled = rows.length === 0;
  }

  async function loadHistory() {
    const day = el["history-day"].value;
    const camera = el["history-camera"].value;
    const params = new URLSearchParams({ limit: String(HISTORY_LIMIT) });
    if (day) { params.set("since", day); params.set("until", day); }
    if (camera) params.set("camera", camera);

    modalStatus(el["history-status"], "Yükleniyor...", "muted");
    try {
      const rows = await api(`/api/logs?${params.toString()}`);
      state.historyRows = rows || [];
      renderHistory(state.historyRows);
      modalStatus(
        el["history-status"],
        state.historyRows.length === HISTORY_LIMIT
          ? `En yeni ${HISTORY_LIMIT} kayıt gösteriliyor.`
          : ""
      );
    } catch (err) {
      state.historyRows = [];
      renderHistory([]);
      modalStatus(el["history-status"], err.message, "bad");
    }
  }

  async function loadHistoryDays() {
    try {
      const days = await api("/api/logs/dates");
      const select = el["history-day"];
      const current = select.value;
      select.textContent = "";
      const all = document.createElement("option");
      all.value = "";
      all.textContent = "Tümü";
      select.append(all);
      (days || []).forEach((day) => {
        const option = document.createElement("option");
        option.value = day;
        option.textContent = day;
        select.append(option);
      });
      select.value = current;
    } catch (_) {
      /* the day filter is a convenience; the unfiltered list still loads */
    }
  }

  function openHistory() {
    openModal("modal-history");
    loadHistoryDays();
    loadHistory();
  }

  // -----------------------------------------------------------------------
  // CSV export
  // -----------------------------------------------------------------------

  /** RFC 4180 field: quote when it contains a delimiter, quote or newline,
   *  and double any embedded quote. Without this a note containing a comma
   *  silently shifts every later column. */
  function csvField(value) {
    const text = value === null || value === undefined ? "" : String(value);
    return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  function toCsv(rows) {
    const header = ["ID", "Zaman (UTC)", "Kamera", "Plaka", "Durum", "Güven (%)"];
    const lines = [header.map(csvField).join(",")];
    rows.forEach((row) => {
      const camera = String(row.camera || "");
      const action = String(row.action || "");
      const confidence = Number(row.confidence);
      lines.push([
        row.id ?? "",
        String(row.ts || "").replace("T", " ").replace("+00:00", ""),
        CAMERA_LABELS[camera] || camera,
        String(row.plate || ""),
        ACTION_LABELS[action] || action.toUpperCase(),
        Number.isFinite(confidence) ? Math.round(confidence * 100) : "",
      ].map(csvField).join(","));
    });
    // CRLF per RFC 4180, and a UTF-8 BOM so Excel reads "İZİN VERİLDİ" as
    // Turkish rather than mojibake.
    return "﻿" + lines.join("\r\n") + "\r\n";
  }

  function downloadCsv() {
    const rows = state.historyRows;
    if (!rows.length) {
      modalStatus(el["history-status"], "Dışa aktarılacak kayıt yok.", "warn");
      return;
    }
    const blob = new Blob([toCsv(rows)], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = CSV_FILENAME;
    // Firefox only fires the download for a link that is in the document.
    link.style.display = "none";
    document.body.append(link);
    link.click();
    link.remove();
    // Revoked on the next tick: revoking synchronously can cancel the
    // download in some browsers before it has read the blob.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    modalStatus(el["history-status"], `${rows.length} kayıt indirildi.`, "ok");
  }

  // -----------------------------------------------------------------------
  // Session
  // -----------------------------------------------------------------------

  function showLogin(message) {
    el["login-screen"].hidden = false;
    el.dashboard.hidden = true;
    setText(el["login-error"], message || "");
    setLoginBusy(false);
    el["login-password"].value = "";
    el["login-username"].focus();
  }

  function setLoginBusy(busy) {
    el["login-submit"].disabled = busy;
    el["login-register"].disabled = busy;
  }

  function startSession() {
    el["login-screen"].hidden = true;
    el.dashboard.hidden = false;
    state.closing = false;
    applyRole();
    loadQuality();
    attachStream("entry");
    attachStream("exit");
    connectSocket();
    refreshStats();
    refreshLicense();
    refreshParking();
    loadRecentLogs();
    clearInterval(state.statsTimer);
    state.statsTimer = setInterval(refreshStats, STATS_INTERVAL_MS);
    clearInterval(state.parkingTimer);
    state.parkingTimer = setInterval(refreshParking, PARKING_INTERVAL_MS);
    // Counted locally between polls so the clock ticks every second instead
    // of jumping once per stats refresh.
    clearInterval(state.uptimeTimer);
    state.uptimeTimer = setInterval(() => {
      if (!state.uptimeKnown) return;
      state.uptimeSeconds += 1;
      setText(el.uptime, formatUptime(state.uptimeSeconds));
    }, 1000);
  }

  function logout(message) {
    state.closing = true;
    closeModal();
    clearInterval(state.statsTimer);
    clearInterval(state.parkingTimer);
    clearInterval(state.uptimeTimer);
    clearTimeout(state.wsTimer);
    if (state.socket) {
      try { state.socket.close(1000, "logout"); } catch (_) { /* already gone */ }
      state.socket = null;
    }
    detachStreams();
    // The quality preference is deliberately kept: it describes this device,
    // not this session.
    localStorage.removeItem(TOKEN_KEY);
    state.token = null;
    state.role = "";
    state.username = "";
    setConnected(false);
    setBanner("");
    state.parking = { inside: 0, capacity: 0, full: false };
    el["full-banner"].hidden = true;
    showLogin(message);
  }

  /** Log in, or create the very first account.
   *
   *  `POST /api/auth/register` is open only while no user exists; once one
   *  does, the server answers 401/403 and only an admin may add accounts.
   *  That is translated here into something an operator can act on, the same
   *  way the desktop client does it. */
  async function submitCredentials(register) {
    const username = el["login-username"].value.trim();
    const password = el["login-password"].value;
    if (!username || !password) {
      setText(el["login-error"], "Kullanıcı adı ve parola zorunludur.");
      return;
    }
    setLoginBusy(true);
    setText(el["login-error"], "");
    try {
      const result = await api(register ? "/api/auth/register" : "/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      state.token = result.access_token;
      state.username = result.username || username;
      state.role = result.role || "";
      localStorage.setItem(TOKEN_KEY, state.token);
      startSession();
    } catch (err) {
      setLoginBusy(false);
      const message = register && (err.status === 401 || err.status === 403)
        ? "Sistemde zaten kullanıcı var. Yeni hesabı bir yönetici oluşturmalı."
        : (err.message || "Giriş başarısız.");
      setText(el["login-error"], message);
      el["login-password"].value = "";
    }
  }

  /** A token in localStorage is only a claim; the server decides. */
  async function restoreSession() {
    const stored = localStorage.getItem(TOKEN_KEY);
    if (!stored) { showLogin(""); return; }
    state.token = stored;
    try {
      const me = await api("/api/auth/me");
      state.username = me.username || "";
      state.role = me.role || "";
      startSession();
    } catch (_) {
      state.token = null;
      localStorage.removeItem(TOKEN_KEY);
      showLogin("");
    }
  }

  // -----------------------------------------------------------------------
  // Boot
  // -----------------------------------------------------------------------

  function init() {
    if (!window.tailwind && el["cdn-warning"]) el["cdn-warning"].hidden = false;

    el["login-form"].addEventListener("submit", (event) => {
      event.preventDefault();
      submitCredentials(false);
    });
    el["login-register"].addEventListener("click", () => submitCredentials(true));
    el["btn-gate"].addEventListener("click", openGate);
    el["btn-pause"].addEventListener("click", togglePause);
    el["btn-plates"].addEventListener("click", openPlates);
    el["btn-history"].addEventListener("click", openHistory);
    el["btn-settings"].addEventListener("click", openSettings);
    if (el["update-run"]) el["update-run"].addEventListener("click", runUpdate);
    el["btn-logout"].addEventListener("click", () => logout(""));

    wireModal("modal-plates");
    wireModal("modal-history");
    wireModal("modal-settings");
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && state.openModal) closeModal();
      else trapFocus(event);
    });

    el["plate-form"].addEventListener("submit", addPlate);
    // Delegated: the rows are rebuilt on every refresh, so binding per row
    // would mean rebinding on every refresh too.
    el["plate-rows"].addEventListener("click", (event) => {
      const button = event.target.closest("button[data-plate]");
      if (button && !button.disabled) removePlate(button.dataset.plate);
    });

    el["history-refresh"].addEventListener("click", loadHistory);
    el["history-day"].addEventListener("change", loadHistory);
    el["history-camera"].addEventListener("change", loadHistory);
    el["history-csv"].addEventListener("click", downloadCsv);

    el["settings-form"].addEventListener("submit", saveSettings);

    // Leaving the page mid-stream otherwise leaves two MJPEG responses open
    // on the server until its idle timeout notices.
    window.addEventListener("pagehide", () => { state.closing = true; detachStreams(); });

    restoreSession();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
