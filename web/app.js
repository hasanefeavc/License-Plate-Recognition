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
 * would fire its own extra pulse for the same car. "Kapıyı Aç" is the
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
    /** Resident records from the last /api/plates load. Search filters this
     *  in place rather than re-querying: a resident list is hundreds of rows,
     *  and a round trip per keystroke would be slower and less reliable. */
    plateRecords: [],
    /** Wall-clock ms until the manual gate button is usable again. Zero when
     *  the gate is not known to be moving. */
    gateBusyUntil: 0,
    gateTimer: null,
    /** The caller's own licence, from /api/license/me. Admins are
     *  `unlimited`; an operator carries a status and remaining days. */
    license: null,
    /** Guards against a burst of 402s opening the dialog once per request. */
    licensePrompted: false,
    /** Human-readable version of the running server (a tag like `v1.0.0`, or
     *  a bare commit hash in an untagged repo). Display only. */
    version: "",
    /** Full commit hash of the running server. This -- not `version` -- is
     *  what says an OTA update actually replaced the process: tagging a
     *  commit that is already deployed changes the version string without
     *  deploying anything. */
    commit: "",
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
    "login-error", "login-submit", "login-register", "login-hint",
    "dashboard", "banner",
    "cdn-warning",
    "uptime", "user-label", "conn-dot", "conn-label", "feed", "feed-empty",
    "feed-count", "activity", "stat-read", "stat-grant", "stat-deny",
    "btn-gate", "btn-gate-label", "gate-spinner",
    "btn-pause", "btn-history", "btn-logout",
    "toast", "cam-entry", "cam-exit",
    // Plate-management modal
    "modal-plates", "btn-plates", "plate-form", "plate-input", "note-input",
    "plate-form", "plate-add", "plate-rows", "plates-empty", "plates-count", "plates-status",
    "owner-input", "apartment-input", "expires-input", "blocked-input", "plate-search",
    "plates-io", "plate-import-file", "plate-import-overwrite", "plate-export",
    // History modal
    "modal-history", "history-day", "history-camera", "history-refresh",
    "history-csv", "history-rows", "history-empty", "history-count",
    "history-status",
    // Settings modal + capacity
    // User management modal
    "modal-users", "btn-users", "user-form", "user-name", "user-password",
    "user-role", "user-ttl", "user-add", "user-rows", "users-empty",
    "users-count", "users-status", "license-days", "license-days-custom",
    // Licence activation modal + navbar badge
    "modal-license", "license-form", "license-key", "license-submit",
    "license-status", "license-state", "license-badge",
    "modal-settings", "btn-settings", "settings-form", "settings-save",
    "settings-status", "capacity-input", "capacity-hint", "quality-select",
    "capacity-section", "capacity-divider",
    "occupancy", "capacity", "full-banner",
    // System update (inside the settings modal)
    "settings-ota-section", "update-version", "update-branch", "update-dirty-row",
    "update-run", "update-check", "update-run-label", "update-spinner", "update-status",
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
      // 402 is specifically "this account's licence has lapsed" — distinct
      // from 403 ("not your role"), which nothing can be done about from here.
      // Surfacing the dialog beats leaving the operator to guess why every
      // button suddenly fails.
      if (response.status === 402 && !state.closing) onLicenseLapsed();
      throw error;
    }
    return payload;
  }

  /** Download a file from an authenticated endpoint.
   *
   *  A plain <a href> cannot carry the bearer header, so the body is fetched,
   *  turned into a blob and handed to a synthetic link. The server's
   *  Content-Disposition filename is preferred over the caller's guess so the
   *  saved file keeps the timestamp the server stamped on it. */
  async function downloadFromApi(path, fallbackName) {
    const headers = {};
    if (state.token) headers.Authorization = `Bearer ${state.token}`;

    const response = await fetch(path, { headers });
    if (!response.ok) {
      let detail = `HTTP ${response.status}`;
      try {
        const payload = await response.json();
        if (payload && payload.error && payload.error.detail) detail = payload.error.detail;
      } catch (_) { /* a CSV error body is not JSON */ }
      const error = new Error(detail);
      error.status = response.status;
      throw error;
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filenameFromResponse(response) || fallbackName;
    // Firefox only fires the download for a link that is in the document.
    link.style.display = "none";
    document.body.append(link);
    link.click();
    link.remove();
    // Revoked on the next tick: revoking synchronously can cancel the download
    // in some browsers before they have read the blob.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /** Pull the filename out of a Content-Disposition header, if there is one. */
  function filenameFromResponse(response) {
    const header = response.headers.get("Content-Disposition") || "";
    const match = /filename="?([^";]+)"?/i.exec(header);
    return match ? match[1] : "";
  }

  /** Re-read the licence and offer the key dialog, at most once per lapse. */
  function onLicenseLapsed() {
    if (state.licensePrompted) return;
    state.licensePrompted = true;
    refreshUserLicense().then(() => {
      if (state.openModal !== "modal-license") openLicense();
    });
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

  /** The deployment licence no longer drives anything in the header.
   *
   *  It used to own a ticker ("Lisans - Toki 1. Etap - 42 gün kaldı") and a
   *  banner that announced the pipeline had stopped. Both are gone: the server
   *  no longer halts recognition or refuses the gate on it, so a warning about
   *  either would be describing something that does not happen.
   *
   *  Kept as a no-op rather than deleted because the WebSocket still pushes a
   *  `license` payload and `refreshLicense()` still polls it; silently
   *  dropping the message here is clearer than removing the plumbing on both
   *  sides at once. The header badge is `renderLicenseBadge`, and it reads the
   *  *user's* licence. */
  function applyLicense(_license) {
    // Nothing to display, and nothing to block: `state.licenceValid` stays
    // true so no control is disabled on the deployment licence's account.
    state.licenceValid = true;
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
    renderUserBadge();
    updateControls();
    applyPlatePermissions();
    el["capacity-input"].disabled = state.role !== "admin";
  }

  /** Username plus a coloured role chip, rather than "name (role)" in text.
   *
   *  The chip is the fastest way to answer "why can I not press that?", which
   *  is the question an operator asks first on a dashboard with admin-only
   *  controls hidden. */
  function renderUserBadge() {
    const node = el["user-label"];
    if (!node) return;
    node.textContent = "";
    if (!state.username) return;

    const name = document.createElement("span");
    name.className = "font-bold text-ink";
    name.textContent = state.username;

    const isAdmin = state.role === "admin";
    const chip = document.createElement("span");
    chip.className =
      "ml-2 rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider " +
      (isAdmin ? "border-accent/50 bg-accent/10 text-accent" : "border-line bg-row text-muted");
    chip.textContent = isAdmin ? "Yönetici" : "Operatör";

    node.append(name, chip);
  }

  function updateControls() {
    const isAdmin = state.role === "admin";
    const gateBusy = state.gateBusyUntil > Date.now();
    const gateBlocked = !state.licenceValid || gateBusy;
    if (el["btn-gate"]) {
      el["btn-gate"].disabled = gateBlocked;
      el["btn-gate"].title = !state.licenceValid
        ? "Lisans geçersiz"
        : (gateBusy ? "Kapı hareket hâlinde" : "");
    }
    // User management is admin-only server-side; hide the entry point rather
    // than opening a modal whose every request returns 403.
    if (el["btn-users"]) el["btn-users"].hidden = !isAdmin;
    if (el["btn-pause"]) {
      el["btn-pause"].disabled = false;
      el["btn-pause"].textContent = state.paused ? "Devam Et" : "Duraklat";
    }
  }

  /** How long the manual button stays busy after a pulse, in ms.
   *
   *  This is the sliding gate's travel time, and it is a hardware fact, not a
   *  UI preference: the motor uses step-by-step logic where a second pulse
   *  *stops* the gate mid-travel instead of re-opening it. Holding the button
   *  down for the cycle is what stops an operator watching a slow gate from
   *  pressing again and halting it halfway.
   *
   *  Keep this in step with `voting.cooldown_s` in config.yaml, which does the
   *  same job for plate-triggered pulses. */
  const GATE_BUSY_MS = 20000;

  /** Put the gate button into (or out of) its post-pulse busy state.
   *
   *  Counts down in the label so the wait reads as "the gate is moving"
   *  rather than as a frozen button. */
  function setGateBusy(busy) {
    if (state.gateTimer) {
      clearInterval(state.gateTimer);
      state.gateTimer = null;
    }
    if (el["gate-spinner"]) el["gate-spinner"].hidden = !busy;

    if (!busy) {
      state.gateBusyUntil = 0;
      setText(el["btn-gate-label"], "Kapıyı Aç");
      updateControls();
      return;
    }

    state.gateBusyUntil = Date.now() + GATE_BUSY_MS;

    const tick = () => {
      const remaining = Math.ceil((state.gateBusyUntil - Date.now()) / 1000);
      if (remaining <= 0 || state.closing) {
        setGateBusy(false);
        return;
      }
      setText(el["btn-gate-label"], `Kapı Açılıyor... ${remaining}s`);
    };
    tick();
    state.gateTimer = setInterval(tick, 1000);
    updateControls();
  }

  async function openGate() {
    if (state.gateBusyUntil > Date.now()) return;

    // Busy immediately, before the request goes out: the double-press this
    // guards against happens in the second or two while the POST is still in
    // flight, not after it has come back.
    setGateBusy(true);
    try {
      await api("/api/relay/trigger", { method: "POST" });
      toast("Kapı açılıyor.", "ok");
    } catch (err) {
      // The pulse never went out, so the gate is not moving: release the
      // button rather than making the operator wait out a cycle that is not
      // happening.
      setGateBusy(false);
      toast(err.message, "bad");
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

    // Capacity and stream quality are both open to operators now. The site
    // capacity is a fact about the car park, not a privileged setting, and the
    // person who notices it is wrong is the one on the gate.
    if (el["capacity-section"]) el["capacity-section"].hidden = false;
    if (el["capacity-divider"]) el["capacity-divider"].hidden = false;

    el["capacity-input"].value = state.parking.capacity ? String(state.parking.capacity) : "0";
    el["capacity-input"].disabled = false;
    el["quality-select"].value = String(state.quality);
    setText(el["capacity-hint"], `Şu an içeride: ${state.parking.inside}`);
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
    setText(el["update-run-label"], label || "Sistemi Güncelle");
  }

  /** Show the current version, and reveal the panel only for an admin on a
   *  server that actually has the feature enabled. */
  /** Fill the OTA card. Never hides it, and never throws.
   *
   *  The card used to start hidden and be revealed only on a successful
   *  `/api/system/version` with `update_enabled`. Two ways that went wrong: a
   *  server with updates switched off lost the whole card rather than an
   *  explanation, and *any* error before the reveal left it hidden with the
   *  reason swallowed. It is now always rendered — what varies is whether the
   *  button is live and what the status line says. */
  async function refreshUpdatePanel() {
    const section = el["settings-ota-section"];
    if (!section) return;
    section.hidden = false;
    updateLog([]);
    setUpdateBusy(false);

    let info = null;
    try {
      info = await api("/api/system/version");
    } catch (err) {
      // A server too old to know the endpoint, or one that refused: say so in
      // the card instead of removing it.
      setUpdateAvailable(false, err.status === 404
        ? "Bu sunum güncelleme uçlarını desteklemiyor."
        : err.message);
      return;
    }

    applyVersion(info);
    if (!info.update_enabled) {
      setUpdateAvailable(false, "Sunucuda güncelleme kapalı (system_update.enabled).");
      return;
    }

    setUpdateAvailable(true, "");
    // A previous update -- or last night's scheduled one -- may have finished
    // while nobody was looking. Both are best-effort: neither may take the
    // card down with it.
    await refreshUpdateState().catch(() => {});
    await refreshUpdateHistory().catch(() => {});
  }

  /** Enable or disable the two OTA buttons, with a reason when disabled. */
  function setUpdateAvailable(available, reason) {
    ["update-run", "update-check"].forEach((id) => {
      const button = el[id];
      if (!button) return;
      button.disabled = !available;
      button.title = available ? "" : reason;
    });
    if (!available) updateStatusText(reason, "warn");
  }

  /** Check for a newer version without installing anything. */
  async function checkForUpdates() {
    const before = state.commit;
    if (el["update-check"]) el["update-check"].disabled = true;
    updateStatusText("Kontrol ediliyor...", "accent");
    try {
      const info = await api("/api/system/version");
      applyVersion(info);
      const now = info.commit || info.short_commit || "";
      updateStatusText(
        before && now && now !== before
          ? `Yeni sürüm yüklendi: ${state.version}`
          : `Çalışan sürüm: ${state.version}`,
        "ok"
      );
      await refreshUpdateHistory().catch(() => {});
    } catch (err) {
      updateStatusText(err.message, "bad");
    } finally {
      if (el["update-check"]) el["update-check"].disabled = false;
    }
  }

  const EVENT_TONES = { error: "bad", warning: "warn", info: "muted" };

  /** Paint one `/api/system/version` payload into the panel and remember it.
   *
   *  `version` is what the server calls itself -- `v1.0.0`, or
   *  `v1.0.0-2-g6845136` between releases, or a bare hash in a repo that has
   *  never been tagged. `commit` is kept separately because it, not the
   *  label, is what identifies the running build. */
  function applyVersion(info) {
    state.version = info.version || info.short_commit || "";
    state.commit = info.commit || info.short_commit || "";

    setText(el["update-version"], state.version || "—");
    setText(el["update-branch"], info.branch || "—");
    if (el["update-dirty-row"]) el["update-dirty-row"].hidden = !info.dirty;
  }

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

    const before = state.commit;
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

      const now = info.commit || info.short_commit || "";
      if (before && now && now !== before) {
        setUpdateBusy(false);
        applyVersion(info);
        updateStatusText(`Güncelleme tamamlandı. Yeni sürüm: ${state.version}`, "ok");
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
  /** Every field a plate form writes. Kept in one list so adding an input to
   *  the markup cannot leave it enabled for an operator by omission. */
  const PLATE_FORM_INPUTS = [
    "plate-input", "owner-input", "apartment-input",
    "note-input", "expires-input", "blocked-input",
  ];

  /** Plate management is open to every signed-in user.
   *
   *  Operators are the people standing at the barrier, so add, edit, block and
   *  delete are all theirs; the server agrees, and gates these endpoints on a
   *  live licence rather than on the role. What an unlicensed operator gets is
   *  a 402 and the licence dialog, not a hidden button — being told why is more
   *  use than the control quietly vanishing.
   *
   *  Kept as a function (rather than deleted) because it is called after every
   *  render, and a future restriction belongs here rather than scattered
   *  through the table code. */
  function applyPlatePermissions() {
    el["plate-add"].disabled = false;
    el["plate-add"].title = "";
    PLATE_FORM_INPUTS.forEach((id) => { if (el[id]) el[id].disabled = false; });

    const form = el["plate-form"];
    if (form) form.hidden = false;
    if (el["plates-io"]) el["plates-io"].hidden = false;

    el["plate-rows"].querySelectorAll("button[data-plate]").forEach((button) => {
      button.disabled = false;
      button.title = "";
    });
  }

  /** Status badge vocabulary. Server-derived, so the badge cannot contradict
   *  what the gate will actually do (see `plate_status` in schemas.py). */
  const PLATE_STATUS = {
    active:  { label: "Aktif",        classes: "border-ok/50 bg-ok/10 text-ok" },
    blocked: { label: "Kara Liste",   classes: "border-bad/50 bg-bad/10 text-bad" },
    expired: { label: "Süresi Doldu", classes: "border-warn/50 bg-warn/10 text-warn" },
    guest:   { label: "Misafir",      classes: "border-accent/50 bg-accent/10 text-accent" },
  };

  /** `2027-01-01T23:59:59+00:00` -> `01.01.2027`; blank -> "Süresiz". */
  function formatExpiry(value) {
    if (!value) return "Süresiz";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value);
    const pad = (n) => String(n).padStart(2, "0");
    return `${pad(parsed.getDate())}.${pad(parsed.getMonth() + 1)}.${parsed.getFullYear()}`;
  }

  /** The plate itself, as a badge that reads like a plate. */
  function plateBadge(plate) {
    const badge = document.createElement("span");
    badge.className =
      "inline-block rounded-md border-2 border-ink/70 bg-ink/5 px-2.5 py-1 " +
      "font-mono text-base font-bold tracking-wider text-ink";
    badge.textContent = formatPlate(plate);
    return badge;
  }

  function statusBadge(status) {
    const spec = PLATE_STATUS[status] || PLATE_STATUS.active;
    const badge = document.createElement("span");
    badge.className =
      `inline-block rounded-full border px-2.5 py-0.5 text-xs font-bold ${spec.classes}`;
    badge.textContent = spec.label;
    return badge;
  }

  /** `Ahmet Yılmaz (Daire 12)`.
   *
   *  The apartment is parenthesised rather than joined with a dash so the name
   *  stays the thing the eye lands on when scanning a column of them. A bare
   *  number is prefixed with "Daire"; anything already carrying its own label
   *  ("B Blok D:12") is left as the manager typed it. Either half may be
   *  missing — an operator adding a plate at the barrier often has neither. */
  function formatResident(owner, apartment) {
    const name = (owner || "").trim();
    const flat = (apartment || "").trim();
    if (!name && !flat) return "—";
    if (!flat) return name;

    const labelled = /^\d+$/.test(flat) ? `Daire ${flat}` : flat;
    return name ? `${name} (${labelled})` : labelled;
  }

  /** Owner on top, apartment and note beneath: the scannable line is the name. */
  function ownerCell(record) {
    const cell = document.createElement("td");
    cell.className = "px-3 py-2.5";

    const primary = document.createElement("div");
    primary.className = "font-semibold text-ink";
    primary.textContent = formatResident(record.owner, record.apartment);
    cell.append(primary);

    if (record.note) {
      const sub = document.createElement("div");
      sub.className = "mt-0.5 truncate text-xs text-muted";
      sub.style.maxWidth = "22rem";
      sub.textContent = record.note;
      sub.title = record.note;  // the full text, for a note wider than the cell
      cell.append(sub);
    }
    return cell;
  }

  function actionButton(label, plate, action, classes, title) {
    const button = document.createElement("button");
    button.type = "button";
    button.className =
      `rounded-md border px-2.5 py-1 text-xs font-bold transition disabled:cursor-not-allowed ` +
      `disabled:opacity-40 ${classes}`;
    button.textContent = label;
    // The raw plate, not the spaced display form: it goes into the URL.
    button.dataset.plate = plate;
    button.dataset.action = action;
    if (title) button.title = title;
    return button;
  }

  function renderPlates(records) {
    const body = el["plate-rows"];
    body.textContent = "";

    records.forEach((record) => {
      const plate = String(record.plate || "");
      const status = String(record.status || "active");

      const row = document.createElement("tr");
      row.className = "text-sm";

      const plateCell = document.createElement("td");
      plateCell.className = "px-4 py-2.5 sm:px-6";
      plateCell.append(plateBadge(plate));

      const statusCell = document.createElement("td");
      statusCell.className = "px-3 py-2.5";
      statusCell.append(statusBadge(status));

      const expiry = document.createElement("td");
      expiry.className = "px-3 py-2.5 font-mono text-xs text-muted";
      expiry.textContent = formatExpiry(record.expires_at);

      const actions = document.createElement("td");
      actions.className = "whitespace-nowrap px-4 py-2.5 text-right sm:px-6";
      actions.append(
        actionButton(
          record.blocked ? "Aç" : "Engelle",
          plate,
          record.blocked ? "unblock" : "block",
          record.blocked
            ? "border-ok/50 text-ok hover:bg-ok hover:text-ground"
            : "border-warn/50 text-warn hover:bg-warn hover:text-ground",
          record.blocked ? "Engeli kaldır" : "Kara listeye al"
        ),
        actionButton(
          "Sil", plate, "delete",
          "ml-1.5 border-bad/50 text-bad hover:bg-bad hover:text-white"
        )
      );

      row.append(plateCell, ownerCell(record), statusCell, expiry, actions);
      body.append(row);
    });

    const total = state.plateRecords.length;
    el["plates-empty"].hidden = records.length > 0;
    el["plates-empty"].textContent = total
      ? "Aramayla eşleşen plaka yok."
      : "Kayıtlı plaka yok.";
    setText(
      el["plates-count"],
      records.length === total ? String(total) : `${records.length}/${total}`
    );
    applyPlatePermissions();
  }

  /** Case-insensitive substring match over plate, owner, apartment and note.
   *
   *  The plate is matched with its spacing stripped as well as with it, so
   *  typing "34ABC" finds a plate the table shows as "34 ABC 123". */
  function filterPlates() {
    const needle = (el["plate-search"] ? el["plate-search"].value : "").trim().toLowerCase();
    if (!needle) return state.plateRecords;

    const bare = needle.replace(/\s+/g, "");
    return state.plateRecords.filter((record) => {
      const plate = String(record.plate || "").toLowerCase();
      if (plate.includes(bare)) return true;
      return [record.owner, record.apartment, record.note].some(
        (value) => value && String(value).toLowerCase().includes(needle)
      );
    });
  }

  function refreshPlateTable() {
    renderPlates(filterPlates());
  }

  async function loadPlates() {
    modalStatus(el["plates-status"], "Yükleniyor...", "muted");
    try {
      const result = await api("/api/plates");
      // `records` carries the resident data; older servers send only `plates`.
      state.plateRecords = result.records
        || (result.plates || []).map((plate) => ({ plate, status: "active" }));
      refreshPlateTable();
      modalStatus(el["plates-status"], "");
    } catch (err) {
      modalStatus(el["plates-status"], err.message, "bad");
    }
  }

  async function addPlate(event) {
    event.preventDefault();
    const plate = el["plate-input"].value.trim().toUpperCase();
    if (!plate) return;

    // `PlateIn` forbids extra keys, so blank optional fields are omitted
    // rather than sent as null.
    const body = { plate };
    const optional = {
      owner: el["owner-input"],
      apartment: el["apartment-input"],
      note: el["note-input"],
      expires_at: el["expires-input"],
    };
    Object.entries(optional).forEach(([key, input]) => {
      const value = input && input.value.trim();
      if (value) body[key] = value;
    });
    if (el["blocked-input"] && el["blocked-input"].checked) body.blocked = true;

    el["plate-add"].disabled = true;
    modalStatus(el["plates-status"], "Ekleniyor...", "muted");
    try {
      const result = await api("/api/plates", { method: "POST", body: JSON.stringify(body) });
      clearPlateForm();
      await loadPlates();
      modalStatus(el["plates-status"], `${formatPlate(result.plate)} eklendi.`, "ok");
    } catch (err) {
      modalStatus(el["plates-status"], err.message, "bad");
    } finally {
      applyPlatePermissions();
      el["plate-input"].focus();
    }
  }

  function clearPlateForm() {
    ["plate-input", "owner-input", "apartment-input", "note-input", "expires-input"]
      .forEach((id) => { if (el[id]) el[id].value = ""; });
    if (el["blocked-input"]) el["blocked-input"].checked = false;
  }

  async function removePlate(plate) {
    if (!window.confirm(`${formatPlate(plate)} kalıcı olarak silinecek.\n\nDevam edilsin mi?`)) {
      return;
    }
    modalStatus(el["plates-status"], "Siliniyor...", "muted");
    try {
      await api(`/api/plates/${encodeURIComponent(plate)}`, { method: "DELETE" });
      await loadPlates();
      modalStatus(el["plates-status"], `${formatPlate(plate)} silindi.`, "ok");
    } catch (err) {
      modalStatus(el["plates-status"], err.message, "bad");
    }
  }

  /** Flip the blocked flag.
   *
   *  PATCH with only `blocked`, so the owner, apartment, note and expiry the
   *  toggle never asked about are left exactly as they were. */
  async function setPlateBlocked(plate, blocked) {
    modalStatus(el["plates-status"], blocked ? "Engelleniyor..." : "Engel kaldırılıyor...", "muted");
    try {
      await api(`/api/plates/${encodeURIComponent(plate)}`, {
        method: "PATCH",
        body: JSON.stringify({ blocked }),
      });
      await loadPlates();
      modalStatus(
        el["plates-status"],
        `${formatPlate(plate)} ${blocked ? "engellendi" : "tekrar aktif"}.`,
        blocked ? "warn" : "ok"
      );
    } catch (err) {
      modalStatus(el["plates-status"], err.message, "bad");
    }
  }

  function openPlates() {
    openModal("modal-plates");
    if (el["plate-search"]) el["plate-search"].value = "";
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


  /** Export the history from the server, using the filters on screen.
   *
   *  Built server-side rather than from `state.historyRows`, which holds only
   *  the page currently rendered: an operator asking for a month of history
   *  wants the month, not the two hundred rows the table happens to show. */
  async function downloadCsv() {
    const params = new URLSearchParams();
    const day = el["history-day"] && el["history-day"].value;
    if (day) {
      params.set("since", `${day}T00:00:00+00:00`);
      params.set("until", `${day}T23:59:59+00:00`);
    }
    const camera = el["history-camera"] && el["history-camera"].value;
    if (camera) params.set("camera", camera);

    el["history-csv"].disabled = true;
    modalStatus(el["history-status"], "Dışa aktarılıyor...", "muted");
    try {
      await downloadFromApi(`/api/events/export?${params.toString()}`, "kayitlar.csv");
      modalStatus(el["history-status"], "Kayıtlar indirildi.", "ok");
    } catch (err) {
      modalStatus(el["history-status"], err.message, "bad");
    } finally {
      el["history-csv"].disabled = false;
    }
  }

  // -----------------------------------------------------------------------
  // Plate list: bulk import / export
  // -----------------------------------------------------------------------

  /** Upload the chosen CSV and report what the server made of it.
   *
   *  The input is cleared afterwards so re-picking the same file fires
   *  `change` again -- without that, correcting the spreadsheet and choosing
   *  it a second time does nothing. */
  async function importPlates(event) {
    const input = event.target;
    const file = input.files && input.files[0];
    if (!file) return;

    const overwrite = Boolean(el["plate-import-overwrite"] && el["plate-import-overwrite"].checked);
    modalStatus(el["plates-status"], `${file.name} yükleniyor...`, "muted");

    const body = new FormData();
    body.append("file", file);

    try {
      // No Content-Type header: the browser must set the multipart boundary.
      const headers = {};
      if (state.token) headers.Authorization = `Bearer ${state.token}`;
      const response = await fetch(
        `/api/plates/import?overwrite=${overwrite ? "true" : "false"}`,
        { method: "POST", headers, body }
      );
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(
          (payload && payload.error && payload.error.detail) || `HTTP ${response.status}`
        );
      }
      reportImport(payload);
      await loadPlates();
    } catch (err) {
      modalStatus(el["plates-status"], err.message, "bad");
    } finally {
      input.value = "";
    }
  }

  /** Turn the per-row counts into one sentence an operator can act on. */
  function reportImport(report) {
    if (!report) return;
    const parts = [];
    if (report.added) parts.push(`${report.added} eklendi`);
    if (report.updated) parts.push(`${report.updated} güncellendi`);
    if (report.skipped) parts.push(`${report.skipped} atlandı`);
    if (report.invalid) parts.push(`${report.invalid} geçersiz`);

    const summary = parts.length ? parts.join(", ") : "değişiklik yok";
    const tone = report.invalid ? "warn" : "ok";
    modalStatus(el["plates-status"], `İçe aktarma: ${summary}.`, tone);

    // The first failing row is worth surfacing; the rest are in the response
    // for anyone who wants them, but a toast is not a log viewer.
    if (report.errors && report.errors.length) {
      toast(report.errors[0], "warn");
    }
  }

  async function exportPlates() {
    if (el["plate-export"]) el["plate-export"].disabled = true;
    modalStatus(el["plates-status"], "Dışa aktarılıyor...", "muted");
    try {
      await downloadFromApi("/api/plates/export", "plakalar.csv");
      modalStatus(el["plates-status"], "Plaka listesi indirildi.", "ok");
    } catch (err) {
      modalStatus(el["plates-status"], err.message, "bad");
    } finally {
      if (el["plate-export"]) el["plate-export"].disabled = false;
    }
  }

  // -----------------------------------------------------------------------
  // Licensing
  //
  // Admins are exempt by construction and carry an "unlimited" badge. An
  // operator holds a key with an expiry, and the server answers 402 on every
  // operational endpoint once it lapses — which is what opens the dialog.
  // -----------------------------------------------------------------------

  const LICENSE_BADGES = {
    unlimited:          { label: "Yönetici (Sınırsız)",  classes: "border-accent/50 bg-accent/10 text-accent" },
    active:             { label: "Lisanslı",             classes: "border-ok/50 bg-ok/10 text-ok" },
    expired:            { label: "Lisans Süresi Doldu",  classes: "border-bad/50 bg-bad/10 text-bad" },
    revoked:            { label: "Lisans İptal Edildi",  classes: "border-bad/50 bg-bad/10 text-bad" },
    pending_activation: { label: "Lisans Bekliyor",      classes: "border-warn/50 bg-warn/10 text-warn" },
  };

  function renderLicenseBadge() {
    const badge = el["license-badge"];
    if (!badge) return;

    const state_ = state.license;
    if (!state_) { badge.hidden = true; return; }

    const spec = LICENSE_BADGES[state_.status] || LICENSE_BADGES.pending_activation;
    let label = spec.label;
    // An operator wants the number; an admin has none to want.
    if (state_.status === "active" && typeof state_.days_remaining === "number") {
      label = `Lisanslı (${Math.max(0, Math.ceil(state_.days_remaining))} gün kaldı)`;
    }

    badge.hidden = false;
    badge.textContent = label;
    badge.className =
      `rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider transition ${spec.classes}`;
    // An admin has nothing to enter, so the badge is inert for them. For an
    // operator it is the way into the activation dialog, whatever the state --
    // including "active", so they can see when it runs out.
    badge.disabled = Boolean(state_.unlimited);
    badge.title = state_.unlimited
      ? state_.detail
      : (state_.valid ? "Lisans durumu" : "Lisans anahtarı girin");
  }

  /** The caller's *own* licence, for the navbar badge.
   *
   *  Named apart from `refreshLicense`, which polls the deployment licence
   *  that gates the whole installation. Two different licences at two
   *  different scopes; sharing a name here would silently shadow one of them. */
  async function refreshUserLicense() {
    try {
      state.license = await api("/api/license/me");
    } catch (_) {
      state.license = null;  // a server too old to know the endpoint
    }
    renderLicenseBadge();
  }

  function openLicense() {
    openModal("modal-license");
    el["license-key"].value = "";
    modalStatus(el["license-status"], "");

    const node = el["license-state"];
    const current = state.license;
    if (node) {
      node.textContent = current
        ? current.detail || current.status
        : "Lisans durumu okunamadı.";
      node.className =
        "rounded-lg border border-line bg-void px-3 py-2.5 text-sm " +
        (current && current.valid ? TEXT_CLASSES.ok : TEXT_CLASSES.warn);
    }
  }

  async function activateLicense(event) {
    event.preventDefault();
    const key = el["license-key"].value.trim();
    if (!key) return;

    el["license-submit"].disabled = true;
    modalStatus(el["license-status"], "Etkinleştiriliyor...", "muted");
    try {
      state.license = await api("/api/license/activate", {
        method: "POST",
        body: JSON.stringify({ key }),
      });
      state.licensePrompted = false;
      renderLicenseBadge();
      modalStatus(el["license-status"], "Lisans etkinleştirildi.", "ok");
      updateControls();
    } catch (err) {
      modalStatus(el["license-status"], err.message, "bad");
    } finally {
      el["license-submit"].disabled = false;
    }
  }

  // -----------------------------------------------------------------------
  // User management (admin only)
  // -----------------------------------------------------------------------

  const ROLE_CHIPS = {
    admin:    { label: "Yönetici", classes: "border-purple-400/50 bg-purple-400/10 text-purple-300" },
    operator: { label: "Operatör", classes: "border-teal-400/50 bg-teal-400/10 text-teal-300" },
  };

  function roleChip(role) {
    const spec = ROLE_CHIPS[role] || ROLE_CHIPS.operator;
    const chip = document.createElement("span");
    chip.className =
      `inline-block rounded-full border px-2.5 py-0.5 text-xs font-bold ${spec.classes}`;
    chip.textContent = spec.label;
    return chip;
  }

  /** Minutes -> "8 saat" / "1 gün"; blank falls back to the role's policy. */
  function formatSession(minutes, role) {
    if (!minutes) {
      return role === "admin" ? "365 gün (rol)" : "8 saat (rol)";
    }
    if (minutes % 1440 === 0) return `${minutes / 1440} gün`;
    if (minutes % 60 === 0) return `${minutes / 60} saat`;
    return `${minutes} dk`;
  }

  /** `2026-08-27T09:14:02+00:00` -> `27.08.2026`. */
  function formatDate(value) {
    if (!value) return "—";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value);
    const pad = (n) => String(n).padStart(2, "0");
    return `${pad(parsed.getDate())}.${pad(parsed.getMonth() + 1)}.${parsed.getFullYear()}`;
  }

  function renderUsers(rows) {
    const body = el["user-rows"];
    body.textContent = "";

    rows.forEach((row) => {
      const username = String(row.username || "");
      const role = String(row.role || "operator");
      const isSelf = username === state.username;

      const tr = document.createElement("tr");
      tr.className = "text-sm";

      const name = document.createElement("td");
      name.className = "px-4 py-2.5 font-semibold text-ink sm:px-6";
      name.textContent = username;
      if (isSelf) {
        const you = document.createElement("span");
        you.className = "ml-2 text-xs font-normal text-muted";
        you.textContent = "(siz)";
        name.append(you);
      }

      const roleCell = document.createElement("td");
      roleCell.className = "px-3 py-2.5";
      roleCell.append(roleChip(role));

      const session = document.createElement("td");
      session.className = "px-3 py-2.5 font-mono text-xs text-muted";
      session.textContent = formatSession(row.token_ttl_min, role);

      const license = document.createElement("td");
      license.className = "px-3 py-2.5";
      license.append(licenseCell(row, role));

      const actions = document.createElement("td");
      actions.className = "whitespace-nowrap px-4 py-2.5 text-right sm:px-6";

      // Admins are exempt, so there is nothing to issue or revoke for them.
      if (role !== "admin") {
        const generate = document.createElement("button");
        generate.type = "button";
        generate.className =
          "mr-1.5 rounded-md border border-accent/50 px-2.5 py-1 text-xs font-bold text-accent " +
          "transition hover:bg-accent hover:text-ground";
        generate.textContent = "Lisans Üret";
        generate.dataset.username = username;
        generate.dataset.licenseAction = "generate";
        // The row's own licence span, carried on the button so the delegated
        // click handler can pre-fill with it instead of the shared dropdown.
        if (row.license_duration_days) {
          generate.dataset.licenseDurationDays = String(row.license_duration_days);
        }
        actions.append(generate);

        if (row.license_key) {
          const revoke = document.createElement("button");
          revoke.type = "button";
          revoke.className =
            "mr-1.5 rounded-md border border-warn/50 px-2.5 py-1 text-xs font-bold text-warn " +
            "transition hover:bg-warn hover:text-ground";
          revoke.textContent = "İptal";
          revoke.dataset.username = username;
          revoke.dataset.licenseAction = "revoke";
          actions.append(revoke);
        }
      }

      const remove = document.createElement("button");
      remove.type = "button";
      remove.className =
        "rounded-md border border-bad/50 px-2.5 py-1 text-xs font-bold text-bad transition " +
        "hover:bg-bad hover:text-white disabled:cursor-not-allowed disabled:opacity-40";
      remove.textContent = "Sil";
      remove.dataset.username = username;
      // Deleting yourself would invalidate the token making the request, so
      // the server refuses it. Say so here rather than collecting a 400.
      if (isSelf) {
        remove.disabled = true;
        remove.title = "Kendi hesabınızı silemezsiniz";
      }
      actions.append(remove);

      tr.append(name, roleCell, session, license, actions);
      body.append(tr);
    });

    el["users-empty"].hidden = rows.length > 0;
    setText(el["users-count"], String(rows.length));
  }

  /** Licence state for one row, with the key exposed for copying. */
  function licenseCell(row, role) {
    const wrap = document.createElement("div");
    const status = String(
      row.license_status || (role === "admin" ? "unlimited" : "pending_activation")
    );
    const spec = LICENSE_BADGES[status] || LICENSE_BADGES.pending_activation;

    const badge = document.createElement("span");
    badge.className =
      `inline-block rounded-full border px-2.5 py-0.5 text-xs font-bold ${spec.classes}`;
    badge.textContent = role === "admin" ? "Sınırsız" : spec.label;
    wrap.append(badge);

    if (role !== "admin" && row.license_expires_at) {
      const until = document.createElement("div");
      until.className = "mt-0.5 font-mono text-[11px] text-muted";
      until.textContent = formatDate(row.license_expires_at);
      wrap.append(until);
    }
    // The key is what the admin has to hand over; the title makes it
    // selectable without widening the column.
    if (row.license_key) wrap.title = row.license_key;
    return wrap;
  }

  /** The panel-wide default validity, in days. */
  function selectedLicenseDays() {
    const choice = el["license-days"] ? el["license-days"].value : "365";
    if (choice !== "custom") return Number(choice) || 365;
    const custom = Number(el["license-days-custom"] && el["license-days-custom"].value);
    return Number.isFinite(custom) && custom > 0 ? Math.min(3650, custom) : 365;
  }

  /**
   * The validity to offer for one operator, in days.
   *
   * A re-issue defaults to the span that operator already had, so replacing a
   * lost 30-day key does not quietly promote them to a year. Only a first
   * issue falls back to the panel's dropdown, which is the admin stating a
   * default for accounts that have no history to inherit.
   */
  function defaultLicenseDaysFor(row) {
    const previous = Number(row && row.license_duration_days);
    if (Number.isFinite(previous) && previous > 0) return Math.min(3650, previous);
    return selectedLicenseDays();
  }

  /**
   * Confirm the validity for this specific operator.
   *
   * Returns the agreed number of days, or null if the admin cancelled.
   *
   * The dropdown above the table is one control shared by every row, so
   * clicking "Lisans Üret" used to issue whatever it happened to say --
   * "1 yıl" unless somebody had changed it -- with nothing on screen tying
   * that number to the row being clicked. Naming the operator and their span
   * in the prompt is what makes the two agree.
   */
  function confirmLicenseDays(username, row) {
    const suggested = defaultLicenseDaysFor(row);
    const answer = window.prompt(
      `${username} için lisans süresi (gün):`,
      String(suggested)
    );
    if (answer === null) return null;  // cancelled
    const days = Number(String(answer).trim());
    if (!Number.isFinite(days) || days < 1) {
      modalStatus(el["users-status"], "Geçersiz gün sayısı.", "bad");
      return null;
    }
    return Math.min(3650, Math.floor(days));
  }

  async function generateLicense(username, row) {
    const days = confirmLicenseDays(username, row);
    if (days === null) return;

    modalStatus(el["users-status"], `${username} için lisans üretiliyor...`, "muted");
    try {
      const issued = await api(`/api/users/${encodeURIComponent(username)}/license`, {
        method: "POST",
        body: JSON.stringify({ days }),
      });
      await loadUsers();
      modalStatus(
        el["users-status"],
        `${username}: ${days} günlük anahtar üretildi. ` +
        "Süre, operatör anahtarı girdiğinde başlar.",
        "ok"
      );
      // Shown rather than silently stored: the admin has to pass it on, and a
      // prompt is the one place a key can be selected and copied reliably.
      window.prompt(`${username} için lisans anahtarı:`, issued.key || "");
    } catch (err) {
      modalStatus(el["users-status"], err.message, "bad");
    }
  }

  async function revokeLicense(username) {
    if (!window.confirm(`${username} kullanıcısının lisansı iptal edilecek.\n\nDevam edilsin mi?`)) {
      return;
    }
    modalStatus(el["users-status"], "İptal ediliyor...", "muted");
    try {
      await api(`/api/users/${encodeURIComponent(username)}/license`, { method: "DELETE" });
      await loadUsers();
      modalStatus(el["users-status"], `${username} lisansı iptal edildi.`, "warn");
    } catch (err) {
      modalStatus(el["users-status"], err.message, "bad");
    }
  }

  async function loadUsers() {
    modalStatus(el["users-status"], "Yükleniyor...", "muted");
    try {
      renderUsers(await api("/api/users"));
      modalStatus(el["users-status"], "");
    } catch (err) {
      modalStatus(el["users-status"], err.message, "bad");
    }
  }

  async function addUser(event) {
    event.preventDefault();
    const username = el["user-name"].value.trim();
    const password = el["user-password"].value;
    if (!username || !password) return;

    const body = { username, password, role: el["user-role"].value };
    const ttl = Number(el["user-ttl"].value);
    if (Number.isFinite(ttl) && ttl > 0) body.token_ttl_min = ttl;

    el["user-add"].disabled = true;
    modalStatus(el["users-status"], "Ekleniyor...", "muted");
    try {
      const created = await api("/api/users", { method: "POST", body: JSON.stringify(body) });
      el["user-form"].reset();
      await loadUsers();
      modalStatus(el["users-status"], `${created.username} eklendi.`, "ok");
    } catch (err) {
      modalStatus(el["users-status"], err.message, "bad");
    } finally {
      el["user-add"].disabled = false;
      el["user-name"].focus();
    }
  }

  async function removeUser(username) {
    if (!window.confirm(`${username} kullanıcısı silinecek.\n\nDevam edilsin mi?`)) return;

    modalStatus(el["users-status"], "Siliniyor...", "muted");
    try {
      await api(`/api/users/${encodeURIComponent(username)}`, { method: "DELETE" });
      await loadUsers();
      modalStatus(el["users-status"], `${username} silindi.`, "ok");
    } catch (err) {
      modalStatus(el["users-status"], err.message, "bad");
    }
  }

  function openUsers() {
    openModal("modal-users");
    el["user-form"].reset();
    loadUsers();
  }

  // -----------------------------------------------------------------------
  // Session
  // -----------------------------------------------------------------------

  /** Show or hide the bootstrap "Kaydol" button.
   *
   *  Public registration only ever applies to the *first* account on a fresh
   *  installation — after that `POST /api/auth/register` requires an admin
   *  token. Leaving the button on screen advertises an action that can only
   *  fail, and reads like an open sign-up on a gate controller. `/health` is
   *  unauthenticated and reports `setup_required`, which is exactly this
   *  question. */
  async function applySetupState() {
    const button = el["login-register"];
    if (!button) return;

    // Hidden until proven otherwise: a fresh install shows it, and a server
    // that cannot answer should not be advertising registration.
    button.hidden = true;
    const hint = el["login-hint"];
    if (hint) hint.hidden = true;

    try {
      const health = await (await fetch("/health")).json();
      if (!health || !health.setup_required) return;
    } catch (_) {
      return;  // unreachable server: offer sign-in only
    }

    button.hidden = false;
    if (hint) hint.hidden = false;
  }

  function showLogin(message) {
    el["login-screen"].hidden = false;
    applySetupState();
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
    refreshLicense();      // deployment licence -> the banner
    refreshUserLicense();  // this account's licence -> the navbar badge
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
    if (el["btn-users"]) el["btn-users"].addEventListener("click", openUsers);
    el["btn-settings"].addEventListener("click", openSettings);
    if (el["update-run"]) el["update-run"].addEventListener("click", runUpdate);
    if (el["update-check"]) el["update-check"].addEventListener("click", checkForUpdates);
    el["btn-logout"].addEventListener("click", () => logout(""));

    wireModal("modal-plates");
    wireModal("modal-history");
    wireModal("modal-license");
    wireModal("modal-users");
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
      if (!button || button.disabled) return;
      const plate = button.dataset.plate;
      if (button.dataset.action === "delete") removePlate(plate);
      else if (button.dataset.action === "block") setPlateBlocked(plate, true);
      else if (button.dataset.action === "unblock") setPlateBlocked(plate, false);
    });

    if (el["plate-search"]) el["plate-search"].addEventListener("input", refreshPlateTable);

    if (el["user-form"]) el["user-form"].addEventListener("submit", addUser);
    if (el["license-form"]) el["license-form"].addEventListener("submit", activateLicense);
    if (el["license-badge"]) el["license-badge"].addEventListener("click", openLicense);
    if (el["license-days"]) {
      el["license-days"].addEventListener("change", () => {
        el["license-days-custom"].hidden = el["license-days"].value !== "custom";
      });
    }
    if (el["user-rows"]) {
      el["user-rows"].addEventListener("click", (event) => {
        const button = event.target.closest("button[data-username]");
        if (!button || button.disabled) return;
        const who = button.dataset.username;
        if (button.dataset.licenseAction === "generate") {
          generateLicense(who, {
            license_duration_days: Number(button.dataset.licenseDurationDays) || 0,
          });
        } else if (button.dataset.licenseAction === "revoke") revokeLicense(who);
        else removeUser(who);
      });
    }

    el["history-refresh"].addEventListener("click", loadHistory);
    el["history-day"].addEventListener("change", loadHistory);
    el["history-camera"].addEventListener("change", loadHistory);
    el["history-csv"].addEventListener("click", downloadCsv);

    if (el["plate-import-file"]) el["plate-import-file"].addEventListener("change", importPlates);
    if (el["plate-export"]) el["plate-export"].addEventListener("click", exportPlates);

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
