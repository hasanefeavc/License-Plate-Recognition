"""Tests for the browser dashboard mount.

The web UI is static content and a *client* of the API, so what is worth
testing on the server side is narrow but load-bearing: that the files are
served, that mounting them did not shadow any API route, and that a build
without a ``web/`` directory still starts.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on invocation
    sys.path.insert(0, str(SRC))

from lpr.api.main import WEB_MOUNT_PATH, _resolve_web_dir, create_app  # noqa: E402

WEB_DIR = Path(__file__).resolve().parents[1] / "web"


def _registered_paths(app: Any) -> set[str]:
    """Every path the app can serve, HTTP and WebSocket alike.

    FastAPI wraps ``include_router`` results in ``_IncludedRouter`` rather
    than flattening them, and WebSocket routes never appear in the OpenAPI
    schema, so both have to be walked by hand.
    """
    found: set[str] = set()

    def walk(routes: Any) -> None:
        for route in routes or ():
            path = getattr(route, "path", None)
            if path:
                found.add(path)
            inner = getattr(route, "original_router", None)
            if inner is not None:
                walk(getattr(inner, "routes", ()))
            walk(getattr(route, "routes", ()) or ())

    walk(app.routes)
    return found


@pytest.fixture()
def web_client() -> TestClient:
    # No `with`: the real lifespan (pipeline, licence watchdog) must not run.
    return TestClient(create_app(), follow_redirects=False)


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------


def test_the_dashboard_is_served_at_the_web_mount(web_client: TestClient) -> None:
    response = web_client.get(f"{WEB_MOUNT_PATH}/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Plaka Tanıma Sistemi" in response.text


def test_the_javascript_is_served(web_client: TestClient) -> None:
    response = web_client.get(f"{WEB_MOUNT_PATH}/app.js")
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "/api/ws/events" in response.text


def test_root_redirects_to_the_dashboard(web_client: TestClient) -> None:
    response = web_client.get("/")
    assert response.status_code in (301, 302, 307, 308)
    assert response.headers["location"] == f"{WEB_MOUNT_PATH}/"


def test_a_missing_web_file_is_a_404_not_a_traceback(web_client: TestClient) -> None:
    assert web_client.get(f"{WEB_MOUNT_PATH}/nope.js").status_code == 404


# ---------------------------------------------------------------------------
# The mount must not shadow the API
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/health", "/docs", "/openapi.json", "/api/stats", "/api/plates", "/api/logs"],
)
def test_mounting_the_ui_does_not_shadow_the_api(web_client: TestClient, path: str) -> None:
    """Every one of these must still be handled by the API, not by StaticFiles.

    A 401 is a pass: it means the route matched and the auth dependency ran.
    A 404 would mean the static mount swallowed it.
    """
    response = web_client.get(path)
    assert response.status_code != 404, f"{path} was shadowed by the web mount"


def test_the_web_mount_is_registered_after_the_api_routers() -> None:
    """Starlette matches in registration order, which is what keeps /api safe."""
    app = create_app()
    paths = [getattr(route, "path", "") for route in app.routes]
    assert WEB_MOUNT_PATH in paths
    mount_index = paths.index(WEB_MOUNT_PATH)
    router_indexes = [
        i
        for i, route in enumerate(app.routes)
        if type(route).__name__ in {"_IncludedRouter", "APIRoute"}
        and getattr(route, "path", "") != "/"
    ]
    assert router_indexes, "no API routes found to compare against"
    assert max(router_indexes) < mount_index


# ---------------------------------------------------------------------------
# Degraded mode
# ---------------------------------------------------------------------------


def test_a_build_without_a_web_directory_still_starts(monkeypatch: Any) -> None:
    """Headless deployments must not fail to boot over a missing HTML file."""
    monkeypatch.setattr("lpr.api.main._resolve_web_dir", lambda _settings: None)
    app = create_app()
    assert app.state.web_dir is None
    assert WEB_MOUNT_PATH not in [getattr(r, "path", "") for r in app.routes]

    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get(f"{WEB_MOUNT_PATH}/").status_code == 404


def test_web_dir_resolves_from_the_repo_root_whatever_the_cwd(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """``uvicorn lpr.api.main:app`` must work from any working directory."""
    from lpr.config import AppConfig, Settings

    monkeypatch.chdir(tmp_path)  # nothing named "web" here
    settings = Settings(app=AppConfig(web_dir="web"))
    assert _resolve_web_dir(settings) == WEB_DIR.resolve()


def test_an_empty_web_dir_setting_disables_the_ui() -> None:
    from lpr.config import AppConfig, Settings

    assert _resolve_web_dir(Settings(app=AppConfig(web_dir=""))) is None


# ---------------------------------------------------------------------------
# The page and the API have to agree on names
# ---------------------------------------------------------------------------


def test_the_page_carries_the_element_ids_the_script_drives() -> None:
    """Every id app.js resolves in its `el` registry must exist in the page.

    The registry is a flat list of ids looked up once at boot, so a rename on
    one side and not the other is a silent `null` at the first click rather
    than an error anywhere near the mistake.
    """
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    registry = re.search(r"\]\.forEach\(\(id\) => \{ el\[id\] = \$\(id\); \}\);", script)
    assert registry, "could not find the element registry in app.js"
    block = script[: registry.start()]
    block = block[block.rindex("[") :]
    ids = set(re.findall(r'"([a-z0-9-]+)"', block))
    assert len(ids) > 25, f"registry parse looks wrong, found {len(ids)} ids"

    missing = sorted(i for i in ids if f'id="{i}"' not in html)
    assert not missing, f"ids used by app.js but absent from index.html: {missing}"


def test_the_modals_are_present_and_closable() -> None:
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    for modal in ("modal-plates", "modal-history", "modal-settings"):
        assert f'id="{modal}"' in html
        section = html[html.index(f'id="{modal}"') :]
        end = section.find("</div>\n\n<!--")
        section = section[: end if end != -1 else len(section)]
        assert "data-backdrop" in section, f"{modal} has no backdrop to click away"
        assert section.count("data-close") >= 2, f"{modal} needs both an X and a Kapat"
        assert 'role="dialog"' in section and 'aria-modal="true"' in section


def test_the_script_targets_endpoints_the_api_actually_exposes() -> None:
    """Catches a typo'd path before it becomes a 404 in somebody's browser."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    known = _registered_paths(create_app())

    for path in (
        "/api/auth/login",
        "/api/auth/me",
        "/api/stats",
        "/api/license",
        "/api/relay/trigger",
        "/api/pipeline/pause",
        "/api/pipeline/resume",
        "/api/plates",
        "/api/logs",
        "/api/logs/dates",
        "/api/parking",
        "/api/system/version",
        "/api/system/update",
        "/api/system/events",
        "/api/plates/import",
        "/api/plates/export",
        "/api/events/export",
        "/api/users",
        "/api/license/me",
        "/api/license/activate",
    ):
        assert path in script, f"{path} not referenced by app.js"
        assert path in known, f"{path} is not a real route"

    # Parameterised and websocket routes are matched by prefix.
    assert "/api/stream/" in script and "/api/stream/{camera}" in known
    assert "/api/ws/events" in script and "/api/ws/events" in known
    assert "/api/plates/${encodeURIComponent(plate)}" in script
    assert "/api/plates/{plate}" in known


def test_the_page_never_triggers_the_relay_from_an_event() -> None:
    """The gate opens itself in the pipeline.

    If this page also fired on a `granted` event, every open browser would add
    its own extra relay pulse for the same car. The manual endpoint must only
    ever be reached from the "Kapıyı Aç" click handler.
    """
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    callers = re.findall(r"[^\n]*\"/api/relay/trigger\"[^\n]*", script)
    assert len(callers) == 1, f"relay endpoint referenced {len(callers)} times"

    start = script.index("async function openGate()")
    end = script.index("async function togglePause()")
    assert "/api/relay/trigger" in script[start:end], "only openGate() may call it"


def test_the_csv_export_downloads_through_an_authenticated_fetch() -> None:
    """The download is the deliverable an operator hands to accounting.

    A plain ``<a href>`` cannot carry the bearer header, so the body is fetched
    and handed to a synthetic link. The object URL must also be revoked, or a
    long session leaks a blob per export.
    """
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function downloadFromApi") :]
    body = body[: body.index("\n  }\n")]

    assert "Authorization" in body, "the export endpoint is authenticated"
    assert "URL.createObjectURL" in body and "URL.revokeObjectURL" in script
    assert "link.download" in body


def test_the_history_export_asks_the_server_not_the_rendered_page() -> None:
    """`state.historyRows` is one page; an operator asking for a month wants it."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function downloadCsv") :]
    body = body[: body.index("\n  }\n")]

    assert "/api/events/export" in body
    assert "state.historyRows" not in body, "must not rebuild the CSV client-side"
    # The filters on screen have to reach the export, or the file is the wrong
    # range with the right name.
    assert "history-day" in body and "history-camera" in body


# ---------------------------------------------------------------------------
# System update panel
# ---------------------------------------------------------------------------


def test_the_update_panel_starts_hidden() -> None:
    """It is revealed only for an admin on a server with the feature enabled.

    Shipping it visible would offer every operator a button that can only ever
    come back 403, and every non-updatable deployment one that only 503s.
    """
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    section = html[html.index('id="update-section"') :][:200]
    assert "hidden" in section


def test_the_update_panel_is_gated_on_server_enablement_only() -> None:
    """Operators run OTA updates on this deployment, so the panel is not
    role-gated. It still respects the server's own switch: offering a button
    that can only ever 503 helps nobody."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function refreshUpdatePanel") :]
    body = body[: body.index("\n  }\n")]
    assert "update_enabled" in body
    assert 'state.role !== "admin"' not in body


def test_the_update_button_asks_for_confirmation_before_posting() -> None:
    """A mis-click must not rebuild a live gate."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function runUpdate") :]
    body = body[: body.index("\n  }\n")]

    confirm_at = body.index("window.confirm")
    post_at = body.index('"/api/system/update"')
    assert confirm_at < post_at, "the POST must come after the confirmation"
    assert "if (!confirmed) return;" in body


def test_the_update_button_shows_a_spinner_while_it_runs() -> None:
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert 'id="update-spinner"' in html
    assert "animate-spin" in html
    assert "setUpdateBusy" in script


def test_the_client_polls_for_the_restart_instead_of_awaiting_the_post() -> None:
    """The POST is 202; success can only be observed by the commit changing."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function pollForRestart") :]
    body = body[: body.index("\n  }\n")]
    assert "/api/system/version" in body
    assert "UPDATE_POLL_TIMEOUT_MS" in script, "the poll loop needs a deadline"
    # A connection error during the rebuild is expected, not fatal.
    assert "continue" in body


def test_the_update_panel_shows_the_nightly_audit_trail() -> None:
    """An admin should see whether 03:00 came and went without incident."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    assert 'id="update-history"' in html
    body = script[script.index("async function refreshUpdateHistory") :]
    body = body[: body.index("\n  }\n")]
    assert "source=ota" in body, "the trail must be filtered to OTA events"


def test_the_audit_trail_is_rendered_as_text_not_markup() -> None:
    """Event messages carry git and compose output; innerHTML would be an XSS."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function refreshUpdateHistory") :]
    body = body[: body.index("\n  }\n")]
    assert "innerHTML" not in body
    assert "textContent" in body


def test_the_panel_displays_the_version_but_tracks_the_commit() -> None:
    """The label and the identity are different fields and must stay separate.

    Showing `commit` was the original complaint (a raw hash reads as noise);
    tracking `version` would be worse, because tagging an already-deployed
    commit would then look like a completed update.
    """
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    body = script[script.index("function applyVersion") :]
    body = body[: body.index("\n  }\n")]
    assert "update-version" in body and "info.version" in body

    poll = script[script.index("async function pollForRestart") :]
    poll = poll[: poll.index("\n  }\n")]
    assert "info.commit" in poll, "restart detection must watch the commit hash"


# ---------------------------------------------------------------------------
# Manual gate control (sliding gate)
# ---------------------------------------------------------------------------


def test_the_gate_button_is_labelled_for_a_sliding_gate() -> None:
    """"Kapı" (gate), not "Bariyer" (barrier) -- this drives a sliding gate."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    start = html.index('id="btn-gate"')
    button = html[start : html.index("</button>", start)]
    assert "Kapıyı Aç" in button
    assert "Bariyeri Aç" not in html


def test_the_gate_button_goes_busy_before_the_request_is_sent() -> None:
    """The accidental double-press happens while the POST is still in flight.

    Waiting for the response to arrive before disabling the button would leave
    exactly the window this is meant to close.
    """
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function openGate") :]
    body = body[: body.index("\n  }\n")]

    assert body.index("setGateBusy(true)") < body.index('"/api/relay/trigger"')


def test_a_repeat_press_inside_the_busy_window_sends_nothing() -> None:
    """A second pulse mid-travel stops a step-by-step gate; it must not leave."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function openGate") :]
    body = body[: body.index("\n  }\n")]
    assert "if (state.gateBusyUntil > Date.now()) return;" in body


def test_a_failed_trigger_releases_the_button() -> None:
    """No pulse went out, so the gate is not moving and the wait is wrong."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function openGate") :]
    body = body[: body.index("\n  }\n")]
    catch = body[body.index("catch (err)") :]
    assert "setGateBusy(false)" in catch


def test_the_busy_window_covers_a_sliding_gate_cycle() -> None:
    """Client-side guard and server-side cooldown protect the same hardware."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    match = re.search(r"const GATE_BUSY_MS = (\d+);", script)
    assert match, "GATE_BUSY_MS not found"
    assert int(match.group(1)) >= 15000


def test_the_busy_state_counts_down_rather_than_freezing() -> None:
    """A dead button for 20 s reads as a bug; a countdown reads as a gate."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert 'id="gate-spinner"' in html
    assert 'id="btn-gate-label"' in html
    assert "Kapı Açılıyor" in script


# ---------------------------------------------------------------------------
# Plate management redesign
# ---------------------------------------------------------------------------


def test_the_add_form_carries_every_schema_v4_field() -> None:
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    for field_id in (
        "plate-input", "owner-input", "apartment-input",
        "note-input", "expires-input", "blocked-input",
    ):
        assert f'id="{field_id}"' in html, field_id


def test_the_expiry_field_is_a_real_date_picker() -> None:
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    start = html.index('id="expires-input"')
    assert 'type="date"' in html[start - 200 : start + 200]


def test_the_add_form_omits_blank_optional_fields() -> None:
    """`PlateIn` forbids extra keys, so a blank input must not be sent as null."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function addPlate") :]
    body = body[: body.index("\n  }\n")]
    assert "if (value) body[key] = value;" in body


def test_the_table_renders_all_four_status_badges() -> None:
    """Aktif / Engelli / Süresi Doldu / Misafir, each visually distinct."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    block = script[script.index("const PLATE_STATUS") :]
    block = block[: block.index("\n  };")]

    for status, label in (
        ("active", "Aktif"),
        ("blocked", "Kara Liste"),
        ("expired", "Süresi Doldu"),
        ("guest", "Misafir"),
    ):
        assert status in block and label in block

    for tone in ("text-ok", "text-bad", "text-warn", "text-accent"):
        assert tone in block, f"{tone} missing: the badges must be distinguishable"


def test_the_status_badge_comes_from_the_server() -> None:
    """A browser with a wrong clock must not contradict the gate's own ruling."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function renderPlates") :]
    body = body[: body.index("\n  }\n")]
    assert "record.status" in body
    assert "Date.now()" not in body, "expiry must not be recomputed client-side"


def test_a_plate_without_an_expiry_reads_as_open_ended() -> None:
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function formatExpiry") :]
    body = body[: body.index("\n  }\n")]
    assert "Süresiz" in body


def test_the_search_box_covers_every_visible_field() -> None:
    """Searching only the plate would be useless on a list sorted by plate."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert 'id="plate-search"' in html

    body = script[script.index("function filterPlates") :]
    body = body[: body.index("\n  }\n")]
    for field in ("plate", "owner", "apartment", "note"):
        assert f"record.{field}" in body, field


def test_the_search_ignores_plate_spacing() -> None:
    """The table shows "34 ABC 123"; nobody types the spaces to find it."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function filterPlates") :]
    body = body[: body.index("\n  }\n")]
    assert "replace(/\\s+/g" in body


def test_the_search_filters_locally_without_a_round_trip() -> None:
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function filterPlates") :]
    body = body[: body.index("\n  }\n")]
    assert "state.plateRecords" in body
    assert "api(" not in body, "a request per keystroke would be slower, not faster"


def test_the_block_toggle_sends_only_the_blocked_flag() -> None:
    """A full overwrite would blank the owner and expiry the toggle never saw."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function setPlateBlocked") :]
    body = body[: body.index("\n  }\n")]

    assert '"PATCH"' in body
    assert "JSON.stringify({ blocked })" in body
    for field in ("owner", "apartment", "note", "expires_at"):
        assert field not in body, f"{field} must not be part of a block toggle"


def test_deleting_a_plate_asks_first() -> None:
    """It is irreversible and sits next to a toggle that is not."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function removePlate") :]
    body = body[: body.index("\n  }\n")]
    assert body.index("window.confirm") < body.index('method: "DELETE"')


def test_row_actions_are_dispatched_by_name_not_position() -> None:
    """Three buttons share one delegated handler; position would be fragile."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    for action in ("delete", "block", "unblock"):
        assert f'=== "{action}"' in script


# ---------------------------------------------------------------------------
# Role gating
# ---------------------------------------------------------------------------


def test_plate_controls_are_open_to_operators() -> None:
    """Operators are the people at the barrier; plate CRUD is their job.

    The server gates these endpoints on a live licence rather than on the role,
    and an unlicensed operator gets a 402 and the licence dialog — being told
    why beats the control quietly vanishing.
    """
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function applyPlatePermissions") :]
    body = body[: body.index("\n  }\n")]

    assert 'state.role === "admin"' not in body
    assert 'el["plate-add"].disabled = false' in body
    assert "form.hidden = false" in body


def test_only_user_management_stays_admin_only() -> None:
    """The one restriction that survives the widening."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function updateControls") :]
    body = body[: body.index("\n  }\n")]
    assert 'el["btn-users"].hidden = !isAdmin' in body


def test_the_search_is_never_disabled() -> None:
    """It is a read control and belongs to everyone, licensed or not."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("const PLATE_FORM_INPUTS") :]
    body = body[: body.index("\n  }\n", body.index("function applyPlatePermissions"))]
    assert "plate-search" not in body


def test_the_settings_modal_is_open_to_operators() -> None:
    """Capacity is a fact about the car park, not a privileged setting, and the
    person who notices it is wrong is the one on the gate."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function openSettings") :]
    body = body[: body.index("\n  }\n")]
    assert 'el["capacity-input"].disabled = false' in body
    assert "quality-select" in body


def test_the_navbar_shows_the_role_as_a_badge() -> None:
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function renderUserBadge") :]
    body = body[: body.index("\n  }\n")]
    assert "Yönetici" in body and "Operatör" in body
    assert "state.username" in body


def test_the_session_is_restored_from_local_storage_and_verified() -> None:
    """A stored token is a claim; the server decides whether it is still good."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function restoreSession") :]
    body = body[: body.index("\n  }\n")]

    assert "localStorage.getItem(TOKEN_KEY)" in body
    assert "/api/auth/me" in body
    assert "localStorage.removeItem(TOKEN_KEY)" in body, "a rejected token must be cleared"


def test_the_login_form_takes_credentials_not_a_token() -> None:
    """Nobody should ever be asked to paste a JWT.

    Checked as "no input collects a token" rather than "the word token does not
    appear": the markup legitimately explains the bootstrap flow in a comment,
    and a substring search on prose is not the claim being made.
    """
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    form = html[html.index('id="login-form"') : html.index("</form>")]

    assert 'id="login-username"' in html
    assert 'id="login-password"' in html
    assert 'type="password"' in html

    inputs = re.findall(r"<input[^>]*>", form)
    assert inputs, "the login form should have inputs"
    for tag in inputs:
        assert "token" not in tag.lower(), f"an input collects a token: {tag}"


def test_the_owner_column_reads_as_a_name_with_the_flat_in_brackets() -> None:
    """`Ahmet Yılmaz (Daire 12)` — the name is what the eye scans for."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function formatResident") :]
    body = body[: body.index("\n  }\n")]

    assert "(${labelled})" in body
    assert "Daire ${flat}" in body, "a bare number should be labelled"
    # Either half can be missing: an operator adding a plate at the barrier
    # often has neither.
    assert 'if (!name && !flat) return "—";' in body
    assert "if (!flat) return name;" in body


def test_the_logout_button_is_labelled_for_the_operator() -> None:
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    button = html[html.index('id="btn-logout"') :]
    assert "Çıkış Yap" in button[: button.index("</button>")]


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------


def test_the_users_button_starts_hidden() -> None:
    """It is revealed only for an admin; every endpoint behind it is 403 to others."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    button = html[html.index('id="btn-users"') :]
    assert "hidden" in button[: button.index(">")]


def test_the_users_button_is_revealed_only_for_an_admin() -> None:
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function updateControls") :]
    body = body[: body.index("\n  }\n")]
    assert 'el["btn-users"].hidden = !isAdmin' in body


def test_the_role_chips_are_visually_distinct() -> None:
    """Purple for Yönetici, teal for Operatör — the brief's own vocabulary."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    block = script[script.index("const ROLE_CHIPS") :]
    block = block[: block.index("\n  };")]

    assert "Yönetici" in block and "purple" in block
    assert "Operatör" in block and "teal" in block


def test_the_user_table_shows_the_session_length() -> None:
    """The whole point of the role split is visible here or it is invisible."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert "OTURUM" in html
    body = script[script.index("function formatSession") :]
    body = body[: body.index("\n  }\n")]
    assert "365 gün" in body and "8 saat" in body, "a blank TTL must name the role default"


def test_the_add_user_form_offers_both_roles_and_a_session_choice() -> None:
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    form = html[html.index('id="user-form"') : html.index("</form>", html.index('id="user-form"'))]
    assert 'value="operator"' in form and 'value="admin"' in form
    assert 'id="user-ttl"' in form
    assert 'minlength="8"' in form, "the password floor the API enforces"


def test_deleting_a_user_asks_first() -> None:
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function removeUser") :]
    body = body[: body.index("\n  }\n")]
    assert body.index("window.confirm") < body.index('method: "DELETE"')


def test_the_delete_button_is_disabled_on_your_own_row() -> None:
    """The server refuses it; saying so beats collecting a 400."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function renderUsers") :]
    body = body[: body.index("\n  }\n")]
    assert "isSelf" in body and "remove.disabled = true" in body


def test_the_bootstrap_button_is_hidden_until_the_server_asks_for_setup() -> None:
    """Public registration applies to the first account only.

    Leaving the button up advertises an action that can only fail, and reads
    like open sign-up on a gate controller.
    """
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    button = html[html.index('id="login-register"') :]
    assert "hidden" in button[: button.index(">")]

    body = script[script.index("async function applySetupState") :]
    body = body[: body.index("\n  }\n")]
    assert "setup_required" in body and "/health" in body
    assert "button.hidden = true;" in body, "default to hidden, reveal on proof"


# ---------------------------------------------------------------------------
# Licensing UI
# ---------------------------------------------------------------------------


def test_the_licence_badge_names_every_state() -> None:
    """The vocabulary the brief specifies, verbatim."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    block = script[script.index("const LICENSE_BADGES") :]
    block = block[: block.index("\n  };")]

    assert "Yönetici (Sınırsız)" in block
    assert "Lisans Bekliyor" in block
    assert "Lisans Süresi Doldu" in block
    for status in ("active", "expired", "revoked", "pending_activation", "unlimited"):
        assert status in block


def test_an_active_operator_badge_counts_down() -> None:
    """`Lisanslı (XX gün kaldı)` — the number is the useful half."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function renderLicenseBadge") :]
    body = body[: body.index("\n  }\n")]
    assert "gün kaldı" in body and "days_remaining" in body


def test_the_badge_shows_remaining_days_for_an_operator() -> None:
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function renderLicenseBadge") :]
    body = body[: body.index("\n  }\n")]
    assert "days_remaining" in body and "gün" in body


def test_a_402_opens_the_licence_dialog() -> None:
    """402 means "your licence lapsed" — distinct from 403, which offers nothing."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function api(") :]
    body = body[: body.index("\n  }\n")]
    assert "response.status === 402" in body
    assert "onLicenseLapsed" in body


def test_the_dialog_is_offered_once_per_lapse() -> None:
    """A burst of failing polls must not stack dialogs."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function onLicenseLapsed") :]
    body = body[: body.index("\n  }\n")]
    assert "state.licensePrompted" in body


def test_the_admin_table_offers_generation_and_revocation() -> None:
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function renderUsers") :]
    body = body[: body.index("\n  }\n")]
    assert "Lisans Üret" in body and "İptal" in body
    # An admin needs no key, so offering to issue one would be misleading.
    assert 'role !== "admin"' in body


def test_the_generated_key_is_shown_to_the_admin() -> None:
    """It has to be handed to the operator; storing it silently helps nobody."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function generateLicense") :]
    body = body[: body.index("\n  }\n")]
    assert "window.prompt" in body and "issued.key" in body


def test_the_validity_choices_include_the_documented_spans() -> None:
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    block = html[html.index('id="license-days"') :]
    block = block[: block.index("</select>")]
    for days in ("30", "90", "365"):
        assert f'value="{days}"' in block
    assert 'value="custom"' in block


def test_the_two_licence_refreshers_do_not_share_a_name() -> None:
    """One polls the deployment licence, one the caller's own.

    They are different licences at different scopes; a shared name would make
    the later definition silently shadow the earlier one.
    """
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert "async function refreshLicense()" in script
    assert "async function refreshUserLicense()" in script
    assert "refreshUserLicense();" in script


def test_the_deployment_licence_ticker_is_gone_from_the_header() -> None:
    """The header shows the *user's* licence, not the installation's.

    The old ticker described an enforcement that no longer happens: the
    deployment licence neither halts the pipeline nor refuses the gate.
    """
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")

    assert 'id="license-label"' not in html
    assert '"license-label"' not in script, "the element registry must not name it either"


def test_the_deployment_licence_no_longer_raises_a_banner() -> None:
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("function applyLicense") :]
    body = body[: body.index("\n  }\n")]
    assert "setBanner" not in body
    assert "görüntü işleme durduruldu" not in body


def test_the_header_badge_reads_the_users_own_licence() -> None:
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function refreshUserLicense") :]
    body = body[: body.index("\n  }\n")]
    assert "/api/license/me" in body


def test_the_admin_modal_says_the_countdown_starts_at_activation() -> None:
    """The admin needs to know the key is not burning while it sits in an email."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function generateLicense") :]
    body = body[: body.index("\n  }\n")]
    assert "operatör anahtarı girdiğinde başlar" in body
