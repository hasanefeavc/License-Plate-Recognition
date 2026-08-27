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


def test_the_csv_export_names_the_file_and_sets_a_csv_mime_type() -> None:
    """The download is the deliverable an operator hands to accounting."""
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    assert 'CSV_FILENAME = "otopark_gecmis.csv"' in script
    assert "text/csv;charset=utf-8;" in script
    assert "URL.createObjectURL" in script and "URL.revokeObjectURL" in script
    assert "link.download = CSV_FILENAME" in script


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


def test_the_update_panel_is_gated_on_admin_and_enablement() -> None:
    script = (WEB_DIR / "app.js").read_text(encoding="utf-8")
    body = script[script.index("async function refreshUpdatePanel") :]
    body = body[: body.index("\n  }\n")]
    assert 'state.role !== "admin"' in body, "the panel must be admin-gated client-side"
    assert "update_enabled" in body, "the panel must respect the server's switch"


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
