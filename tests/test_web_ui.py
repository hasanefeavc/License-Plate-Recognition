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
    ever be reached from the "Bariyeri Aç" click handler.
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
