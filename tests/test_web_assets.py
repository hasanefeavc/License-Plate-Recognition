"""The dashboard must be fully styled with no network access.

The page used to pull https://cdn.tailwindcss.com at load time. On a gate box
-- which normally has no route to the internet -- the script did not load, and
the operator got unstyled HTML with a warning banner explaining why. These
tests pin the replacement: a stylesheet generated from the markup, committed,
and served from the same mount as the rest of the UI.

Three things have to stay true, and each fails silently in a browser nobody is
watching, which is why they are asserted here instead:

* nothing in ``web/`` reaches out to a remote host;
* the committed stylesheet matches what the generator produces from the
  current markup (otherwise a new class ships with no rule behind it);
* the API actually serves it at the path the page asks for.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:  # pragma: no cover - depends on invocation
    sys.path.insert(0, str(SRC))

from lpr.api.main import WEB_MOUNT_PATH, create_app  # noqa: E402

WEB_DIR = ROOT / "web"
STYLESHEET = WEB_DIR / "static" / "css" / "app.css"
BUILDER = ROOT / "scripts" / "build_web_css.py"


def load_builder() -> Any:
    """Import ``scripts/build_web_css.py`` by path -- scripts/ is not a package."""
    spec = importlib.util.spec_from_file_location("build_web_css", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def web_client() -> TestClient:
    # No `with`: the real lifespan (pipeline, licence watchdog) must not run.
    return TestClient(create_app(), follow_redirects=False)


# ---------------------------------------------------------------------------
# Offline
# ---------------------------------------------------------------------------

#: A URL in an ``href``/``src``/``@import``/``fetch`` -- i.e. something the
#: browser would actually request. A URL inside a comment is documentation.
_REMOTE_REFERENCE = re.compile(
    r"""(?:href|src)\s*=\s*["']https?://|@import\s+(?:url\()?["']?https?://""",
    re.IGNORECASE,
)


@pytest.mark.parametrize("name", ["index.html", "app.js", "static/css/app.css"])
def test_the_dashboard_requests_nothing_from_a_remote_host(name: str) -> None:
    text = (WEB_DIR / name).read_text(encoding="utf-8")
    found = _REMOTE_REFERENCE.findall(text)
    assert not found, (
        f"web/{name} loads a remote asset ({found}); the dashboard has to render "
        "completely on a site with no internet access"
    )


def test_the_tailwind_cdn_script_is_gone() -> None:
    """The specific regression: a <script> tag that silently no-ops offline."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert '<script src="https://cdn.tailwindcss.com">' not in html
    assert 'href="static/css/app.css"' in html, "the local bundle must be linked"


def test_no_webfont_is_pulled_in() -> None:
    """Fonts are OS stacks; an @font-face would mean a file to ship or fetch."""
    css = STYLESHEET.read_text(encoding="utf-8")
    assert "@font-face" not in css
    assert "fonts.googleapis.com" not in css and "fonts.gstatic.com" not in css


# ---------------------------------------------------------------------------
# The generated stylesheet
# ---------------------------------------------------------------------------


def test_the_committed_stylesheet_is_current() -> None:
    """Regenerate with `python scripts/build_web_css.py` (or `make css`)."""
    expected, _ = load_builder().build(ROOT)
    assert STYLESHEET.read_text(encoding="utf-8") == expected, (
        "web/static/css/app.css is stale -- run `make css`"
    )


def test_every_class_the_markup_declares_has_a_rule() -> None:
    """A class with no rule is a silently unstyled element in the browser."""
    builder = load_builder()
    _, unknown = builder.build(ROOT)
    assert not unknown, f"no CSS rule is generated for: {unknown}"


def test_the_preflight_border_reset_survives() -> None:
    """`border` sets a width only; without the reset a card draws no line.

    Tailwind's preflight is what makes that work, and it is the one part of the
    reset whose absence looks like a design change rather than a bug.
    """
    css = STYLESHEET.read_text(encoding="utf-8")
    assert "border-width: 0;" in css and "border-style: solid;" in css


def test_the_runtime_colours_app_js_builds_are_compiled() -> None:
    """app.js assembles class names from constants at runtime.

    A generator that only read ``class="..."`` attributes would miss every one
    of these, and the feed would render its event stripes with no colour.
    """
    css = STYLESHEET.read_text(encoding="utf-8")
    for name in (
        ".text-ok",
        ".text-bad",
        ".text-warn",
        ".text-accent",
        ".text-muted",
        ".border-ok",
        ".border-bad",
        ".border-warn",
        ".border-accent",
    ):
        assert f"{name} {{" in css, f"{name} is applied by app.js but has no rule"


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------


def test_the_stylesheet_is_served_from_the_web_mount(web_client: TestClient) -> None:
    response = web_client.get(f"{WEB_MOUNT_PATH}/static/css/app.css")
    assert response.status_code == 200
    assert "css" in response.headers["content-type"]
    assert "--lpr-css" in response.text


def test_the_page_and_the_stylesheet_agree_on_the_path(web_client: TestClient) -> None:
    """The href is relative, so it must resolve under whatever mount is used."""
    page = web_client.get(f"{WEB_MOUNT_PATH}/")
    assert page.status_code == 200
    match = re.search(r'<link rel="stylesheet" href="([^"]+)"', page.text)
    assert match, "no stylesheet link in the page"
    href = match.group(1)
    assert not href.startswith(("/", "http")), "an absolute href breaks under a sub-path mount"
    assert web_client.get(f"{WEB_MOUNT_PATH}/{href}").status_code == 200


# ---------------------------------------------------------------------------
# Camera aspect ratio
# ---------------------------------------------------------------------------


def test_the_camera_image_letterboxes_rather_than_stretching() -> None:
    """`object-fit: contain` must survive the compile, not just the markup.

    This regressed once and was invisible from the markup: a rule inserted
    directly above `_object_fit` landed *between* its `@rule` decorator and its
    body, so the decorator registered the wrong function and every `object-*`
    class compiled to `appearance: none`. The class was still in the HTML, the
    stylesheet still had a `.object-contain` line, and nothing looked wrong
    except the video -- an <img> with no `object-fit` falls back to `fill`,
    which distorts a 4:3 sensor into a 16:9 card silently.
    """
    css = STYLESHEET.read_text(encoding="utf-8")
    assert ".object-contain { object-fit: contain; }" in css


@pytest.mark.parametrize(
    ("utility", "declaration"),
    [
        ("object-contain", "object-fit: contain"),
        ("object-cover", "object-fit: cover"),
        ("appearance-none", "-webkit-appearance: none; appearance: none"),
        ("h-full", "height: 100%"),
        ("w-full", "width: 100%"),
        ("aspect-video", "aspect-ratio: 16 / 9"),
    ],
)
def test_a_utility_compiles_to_what_it_says(utility: str, declaration: str) -> None:
    """Spot checks on the utilities the camera panes are built from."""
    compiled = load_builder().compile_class(utility)
    assert compiled is not None, f"{utility} has no rule"
    assert compiled[0] == declaration


def test_no_two_rule_decorators_share_one_builder() -> None:
    """The structural form of the bug above, caught for any future insertion.

    Stacking `@rule` decorators is never intended here -- each pattern has its
    own builder -- so two adjacent ones mean a function was inserted between a
    decorator and the body it was written for, and one builder is now silently
    dead code registered under someone else's pattern.
    """
    source = BUILDER.read_text(encoding="utf-8").splitlines()
    stacked = [
        (index + 1, line.strip())
        for index, line in enumerate(source[:-1])
        if line.startswith("@rule(") and source[index + 1].startswith("@rule(")
    ]
    assert not stacked, f"stacked @rule decorators at {stacked}"


def test_the_camera_panes_ask_for_contain() -> None:
    """Both feeds, so a fix to one cannot quietly miss the other."""
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    for camera in ("cam-entry", "cam-exit"):
        tag = html[html.index(f'id="{camera}"') :]
        tag = tag[: tag.index(">")]
        assert "object-contain" in tag, f"{camera} would stretch its frame"
