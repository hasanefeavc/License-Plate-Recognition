#!/usr/bin/env python3
"""Compile web/static/css/app.css from the classes the dashboard actually uses.

The dashboard used to pull https://cdn.tailwindcss.com at load time. On a gate
box with no internet -- which is most of them -- the script silently failed and
the operator got unstyled HTML. This script replaces that runtime dependency
with a build-time one: it scans ``web/*.html`` and ``web/*.js`` for utility
class names, compiles each one against the rule table below, and writes a
self-contained stylesheet.

It is deliberately *not* a Tailwind installation. Tailwind's own CLI needs
Node, a network install and a lockfile, none of which belong in a Python
project that ships to an offline site; and the dashboard uses about 300
utilities out of Tailwind's tens of thousands. What is here is a
Tailwind-compatible subset: same class names, same generated declarations, so
the markup does not change and anybody who knows Tailwind can read it.

Usage:
    python scripts/build_web_css.py            # write web/static/css/app.css
    python scripts/build_web_css.py --check    # fail if the file is stale
    python scripts/build_web_css.py --report   # list classes with no rule

Exit codes:
    0  the stylesheet is up to date (or was just written)
    1  --check found it stale, or a class in the markup has no rule
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable
from pathlib import Path

# ---------------------------------------------------------------------------
# Theme -- the palette that used to live in the inline `tailwind.config`
# ---------------------------------------------------------------------------

#: Named colours. Keep in sync with the ``:root`` custom properties emitted
#: into PREFLIGHT, which is what the hand-written rules in index.html read.
COLORS: dict[str, str] = {
    "ground": "#10141b",  # window surface
    "chrome": "#161c26",  # header / control panel
    "card": "#1a2029",  # card body
    "row": "#212936",  # one row inside a card
    "void": "#0a0d12",  # video area, no signal
    "line": "#2c3542",
    "ink": "#e8ecf3",
    "muted": "#78859a",
    "ok": "#2ecc71",
    "bad": "#ff5c5c",
    "warn": "#f0ad4e",
    "accent": "#4c9aff",
    # Straight from Tailwind's default palette, kept because the role chips in
    # app.js use them and nothing in the custom scale reads as "a role".
    "purple-300": "#d8b4fe",
    "purple-400": "#c084fc",
    "teal-300": "#5eead4",
    "teal-400": "#2dd4bf",
    "white": "#ffffff",
    "black": "#000000",
    "transparent": "transparent",
    "current": "currentColor",
}

FONT_SANS = "'Segoe UI', 'Helvetica Neue', Helvetica, Arial, sans-serif"
FONT_MONO = "Consolas, 'DejaVu Sans Mono', Menlo, monospace"

#: Tailwind's default border colour. Preflight applies it to every element,
#: which is what lets `border` on its own draw a visible line.
DEFAULT_BORDER_COLOR = COLORS["line"]

#: ``sm`` / ``md`` / ``lg`` breakpoints, in the order they must be emitted.
BREAKPOINTS: dict[str, str] = {"sm": "640px", "md": "768px", "lg": "1024px"}

#: Non-responsive variants, and how each one decorates a selector. Emitted
#: after the plain utilities and before the responsive blocks, which is the
#: order Tailwind itself uses and the reason `hover:` beats a bare colour.
STATE_VARIANTS: dict[str, Callable[[str], str]] = {
    "hover": lambda sel: f"{sel}:hover",
    "focus": lambda sel: f"{sel}:focus",
    "active": lambda sel: f"{sel}:active",
    "disabled": lambda sel: f"{sel}:disabled",
    "placeholder": lambda sel: f"{sel}::placeholder",
}

FONT_SIZES: dict[str, tuple[str, str]] = {
    "xs": ("0.75rem", "1rem"),
    "sm": ("0.875rem", "1.25rem"),
    "base": ("1rem", "1.5rem"),
    "lg": ("1.125rem", "1.75rem"),
    "xl": ("1.25rem", "1.75rem"),
    "2xl": ("1.5rem", "2rem"),
    "3xl": ("1.875rem", "2.25rem"),
    "4xl": ("2.25rem", "2.5rem"),
}

RADII: dict[str, str] = {
    "": "0.25rem",
    "none": "0",
    "sm": "0.125rem",
    "md": "0.375rem",
    "lg": "0.5rem",
    "xl": "0.75rem",
    "2xl": "1rem",
    "full": "9999px",
}

MAX_WIDTHS: dict[str, str] = {
    "none": "none",
    "xs": "20rem",
    "sm": "24rem",
    "md": "28rem",
    "lg": "32rem",
    "xl": "36rem",
    "2xl": "42rem",
    "3xl": "48rem",
    "4xl": "56rem",
    "full": "100%",
}

TRACKING: dict[str, str] = {
    "tighter": "-0.05em",
    "tight": "-0.025em",
    "normal": "0em",
    "wide": "0.025em",
    "wider": "0.05em",
    "widest": "0.1em",
}

LEADING: dict[str, str] = {
    "none": "1",
    "tight": "1.25",
    "snug": "1.375",
    "normal": "1.5",
    "relaxed": "1.625",
    "loose": "2",
}

FONT_WEIGHTS: dict[str, str] = {
    "thin": "100",
    "light": "300",
    "normal": "400",
    "medium": "500",
    "semibold": "600",
    "bold": "700",
    "extrabold": "800",
}


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------


def _arbitrary(value: str) -> str | None:
    """``[60vh]`` -> ``60vh``. Underscores become spaces, as in Tailwind."""
    if len(value) > 2 and value.startswith("[") and value.endswith("]"):
        return value[1:-1].replace("_", " ")
    return None


def spacing(value: str) -> str | None:
    """Tailwind's spacing scale: ``4`` -> ``1rem``, plus the named steps."""
    arbitrary = _arbitrary(value)
    if arbitrary is not None:
        return arbitrary
    if value == "px":
        return "1px"
    if value == "full":
        return "100%"
    if value == "auto":
        return "auto"
    if value == "none":
        return "none"
    if re.fullmatch(r"\d+/\d+", value):
        numerator, denominator = value.split("/")
        return f"{float(numerator) / float(denominator) * 100:.6g}%"
    if re.fullmatch(r"\d+(\.\d+)?", value):
        rem = float(value) * 0.25
        return "0px" if rem == 0 else f"{rem:.6g}rem"
    return None


def color(value: str) -> str | None:
    """``accent`` -> hex; ``ink/70`` -> ``rgb(r g b / 0.7)``; ``[#abc]`` -> raw."""
    arbitrary = _arbitrary(value)
    if arbitrary is not None:
        return arbitrary
    name, _, alpha = value.partition("/")
    base = COLORS.get(name)
    if base is None:
        return None
    if not alpha:
        return base
    if not re.fullmatch(r"\d{1,3}", alpha) or not base.startswith("#"):
        return None
    red, green, blue = (int(base[i : i + 2], 16) for i in (1, 3, 5))
    return f"rgb({red} {green} {blue} / {int(alpha) / 100:.6g})"


def _size(value: str) -> str | None:
    """Spacing scale plus the viewport/content keywords sizes accept."""
    if value in ("screen", "dvh"):
        return "100vh"
    if value in ("min", "max", "fit"):
        return f"{value}-content"
    return spacing(value)


# ---------------------------------------------------------------------------
# Rule table
# ---------------------------------------------------------------------------
#
# Each entry is (pattern, builder). The FIRST match wins, and the table order
# is also the emission order, so a utility that must override another simply
# sits below it -- same contract as Tailwind's layer ordering.

Decls = str | None
Rule = tuple[re.Pattern[str], Callable[[re.Match[str]], Decls]]
_RULES: list[Rule] = []


Builder = Callable[[re.Match[str]], Decls]


def rule(pattern: str) -> Callable[[Builder], Builder]:
    def register(fn: Builder) -> Builder:
        _RULES.append((re.compile(pattern + r"\Z"), fn))
        return fn

    return register


def _kv(**declarations: str | None) -> Decls:
    """Build a declaration block, or None when any value failed to resolve."""
    parts = []
    for name, value in declarations.items():
        if value is None:
            return None
        parts.append(f"{name.replace('_', '-')}: {value}")
    return "; ".join(parts)


# -- display / layout -------------------------------------------------------


@rule(r"(block|inline-block|inline|flex|inline-flex|grid|inline-grid|contents|table|hidden)")
def _display(m: re.Match[str]) -> Decls:
    token = m.group(1)
    return "display: none" if token == "hidden" else f"display: {token}"


@rule(r"(static|fixed|absolute|relative|sticky)")
def _position(m: re.Match[str]) -> Decls:
    return f"position: {m.group(1)}"


@rule(r"inset-(.+)")
def _inset(m: re.Match[str]) -> Decls:
    value = spacing(m.group(1))
    return _kv(top=value, right=value, bottom=value, left=value)


@rule(r"(top|right|bottom|left)-(.+)")
def _offset(m: re.Match[str]) -> Decls:
    return _kv(**{m.group(1): spacing(m.group(2))})


@rule(r"z-(.+)")
def _z(m: re.Match[str]) -> Decls:
    value = _arbitrary(m.group(1)) or (m.group(1) if m.group(1).isdigit() else None)
    return _kv(z_index=value)


@rule(r"(?:overflow)-(auto|hidden|visible|scroll)")
def _overflow(m: re.Match[str]) -> Decls:
    return f"overflow: {m.group(1)}"


@rule(r"overflow-(x|y)-(auto|hidden|visible|scroll)")
def _overflow_axis(m: re.Match[str]) -> Decls:
    return f"overflow-{m.group(1)}: {m.group(2)}"


@rule(r"aspect-(video|square|auto)")
def _aspect(m: re.Match[str]) -> Decls:
    return "aspect-ratio: " + {"video": "16 / 9", "square": "1 / 1", "auto": "auto"}[m.group(1)]


@rule(r"object-(contain|cover|fill|none|scale-down)")
def _object_fit(m: re.Match[str]) -> Decls:
    return f"object-fit: {m.group(1)}"


# -- flex / grid ------------------------------------------------------------


@rule(r"flex-(row|row-reverse|col|col-reverse)")
def _flex_direction(m: re.Match[str]) -> Decls:
    return "flex-direction: " + m.group(1).replace("col", "column")


@rule(r"flex-(wrap|nowrap|wrap-reverse)")
def _flex_wrap(m: re.Match[str]) -> Decls:
    return f"flex-wrap: {m.group(1)}"


@rule(r"flex-(1|auto|initial|none)")
def _flex(m: re.Match[str]) -> Decls:
    values = {"1": "1 1 0%", "auto": "1 1 auto", "initial": "0 1 auto", "none": "none"}
    return f"flex: {values[m.group(1)]}"


@rule(r"(?:flex-)?(?:shrink|grow)-?(0|1)?")
def _flex_grow_shrink(m: re.Match[str]) -> Decls:
    prop = "flex-shrink" if "shrink" in m.string else "flex-grow"
    return f"{prop}: {m.group(1) or '1'}"


@rule(r"items-(start|end|center|baseline|stretch)")
def _align_items(m: re.Match[str]) -> Decls:
    token = m.group(1)
    return "align-items: " + {"start": "flex-start", "end": "flex-end"}.get(token, token)


@rule(r"justify-(start|end|center|between|around|evenly)")
def _justify(m: re.Match[str]) -> Decls:
    token = m.group(1)
    mapped = {
        "start": "flex-start",
        "end": "flex-end",
        "between": "space-between",
        "around": "space-around",
        "evenly": "space-evenly",
    }.get(token, token)
    return f"justify-content: {mapped}"


@rule(r"order-(last|first|none|\d+)")
def _order(m: re.Match[str]) -> Decls:
    return "order: " + {"last": "9999", "first": "-9999", "none": "0"}.get(m.group(1), m.group(1))


@rule(r"grid-cols-(.+)")
def _grid_cols(m: re.Match[str]) -> Decls:
    value = m.group(1)
    arbitrary = _arbitrary(value)
    if arbitrary is not None:
        return f"grid-template-columns: {arbitrary}"
    if value == "none":
        return "grid-template-columns: none"
    if value.isdigit():
        return f"grid-template-columns: repeat({value}, minmax(0, 1fr))"
    return None


@rule(r"col-span-(\d+|full)")
def _col_span(m: re.Match[str]) -> Decls:
    value = m.group(1)
    return "grid-column: " + ("1 / -1" if value == "full" else f"span {value} / span {value}")


@rule(r"gap-(.+)")
def _gap(m: re.Match[str]) -> Decls:
    return _kv(gap=spacing(m.group(1)))


@rule(r"gap-(x|y)-(.+)")
def _gap_axis(m: re.Match[str]) -> Decls:
    prop = "column-gap" if m.group(1) == "x" else "row-gap"
    return _kv(**{prop.replace("-", "_"): spacing(m.group(2))})


# -- spacing ----------------------------------------------------------------

_SPACING_SIDES: dict[str, tuple[str, ...]] = {
    "": ("",),
    "x": ("-left", "-right"),
    "y": ("-top", "-bottom"),
    "t": ("-top",),
    "r": ("-right",),
    "b": ("-bottom",),
    "l": ("-left",),
}


@rule(r"(-?)(p|m)([xytrbl]?)-(.+)")
def _padding_margin(m: re.Match[str]) -> Decls:
    negative, kind, side, raw = m.groups()
    value = spacing(raw)
    if value is None or (negative and kind == "p"):
        return None
    if negative and value != "auto":
        value = f"-{value}"
    prop = "padding" if kind == "p" else "margin"
    return "; ".join(f"{prop}{suffix}: {value}" for suffix in _SPACING_SIDES[side])


@rule(r"space-(x|y)-(.+)")
def _space_between(m: re.Match[str]) -> Decls:
    """Margin on every child but the first -- Tailwind's `> * + *` form."""
    value = spacing(m.group(2))
    if value is None:
        return None
    prop = "margin-left" if m.group(1) == "x" else "margin-top"
    return f"@children {prop}: {value}"


# -- sizing -----------------------------------------------------------------


@rule(r"w-(.+)")
def _width(m: re.Match[str]) -> Decls:
    return _kv(width=_size(m.group(1)))


@rule(r"h-(.+)")
def _height(m: re.Match[str]) -> Decls:
    return _kv(height=_size(m.group(1)))


@rule(r"min-w-(.+)")
def _min_width(m: re.Match[str]) -> Decls:
    return _kv(min_width=_size(m.group(1)))


@rule(r"min-h-(.+)")
def _min_height(m: re.Match[str]) -> Decls:
    return _kv(min_height=_size(m.group(1)))


@rule(r"max-w-(.+)")
def _max_width(m: re.Match[str]) -> Decls:
    value = m.group(1)
    return _kv(max_width=_arbitrary(value) or MAX_WIDTHS.get(value) or _size(value))


@rule(r"max-h-(.+)")
def _max_height(m: re.Match[str]) -> Decls:
    return _kv(max_height=_size(m.group(1)))


# -- typography -------------------------------------------------------------


@rule(r"text-(left|center|right|justify)")
def _text_align(m: re.Match[str]) -> Decls:
    return f"text-align: {m.group(1)}"


@rule(r"text-(.+)")
def _text(m: re.Match[str]) -> Decls:
    value = m.group(1)
    if value in FONT_SIZES:
        size, line_height = FONT_SIZES[value]
        return f"font-size: {size}; line-height: {line_height}"
    arbitrary = _arbitrary(value)
    if arbitrary is not None and re.fullmatch(r"[\d.]+(px|rem|em|%)", arbitrary):
        return f"font-size: {arbitrary}"
    return _kv(color=color(value))


@rule(r"font-(sans|mono|serif)")
def _font_family(m: re.Match[str]) -> Decls:
    family = {"sans": FONT_SANS, "mono": FONT_MONO, "serif": "Georgia, 'Times New Roman', serif"}
    return f"font-family: {family[m.group(1)]}"


@rule(r"font-(.+)")
def _font_weight(m: re.Match[str]) -> Decls:
    return _kv(font_weight=FONT_WEIGHTS.get(m.group(1)))


@rule(r"leading-(.+)")
def _leading(m: re.Match[str]) -> Decls:
    value = m.group(1)
    return _kv(line_height=_arbitrary(value) or LEADING.get(value) or spacing(value))


@rule(r"tracking-(.+)")
def _tracking(m: re.Match[str]) -> Decls:
    value = m.group(1)
    return _kv(letter_spacing=_arbitrary(value) or TRACKING.get(value))


@rule(r"(uppercase|lowercase|capitalize|normal-case)")
def _text_transform(m: re.Match[str]) -> Decls:
    token = m.group(1)
    return "text-transform: " + ("none" if token == "normal-case" else token)


@rule(r"whitespace-(normal|nowrap|pre|pre-line|pre-wrap)")
def _whitespace(m: re.Match[str]) -> Decls:
    return f"white-space: {m.group(1)}"


@rule(r"truncate")
def _truncate(_: re.Match[str]) -> Decls:
    return "overflow: hidden; text-overflow: ellipsis; white-space: nowrap"


@rule(r"tabular-nums")
def _tabular(_: re.Match[str]) -> Decls:
    return "font-variant-numeric: tabular-nums"


@rule(r"antialiased")
def _antialiased(_: re.Match[str]) -> Decls:
    return "-webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale"


@rule(r"sr-only")
def _sr_only(_: re.Match[str]) -> Decls:
    return (
        "position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; "
        "overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border-width: 0"
    )


@rule(r"resize-(none|x|y)")
def _resize(m: re.Match[str]) -> Decls:
    return "resize: " + {"none": "none", "x": "horizontal", "y": "vertical"}[m.group(1)]


# -- backgrounds / borders --------------------------------------------------


@rule(r"bg-(.+)")
def _background(m: re.Match[str]) -> Decls:
    return _kv(background_color=color(m.group(1)))


@rule(r"accent-(.+)")
def _accent_color(m: re.Match[str]) -> Decls:
    return _kv(accent_color=color(m.group(1)))


@rule(r"rounded(?:-(t|r|b|l|tl|tr|br|bl))?(?:-(.+))?")
def _rounded(m: re.Match[str]) -> Decls:
    side, size = m.group(1), m.group(2) or ""
    radius = _arbitrary(size) or RADII.get(size)
    if radius is None:
        return None
    corners = {
        None: ("top-left", "top-right", "bottom-right", "bottom-left"),
        "t": ("top-left", "top-right"),
        "r": ("top-right", "bottom-right"),
        "b": ("bottom-right", "bottom-left"),
        "l": ("top-left", "bottom-left"),
        "tl": ("top-left",),
        "tr": ("top-right",),
        "br": ("bottom-right",),
        "bl": ("bottom-left",),
    }[side]
    return "; ".join(f"border-{corner}-radius: {radius}" for corner in corners)


@rule(r"border-collapse")
def _border_collapse(_: re.Match[str]) -> Decls:
    return "border-collapse: collapse"


@rule(r"border(?:-(x|y|t|r|b|l))?(?:-(\d+))?")
def _border_width(m: re.Match[str]) -> Decls:
    side, width = m.group(1), m.group(2)
    value = f"{width}px" if width else "1px"
    return "; ".join(f"border{suffix}-width: {value}" for suffix in _SPACING_SIDES[side or ""])


@rule(r"border-(x|y|t|r|b|l)-(\d+)")
def _border_width_side(m: re.Match[str]) -> Decls:
    return "; ".join(
        f"border{suffix}-width: {m.group(2)}px" for suffix in _SPACING_SIDES[m.group(1)]
    )


@rule(r"border-(?:(x|y|t|r|b|l)-)?(.+)")
def _border_color(m: re.Match[str]) -> Decls:
    resolved = color(m.group(2))
    if resolved is None:
        return None
    return "; ".join(
        f"border{suffix}-color: {resolved}" for suffix in _SPACING_SIDES[m.group(1) or ""]
    )


@rule(r"divide-y(?:-(\d+))?")
def _divide_y(m: re.Match[str]) -> Decls:
    width = m.group(1) or "1"
    return f"@children border-top-width: {width}px; border-bottom-width: 0"


@rule(r"divide-(.+)")
def _divide_color(m: re.Match[str]) -> Decls:
    resolved = color(m.group(1))
    return None if resolved is None else f"@children border-color: {resolved}"


@rule(r"outline-none")
def _outline_none(_: re.Match[str]) -> Decls:
    return "outline: 2px solid transparent; outline-offset: 2px"


# -- effects ----------------------------------------------------------------


@rule(r"shadow-(sm|md|lg|xl|2xl|none)?")
def _shadow(m: re.Match[str]) -> Decls:
    return (
        "box-shadow: "
        + {
            None: "0 1px 3px 0 rgb(0 0 0 / 0.5)",
            "sm": "0 1px 2px 0 rgb(0 0 0 / 0.4)",
            "md": "0 4px 6px -1px rgb(0 0 0 / 0.5)",
            "lg": "0 10px 15px -3px rgb(0 0 0 / 0.5)",
            "xl": "0 20px 25px -5px rgb(0 0 0 / 0.55)",
            "2xl": "0 25px 50px -12px rgb(0 0 0 / 0.7)",
            "none": "none",
        }[m.group(1)]
    )


@rule(r"opacity-(\d+)")
def _opacity(m: re.Match[str]) -> Decls:
    return f"opacity: {int(m.group(1)) / 100:.6g}"


@rule(r"brightness-(\d+)")
def _brightness(m: re.Match[str]) -> Decls:
    return f"filter: brightness({int(m.group(1)) / 100:.6g})"


@rule(r"backdrop-blur(?:-(sm|md|lg))?")
def _backdrop_blur(m: re.Match[str]) -> Decls:
    radius = {None: "8px", "sm": "4px", "md": "12px", "lg": "16px"}[m.group(1)]
    return f"-webkit-backdrop-filter: blur({radius}); backdrop-filter: blur({radius})"


@rule(r"transition(?:-(colors|opacity|transform|all|none))?")
def _transition(m: re.Match[str]) -> Decls:
    properties = {
        None: "color, background-color, border-color, text-decoration-color, fill, stroke, "
        "opacity, box-shadow, transform, filter, backdrop-filter",
        "colors": "color, background-color, border-color, text-decoration-color, fill, stroke",
        "opacity": "opacity",
        "transform": "transform",
        "all": "all",
        "none": "none",
    }[m.group(1)]
    if properties == "none":
        return "transition-property: none"
    return (
        f"transition-property: {properties}; "
        "transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1); "
        "transition-duration: 150ms"
    )


#: Every transform utility writes the same composed value, so translate and
#: scale on one element compose instead of overwriting each other -- the same
#: trick Tailwind uses, with one variable per axis.
_TRANSFORM = (
    "transform: translate(var(--tw-translate-x, 0), var(--tw-translate-y, 0)) "
    "scale(var(--tw-scale, 1))"
)


@rule(r"(-?)translate-(x|y)-(.+)")
def _translate(m: re.Match[str]) -> Decls:
    negative, axis, raw = m.groups()
    value = spacing(raw)
    if value is None:
        return None
    if negative:
        value = f"-{value}"
    var = f"--tw-translate-{axis}"
    return f"{var}: {value}; {_TRANSFORM}"


@rule(r"scale-(.+)")
def _scale(m: re.Match[str]) -> Decls:
    raw = m.group(1)
    arbitrary = _arbitrary(raw)
    if arbitrary is not None:
        value = arbitrary
    elif raw.isdigit():
        value = f"{int(raw) / 100:.6g}"
    else:
        value = None
    if value is None:
        return None
    return f"--tw-scale: {value}; {_TRANSFORM}"


@rule(r"animate-spin")
def _animate_spin(_: re.Match[str]) -> Decls:
    return "animation: lpr-spin 1s linear infinite"


@rule(r"cursor-(pointer|default|not-allowed|wait|text|move)")
def _cursor(m: re.Match[str]) -> Decls:
    return f"cursor: {m.group(1)}"


@rule(r"pointer-events-(none|auto)")
def _pointer_events(m: re.Match[str]) -> Decls:
    return f"pointer-events: {m.group(1)}"


@rule(r"select-(none|text|all|auto)")
def _user_select(m: re.Match[str]) -> Decls:
    return f"-webkit-user-select: {m.group(1)}; user-select: {m.group(1)}"


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------

#: Classes styled by hand in ``index.html`` (animations, scrollbars). They are
#: not utilities and must not be reported as missing.
HAND_WRITTEN = frozenset({"scroll-thin", "feed-in", "pulse-full"})

#: Characters a Tailwind class can contain. Anything else in a string literal
#: is not a class name and is discarded before the rule table ever sees it.
_CLASS_TOKEN = re.compile(r"[A-Za-z0-9_:/\[\]().,%#\-]+")


def escape_class(name: str) -> str:
    """CSS-escape a class name: ``sm:w-1/2`` -> ``.sm\\:w-1\\/2``."""
    return "." + re.sub(r"([:/\[\]().,%#])", r"\\\1", name)


def compile_class(name: str) -> tuple[str, int] | None:
    """``(declarations, rule_index)`` for one utility, or None if unknown."""
    for index, (pattern, builder) in enumerate(_RULES):
        match = pattern.match(name)
        if match is None:
            continue
        declarations = builder(match)
        if declarations is not None:
            return declarations, index
    return None


def split_variants(name: str) -> tuple[list[str], str]:
    """``sm:hover:bg-ok`` -> ``(["sm", "hover"], "bg-ok")``.

    Colons inside an arbitrary value (``lg:grid-cols-[a:b]``) are not variant
    separators, so the split stops at the first ``[``.
    """
    head, bracket, tail = name.partition("[")
    parts = head.split(":")
    utility = parts[-1] + bracket + tail
    return parts[:-1], utility


#: Places a class name is *declared* rather than merely mentioned. Anything
#: found here has to compile, because it is markup that will be rendered.
#: ``(pattern, already_unquoted)``. The HTML attribute patterns capture the
#: attribute *value*, so its words are class names directly; the JavaScript
#: ones capture an expression, whose class names are only the string literals
#: inside it -- ``el.className = TEXT_CLASSES.muted;`` names no class at all.
_CLASS_CONTEXTS: tuple[tuple[re.Pattern[str], bool], ...] = (
    (re.compile(r'\bclass\s*=\s*"([^"]*)"'), True),  # HTML attribute
    (re.compile(r"\bclass\s*=\s*'([^']*)'"), True),
    (re.compile(r"\bclassName\s*=\s*([^;]*);"), False),  # el.className = ...
    (re.compile(r"\bclassList\.(?:add|remove|toggle)\(([^)]*)\)"), False),
    (re.compile(r"\bclasses:\s*([^,}\n]*)"), False),  # { classes: "..." }
)

#: ``${...}`` inside a template literal is a value, not a class name.
_INTERPOLATION = re.compile(r"\$\{[^{}]*\}")


def _tokens_from(fragment: str, already_unquoted: bool) -> set[str]:
    """Split one class-context capture into candidate class names."""
    fragment = _INTERPOLATION.sub(" ", fragment)
    found: set[str] = set(fragment.split()) if already_unquoted else set()
    for literal in re.findall(r'"([^"\n]*)"|\'([^\'\n]*)\'|`([^`]*)`', fragment):
        for part in literal:
            found.update(part.split())
    return {token for token in found if _CLASS_TOKEN.fullmatch(token)}


def extract_classes(sources: list[Path]) -> tuple[set[str], set[str]]:
    """``(declared, incidental)`` class names found across the web sources.

    Two tiers, because the two failure modes are opposite. **Declared** names
    come from a class attribute, a ``className`` assignment, a ``classList``
    call or a ``classes:`` spec -- markup that will reach a browser, so a name
    with no rule is a bug and is reported. **Incidental** names come from every
    other string literal: ``app.js`` assembles class lists from constants, and
    missing one would ship a dashboard without the colours it paints live
    events with. Those are compiled when they happen to be utilities and
    dropped in silence when they are prose, which most of them are.
    """
    declared: set[str] = set()
    incidental: set[str] = set()
    for path in sources:
        text = path.read_text(encoding="utf-8")
        for pattern, already_unquoted in _CLASS_CONTEXTS:
            for match in pattern.finditer(text):
                declared |= _tokens_from(match.group(1), already_unquoted)
        for groups in re.findall(r'"([^"\n]*)"|\'([^\'\n]*)\'|`([^`]*)`', text):
            for literal in groups:
                for token in _INTERPOLATION.sub(" ", literal).split():
                    if _CLASS_TOKEN.fullmatch(token):
                        incidental.add(token)
    return declared, incidental - declared


PREFLIGHT = f"""\
/* --------------------------------------------------------------------------
   Preflight -- the subset of Tailwind's reset the dashboard depends on.

   `border-width: 0; border-style: solid` on every element is the load-bearing
   part: the `border` utility only sets a width, so without this a bordered
   card would draw nothing at all.
   -------------------------------------------------------------------------- */
*, ::before, ::after {{
  box-sizing: border-box;
  border-width: 0;
  border-style: solid;
  border-color: {DEFAULT_BORDER_COLOR};
}}
::before, ::after {{ --tw-content: ''; }}

html {{
  line-height: 1.5;
  -webkit-text-size-adjust: 100%;
  tab-size: 4;
  font-family: {FONT_SANS};
}}
body {{ margin: 0; line-height: inherit; }}
hr {{ height: 0; color: inherit; border-top-width: 1px; }}
h1, h2, h3, h4, h5, h6 {{ font-size: inherit; font-weight: inherit; margin: 0; }}
p, figure, blockquote, dl, dd {{ margin: 0; }}
ol, ul, menu {{ list-style: none; margin: 0; padding: 0; }}
a {{ color: inherit; text-decoration: inherit; }}
b, strong {{ font-weight: bolder; }}
code, kbd, samp, pre {{ font-family: {FONT_MONO}; font-size: 1em; }}
small {{ font-size: 80%; }}
table {{ text-indent: 0; border-color: inherit; border-collapse: collapse; }}
button, input, optgroup, select, textarea {{
  font-family: inherit;
  font-feature-settings: inherit;
  font-size: 100%;
  font-weight: inherit;
  line-height: inherit;
  color: inherit;
  margin: 0;
  padding: 0;
}}
button, select {{ text-transform: none; }}
button, [type='button'], [type='reset'], [type='submit'] {{
  -webkit-appearance: button;
  background-color: transparent;
  background-image: none;
  cursor: pointer;
}}
:disabled {{ cursor: default; }}
img, svg, video, canvas, audio, iframe, embed, object {{ display: block; vertical-align: middle; }}
img, video {{ max-width: 100%; height: auto; }}
[hidden] {{ display: none !important; }}
textarea {{ resize: vertical; }}
input::placeholder, textarea::placeholder {{ opacity: 1; color: {COLORS["muted"]}; }}
:root {{ color-scheme: dark; }}

@keyframes lpr-spin {{ to {{ transform: rotate(360deg); }} }}

/* Read by init() in app.js to prove this stylesheet actually loaded. */
:root {{ --lpr-css: 1; }}
"""


def render(declared: set[str], incidental: set[str] = frozenset()) -> tuple[str, list[str]]:
    """``(stylesheet, unknown)`` -- ``unknown`` covers ``declared`` only.

    ``incidental`` names are compiled into the sheet when they are utilities
    and dropped without comment when they are not; see :func:`extract_classes`.
    """
    classes = set(declared) | set(incidental)
    # bucket -> sort key -> (selector, declarations)
    plain: list[tuple[int, str, str]] = []
    stateful: dict[str, list[tuple[int, str, str]]] = {name: [] for name in STATE_VARIANTS}
    responsive: dict[str, list[tuple[int, str, str]]] = {name: [] for name in BREAKPOINTS}
    responsive_state: dict[tuple[str, str], list[tuple[int, str, str]]] = {}
    unknown: list[str] = []

    for name in sorted(classes):
        if name in HAND_WRITTEN:
            continue
        variants, utility = split_variants(name)
        known = set(STATE_VARIANTS) | set(BREAKPOINTS)
        if any(variant not in known for variant in variants):
            continue
        compiled = compile_class(utility)
        if compiled is None:
            if name in declared:
                unknown.append(name)
            continue
        declarations, index = compiled

        selector = escape_class(name)
        if declarations.startswith("@children "):
            selector += " > * + *"
            declarations = declarations[len("@children ") :]
        for variant in variants:
            if variant in STATE_VARIANTS:
                selector = STATE_VARIANTS[variant](selector)

        breakpoint = next((v for v in variants if v in BREAKPOINTS), None)
        state = next((v for v in variants if v in STATE_VARIANTS), None)
        entry = (index, selector, declarations)
        if breakpoint and state:
            responsive_state.setdefault((breakpoint, state), []).append(entry)
        elif breakpoint:
            responsive[breakpoint].append(entry)
        elif state:
            stateful[state].append(entry)
        else:
            plain.append(entry)

    def block(entries: list[tuple[int, str, str]], indent: str = "") -> str:
        lines = []
        for _, selector, declarations in sorted(entries, key=lambda e: (e[0], e[1])):
            lines.append(f"{indent}{selector} {{ {declarations}; }}")
        return "\n".join(lines)

    out = [PREFLIGHT, "\n/* --- utilities --- */\n", block(plain)]

    for variant in STATE_VARIANTS:
        entries = stateful[variant]
        if entries:
            out.append(f"\n/* --- {variant}: --- */\n" + block(entries))

    for breakpoint, width in BREAKPOINTS.items():
        entries = responsive[breakpoint]
        extra = [(bp, st) for (bp, st) in responsive_state if bp == breakpoint]
        if not entries and not extra:
            continue
        body = block(entries, indent="  ")
        for key in sorted(extra, key=lambda k: list(STATE_VARIANTS).index(k[1])):
            body += ("\n" if body else "") + block(responsive_state[key], indent="  ")
        out.append(f"\n@media (min-width: {width}) {{\n{body}\n}}")

    return "\n".join(out).rstrip() + "\n", unknown


BANNER = """\
/* GENERATED FILE -- do not edit.
 *
 * Built from the class names used in web/index.html and web/app.js by
 * scripts/build_web_css.py. Regenerate after changing either file:
 *
 *     python scripts/build_web_css.py
 *
 * This replaces the https://cdn.tailwindcss.com script the dashboard used to
 * load, so the UI is fully styled on a site with no internet access.
 */
"""


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def build(root: Path | None = None) -> tuple[str, list[str]]:
    """Compile the stylesheet for a checkout. Returns ``(css, unknown)``."""
    base = root or repo_root()
    web = base / "web"
    sources = sorted(web.glob("*.html")) + sorted(web.glob("*.js"))
    declared, incidental = extract_classes(sources)
    css, unknown = render(declared, incidental)
    return BANNER + css, unknown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="Fail if the stylesheet is stale.")
    parser.add_argument("--report", action="store_true", help="List classes with no rule.")
    parser.add_argument(
        "--out",
        type=Path,
        default=repo_root() / "web" / "static" / "css" / "app.css",
        help="Where to write the stylesheet.",
    )
    args = parser.parse_args(argv)

    css, unknown = build()

    if args.report or unknown:
        for name in unknown:
            print(f"[build-css] no rule for class: {name}", file=sys.stderr)

    if args.check:
        if not args.out.is_file():
            print(f"[build-css] {args.out} does not exist -- run this script.", file=sys.stderr)
            return 1
        if args.out.read_text(encoding="utf-8") != css:
            print(f"[build-css] {args.out} is stale -- run this script.", file=sys.stderr)
            return 1
        print(f"[build-css] {args.out} is up to date ({len(css)} bytes).")
        return 1 if unknown else 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(css, encoding="utf-8")
    rules = css.count("{") - css.count("@media") - css.count("@keyframes")
    print(f"[build-css] wrote {args.out} ({len(css)} bytes, ~{rules} rules)")
    return 1 if unknown else 0


if __name__ == "__main__":
    raise SystemExit(main())
