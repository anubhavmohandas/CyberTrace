"""Regression for the Graph tab's SVG console-error defect: web/CyberTrace
Workspace.dc.html's <x-dc> block is real, live markup the instant the browser
parses the page — dc-runtime (support.js) only replaces it with the hydrated
React tree once React finishes loading. Until then, any <circle>/<line>/<text>
written with its literal, un-substituted "{{ n.x }}" binding as a numeric
attribute (cx, cy, r, x1, y1, x2, y2, x, y) fails Blink/WebKit's typed SVG
attribute validation and logs "Expected length" console errors — confirmed via
real Chromium (Playwright) against the live tortaxi case: 16 such errors were
reported for the unmodified template, none of them affecting the (correctly
rendered) hydrated output.

The fix authors those three tags as sc-raw-circle/sc-raw-line/sc-raw-text —
dc-runtime's own RAW_WRAP/RAW_UNWRAP mechanism (already used for table/select,
which have an analogous raw-parse quirk). The browser parses the alias as an
untyped, unvalidated element; walkElement() maps it back to the real tag name
once resolve() has filled in real numbers, so the hydrated graph is unchanged.

This test statically guards both halves of that fix without needing a real
browser: no numeric-attribute-bearing SVG tag may appear un-aliased with a
"{{ }}" binding anywhere in the workspace template, and support.js's RAW_WRAP
must still know how to unwrap the aliases it's given.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "web" / "CyberTrace Workspace.dc.html"
SUPPORT_JS = ROOT / "web" / "support.js"

# SVG elements whose geometry attributes are typed (SVGAnimatedLength) and so
# fail Blink/WebKit's raw-parse validation on an unresolved "{{ }}" value.
RISKY_TAGS = ("circle", "line", "text", "rect", "ellipse", "polygon", "polyline", "path")


def test_no_unaliased_svg_tag_carries_an_unresolved_binding():
    html = WORKSPACE.read_text()
    for tag in RISKY_TAGS:
        # "<circle ...>" never matches the "<sc-raw-circle ...>" alias (wrong
        # character right after "<") or the "</circle>" close tag (a "/"
        # follows "<", not the tag name) — any match here is a raw, live tag.
        for m in re.finditer(r"<" + tag + r"(\s[^>]*)?>", html):
            assert "{{" not in (m.group(1) or ""), (
                f"<{tag}> in the Workspace template has an unresolved {{{{ }}}} binding but "
                f"isn't aliased to sc-raw-{tag} (see RAW_WRAP in support.js) — this fails "
                f"SVG attribute validation on raw parse, before dc-runtime hydrates it"
            )


def test_raw_wrap_still_unwraps_the_aliased_graph_tags():
    js = SUPPORT_JS.read_text()
    m = re.search(r"var RAW_WRAP = \{(.*?)\};", js, re.S)
    assert m, "RAW_WRAP object not found in support.js"
    body = m.group(1)
    for tag in ("circle", "line", "text"):
        assert re.search(rf'\b{tag}:\s*"sc-raw-{tag}"', body), (
            f"support.js's RAW_WRAP is missing {tag}: \"sc-raw-{tag}\" — without it, "
            f"walkElement() would render a literal <sc-raw-{tag}> element instead of "
            f"a real <{tag}>, breaking the graph"
        )
