"""Regression for the real "node labels not rendering" defect: dc-runtime's
walkText() (support.js) wraps every resolved "{{ }}" text interpolation in
an HTML <span>. That's harmless anywhere in the app except the Graph tab,
where node/edge labels interpolate inside SVG <text> elements — an HTML
<span> nested there isn't valid SVG text content, so the browser silently
drops it from text layout: the label string is present in the DOM (a
snapshot test wouldn't catch this) but paints nothing and has a zero-size
bounding box.

Confirmed via real Chromium (Playwright) against the live tortaxi case:
every graph label's getBBox() was {0,0,0,0} before this fix and real,
non-zero rectangles after it.

The fix swaps the wrapper element from "span" to "tspan". React namespaces
a host element the same as its parent, so the exact same call renders a
real (X)HTML <span> inside ordinary HTML and a real, spec-valid SVG <tspan>
inside SVG <text> — no context-detection code needed, and no visible change
anywhere outside the Graph tab (confirmed: Overview tab's HTML interpolations
render identically either way).

This test statically guards the fix without needing a real browser: none of
walkText's three text-interpolation branches (resolved value, streaming
placeholder, editor-mode unresolved marker) may use "span" for the
"sc-interp" wrapper.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUPPORT_JS = ROOT / "web" / "support.js"


def test_text_interpolation_wrapper_is_tspan_not_span():
    js = SUPPORT_JS.read_text()
    assert 'h("tspan", { key: i, className: "sc-interp" }, String(v));' in js, (
        'walkText\'s resolved-value branch must wrap in "tspan", not "span" — '
        "an HTML span silently fails to paint inside an SVG <text> element "
        "(e.g. the Graph tab's node/edge labels), even though it's present in the DOM"
    )
    assert not re.search(r'h\(\s*"span"\s*,\s*\{\s*key:\s*i,\s*className:\s*"sc-interp', js), (
        'a text-interpolation branch in walkText is still using "span" for the '
        '"sc-interp" wrapper — this breaks any label rendered inside SVG <text>'
    )
