"""Regression for the graph-rendering defect: web/CyberTrace Workspace.dc.html
loaded React/ReactDOM from unpkg.com before rendering anything. dc-runtime
(support.js) parses the whole template — including the Graph tab's SVG,
literal "{{ n.x }}" and all — as live DOM the instant the browser reaches
<body>, and only replaces it once React has hydrated. If that CDN fetch is
blocked (this tool routes investigation targets over Tor; an analyst's
network is not assumed to reach the open internet), hydration never
happens and the Workspace stays a permanently blank, un-rendered page.

The fix vendors React/ReactDOM locally and points dc-runtime's own
window.__resources override hook (see cdnScriptFor in support.js) at them,
so hydration no longer depends on external network access. This test pins
that wiring without needing a real browser: it checks the override is
declared before support.js loads, targets the exact CDN URLs support.js
would otherwise fetch, and that the vendored files are byte-identical to
what those URLs serve (via the SRI hashes support.js already pins).
"""
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "web" / "CyberTrace Workspace.dc.html"
SUPPORT_JS = ROOT / "web" / "support.js"


def _sri_to_hex(sri: str) -> str:
    import base64
    algo, b64 = sri.split("-", 1)
    assert algo == "sha384"
    return base64.b64decode(b64).hex()


def test_workspace_vendors_react_before_loading_support_js():
    html = WORKSPACE.read_text()
    react_url, react_dom_url = _pinned_cdn_urls()

    resources_idx = html.find("window.__resources")
    support_idx = html.find('<script src="./support.js">')
    assert resources_idx != -1, "window.__resources override is missing"
    assert support_idx != -1, "support.js script tag is missing"
    assert resources_idx < support_idx, (
        "window.__resources must be set before support.js runs, or its "
        "cdnScriptFor() will already have fetched from unpkg.com"
    )

    assert react_url in html, "support.js's pinned React CDN URL isn't overridden in the workspace"
    assert react_dom_url in html, "support.js's pinned ReactDOM CDN URL isn't overridden in the workspace"


def test_vendored_react_matches_the_version_support_js_expects():
    react_sri, react_dom_sri = _pinned_sri()
    react_file = ROOT / "web" / "vendor" / "react.production.min.js"
    react_dom_file = ROOT / "web" / "vendor" / "react-dom.production.min.js"

    assert react_file.is_file(), "web/vendor/react.production.min.js is missing"
    assert react_dom_file.is_file(), "web/vendor/react-dom.production.min.js is missing"

    assert hashlib.sha384(react_file.read_bytes()).hexdigest() == _sri_to_hex(react_sri), (
        "vendored react.production.min.js doesn't match the version pinned by "
        "REACT_SRI in support.js — re-vendor from the exact unpkg URL/version"
    )
    assert hashlib.sha384(react_dom_file.read_bytes()).hexdigest() == _sri_to_hex(react_dom_sri), (
        "vendored react-dom.production.min.js doesn't match the version pinned "
        "by REACT_DOM_SRI in support.js — re-vendor from the exact unpkg URL/version"
    )


def _pinned_cdn_urls() -> tuple[str, str]:
    js = SUPPORT_JS.read_text()
    react_url = re.search(r'REACT_URL\s*=\s*"([^"]+)"', js).group(1)
    react_dom_url = re.search(r'REACT_DOM_URL\s*=\s*"([^"]+)"', js).group(1)
    return react_url, react_dom_url


def _pinned_sri() -> tuple[str, str]:
    js = SUPPORT_JS.read_text()
    react_sri = re.search(r'REACT_SRI\s*=\s*"([^"]+)"', js).group(1)
    react_dom_sri = re.search(r'REACT_DOM_SRI\s*=\s*"([^"]+)"', js).group(1)
    return react_sri, react_dom_sri
