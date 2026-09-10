"""Regression for the landing page's live "detected type" hint: detect() is
a pattern-only, no-network-round-trip guess (by design, see its own
comment) with no "malformed" bucket, so a string shaped like a BTC address
but using a character Base58 never uses (0, O, I, l) matched none of its
regexes and fell through to the USERNAME catch-all forever, even after the
server's real detector (the same /api/detect every submitted search already
calls) had identified it as invalid. Static guard, same convention as
test_graph_no_hardcoded_market_count in test_market_relationships.py — no
browser needed, this only pins that the wiring exists and reuses the
existing endpoint rather than inventing a second one.

Live verification (Playwright, not committed — Playwright isn't a
requirements.txt dependency in this project) confirmed the actual behavior:
the invalid Kaggle string (19e6aqs6ru2ei5r3cuzcfmcklq78uksmry) shows
USERNAME instantly, then INVALID_ADDRESS once the debounced authoritative
check resolves; a valid BTC address (158treVZBGMBThoaympxccPdZPtqUfYrT9)
shows BTC_ADDRESS both instantly and after the check — no regression on the
already-correct path, and no new console errors or failed requests.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "web" / "CyberTrace Workspace.dc.html"


def test_landing_detected_type_defers_to_authoritative_invalid_result():
    html = WORKSPACE.read_text()

    assert "scheduleDetectCheck" in html, (
        "the landing input's onQuery no longer schedules an authoritative "
        "check — a malformed address will silently show USERNAME forever"
    )
    assert "onQuery: (e) => { const v = e.target.value; this.set({ query: v }); this.scheduleDetectCheck(v); }," in html, (
        "onQuery no longer calls scheduleDetectCheck on every keystroke — "
        "the debounced authoritative check will never fire"
    )

    start = html.index("scheduleDetectCheck(rawQuery)")
    end = html.index("\n  }", start)
    fn = html[start:end]
    assert "detectUrl(q)" in fn and "apiFetch(" in fn, (
        "scheduleDetectCheck must reuse the exact detectUrl()/apiFetch() "
        "runSearch() already calls, not a second hand-rolled fetch to a "
        "different endpoint"
    )

    dt_start = html.index("detectedType: (st.detectResult")
    dt_end = html.index("this.detect(st.query),", dt_start) + len("this.detect(st.query),")
    detected_type_expr = html[dt_start:dt_end]
    assert "valid_address === false" in detected_type_expr, (
        "detectedType no longer checks the authoritative valid_address flag "
        "— a malformed address can show USERNAME even after the server has "
        "identified it as invalid"
    )
    assert "'INVALID_ADDRESS'" in detected_type_expr, (
        "detectedType no longer surfaces an explicit invalid label when the "
        "authoritative check disagrees with the instant client guess"
    )
    assert "this.detect(st.query)" in detected_type_expr, (
        "detectedType must still fall back to the instant client guess "
        "while no authoritative answer has arrived yet, or once it confirms "
        "the address is valid — this must not become a blocking network "
        "round trip on every keystroke"
    )
