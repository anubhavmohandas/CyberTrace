"""Locks the shape tools/export_case_gui.py hands to web/CyberTrace Workspace.dc.html
against the real tor.taxi captures — not a synthetic fixture, per the same
real-corpus-over-fixture convention as test_corpus_regression.py.
"""

import json
from pathlib import Path

from cybertrace.evidence import EvidenceStore, ingest
from tools.export_case_gui import build, build_payload

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = [ROOT / "runs" / "raw" / "v8" / "tortaxi-prd.json",
            ROOT / "runs" / "raw" / "v8" / "tortaxi-2dev.json"]


def test_tortaxi_export_matches_gui_shape():
    assert all(p.is_file() for p in CAPTURES), "runs/raw/v8 tortaxi captures are missing"
    case = build(CAPTURES, "CASE-TEST", "tor.taxi mirror pair")

    assert len(case["candidates"]) == 2
    assert {c["etype"] for c in case["candidates"]} == {"PGP_KEY", "EMAIL"}
    assert all(c["band"] in ("LOW", "MEDIUM", "HIGH") for c in case["candidates"])
    assert all(c["markets"] for c in case["candidates"])

    # The real clone-similarity contradiction must survive into `suppressed`,
    # since that is what the GUI's verdict modal and graph edge read from.
    assert case["suppressed"], "expected the page-similarity contradiction to surface"
    assert any("cloning" in s["rule"].lower() for s in case["suppressed"])

    assert case["evidence"]
    assert case["timeline"] == sorted(case["timeline"], key=lambda r: r["date"])
    assert len(case["markets"]) == 2

    # case metadata real (section 7): always present even on a fresh store.
    assert case["status"] == "OPEN"
    assert case["updated_at"]

    # report output real (section 8): the actual dossier/report machinery,
    # not a client-generated summary.
    assert "correlation brief" in case["report_markdown"].lower()
    for c in case["candidates"]:
        assert c["candidate_id"]
        assert c["recommended_actions"]
        assert c["limitations"]
        assert c["verdict"] is None  # no analyst_feedback recorded on this fresh store

    assert all("snapshot_id" in cap for cap in case["captures"])
    assert case["notes"] == []  # no analyst notes recorded on this fresh store


def test_case_notes_reach_the_gui_payload():
    with EvidenceStore(":memory:") as store:
        for p in CAPTURES:
            ingest(json.loads(p.read_text()), store)
        store.add_case_note("watch this one closely", analyst="jdoe")
        case = build_payload(store, "CASE-TEST", "tor.taxi mirror pair")

    assert len(case["notes"]) == 1
    assert case["notes"][0]["note"] == "watch this one closely"
    assert case["notes"][0]["analyst"] == "jdoe"
    assert case["notes"][0]["recorded_at"]
