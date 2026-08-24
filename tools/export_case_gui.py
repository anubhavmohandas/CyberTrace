#!/usr/bin/env python3
"""Run real captures through the correlation engine and emit the JSON shape
the CyberTrace Workspace GUI prototype (web/CyberTrace Workspace.dc.html)
expects, so the mockup can be backed by an actual case instead of the
hand-written fixtures it ships with.

    python tools/export_case_gui.py runs/raw/v8/tortaxi-prd.json runs/raw/v8/tortaxi-2dev.json \
        --case-id CASE-0001 --title "tor.taxi mirror pair" -o web/case-tortaxi.json

build_payload() is also reused live by tools/case_api.py against a persistent
--db case file, so the GUI can read a case without a batch export step.

occam: one case, one operator role, one contradiction type mapped (cloning).
Extend the mappers below when a case needs a second role or contradiction
rule represented — no dispatch table until there's a second one to dispatch.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybertrace.correlate import render_markdown, run_correlation, entity_timeline
from cybertrace.evidence import EvidenceStore, ingest

BAND_COLOR = {"HIGH": "#63c48b", "MEDIUM": "#2fb4e8", "LOW": "#7c878c"}


def short(value: str, n: int = 28) -> str:
    return value if len(value) <= n else value[: n - 1] + "…"


def build(paths: list[Path], case_id: str, title: str) -> dict:
    """Batch entry point: ingest raw capture JSON into a scratch store, export once."""
    with EvidenceStore(":memory:") as store:
        for p in paths:
            ingest(json.loads(p.read_text()), store)
        return build_payload(store, case_id, title)


def build_payload(store: EvidenceStore, case_id: str, title: str) -> dict:
    """Compute the GUI JSON shape from an already-populated store (batch or live)."""
    results = run_correlation(store)
    targets = {r["target_id"]: r["url"] for r in
               store._all("SELECT target_id, url FROM targets")}
    snaps = store._all(
        "SELECT snapshot_id, target_id, collector, status, sha256, observed_at "
        "FROM snapshots ORDER BY observed_at")

    candidates, drawers, evidence_rows, timeline_rows = [], {}, [], []

    for d in results["dossiers"]:
        ent = d["entity"]
        key = ent["entity_id"]
        band = d["confidence_level"]
        supporting = [{
            "label": f"{ke['extraction_method'].split(':')[-1].replace('_', ' ').title()} — {short(ent['value'], 40)}",
            "strength": "DIRECT",
            "color": "#63c48b",
        } for ke in d["key_evidence"][:1]] or [{
            "label": short(ent["value"], 40), "strength": "DIRECT", "color": "#63c48b"}]
        contradicting = [{"label": c["detail"]} for c in d["contradictions"]] or [{"label": "None recorded"}]

        feedback_rows = store.feedback_for_entity(key)
        verdict = None
        if feedback_rows:
            latest = feedback_rows[0]  # feedback_for_entity is already DESC by recorded_at
            verdict = {"outcome": latest["outcome"], "note": latest["note"] or "",
                       "analyst": latest["analyst"] or "", "recorded_at": latest["recorded_at"]}

        candidates.append({
            "key": key, "candidate_id": d["candidate_id"],
            "name": short(ent["value"], 22), "etype": ent["etype"],
            "band": band, "score": f"{d['score']:.2f}", "markets": d["markets"],
            "assessment": (
                f"Shared {ent['etype'].replace('_', ' ').title()} across "
                f"{len(d['markets'])} onion(s): " + ", ".join(short(m, 24) for m in d["markets"]) + "."
            ),
            "supporting": supporting, "contradicting": contradicting,
            "objections": [{"text": c["detail"], "rule": c["rule"].upper()}
                           for c in d["contradictions"]],
            "recommended_actions": d["recommended_actions"],
            "limitations": d["limitations"],
            "verdict": verdict,
        })

        drawer_sources = sorted({ke["url"] for ke in d["key_evidence"]})
        drawers[key] = {
            "etype": ent["etype"], "value": ent["value"],
            "first": d["timeline"][0]["observed_at"][:10] if d["timeline"] else "",
            "last": d["timeline"][-1]["observed_at"][:10] if d["timeline"] else "",
            "evidence": [{
                "mark": "✓", "color": "#63c48b",
                "text": f"{ke['extraction_method']} on {short(ke['url'], 30)} (conf {ke['confidence']:.1f})",
            } for ke in d["key_evidence"]] + [{
                "mark": "⚠", "color": "#c2b280", "text": c["detail"],
            } for c in d["contradictions"]],
            "relationships": [{"to": short(m, 24), "rtype": "LINKED_TO", "color": "#2fb4e8"}
                               for m in d["markets"]],
            "sources": [{"name": short(u, 40)} for u in drawer_sources]
                       or [{"name": "CyberTrace capture · Tor"}],
        }

        for row in entity_timeline(store, key, limit=20):
            timeline_rows.append({
                "date": row["observed_at"][:10], "title": f"{ent['etype']} observed on {short(row['url'], 26)}",
                "detail": f"{row['section']} via {row['extraction_method']} (confidence {row['confidence']:.1f})",
                "meta": f"SNAPSHOT {row['sha256'][:8]}…", "dot": "#2fb4e8",
            })
            evidence_rows.append({
                "kind": "OBSERVED", "cls": "DIRECT", "title": f"{ent['etype'].replace('_', ' ').title()}",
                "value": ent["value"], "source": short(row["url"], 30), "observed": row["observed_at"][:16].replace("T", " ") + " UTC",
                "hash": "sha256 " + row["sha256"][:8] + "…",
            })

    for c in results["dossiers"]:
        for contra in c["contradictions"]:
            evidence_rows.append({
                "kind": "INFERRED", "cls": "SUPPRESSED",
                "title": "Shared-artifact contradiction", "value": contra["detail"],
                "source": "correlation engine", "observed": "",
                "hash": "finding " + contra["finding_id"][:8] + "…",
                "rule": contra["rule"].upper(), "ruleWhy": contra["detail"],
            })

    timeline_rows.sort(key=lambda r: r["date"])

    captures = [{
        "source": short(targets.get(s["target_id"], s["target_id"]), 20),
        "reliability": "—", "rel": "#67716f", "snapshot_id": s["snapshot_id"],
        "sha": s["sha256"][:24] + "…", "at": s["observed_at"][:16].replace("T", " "),
        "status": s["status"], "sc": "#63c48b" if s["status"] == "OK" else "#d97a6c",
    } for s in snaps]

    suppressed = [{
        "signal": c["rule"].replace("_", " "), "observed": f"similarity {c.get('similarity', '—')}",
        "rule": c["rule"].upper(), "why": c["detail"],
    } for d in results["dossiers"] for c in d["contradictions"]]

    stats = [
        {"label": "ENTITIES", "value": str(len(candidates) + len(targets)), "note": "unique after normalization"},
        {"label": "EVIDENCE", "value": str(len(evidence_rows)), "note": f"observations across {len(snaps)} snapshots"},
        {"label": "CANDIDATES", "value": str(len(candidates)), "note": f"{len(results['contradictions'])} contradictions recorded"},
    ]

    info = store.case_info()
    return {
        "case_id": case_id, "title": title,
        "status": info.get("status", "OPEN"), "updated_at": info.get("updated_at", ""),
        "stats": stats, "candidates": candidates, "drawers": drawers,
        "evidence": evidence_rows, "timeline": timeline_rows,
        "captures": captures, "suppressed": suppressed,
        "markets": sorted(targets.values()),
        "report_markdown": render_markdown(results["dossiers"], results),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("captures", nargs="+", type=Path)
    ap.add_argument("--case-id", default="CASE-0001")
    ap.add_argument("--title", default="Real case export")
    ap.add_argument("-o", "--out", type=Path, required=True)
    args = ap.parse_args()

    missing = [p for p in args.captures if not p.is_file()]
    if missing:
        ap.error(f"no such file: {', '.join(str(p) for p in missing)}")

    case = build(args.captures, args.case_id, args.title)
    args.out.write_text(json.dumps(case, indent=2, ensure_ascii=False))
    print(f"wrote {args.out} — {len(case['candidates'])} candidates, "
          f"{len(case['evidence'])} evidence rows, {len(case['timeline'])} timeline entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
