"""M7: re-visit everything in a case and report what moved.

One investigation is a photograph. The question an investigator actually has is
"what changed" — a market that went dark, a key that appeared on a second site,
a relaunch at a new address — and every one of those is a *diff* between two
captures. The evidence store already keeps hashed, chained snapshots, so this
module is deliberately thin: re-collect, ingest, then read the chain.

    cybertrace watch --db case.db
    cybertrace watch --db case.db --discover

occam: no scheduler, no daemon, no watchlist table. The targets already in the
store ARE the watchlist, and cron (or the operator) decides when this runs.
A schedule column earns its place when different targets need different
cadences, which no case here has yet.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

from .evidence import EvidenceStore, ingest, utcnow

# What a re-check can conclude about one target.
LIVE_CHANGED, LIVE_SAME, WENT_DARK, BACK_UP = "CHANGED", "UNCHANGED", "DARK", "BACK_UP"


def watch_targets(store: EvidenceStore) -> List[dict]:
    """Onion targets in this case, newest activity first. Inactive ones are
    included on purpose: a market that went dark is exactly the one whose
    return matters."""
    return [dict(r) for r in store._all(
        "SELECT target_id, url, label, active, last_seen FROM targets "
        "WHERE kind='ONION' AND url NOT LIKE '%.correlate.local' "
        "ORDER BY last_seen DESC")]


async def _visit(module, url: str) -> dict:
    """One live visit, shaped like a saved ModuleResult so ingest() can eat it.

    Only the onion fetch runs — no indexes, no pivots. A re-check answers "is
    this site still there and has it changed", and paying for a full sweep of
    every source per target is what would stop anyone running this on a
    schedule.
    """
    host = url.split("/")[0]
    source = await module._fetch_target_onion(host)
    return {
        "target": host,
        "target_type": "darkweb",
        "module": "watch",
        "sources": {"watch": {
            "success": source.success,
            "data": source.data,
            "error": source.error,
            "timestamp": utcnow(),
        }},
    }


def _verdict(store: EvidenceStore, target_id: str, was_active: bool,
             online: bool) -> str:
    if not online:
        return WENT_DARK
    if not was_active:
        return BACK_UP
    snap = store.latest_snapshot(target_id)
    if not snap or not snap["diff_summary"]:
        return LIVE_CHANGED                 # first capture by this collector
    import json
    return LIVE_CHANGED if json.loads(snap["diff_summary"]).get("changed") else LIVE_SAME


async def recheck(store: EvidenceStore, urls: Optional[List[str]] = None,
                  discover: bool = False) -> Dict[str, Any]:
    """Re-visit each target, ingest the result, and report the deltas.

    Returns {"checked": [...], "discovered": [...]}; the caller runs correlation
    afterwards, because what a change *means* is the correlation layer's job and
    keeping that out of here is what stops this becoming a second engine.
    """
    from .modules.darkweb_module import DarkwebModule

    watching = [t for t in watch_targets(store)
                if urls is None or t["url"].split("/")[0] in
                {u.strip().lower().removeprefix("http://").rstrip("/") for u in urls}]
    checked: List[dict] = []
    discovered: List[dict] = []

    async with DarkwebModule() as module:
        module.show_progress = False
        for target in watching:
            was_active = bool(target["active"])
            result = await _visit(module, target["url"])
            source = result["sources"]["watch"]
            ingest(result, store)
            online = bool(source["success"])
            if online:
                # ingest() only touches `active` when a site is dark; a target
                # that answered again has to be revived explicitly or it stays
                # flagged inactive forever after one bad night.
                store.conn.execute("UPDATE targets SET active=1 WHERE target_id=?",
                                   (target["target_id"],))
                store.conn.commit()
            checked.append({
                "url": target["url"],
                "status": _verdict(store, target["target_id"], was_active, online),
                "online": online,
                "error": None if online else source.get("error"),
                "title": (source.get("data") or {}).get("title"),
                "pages": (source.get("data") or {}).get("pages_fetched"),
            })

        if discover:
            known = {r["url"].split("/")[0] for r in store._all("SELECT url FROM targets")}
            directories = await module._fetch_onion_directories()
            for name, onion in (directories.data.get("services") or {}).items():
                if onion.lower() not in known:
                    discovered.append({"service": name, "onion": onion})

    return {"checked": checked, "discovered": discovered, "checked_at": utcnow()}


def candidate_deltas(before: List[dict], after: List[dict]) -> List[dict]:
    """What correlation concluded differently after the re-check.

    Compared by candidate_id against the `candidates` rows read before the pass:
    a new candidate, or one whose confidence moved, is the alert. A candidate
    that merely persists is not news and would bury the two lines that are.
    """
    old = {c["candidate_id"]: c for c in before}
    out = []
    for cand in after:
        prev = old.get(cand["candidate_id"])
        if prev is None:
            out.append({"change": "NEW", "candidate_id": cand["candidate_id"],
                        "confidence": cand["confidence"],
                        "assessment": cand["assessment"]})
        elif round(prev["confidence"] or 0, 3) != round(cand["confidence"] or 0, 3):
            out.append({"change": "MOVED", "candidate_id": cand["candidate_id"],
                        "from": prev["confidence"], "confidence": cand["confidence"],
                        "assessment": cand["assessment"]})
    for candidate_id, prev in old.items():
        if candidate_id not in {c["candidate_id"] for c in after}:
            out.append({"change": "GONE", "candidate_id": candidate_id,
                        "confidence": prev["confidence"],
                        "assessment": prev["assessment"]})
    return out


def read_candidates(store: EvidenceStore) -> List[dict]:
    return [dict(r) for r in store._all(
        "SELECT candidate_id, confidence, assessment FROM candidates")]


def run_watch(store: EvidenceStore, urls: Optional[List[str]] = None,
              discover: bool = False, correlate: bool = True) -> Dict[str, Any]:
    """Synchronous entry point: re-check, then re-correlate and diff."""
    before = read_candidates(store)
    report = asyncio.run(recheck(store, urls=urls, discover=discover))
    if correlate:
        from .correlate import run_correlation
        results = run_correlation(store)
        report["deltas"] = candidate_deltas(before, read_candidates(store))
        report["successors"] = [s for s in results["successors"] if not s["suppressed"]]
        report["contradictions"] = results["contradictions"]
    return report
