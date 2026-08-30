"""M7: re-visit everything in a case and report what moved.

One investigation is a photograph. The question an investigator actually has is
"what changed" — a market that went dark, a key that appeared on a second site,
a relaunch at a new address, a wallet that reached a VASP it did not reach last
week — and every one of those is a *diff* between two captures. The evidence
store already keeps hashed, chained snapshots, so this module is deliberately
thin: re-collect, ingest, then read the chain. Onion targets and the wallet
addresses a `search` already enriched are both re-checked the same pass (see
watch_targets / wallet_targets) — this is still polling, on whatever cadence
cron gives it, never a stream; "real-time" here means "not stale until the
next run," not sub-second.

    cybertrace watch --db case.db
    cybertrace watch --db case.db --discover

occam: no scheduler, no daemon, no watchlist table. The targets already in the
store ARE the watchlist, and cron (or the operator) decides when this runs.
A schedule column earns its place when different targets need different
cadences, which no case here has yet. Run it continuously with the OS's own
scheduler, not a new one:

    # cron: re-check every 6 hours
    0 */6 * * * cybertrace watch --db /path/case.db -o json >> /path/watch.log
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

from .evidence import EvidenceStore, ingest, utcnow

# What a re-check can conclude about one target.
LIVE_CHANGED, LIVE_SAME, WENT_DARK, BACK_UP = "CHANGED", "UNCHANGED", "DARK", "BACK_UP"
CHECK_FAILED = "CHECK_FAILED"

# entities.etype -> the module registry key that can re-search that chain.
# Not detector.detect_input_type: the address's chain is already known (it is
# the entity's own etype), so re-detecting from the string would just be a
# second, redundant way to get the same answer wrong if it ever disagreed.
_CHAIN_MODULE_TYPE = {"BTC_ADDRESS": "bitcoin", "ETH_ADDRESS": "ethereum", "TRX_ADDRESS": "tron"}


def watch_targets(store: EvidenceStore) -> List[dict]:
    """Onion targets in this case, newest activity first. Inactive ones are
    included on purpose: a market that went dark is exactly the one whose
    return matters."""
    return [dict(r) for r in store._all(
        "SELECT target_id, url, label, active, last_seen FROM targets "
        "WHERE kind='ONION' AND url NOT LIKE '%.correlate.local' "
        "ORDER BY last_seen DESC")]


def wallet_targets(store: EvidenceStore) -> List[dict]:
    """Wallet addresses this case has already searched -- the btc:/eth:/trx:
    enrichment targets a `cybertrace search <address>` creates, distinct from
    the ONION market targets watch_targets covers above.

    Found through the entity that carries the address, not targets.kind:
    every non-onion target lands under the same 'CLEARNET' kind regardless of
    whether it is a wallet, an IP or an email, so kind alone cannot tell a
    wallet apart from either. Restricted to observations an enrichment call
    actually wrote (evidence._ingest_enrichment's `f"{collector}:enrichment"`
    method), so an address merely typed into a market's page text -- never
    itself the *subject* of an enrichment call -- is not picked up.

    That restriction alone is not enough to name the right re-check target,
    though: a market crawl's own operator_pivot enrichment of an address it
    found on the page ALSO ends in `:enrichment`, and is filed under the
    MARKET's target row on purpose (evidence.py:1290-1294 -- "the market and
    the enrichment end up on one graph"), not a dedicated one for the address.
    Returning that target_id here would make a wallet's first `watch` re-check
    diff its new capture against an unrelated market's snapshot chain instead
    of its own. `store.upsert_target` is idempotent and is exactly what a
    direct `cybertrace search <address>` (and this module's own re-check) key
    a wallet's captures under, so re-deriving it here is what makes a
    pivot-discovered wallet and a directly-searched one converge on the same
    chain the first time either is re-checked.
    """
    rows = store._all(
        "SELECT DISTINCT e.entity_id, e.etype, "
        "       COALESCE(e.raw_value, e.normalized_value) AS address, "
        "       t.last_seen "
        "FROM entities e "
        "JOIN observations o ON o.entity_id = e.entity_id "
        "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        "JOIN targets t ON t.target_id = s.target_id "
        "WHERE e.etype IN ('BTC_ADDRESS','ETH_ADDRESS','TRX_ADDRESS') "
        "AND o.extraction_method LIKE '%:enrichment' "
        "ORDER BY t.last_seen DESC")
    return [{"entity_id": r["entity_id"], "etype": r["etype"], "address": r["address"],
            "target_id": store.upsert_target(r["address"]), "last_seen": r["last_seen"]}
            for r in rows]


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


async def _visit_wallet(module, address: str, deep: bool = False) -> dict:
    """One live re-search of a wallet, through the same chain module and the
    same `search()` a fresh `cybertrace search <address>` would use -- no
    wallet-monitoring-specific client, so a re-check and a first look apply
    the identical safety bounds (the `_TX_DEEP_PAGES` cap, and uncapped-but-
    bounded relationship output).
    """
    async with module:
        result = await module.search(address, deep=deep)
    return result.to_dict()


def _wallet_verdict(store: EvidenceStore, target_id: str) -> str:
    """Same generic chained-snapshot diff `_verdict` reads for onions --
    insert_snapshot chains per (target_id, collector) regardless of what kind
    of target it is, so a wallet's re-check is compared the same way a
    market's re-crawl is: against its own last capture, never a stranger's."""
    snap = store.latest_snapshot(target_id)
    if not snap or not snap["diff_summary"]:
        return LIVE_CHANGED                 # first capture by this collector
    import json
    return LIVE_CHANGED if json.loads(snap["diff_summary"]).get("changed") else LIVE_SAME


def wallet_deltas(before: Dict[str, dict], after: List[dict]) -> List[dict]:
    """What a wallet re-check changed about its reachability to a VASP.

    Compared by entity_id, the same identity wallet_exchange_paths keys its
    rows by. `before` is a dict (this case's own watched wallets only, captured
    before any re-check ran) rather than a list like candidate_deltas takes, because
    diffing against every wallet in the whole case -- most of them not even
    re-checked this run -- would report "changed" for wallets nothing touched.

    No GONE case: the evidence store is append-only, so a path that existed
    before a re-check cannot vanish because one ran -- only gain hops, an
    endpoint or a direction it did not have, never lose one.
    """
    FIELDS = ("proximity", "hops", "exchange", "attribution", "direction")
    after_by_id = {p["entity_id"]: p for p in after}
    out = []
    for entity_id, prev in before.items():
        cur = after_by_id.get(entity_id)
        if cur is None:
            continue
        if tuple(cur[f] for f in FIELDS) != tuple(prev[f] for f in FIELDS):
            out.append({"change": "MOVED", "entity_id": entity_id, "value": cur["value"],
                       "before": {f: prev[f] for f in FIELDS},
                       "after": {f: cur[f] for f in FIELDS}})
    for entity_id, cur in after_by_id.items():
        if entity_id not in before:
            out.append({"change": "NEW", "entity_id": entity_id, "value": cur["value"],
                       **{f: cur[f] for f in FIELDS}})
    return out


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
                  discover: bool = False, deep: bool = False) -> Dict[str, Any]:
    """Re-visit each target, ingest the result, and report the deltas.

    Returns {"checked": [...], "wallets_checked": [...], "wallet_deltas": [...],
    "discovered": [...]}; the caller runs correlation afterwards, because what a
    change *means* is the correlation layer's job and keeping that out of here
    is what stops this becoming a second engine.

    Wallets are re-checked the same pass, over the enrichment targets a wallet
    `search` already created (see wallet_targets) -- closing a PS3 gap where
    every other piece (ingest, the chained-snapshot diff, wallet_exchange_paths)
    already existed and only never ran again after the first look. `urls` does
    not filter wallets -- it names onion hosts, and a wallet address would
    never match one.
    """
    from .correlate import wallet_exchange_paths
    from .modules import get_module
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

    wallets = wallet_targets(store)
    # Scoped to the wallets THIS case itself searched, not every address in
    # wallet_exchange_paths(store) -- that BFS also reports collateral
    # addresses (a plain counterparty, an exchange's own hot wallet) whose
    # reachability shifts as a side effect of a re-check nobody asked for.
    # Alerting on those too would bury the one delta an analyst actually
    # watches this case for under every address adjacent to it in the graph.
    watched_ids = {w["entity_id"] for w in wallets}
    wallets_before = {p["entity_id"]: p for p in wallet_exchange_paths(store)
                      if p["entity_id"] in watched_ids}
    wallets_checked: List[dict] = []
    for w in wallets:
        module_type = _CHAIN_MODULE_TYPE.get(w["etype"])
        chain_module = get_module(module_type) if module_type else None
        if chain_module is None:
            continue                        # etype without a chain module: nothing to re-run
        chain_module.show_progress = False
        result = await _visit_wallet(chain_module, w["address"], deep=deep)
        has_data = bool(result.get("summary"))
        if has_data:
            ingest(result, store)
        wallets_checked.append({
            "address": w["address"], "chain": w["etype"],
            "status": _wallet_verdict(store, w["target_id"]) if has_data else CHECK_FAILED,
        })
    wallets_after = [p for p in wallet_exchange_paths(store) if p["entity_id"] in watched_ids]
    wallet_delta_rows = wallet_deltas(wallets_before, wallets_after)

    return {"checked": checked, "wallets_checked": wallets_checked,
            "wallet_deltas": wallet_delta_rows, "discovered": discovered,
            "checked_at": utcnow()}


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


def watch_narrative(store: EvidenceStore, case_id: str, deltas: List[dict]) -> Optional[dict]:
    """The one analyst-alert step M7 didn't have: "what changed and why it
    might matter", grounded rather than a bare NEW/MOVED/GONE list.

    None on a quiet re-check (deltas empty) so an unattended cron run costs
    nothing — no investigator call, no LLM spend — when there is nothing to
    say. Reuses cybertrace.investigator.answer() end to end: that module
    already has a `_changed` handler reading memory.py's case_history for
    exactly this question, so this is wiring, not a second reasoning path.
    """
    if not deltas:
        return None
    from .investigator import answer
    return answer(store, case_id, "what changed")


def run_watch(store: EvidenceStore, urls: Optional[List[str]] = None,
              discover: bool = False, correlate: bool = True,
              case_id: Optional[str] = None, deep: bool = False) -> Dict[str, Any]:
    """Synchronous entry point: re-check, then re-correlate and diff."""
    before = read_candidates(store)
    report = asyncio.run(recheck(store, urls=urls, discover=discover, deep=deep))
    if correlate:
        from .correlate import run_correlation
        results = run_correlation(store)
        report["deltas"] = candidate_deltas(before, read_candidates(store))
        report["successors"] = [s for s in results["successors"] if not s["suppressed"]]
        report["contradictions"] = results["contradictions"]
        report["narrative"] = watch_narrative(store, case_id or "case", report["deltas"])
    return report
