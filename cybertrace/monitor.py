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

from .evidence import EvidenceStore, WALLET_ETYPES_SQL, ingest, utcnow

# What a re-check can conclude about one target.
LIVE_CHANGED, LIVE_SAME, WENT_DARK, BACK_UP = "CHANGED", "UNCHANGED", "DARK", "BACK_UP"
CHECK_FAILED = "CHECK_FAILED"

# entities.etype -> the module registry key that can re-search that chain.
# Not detector.detect_input_type: the address's chain is already known (it is
# the entity's own etype), so re-detecting from the string would just be a
# second, redundant way to get the same answer wrong if it ever disagreed.
_CHAIN_MODULE_TYPE = {"BTC_ADDRESS": "bitcoin", "ETH_ADDRESS": "ethereum",
                      "BNB_ADDRESS": "bnb", "POLYGON_ADDRESS": "polygon",
                      "TRX_ADDRESS": "tron", "SOL_ADDRESS": "solana"}


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
        f"WHERE e.etype IN ({WALLET_ETYPES_SQL}) "
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


async def _visit_wallet(module, address: str, deep: bool = False,
                        module_type: Optional[str] = None) -> dict:
    """One live re-search of a wallet, through the same chain module and the
    same `search()` a fresh `cybertrace search <address>` would use -- no
    wallet-monitoring-specific client, so a re-check and a first look apply
    the identical safety bounds (the `_TX_DEEP_PAGES` cap, and uncapped-but-
    bounded relationship output).

    `module_type` is passed through as `target_type` for BNB/Polygon: the
    entity's own etype already says which of the two it is (see
    _CHAIN_MODULE_TYPE's docstring on why this is not re-detected from the
    address string), but BitcoinModule.search() cannot recover that from a
    bare 0x address on its own -- without this, a watched BNB wallet would
    silently re-search as Ethereum every cycle.
    """
    async with module:
        result = await module.search(address, deep=deep, target_type=module_type)
    return result.to_dict()


def _wallet_verdict(store: EvidenceStore, target_id: str) -> str:
    """Same generic chained-snapshot diff `_verdict` reads for onions --
    insert_snapshot chains per (target_id, collector) regardless of what kind
    of target it is, so a wallet's re-check is compared the same way a
    market's re-crawl is: against its own last capture, never a stranger's."""
    snap = store.latest_snapshot(target_id)
    if not snap or not snap["diff_summary"]:
        return LIVE_CHANGED                 # first capture by this collector
    return LIVE_CHANGED if json.loads(snap["diff_summary"]).get("changed") else LIVE_SAME


def _vasp_contacts(row: dict) -> List[dict]:
    """Every OTHER VASP an AT_VASP row itself reaches -- direct_vasp_contacts
    (Loop 28, hop 1) and secondary_vasp_contacts (Loop 30, hop 2+) -- reduced
    to a list of {exchange, hops, attribution, direction}: the same shape
    FIELDS below already tracks for the primary relationship, so a brand's
    arrival, or a real change in how it's reached, deltas the same way a
    primary-path change already does.

    Both source keys exist only on AT_VASP (hop 0) rows, never on
    DIRECT/INDIRECT ones (see wallet_exchange_paths) -- row.get(f, []) reads
    that absence as "reaches no other VASP", same as an AT_VASP row that
    genuinely has none, rather than the KeyError a bare row[f] would raise.
    This is a narrowly scoped normalization for these two optional,
    list-valued fields only -- FIELDS below still indexes every watched row
    with plain row[f], unchanged, because proximity/hops/exchange/attribution
    /direction are present on every row regardless of proximity.

    A brand can only ever land in one of the two source lists --
    wallet_exchange_paths' own direct_brands guard excludes a hop-1 brand
    from secondary_vasp_contacts -- so concatenating them can't double-count
    one relationship under two entries (Phase 3E / Test 8).

    path and evidence_ids are left out on purpose, matching FIELDS' own
    omission of both for the primary relationship: this tracks "does a VASP
    relationship exist, and how" (brand, hop count, attribution, flow
    direction), not "did the BFS re-walk the same conclusion over one more
    piece of evidence" -- so a path- or evidence-only change produces no
    delta, same as it already does not for the primary relationship.

    Sorted by (exchange, hops) so two calls over the same contacts in a
    different order compare equal.
    """
    contacts = row.get("direct_vasp_contacts", []) + row.get("secondary_vasp_contacts", [])
    return sorted(({"exchange": c["exchange"], "hops": c.get("hops", 1),
                    "attribution": c["attribution"], "direction": c["direction"]}
                   for c in contacts), key=lambda c: (c["exchange"], c["hops"]))


def wallet_deltas(before: Dict[str, dict], after: List[dict]) -> List[dict]:
    """What a wallet re-check changed about its reachability to a VASP.

    Compared by entity_id, the same identity wallet_exchange_paths keys its
    rows by. `before` is a dict (this case's own watched wallets only, captured
    before any re-check ran) rather than a list like candidate_deltas takes, because
    diffing against every wallet in the whole case -- most of them not even
    re-checked this run -- would report "changed" for wallets nothing touched.

    No GONE case for the primary relationship: the evidence store is
    append-only, so a path that existed before a re-check cannot vanish
    because one ran -- only gain hops, an endpoint or a direction it did not
    have, never lose one. direct_vasp_contacts/secondary_vasp_contacts (see
    _vasp_contacts) do not get that same guarantee specially enforced --
    relationships live behind status='ACTIVE' in wallet_exchange_paths'
    adjacency query, so a brand a prior cycle reported could in principle be
    suppressed later. Rather than invent removal semantics this loop has no
    evidence are needed for, a contact set change is compared like any other
    FIELDS change: plain inequality, in either direction.
    """
    FIELDS = ("proximity", "hops", "exchange", "attribution", "direction", "risk")
    after_by_id = {p["entity_id"]: p for p in after}
    out = []
    for entity_id, prev in before.items():
        cur = after_by_id.get(entity_id)
        if cur is None:
            continue
        cur_contacts, prev_contacts = _vasp_contacts(cur), _vasp_contacts(prev)
        if (tuple(cur[f] for f in FIELDS) != tuple(prev[f] for f in FIELDS)
                or cur_contacts != prev_contacts):
            out.append({"change": "MOVED", "entity_id": entity_id, "value": cur["value"],
                       "before": {**{f: prev[f] for f in FIELDS}, "vasp_contacts": prev_contacts},
                       "after": {**{f: cur[f] for f in FIELDS}, "vasp_contacts": cur_contacts}})
    for entity_id, cur in after_by_id.items():
        if entity_id not in before:
            out.append({"change": "NEW", "entity_id": entity_id, "value": cur["value"],
                       **{f: cur[f] for f in FIELDS}, "vasp_contacts": _vasp_contacts(cur)})
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
    from .correlate import (_attach_wallet_risk, _attach_wallet_service_intelligence,
                            wallet_exchange_paths)
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
    wallets_before_list = [p for p in wallet_exchange_paths(store) if p["entity_id"] in watched_ids]
    # FIELDS (below) compares risk before/after, same as every other tracked
    # field -- so a wallet whose risk crosses a level with no path/attribution
    # change (a fresh Chainabuse report, a newly tagged mixing hop) still
    # surfaces as MOVED instead of only ever showing up in risk_alerts.
    # _attach_wallet_service_intelligence must run first: risk scoring reads
    # service_tags off each row rather than recomputing it (see
    # _attach_wallet_risk's own docstring).
    _attach_wallet_service_intelligence(store, wallets_before_list)
    _attach_wallet_risk(store, wallets_before_list)
    wallets_before = {p["entity_id"]: p for p in wallets_before_list}
    wallets_checked: List[dict] = []
    for w in wallets:
        module_type = _CHAIN_MODULE_TYPE.get(w["etype"])
        chain_module = get_module(module_type) if module_type else None
        if chain_module is None:
            continue                        # etype without a chain module: nothing to re-run
        chain_module.show_progress = False
        result = await _visit_wallet(chain_module, w["address"], deep=deep, module_type=module_type)
        has_data = bool(result.get("summary"))
        if has_data:
            ingest(result, store)
        wallets_checked.append({
            "address": w["address"], "chain": w["etype"],
            "status": _wallet_verdict(store, w["target_id"]) if has_data else CHECK_FAILED,
        })
    wallets_after = [p for p in wallet_exchange_paths(store) if p["entity_id"] in watched_ids]
    _attach_wallet_service_intelligence(store, wallets_after)
    _attach_wallet_risk(store, wallets_after)
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
    """Synchronous entry point: re-check, then re-correlate and diff.

    Refuses outright against a closed/archived case (via store._require_open,
    the same gate every other new-evidence write already goes through) --
    a watch cycle fetches live data and ingests it, so it is exactly the
    "new investigative fact" mutation a sealed case must stop accruing,
    checked before any live fetch runs rather than partway through one.
    The completed cycle is then persisted to watch_runs (see
    EvidenceStore.record_watch_run) so reopening this case later shows what
    this run found, not only what it printed.
    """
    store._require_open()
    before = read_candidates(store)
    report = asyncio.run(recheck(store, urls=urls, discover=discover, deep=deep))
    if correlate:
        from .correlate import run_correlation
        results = run_correlation(store)
        report["deltas"] = candidate_deltas(before, read_candidates(store))
        report["successors"] = [s for s in results["successors"] if not s["suppressed"]]
        report["contradictions"] = results["contradictions"]
        report["risk_alerts"] = results["risk_alerts"]
        report["data_source_status"] = results["data_source_status"]
        report["narrative"] = watch_narrative(store, case_id or "case", report["deltas"])
    store.record_watch_run(report)
    return report
