"""Unknown-wallet -> VASP candidate attribution (Loop 45).

Answers the question `wallet_exchange_paths` cannot: for a wallet with NO
graph path to a VASP-attributed address within `max_hops` (today: simply
absent from that function's output -- the GUI's Wallets tab falls back to
"No traced wallet in this case has a path to a labeled exchange yet"), what,
if anything, can still be said about which VASP it plausibly touches, and how
sure is that -- without ever promoting graph proximity, a single behavioral
pattern, or an unverified label to an ownership claim.

Same discipline as risk.py, applied to a different question:

    reachability confidence (wallet_exchange_paths' hop-decay `confidence`)
        != VASP attribution TIER (correlate.ANALYST_ASSERTED/VASP_DISCLOSED/...)
        != candidate STRENGTH (this module: HIGH/MEDIUM/LOW, never a percentage)

**No opaque scoring.** Every contribution traces to one `RULES` entry with a
`why`, exactly `risk.py`'s pattern (RULES -> features -> contributions ->
capped sum -> named level). The summed number is an internal bucketing
device only -- never returned to a caller, never rendered, never called a
confidence or probability. Loop 45 brief section F is explicit that a
percentage ("Binance -- 87%") requires calibration against a benchmark this
corpus does not yet support; this module ships HIGH/MEDIUM/LOW only.

**OFAC is not a VASP source.** Every signal below reads `correlate.
_vasp_endpoints`' precomputed `exchange_of` dict but explicitly discards any
hit tagged `REGULATORY_ATTESTED` (see `_ground_truth_hit`) -- a sanctioned
entity is not evidence of which exchange a wallet uses, and mixing the two
is exactly the mistake Loop 45 section A forbids.

**Behavioral evidence never creates a candidate by itself.** The brief asks
for transaction-frequency/volume/flow-pattern features (section C.2-C.3),
and is equally explicit that they are "still only behavioural evidence" and
that this engine "must never say it's near Binance, therefore Binance"
(section C.5). `attribution.behavioral_context.v1` is CONTEXTUAL: it can
only add color to a brand already named by a counterparty or cross-chain
signal, never name one on its own. A wallet with exchange-like flow but zero
corroborating source stays with no candidates at all -- the section M
adversarial case ("high-volume personal wallet") this is built to resist.

**Counterparty overlap is 1-hop only, not a second BFS.** `wallet_exchange_
paths` already walks TRANSACTED_WITH/SENT_FUNDS_TO/PART_OF_CLUSTER up to
`max_hops` and would have found any of THIS wallet's 1..max_hops peers that
carry a VASP attribution -- so for a wallet already absent from its output,
1-hop counterparty overlap against the SAME `exchange_of` dict is
necessarily empty in production (this is provable, not a guess: see
correlate.unattributed_wallet_candidates, which only calls this module for
wallets `_vasp_endpoints`/`wallet_exchange_paths` already ruled out). It is
NOT empty in `tools/eval_attribution.py`'s benchmark, which deliberately
masks a held-out wallet's own ground truth (and its cluster-mates) before
calling this module directly -- that is the actual test: can the engine
reconstruct a real label from peers/cross-chain/behavior alone, with the
answer hidden. Kept as its own rule regardless, both for that benchmark and
for any future direct caller that has not already run the graph BFS.

**Cross-chain corroboration is real transaction evidence, not inference.**
Reads `store.cross_chain_tx_links_for` -- the real Wormhole/THORChain/
Across/LI.FI bridge-and-swap records Loop 42/44 wired in -- never address
timing or amount matching.

No new external API. Every field this module reads (`store.metadata`,
`relationships`, `cross_chain_tx_links`, `_vasp_endpoints`'s own sources) is
already fetched/ingested elsewhere in this codebase.
"""

from __future__ import annotations

from typing import Dict, List, Optional

ATTRIBUTION_POLICY_VERSION = "attribution-v1"

CANDIDATE, CORROBORATED, ATTESTED = "CANDIDATE", "CORROBORATED", "ATTESTED"
HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"

COUNTERPARTY, CROSS_CHAIN, CONTEXTUAL = "COUNTERPARTY", "CROSS_CHAIN", "CONTEXTUAL"

# POLICY-DEFINED, not empirically calibrated -- same admission as risk.py's
# LEVEL_THRESHOLDS/CATEGORY_CAP (no labelled corpus exists to fit this
# against yet; tools/eval_attribution.py is the first step toward one).
RULES: Dict[str, dict] = {
    "attribution.counterparty_overlap.v1": {
        "signal_type": COUNTERPARTY, "base": 30,
        "why": "This wallet directly transacted with (or was co-spent with) an "
               "address independently attributed to this brand -- the same "
               "counterparty/cospend edges wallet_exchange_paths reads, but "
               "surfaced per-brand rather than stopping at the first match a "
               "shortest-path search happens to reach, so a wallet touching two "
               "different VASPs' addresses shows both (section G).",
    },
    "attribution.cross_chain_corroboration.v1": {
        "signal_type": CROSS_CHAIN, "base": 35,
        "why": "A real bridge/swap transaction (Wormhole/THORChain/Across/LI.FI -- "
               "see correlate.cross_chain_links' own sourcing) ties this wallet to "
               "an address on another chain that is independently attributed to "
               "this brand. Weighted above a same-chain counterparty touch: a "
               "distinct transaction record naming both sides is stronger than an "
               "ordinary payment edge.",
    },
    "attribution.behavioral_context.v1": {
        "signal_type": CONTEXTUAL, "base": 8,
        "why": "Consolidation-like flow (many counterparties, net inflow) is "
               "consistent with an operational/exchange-style wallet, but this "
               "codebase has no per-brand behavioral profile to tell Binance's "
               "typical hot-wallet shape from Bybit's, or from an ordinary "
               "high-volume personal wallet's -- contextual only, and by "
               "construction (see _score below) can never create a brand "
               "candidate on its own.",
    },
}

# Per-brand ceiling on the counterparty/cross-chain rules -- an omnibus VASP
# wallet touched by many unrelated addresses must not let sheer peer COUNT
# manufacture HIGH by itself, same reasoning as correlate.wallet_exchange_
# paths' own endpoint_shared_by/vasp_shared_by omnibus guards.
_SIGNAL_CAP = {COUNTERPARTY: 60, CROSS_CHAIN: 70, CONTEXTUAL: 8}

# POLICY-DEFINED strength buckets over the internal (never-exposed) summed
# score -- deliberately coarse, mirroring risk.py's LEVEL_THRESHOLDS.
_STRENGTH_THRESHOLDS = ((30, LOW), (70, MEDIUM), (None, HIGH))

# Third-party tags (correlate.TAG_ATTESTED) are a community guess, so a
# candidate resting only on tag-attested peers is discounted relative to a
# VASP's own disclosure or an analyst's cited claim. Applied to base amounts,
# never to strength buckets directly, so the "why" for the resulting number
# stays a plain base*multiplier like every rule in risk.py.
def _tier_multiplier(attribution: str) -> float:
    from .correlate import TAG_ATTESTED
    return 0.6 if attribution == TAG_ATTESTED else 1.0


def _ground_truth_hit(exchange_of: dict, entity_id: Optional[str]) -> Optional[dict]:
    """One entry of correlate._vasp_endpoints' output, or None -- filtering out
    REGULATORY_ATTESTED (OFAC) every time, structurally, so no caller in this
    module can accidentally treat a sanctions designation as VASP evidence
    (Loop 45 section A)."""
    from .correlate import REGULATORY_ATTESTED
    if not entity_id:
        return None
    hit = exchange_of.get(entity_id)
    if not hit or hit["attribution"] == REGULATORY_ATTESTED:
        return None
    return hit


def wallet_fingerprint(store, entity_id: str, counterparty_count: Optional[int] = None) -> dict:
    """Named, explainable behavioral facts about one address -- never a
    manufactured zero. `counterparty_count` is accepted rather than
    recomputed when the caller already built the peer adjacency (same
    "read only what callers already computed" discipline as risk.py's
    `_extract_features`); computed fresh from `relationships` otherwise.

    `total_received`/`total_sent` are BTC-chain-only today (see
    evidence.enrich_bitcoin and bitcoin_module._build_summary -- only
    blockchain.com's rawaddr response reports these) -- None on every other
    chain, which `_score` already treats as "no basis", not zero.
    """
    md = store.metadata(entity_id) if entity_id else {}
    tx_count = md.get("tx_count")
    total_received = md.get("total_received")
    total_sent = md.get("total_sent")

    if counterparty_count is None:
        row = store._one(
            "SELECT COUNT(DISTINCT peer) AS n FROM ("
            "  SELECT target_entity_id AS peer FROM relationships "
            "  WHERE source_entity_id=? AND status='ACTIVE' "
            "  AND rtype IN ('TRANSACTED_WITH','SENT_FUNDS_TO','PART_OF_CLUSTER') "
            "  UNION "
            "  SELECT source_entity_id AS peer FROM relationships "
            "  WHERE target_entity_id=? AND status='ACTIVE' "
            "  AND rtype IN ('TRANSACTED_WITH','SENT_FUNDS_TO','PART_OF_CLUSTER'))",
            (entity_id, entity_id))
        counterparty_count = row["n"] if row else 0

    net_flow_ratio = None
    if total_received is not None and total_sent is not None and (total_received + total_sent) > 0:
        net_flow_ratio = round(total_received / (total_received + total_sent), 4)

    avg_tx_value = None
    if tx_count and total_received is not None and total_sent is not None:
        avg_tx_value = round((total_received + total_sent) / tx_count, 8)

    return {
        "tx_count": tx_count, "total_received": total_received, "total_sent": total_sent,
        "counterparty_count": counterparty_count,
        "net_flow_ratio": net_flow_ratio, "avg_tx_value": avg_tx_value,
    }


# Consolidation-like shape: enough distinct counterparties, and funds net
# flowing IN, to be worth mentioning as context -- not a threshold fit to any
# labelled data, a documented editorial floor to keep single-counterparty
# wallets from getting a "consolidation pattern" note that means nothing at
# n=1. See the module docstring: this can never create a candidate, only
# annotate one that already exists from a real source.
_CONSOLIDATION_MIN_COUNTERPARTIES = 5
_CONSOLIDATION_MIN_INFLOW_RATIO = 0.6


def _behavioral_note(fp: dict) -> Optional[str]:
    n, ratio = fp.get("counterparty_count"), fp.get("net_flow_ratio")
    if n is not None and n >= _CONSOLIDATION_MIN_COUNTERPARTIES and \
            ratio is not None and ratio >= _CONSOLIDATION_MIN_INFLOW_RATIO:
        return (f"consolidation-like pattern: {n} distinct counterparties, "
                f"net inflow ratio {ratio}")
    return None


def _counterparty_signals(peers: Dict[str, tuple], exchange_of: dict,
                          values: Dict[str, str]) -> List[dict]:
    """One signal per DISTINCT peer address that is itself VASP-attributed --
    every matching peer, not the first (see module docstring: this is what
    lets two different brands both surface for the same wallet)."""
    out = []
    for peer_id in peers:
        hit = _ground_truth_hit(exchange_of, peer_id)
        if not hit:
            continue
        peer_address = values.get(peer_id, peer_id)
        out.append({"rule_id": "attribution.counterparty_overlap.v1",
                    "brand": hit["exchange"], "attribution": hit["attribution"],
                    "attribution_source": hit["attribution_source"],
                    "peer_address": peer_address,
                    "evidence_ids": hit.get("evidence_ids") or [],
                    "detail": f"direct counterparty {peer_address} is independently "
                              f"attributed to {hit['exchange']}"})
    return out


def _cross_chain_signals(store, wallet_address: str, exchange_of: dict) -> List[dict]:
    out = []
    for link in store.cross_chain_tx_links_for(wallet_address):
        if link.get("source_address") == wallet_address:
            other_chain, other_addr = link.get("dest_chain"), link.get("dest_address")
        else:
            other_chain, other_addr = link.get("source_chain"), link.get("source_address")
        if not other_chain or not other_addr:
            continue
        other_id = store.find_entity(other_chain, other_addr)
        hit = _ground_truth_hit(exchange_of, other_id)
        if not hit:
            continue
        out.append({"rule_id": "attribution.cross_chain_corroboration.v1",
                    "brand": hit["exchange"], "attribution": hit["attribution"],
                    "attribution_source": hit["attribution_source"],
                    "peer_address": other_addr, "peer_chain": other_chain,
                    "mechanism": link.get("mechanism"), "evidence_ref": link.get("evidence_ref"),
                    "evidence_ids": hit.get("evidence_ids") or [],
                    "detail": f"a real {(link.get('mechanism') or 'cross-chain').lower()} "
                              f"transaction links this wallet to {other_addr} "
                              f"({other_chain}), independently attributed to "
                              f"{hit['exchange']} [ref: {link.get('evidence_ref')}]"})
    return out


def _score_brand(signals: List[dict]) -> dict:
    """Sum this brand's signals under their rule's base*tier-multiplier,
    capped per signal_type (same shape as risk.py's `_score`/CATEGORY_CAP),
    then bucket into HIGH/MEDIUM/LOW. The summed number is returned only for
    `_strength`'s own use -- callers of vasp_candidates never see it."""
    by_type: Dict[str, List[dict]] = {}
    for s in signals:
        rule = RULES[s["rule_id"]]
        amount = round(rule["base"] * _tier_multiplier(s["attribution"]))
        by_type.setdefault(rule["signal_type"], []).append({**s, "amount": amount})

    kept, total = [], 0
    for signal_type, items in by_type.items():
        cap = _SIGNAL_CAP.get(signal_type, 0)
        running = 0
        for item in sorted(items, key=lambda i: -i["amount"]):
            room = max(cap - running, 0)
            applied = max(min(item["amount"], room), 0)
            running += applied
            total += applied
            kept.append({**item, "applied_amount": applied})

    return {"contributions": kept, "score": total}


def _strength(score: int) -> str:
    for ceiling, name in _STRENGTH_THRESHOLDS:
        if ceiling is None or score < ceiling:
            return name
    return HIGH


def vasp_candidates(store, wallet_entity_id: str, wallet_address: str, chain: str,
                    peers: Dict[str, tuple], exchange_of: dict, values: Dict[str, str]) -> dict:
    """The candidate-VASP object for one wallet that has no direct
    attribution and no `wallet_exchange_paths` hit of its own.

    `peers` is that wallet's own adjacency entry (peer entity_id -> (obs_ids,
    flow set)), `exchange_of` is correlate._vasp_endpoints' full precomputed
    dict, `values` resolves peer entity_ids to addresses for citation --
    all three already computed once by the caller (correlate.
    unattributed_wallet_candidates), never requeried here. `peers` doubles
    as the fingerprint's own counterparty_count (`len(peers)`) -- the caller
    already built this exact adjacency, so asking wallet_fingerprint to
    re-derive it with a second `relationships` query would both waste the
    query and risk silently disagreeing with what `peers` itself says.

    Returns `{primary_candidate, also_attributed, status, strength,
    supporting_signals, contradicting_signals, behavioral_note,
    policy_version}`. `primary_candidate`/`also_attributed` are None/[] when
    no real signal exists at all -- never a forced answer (section M).
    """
    fp = wallet_fingerprint(store, wallet_entity_id, counterparty_count=len(peers))
    behavioral_note = _behavioral_note(fp)

    raw_signals = (_counterparty_signals(peers, exchange_of, values)
                  + _cross_chain_signals(store, wallet_address, exchange_of))

    by_brand: Dict[str, List[dict]] = {}
    for s in raw_signals:
        by_brand.setdefault(s["brand"], []).append(s)

    brands = []
    for brand, signals in by_brand.items():
        scored = _score_brand(signals)
        signal_types = {RULES[s["rule_id"]]["signal_type"] for s in signals}
        if behavioral_note and scored["score"] > 0:
            # Contextual color on an already-real candidate only -- see
            # RULES["attribution.behavioral_context.v1"]'s own "why".
            ctx_amount = round(RULES["attribution.behavioral_context.v1"]["base"])
            scored["contributions"].append({
                "rule_id": "attribution.behavioral_context.v1", "brand": brand,
                "attribution": None, "attribution_source": "wallet_fingerprint",
                "applied_amount": ctx_amount, "detail": behavioral_note})
            scored["score"] += ctx_amount
        # ATTESTED (this address itself is a verified VASP address) never
        # applies here -- correlate.unattributed_wallet_candidates only calls
        # this function for wallets _vasp_endpoints already ruled out of that
        # case; that status is wallet_exchange_paths' AT_VASP row, not
        # duplicated by this module. CORROBORATED requires two INDEPENDENT
        # signal types agreeing (never two counterparty peers of the same
        # type, which is still one kind of evidence) -- see section D/N.
        status = CORROBORATED if len(signal_types) >= 2 else CANDIDATE
        brands.append({
            "brand": brand, "strength": _strength(scored["score"]), "status": status,
            "supporting_signals": scored["contributions"],
            "sources": sorted({s["attribution_source"] for s in signals}),
        })

    if not brands:
        return {"policy_version": ATTRIBUTION_POLICY_VERSION,
                "primary_candidate": None, "also_attributed": [],
                "status": None, "strength": None,
                "supporting_signals": [], "contradicting_signals": [],
                "behavioral_note": behavioral_note, "fingerprint": fp}

    # Strongest internal score first (never exposed -- see _score_brand);
    # ties broken by brand name for deterministic output.
    brands.sort(key=lambda b: (-sum(c["applied_amount"] for c in b["supporting_signals"]),
                               b["brand"]))
    primary, rest = brands[0], brands[1:]
    return {
        "policy_version": ATTRIBUTION_POLICY_VERSION,
        "primary_candidate": primary["brand"], "status": primary["status"],
        "strength": primary["strength"],
        "supporting_signals": primary["supporting_signals"], "sources": primary["sources"],
        # Real, distinct brand claims on the SAME wallet, never merged or
        # dropped -- the section G conflict-preservation rule, same shape as
        # correlate's existing `also_attributed` field.
        "also_attributed": [{"brand": b["brand"], "strength": b["strength"],
                             "status": b["status"], "sources": b["sources"]}
                            for b in rest],
        "contradicting_signals": rest,
        "behavioral_note": behavioral_note, "fingerprint": fp,
    }
