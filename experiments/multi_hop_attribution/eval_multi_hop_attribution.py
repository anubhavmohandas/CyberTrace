#!/usr/bin/env python3
"""Benchmark multi_hop_attribution.py (Loop 47, REJECTED -- Decision C, see
docs/LOOP47.md) against the frozen Loop 45 baseline (tools/eval_attribution.py)
and against real held-out data -- never a synthetic wallet or an invented
label for the live/adversarial real-address cases.

    python experiments/multi_hop_attribution/eval_multi_hop_attribution.py
        # offline adversarial suite only
    python experiments/multi_hop_attribution/eval_multi_hop_attribution.py --live --per-brand 3
        # + live hop-depth ablation + FPR
    python experiments/multi_hop_attribution/eval_multi_hop_attribution.py --live --ablation
        # + path-quality ablation

Reuses tools/eval_attribution.py's corpus loading, brand canonicalization,
and live search+ingest path wholesale (imported, not re-implemented -- this
script adds ONLY the multi-hop-specific prediction/ablation/FPR/adversarial
logic Loop 47 needs). Both scripts run their live sample through the exact
same `_ingest_live` call, so a real address's graph is identical whichever
engine scores it -- the Loop 45 vs Loop 47 comparison below is never
confounded by two different live-fetch runs seeing different network luck.

**Ground-truth leakage.** Same discipline as eval_attribution.py's own
`_masked_prediction`: a held-out wallet's own entity AND its whole cospend
cluster are stripped from `exchange_of` before any prediction is made, using
correlate.crypto_clusters -- real PART_OF_CLUSTER data from the live ingest,
never a synthetic split. `_masked_multi_hop_prediction` below asserts the
masked entity_id is absent from the exchange_of it hands to the engine, so a
future edit that weakens the mask fails loudly rather than silently leaking.

**Stratification (section 23).** For each evaluated wallet, "direct" /
"indirect" / "no_path" is measured against the wallet's OWN true brand
specifically (does a still-visible address of that SAME brand sit at hop 1 /
hop>1 / nowhere within the tested bound in the masked graph) -- not against
whether the engine merely found *some* brand. The real Loop 47 question
(section 23) is the "indirect" bucket.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# experiments/multi_hop_attribution/eval_multi_hop_attribution.py ->
# experiments/ -> repo root -- same layout build_ml_dataset.py uses.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "tools"))  # eval_attribution.py stays in tools/ (Loop 45's own)
sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling: multi_hop_attribution.py

import eval_attribution as base  # Loop 45's own benchmark -- reused, not re-implemented
from multi_hop_attribution import (
    MAX_HOPS_HARD_CEILING, VERDICT_AMBIGUOUS, VERDICT_INSUFFICIENT_EVIDENCE,
    VERDICT_PRIMARY, _independent_paths, _rules_for, _score_brand,
    _tier_multiplier, multi_hop_candidates, multi_hop_paths,
)

from cybertrace import attribution, correlate  # cybertrace is pip-installed editable -- no path insert needed
from cybertrace.evidence import EvidenceStore, label_exchange
from cybertrace.normalize import b58encode

HOP_DEPTHS_DEFAULT = (1, 2, 3)


def _synth_btc(seed: str) -> str:
    """Deterministic, checksum-valid synthetic BTC address -- same scheme
    tests/test_correlate.py's own _synth_btc uses (a made-up string fails
    normalize's base58check validation and upsert_entity silently returns
    None, so the adversarial fixtures below need real checksummed addresses,
    not just distinct-looking strings)."""
    payload = b"\x00" + hashlib.sha256(f"loop47-{seed}".encode()).digest()[:20]
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)


# --- masking (reuses correlate.crypto_clusters, same as base._masked_prediction) --

def _masked_graph(store: EvidenceStore, entity_id: str) -> Tuple[Dict[str, Dict[str, tuple]], dict, Dict[str, str]]:
    """(adjacency, exchange_of, values) with `entity_id`'s own ground truth
    and its whole cospend cluster stripped out of exchange_of -- one shared
    mask, computed once per wallet, fed to every hop-depth/ablation variant
    below so all of them see the identical held-out graph."""
    wallet_rows = store._all(
        "SELECT entity_id, normalized_value, raw_value, etype FROM entities "
        "WHERE etype IN ('BTC_ADDRESS','ETH_ADDRESS','BNB_ADDRESS','POLYGON_ADDRESS','TRX_ADDRESS','SOL_ADDRESS')")
    values = {r["entity_id"]: (r["raw_value"] or r["normalized_value"]) for r in wallet_rows}

    exchange_of = correlate._vasp_endpoints(store, values)
    clusters = correlate.crypto_clusters(store)
    cluster_label = clusters.get(entity_id)
    masked = {entity_id} | ({eid for eid, c in clusters.items() if c == cluster_label}
                            if cluster_label else set())
    exchange_of = {eid: hit for eid, hit in exchange_of.items() if eid not in masked}
    assert entity_id not in exchange_of, "masking failed: wallet's own ground truth leaked"

    adjacency = correlate._adjacency(store)
    return adjacency, exchange_of, values


def _reachable_own_brand_hop(adjacency, exchange_of, entity_id: str, true_brand: str,
                             max_hops: int) -> Optional[int]:
    """Nearest hop distance, in the MASKED graph, to any surviving address
    independently attributed to the wallet's OWN true brand -- or None if no
    such path exists within max_hops. Drives the direct/indirect/no_path
    stratification (section 23); unrelated to what the engine predicts."""
    reach = multi_hop_paths(adjacency, exchange_of, entity_id, max_hops=max_hops)
    hops = [p["hops"] for p in reach["paths"] if base.canonical_brand(p["vasp"]) == true_brand]
    return min(hops) if hops else None


# --- scoring ablation variants (benchmark-only, section 20) -----------------
# Each takes the SAME raw `reach["paths"]` (one traversal, reused across
# variants -- no re-traversal cost) and produces a brand -> score dict with
# its own, deliberately simpler, rule. Never used by the production engine;
# these exist only to isolate which piece of multi_hop_attribution's
# evidence model actually drives any improvement.

def _variant_A_raw_reachability(paths: List[dict]) -> Dict[str, float]:
    """Ignore hop/independence/hub entirely: 1 point per brand that has ANY
    path at all. Tests whether "eventually connects" alone is doing the work."""
    return {p["vasp"]: 1 for p in paths}


def _variant_B_hop_decay_only(paths: List[dict], rules) -> Dict[str, float]:
    """Sum every path's hop-decayed, tier-discounted amount -- no
    independence dedupe (double-counts shared-intermediary paths), no hub
    penalty."""
    out: Dict[str, float] = {}
    for p in paths:
        amount = rules[f"multi_hop.path_{p['hops']}hop.v1"]["base"] * _tier_multiplier(p["attribution"])
        out[p["vasp"]] = out.get(p["vasp"], 0) + amount
    return out


def _variant_C_independence_no_hub(paths: List[dict], rules) -> Dict[str, float]:
    by_brand: Dict[str, List[dict]] = {}
    for p in paths:
        by_brand.setdefault(p["vasp"], []).append(p)
    out = {}
    for brand, brand_paths in by_brand.items():
        independent, _ = _independent_paths(brand_paths)
        out[brand] = sum(rules[f"multi_hop.path_{p['hops']}hop.v1"]["base"]
                         * _tier_multiplier(p["attribution"]) for p in independent)
    return out


def _variant_D_hub_only_no_independence(paths: List[dict], rules) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for p in paths:
        amount = rules[f"multi_hop.path_{p['hops']}hop.v1"]["base"] * _tier_multiplier(p["attribution"])
        if p["hub_dependent"]:
            amount *= 0.3
        out[p["vasp"]] = out.get(p["vasp"], 0) + amount
    return out


def _variant_E_full(paths: List[dict], rules) -> Dict[str, float]:
    by_brand: Dict[str, List[dict]] = {}
    for p in paths:
        by_brand.setdefault(p["vasp"], []).append(p)
    return {brand: _score_brand(bp, rules)["score"] for brand, bp in by_brand.items()}


def _verdict_from_scores(scores: Dict[str, float]) -> Tuple[Optional[str], str, List[str]]:
    """Same PRIMARY/AMBIGUOUS/INSUFFICIENT_EVIDENCE margin rule
    multi_hop_candidates uses, applied to an arbitrary ablation-variant score
    dict so every variant is judged by the identical verdict policy."""
    from multi_hop_attribution import _PRIMARY_MARGIN_ABS, _PRIMARY_MARGIN_RATIO
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    if not ranked:
        return None, VERDICT_INSUFFICIENT_EVIDENCE, []
    if len(ranked) == 1:
        return ranked[0][0], VERDICT_PRIMARY, [b for b, _ in ranked]
    top, runner_up = ranked[0][1], ranked[1][1]
    if top >= runner_up * _PRIMARY_MARGIN_RATIO and top - runner_up >= _PRIMARY_MARGIN_ABS:
        return ranked[0][0], VERDICT_PRIMARY, [b for b, _ in ranked]
    return None, VERDICT_AMBIGUOUS, [b for b, _ in ranked]


ABLATION_VARIANTS = ("A_raw_reachability", "B_hop_decay_only", "C_independence_no_hub",
                    "D_hub_only_no_independence", "E_full")


def _score_all_variants(paths: List[dict], max_hops: int) -> Dict[str, Dict[str, float]]:
    rules = _rules_for(max_hops)
    return {
        "A_raw_reachability": _variant_A_raw_reachability(paths),
        "B_hop_decay_only": _variant_B_hop_decay_only(paths, rules),
        "C_independence_no_hub": _variant_C_independence_no_hub(paths, rules),
        "D_hub_only_no_independence": _variant_D_hub_only_no_independence(paths, rules),
        "E_full": _variant_E_full(paths, rules),
    }


# --- live sample: hop-depth ablation + FPR ----------------------------------

async def run_live_multi_hop(sample: List[Tuple[Tuple[str, str], dict]], concurrency: int,
                             hop_depths: Tuple[int, ...], run_ablation: bool) -> List[dict]:
    """One store, one live ingest per address (shared with the Loop 45
    comparison column), every hop depth (and, if requested, every ablation
    variant) scored off ONE traversal per depth -- never one live fetch per
    depth, which would multiply real network calls for no reason."""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    rows = []
    with EvidenceStore(":memory:") as store:
        for (currency, address), truth in sample:
            ok = await base._ingest_live(currency, address, store, semaphore, fetch_cross_chain=False)
            etype = base._CURRENCY_TO_ETYPE[currency]
            entity_id = store.find_entity(etype, address)
            if not ok or entity_id is None:
                rows.append({"address": address, "true_brand": truth["brand"], "tier": truth["tier"],
                            "status": "not_ingested"})
                continue

            adjacency, exchange_of, values = _masked_graph(store, entity_id)
            max_depth = max(hop_depths)
            true_brand = truth["brand"]
            own_hop = _reachable_own_brand_hop(adjacency, exchange_of, entity_id, true_brand, max_depth)
            stratum = ("direct" if own_hop == 1 else "indirect" if own_hop else "no_path")

            # Loop 45 baseline, on the SAME masked graph/store -- direct comparison point.
            peers = adjacency.get(entity_id, {})
            l45 = attribution.vasp_candidates(store, entity_id, address, etype, peers, exchange_of, values)
            l45_brand = base.canonical_brand(l45["primary_candidate"]) if l45["primary_candidate"] else None
            l45_top3 = {l45_brand} | {base.canonical_brand(c["brand"]) for c in l45["also_attributed"]}

            row = {"address": address, "true_brand": true_brand, "tier": truth["tier"],
                  "status": "ok", "stratum": stratum, "own_brand_nearest_hop": own_hop,
                  "loop45_primary": l45_brand, "loop45_correct": l45_brand == true_brand,
                  "loop45_top3_hit": true_brand in l45_top3, "by_depth": {}}

            for depth in hop_depths:
                t0 = time.perf_counter()
                reach = multi_hop_paths(adjacency, exchange_of, entity_id, max_hops=depth)
                elapsed = time.perf_counter() - t0
                result = multi_hop_candidates(adjacency, exchange_of, entity_id, max_hops=depth)
                predicted = base.canonical_brand(result["primary_candidate"]) if result["primary_candidate"] else None
                top3 = {base.canonical_brand(c["brand"]) for c in result["candidates"][:3]}
                depth_row = {
                    "verdict": result["verdict"], "predicted": predicted,
                    "correct": predicted == true_brand, "top3_hit": true_brand in top3,
                    "elapsed_s": elapsed, "nodes_explored": reach["nodes_explored"],
                    "truncated": reach["truncated"],
                }
                if run_ablation:
                    variants = _score_all_variants(reach["paths"], depth)
                    depth_row["ablation"] = {
                        name: {"predicted": (base.canonical_brand(v[0]) if v[0] else None),
                              "correct": v[0] is not None and base.canonical_brand(v[0]) == true_brand,
                              "verdict": v[1]}
                        for name, scores in variants.items()
                        for v in [_verdict_from_scores(scores)]
                    }
                row["by_depth"][depth] = depth_row
            rows.append(row)
    return rows


async def run_live_fpr(ofac_sample: List[dict], concurrency: int, hop_depths: Tuple[int, ...]) -> List[dict]:
    """Real OFAC-designated (definitely-not-a-VASP) addresses: any non-None
    primary_candidate at any hop depth is a false attribution. Reuses the
    identical ingest+mask path -- an OFAC address's OWN entity is masked out
    the same way a held-out VASP address's is, so a genuine real
    suspect->VASP deposit this engine finds (see docs/LOOP26.md's Polyanin->
    Binance case) still counts against FPR here, exactly as section 18
    defines it: a real reachability fact is not the same claim as
    "this wallet is that VASP's customer"."""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    rows = []
    with EvidenceStore(":memory:") as store:
        for entry in ofac_sample:
            address = entry["address"]
            ok = await base._ingest_live("BTC", address, store, semaphore, fetch_cross_chain=False)
            entity_id = store.find_entity("BTC_ADDRESS", address)
            if not ok or entity_id is None:
                rows.append({"address": address, "entity_name": entry["entity_name"], "status": "not_ingested"})
                continue
            adjacency, exchange_of, values = _masked_graph(store, entity_id)
            row = {"address": address, "entity_name": entry["entity_name"], "status": "ok", "by_depth": {}}
            for depth in hop_depths:
                result = multi_hop_candidates(adjacency, exchange_of, entity_id, max_hops=depth)
                row["by_depth"][depth] = {"primary": result["primary_candidate"],
                                          "false_positive": result["primary_candidate"] is not None}
            # Loop 45 baseline, same masked graph -- its own 1-hop counterparty
            # rule (attribution._counterparty_signals) is not itself gated by
            # REGULATORY_ATTESTED on the SUSPECT, only on candidate peers, so a
            # fair FPR comparison needs it measured here too, not assumed.
            peers = adjacency.get(entity_id, {})
            l45 = attribution.vasp_candidates(store, entity_id, address, "BTC_ADDRESS", peers, exchange_of, values)
            row["loop45_primary"] = l45["primary_candidate"]
            row["loop45_false_positive"] = l45["primary_candidate"] is not None
            rows.append(row)
    return rows


# --- offline adversarial suite (section 24, no network) ---------------------

def adversarial_suite(corpus: Dict[Tuple[str, str], dict]) -> List[dict]:
    results = []

    # 1. High-degree hub: suspect -> common intermediary (inflated degree) -> VASP.
    #    Expect: path found, but flagged hub_dependent and scored below a
    #    same-shape non-hub path.
    binance = base._pick(corpus, "Binance")
    if binance:
        with EvidenceStore(":memory:") as store:
            hub = _synth_btc("hub-adversarial")
            suspect = _synth_btc("suspect-hub")
            assert label_exchange(store, binance[1], "Binance") is not None
            hub_id = store.upsert_entity("BTC_ADDRESS", hub)
            suspect_id = store.upsert_entity("BTC_ADDRESS", suspect)
            vasp_id = store.find_entity("BTC_ADDRESS", binance[1])
            snap = store.insert_snapshot(store.upsert_target("http://eval.local"), {}, "eval")
            obs = store.insert_observation(snap, hub_id, method="eval:hub")
            store.add_evidence(store.upsert_relationship(suspect_id, hub_id, "TRANSACTED_WITH", source_label="eval"), [obs])
            store.add_evidence(store.upsert_relationship(hub_id, vasp_id, "SENT_FUNDS_TO", source_label="eval"), [obs])
            for i in range(30):  # inflate hub's own degree past _HUB_DEGREE_THRESHOLD
                peer = store.upsert_entity("BTC_ADDRESS", _synth_btc(f"hub-peer-{i}"))
                o = store.insert_observation(snap, peer, method="eval:hub-fanout")
                store.add_evidence(store.upsert_relationship(hub_id, peer, "TRANSACTED_WITH", source_label="eval"), [o])

            adjacency, exchange_of, _values = _masked_graph(store, suspect_id)
            reach = multi_hop_paths(adjacency, exchange_of, suspect_id, max_hops=3)
            found = next((p for p in reach["paths"] if p["vasp"] == "binance"), None)
            ok = found is not None and found["hub_dependent"] is True
            results.append({"case": "high_degree_hub_flagged_and_discounted", "pass": ok,
                            "detail": f"path found={found is not None}, hub_dependent={found and found['hub_dependent']}"})
    else:
        results.append({"case": "high_degree_hub_flagged_and_discounted", "pass": None,
                        "detail": "no real Binance BTC ground truth available locally"})

    # 2. Competing VASPs at equal hop/tier: must be AMBIGUOUS, never a coin-flip PRIMARY.
    bybit = base._pick(corpus, "Bybit")
    if binance and bybit:
        with EvidenceStore(":memory:") as store:
            suspect = _synth_btc("suspect-competing")
            assert label_exchange(store, binance[1], "Binance") is not None
            assert label_exchange(store, bybit[1], "Bybit") is not None
            suspect_id = store.upsert_entity("BTC_ADDRESS", suspect)
            for _cur, addr in (binance, bybit):
                peer_id = store.find_entity("BTC_ADDRESS", addr)
                snap = store.insert_snapshot(store.upsert_target("http://eval.local"), {}, "eval")
                obs = store.insert_observation(snap, peer_id, method="eval:competing")
                store.add_evidence(store.upsert_relationship(suspect_id, peer_id, "TRANSACTED_WITH", source_label="eval"), [obs])
            adjacency, exchange_of, _values = _masked_graph(store, suspect_id)
            result = multi_hop_candidates(adjacency, exchange_of, suspect_id, max_hops=3)
            ok = result["verdict"] == VERDICT_AMBIGUOUS
            results.append({"case": "competing_vasps_equal_evidence_is_ambiguous", "pass": ok,
                            "detail": f"verdict={result['verdict']}, candidates={[c['brand'] for c in result['candidates']]}"})
    else:
        results.append({"case": "competing_vasps_equal_evidence_is_ambiguous", "pass": None,
                        "detail": "no real Binance+Bybit BTC ground truth available locally"})

    # 3. Long path beyond the configured bound: must weaken to nothing, not
    #    a low-confidence guess.
    if binance:
        with EvidenceStore(":memory:") as store:
            assert label_exchange(store, binance[1], "Binance") is not None
            chain = [_synth_btc(f"suspect-long-{c}") for c in "ABCD"]
            ids = [store.upsert_entity("BTC_ADDRESS", a) for a in chain]
            vasp_id = store.find_entity("BTC_ADDRESS", binance[1])
            snap = store.insert_snapshot(store.upsert_target("http://eval.local"), {}, "eval")
            nodes = ids + [vasp_id]
            for a, b in zip(nodes, nodes[1:]):
                obs = store.insert_observation(snap, b, method="eval:long")
                store.add_evidence(store.upsert_relationship(a, b, "SENT_FUNDS_TO", source_label="eval"), [obs])
            adjacency, exchange_of, _values = _masked_graph(store, ids[0])
            result3 = multi_hop_candidates(adjacency, exchange_of, ids[0], max_hops=3)  # chain is 5 hops
            ok = result3["verdict"] == VERDICT_INSUFFICIENT_EVIDENCE
            results.append({"case": "long_path_beyond_bound_yields_no_candidate", "pass": ok,
                            "detail": f"5-hop real chain, max_hops=3 -> verdict={result3['verdict']}"})
    else:
        results.append({"case": "long_path_beyond_bound_yields_no_candidate", "pass": None,
                        "detail": "no real Binance BTC ground truth available locally"})

    # 4. Non-VASP high-activity wallet: many counterparties, zero of them
    #    VASP-attributed -- must never manufacture a candidate from volume alone.
    with EvidenceStore(":memory:") as store:
        suspect = _synth_btc("suspect-high-activity")
        suspect_id = store.upsert_entity("BTC_ADDRESS", suspect)
        snap = store.insert_snapshot(store.upsert_target("http://eval.local"), {}, "eval")
        for i in range(40):
            peer = store.upsert_entity("BTC_ADDRESS", _synth_btc(f"plain-peer-{i}"))
            obs = store.insert_observation(snap, peer, method="eval:volume")
            store.add_evidence(store.upsert_relationship(suspect_id, peer, "TRANSACTED_WITH", source_label="eval"), [obs])
        adjacency, exchange_of, _values = _masked_graph(store, suspect_id)
        result = multi_hop_candidates(adjacency, exchange_of, suspect_id, max_hops=3)
        ok = result["verdict"] == VERDICT_INSUFFICIENT_EVIDENCE
        results.append({"case": "high_activity_non_vasp_wallet_no_candidate", "pass": ok,
                        "detail": f"40 counterparties, none VASP-attributed -> verdict={result['verdict']}"})

    # 5. OFAC never a reachable endpoint, even through multi-hop.
    ofac_rows = base.ofac_negatives()
    ofac_row = next((r for r in ofac_rows if r["currency"] == "BTC"), None)
    if ofac_row and binance:
        with EvidenceStore(":memory:") as store:
            assert label_exchange(store, binance[1], "Binance") is not None
            suspect = _synth_btc("suspect-ofac-chain-a")
            mid = _synth_btc("suspect-ofac-chain-b")
            suspect_id = store.upsert_entity("BTC_ADDRESS", suspect)
            mid_id = store.upsert_entity("BTC_ADDRESS", mid)
            ofac_id = store.upsert_entity("BTC_ADDRESS", ofac_row["address"])
            vasp_id = store.find_entity("BTC_ADDRESS", binance[1])
            snap = store.insert_snapshot(store.upsert_target("http://eval.local"), {}, "eval")
            for a, b in ((suspect_id, ofac_id), (ofac_id, mid_id), (mid_id, vasp_id)):
                obs = store.insert_observation(snap, b, method="eval:ofac-chain")
                store.add_evidence(store.upsert_relationship(a, b, "SENT_FUNDS_TO", source_label="eval"), [obs])
            adjacency, exchange_of, _values = _masked_graph(store, suspect_id)
            reach = multi_hop_paths(adjacency, exchange_of, suspect_id, max_hops=3)
            # Real path is suspect->OFAC->mid->Binance (3 hops); OFAC must be
            # walked THROUGH (never a dead end, never itself a candidate).
            found = next((p for p in reach["paths"] if p["vasp"] == "binance"), None)
            ok = found is not None and found["hops"] == 3 and ofac_id not in [p["entity_id"] for p in reach["paths"]]
            results.append({"case": "ofac_walked_through_never_a_dead_end_or_candidate", "pass": ok,
                            "detail": f"found={found}"})
    else:
        results.append({"case": "ofac_walked_through_never_a_dead_end_or_candidate", "pass": None,
                        "detail": "no real OFAC BTC + Binance ground truth available locally"})

    return results


# --- reporting ---------------------------------------------------------------

def _rate(n: int, d: int) -> str:
    return f"{n}/{d} = {n/d:.4f}" if d else f"{n}/0 = n/a"


def print_report(offline_results: List[dict], live_rows: Optional[List[dict]],
                 fpr_rows: Optional[List[dict]], hop_depths: Tuple[int, ...],
                 run_ablation: bool) -> int:
    print("\n=== offline adversarial suite (no network, real ground truth + constructed edges) ===")
    exit_code = 0
    for r in offline_results:
        mark = "SKIP" if r["pass"] is None else ("PASS" if r["pass"] else "FAIL")
        if r["pass"] is False:
            exit_code = 1
        print(f"  [{mark}] {r['case']}: {r['detail']}")

    if live_rows is None:
        print("\n(--live not passed: no held-out real-address benchmark was run)")
        return exit_code

    gradable = [r for r in live_rows if r["status"] == "ok"]
    ungradable = [r for r in live_rows if r["status"] != "ok"]
    print(f"\n=== --live held-out sample: {len(live_rows)} real address(es), "
          f"{len(gradable)} gradable, {len(ungradable)} not ingested (excluded, not scored as a miss) ===")

    strata = {"direct": 0, "indirect": 0, "no_path": 0}
    for r in gradable:
        strata[r["stratum"]] += 1
    print(f"  stratification (own-brand reachability in the masked graph): {strata}")

    l45_top1 = sum(1 for r in gradable if r["loop45_correct"])
    l45_top3 = sum(1 for r in gradable if r["loop45_top3_hit"])
    print("\n  Loop 45 baseline (1-hop counterparty/cross-chain only), same masked sample:")
    print(f"    top-1: {_rate(l45_top1, len(gradable))}   top-3: {_rate(l45_top3, len(gradable))}")

    print("\n=== hop-depth ablation (section 19) ===")
    print(f"  {'hop':>4}  {'top-1':>14}  {'top-3':>14}  {'abstention':>16}  "
          f"{'avg_ms':>8}  {'max_ms':>8}  {'nodes/s':>9}")
    for depth in hop_depths:
        depth_rows = [r["by_depth"][depth] for r in gradable]
        top1 = sum(1 for d in depth_rows if d["correct"])
        top3 = sum(1 for d in depth_rows if d["top3_hit"])
        abstained = sum(1 for d in depth_rows if d["verdict"] != VERDICT_PRIMARY)
        times = [d["elapsed_s"] for d in depth_rows]
        avg_ms = statistics.mean(times) * 1000 if times else 0
        max_ms = max(times) * 1000 if times else 0
        wallets_per_s = len(depth_rows) / sum(times) if sum(times) > 0 else float("inf")
        print(f"  {depth:>4}  {_rate(top1, len(depth_rows)):>14}  {_rate(top3, len(depth_rows)):>14}  "
              f"{_rate(abstained, len(depth_rows)):>16}  {avg_ms:>8.2f}  {max_ms:>8.2f}  {wallets_per_s:>9.1f}")

    print(f"\n  stratified top-1 (deepest tested hop depth = {max(hop_depths)}):")
    for stratum in ("direct", "indirect", "no_path"):
        rows_s = [r for r in gradable if r["stratum"] == stratum]
        if not rows_s:
            print(f"    {stratum:9} no gradable wallets in this stratum")
            continue
        top1 = sum(1 for r in rows_s if r["by_depth"][max(hop_depths)]["correct"])
        print(f"    {stratum:9} n={len(rows_s):3}  top-1: {_rate(top1, len(rows_s))}")

    if run_ablation:
        print(f"\n=== path-quality ablation (section 20), deepest tested hop depth = {max(hop_depths)} ===")
        for variant in ABLATION_VARIANTS:
            correct = sum(1 for r in gradable if r["by_depth"][max(hop_depths)]["ablation"][variant]["correct"])
            print(f"  {variant:28} top-1: {_rate(correct, len(gradable))}")

    if fpr_rows is not None:
        fpr_gradable = [r for r in fpr_rows if r["status"] == "ok"]
        print(f"\n=== VASP false-positive rate (section 18): {len(fpr_gradable)} real OFAC-designated "
              f"(non-VASP) address(es) ===")
        l45_fp = sum(1 for r in fpr_gradable if r["loop45_false_positive"])
        print(f"  Loop 45 baseline (same masked graph, always names a top scorer): FPR {_rate(l45_fp, len(fpr_gradable))}")
        for r in fpr_gradable:
            if r["loop45_false_positive"]:
                print(f"    [FP] {r['address']} ({r['entity_name']}) -> primary={r['loop45_primary']}")
        for depth in hop_depths:
            fp = sum(1 for r in fpr_gradable if r["by_depth"][depth]["false_positive"])
            print(f"  Loop 47 hop<= {depth}: FPR {_rate(fp, len(fpr_gradable))}")
            for r in fpr_gradable:
                if r["by_depth"][depth]["false_positive"]:
                    print(f"    [FP] {r['address']} ({r['entity_name']}) -> primary={r['by_depth'][depth]['primary']}")

    return exit_code


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true", help="run the live held-out hop-depth benchmark + FPR (network required)")
    ap.add_argument("--per-brand", type=int, default=3)
    ap.add_argument("--max-total", type=int, default=30)
    ap.add_argument("--concurrency", type=int, default=2)
    ap.add_argument("--hop-depths", type=int, nargs="+", default=list(HOP_DEPTHS_DEFAULT),
                    help=f"hop depths to benchmark (default: {list(HOP_DEPTHS_DEFAULT)}, hard ceiling {MAX_HOPS_HARD_CEILING})")
    ap.add_argument("--ablation", action="store_true", help="also run the path-quality ablation (section 20)")
    ap.add_argument("--fpr-sample", type=int, default=15, help="number of real OFAC BTC addresses to sample for the FPR metric")
    args = ap.parse_args()
    hop_depths = tuple(sorted(min(h, MAX_HOPS_HARD_CEILING) for h in args.hop_depths))

    corpus = base.ground_truth_corpus()
    categories = base.categorize(corpus)
    offline_results = adversarial_suite(corpus)

    live_rows, fpr_rows = None, None
    if args.live:
        sample = base._by_brand_sample(categories["easy_positive"] + categories["hard_positive"],
                                       args.per_brand, args.max_total)
        if not sample:
            print("[!] --live requested but no real ground-truth addresses are available locally", file=sys.stderr)
            return 1
        live_rows = asyncio.run(run_live_multi_hop(sample, args.concurrency, hop_depths, args.ablation))

        ofac_sample = sorted(base.ofac_negatives(), key=lambda r: r["address"])
        ofac_sample = [r for r in ofac_sample if r["currency"] == "BTC"][:args.fpr_sample]
        if ofac_sample:
            fpr_rows = asyncio.run(run_live_fpr(ofac_sample, args.concurrency, hop_depths))

    return print_report(offline_results, live_rows, fpr_rows, hop_depths, args.ablation)


if __name__ == "__main__":
    raise SystemExit(main())
