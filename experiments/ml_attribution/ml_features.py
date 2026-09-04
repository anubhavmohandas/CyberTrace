"""Wallet feature vectors for Loop 46's ML-vs-rules VASP attribution
benchmark.

EXPERIMENTAL, not production. Benchmarked against attribution.py's rule
engine in docs/LOOP46.md; decision was C (don't integrate) -- the real
labelled corpus is too small/skewed for ML to clear the false-positive bar.
Lives under experiments/ml_attribution/, outside the cybertrace/ package, so
it is never imported by anything CyberTrace actually ships. Kept, tested,
and runnable so a future, larger real corpus can be benchmarked again
without rebuilding this from scratch -- see this folder's README.md.

No sklearn import here -- this module only turns store/correlate data
already computed elsewhere into a fixed-schema numeric vector; every model
lives in ml_attribution.py (same folder) so a feature-extraction bug can
never be a training-pipeline bug and vice versa.

Two independent sources feed the same `FEATURE_SCHEMA`, never mixed at the
row level (see `feature_source` in each extractor's output):

  "cybertrace"  `extract_features` -- reads this codebase's own store via
                the exact functions attribution.py/correlate.py already use
                (`correlate._adjacency`, `_vasp_endpoints`,
                `_secondary_vasp_reach`, `crypto_clusters`,
                `attribution.wallet_fingerprint`,
                `store.cross_chain_tx_links_for`). No new query shape, no
                second BFS engine.

  "ellipticpp"  `extract_features_ellipticpp` -- reads the already-indexed,
                offline Elliptic++ dataset (`cybertrace.integrations.
                ellipticpp`). VASP-tagpack overlap with this dataset is
                negligible (~0.06%, checked directly against the real index
                before writing this module), so it can never supply a
                positive (VASP-labelled) example -- it exists here only to
                give the negative/adversarial side of the Loop 46 benchmark
                a large, real, offline "known non-VASP wallet" population
                instead of leaving that category NOT TESTABLE. Its own
                module docstring's safety boundary ("dataset_label is
                non-attributive, never written as ownership evidence") is
                about CyberTrace's evidence store; reading its 55 real
                engineered columns as ML training features doesn't cross
                that line, because nothing this module or ml_attribution.py
                produces is ever written back as evidence either.

Every value is `float | None` -- `None` means no real basis to compute this
feature for this wallet, never a manufactured 0. `FEATURE_SCHEMA` is the
single fixed column order both extractors and every model in
ml_attribution.py share, so a row from either source always has the same
shape.

Three of the brief's requested behavioural features -- transaction
regularity, batching behaviour, sweep-like behaviour -- have NO real basis
in either source: `evidence.py` stores only aggregate tx_count/total_received
/total_sent per address (confirmed -- no per-transaction table exists
anywhere in this codebase), and Elliptic++'s wallet file is likewise one
lifetime-aggregate row per address, not a per-transaction timeline. One
defensible real proxy exists (Elliptic++ only): total_txs per active
timestep, as `behav_transaction_regularity`. The other two stay `None` for
every wallet from every source -- reported NOT TESTABLE in the benchmark,
never faked.
"""

from __future__ import annotations

from typing import Dict, Optional

FEATURE_SCHEMA = (
    # transaction -- real aggregate counts, BTC-chain-only (only
    # blockchain.com's rawaddr response reports these; see
    # attribution.wallet_fingerprint's own docstring).
    "txn_tx_count", "txn_total_received", "txn_total_sent",
    "txn_avg_tx_value", "txn_net_flow_ratio",
    # counterparty -- from the wallet's own adjacency slice.
    "cp_counterparty_count", "cp_unique_incoming", "cp_unique_outgoing",
    "cp_counterparty_frequency",
    # graph -- from the shared adjacency/exchange_of/cluster machinery
    # correlate.py's own BFS (wallet_exchange_paths/_secondary_vasp_reach)
    # already computes.
    "graph_degree", "graph_vasp_neighbor_count", "graph_distance_to_vasp",
    "graph_vasp_brand_count", "graph_cluster_size",
    # cross-chain -- real Wormhole/THORChain/Across/LI.FI transaction
    # records (store.cross_chain_tx_links_for), never address/timing
    # matching.
    "xchain_link_count", "xchain_destination_chain_count",
    "xchain_known_vasp_destination_count", "xchain_bridge_count",
    "xchain_swap_count",
    # behavioural -- see module docstring: only a regularity proxy has any
    # real basis, and only for Elliptic++-sourced rows.
    "behav_transaction_regularity", "behav_batching_behavior",
    "behav_sweep_like_behavior",
)


def _empty_features() -> Dict[str, Optional[float]]:
    return {k: None for k in FEATURE_SCHEMA}


def extract_features(store, entity_id: str, address: str, chain: str,
                     adjacency: Dict[str, Dict[str, tuple]],
                     exchange_of: Dict[str, dict],
                     clusters: Optional[Dict[str, str]] = None,
                     max_hops: int = 4) -> dict:
    """One CyberTrace-sourced feature row for `entity_id`.

    `adjacency`/`exchange_of`/`clusters` are precomputed once by the caller
    (correlate._adjacency / correlate._vasp_endpoints / correlate.
    crypto_clusters) and passed in -- same "read only what the caller
    already built" discipline attribution.vasp_candidates uses, so scoring
    N wallets in one case never re-runs these queries N times.
    """
    from cybertrace import attribution
    from cybertrace.correlate import _secondary_vasp_reach

    peers = adjacency.get(entity_id, {})
    fp = attribution.wallet_fingerprint(store, entity_id, counterparty_count=len(peers))

    unique_incoming = sum(1 for _obs, flows in peers.values() if False in flows)
    unique_outgoing = sum(1 for _obs, flows in peers.values() if True in flows)
    counterparty_frequency = (round(fp["tx_count"] / len(peers), 4)
                              if fp["tx_count"] and peers else None)

    vasp_neighbor_count = sum(1 for peer_id in peers
                              if attribution._ground_truth_hit(exchange_of, peer_id))
    reach = _secondary_vasp_reach(adjacency, exchange_of, entity_id, max_hops)
    # _secondary_vasp_reach dead-ends at any VASP-attributed node including
    # REGULATORY_ATTESTED ones (it only excludes `start`'s own brand, not
    # OFAC) -- filter those out here the same way attribution.py's own
    # counterparty/cross-chain signals do, so an OFAC neighbour can never
    # shorten this wallet's reported distance-to-VASP.
    from cybertrace.correlate import REGULATORY_ATTESTED
    reach = {b: v for b, v in reach.items() if v["attribution"] != REGULATORY_ATTESTED}
    distance_to_vasp = min((v["hops"] for v in reach.values()), default=None)

    cluster_label = (clusters or {}).get(entity_id)
    cluster_size = (sum(1 for v in clusters.values() if v == cluster_label)
                    if clusters and cluster_label else None)

    xchain = _cross_chain_features(store, address, exchange_of)

    out = _empty_features()
    out.update({
        "txn_tx_count": fp["tx_count"], "txn_total_received": fp["total_received"],
        "txn_total_sent": fp["total_sent"], "txn_avg_tx_value": fp["avg_tx_value"],
        "txn_net_flow_ratio": fp["net_flow_ratio"],
        # cp_counterparty_count and graph_degree are the same value on
        # purpose -- one wallet-peer adjacency, read once, named twice to
        # match the brief's own Counterparty/Graph section split rather than
        # inventing two different definitions of "how many peers".
        "cp_counterparty_count": float(len(peers)),
        "cp_unique_incoming": float(unique_incoming), "cp_unique_outgoing": float(unique_outgoing),
        "cp_counterparty_frequency": counterparty_frequency,
        "graph_degree": float(len(peers)),
        "graph_vasp_neighbor_count": float(vasp_neighbor_count),
        "graph_distance_to_vasp": float(distance_to_vasp) if distance_to_vasp is not None else None,
        "graph_vasp_brand_count": float(len(reach)),
        "graph_cluster_size": float(cluster_size) if cluster_size is not None else None,
        **xchain,
    })
    return {"meta": {"entity_id": entity_id, "address": address, "chain": chain,
                     "feature_source": "cybertrace"},
            "features": out}


def _cross_chain_features(store, address: str, exchange_of: dict) -> Dict[str, Optional[float]]:
    """Same real per-link data attribution._cross_chain_signals reads,
    aggregated into counts instead of per-brand signals."""
    from cybertrace import attribution

    links = store.cross_chain_tx_links_for(address)
    if not links:
        return {"xchain_link_count": 0.0, "xchain_destination_chain_count": 0.0,
                "xchain_known_vasp_destination_count": 0.0,
                "xchain_bridge_count": 0.0, "xchain_swap_count": 0.0}

    dest_chains, vasp_dests = set(), set()
    bridge_count = swap_count = 0
    for link in links:
        if link.get("mechanism") == "BRIDGE":
            bridge_count += 1
        elif link.get("mechanism") == "SWAP":
            swap_count += 1
        if link.get("source_address") == address:
            other_chain, other_addr = link.get("dest_chain"), link.get("dest_address")
        else:
            other_chain, other_addr = link.get("source_chain"), link.get("source_address")
        if not other_chain or not other_addr:
            continue
        dest_chains.add(other_chain)
        other_id = store.find_entity(other_chain, other_addr)
        if attribution._ground_truth_hit(exchange_of, other_id):
            vasp_dests.add(other_id)

    return {"xchain_link_count": float(len(links)),
            "xchain_destination_chain_count": float(len(dest_chains)),
            "xchain_known_vasp_destination_count": float(len(vasp_dests)),
            "xchain_bridge_count": float(bridge_count),
            "xchain_swap_count": float(swap_count)}


def extract_features_ellipticpp(address: str, record: dict, neighbor_limit: int = 1000) -> dict:
    """One negative/adversarial-class feature row from the offline
    Elliptic++ index. `record` is `cybertrace.integrations.ellipticpp.
    lookup_wallet(address)`'s own return value -- this function never opens
    the index itself, keeping the sqlite/CSV boundary in one place.

    Only transaction/behavioural/degree columns have a real mapping onto
    `FEATURE_SCHEMA`; graph_vasp_*/graph_cluster_size/xchain_* stay None
    (this dataset carries no VASP labels or cross-chain data at all -- "no
    basis", not "zero", since VASP-reachability was never even checked for
    these wallets). `neighbor_limit` matches ellipticpp.wallet_neighbors'
    own cap.
    # occam: degree is capped at neighbor_limit for a pathological hub
    # rather than an exact uncapped count -- raise neighbor_limit if a real
    # case needs one.
    """
    from cybertrace.integrations import ellipticpp

    f = record["features"]

    def _num(key):
        v = f.get(key)
        try:
            return float(v) if v not in (None, "") else None
        except (TypeError, ValueError):
            return None

    total_txs, received, sent = _num("total_txs"), _num("btc_received_total"), _num("btc_sent_total")
    net_flow_ratio = (round(received / (received + sent), 4)
                      if received is not None and sent is not None and (received + sent) > 0
                      else None)
    timesteps = _num("num_timesteps_appeared_in")
    regularity = (round(total_txs / timesteps, 4)
                 if total_txs is not None and timesteps and timesteps > 0 else None)

    neighbors = ellipticpp.wallet_neighbors(address, limit=neighbor_limit)
    degree = float(len(neighbors))

    out = _empty_features()
    out.update({
        "txn_tx_count": total_txs, "txn_total_received": received, "txn_total_sent": sent,
        "txn_avg_tx_value": _num("btc_transacted_mean"), "txn_net_flow_ratio": net_flow_ratio,
        "cp_counterparty_count": degree, "graph_degree": degree,
        "cp_counterparty_frequency": (round(total_txs / degree, 4)
                                      if total_txs is not None and degree else None),
        "behav_transaction_regularity": regularity,
    })
    return {"meta": {"entity_id": None, "address": address, "chain": "bitcoin",
                     "feature_source": "ellipticpp",
                     "dataset_label_name": record.get("dataset_label_name")},
            "features": out}


def demo() -> None:
    """occam self-check: schema stays consistent, missing stays None, empty
    adjacency/exchange_of/links never crash."""
    empty = _empty_features()
    assert set(empty) == set(FEATURE_SCHEMA)
    assert all(v is None for v in empty.values())

    xchain = _cross_chain_features(_NoLinksStore(), "1Addr", {})
    assert xchain["xchain_link_count"] == 0.0
    assert xchain["xchain_known_vasp_destination_count"] == 0.0
    print("ml_features.demo: OK")


class _NoLinksStore:
    def cross_chain_tx_links_for(self, address):
        return []


if __name__ == "__main__":
    demo()
