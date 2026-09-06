"""Loop 53: cybertrace/investigation_graph.py -- pure construction over
already-computed wallet-trace/transaction/cross-chain data."""
from cybertrace.investigation_graph import (
    BRIDGE, BRIDGE_TRANSFER, PARTICIPATED_IN, SENT_TO, SWAP, SWAP_SERVICE,
    TRANSACTION, VASP, VASP_EXPOSURE, WALLET, build_from_wallet_trace,
)


def _trace(**overrides):
    base = {
        "address": "1Suspect", "chain": "BTC_ADDRESS",
        "path": ["1Suspect"], "hops": None, "direction": None,
        "exchange_confidence": None, "evidence_ids": [],
        "vasp_investigation": {"primary_vasp": None, "candidate_vasps": [],
                               "confidence": None, "evidence": [], "provenance": [],
                               "attribution_tier": None, "control_status": "UNKNOWN"},
    }
    base.update(overrides)
    return base


def test_direct_transfer_single_hop_to_vasp():
    trace = _trace(path=["1Suspect", "1BinanceHot"], hops=1, direction="TO_VASP",
                   exchange_confidence=0.75,
                   vasp_investigation={"primary_vasp": "Binance", "candidate_vasps": [],
                                       "confidence": "HIGH", "evidence": [{"brand": "Binance"}],
                                       "provenance": ["DIRECT_VASP_EXPOSURE"],
                                       "attribution_tier": "VASP_DISCLOSED",
                                       "control_status": "ESTABLISHED"})
    g = build_from_wallet_trace(trace)
    d = g.to_dict()
    node_types = {n["type"] for n in d["nodes"]}
    assert WALLET in node_types and VASP in node_types
    exposure_edges = [e for e in d["edges"] if e["rel"] == VASP_EXPOSURE]
    assert len(exposure_edges) == 1
    assert exposure_edges[0]["control_status"] == "ESTABLISHED"
    sent_edges = [e for e in d["edges"] if e["rel"] == SENT_TO]
    assert len(sent_edges) == 1


def test_multi_hop_path_never_becomes_ownership():
    """Multi-hop path to a VASP must still only ever produce EXPOSURE edges,
    never a control claim on an intermediate hop."""
    trace = _trace(path=["1Suspect", "1Mid1", "1Mid2", "1Kraken"], hops=3,
                   direction="TO_VASP",
                   vasp_investigation={"primary_vasp": "Kraken", "candidate_vasps": [],
                                       "confidence": "LOW", "evidence": [],
                                       "provenance": ["MULTI_HOP_VASP_EXPOSURE"],
                                       "attribution_tier": "TAG_ATTESTED",
                                       "control_status": "NOT_ESTABLISHED"})
    g = build_from_wallet_trace(trace)
    d = g.to_dict()
    sent_edges = [e for e in d["edges"] if e["rel"] == SENT_TO]
    assert len(sent_edges) == 3  # suspect->mid1->mid2->kraken
    exposure = [e for e in d["edges"] if e["rel"] == VASP_EXPOSURE][0]
    assert exposure["control_status"] == "NOT_ESTABLISHED"


def test_duplicate_transaction_rows_do_not_duplicate_nodes():
    trace = _trace()
    txs = [
        {"tx_hash": "h1", "counterparty": "1Peer", "chain": "BTC_ADDRESS",
         "provider": "blockchain.com", "status": "FOUND", "value": 0.5,
         "asset": "BTC", "direction": "OUT", "timestamp": "2026-01-01T00:00:00+00:00"},
        {"tx_hash": "h1", "counterparty": "1Peer", "chain": "BTC_ADDRESS",
         "provider": "blockchain.com", "status": "FOUND", "value": 0.5,
         "asset": "BTC", "direction": "OUT", "timestamp": "2026-01-01T00:00:00+00:00"},
    ]
    g = build_from_wallet_trace(trace, transactions=txs)
    tx_nodes = [n for n in g.nodes.values() if n["type"] == TRANSACTION]
    assert len(tx_nodes) == 1


def test_cycle_suspect_appears_as_its_own_counterparty_is_handled():
    """A malformed/self-referential tx row must not crash graph construction."""
    trace = _trace()
    txs = [{"tx_hash": "h1", "counterparty": "1Suspect", "chain": "BTC_ADDRESS",
           "provider": "x", "status": "FOUND", "value": 0.1, "asset": "BTC",
           "direction": "OUT", "timestamp": "2026-01-01T00:00:00+00:00"}]
    g = build_from_wallet_trace(trace, transactions=txs)
    assert len(g.nodes) >= 1  # did not raise


def test_bounded_transaction_traversal():
    trace = _trace()
    txs = [{"tx_hash": f"h{i}", "counterparty": f"1Peer{i}", "chain": "BTC_ADDRESS",
           "provider": "x", "status": "FOUND", "value": 0.1, "asset": "BTC",
           "direction": "OUT", "timestamp": "2026-01-01T00:00:00+00:00"} for i in range(50)]
    g = build_from_wallet_trace(trace, transactions=txs, max_transactions=10)
    tx_nodes = [n for n in g.nodes.values() if n["type"] == TRANSACTION]
    assert len(tx_nodes) == 10


def test_confirmed_bridge_event_gets_high_confidence_edge():
    trace = _trace()
    events = [{"mechanism": "BRIDGE", "source_api": "wormholescan",
              "event_type": "BRIDGE_CONFIRMED", "evidence_ref": "ref1",
              "dest_chain": "ETH_ADDRESS", "tx_timestamp": "2026-01-01T00:00:00+00:00"}]
    g = build_from_wallet_trace(trace, cross_chain_events=events)
    edges = [e for e in g.to_dict()["edges"] if e["rel"] == BRIDGE_TRANSFER]
    assert len(edges) == 1 and edges[0]["confidence"] == 1.0
    assert any(n["type"] == BRIDGE for n in g.nodes.values())


def test_candidate_cross_chain_event_still_gets_a_node_but_lower_confidence():
    """A CROSS_CHAIN_CANDIDATE (no live tx, corpus-level grouping only) must
    still surface in the graph -- never silently dropped -- but with a
    visibly lower confidence than a confirmed record."""
    trace = _trace()
    events = [{"mechanism": "SWAP", "source_api": "corpus_grouping",
              "event_type": "CROSS_CHAIN_CANDIDATE", "evidence_ref": None,
              "dest_chain": "ETH_ADDRESS", "tx_timestamp": None}]
    g = build_from_wallet_trace(trace, cross_chain_events=events)
    edges = [e for e in g.to_dict()["edges"] if e["rel"] == SWAP]
    assert len(edges) == 1
    assert edges[0]["confidence"] < 1.0
    assert any(n["type"] == SWAP_SERVICE for n in g.nodes.values())


def test_summary_counts_are_consistent():
    trace = _trace(path=["1Suspect", "1BinanceHot"], hops=1, direction="TO_VASP",
                   vasp_investigation={"primary_vasp": "Binance", "candidate_vasps": [],
                                       "confidence": "HIGH", "evidence": [], "provenance": [],
                                       "attribution_tier": "VASP_DISCLOSED",
                                       "control_status": "ESTABLISHED"})
    g = build_from_wallet_trace(trace)
    summary = g.summary()
    assert summary["node_count"] == len(g.nodes)
    assert summary["edge_count"] == len(g.edges)
    assert summary["node_types"].get(WALLET, 0) + summary["node_types"].get(VASP, 0) == len(g.nodes)
