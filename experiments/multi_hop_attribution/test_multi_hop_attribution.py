"""Deterministic multi-hop VASP evidence engine (Loop 47, REJECTED --
Decision C, see docs/LOOP47.md): traversal, evidence, ranking and safety
tests. Not part of the default `pytest` run (this folder is not under
`tests/`) -- run explicitly: `pytest experiments/multi_hop_attribution/`.

Same two-layer split test_attribution.py uses:

- Unit tests drive multi_hop_paths/multi_hop_candidates/_independent_paths/
  _score_brand directly with hand-built adjacency/exchange_of dicts,
  isolating the traversal+scoring policy from correlate's store/BFS
  machinery -- fast, deterministic, full control over hop count, tier, and
  hub degree.
- Real-data-shaped tests wire correlate._adjacency/_vasp_endpoints (via a
  real EvidenceStore + the same _traced/label_exchange fixtures
  test_correlate.py's own multi-hop suite uses) into multi_hop_candidates
  end to end, proving the integration -- not just the pure functions.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling: multi_hop_attribution.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))  # repo root: tests is a real package

from multi_hop_attribution import (
    HIGH, LOW, MAX_HOPS_HARD_CEILING, MEDIUM, MULTI_HOP_INFERENCE,
    MULTI_HOP_POLICY_VERSION, VERDICT_AMBIGUOUS, VERDICT_INSUFFICIENT_EVIDENCE,
    VERDICT_PRIMARY, _HUB_DEGREE_THRESHOLD, _independent_paths, _score_brand,
    multi_hop_candidates, multi_hop_paths, _rules_for,
)

from cybertrace import correlate
from cybertrace.correlate import TAG_ATTESTED, VASP_DISCLOSED
from cybertrace.evidence import EvidenceStore, label_exchange
from tests.test_correlate import _synth_btc, _traced

# --- hand-built graph helpers ------------------------------------------------


def _hit(brand, attribution=VASP_DISCLOSED, source="test", entity_id="vasp"):
    return {"exchange": brand, "attribution": attribution,
            "attribution_source": source, "evidence_ids": []}


def _edge(*, obs=None, flow=None):
    return (obs or [], {flow})


def _chain_adjacency(nodes, flow=True):
    """Straight-line undirected adjacency start -> nodes[0] -> ... ->
    nodes[-1], each hop carrying one observation id and a SENT_FUNDS_TO-style
    directed flow marker (matches _wallet_chain's real-store shape)."""
    adjacency = {}
    for a, b in zip(nodes, nodes[1:]):
        adjacency.setdefault(a, {})[b] = ([f"obs:{a}->{b}"], {flow})
        adjacency.setdefault(b, {})[a] = ([f"obs:{a}->{b}"], {not flow if flow is not None else None})
    return adjacency


# --- traversal: graph discovery ---------------------------------------------


def test_1_hop_discovery():
    adjacency = _chain_adjacency(["suspect", "vasp"])
    exchange_of = {"vasp": _hit("Binance")}
    reach = multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=3)
    assert [p["vasp"] for p in reach["paths"]] == ["Binance"]
    assert reach["paths"][0]["hops"] == 1
    assert reach["paths"][0]["path"] == ["suspect", "vasp"]
    assert reach["paths"][0]["intermediate_nodes"] == []


def test_2_hop_discovery():
    adjacency = _chain_adjacency(["suspect", "a", "vasp"])
    exchange_of = {"vasp": _hit("Binance")}
    reach = multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=3)
    assert reach["paths"][0]["hops"] == 2
    assert reach["paths"][0]["path"] == ["suspect", "a", "vasp"]
    assert reach["paths"][0]["intermediate_nodes"] == ["a"]


def test_3_hop_discovery():
    adjacency = _chain_adjacency(["suspect", "a", "b", "vasp"])
    exchange_of = {"vasp": _hit("Binance")}
    reach = multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=3)
    assert reach["paths"][0]["hops"] == 3
    assert reach["paths"][0]["intermediate_nodes"] == ["a", "b"]


def test_max_hop_enforcement_is_real_not_decorative():
    """A path one hop past the budget is invisible -- silence, never a
    truncated/wrong path -- same contract as correlate._secondary_vasp_reach."""
    adjacency = _chain_adjacency(["suspect", "a", "b", "c", "vasp"])  # 4 hops
    exchange_of = {"vasp": _hit("Binance")}
    assert multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=3)["paths"] == []
    reach4 = multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=4)
    assert [p["vasp"] for p in reach4["paths"]] == ["Binance"]


def test_hard_ceiling_clamps_even_if_caller_requests_more():
    """A caller passing max_hops far past MAX_HOPS_HARD_CEILING never gets a
    traversal past the ceiling -- section 25's floor under the configurable
    default, not just a documented convention."""
    nodes = ["suspect"] + [f"w{i}" for i in range(MAX_HOPS_HARD_CEILING)] + ["vasp"]
    adjacency = _chain_adjacency(nodes)  # MAX_HOPS_HARD_CEILING + 1 hops
    exchange_of = {"vasp": _hit("Binance")}
    reach = multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=10_000)
    assert reach["paths"] == []


def test_cycle_terminates_and_does_not_block_the_other_branch():
    """A -> B -> C -> B (cycle back to an already-visited node): must not
    loop, and must not block C's other edge onward to the VASP."""
    adjacency = {
        "a": {"b": _edge()}, "b": {"a": _edge(), "c": _edge()},
        "c": {"b": _edge(), "vasp": _edge()},
    }
    exchange_of = {"vasp": _hit("Binance")}
    reach = multi_hop_paths(adjacency, exchange_of, "a", max_hops=6)
    assert [p["vasp"] for p in reach["paths"]] == ["Binance"]
    assert reach["paths"][0]["hops"] == 3


def test_does_not_walk_through_a_vasp_attributed_node():
    """VASP_X is a dead end: its own further edge to VASP_Y one hop past it
    must never be discovered, exactly like correlate._secondary_vasp_reach."""
    adjacency = {
        "suspect": {"vasp_x": _edge()},
        "vasp_x": {"suspect": _edge(), "w2": _edge()},
        "w2": {"vasp_x": _edge(), "vasp_y": _edge()},
    }
    exchange_of = {"vasp_x": _hit("VASP X"), "vasp_y": _hit("VASP Y")}
    reach = multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=6)
    assert {p["vasp"] for p in reach["paths"]} == {"VASP X"}


def test_ofac_never_reachable_as_an_endpoint():
    """REGULATORY_ATTESTED (OFAC) is filtered out of the traversal's own
    endpoint set entirely -- a suspect one hop from a sanctioned address must
    not even discover it as a destination, and must still walk PAST it to
    find a real VASP further out (OFAC is not a dead end here; it is simply
    invisible as a target)."""
    adjacency = _chain_adjacency(["suspect", "ofac_addr", "vasp"])
    exchange_of = {
        "ofac_addr": _hit("Some Sanctioned Entity", attribution=correlate.REGULATORY_ATTESTED),
        "vasp": _hit("Binance"),
    }
    reach = multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=3)
    assert [p["vasp"] for p in reach["paths"]] == ["Binance"]
    assert reach["paths"][0]["hops"] == 2  # walked straight through the OFAC node


def test_truncation_flagged_when_node_budget_exceeded(monkeypatch):
    import multi_hop_attribution as mha
    monkeypatch.setattr(mha, "_MAX_NODES_EXPLORED", 2)
    adjacency = _chain_adjacency(["suspect", "a", "b", "vasp"])
    exchange_of = {"vasp": _hit("Binance")}
    reach = multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=3)
    assert reach["truncated"] is True
    assert reach["paths"] == []  # cut off before ever reaching the VASP node


# --- evidence: hop decay, independence, hub penalty, directionality --------


def test_hop_penalty_1hop_scores_higher_than_2hop():
    rules = _rules_for(3)
    p1 = {"hops": 1, "attribution": VASP_DISCLOSED, "hub_dependent": False,
          "intermediate_nodes": [], "entity_id": "v1", "path": ["s", "v1"],
          "vasp": "Binance", "direction": "UNKNOWN", "evidence_ids": [],
          "attribution_source": "t"}
    p2 = {**p1, "hops": 2, "entity_id": "v2", "intermediate_nodes": ["a"], "path": ["s", "a", "v2"]}
    score1 = _score_brand([p1], rules)["score"]
    score2 = _score_brand([p2], rules)["score"]
    assert score1 > score2 > 0


def test_shared_intermediate_node_paths_are_not_double_counted():
    """suspect -> A -> VASP(addr1) and suspect -> A -> VASP(addr2): both share
    intermediate node A, so only one counts toward the score (section 12)."""
    rules = _rules_for(3)
    base = {"hops": 2, "attribution": VASP_DISCLOSED, "hub_dependent": False,
            "intermediate_nodes": ["a"], "vasp": "Binance", "direction": "UNKNOWN",
            "evidence_ids": [], "attribution_source": "t"}
    p1 = {**base, "entity_id": "v1", "path": ["s", "a", "v1"]}
    p2 = {**base, "entity_id": "v2", "path": ["s", "a", "v2"]}
    result = _score_brand([p1, p2], rules)
    independent = [c for c in result["contributions"] if c["independent"]]
    dependent = [c for c in result["contributions"] if not c["independent"]]
    assert len(independent) == 1
    assert len(dependent) == 1
    assert dependent[0]["applied_amount"] == 0
    # score equals a single 2-hop contribution, not two summed.
    single = _score_brand([p1], rules)["score"]
    assert result["score"] == single


def test_disjoint_intermediate_paths_are_independent_and_stack():
    rules = _rules_for(3)
    base = {"hops": 2, "attribution": VASP_DISCLOSED, "hub_dependent": False,
            "vasp": "Binance", "direction": "UNKNOWN", "evidence_ids": [],
            "attribution_source": "t"}
    p1 = {**base, "entity_id": "v1", "intermediate_nodes": ["b"], "path": ["s", "b", "v1"]}
    p2 = {**base, "entity_id": "v2", "intermediate_nodes": ["c"], "path": ["s", "c", "v2"]}
    result = _score_brand([p1, p2], rules)
    assert all(c["independent"] for c in result["contributions"])
    single = _score_brand([p1], rules)["score"]
    assert result["score"] == min(single * 2, 70)  # _BRAND_SCORE_CAP


def test_independent_paths_helper_orders_nearest_first():
    near = {"hops": 1, "attribution": VASP_DISCLOSED, "hub_dependent": False,
            "intermediate_nodes": [], "entity_id": "near", "path": ["s", "near"],
            "vasp": "X", "direction": "UNKNOWN", "evidence_ids": [], "attribution_source": "t"}
    far = {**near, "hops": 3, "entity_id": "far", "intermediate_nodes": ["a", "b"],
           "path": ["s", "a", "b", "far"]}
    independent, dependent = _independent_paths([far, near])
    assert independent == [near, far]  # nearest first regardless of input order
    assert dependent == []


def test_hub_dependent_path_is_discounted():
    adjacency = _chain_adjacency(["suspect", "hub", "vasp"])
    # Inflate hub's own adjacency degree past _HUB_DEGREE_THRESHOLD.
    for i in range(_HUB_DEGREE_THRESHOLD + 5):
        adjacency["hub"][f"peer{i}"] = _edge()
    exchange_of = {"vasp": _hit("Binance")}
    reach = multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=3)
    assert reach["paths"][0]["hub_dependent"] is True

    rules = _rules_for(3)
    hub_score = _score_brand(reach["paths"], rules)["score"]
    plain = {**reach["paths"][0], "hub_dependent": False}
    plain_score = _score_brand([plain], rules)["score"]
    assert 0 < hub_score < plain_score


def test_directionality_preserved_on_final_hop():
    adjacency = _chain_adjacency(["suspect", "a", "vasp"], flow=True)  # a -> vasp deposit
    exchange_of = {"vasp": _hit("Binance")}
    reach = multi_hop_paths(adjacency, exchange_of, "suspect", max_hops=3)
    assert reach["paths"][0]["direction"] == correlate.TO_VASP


def test_tag_attested_tier_scores_lower_than_vasp_disclosed():
    rules = _rules_for(3)
    disclosed = {"hops": 1, "attribution": VASP_DISCLOSED, "hub_dependent": False,
                "intermediate_nodes": [], "entity_id": "v1", "path": ["s", "v1"],
                "vasp": "X", "direction": "UNKNOWN", "evidence_ids": [], "attribution_source": "t"}
    tagged = {**disclosed, "attribution": TAG_ATTESTED, "entity_id": "v2", "path": ["s", "v2"]}
    assert _score_brand([tagged], rules)["score"] < _score_brand([disclosed], rules)["score"]


# --- candidate ranking: verdict semantics -----------------------------------


def test_no_evidence_is_insufficient():
    result = multi_hop_candidates({}, {}, "suspect", max_hops=3)
    assert result["verdict"] == VERDICT_INSUFFICIENT_EVIDENCE
    assert result["primary_candidate"] is None
    assert result["candidates"] == []
    assert result["policy_version"] == MULTI_HOP_POLICY_VERSION
    assert result["provenance"] == MULTI_HOP_INFERENCE


def test_single_real_candidate_is_primary():
    adjacency = _chain_adjacency(["suspect", "vasp"])
    exchange_of = {"vasp": _hit("Binance")}
    result = multi_hop_candidates(adjacency, exchange_of, "suspect", max_hops=3)
    assert result["verdict"] == VERDICT_PRIMARY
    assert result["primary_candidate"] == "Binance"
    assert result["strength"] in (LOW, MEDIUM, HIGH)


def test_clear_margin_between_two_candidates_is_primary():
    """A 1-hop Binance relationship next to a lone 3-hop Coinbase relationship
    clears both the ratio and absolute margin -- PRIMARY, not a coin flip."""
    adjacency = {
        "suspect": {"binance": _edge(), "a": _edge()},
        "binance": {"suspect": _edge()},
        "a": {"suspect": _edge(), "b": _edge()},
        "b": {"a": _edge(), "coinbase": _edge()},
        "coinbase": {"b": _edge()},
    }
    exchange_of = {"binance": _hit("Binance"), "coinbase": _hit("Coinbase")}
    result = multi_hop_candidates(adjacency, exchange_of, "suspect", max_hops=3)
    assert result["verdict"] == VERDICT_PRIMARY
    assert result["primary_candidate"] == "Binance"
    brands = {c["brand"] for c in result["candidates"]}
    assert brands == {"Binance", "Coinbase"}


def test_close_scores_are_ambiguous_not_a_guess():
    """Two brands reached at the identical hop count/tier: no defensible
    primary -- must not guess off brand-name tie-break alone (section 14)."""
    adjacency = {
        "suspect": {"a": _edge(), "b": _edge()},
        "a": {"suspect": _edge(), "binance": _edge()},
        "binance": {"a": _edge()},
        "b": {"suspect": _edge(), "coinbase": _edge()},
        "coinbase": {"b": _edge()},
    }
    exchange_of = {"binance": _hit("Binance"), "coinbase": _hit("Coinbase")}
    result = multi_hop_candidates(adjacency, exchange_of, "suspect", max_hops=3)
    assert result["verdict"] == VERDICT_AMBIGUOUS
    assert result["primary_candidate"] is None
    assert {c["brand"] for c in result["candidates"]} == {"Binance", "Coinbase"}


# --- real-store integration (correlate._adjacency/_vasp_endpoints) ---------


def test_real_store_2hop_chain_reaches_the_engine_end_to_end(tmp_path):
    suspect = _synth_btc("mha-2hop-suspect")
    w1 = _synth_btc("mha-2hop-w1")
    vasp_addr = _synth_btc("mha-2hop-vasp")
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        assert label_exchange(store, vasp_addr, "Real Brand") is not None
        suspect_id = _traced(store, suspect, {"counterparty_addresses": [w1]})
        _traced(store, w1, {"sent_to_addresses": [vasp_addr]})

        wallet_rows = store._all(
            "SELECT entity_id, raw_value FROM entities WHERE etype='BTC_ADDRESS'")
        values = {r["entity_id"]: r["raw_value"] for r in wallet_rows}
        adjacency = correlate._adjacency(store)
        exchange_of = correlate._vasp_endpoints(store, values)

        result = multi_hop_candidates(adjacency, exchange_of, suspect_id, max_hops=3)
        assert result["verdict"] == VERDICT_PRIMARY
        assert result["primary_candidate"] == "real brand"


def test_real_store_masked_ground_truth_wallet_has_no_leaked_self_hit(tmp_path):
    """A wallet whose OWN address is the VASP endpoint contributes nothing to
    its own candidacy when correctly excluded from exchange_of by a caller
    (the benchmark's masking contract) -- multi_hop_candidates never queries
    the store itself, so it cannot re-discover a masked label on its own."""
    suspect = _synth_btc("mha-masked-suspect")
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        assert label_exchange(store, suspect, "Self Brand") is not None
        suspect_id = store.find_entity("BTC_ADDRESS", suspect)
        adjacency = correlate._adjacency(store)
        # Masked: exchange_of deliberately empty, as a benchmark would build it
        # after stripping this wallet's own ground truth.
        result = multi_hop_candidates(adjacency, {}, suspect_id, max_hops=3)
        assert result["verdict"] == VERDICT_INSUFFICIENT_EVIDENCE
