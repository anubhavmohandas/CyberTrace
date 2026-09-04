"""experiments/ml_attribution/ml_features.py (Loop 46): schema and
provenance tests -- does the extractor ever manufacture a value it has no
basis for. EXPERIMENTAL, not production -- see this folder's README.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))               # ml_features (sibling)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))  # repo root: tests is a real
                                                                        # package (tests/__init__.py) whose
                                                                        # own modules use relative imports
                                                                        # among themselves -- must be
                                                                        # imported as tests.test_correlate,
                                                                        # not as a bare top-level module,
                                                                        # or its own `from .test_evidence
                                                                        # import ...` breaks.

from cybertrace.correlate import TAG_ATTESTED, _adjacency, _vasp_endpoints, crypto_clusters
from cybertrace.evidence import EvidenceStore, enrich_bitcoin
from cybertrace.integrations import ellipticpp
from ml_features import (  # noqa: E402
    FEATURE_SCHEMA, _empty_features, extract_features, extract_features_ellipticpp,
)

from tests.test_correlate import _synth_btc, _traced  # noqa: E402

WALLET_A = _synth_btc("ml-features-a")
WALLET_B = _synth_btc("ml-features-b")


def test_empty_features_are_all_none_never_zero():
    empty = _empty_features()
    assert set(empty) == set(FEATURE_SCHEMA)
    assert all(v is None for v in empty.values())


def test_isolated_wallet_has_no_graph_or_cluster_basis(tmp_path):
    """A wallet with zero counterparties: graph_vasp_neighbor_count/
    graph_distance_to_vasp/graph_cluster_size must read None (no basis),
    never a manufactured 0/absent-VASP claim."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        entity_id = _traced(store, WALLET_A, {"n_tx": 0, "total_received": 0, "total_sent": 0})
        adjacency = _adjacency(store)
        exchange_of = _vasp_endpoints(store, {entity_id: WALLET_A})
        clusters = crypto_clusters(store)
        row = extract_features(store, entity_id, WALLET_A, "BTC_ADDRESS",
                               adjacency, exchange_of, clusters)

    f = row["features"]
    assert f["graph_degree"] == 0.0
    assert f["graph_vasp_neighbor_count"] == 0.0
    assert f["graph_distance_to_vasp"] is None  # nothing reachable, not "far"
    assert f["graph_cluster_size"] is None       # not clustered, not "alone" as a 0
    assert row["meta"]["feature_source"] == "cybertrace"


def test_vasp_neighbor_is_counted_and_ofac_neighbor_is_not(tmp_path):
    """graph_vasp_neighbor_count must reuse attribution's own OFAC exclusion
    -- a REGULATORY_ATTESTED peer is not a VASP neighbor (same rule
    attribution.py's _ground_truth_hit already enforces elsewhere)."""
    from cybertrace.correlate import REGULATORY_ATTESTED

    with EvidenceStore(str(tmp_path / "e.db")) as store:
        wallet_id = store.upsert_entity("BTC_ADDRESS", WALLET_A)
        vasp_peer = store.upsert_entity("BTC_ADDRESS", WALLET_B)
        target_id = store.upsert_target("http://ml-features-test.local")
        snap_id = store.insert_snapshot(target_id, {}, "test", status="OK")
        obs = store.insert_observation(snap_id, vasp_peer, method="test:counterparty")
        rel = store.upsert_relationship(wallet_id, vasp_peer, "TRANSACTED_WITH", source_label="test")
        store.add_evidence(rel, [obs])

        adjacency = _adjacency(store)
        exchange_of = {vasp_peer: {"exchange": "Binance", "attribution": TAG_ATTESTED,
                                   "attribution_source": "test", "wallet_role": None,
                                   "evidence_ids": []},
                       "ofac-entity": {"exchange": "N/A", "attribution": REGULATORY_ATTESTED,
                                      "attribution_source": "test", "wallet_role": None,
                                      "evidence_ids": []}}
        row = extract_features(store, wallet_id, WALLET_A, "BTC_ADDRESS",
                               adjacency, exchange_of, clusters={})

    f = row["features"]
    assert f["graph_vasp_neighbor_count"] == 1.0
    assert f["graph_distance_to_vasp"] == 1.0


@pytest.mark.skipif(not ellipticpp.index_available(),
                    reason="Elliptic++ index not built locally (see ellipticpp.build_index)")
def test_ellipticpp_extractor_never_fabricates_vasp_or_graph_fields():
    """The offline Elliptic++ source has no VASP-label or cross-chain
    concept at all -- those columns must stay None, not 0 (module
    docstring: "no basis", not "zero, checked and absent")."""
    record = {"dataset_label_name": "licit",
             "features": {"total_txs": "12", "btc_received_total": "5.0",
                         "btc_sent_total": "3.0", "btc_transacted_mean": "0.4",
                         "num_timesteps_appeared_in": "4"}}
    row = extract_features_ellipticpp(WALLET_A, record, neighbor_limit=0)

    f = row["features"]
    assert f["txn_tx_count"] == 12.0
    assert f["behav_transaction_regularity"] == 3.0  # 12 txs / 4 timesteps
    for key in ("graph_vasp_neighbor_count", "graph_distance_to_vasp",
               "graph_cluster_size", "xchain_link_count",
               "behav_batching_behavior", "behav_sweep_like_behavior"):
        assert f[key] is None, f"{key} must stay None for an ellipticpp-sourced row"
    assert row["meta"]["feature_source"] == "ellipticpp"
