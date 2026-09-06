"""Loop 53: cybertrace/crypto_investigation.py -- the canonical composition
entrypoint. Covers transaction-status honesty, cross-chain confirmed/
candidate labeling, and end-to-end composition over a real EvidenceStore."""
from cybertrace.crypto_investigation import (
    BRIDGE_CONFIRMED, CROSS_CHAIN_CANDIDATE, FOUND, NOT_CHECKED, NOT_FOUND, PARTIAL,
    SWAP_CONFIRMED, cross_chain_events, investigate_wallet, investigation_timeline,
    normalize_transactions,
)
from cybertrace.evidence import EvidenceStore

BTC_VALID = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BTC_OTHER = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"


def test_wallet_never_searched_returns_none(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        assert investigate_wallet(store, BTC_VALID) is None


def test_transaction_status_not_checked_when_never_searched():
    assert normalize_transactions(object(), None) == []


def test_transaction_status_not_found_when_searched_but_empty(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        eid = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        from cybertrace.crypto_investigation import _transaction_status
        assert _transaction_status(eid, []) == NOT_FOUND
        assert _transaction_status(None, []) == NOT_CHECKED


def test_full_composition_end_to_end(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        eid = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.set_metadata(eid, tx_count=5)
        store.record_transactions(eid, BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": "h1", "direction": "OUT", "counterparty": BTC_OTHER,
             "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T00:00:00+00:00"},
        ])
        result = investigate_wallet(store, BTC_VALID, chain="BTC_ADDRESS")
        assert result["address"] == BTC_VALID
        assert result["transaction_status"] == FOUND
        for key in ("wallet_trace", "transactions", "graph", "graph_summary",
                   "typology_signals", "cross_chain_events", "timeline",
                   "recommended_actions", "risk", "vasp_investigation"):
            assert key in result


def test_confirmed_bridge_event_from_real_cross_chain_tx_link(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        store.record_cross_chain_tx_link({
            "source_chain": "BTC_ADDRESS", "source_address": BTC_VALID,
            "source_tx": "srctx", "dest_chain": "ETH_ADDRESS",
            "dest_address": "0xabc", "dest_tx": "desttx", "mechanism": "BRIDGE",
            "evidence_ref": "ref1", "tx_timestamp": "2026-01-01T00:00:00+00:00",
            "source_api": "wormholescan", "status": "confirmed",
        })
        events = cross_chain_events(store, BTC_VALID, "BTC_ADDRESS", None)
        assert len(events) == 1
        assert events[0]["event_type"] == BRIDGE_CONFIRMED
        assert events[0]["confidence"] == "HIGH_CONFIDENCE"


def test_swap_event_type_from_swap_mechanism(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        store.record_cross_chain_tx_link({
            "source_chain": "BTC_ADDRESS", "source_address": BTC_VALID,
            "source_tx": "s2", "dest_chain": "ETH_ADDRESS", "dest_address": "0xdef",
            "dest_tx": "d2", "mechanism": "SWAP", "evidence_ref": "ref2",
            "tx_timestamp": None, "source_api": "thorchain_midgard", "status": None,
        })
        events = cross_chain_events(store, BTC_VALID, "BTC_ADDRESS", None)
        assert events[0]["event_type"] == SWAP_CONFIRMED


def test_no_cross_chain_evidence_is_an_empty_list_not_a_fabricated_candidate(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        assert cross_chain_events(store, BTC_VALID, "BTC_ADDRESS", None) == []


def test_timeline_orders_timed_entries_and_appends_untimed_last():
    trace = {"vasp_investigation": {"primary_vasp": "Binance", "attribution_tier": "TAG_ATTESTED",
                                    "control_status": "NOT_ESTABLISHED", "evidence": []}}
    txs = [
        {"timestamp": "2026-01-02T00:00:00+00:00", "direction": "OUT", "value": 1,
         "asset": "BTC", "counterparty": "x", "provider": "p", "tx_hash": "h2"},
        {"timestamp": "2026-01-01T00:00:00+00:00", "direction": "IN", "value": 1,
         "asset": "BTC", "counterparty": "y", "provider": "p", "tx_hash": "h1"},
    ]
    timeline = investigation_timeline(trace, txs, [], [])
    timed = [e for e in timeline if e["timestamp"]]
    assert [e["timestamp"] for e in timed] == sorted(e["timestamp"] for e in timed)
    # the untimed VASP exposure entry appears, but after every timed entry
    untimed_kinds = [e["kind"] for e in timeline if not e["timestamp"]]
    assert "VASP_EXPOSURE" in untimed_kinds
    assert timeline.index([e for e in timeline if e["kind"] == "VASP_EXPOSURE"][0]) >= len(timed)
