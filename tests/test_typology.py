"""Loop 53: cybertrace/typology.py -- deterministic behavioral typology
signals over real transaction/metadata data, never a fabricated result."""
import hashlib

from cybertrace.evidence import EvidenceStore
from cybertrace.normalize import b58encode
from cybertrace.typology import (
    CONSOLIDATION, DETECTED, DISPERSAL, FAN_IN, FAN_OUT, HIGH_ACTIVITY, HIGH_VALUE,
    NOT_EVALUATED, BURST_ACTIVITY, RAPID_FORWARDING, DORMANT_TO_ACTIVE, PEEL_CHAIN_LIKE,
    ANOMALOUS, SUSPICIOUS_PATTERN, HIGH_RISK_SIGNAL, typology_signals,
)

BTC_VALID = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def btc_addr(i: int) -> str:
    """A real, checksum-valid (but not real-world-used) P2PKH address --
    upsert_entity enforces base58check, so an arbitrary placeholder string
    is silently rejected rather than inserted."""
    payload = b"\x00" + hashlib.sha256(f"typology-test-{i}".encode()).digest()[:20]
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)


def _by_signal(signals):
    return {s["signal"]: s for s in signals}


def test_never_searched_wallet_is_not_evaluated_not_fabricated():
    class _Store:
        def metadata(self, e):
            return {}

        def transactions_for(self, e):
            return []
    signals = _by_signal(typology_signals(_Store(), None))
    assert all(s["status"] == NOT_EVALUATED for s in signals.values())


def test_high_activity_detected_from_real_tx_count(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.set_metadata(addr_id, tx_count=150)
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals[HIGH_ACTIVITY]["status"] == DETECTED
        assert signals[HIGH_ACTIVITY]["severity"] in (ANOMALOUS, SUSPICIOUS_PATTERN, HIGH_RISK_SIGNAL)


def test_high_activity_not_evaluated_when_tx_count_missing(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals[HIGH_ACTIVITY]["status"] == NOT_EVALUATED


def test_high_activity_below_threshold_is_absent_not_a_forced_entry(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.set_metadata(addr_id, tx_count=3)
        signals = _by_signal(typology_signals(store, addr_id))
        assert HIGH_ACTIVITY not in signals


def test_high_value_detected_from_real_transaction_row(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": "h1", "direction": "IN", "counterparty": "peer1",
             "asset": "BTC", "value": 12.5, "timestamp": "2026-01-01T00:00:00+00:00"},
        ])
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals[HIGH_VALUE]["status"] == DETECTED
        assert signals[HIGH_VALUE]["evidence"][0]["tx_hash"] == "h1"


def test_high_value_not_evaluated_without_transaction_rows(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.set_metadata(addr_id, total_received=50.0)  # aggregate only, no per-tx rows
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals[HIGH_VALUE]["status"] == NOT_EVALUATED


def test_fan_out_detected_from_transaction_rows(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        rows = [{"tx_hash": f"h{i}", "direction": "OUT", "counterparty": btc_addr(i),
                "asset": "BTC", "value": 0.1} for i in range(12)]
        store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", rows)
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals[FAN_OUT]["status"] == DETECTED
        assert FAN_IN not in signals or signals[FAN_IN]["status"] != DETECTED


def test_fan_out_falls_back_to_counterparty_address_list(tmp_path):
    """No transaction rows yet (pre-Loop-53 search), but sent_to_addresses
    already exists -- must still detect, off the coarser basis, not silently
    report NOT_EVALUATED when real (if coarser) evidence exists."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.set_metadata(addr_id, sent_to_addresses=[btc_addr(i) for i in range(11)])
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals[FAN_OUT]["status"] == DETECTED
        assert "not directly comparable" in signals[FAN_OUT]["explanation"]


def test_consolidation_and_dispersal_are_mutually_exclusive(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.set_metadata(addr_id, total_received=9.0, total_sent=1.0)
        for i in range(6):
            store.upsert_relationship(addr_id, store.upsert_entity("BTC_ADDRESS", btc_addr(100 + i)),
                                      "TRANSACTED_WITH")
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals.get(CONSOLIDATION, {}).get("status") == DETECTED
        assert DISPERSAL not in signals


def test_consolidation_never_fires_below_counterparty_floor(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.set_metadata(addr_id, total_received=9.0, total_sent=1.0)
        signals = _by_signal(typology_signals(store, addr_id))
        assert CONSOLIDATION not in signals and DISPERSAL not in signals


def test_burst_activity_detected_from_clustered_timestamps(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        rows = [{"tx_hash": f"h{i}", "direction": "OUT", "counterparty": btc_addr(i),
                "asset": "BTC", "value": 0.01,
                "timestamp": f"2026-01-01T00:0{i}:00+00:00"} for i in range(6)]
        store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", rows)
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals[BURST_ACTIVITY]["status"] == DETECTED


def test_burst_activity_not_evaluated_without_timestamps(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": "h1", "direction": "OUT", "counterparty": "1Peer1", "asset": "BTC"},
        ])
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals[BURST_ACTIVITY]["status"] == NOT_EVALUATED


def test_rapid_forwarding_detected(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": "in1", "direction": "IN", "counterparty": btc_addr(9001),
             "asset": "BTC", "value": 2.0, "timestamp": "2026-01-01T00:00:00+00:00"},
            {"tx_hash": "out1", "direction": "OUT", "counterparty": btc_addr(9002),
             "asset": "BTC", "value": 1.9, "timestamp": "2026-01-01T00:10:00+00:00"},
        ])
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals[RAPID_FORWARDING]["status"] == DETECTED


def test_rapid_forwarding_ignores_same_counterparty_round_trip(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": "in1", "direction": "IN", "counterparty": btc_addr(9003),
             "asset": "BTC", "value": 2.0, "timestamp": "2026-01-01T00:00:00+00:00"},
            {"tx_hash": "out1", "direction": "OUT", "counterparty": btc_addr(9003),
             "asset": "BTC", "value": 1.9, "timestamp": "2026-01-01T00:10:00+00:00"},
        ])
        signals = _by_signal(typology_signals(store, addr_id))
        # Evaluated fine, found nothing real -- absent from the list, never
        # a forced DETECTED for a same-peer round-trip.
        assert signals.get(RAPID_FORWARDING, {}).get("status") != DETECTED


def test_dormant_to_active_detected(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": "old1", "direction": "IN", "counterparty": btc_addr(9004),
             "asset": "BTC", "value": 0.1, "timestamp": "2024-01-01T00:00:00+00:00"},
            {"tx_hash": "new1", "direction": "OUT", "counterparty": btc_addr(9005),
             "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T00:00:00+00:00"},
            {"tx_hash": "new2", "direction": "OUT", "counterparty": btc_addr(9006),
             "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T01:00:00+00:00"},
        ])
        signals = _by_signal(typology_signals(store, addr_id))
        assert signals[DORMANT_TO_ACTIVE]["status"] == DETECTED


def test_normal_wallet_has_no_forced_signals(tmp_path):
    """A quiet wallet with a couple of ordinary transactions should trigger
    nothing DETECTED -- absence, not a manufactured low-severity entry."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.set_metadata(addr_id, tx_count=2)
        store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": "h1", "direction": "IN", "counterparty": btc_addr(9007),
             "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T00:00:00+00:00"},
            {"tx_hash": "h2", "direction": "OUT", "counterparty": btc_addr(9008),
             "asset": "BTC", "value": 0.1, "timestamp": "2026-06-01T00:00:00+00:00"},
        ])
        detected = [s for s in typology_signals(store, addr_id) if s["status"] == DETECTED]
        assert detected == []


def test_peel_chain_like_is_capped_below_high_risk_signal(tmp_path):
    """A single-wallet proxy for a multi-wallet pattern must never present
    as the most severe possible signal on its own -- see module docstring."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        rows = [{"tx_hash": "big_in", "direction": "IN", "counterparty": btc_addr(9001),
                "asset": "BTC", "value": 20.0, "timestamp": "2026-01-01T00:00:00+00:00"}]
        for i in range(8):
            rows.append({"tx_hash": f"peel{i}", "direction": "OUT",
                        "counterparty": btc_addr(200 + i), "asset": "BTC", "value": 0.5,
                        "timestamp": f"2026-01-01T0{i}:00:00+00:00"})
        store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", rows)
        signals = _by_signal(typology_signals(store, addr_id))
        if signals[PEEL_CHAIN_LIKE]["status"] == DETECTED:
            assert signals[PEEL_CHAIN_LIKE]["severity"] != HIGH_RISK_SIGNAL
