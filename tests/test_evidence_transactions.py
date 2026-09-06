"""Loop 53: the `transactions` table -- real per-transaction rows a chain
module already fetched (see evidence.py's schema comment and
evidence.enrich_bitcoin's `raw_transactions` wiring), captured once and never
re-derived from aggregates. Covers record/read, dedup, and the "missing field
stays NULL, never 0" discipline this whole loop is built on.
"""
from cybertrace.evidence import EvidenceStore, enrich_bitcoin

# Real, checksummed, well-known addresses (same constants used across
# test_correlate.py/test_risk.py) -- upsert_entity enforces checksum
# validation, so a placeholder string like "1Suspect..." is silently
# rejected (returns None) rather than inserted.
BTC_VALID = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BTC_OTHER = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
TRX_VALID = "TGXE9dGWawjfd3xqFSho1h1bRbRv9wUGrF"
TRX_OTHER = "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7"


def test_record_and_read_back(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        n = store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": "h1", "direction": "OUT", "counterparty": BTC_OTHER,
             "asset": "BTC", "value": 0.5, "timestamp": "2026-01-01T00:00:00+00:00",
             "block": "800000", "fee": 0.0001, "provider": "blockchain.com"},
        ])
        assert n == 1
        rows = store.transactions_for(addr_id)
        assert len(rows) == 1
        assert rows[0]["tx_hash"] == "h1"
        assert rows[0]["value"] == 0.5
        assert rows[0]["status"] == "FOUND"


def test_missing_fields_stay_null_never_zero(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("TRX_ADDRESS", TRX_VALID)
        store.record_transactions(addr_id, TRX_VALID, "TRX_ADDRESS", "tron", [
            {"tx_hash": "h2", "direction": "OUT", "counterparty": TRX_OTHER,
             "asset": "TRC20", "value": None, "timestamp": "2026-01-01T00:00:00+00:00",
             "status": "PARTIAL"},
        ])
        row = store.transactions_for(addr_id)[0]
        assert row["value"] is None
        assert row["status"] == "PARTIAL"
        assert row["block"] is None and row["fee"] is None


def test_dedup_on_resubmission(tmp_path):
    """Re-searching the same wallet (e.g. a `watch` cycle) must not grow
    duplicate rows for the same real transaction."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        row = {"tx_hash": "h1", "direction": "OUT", "counterparty": BTC_OTHER,
               "asset": "BTC", "value": 0.5, "timestamp": "2026-01-01T00:00:00+00:00"}
        first = store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", [row])
        second = store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", [row])
        assert first == 1
        assert second == 0
        assert len(store.transactions_for(addr_id)) == 1


def test_empty_rows_is_a_real_zero_not_an_error(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        assert store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", []) == 0
        assert store.transactions_for(addr_id) == []


def test_rows_missing_tx_hash_or_bad_direction_are_skipped_not_crashed(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        n = store.record_transactions(addr_id, BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": None, "direction": "OUT"},
            {"tx_hash": "h3", "direction": "SIDEWAYS"},
        ])
        assert n == 0
        assert store.transactions_for(addr_id) == []


def test_enrich_bitcoin_wires_raw_transactions_into_the_store(tmp_path):
    """evidence.enrich_bitcoin (the single generic enricher every chain
    module routes through -- see evidence._ENRICHERS) must persist
    summary['raw_transactions'] additively, without touching any existing
    metadata/relationship write."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        target_id = store.upsert_target(BTC_VALID)
        addr_id = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        snap_id = store.insert_snapshot(target_id, {}, collector="bitcoin",
                                        observed_at="2026-01-01T00:00:00+00:00")
        enrich_bitcoin(store, snap_id, addr_id, {
            "address": BTC_VALID, "tx_count": 1,
            "raw_transactions": [{
                "tx_hash": "h4", "direction": "IN", "counterparty": BTC_OTHER,
                "asset": "BTC", "value": 1.2, "timestamp": "2026-01-01T00:00:00+00:00",
            }],
        }, "bitcoin", observed_at="2026-01-01T00:00:00+00:00")
        rows = store.transactions_for(addr_id)
        assert len(rows) == 1
        assert rows[0]["tx_hash"] == "h4"
        assert store.metadata(addr_id).get("tx_count") == 1


def test_wallet_never_searched_has_no_rows_not_a_fabricated_empty_list(tmp_path):
    """A wallet this case never searched has no entity_id at all -- calling
    code must distinguish that from a genuinely-empty real result (see
    crypto_investigation.normalize_transactions' NOT_CHECKED status)."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        assert store.find_entity("BTC_ADDRESS", BTC_OTHER) is None
