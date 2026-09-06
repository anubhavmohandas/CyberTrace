"""`cybertrace crypto investigate` (Loop 53): the CLI surface over
crypto_investigation.investigate_wallet. Wraps trace-wallet/trace-cross-
chain logic already tested elsewhere -- what's under test here is the CLI
wiring, output shapes, and the never-searched-wallet error path."""
import json

from click.testing import CliRunner

from cybertrace.cli import cli
from cybertrace.evidence import EvidenceStore

BTC_VALID = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BTC_OTHER = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"


def test_investigate_never_searched_wallet_errors(tmp_path):
    db = str(tmp_path / "e.db")
    with EvidenceStore(db):
        pass
    result = CliRunner().invoke(cli, ['crypto', 'investigate', BTC_VALID, '--db', db])
    assert result.exit_code == 1
    assert "never searched" in result.output


def test_investigate_json_output_has_full_composed_shape(tmp_path):
    db = str(tmp_path / "e.db")
    with EvidenceStore(db) as store:
        eid = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        store.set_metadata(eid, tx_count=1)
        store.record_transactions(eid, BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": "h1", "direction": "OUT", "counterparty": BTC_OTHER,
             "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T00:00:00+00:00"},
        ])

    result = CliRunner().invoke(cli, ['crypto', 'investigate', BTC_VALID, '--db', db,
                                      '--output', 'json'])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    for key in ("wallet_trace", "transactions", "graph", "graph_summary",
               "typology_signals", "cross_chain_events", "timeline",
               "recommended_actions", "risk", "vasp_investigation"):
        assert key in payload
    assert payload["address"] == BTC_VALID
    assert len(payload["transactions"]) == 1


def test_investigate_table_output_is_human_readable(tmp_path):
    db = str(tmp_path / "e.db")
    with EvidenceStore(db) as store:
        store.upsert_entity("BTC_ADDRESS", BTC_VALID)

    result = CliRunner().invoke(cli, ['crypto', 'investigate', BTC_VALID, '--db', db])
    assert result.exit_code == 0
    assert "Wallet:" in result.output
    assert "Risk:" in result.output
    assert "Behavioral signals" in result.output


def test_max_transactions_flag_is_accepted(tmp_path):
    db = str(tmp_path / "e.db")
    with EvidenceStore(db) as store:
        store.upsert_entity("BTC_ADDRESS", BTC_VALID)
    result = CliRunner().invoke(cli, ['crypto', 'investigate', BTC_VALID, '--db', db,
                                      '--max-transactions', '10', '--max-hops', '2'])
    assert result.exit_code == 0
