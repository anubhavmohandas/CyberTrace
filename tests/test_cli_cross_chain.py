"""`cybertrace trace-cross-chain` (Loop 42): live Wormholescan/THORChain
Midgard lookup, CLI/orchestration level. Both modules' own .search() are
mocked (same convention as test_cli_batch.py's BitcoinModule/TronModule
mocking) -- correctness of the real parse is pinned in
tests/test_cross_chain_module.py; what's under test here is recording,
case-state enforcement, and output.
"""
import json

from click.testing import CliRunner

from cybertrace.cli import cli
from cybertrace.evidence import EvidenceStore
from cybertrace.modules.base import ModuleResult
from cybertrace.modules.cross_chain_module import ThorchainModule, WormholeModule

BTC_ADDR = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"


def _mock_no_links(monkeypatch):
    async def fake_search(self, target, **options):
        result = ModuleResult(target=target, target_type=self.name, module=self.name)
        result.summary["transaction_cross_chain_links"] = []
        return result
    monkeypatch.setattr(WormholeModule, "search", fake_search)
    monkeypatch.setattr(ThorchainModule, "search", fake_search)


def _mock_one_link_each(monkeypatch):
    async def fake_wormhole(self, target, **options):
        result = ModuleResult(target=target, target_type=self.name, module=self.name)
        result.summary["transaction_cross_chain_links"] = [{
            "source_chain": "BTC_ADDRESS", "source_address": target, "source_tx": "BTCTX1",
            "dest_chain": "ETH_ADDRESS", "dest_address": "0xdest", "dest_tx": None,
            "mechanism": "BRIDGE", "evidence_ref": "wh-op-1", "tx_timestamp": None,
            "source_api": "wormholescan", "status": "completed",
        }]
        return result

    async def fake_thorchain(self, target, **options):
        result = ModuleResult(target=target, target_type=self.name, module=self.name)
        result.summary["transaction_cross_chain_links"] = [{
            "source_chain": "BTC_ADDRESS", "source_address": target, "source_tx": "BTCTX2",
            "dest_chain": "ETH_ADDRESS", "dest_address": "0xdest2", "dest_tx": "ETHTX2",
            "mechanism": "SWAP", "evidence_ref": "BTCTX2", "tx_timestamp": None,
            "source_api": "thorchain_midgard", "status": "success",
        }]
        return result

    monkeypatch.setattr(WormholeModule, "search", fake_wormhole)
    monkeypatch.setattr(ThorchainModule, "search", fake_thorchain)


def test_no_links_found(tmp_path, monkeypatch):
    _mock_no_links(monkeypatch)
    db = str(tmp_path / "case.db")
    with EvidenceStore(db):
        pass
    result = CliRunner().invoke(cli, ["trace-cross-chain", BTC_ADDR, "--db", db])
    assert result.exit_code == 0, result.output
    assert "No live bridge/swap activity found" in result.output
    with EvidenceStore(db) as store:
        assert store.all_cross_chain_tx_links() == []


def test_links_from_both_sources_are_recorded(tmp_path, monkeypatch):
    _mock_one_link_each(monkeypatch)
    db = str(tmp_path / "case.db")
    with EvidenceStore(db):
        pass
    result = CliRunner().invoke(
        cli, ["trace-cross-chain", BTC_ADDR, "--db", db, "--output", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert len(data) == 2
    assert {link["source_api"] for link in data} == {"wormholescan", "thorchain_midgard"}

    with EvidenceStore(db) as store:
        rows = store.all_cross_chain_tx_links()
        assert len(rows) == 2
        assert {r["evidence_ref"] for r in rows} == {"wh-op-1", "BTCTX2"}


def test_refused_once_case_is_closed(tmp_path, monkeypatch):
    _mock_one_link_each(monkeypatch)  # must not even be reached
    db = str(tmp_path / "case.db")
    with EvidenceStore(db) as store:
        store.update_case(status="CLOSED")

    result = CliRunner().invoke(cli, ["trace-cross-chain", BTC_ADDR, "--db", db])
    assert result.exit_code != 0
    assert "case is CLOSED" in result.output
    with EvidenceStore(db) as store:
        assert store.all_cross_chain_tx_links() == []


def test_rerunning_does_not_duplicate_the_same_real_link(tmp_path, monkeypatch):
    _mock_one_link_each(monkeypatch)
    db = str(tmp_path / "case.db")
    with EvidenceStore(db):
        pass
    CliRunner().invoke(cli, ["trace-cross-chain", BTC_ADDR, "--db", db])
    CliRunner().invoke(cli, ["trace-cross-chain", BTC_ADDR, "--db", db])
    with EvidenceStore(db) as store:
        assert len(store.all_cross_chain_tx_links()) == 2
