"""`cybertrace trace-cross-chain` (Loop 42, extended Loop 44): live
Wormholescan/THORChain Midgard/Across/LI.FI lookup, CLI/orchestration
level. Every module's own .search() is mocked (same convention as
test_cli_batch.py's BitcoinModule/TronModule mocking) -- correctness of
the real parse is pinned in tests/test_cross_chain_module.py; what's
under test here is recording, case-state enforcement, and output.
"""
import json

from click.testing import CliRunner

from cybertrace.cli import cli
from cybertrace.evidence import EvidenceStore
from cybertrace.modules.base import ModuleResult
from cybertrace.modules.cross_chain_module import (
    AcrossModule, LifiModule, ThorchainModule, WormholeModule,
)

BTC_ADDR = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

ALL_MODULES = (WormholeModule, ThorchainModule, AcrossModule, LifiModule)


def _mock_no_links(monkeypatch):
    async def fake_search(self, target, **options):
        result = ModuleResult(target=target, target_type=self.name, module=self.name)
        result.summary["transaction_cross_chain_links"] = []
        return result
    for module_cls in ALL_MODULES:
        monkeypatch.setattr(module_cls, "search", fake_search)


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

    async def fake_across(self, target, **options):
        result = ModuleResult(target=target, target_type=self.name, module=self.name)
        result.summary["transaction_cross_chain_links"] = [{
            "source_chain": "ETH_ADDRESS", "source_address": target, "source_tx": "0xdep1",
            "dest_chain": "BNB_ADDRESS", "dest_address": "0xdest3", "dest_tx": "0xfill1",
            "mechanism": "BRIDGE", "evidence_ref": "0xdep1", "tx_timestamp": None,
            "source_api": "across", "status": "filled",
        }]
        return result

    async def fake_lifi(self, target, **options):
        result = ModuleResult(target=target, target_type=self.name, module=self.name)
        result.summary["transaction_cross_chain_links"] = [{
            "source_chain": "ETH_ADDRESS", "source_address": target, "source_tx": "0xsend1",
            "dest_chain": "POLYGON_ADDRESS", "dest_address": "0xdest4", "dest_tx": "0xrecv1",
            "mechanism": "BRIDGE", "evidence_ref": "lifi-txn-1", "tx_timestamp": None,
            "source_api": "lifi", "status": "DONE",
        }]
        return result

    monkeypatch.setattr(WormholeModule, "search", fake_wormhole)
    monkeypatch.setattr(ThorchainModule, "search", fake_thorchain)
    monkeypatch.setattr(AcrossModule, "search", fake_across)
    monkeypatch.setattr(LifiModule, "search", fake_lifi)


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


def test_links_from_all_sources_are_recorded(tmp_path, monkeypatch):
    _mock_one_link_each(monkeypatch)
    db = str(tmp_path / "case.db")
    with EvidenceStore(db):
        pass
    result = CliRunner().invoke(
        cli, ["trace-cross-chain", BTC_ADDR, "--db", db, "--output", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert len(data) == 4
    assert {link["source_api"] for link in data} == {
        "wormholescan", "thorchain_midgard", "across", "lifi"}

    with EvidenceStore(db) as store:
        rows = store.all_cross_chain_tx_links()
        assert len(rows) == 4
        assert {r["evidence_ref"] for r in rows} == {
            "wh-op-1", "BTCTX2", "0xdep1", "lifi-txn-1"}


def test_table_output_cites_the_real_evidence_ref(tmp_path, monkeypatch):
    """Loop 43: the human-readable table previously showed mechanism/chain/
    source_api but silently dropped evidence_ref -- only `--output json`
    carried it, so a table reader had no way to look the record back up.
    """
    _mock_one_link_each(monkeypatch)
    db = str(tmp_path / "case.db")
    with EvidenceStore(db):
        pass
    result = CliRunner().invoke(cli, ["trace-cross-chain", BTC_ADDR, "--db", db])
    assert result.exit_code == 0, result.output
    assert "[ref: wh-op-1]" in result.output
    assert "[ref: BTCTX2]" in result.output
    assert "[ref: 0xdep1]" in result.output
    assert "[ref: lifi-txn-1]" in result.output


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
        assert len(store.all_cross_chain_tx_links()) == 4


def test_a_duplicate_record_within_one_fetch_does_not_double_write(monkeypatch, tmp_path):
    """An adversarial or simply repeating single API response (two
    identical records in one page) must collapse to one row, the same as
    the two-separate-runs case above -- dedup is keyed on
    (source_api, evidence_ref), not on when the record was seen."""
    async def fake_across_dup(self, target, **options):
        result = ModuleResult(target=target, target_type=self.name, module=self.name)
        link = {
            "source_chain": "ETH_ADDRESS", "source_address": target, "source_tx": "0xdep1",
            "dest_chain": "BNB_ADDRESS", "dest_address": "0xdest3", "dest_tx": "0xfill1",
            "mechanism": "BRIDGE", "evidence_ref": "0xdep1", "tx_timestamp": None,
            "source_api": "across", "status": "filled",
        }
        result.summary["transaction_cross_chain_links"] = [dict(link), dict(link)]
        return result

    async def fake_no_links(self, target, **options):
        result = ModuleResult(target=target, target_type=self.name, module=self.name)
        result.summary["transaction_cross_chain_links"] = []
        return result

    monkeypatch.setattr(AcrossModule, "search", fake_across_dup)
    for module_cls in (WormholeModule, ThorchainModule, LifiModule):
        monkeypatch.setattr(module_cls, "search", fake_no_links)

    db = str(tmp_path / "case.db")
    with EvidenceStore(db):
        pass
    result = CliRunner().invoke(cli, ["trace-cross-chain", BTC_ADDR, "--db", db])
    assert result.exit_code == 0, result.output
    with EvidenceStore(db) as store:
        assert len(store.all_cross_chain_tx_links()) == 1
