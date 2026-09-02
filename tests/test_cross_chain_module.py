"""Tests for cybertrace.modules.cross_chain_module (Loop 42).

Mocked at the fetch_json level (same convention as test_solana_module.py)
so each module's own _parse() is exercised against realistic response
shapes without a live network call. The shapes below are drawn from a
live-verified audit of the real Wormholescan/Midgard APIs, not guessed.
"""
import asyncio

from cybertrace.modules.cross_chain_module import (
    BRIDGE, SWAP, ThorchainModule, WormholeModule,
)

ETH_ADDR = "0x" + "ab" * 20
SOL_ADDR = "So11111111111111111111111111111111111111"


class TestWormholeModule:
    def test_parses_a_supported_bridge_operation(self):
        response = {"operations": [{
            "id": "op123",
            "sourceChain": {
                "chainId": 2,  # Ethereum
                "from": ETH_ADDR,
                "transaction": {"txHash": "0xsrc111"},
                "timestamp": "2026-08-01T00:00:00Z",
                "status": "completed",
            },
            "content": {"standarizedProperties": {
                "fromChain": 2, "toChain": 1,  # Solana
                "toAddress": SOL_ADDR,
            }},
        }]}
        links = WormholeModule._parse(response, ETH_ADDR)
        assert len(links) == 1
        link = links[0]
        assert link["source_chain"] == "ETH_ADDRESS"
        assert link["source_address"] == ETH_ADDR
        assert link["source_tx"] == "0xsrc111"
        assert link["dest_chain"] == "SOL_ADDRESS"
        assert link["dest_address"] == SOL_ADDR
        assert link["dest_tx"] is None
        assert link["mechanism"] == BRIDGE
        assert link["evidence_ref"] == "op123"
        assert link["source_api"] == "wormholescan"
        assert link["status"] == "completed"

    def test_skips_an_operation_on_a_chain_this_codebase_does_not_trace(self):
        """Wormhole chain id 3 is Terra -- not one of the six chains
        CyberTrace traces. Must be skipped, not mapped to None as a chain."""
        response = {"operations": [{
            "id": "op456",
            "sourceChain": {"chainId": 3, "transaction": {"txHash": "0xterra"}},
            "content": {"standarizedProperties": {}},
        }]}
        assert WormholeModule._parse(response, "terra1...") == []

    def test_skips_an_operation_with_no_stable_reference(self):
        """No operation id and no source tx hash -- nothing to cite as
        evidence_ref. Must be refused, never given an invented reference."""
        response = {"operations": [{
            "sourceChain": {"chainId": 2}, "content": {"standarizedProperties": {}},
        }]}
        assert WormholeModule._parse(response, ETH_ADDR) == []

    def test_no_operations_key_is_handled(self):
        assert WormholeModule._parse({}, ETH_ADDR) == []

    def test_search_reports_failure_when_fetch_json_returns_none(self):
        module = WormholeModule()

        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search(ETH_ADDR))
        assert result.sources["wormholescan"].success is False
        assert result.summary.get("transaction_cross_chain_links") is None

    def test_search_does_not_crash_on_a_non_dict_response(self):
        """A malformed/unexpected-shape response (a bare list, here) must
        report failure like a None response, never raise AttributeError."""
        module = WormholeModule()

        async def fake_fetch_json(url, **kwargs):
            return ["not", "a", "dict"]
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search(ETH_ADDR))
        assert result.sources["wormholescan"].success is False

    def test_parse_skips_malformed_list_entries_without_crashing(self):
        """A non-dict entry in `operations`, or a non-dict `sourceChain`,
        must be skipped rather than crash the whole parse; a non-dict
        `content`/`transaction` degrades to missing destination/tx fields
        rather than crashing, since the operation's own `id` is still a
        valid, stable reference."""
        response = {"operations": [
            "not a dict",
            {"id": "op1", "sourceChain": "also not a dict"},
            {"id": "op2", "sourceChain": {"chainId": 2, "transaction": "not a dict either"},
             "content": "not a dict"},
        ]}
        links = WormholeModule._parse(response, ETH_ADDR)
        assert len(links) == 1
        assert links[0]["evidence_ref"] == "op2"
        assert links[0]["source_tx"] is None
        assert links[0]["dest_chain"] is None

    def test_search_wires_the_address_into_the_query_and_summary(self):
        module = WormholeModule()
        captured = {}

        async def fake_fetch_json(url, **kwargs):
            captured["url"] = url
            return {"operations": [{
                "id": "op1", "sourceChain": {"chainId": 1, "transaction": {"txHash": "tx1"}},
                "content": {"standarizedProperties": {}},
            }]}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search(SOL_ADDR))
        assert SOL_ADDR in captured["url"]
        assert len(result.summary["transaction_cross_chain_links"]) == 1


class TestThorchainModule:
    def test_parses_a_genuine_l1_swap(self):
        response = {"actions": [{
            "type": "swap", "status": "success", "date": "1700000000000000000",
            "in": [{"address": "bc1qsrc", "coins": [{"asset": "BTC.BTC"}], "txID": "BTCTX1"}],
            "out": [{"address": ETH_ADDR, "coins": [{"asset": "ETH.ETH"}], "txID": "ETHTX1"}],
        }]}
        links = ThorchainModule._parse(response)
        assert len(links) == 1
        link = links[0]
        assert link["source_chain"] == "BTC_ADDRESS"
        assert link["source_address"] == "bc1qsrc"
        assert link["source_tx"] == "BTCTX1"
        assert link["dest_chain"] == "ETH_ADDRESS"
        assert link["dest_address"] == ETH_ADDR
        assert link["dest_tx"] == "ETHTX1"
        assert link["mechanism"] == SWAP
        assert link["evidence_ref"] == "BTCTX1"
        assert link["source_api"] == "thorchain_midgard"
        assert link["status"] == "success"
        assert link["tx_timestamp"] == "2023-11-14T22:13:20+00:00"

    def test_skips_a_trade_account_leg_with_no_genuine_l1_address(self):
        """A Trade Account asset (tilde, not dot) reports a thor1... bech32
        account instead of the depositor's real L1 address -- must not be
        reported as that chain's address (Loop 42 audit)."""
        response = {"actions": [{
            "type": "swap", "status": "success", "date": "1700000000000000000",
            "in": [{"address": "thor1xxxx", "coins": [{"asset": "ETH~ETH"}], "txID": "TX2"}],
            "out": [],
        }]}
        assert ThorchainModule._parse(response) == []

    def test_skips_a_non_swap_action(self):
        response = {"actions": [{
            "type": "addLiquidity",
            "in": [{"address": "bc1qx", "coins": [{"asset": "BTC.BTC"}], "txID": "TX3"}],
        }]}
        assert ThorchainModule._parse(response) == []

    def test_skips_an_action_with_no_in_leg(self):
        response = {"actions": [{"type": "swap", "in": [], "out": []}]}
        assert ThorchainModule._parse(response) == []

    def test_dest_is_none_when_the_out_leg_is_a_trade_account(self):
        """The IN leg can be genuine L1 while OUT is a trade account (or
        vice versa) -- dest_chain/dest_address must be None, not a
        misreported thor1... string standing in for a chain address."""
        response = {"actions": [{
            "type": "swap", "date": "1700000000000000000",
            "in": [{"address": "bc1qsrc", "coins": [{"asset": "BTC.BTC"}], "txID": "TX4"}],
            "out": [{"address": "thor1yyyy", "coins": [{"asset": "BTC~BTC"}], "txID": "TX5"}],
        }]}
        links = ThorchainModule._parse(response)
        assert len(links) == 1
        assert links[0]["dest_chain"] is None
        assert links[0]["dest_address"] is None

    def test_no_actions_key_is_handled(self):
        assert ThorchainModule._parse({}) == []

    def test_malformed_actions_and_legs_do_not_crash(self):
        """A non-dict action, a non-list in/out, or a non-dict leg/coin must
        be skipped rather than crash the whole parse."""
        response = {"actions": [
            "not a dict",
            {"type": "swap", "in": "not a list", "out": []},
            {"type": "swap", "in": [{"address": "bc1qsrc", "coins": ["not a dict"], "txID": "TX1"}],
             "out": []},
            {"type": "swap", "in": [{"address": "bc1qsrc2", "coins": [{"asset": "BTC.BTC"}],
                                     "txID": "TX2"}],
             "out": "not a list", "date": "not-a-number"},
        ]}
        links = ThorchainModule._parse(response)
        assert len(links) == 1
        assert links[0]["source_address"] == "bc1qsrc2"
        assert links[0]["dest_chain"] is None
        assert links[0]["tx_timestamp"] is None  # malformed date degrades, does not crash

    def test_search_reports_failure_when_fetch_json_returns_none(self):
        module = ThorchainModule()

        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search("bc1qsrc"))
        assert result.sources["thorchain_midgard"].success is False

    def test_search_does_not_crash_on_a_non_dict_response(self):
        module = ThorchainModule()

        async def fake_fetch_json(url, **kwargs):
            return "not a dict"
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search("bc1qsrc"))
        assert result.sources["thorchain_midgard"].success is False
