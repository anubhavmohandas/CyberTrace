"""Tests for cybertrace.modules.cross_chain_module (Loops 42 and 44).

Mocked at the fetch_json level (same convention as test_solana_module.py)
so each module's own _parse() is exercised against realistic response
shapes without a live network call. The shapes below are drawn from a
live-verified audit of the real Wormholescan/Midgard/Across/LI.FI APIs,
not guessed.
"""
import asyncio

from cybertrace.modules.cross_chain_module import (
    AcrossModule, BRIDGE, LifiModule, SWAP, ThorchainModule, WormholeModule,
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


class TestAcrossModule:
    def test_parses_a_filled_deposit(self):
        response = [{
            "originChainId": 1, "destinationChainId": 56,
            "depositor": ETH_ADDR, "recipient": ETH_ADDR,
            "depositTxHash": "0xdep1", "fillTx": "0xfill1",
            "depositBlockTimestamp": "2026-09-03T02:48:00.000Z",
            "status": "filled",
        }]
        links = AcrossModule._parse(response)
        assert len(links) == 1
        link = links[0]
        assert link["source_chain"] == "ETH_ADDRESS"
        assert link["source_address"] == ETH_ADDR
        assert link["source_tx"] == "0xdep1"
        assert link["dest_chain"] == "BNB_ADDRESS"
        assert link["dest_address"] == ETH_ADDR
        assert link["dest_tx"] == "0xfill1"
        assert link["mechanism"] == BRIDGE
        assert link["evidence_ref"] == "0xdep1"
        assert link["source_api"] == "across"
        assert link["status"] == "filled"

    def test_unfilled_deposit_has_no_dest_tx(self):
        response = [{
            "originChainId": 137, "destinationChainId": 1,
            "depositor": ETH_ADDR, "recipient": ETH_ADDR,
            "depositTxHash": "0xdep2", "fillTx": None, "status": "unfilled",
        }]
        links = AcrossModule._parse(response)
        assert len(links) == 1
        assert links[0]["dest_tx"] is None
        assert links[0]["status"] == "unfilled"

    def test_skips_a_deposit_on_a_chain_this_codebase_does_not_trace(self):
        """A real Across origin/destination like 8453 (Base) or 42161
        (Arbitrum) isn't a CyberTrace-traced chain -- must be skipped."""
        response = [{
            "originChainId": 8453, "destinationChainId": 42161,
            "depositor": ETH_ADDR, "recipient": ETH_ADDR,
            "depositTxHash": "0xdep3", "status": "filled",
        }]
        assert AcrossModule._parse(response) == []

    def test_skips_a_deposit_with_no_depositor_or_no_tx(self):
        response = [
            {"originChainId": 1, "destinationChainId": 56,
             "depositor": None, "depositTxHash": "0xdep4"},
            {"originChainId": 1, "destinationChainId": 56,
             "depositor": ETH_ADDR, "depositTxHash": None},
        ]
        assert AcrossModule._parse(response) == []

    def test_parse_skips_malformed_list_entries_without_crashing(self):
        response = ["not a dict", {"originChainId": 999}]
        assert AcrossModule._parse(response) == []

    def test_search_reports_failure_when_fetch_json_returns_none(self):
        module = AcrossModule()

        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search(ETH_ADDR))
        assert result.sources["across"].success is False

    def test_search_does_not_crash_on_a_non_list_response(self):
        """The real API returns a bare list; a dict (or anything else)
        would be an unexpected shape -- must degrade, never crash."""
        module = AcrossModule()

        async def fake_fetch_json(url, **kwargs):
            return {"not": "a list"}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search(ETH_ADDR))
        assert result.sources["across"].success is False

    def test_search_wires_the_address_into_the_query_and_summary(self):
        module = AcrossModule()
        captured = {}

        async def fake_fetch_json(url, **kwargs):
            captured["url"] = url
            return [{"originChainId": 1, "destinationChainId": 137,
                     "depositor": ETH_ADDR, "recipient": ETH_ADDR,
                     "depositTxHash": "0xdep5", "status": "filled"}]
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search(ETH_ADDR))
        assert ETH_ADDR in captured["url"]
        assert len(result.summary["transaction_cross_chain_links"]) == 1

    def test_duplicate_records_in_one_response_both_parse(self):
        """An adversarial or simply repeating API response must not crash
        or silently merge two records -- dedup on evidence_ref happens at
        the evidence-store layer (see test_cli_cross_chain's rerun test),
        not here."""
        dep = {"originChainId": 1, "destinationChainId": 56,
               "depositor": ETH_ADDR, "recipient": ETH_ADDR,
               "depositTxHash": "0xdup", "status": "filled"}
        links = AcrossModule._parse([dep, dep])
        assert len(links) == 2
        assert links[0]["evidence_ref"] == links[1]["evidence_ref"]

    def test_huge_string_and_unicode_fields_do_not_crash(self):
        response = [{
            "originChainId": 1, "destinationChainId": 56,
            "depositor": "0x" + "f" * 100_000,
            "recipient": "0x🪙💰🔥" + "字" * 5000,
            "depositTxHash": "0x" + "a" * 100_000, "status": "🚀" * 10_000,
        }]
        links = AcrossModule._parse(response)
        assert len(links) == 1
        assert links[0]["status"] == "🚀" * 10_000


class TestLifiModule:
    def test_parses_a_genuine_cross_chain_transfer(self):
        response = {"transfers": [{
            "transactionId": "txn1",
            "fromAddress": ETH_ADDR, "toAddress": ETH_ADDR,
            "sending": {"chainId": 1, "txHash": "0xsend1", "timestamp": 1700000000},
            "receiving": {"chainId": 137, "txHash": "0xrecv1"},
            "status": "DONE",
        }]}
        links = LifiModule._parse(response["transfers"])
        assert len(links) == 1
        link = links[0]
        assert link["source_chain"] == "ETH_ADDRESS"
        assert link["source_address"] == ETH_ADDR
        assert link["source_tx"] == "0xsend1"
        assert link["dest_chain"] == "POLYGON_ADDRESS"
        assert link["dest_address"] == ETH_ADDR
        assert link["dest_tx"] == "0xrecv1"
        assert link["mechanism"] == BRIDGE
        assert link["evidence_ref"] == "txn1"
        assert link["source_api"] == "lifi"
        assert link["status"] == "DONE"
        assert link["tx_timestamp"] == "2023-11-14T22:13:20+00:00"

    def test_skips_a_same_chain_swap(self):
        """LI.FI's own transfers feed mixes in-chain swaps with real
        cross-chain moves (live-verified, Loop 44) -- a swap must never be
        reported as cross-chain evidence."""
        response = [{
            "transactionId": "txn2",
            "fromAddress": ETH_ADDR, "toAddress": ETH_ADDR,
            "sending": {"chainId": 1, "txHash": "0xsend2"},
            "receiving": {"chainId": 1, "txHash": "0xrecv2"},
            "status": "DONE",
        }]
        assert LifiModule._parse(response) == []

    def test_skips_a_transfer_on_a_chain_this_codebase_does_not_trace(self):
        response = [{
            "transactionId": "txn3", "fromAddress": ETH_ADDR,
            "sending": {"chainId": 8453, "txHash": "0xsend3"},
            "receiving": {"chainId": 1, "txHash": "0xrecv3"},
        }]
        assert LifiModule._parse(response) == []

    def test_skips_a_transfer_with_no_from_address_or_no_tx_or_no_id(self):
        response = [
            {"transactionId": "txn4", "fromAddress": None,
             "sending": {"chainId": 1, "txHash": "0xsend4"}, "receiving": {"chainId": 137}},
            {"transactionId": "txn5", "fromAddress": ETH_ADDR,
             "sending": {"chainId": 1, "txHash": None}, "receiving": {"chainId": 137}},
            {"transactionId": None, "fromAddress": ETH_ADDR,
             "sending": {"chainId": 1, "txHash": "0xsend6"}, "receiving": {"chainId": 137}},
        ]
        assert LifiModule._parse(response) == []

    def test_malformed_entries_and_legs_do_not_crash(self):
        response = [
            "not a dict",
            {"transactionId": "txn7", "fromAddress": ETH_ADDR,
             "sending": "not a dict", "receiving": {"chainId": 137}},
            {"transactionId": "txn8", "fromAddress": ETH_ADDR,
             "sending": {"chainId": 1, "txHash": "0xsend8", "timestamp": "not-a-number"},
             "receiving": "not a dict"},
        ]
        links = LifiModule._parse(response)
        assert len(links) == 1
        assert links[0]["evidence_ref"] == "txn8"
        assert links[0]["dest_chain"] is None
        assert links[0]["tx_timestamp"] is None  # malformed timestamp degrades, does not crash

    def test_search_reports_failure_when_fetch_json_returns_none(self):
        module = LifiModule()

        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search(ETH_ADDR))
        assert result.sources["lifi"].success is False

    def test_search_reports_failure_on_an_error_body_with_no_transfers_key(self):
        """A malformed-address 400 from the real API lands here: a 200-
        shaped dict (fetch_json's own contract) with no `transfers` key."""
        module = LifiModule()

        async def fake_fetch_json(url, **kwargs):
            return {"message": "/wallet Invalid address", "code": 1011}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search("notanaddress"))
        assert result.sources["lifi"].success is False

    def test_search_wires_the_address_into_the_query_and_summary(self):
        module = LifiModule()
        captured = {}

        async def fake_fetch_json(url, **kwargs):
            captured["url"] = url
            return {"transfers": [{
                "transactionId": "txn9", "fromAddress": ETH_ADDR,
                "sending": {"chainId": 1, "txHash": "0xsend9"},
                "receiving": {"chainId": 56, "txHash": "0xrecv9"},
            }]}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module.search(ETH_ADDR))
        assert ETH_ADDR in captured["url"]
        assert len(result.summary["transaction_cross_chain_links"]) == 1

    def test_duplicate_records_in_one_response_both_parse(self):
        t = {"transactionId": "dup1", "fromAddress": ETH_ADDR,
             "sending": {"chainId": 1, "txHash": "0xsend"},
             "receiving": {"chainId": 56, "txHash": "0xrecv"}}
        links = LifiModule._parse([t, dict(t)])
        assert len(links) == 2
        assert links[0]["evidence_ref"] == links[1]["evidence_ref"] == "dup1"

    def test_huge_string_and_unicode_fields_do_not_crash(self):
        response = [{
            "transactionId": "🔥" * 10_000,
            "fromAddress": "0x" + "f" * 100_000,
            "toAddress": "0x🪙" + "字" * 5000,
            "sending": {"chainId": 1, "txHash": "0x" + "a" * 100_000},
            "receiving": {"chainId": 56, "txHash": "0x" + "b" * 100_000},
            "status": "DONE" * 5000,
        }]
        links = LifiModule._parse(response)
        assert len(links) == 1
        assert links[0]["evidence_ref"] == "🔥" * 10_000
