"""Tests for cybertrace.modules.solana_module (Loop 38 Section 8).

Mocks at the fetch_json level (same convention as test_modules.py's
bitcoin/tron coverage) so _rpc's own result/error extraction is actually
exercised, not bypassed.
"""

import asyncio

from cybertrace.integrations import exchange_tags
from cybertrace.modules import MODULE_REGISTRY, TYPE_TO_MODULE, get_module
from cybertrace.modules.base import ModuleResult, SourceResult
from cybertrace.modules.solana_module import SolanaModule

ADDR = "FxteHmLwG9nk1eL4pjNve3Eub2goGkkz6g6TbvdmW46a"   # real Bitfinex Solana hot wallet
PEER_A = "3yJ1h8xrF5yFhazVZoxm8QxX5huM1tEudzAx2tub6kmH"  # real, unrelated Solana address
PEER_B = "3yJNtRhKbVSnTm9GZD3ubWbUhbzvX3P9KJjj87pWpkmH"


class TestSolanaModuleRegistration:
    def test_registered_under_solana(self):
        assert MODULE_REGISTRY['solana'] is SolanaModule
        assert TYPE_TO_MODULE['solana'] == 'solana'
        module = get_module('solana')
        assert isinstance(module, SolanaModule)

    def test_module_attributes(self):
        module = SolanaModule()
        assert module.name == 'solana'
        assert 'solana' in module.supported_types


class TestSolanaRpcUrl:
    def test_defaults_to_the_public_endpoint(self):
        module = SolanaModule()
        original = module.config.api_keys.solana_rpc
        module.config.api_keys.solana_rpc = None
        try:
            assert module._rpc_url() == "https://api.mainnet-beta.solana.com"
        finally:
            module.config.api_keys.solana_rpc = original

    def test_uses_a_configured_private_endpoint(self):
        module = SolanaModule()
        original = module.config.api_keys.solana_rpc
        module.config.api_keys.solana_rpc = "https://my-private-rpc.example/key123"
        try:
            assert module._rpc_url() == "https://my-private-rpc.example/key123"
        finally:
            module.config.api_keys.solana_rpc = original


class TestSolanaRetryablePredicate:
    """Same in-band-rate-limit shape as NodeReal/TronGrid -- HTTP 200 with a
    JSON-RPC `error` that is actually a transient rate limit, which
    fetch_json's own status-code retry never sees without this hook."""

    def test_rate_limit_message_is_retryable(self):
        assert SolanaModule._retryable(
            {'jsonrpc': '2.0', 'error': {'code': 429, 'message': 'Too many requests'}}) is True

    def test_generic_rate_limit_wording_is_retryable(self):
        assert SolanaModule._retryable(
            {'jsonrpc': '2.0', 'error': {'code': -32005, 'message': 'rate limit exceeded'}}) is True

    def test_permanent_error_is_not_retryable(self):
        assert SolanaModule._retryable(
            {'jsonrpc': '2.0', 'error': {'code': -32602, 'message': 'invalid params'}}) is False

    def test_a_successful_body_is_not_retryable(self):
        assert SolanaModule._retryable({'jsonrpc': '2.0', 'result': {'value': 0}}) is False

    def test_malformed_body_does_not_crash(self):
        assert SolanaModule._retryable([1, 2, 3]) is False
        assert SolanaModule._retryable(None) is False


class TestSolanaRpcCall:
    def test_wires_the_retryable_predicate_into_fetch_json(self):
        module = SolanaModule()
        captured = {}

        async def fake_fetch_json(url, **kwargs):
            captured['retryable_body'] = kwargs.get('retryable_body')
            captured['method'] = kwargs['json']['method']
            captured['url'] = url
            return {'jsonrpc': '2.0', 'result': 42}
        module.fetch_json = fake_fetch_json
        result, err = asyncio.run(module._rpc('getBalance', [ADDR]))
        assert result == 42
        assert err is None
        assert captured['method'] == 'getBalance'
        assert captured['url'] == module._rpc_url()
        assert captured['retryable_body'] is module._retryable

    def test_fetch_json_failure_reports_rpc_failed(self):
        module = SolanaModule()

        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        from cybertrace.modules.solana_module import _RPC_FAILED
        result, err = asyncio.run(module._rpc('getBalance', [ADDR]))
        assert result is _RPC_FAILED
        assert err

    def test_json_rpc_error_reports_rpc_failed(self):
        module = SolanaModule()

        async def fake_fetch_json(url, **kwargs):
            return {'jsonrpc': '2.0', 'error': {'code': -32000, 'message': 'boom'}}
        module.fetch_json = fake_fetch_json
        from cybertrace.modules.solana_module import _RPC_FAILED
        result, err = asyncio.run(module._rpc('getBalance', [ADDR]))
        assert result is _RPC_FAILED
        assert 'boom' in err

    def test_a_legitimate_null_result_is_not_rpc_failed(self):
        """getTransaction on a signature the node no longer retains returns
        result: null with NO error -- must read as "nothing here", not a
        fetch failure. See _RPC_FAILED's own docstring."""
        module = SolanaModule()

        async def fake_fetch_json(url, **kwargs):
            return {'jsonrpc': '2.0', 'result': None}
        module.fetch_json = fake_fetch_json
        from cybertrace.modules.solana_module import _RPC_FAILED
        result, err = asyncio.run(module._rpc('getTransaction', ['sig']))
        assert result is None
        assert result is not _RPC_FAILED
        assert err is None


def _fake_tx(address: str, peer: str, pre_me: int, post_me: int,
            pre_peer: int, post_peer: int, block_time: int = 1700000000) -> dict:
    return {
        'blockTime': block_time,
        'transaction': {'message': {'accountKeys': [address, peer]}},
        'meta': {'preBalances': [pre_me, pre_peer], 'postBalances': [post_me, post_peer]},
    }


class TestCheckSolanaRpc:
    def _module_with(self, monkeypatch, balance_result, signatures_result, tx_by_sig):
        module = SolanaModule()

        async def fake_fetch_json(url, **kwargs):
            method = kwargs['json']['method']
            if method == 'getBalance':
                if balance_result is None:
                    return None
                return {'jsonrpc': '2.0', 'result': balance_result}
            if method == 'getSignaturesForAddress':
                if signatures_result is None:
                    return None
                return {'jsonrpc': '2.0', 'result': signatures_result}
            if method == 'getTransaction':
                sig = kwargs['json']['params'][0]
                tx = tx_by_sig.get(sig, 'MISSING')
                if tx == 'MISSING':
                    return None  # simulates a genuine fetch failure
                return {'jsonrpc': '2.0', 'result': tx}  # tx may legitimately be None
            raise AssertionError(f"unexpected method {method}")
        module.fetch_json = fake_fetch_json
        return module

    def test_balance_fetch_failure_is_reported(self, monkeypatch):
        module = self._module_with(monkeypatch, balance_result=None,
                                   signatures_result=[], tx_by_sig={})
        result = asyncio.run(module._check_solana_rpc(ADDR))
        assert result.success is False
        assert result.error

    def test_signatures_fetch_failure_is_reported(self, monkeypatch):
        module = self._module_with(monkeypatch, balance_result={'value': 0},
                                   signatures_result=None, tx_by_sig={})
        result = asyncio.run(module._check_solana_rpc(ADDR))
        assert result.success is False
        assert result.error

    def test_a_wallet_with_no_history_is_success_not_failure(self, monkeypatch):
        module = self._module_with(monkeypatch, balance_result={'value': 5_000_000_000},
                                   signatures_result=[], tx_by_sig={})
        result = asyncio.run(module._check_solana_rpc(ADDR))
        assert result.success is True
        assert result.data['tx_count'] == 0
        assert result.data['balance_sol'] == 5.0
        assert result.data.get('pagination_incomplete', False) is False

    def test_extracts_counterparty_and_direction_from_balance_change(self, monkeypatch):
        sent_tx = _fake_tx(ADDR, PEER_A, pre_me=10_000_000_000, post_me=8_000_000_000,
                           pre_peer=0, post_peer=2_000_000_000)
        received_tx = _fake_tx(ADDR, PEER_B, pre_me=8_000_000_000, post_me=9_000_000_000,
                               pre_peer=3_000_000_000, post_peer=2_000_000_000)
        module = self._module_with(
            monkeypatch, balance_result={'value': 9_000_000_000},
            signatures_result=[{'signature': 'sig1', 'blockTime': 1700000000},
                              {'signature': 'sig2', 'blockTime': 1700000100}],
            tx_by_sig={'sig1': sent_tx, 'sig2': received_tx})
        result = asyncio.run(module._check_solana_rpc(ADDR))
        assert result.success is True
        assert result.data['sent_to_addresses'] == [PEER_A]
        assert result.data['received_from_addresses'] == [PEER_B]
        assert sorted(result.data['counterparty_addresses']) == sorted([PEER_A, PEER_B])
        assert result.data['first_seen'] < result.data['last_seen']

    def test_a_failed_transaction_detail_fetch_flags_pagination_incomplete(self, monkeypatch):
        module = self._module_with(
            monkeypatch, balance_result={'value': 0},
            signatures_result=[{'signature': 'sig-missing', 'blockTime': 1700000000}],
            tx_by_sig={})  # 'MISSING' sentinel -> fetch_json returns None
        result = asyncio.run(module._check_solana_rpc(ADDR))
        assert result.success is True   # balance/signature list still came back fine
        assert result.data['pagination_incomplete'] is True
        assert result.data['counterparty_addresses'] == []

    def test_a_pruned_transaction_is_not_flagged_incomplete(self, monkeypatch):
        """result: null (no error) -- a real, common public-RPC history-
        retention gap -- must not be confused with a genuine failure."""
        module = self._module_with(
            monkeypatch, balance_result={'value': 0},
            signatures_result=[{'signature': 'sig-pruned', 'blockTime': 1700000000}],
            tx_by_sig={'sig-pruned': None})
        result = asyncio.run(module._check_solana_rpc(ADDR))
        assert result.success is True
        assert result.data.get('pagination_incomplete', False) is False

    def test_deep_flag_requests_a_wider_signature_limit(self, monkeypatch):
        from cybertrace.modules.solana_module import _DEEP_LIMIT, _SHALLOW_LIMIT
        module = SolanaModule()
        captured = {}

        async def fake_fetch_json(url, **kwargs):
            method = kwargs['json']['method']
            if method == 'getBalance':
                return {'jsonrpc': '2.0', 'result': {'value': 0}}
            if method == 'getSignaturesForAddress':
                captured['limit'] = kwargs['json']['params'][1]['limit']
                return {'jsonrpc': '2.0', 'result': []}
            raise AssertionError
        module.fetch_json = fake_fetch_json
        asyncio.run(module._check_solana_rpc(ADDR, deep=False))
        assert captured['limit'] == _SHALLOW_LIMIT
        asyncio.run(module._check_solana_rpc(ADDR, deep=True))
        assert captured['limit'] == _DEEP_LIMIT


class TestExtractPeer:
    def test_sent_direction_from_a_balance_decrease(self):
        tx = _fake_tx(ADDR, PEER_A, pre_me=10_000_000_000, post_me=8_000_000_000,
                     pre_peer=0, post_peer=2_000_000_000)
        peer, direction = SolanaModule._extract_peer(tx, ADDR)
        assert peer == PEER_A
        assert direction == 'sent'

    def test_received_direction_from_a_balance_increase(self):
        tx = _fake_tx(ADDR, PEER_A, pre_me=1_000_000_000, post_me=3_000_000_000,
                     pre_peer=5_000_000_000, post_peer=3_000_000_000)
        peer, direction = SolanaModule._extract_peer(tx, ADDR)
        assert peer == PEER_A
        assert direction == 'received'

    def test_account_keys_as_pubkey_dicts_are_normalized(self):
        tx = {
            'transaction': {'message': {'accountKeys': [
                {'pubkey': ADDR}, {'pubkey': PEER_A}]}},
            'meta': {'preBalances': [10, 0], 'postBalances': [8, 2]},
        }
        peer, direction = SolanaModule._extract_peer(tx, ADDR)
        assert peer == PEER_A
        assert direction == 'sent'

    def test_zero_balance_change_yields_no_peer(self):
        tx = _fake_tx(ADDR, PEER_A, pre_me=5_000_000_000, post_me=5_000_000_000,
                     pre_peer=0, post_peer=0)
        assert SolanaModule._extract_peer(tx, ADDR) == (None, None)

    def test_address_absent_from_the_transaction_yields_no_peer(self):
        tx = _fake_tx(PEER_A, PEER_B, pre_me=10, post_me=8, pre_peer=0, post_peer=2)
        assert SolanaModule._extract_peer(tx, ADDR) == (None, None)

    def test_malformed_transaction_shape_does_not_crash(self):
        assert SolanaModule._extract_peer({}, ADDR) == (None, None)
        assert SolanaModule._extract_peer({'transaction': None}, ADDR) == (None, None)


class TestSolanaExchangeTags:
    def test_degrades_when_dataset_not_downloaded(self, monkeypatch):
        monkeypatch.setattr(exchange_tags, "available", lambda: False)
        module = SolanaModule()
        result = asyncio.run(module._check_exchange_tags(ADDR))
        assert result.success is False
        assert 'not downloaded' in result.error

    def test_degrades_when_index_not_built(self, monkeypatch):
        monkeypatch.setattr(exchange_tags, "available", lambda: True)
        monkeypatch.setattr(exchange_tags, "index_available", lambda: False)
        module = SolanaModule()
        result = asyncio.run(module._check_exchange_tags(ADDR))
        assert result.success is False
        assert 'build_index' in result.error

    def test_degrades_when_index_is_stale(self, monkeypatch):
        monkeypatch.setattr(exchange_tags, "available", lambda: True)
        monkeypatch.setattr(exchange_tags, "index_available", lambda: True)
        monkeypatch.setattr(exchange_tags, "is_stale", lambda: True)
        module = SolanaModule()
        result = asyncio.run(module._check_exchange_tags(ADDR))
        assert result.success is False
        assert 'stale' in result.error

    def test_untagged_address_is_a_successful_negative(self, monkeypatch):
        monkeypatch.setattr(exchange_tags, "available", lambda: True)
        monkeypatch.setattr(exchange_tags, "index_available", lambda: True)
        monkeypatch.setattr(exchange_tags, "is_stale", lambda: False)
        monkeypatch.setattr(exchange_tags, "lookup_address", lambda addr, cur: [])
        module = SolanaModule()
        result = asyncio.run(module._check_exchange_tags(ADDR))
        assert result.success is True
        assert result.data == {'tagged': False}

    def test_a_real_bitfinex_tag_reports_exchange_attribution(self, monkeypatch):
        monkeypatch.setattr(exchange_tags, "available", lambda: True)
        monkeypatch.setattr(exchange_tags, "index_available", lambda: True)
        monkeypatch.setattr(exchange_tags, "is_stale", lambda: False)
        monkeypatch.setattr(exchange_tags, "lookup_address", lambda addr, cur: [
            {"currency": "SOL", "category": "exchange", "label": "bitfinex Solana hot wallet",
             "actor": "bitfinex",
             "source": "https://github.com/bitfinexcom/pub/blob/main/wallets.txt",
             "pack": "exchange-wallets-bitfinexcom"},
        ])
        module = SolanaModule()
        result = asyncio.run(module._check_exchange_tags(ADDR))
        assert result.success is True
        assert result.data['tagged'] is True
        assert result.data['is_exchange_tagged'] is True
        assert result.data['labels'] == ['bitfinex Solana hot wallet']


class TestSolanaBuildSummary:
    def test_shares_tron_shaped_fields_for_enrich_bitcoin_reuse(self):
        """evidence._ENRICHERS routes 'solana' through the same generic
        enrich_bitcoin tron already reuses -- this only works if the summary
        carries the same field names (Loop 38 Section 8)."""
        module = SolanaModule()
        result = ModuleResult(target=ADDR, target_type='solana', module='solana')
        result.sources['solana_rpc'] = SourceResult(
            source='solana_rpc', success=True, data={
                'balance_sol': 1.5, 'tx_count': 2,
                'first_seen': '2026-01-01T00:00:00+00:00',
                'last_seen': '2026-01-02T00:00:00+00:00',
                'counterparty_addresses': [PEER_A], 'sent_to_addresses': [PEER_A],
                'received_from_addresses': [], 'connected_addresses': [PEER_A],
            })
        summary = module._build_summary(result)
        for key in ('address', 'balance', 'tx_count', 'first_seen', 'last_seen',
                   'counterparty_addresses', 'sent_to_addresses',
                   'received_from_addresses', 'connected_addresses'):
            assert key in summary
        assert summary['balance'] == '1.500000000 SOL'
        assert summary['counterparty_addresses'] == [PEER_A]
        assert PEER_A in result.related

    def test_pagination_incomplete_reaches_the_summary(self):
        module = SolanaModule()
        result = ModuleResult(target=ADDR, target_type='solana', module='solana')
        result.sources['solana_rpc'] = SourceResult(
            source='solana_rpc', success=True,
            data={'balance_sol': 0, 'tx_count': 1, 'first_seen': None, 'last_seen': None,
                 'counterparty_addresses': [], 'sent_to_addresses': [],
                 'received_from_addresses': [], 'connected_addresses': [],
                 'pagination_incomplete': True})
        summary = module._build_summary(result)
        assert summary['pagination_incomplete'] is True


class TestSolanaEndToEndSearch:
    def test_search_runs_both_sources_and_builds_a_summary(self, monkeypatch):
        module = SolanaModule()

        async def fake_fetch_json(url, **kwargs):
            method = kwargs['json']['method']
            if method == 'getBalance':
                return {'jsonrpc': '2.0', 'result': {'value': 1_000_000_000}}
            if method == 'getSignaturesForAddress':
                return {'jsonrpc': '2.0', 'result': []}
            raise AssertionError
        module.fetch_json = fake_fetch_json
        monkeypatch.setattr(exchange_tags, "available", lambda: False)

        result = asyncio.run(module.search(ADDR))
        assert result.target_type == 'solana'
        assert result.sources['solana_rpc'].success is True
        assert result.sources['exchange_tags'].success is False
        assert result.summary['balance'] == '1.000000000 SOL'
