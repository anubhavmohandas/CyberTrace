"""Tests for OSINT modules."""

import pytest
from cybertrace.modules import (
    get_module,
    list_modules,
    MODULE_REGISTRY,
    TYPE_TO_MODULE,
    BitcoinModule,
    TronModule,
    UsernameModule,
    DomainModule,
    EmailModule,
    DarkwebModule,
    IndianModule,
    PhoneModule,
    GeointModule,
    IPModule,
    ImageModule,
    BreachModule,
    SocialModule,
)
from cybertrace.integrations import evolution, exchange_tags
from cybertrace.modules.base import ModuleResult, SourceResult
from cybertrace.normalize import norm_btc, norm_email, norm_xmr

# norm_onion verifies the checksum a v3 address carries, so a fixture has to be
# an address that could exist — `'b' * 56` is exactly what that gate refuses.
from .test_evidence import onion as checksummed_onion, TRX_VALID


class TestModuleRegistry:
    """Test module registry functionality."""

    def test_module_registry_not_empty(self):
        assert len(MODULE_REGISTRY) > 0

    def test_all_modules_registered(self):
        expected = ['bitcoin', 'ethereum', 'tron', 'domain', 'username', 'email',
                   'darkweb', 'indian']
        for name in expected:
            assert name in MODULE_REGISTRY

    def test_type_to_module_mapping(self):
        assert TYPE_TO_MODULE['email'] == 'email'
        assert TYPE_TO_MODULE['btc_legacy'] == 'bitcoin'
        assert TYPE_TO_MODULE['vehicle_indian'] == 'indian'
        assert TYPE_TO_MODULE['tron'] == 'tron'

    def test_get_module_returns_tron_instance(self):
        module = get_module('tron')
        assert module is not None
        assert isinstance(module, TronModule)

    def test_get_module_returns_instance(self):
        module = get_module('bitcoin')
        assert module is not None
        assert isinstance(module, BitcoinModule)

    def test_get_module_invalid_returns_none(self):
        module = get_module('nonexistent')
        assert module is None

    def test_list_modules_returns_dict(self):
        modules = list_modules()
        assert isinstance(modules, dict)
        assert 'bitcoin' in modules
        assert 'domain' in modules


class TestBitcoinModule:
    """Test Bitcoin module."""

    def test_module_attributes(self):
        module = BitcoinModule()
        assert module.name == 'bitcoin'
        assert 'bitcoin' in module.supported_types
        assert 'ethereum' in module.supported_types

    def test_detect_crypto_type_btc_legacy(self):
        module = BitcoinModule()
        result = module._detect_crypto_type("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert result == 'bitcoin'

    def test_detect_crypto_type_btc_bech32(self):
        module = BitcoinModule()
        result = module._detect_crypto_type("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
        assert result == 'bitcoin'

    def test_detect_crypto_type_ethereum(self):
        module = BitcoinModule()
        result = module._detect_crypto_type("0x742d35Cc6634C0532925a3b844Bc9e7595f12345")
        assert result == 'ethereum'


class TestBitcoinModuleChainabuse:
    """Chainabuse rides the same graceful-degradation-without-a-key path as
    Shodan (darkweb_module._favicon_pivot), and the same non-attributive
    metadata path bitcoinabuse (cryptoscamdb) already uses — a report becomes
    `reported_scam` metadata on the address, never an operator-funnel signal.
    """

    def test_no_key_configured_degrades_gracefully(self):
        import asyncio
        module = BitcoinModule()
        module.config.api_keys.chainabuse = None
        result = asyncio.run(
            module._check_chainabuse('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'BTC'))
        assert result.success is False
        assert 'CHAINABUSE_API_KEY' in result.error

    def test_a_report_is_parsed_from_the_documented_response_shape(self):
        import asyncio
        module = BitcoinModule()
        module.config.api_keys.chainabuse = 'testkey'
        try:
            async def fake_fetch_json(url, **kwargs):
                assert url == 'https://api.chainabuse.com/v0/reports'
                assert kwargs['params']['chain'] == 'BTC'
                return {
                    'reports': [
                        {'id': 'r1', 'trusted': True, 'scamCategory': 'RUG_PULL',
                         'createdAt': '2026-02-01T00:00:00.000Z'},
                        {'id': 'r2', 'trusted': False, 'scamCategory': 'PHISHING',
                         'createdAt': '2026-01-15T00:00:00.000Z'},
                    ],
                    'count': 2,
                }
            module.fetch_json = fake_fetch_json
            result = asyncio.run(
                module._check_chainabuse('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'BTC'))
            assert result.success is True
            assert result.data == {
                'reported': True,
                'report_count': 2,
                'scam_categories': ['PHISHING', 'RUG_PULL'],
                'trusted_report_count': 1,
                # Sorted, not filing order — report_dates is when each report
                # was FILED (external paperwork), never a sighting of the
                # address; see evidence.enrich_bitcoin's chainabuse_* docstring.
                'report_dates': ['2026-01-15T00:00:00.000Z', '2026-02-01T00:00:00.000Z'],
            }
        finally:
            module.config.api_keys.chainabuse = None


class TestBitcoinModuleEtherscan:
    """Ethereum counterparty extraction -- ETH is account-based like TRON, so
    this mirrors TestTronModule's trongrid_transactions coverage rather than
    _check_blockchain_com's cospend/counterparty split, which needs UTXO
    inputs ETH doesn't have."""

    ETH_ADDR = "0x742d35Cc6634C0532925a3b844Bc9e7595f12345"

    def test_no_key_configured_degrades_gracefully(self):
        import asyncio
        module = BitcoinModule()
        module.config.api_keys.etherscan = None
        result = asyncio.run(module._check_etherscan_transactions(self.ETH_ADDR))
        assert result.success is False
        assert 'ETHERSCAN_API_KEY' in result.error

    def test_transactions_yield_counterparties_and_connected_addresses(self):
        import asyncio
        module = BitcoinModule()
        module.config.api_keys.etherscan = 'testkey'
        peer = "0x0000000000000000000000000000000000dead"
        try:
            async def fake_fetch_json(url, **kwargs):
                assert url == 'https://api.etherscan.io/api'
                assert kwargs['params']['action'] == 'txlist'
                return {
                    'status': '1',
                    'result': [
                        {'from': self.ETH_ADDR, 'to': peer, 'timeStamp': '1700000000'},
                    ],
                }
            module.fetch_json = fake_fetch_json
            result = asyncio.run(module._check_etherscan_transactions(self.ETH_ADDR))
            assert result.success is True
            assert result.data['counterparty_addresses'] == [peer]
            assert result.data['connected_addresses'] == [peer]
            assert result.data['tx_count'] == 1
        finally:
            module.config.api_keys.etherscan = None

    def test_counterparty_addresses_reach_the_summary_and_related(self):
        """Same generic _build_summary path bitcoin/tron already rely on --
        this pins that an ETH source's counterparties actually surface as
        related targets, not just evidence-graph metadata."""
        module = BitcoinModule()
        result = ModuleResult(target=self.ETH_ADDR, target_type='ethereum', module='bitcoin')
        peer = "0x0000000000000000000000000000000000beef"
        result.sources['etherscan_transactions'] = SourceResult(
            source='etherscan_transactions', success=True,
            data={'tx_count': 1, 'first_seen': None, 'last_seen': None,
                 'counterparty_addresses': [peer], 'connected_addresses': [peer]})
        summary = module._build_summary(result)
        assert summary['counterparty_addresses'] == [peer]
        assert summary['connected_addresses'] == [peer]
        assert peer in result.related


class TestBitcoinModuleFundFlowDirection:
    """Which SIDE of a transaction the address was on. A deposit into a VASP
    and a payout from one are the same counterparty edge and opposite
    investigative facts, so the collectors that can tell them apart must, and
    `counterparty_addresses` must keep its original direction-blind value --
    every saved capture and every corpus run was scored on that field."""

    BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    PAYEE = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    PAYER = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

    def _run(self, txs):
        import asyncio
        module = BitcoinModule()

        async def fake_fetch_json(url, **kwargs):
            return {'address': self.BTC, 'final_balance': 0, 'total_received': 0,
                    'total_sent': 0, 'n_tx': len(txs), 'txs': txs}
        module.fetch_json = fake_fetch_json
        return asyncio.run(module._check_blockchain_com(self.BTC)).data

    def test_spending_from_the_address_makes_every_output_a_sent_to(self):
        data = self._run([{
            'time': 1700000000,
            'inputs': [{'prev_out': {'addr': self.BTC}}],
            'out': [{'addr': self.PAYEE}],
        }])
        assert data['sent_to_addresses'] == [self.PAYEE]
        assert data['received_from_addresses'] == []

    def test_being_paid_makes_every_input_a_received_from(self):
        data = self._run([{
            'time': 1700000000,
            'inputs': [{'prev_out': {'addr': self.PAYER}}],
            'out': [{'addr': self.BTC}],
        }])
        assert data['received_from_addresses'] == [self.PAYER]
        assert data['sent_to_addresses'] == []

    def test_counterparty_addresses_keep_their_original_direction_blind_value(self):
        """The regression that matters: adding direction must not silently
        re-scope the field the whole corpus was scored on."""
        data = self._run([
            {'time': 1700000000,
             'inputs': [{'prev_out': {'addr': self.BTC}}],
             'out': [{'addr': self.PAYEE}]},
            {'time': 1700000001,
             'inputs': [{'prev_out': {'addr': self.PAYER}}],
             'out': [{'addr': self.BTC}]},
        ])
        assert data['counterparty_addresses'] == sorted([self.PAYEE, self.PAYER])

    def test_a_cospend_is_never_reported_as_a_direction(self):
        """Co-spend is a control claim and travels its own path; it must not
        also arrive as a flow edge, or one transaction would evidence both."""
        data = self._run([{
            'time': 1700000000,
            'inputs': [{'prev_out': {'addr': self.BTC}}, {'prev_out': {'addr': self.PAYER}}],
            'out': [{'addr': self.PAYEE}],
        }])
        assert data['cospend_addresses'] == [self.PAYER]
        assert self.PAYER not in data['sent_to_addresses']
        assert self.PAYER not in data['received_from_addresses']


class TestBitcoinModuleTransactionDepth:
    """Loop 21: transaction depth must be explicit and bounded, not an
    accident of the API's default page size or a hardcoded top-10 slice.
    See bitcoin_module.py's _TX_PAGE_SIZE/_TX_SHALLOW_PAGES/_TX_DEEP_PAGES and
    docs/LOOP21.md for the real Bitfinex hot<->cold wallet pair this was sized
    against -- docs/LOOP20.md found the real reciprocal transaction at
    positions 105/139/142 of one wallet's own history, past any single page.
    """

    BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    PEER = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"

    def _padding_txs(self, n, start_time, prefix):
        """n distinct, unrelated transactions -- each address different, so
        none of them accidentally becomes a real counterparty/direction
        signal for PEER."""
        return [{'time': start_time - i, 'hash': f'{prefix}{i}',
                'inputs': [{'prev_out': {'addr': self.BTC}}],
                'out': [{'addr': f'1Padding{prefix}{i}'}]}
               for i in range(n)]

    def _paged_module(self, pages, monkeypatch):
        """pages: list of tx-lists, one per successive 50-tx offset. Returns
        (module, calls) where calls records the params of every fetch."""
        from cybertrace.modules import bitcoin_module

        async def _no_op_sleep(*_a, **_k):
            return

        monkeypatch.setattr(bitcoin_module.asyncio, "sleep", _no_op_sleep)
        module = BitcoinModule()
        calls = []
        total_n_tx = sum(len(p) for p in pages)

        async def fake_fetch_json(url, **kwargs):
            params = kwargs.get('params') or {}
            calls.append(params)
            page_idx = params.get('offset', 0) // params.get('limit', 50)
            page_txs = pages[page_idx] if page_idx < len(pages) else []
            return {'address': self.BTC, 'final_balance': 0, 'total_received': 0,
                    'total_sent': 0, 'n_tx': total_n_tx, 'txs': page_txs}
        module.fetch_json = fake_fetch_json
        return module, calls

    def test_default_mode_reads_exactly_one_bounded_page(self, monkeypatch):
        import asyncio
        pages = [self._padding_txs(50, 1700000000, 'p0')]
        module, calls = self._paged_module(pages, monkeypatch)
        result = asyncio.run(module._check_blockchain_com(self.BTC, deep=False))
        assert len(calls) == 1
        assert calls[0] == {'limit': 50, 'offset': 0}
        assert result.data['tx_sample_size'] == 50

    def test_deep_mode_stops_as_soon_as_a_page_comes_back_short(self, monkeypatch):
        """A wallet with 110 real transactions must not pay for a 4th call
        that cannot return anything -- pagination stops on the short page,
        not at the hard cap."""
        import asyncio
        pages = [self._padding_txs(50, 1700000000, 'p0'),
                self._padding_txs(50, 1690000000, 'p1'),
                self._padding_txs(10, 1680000000, 'p2')]
        module, calls = self._paged_module(pages, monkeypatch)
        result = asyncio.run(module._check_blockchain_com(self.BTC, deep=True))
        assert len(calls) == 3
        assert result.data['tx_sample_size'] == 110

    def test_deep_mode_never_exceeds_the_hard_page_cap(self, monkeypatch):
        """A huge exchange wallet (Bitfinex's real hot wallet: 487,628 tx) must
        not turn --deep into an unbounded crawl -- always <=_TX_DEEP_PAGES
        calls, no matter how many full pages the address actually has."""
        import asyncio
        from cybertrace.modules.bitcoin_module import _TX_DEEP_PAGES, _TX_PAGE_SIZE
        pages = [self._padding_txs(50, 1700000000 - i * 100, f'p{i}') for i in range(10)]
        module, calls = self._paged_module(pages, monkeypatch)
        result = asyncio.run(module._check_blockchain_com(self.BTC, deep=True))
        assert len(calls) == _TX_DEEP_PAGES
        assert result.data['tx_sample_size'] == _TX_DEEP_PAGES * _TX_PAGE_SIZE

    def test_a_transaction_repeated_across_a_pagination_boundary_counts_once(self, monkeypatch):
        """A new tx landing on the address between two paginated calls shifts
        every offset by one, so the same transaction can appear twice across
        a page boundary. It must not be double-counted into the counterparty
        set (harmless here) or, worse, be double-processed in a way that
        could ever invent a second distinct peer out of one real transaction.

        Padding is on the RECEIVED side (peer -> BTC) so it cannot crowd
        sent_to_addresses' own [:20] cap and mask the assertion below --
        overlap_tx (BTC -> PEER) is the only thing that can ever appear there.
        """
        import asyncio
        overlap_tx = {'time': 1700000000, 'hash': 'overlap',
                     'inputs': [{'prev_out': {'addr': self.BTC}}],
                     'out': [{'addr': self.PEER}]}
        def _received_padding(n, prefix):
            return [{'time': 1699999999 - i, 'hash': f'{prefix}{i}',
                    'inputs': [{'prev_out': {'addr': f'1Padding{prefix}{i}'}}],
                    'out': [{'addr': self.BTC}]} for i in range(n)]
        page0 = [overlap_tx] + _received_padding(49, 'p0')
        page1 = [overlap_tx] + _received_padding(49, 'p1')  # boundary re-sends overlap_tx
        module, calls = self._paged_module([page0, page1], monkeypatch)
        result = asyncio.run(module._check_blockchain_com(self.BTC, deep=True))
        assert result.data['sent_to_addresses'] == [self.PEER]
        # 50 + 50 - 1 shared duplicate = 99 distinct transactions actually scanned
        assert result.data['tx_sample_size'] == 99

    def test_a_reciprocal_transaction_past_the_first_page_is_only_found_deep(self, monkeypatch):
        """The exact real-world gap this loop closes (docs/LOOP20.md): a
        genuine reciprocal transaction sits beyond the first page of the
        wallet's own history. The default (shallow) mode must not see it --
        it is genuinely outside what a bounded default call reads -- while
        --deep, paginating further into the same real history, must."""
        import asyncio
        reciprocal_tx = {'time': 1600000000, 'hash': 'reciprocal',
                         'inputs': [{'prev_out': {'addr': self.PEER}}],
                         'out': [{'addr': self.BTC}]}
        pages = [self._padding_txs(50, 1700000000, 'p0'),
                self._padding_txs(50, 1690000000, 'p1'),
                [reciprocal_tx] + self._padding_txs(4, 1680000000, 'p2')]

        module, _ = self._paged_module(pages, monkeypatch)
        shallow = asyncio.run(module._check_blockchain_com(self.BTC, deep=False))
        assert self.PEER not in shallow.data.get('received_from_addresses', [])

        module, calls = self._paged_module(pages, monkeypatch)
        deep = asyncio.run(module._check_blockchain_com(self.BTC, deep=True))
        assert self.PEER in deep.data['received_from_addresses']
        assert len(calls) == 3  # stopped on page 2's short (5-tx) page


class TestBitcoinModuleRelationshipOutputCompleteness:
    """Loop 22: _check_blockchain_com used to re-truncate its own already-
    bounded transaction sample to the first 20 relationships, ALPHABETICALLY
    -- a second, unrelated cap layered on top of the real one (transaction
    DEPTH, see TestBitcoinModuleTransactionDepth above). A relationship fully
    inside the scanned window could still vanish from the output purely
    because 20 alphabetically-earlier addresses filled the cap first --
    transaction discovery and relationship reporting are different things,
    and only the first was ever meant to be bounded."""

    BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

    def _run(self, txs):
        import asyncio
        module = BitcoinModule()

        async def fake_fetch_json(url, **kwargs):
            return {'address': self.BTC, 'final_balance': 0, 'total_received': 0,
                    'total_sent': 0, 'n_tx': len(txs), 'txs': txs}
        module.fetch_json = fake_fetch_json
        return asyncio.run(module._check_blockchain_com(self.BTC)).data

    def _sent_to_tx(self, n):
        """One transaction, n distinct outputs -- all inside ONE bounded
        transaction, the case that matters: transaction DEPTH was never the
        problem here, only the output projection was."""
        peers = [f'1Peer{i:03d}' for i in range(n)]
        return peers, [{
            'time': 1700000000,
            'inputs': [{'prev_out': {'addr': self.BTC}}],
            'out': [{'addr': p} for p in peers],
        }]

    def test_fewer_than_twenty_relationships_all_survive(self):
        peers, txs = self._sent_to_tx(5)
        data = self._run(txs)
        assert data['sent_to_addresses'] == sorted(peers)

    def test_exactly_twenty_relationships_all_survive(self):
        peers, txs = self._sent_to_tx(20)
        data = self._run(txs)
        assert data['sent_to_addresses'] == sorted(peers)

    def test_more_than_twenty_relationships_in_one_bounded_transaction_all_survive(self):
        """The regression: this is exactly the shape the old [:20] alphabetical
        slice broke -- more unique addresses than the old cap, all discovered
        from a SINGLE transaction already inside the bounded sample."""
        peers, txs = self._sent_to_tx(37)
        data = self._run(txs)
        assert data['sent_to_addresses'] == sorted(peers)
        assert len(data['sent_to_addresses']) == 37

    def test_a_peer_sorting_after_the_old_boundary_is_retained(self):
        """The exact real-world failure mode: a directed counterparty (the
        kind SENT_FUNDS_TO is built from -- see enrich_bitcoin and
        wallet_exchange_paths' BOTH_WAYS) whose own address value sorts after
        the first 20 peers alphabetically must not disappear just because
        other peers' values happened to sort earlier -- exactly what a busy
        exchange hot wallet with many counterparties looks like."""
        padding = [f'1Peer{i:03d}' for i in range(24)]
        reciprocal = 'zReciprocalPeer'
        peers = padding + [reciprocal]
        txs = [{
            'time': 1700000000,
            'inputs': [{'prev_out': {'addr': self.BTC}}],
            'out': [{'addr': p} for p in peers],
        }]
        data = self._run(txs)
        assert reciprocal in data['sent_to_addresses']
        # inside ONE bounded transaction -- depth was never the issue here
        assert data['tx_sample_size'] == 1

    def test_a_received_from_peer_beyond_the_old_boundary_is_retained_without_collapsing_direction(self):
        """Mirrors test_a_peer_sorting_after_the_old_boundary_is_retained but
        for the OTHER directed set -- received_from_addresses is built from
        the same sorted(...)[was :20] call site the fix touched, and the two
        directions must stay disjoint even once received_from alone exceeds
        the old cap."""
        payers = [f'1Payer{i:03d}' for i in range(24)]
        late_payer = 'zLatePayer'
        receiving_tx = {
            'time': 1700000000,
            'inputs': [{'prev_out': {'addr': p}} for p in payers + [late_payer]],
            'out': [{'addr': self.BTC}],
        }
        sent_peer = 'aSentToPeer'
        paying_tx = {
            'time': 1700000001,
            'inputs': [{'prev_out': {'addr': self.BTC}}],
            'out': [{'addr': sent_peer}],
        }
        data = self._run([receiving_tx, paying_tx])
        assert len(data['received_from_addresses']) == 25
        assert late_payer in data['received_from_addresses']
        assert data['sent_to_addresses'] == [sent_peer]
        assert late_payer not in data['sent_to_addresses']
        assert sent_peer not in data['received_from_addresses']

    def test_cospend_and_counterparty_also_survive_beyond_the_old_cap(self):
        """The fix touched five sibling fields in the same function -- this
        pins that cospend_addresses and counterparty_addresses (not just the
        directed sent_to/received_from sets exercised above) were fixed too,
        and that the semantic split between them (PART_OF_CLUSTER-eligible
        vs TRANSACTED_WITH-eligible) survives an output larger than 20."""
        cospend_peers = [f'1Cospend{i:03d}' for i in range(25)]
        counterparty_peer = 'zLoneCounterparty'
        txs = [{
            'time': 1700000000,
            'inputs': ([{'prev_out': {'addr': self.BTC}}]
                      + [{'prev_out': {'addr': p}} for p in cospend_peers]),
            'out': [{'addr': counterparty_peer}],
        }]
        data = self._run(txs)
        assert data['cospend_addresses'] == sorted(cospend_peers)
        assert len(data['cospend_addresses']) == 25
        assert data['counterparty_addresses'] == [counterparty_peer]


class TestBitcoinModuleSamplingWindowBoundary:
    """Loop 23: distinguishes two different, non-conflicting facts about
    _check_blockchain_com's bounded transaction sample.

    Loop 22's guarantee: every relationship found INSIDE the sampled
    transactions is emitted (no second, alphabetical output cap).

    Loop 23's limitation: a relationship that only exists OUTSIDE the
    bounded transaction window (page 5+, beyond _TX_DEEP_PAGES) cannot be
    discovered -- and must be correctly, silently absent, never fabricated
    or inferred. Real-world evidence for why this is an accepted, documented
    tradeoff rather than a defect is in docs/LOOP23.md Phase 3: the real
    Bitfinex hot wallet's own most-recent 200-tx window covers ~2.5 real
    calendar days (487,629 total tx, extreme velocity), and a real,
    independently-verified reciprocal counterparty (the cold wallet) sits at
    real transaction index 556 of the hot wallet's own history -- outside
    even a hypothetical 500-tx bound, and moving farther away every day.
    """

    BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

    def _padding_txs(self, n, start_time, prefix):
        return [{'time': start_time - i, 'hash': f'{prefix}{i}',
                'inputs': [{'prev_out': {'addr': self.BTC}}],
                'out': [{'addr': f'1Padding{prefix}{i}'}]}
               for i in range(n)]

    def _paged_module(self, pages, monkeypatch):
        from cybertrace.modules import bitcoin_module

        async def _no_op_sleep(*_a, **_k):
            return

        monkeypatch.setattr(bitcoin_module.asyncio, "sleep", _no_op_sleep)
        module = BitcoinModule()
        calls = []
        total_n_tx = sum(len(p) for p in pages)

        async def fake_fetch_json(url, **kwargs):
            params = kwargs.get('params') or {}
            calls.append(params)
            page_idx = params.get('offset', 0) // params.get('limit', 50)
            page_txs = pages[page_idx] if page_idx < len(pages) else []
            return {'address': self.BTC, 'final_balance': 0, 'total_received': 0,
                    'total_sent': 0, 'n_tx': total_n_tx, 'txs': page_txs}
        module.fetch_json = fake_fetch_json
        return module, calls

    def test_a_relationship_beyond_the_deep_window_is_correctly_absent_not_inferred(self, monkeypatch):
        """A relationship inside the bounded deep window (page 4, the last
        page _TX_DEEP_PAGES reads) survives -- Loop 22's guarantee. A second
        relationship that exists only on page 5, one page past the hard cap,
        must be absent from the output, and the module must never even fetch
        page 5 to learn that -- the absence is a property of the bound, not
        a filtered-out discovery."""
        import asyncio
        from cybertrace.modules.bitcoin_module import _TX_DEEP_PAGES, _TX_PAGE_SIZE
        inside_peer = 'zInsideWindowPeer'
        outside_peer = 'zOutsideWindowPeer'
        inside_tx = {'time': 1670000000, 'hash': 'inside',
                     'inputs': [{'prev_out': {'addr': self.BTC}}],
                     'out': [{'addr': inside_peer}]}
        outside_tx = {'time': 1660000000, 'hash': 'outside',
                      'inputs': [{'prev_out': {'addr': self.BTC}}],
                      'out': [{'addr': outside_peer}]}
        pages = [
            self._padding_txs(50, 1700000000, 'p0'),
            self._padding_txs(50, 1690000000, 'p1'),
            self._padding_txs(50, 1680000000, 'p2'),
            [inside_tx] + self._padding_txs(49, 1670000000, 'p3'),
            [outside_tx] + self._padding_txs(49, 1660000000, 'p4'),
        ]
        module, calls = self._paged_module(pages, monkeypatch)
        result = asyncio.run(module._check_blockchain_com(self.BTC, deep=True))
        assert len(calls) == _TX_DEEP_PAGES  # page 5 is never requested
        assert inside_peer in result.data['sent_to_addresses']
        assert outside_peer not in result.data['sent_to_addresses']
        assert result.data['tx_sample_size'] == _TX_DEEP_PAGES * _TX_PAGE_SIZE

    def test_repeated_execution_of_the_same_bounded_request_is_deterministic(self, monkeypatch):
        """Same paginated responses in, byte-identical relationship sets and
        tx_sample_size out, every time -- no randomness anywhere in the
        sampling path (every output field is sorted())."""
        import asyncio
        pages = [self._padding_txs(50, 1700000000, 'p0'),
                 self._padding_txs(50, 1690000000, 'p1'),
                 self._padding_txs(50, 1680000000, 'p2'),
                 self._padding_txs(50, 1670000000, 'p3')]
        runs = []
        for _ in range(3):
            module, _ = self._paged_module(pages, monkeypatch)
            runs.append(asyncio.run(module._check_blockchain_com(self.BTC, deep=True)).data)
        assert runs[0] == runs[1] == runs[2]


class TestBitcoinModuleEllipticpp:
    """Local-index lookup, no network -- degrades the same way chainabuse does
    without a key, but on dataset/index availability instead of a config key.
    """

    def test_degrades_gracefully_when_dataset_not_downloaded(self, monkeypatch):
        import asyncio
        from cybertrace.integrations import ellipticpp
        monkeypatch.setattr(ellipticpp, "available", lambda: False)
        module = BitcoinModule()
        result = asyncio.run(module._check_ellipticpp('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'))
        assert result.success is False
        assert 'not downloaded' in result.error

    def test_degrades_gracefully_when_index_not_built(self, monkeypatch):
        import asyncio
        from cybertrace.integrations import ellipticpp
        monkeypatch.setattr(ellipticpp, "available", lambda: True)
        monkeypatch.setattr(ellipticpp, "index_available", lambda: False)
        module = BitcoinModule()
        result = asyncio.run(module._check_ellipticpp('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'))
        assert result.success is False
        assert 'build_index' in result.error

    def test_address_not_in_dataset_is_a_successful_negative(self, monkeypatch):
        import asyncio
        from cybertrace.integrations import ellipticpp
        monkeypatch.setattr(ellipticpp, "available", lambda: True)
        monkeypatch.setattr(ellipticpp, "index_available", lambda: True)
        monkeypatch.setattr(ellipticpp, "lookup_wallet", lambda addr: None)
        module = BitcoinModule()
        result = asyncio.run(module._check_ellipticpp('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'))
        assert result.success is True
        assert result.data == {'seen_in_dataset': False}

    def test_a_dataset_hit_carries_the_label_into_the_summary(self, monkeypatch):
        """_build_summary only reads ellipticpp fields off the source actually
        named 'ellipticpp' -- this pins that the label makes it all the way
        from the source result into the module's summary dict, which is what
        evidence.enrich_bitcoin's ellipticpp_* metadata is built from."""
        import asyncio
        from cybertrace.integrations import ellipticpp
        monkeypatch.setattr(ellipticpp, "available", lambda: True)
        monkeypatch.setattr(ellipticpp, "index_available", lambda: True)
        monkeypatch.setattr(ellipticpp, "lookup_wallet", lambda addr: {
            "address": addr, "dataset_label": "1", "dataset_label_name": "illicit",
            "time_steps": ["25"], "record_count": 1, "features": {},
        })
        module = BitcoinModule()
        result = ModuleResult(target='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                              target_type='bitcoin', module='bitcoin')
        result.sources['ellipticpp'] = asyncio.run(
            module._check_ellipticpp('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'))
        summary = module._build_summary(result)
        assert summary['ellipticpp_dataset_label_name'] == 'illicit'
        assert summary['ellipticpp_record_count'] == 1

    def test_counterparty_addresses_reach_the_summary(self):
        """_build_summary must carry counterparty_addresses through the same
        way it already does cospend_addresses -- this is the raw material
        evidence.enrich_bitcoin turns into TRANSACTED_WITH tracing edges, and
        it was silently dropped before this test existed."""
        from cybertrace.modules.base import SourceResult
        module = BitcoinModule()
        result = ModuleResult(target='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                              target_type='bitcoin', module='bitcoin')
        result.sources['blockchain.com'] = SourceResult(
            source='blockchain.com', success=True,
            data={'balance_btc': 0.0, 'cospend_addresses': ['3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'],
                 'counterparty_addresses': ['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4']})
        summary = module._build_summary(result)
        assert summary['counterparty_addresses'] == ['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4']
        assert summary['cospend_addresses'] == ['3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy']


class TestExchangeTagsSource:
    """Same degrade-without-network-call contract as TestBitcoinModuleEllipticpp,
    checked once for the shared _check_exchange_tags helper both BitcoinModule
    and TronModule call -- a tag is EXTERNAL_DATASET_MATCH metadata, never a
    relationship (see evidence.enrich_bitcoin's exchange_tag_* docstring)."""

    def test_degrades_gracefully_when_dataset_not_downloaded(self, monkeypatch):
        import asyncio
        monkeypatch.setattr(exchange_tags, "available", lambda: False)
        module = BitcoinModule()
        result = asyncio.run(module._check_exchange_tags(
            '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'BTC'))
        assert result.success is False
        assert 'not downloaded' in result.error

    def test_degrades_gracefully_when_index_not_built(self, monkeypatch):
        import asyncio
        monkeypatch.setattr(exchange_tags, "available", lambda: True)
        monkeypatch.setattr(exchange_tags, "index_available", lambda: False)
        module = BitcoinModule()
        result = asyncio.run(module._check_exchange_tags(
            '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'BTC'))
        assert result.success is False
        assert 'build_index' in result.error

    def test_address_not_tagged_is_a_successful_negative(self, monkeypatch):
        import asyncio
        monkeypatch.setattr(exchange_tags, "available", lambda: True)
        monkeypatch.setattr(exchange_tags, "index_available", lambda: True)
        monkeypatch.setattr(exchange_tags, "lookup_address", lambda addr, cur: [])
        module = BitcoinModule()
        result = asyncio.run(module._check_exchange_tags(
            '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'BTC'))
        assert result.success is True
        assert result.data == {'tagged': False}

    def test_a_tag_hit_carries_the_exchange_flag_into_the_summary(self, monkeypatch):
        """_build_summary only reads exchange_tags fields off the source
        actually named 'exchange_tags' -- pins that a hit reaches the summary
        dict evidence.enrich_bitcoin's exchange_tag_* metadata is built from,
        and that a category of 'exchange' sets is_exchange_tagged."""
        import asyncio
        monkeypatch.setattr(exchange_tags, "available", lambda: True)
        monkeypatch.setattr(exchange_tags, "index_available", lambda: True)
        monkeypatch.setattr(exchange_tags, "lookup_address", lambda addr, cur: [
            {"currency": cur, "category": "exchange", "label": "binance.com",
             "actor": "binance", "source": "https://example.com", "pack": "binance"},
        ])
        module = BitcoinModule()
        result = ModuleResult(target='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                              target_type='bitcoin', module='bitcoin')
        result.sources['exchange_tags'] = asyncio.run(
            module._check_exchange_tags('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'BTC'))
        summary = module._build_summary(result)
        assert summary['exchange_tag_categories'] == ['exchange']
        assert summary['exchange_tag_labels'] == ['binance.com']
        assert summary['exchange_tag_is_exchange'] is True


class TestTronModule:
    """Test TRON module. TRC20 decode assertions use real TronGrid payload
    shapes (verified live against api.trongrid.io while building this
    module), not invented ones -- see _decode_trc20_transfer_recipient."""

    def test_module_attributes(self):
        module = TronModule()
        assert module.name == 'tron'
        assert 'tron' in module.supported_types

    def test_no_key_configured_sends_no_auth_header(self):
        module = TronModule()
        module.config.api_keys.trongrid = None
        assert module._headers() == {}

    def test_key_configured_sends_pro_api_key_header(self):
        module = TronModule()
        module.config.api_keys.trongrid = 'testkey'
        try:
            assert module._headers() == {'TRON-PRO-API-KEY': 'testkey'}
        finally:
            module.config.api_keys.trongrid = None

    def test_trc20_transfer_recipient_decodes_a_real_payload(self):
        from cybertrace.modules.tron_module import _decode_trc20_transfer_recipient
        # A real TriggerSmartContract calldata captured off api.trongrid.io:
        # selector + 32-byte padded recipient + 32-byte amount.
        data = ('a9059cbb0000000000000000000000002f50fc2ad54b274619cb44c9fd26427'
               'ccdeeeebb00000000000000000000000000000000000000000000000000000'
               '003680db270')
        recipient = _decode_trc20_transfer_recipient(data)
        assert recipient is not None
        assert recipient.startswith('T')

    def test_trc20_transfer_recipient_ignores_other_selectors(self):
        from cybertrace.modules.tron_module import _decode_trc20_transfer_recipient
        assert _decode_trc20_transfer_recipient('095ea7b3' + '00' * 64) is None  # approve()
        assert _decode_trc20_transfer_recipient('') is None

    def test_counterparty_addresses_reach_the_summary(self):
        module = TronModule()
        result = ModuleResult(target=TRX_VALID, target_type='tron', module='tron')
        result.sources['trongrid_transactions'] = SourceResult(
            source='trongrid_transactions', success=True,
            data={'tx_count': 1, 'first_seen': None, 'last_seen': None,
                 'counterparty_addresses': [TRX_VALID]})
        summary = module._build_summary(result)
        assert summary['counterparty_addresses'] == [TRX_VALID]
        assert summary['connected_addresses'] == [TRX_VALID]


class TestUsernameModule:
    """Test Username module."""

    def test_module_attributes(self):
        module = UsernameModule()
        assert module.name == 'username'
        assert 'username' in module.supported_types

    def test_key_platforms_defined(self):
        module = UsernameModule()
        assert 'github' in module.KEY_PLATFORMS
        assert 'twitter' in module.KEY_PLATFORMS
        assert 'reddit' in module.KEY_PLATFORMS


class TestDomainModule:
    """Test Domain module."""

    def test_module_attributes(self):
        module = DomainModule()
        assert module.name == 'domain'
        assert 'domain' in module.supported_types

    def test_clean_domain_removes_protocol(self):
        module = DomainModule()
        assert module._clean_domain("https://example.com") == "example.com"
        assert module._clean_domain("http://example.com") == "example.com"

    def test_clean_domain_removes_path(self):
        module = DomainModule()
        assert module._clean_domain("example.com/path") == "example.com"

    def test_clean_domain_removes_port(self):
        module = DomainModule()
        assert module._clean_domain("example.com:8080") == "example.com"


class TestEmailModule:
    """Test Email module."""

    def test_module_attributes(self):
        module = EmailModule()
        assert module.name == 'email'
        assert 'email' in module.supported_types


class TestDarkwebModule:
    """Test Darkweb module."""

    def test_module_attributes(self):
        module = DarkwebModule()
        assert module.name == 'darkweb'
        assert 'darkweb' in module.supported_types

    def test_tor_socks_up_detects_listener(self):
        """Tor-down vs onion-down must not collapse into one error."""
        import asyncio
        import socket

        module = DarkwebModule()

        async def probe(port):
            module.config.tor.socks_port = port
            return await module._tor_socks_up()

        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            sock.listen(1)
            module.config.tor.socks_host = '127.0.0.1'
            assert asyncio.run(probe(sock.getsockname()[1])) is True
            closed_port = sock.getsockname()[1]
        assert asyncio.run(probe(closed_port)) is False


class TestDarkwebOperatorIntel:
    """De-anonymisation signal extraction from a live onion page (pure logic)."""

    def test_public_ipv4_drops_private_and_reserved(self):
        ips = ['192.168.1.1', '10.0.0.5', '127.0.0.1', '8.8.8.8', '203.0.113.9', 'not-an-ip']
        # 203.0.113.0/24 is TEST-NET-3 (reserved) — must be dropped too.
        assert DarkwebModule._public_ipv4(ips) == ['8.8.8.8']

    def test_artifact_regexes_extract_operator_pii(self):
        html = (
            "contact admin@example.com pay bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
            "eth 0x742d35Cc6634C0532925a3b844Bc9e7595f12345 ga UA-1234567-8 "
            "leak 8.8.8.8"
        )
        assert 'admin@example.com' in DarkwebModule._RE_EMAIL.findall(html)
        assert 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq' in DarkwebModule._RE_BTC.findall(html)
        assert '0x742d35Cc6634C0532925a3b844Bc9e7595f12345' in DarkwebModule._RE_ETH.findall(html)
        assert 'UA-1234567-8' in DarkwebModule._RE_ANALYTICS.findall(html)
        assert DarkwebModule._public_ipv4(DarkwebModule._RE_IPV4.findall(html)) == ['8.8.8.8']

    def test_validated_rejects_addresses_that_fail_checksum(self):
        # Same address, last char changed — regex-shaped but checksum-invalid.
        # It must never reach the graph, or two markets quoting the same typo
        # would correlate into an operator that doesn't exist.
        html = ("donate 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 "
                "and 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3")
        values, evidence = DarkwebModule._validated(
            html, DarkwebModule._RE_BTC, norm_btc)
        assert values == ['1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2']
        assert '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3' not in evidence

    def test_validated_records_section_and_context(self):
        html = ('<div class="footer">seen at admin@morke.ru</div>'
                + '<p>filler prose that separates the two blocks.</p>' * 3
                + '<div id="donate">pay support@shop.li</div>')
        _values, evidence = DarkwebModule._validated(
            html, DarkwebModule._RE_EMAIL, norm_email)
        assert evidence['admin@morke.ru']['section'] == 'footer'
        assert evidence['support@shop.li']['section'] == 'wallet'
        # context is the tag-stripped window the artifact was seen in
        assert 'pay' in evidence['support@shop.li']['context']

    def test_quoted_content_is_not_the_operator(self):
        """A mailing-list archive reproduces other people's messages. The Riseup
        list archive quoted a script header naming its author's Gmail, and that
        address became an operator artifact and then a username, which pivoted
        to a real person's GitHub. Provenance is what separates them — the site
        publishing an address versus the site quoting someone who did."""
        # The shape that caused it: an attribution beside the address.
        _v, ev = DarkwebModule._validated(
            '<pre>* script MICRO-CAL par S.A. (amrounix@gmail.com) '
            '* all copies and modifications are allowed.</pre>',
            DarkwebModule._RE_EMAIL, norm_email)
        assert ev['amrounix@gmail.com']['section'] == 'quoted'

        # The commoner shape: the marker heads the block, far above the address.
        # This is what the ±70 window used for every other section cannot see.
        _v, ev = DarkwebModule._validated(
            '<p>On Mon, 3 Jun 2024, S.A. wrote:</p><p>' + 'quoted body. ' * 30
            + 'mail me at amrounix@gmail.com</p>', DarkwebModule._RE_EMAIL, norm_email)
        assert ev['amrounix@gmail.com']['section'] == 'quoted'

        # A blockquote that already closed is the site speaking again. Without
        # the open/close comparison every address below any quote reads quoted.
        _v, ev = DarkwebModule._validated(
            '<blockquote>old thread</blockquote><div>' + 'our own words. ' * 25
            + 'write support@morke.ru</div>', DarkwebModule._RE_EMAIL, norm_email)
        assert ev['support@morke.ru']['section'] != 'quoted'

    def test_analytics_ids_carry_a_section(self):
        """An analytics id reaches correlation at FULL control weight —
        USES_ANALYTICS has no CONTEXT_WEIGHT entry, and the dossier reads one
        account id across two markets as an operator-level tell. Extracted with
        a bare findall it carried no provenance at all, so an id copied out of a
        quoted embed snippet was the cheapest possible way to put two unrelated
        sites under one operator."""
        html = ('<blockquote>use my snippet: '
                '<script>ga("create","UA-111111-1")</script></blockquote>'
                + '<div>our own words. ' * 20 + '</div>'
                + '<footer>GTM-ABCD12</footer>')
        found = DarkwebModule()._extract_artifacts(html, 'x' * 56 + '.onion')
        ev = found['artifact_evidence']
        assert 'UA-111111-1' in found['analytics_ids']
        assert ev['UA-111111-1']['section'] == 'quoted'
        assert ev['GTM-ABCD12']['section'] == 'footer'

    def test_pgp_fingerprint_shown_as_0x_hex_is_not_read_as_an_eth_address(self):
        """parckwart.de (runs/raw/v11) displays 'My OpenPGP Key Fingerprint:
        0x47BC7DE8...' — shape-identical to the ETH regex, and the extractor
        recorded it as an ethereum_addresses hit even though it is the same
        40 hex chars as the page's own PGP key. A person's fingerprint must
        never read as their own wallet."""
        from .test_evidence import _armor, _pubkey_packet

        key_block = _armor(_pubkey_packet((1 << 2047) | 0x9999))
        keys = DarkwebModule._extract_pgp_keys(key_block)
        fp = keys[0]['fingerprint']

        html = f'My OpenPGP Key Fingerprint: 0x{fp} {key_block}'
        found = DarkwebModule()._extract_artifacts(html, 'x' * 56 + '.onion')
        assert found['pgp_keys'], "fixture must actually carry a parseable key"
        assert f'0x{fp}' not in found['ethereum_addresses']
        assert f'0x{fp}' not in found['artifact_evidence']

    def test_quoted_artifacts_are_never_enriched(self):
        """Enrichment is the step that turns a string into a named person, so a
        quoted address has to be stopped before the pivot, not scored down
        after it."""
        jobs = DarkwebModule._pivot_targets({
            'emails': ['amrounix@gmail.com', 'support@dnmx.cc'],
            'bitcoin_addresses': ['1QuotedAddr'],
            'candidate_operator_ips': ['8.8.8.8', '9.9.9.9'],
            'artifact_evidence': {
                'amrounix@gmail.com': {'section': 'quoted'},
                '1QuotedAddr': {'section': 'quoted'},
                '8.8.8.8': {'section': 'quoted'},
                'support@dnmx.cc': {'section': 'contact'},
            },
        })
        assert ('email', 'support@dnmx.cc') in jobs
        assert ('email', 'amrounix@gmail.com') not in jobs
        assert ('bitcoin', '1QuotedAddr') not in jobs
        # An IP read out of a quoted mail header is the sender's, not the
        # site's — it earns the same refusal now that IPs carry evidence.
        assert ('ip', '8.8.8.8') not in jobs
        assert ('ip', '9.9.9.9') in jobs
        # and the quoted address must not seed a username either — that pivot is
        # what reached the script author's GitHub.
        assert ('username', 'amrounix') not in jobs

    def test_list_subscriber_is_not_the_list_operator(self):
        """Riseup's list manager renders the logged-in user's own address into
        its menu. It was minted as a Riseup operator artifact, pivoted to the
        username `honeytroll`, and pivoted again across 26 social sites — a
        subscriber of a hosted list attributed to whoever hosts it.

        The markup is the real thing off `lists.riseup.net`, trimmed to the
        window the section rules see.
        """
        html = ('<p>Check out the FAQs for <a href="https://riseup.net/lists/'
                'list-admin/faq">list admins</a> and <a href="https://riseup.net'
                '/lists/list-user">subscribers</a>.</p>'
                '<a href="mailto:honeytroll@riseup.net"><span>x</span></a>')
        _v, ev = DarkwebModule._validated(html, DarkwebModule._RE_EMAIL, norm_email)
        assert ev['honeytroll@riseup.net']['section'] == 'roster'
        # …and being roster is what keeps it out of the enrichment pivot.
        assert ('email', 'honeytroll@riseup.net') not in DarkwebModule._pivot_targets({
            'emails': ['honeytroll@riseup.net'],
            'artifact_evidence': {'honeytroll@riseup.net': {'section': 'roster'}}})

        # The operator's own contact block on the very same kind of page must
        # keep its full weight — a rule that demoted this too would trade one
        # false attribution for the loss of every real one.
        for genuine, section in (('support@dnmx.cc', 'contact'),
                                 ('abuse@morke.ru', 'contact'),
                                 ('admin@Mail2Tor.com', 'contact')):
            _v, ev = DarkwebModule._validated(
                f'<div class="footer">Abuse contact: {genuine}</div>',
                DarkwebModule._RE_EMAIL, norm_email)
            assert ev[genuine]['section'] == section, genuine
            assert ('email', genuine) in DarkwebModule._pivot_targets({
                'emails': [genuine],
                'artifact_evidence': {genuine: {'section': section}}})

    def test_tutorial_transcripts_are_not_the_operators_identity(self):
        """A walkthrough's cast, measured on nowhere.moe's OPSEC Bible.

        The gpg key-generation prompts, a signature-verification line and
        monero-wallet-cli output yielded `alice@nowhere.com`, `bob@bob.com` and
        three Monero addresses, all filed as the site's own. Both addresses then
        went through the email pivot: the keyserver answered alice with a real
        fingerprint and bob with sixty-nine of them plus the GitHub account
        `caverobot`. The wallets were worse than merely accepted — "Generated new
        wallet" contains the word `wallet`, so they landed in the section that
        PROMOTES confidence, outranking a real donate box.

        Markup below is the page text as captured, cut to the windows the
        section rules see.
        """
        keygen = ('You need a user ID to identify your key. Real name: alice '
                  'Email address: alice@nowhere.com You selected this USER-ID')
        verify = ('gpg: Signature made Fri 14 Aug 2026 gpg: issuer "bob@bob.com" '
                  'gpg: Good signature from "bob bob"')
        for html, value in ((keygen, 'alice@nowhere.com'), (verify, 'bob@bob.com')):
            _v, ev = DarkwebModule._validated(html, DarkwebModule._RE_EMAIL, norm_email)
            assert ev[value]['section'] == 'demo', html
            assert ('email', value) not in DarkwebModule._pivot_targets({
                'emails': [value], 'artifact_evidence': {value: {'section': 'demo'}}})
            # and no username pivot either: `alice` reached 26 social sites.
            assert ('username', value.split('@')[0]) not in DarkwebModule._pivot_targets({
                'emails': [value], 'artifact_evidence': {value: {'section': 'demo'}}})

        wallet_run = (
            'Generated new wallet: 46XVFMwQiY1L4WEbuQr9kS2huy39b7xQV7voVEQyDiEu'
            '5ge2YA9C5c9HWLvYnG33iEgmC8ENX9oSsDfBQu2PCjZWDUzMqKy'
            + ' filler line of transcript output. ' * 6 +
            'spent 0.000414840330, change to 4Avk37RuxDWEPz17ZNdG9nKtnpXgC5ip5fk1'
            'eyw27CQ871GfLdA4EjvA2DRe61syBvdZnEBK5gBbuDEU2brrEJfQ8rRdm1B')
        _v, ev = DarkwebModule._validated(
            wallet_run, DarkwebModule._RE_XMR, norm_xmr)
        # The second address has no marker within ±70 — the transcript header is
        # lines above it — which is why demo gets the wide look-back.
        assert {e['section'] for e in ev.values()} == {'demo'}, ev

        # Two more shapes off the same site, both of which survived the first
        # cut: a gpg invocation that uses a short option rather than `--`, and
        # monero-wallet-cli naming where a transfer's change went.
        _v, ev = DarkwebModule._validated(
            'gpg -u nihilist@contact.nowhere.moe --clearsign message.txt',
            DarkwebModule._RE_EMAIL, norm_email)
        assert ev['nihilist@contact.nowhere.moe']['section'] == 'demo'
        # …and the bare phrase in prose is not a marker: only the address the
        # line is naming is covered.
        _v, ev = DarkwebModule._validated(
            '<div id="donate">no change to our address: support@dnmx.cc</div>',
            DarkwebModule._RE_EMAIL, norm_email)
        assert ev['support@dnmx.cc']['section'] == 'wallet'

        # A real donate box on a page that also shows a canary transcript keeps
        # its section: the rule is the program's own output, not the topic.
        donate = ('<div id="donate">Monero XMR 46XVFMwQiY1L4WEbuQr9kS2huy39b7xQ'
                  'V7voVEQyDiEu5ge2YA9C5c9HWLvYnG33iEgmC8ENX9oSsDfBQu2PCjZWDUzMqKy'
                  '</div>')
        _v, ev = DarkwebModule._validated(donate, DarkwebModule._RE_XMR, norm_xmr)
        assert [e['section'] for e in ev.values()] == ['wallet']

    def test_url_userinfo_is_not_a_mailbox(self):
        """Reddit's onion embeds a Sentry DSN, `https://<key>@<host>/<project>`.
        The key@host half is regex-shaped like an address and normalizes
        cleanly, so only the `://` in front of it says it is a credential in a
        URL authority rather than a mailbox somebody reads."""
        html = ('var SENTRY_CONFIG = {"dsn":"https://9f057df6115a4bb488c08ea12a'
                '835e6e@error-tracking.' + 'r' * 56 + '.onion/o418887/5810803"};')
        values, ev = DarkwebModule._validated(
            html, DarkwebModule._RE_EMAIL, norm_email)
        assert values == [] and ev == {}
        # A mailto link and an address beside an ordinary hyperlink still count.
        for markup in ('<a href="mailto:admin@morke.ru">write us</a>',
                       '<a href="https://morke.ru">site</a> or admin@morke.ru'):
            values, _ = DarkwebModule._validated(
                markup, DarkwebModule._RE_EMAIL, norm_email)
            assert values == ['admin@morke.ru'], markup

    def test_dotted_numeric_noise_is_not_an_ip(self):
        """An IP is the one artifact with no checksum to fail, so context is the
        only validation there is. Measured on Reddit's onion: the SVG path
        `c0 .5.4.9.9.9h14.2` yielded `5.4.9.9`, which was enriched into a
        Telefonica DSL line and offered as the market's candidate operator IP.
        """
        svg = ('<path d="M18 8.2V5.3C18 3.48 16.52 2 14.7 2H5.3C3.48 2 2 3.48 2 '
               '5.3v2.9c0 .5.4.9.9.9h14.2c.5 0 .9-.4.9-.9z"/>')
        assert DarkwebModule._public_ipv4_in(svg)[0] == []
        # Version strings in the shapes that reach the header fingerprint too.
        for text in ('Server: PHP/5.4.9.9', '{"version":"5.4.9.9"}',
                     'release 5.4.9.9', 'build 5.4.9.9'):
            assert DarkwebModule._public_ipv4_in(text)[0] == [], text
        # A real leak, in the shapes it actually arrives in, still lands.
        for text in ('X-Real-IP: 203.0.113.9 X-Forwarded-For: 8.8.8.8',
                     'proxy_pass http://8.8.8.8/;', 'MySQL host 8.8.8.8 refused'):
            assert '8.8.8.8' in DarkwebModule._public_ipv4_in(text)[0], text
        # and it arrives with provenance, which is what the pivot gate reads.
        _v, ev = DarkwebModule._public_ipv4_in('<div id="footer">host 8.8.8.8</div>')
        assert ev['8.8.8.8']['section'] == 'footer'

    def test_svg_geometry_is_not_a_leaked_host(self):
        """The same family as the test above, one level up, and the version
        guard could not see it: inside path data the quad's neighbours are
        space-separated, not dotted, so `_VERSION_LEAD` never fires.

        Measured on Git Datura (nowhere.moe's Forgejo instance): three icon
        paths yielded `1.5.75.75`, `1.7.75.75` and `5.142.75.75`, every one was
        promoted to a candidate operator IP, and the pivot enriched them into
        SoftBank, Sify and Rostelecom subscriber networks — three uninvolved
        people's addresses filed as leads on that site.
        """
        forgejo = (
            '<svg aria-hidden="true" width="16" height="16"><path d="M10.561 '
            '8.073a6 6 0 0 1 3.432 5.142.75.75 0 1 1-1.498.07 4.5 4.5 0 0 0-8.99 '
            '0 .75.75 0 0 1-1.498-.07 6 6 0 0 1 3.431-5.142"/></svg>'
            '<path d="M5 3.25a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0m6.75.75a.75.75 '
            '0 1 0 0-1.5.75.75 0 0 0 0 1.5m-3 8.75a.75.75 0 0 1 0-1.5h1.75v-2h-8a1 '
            '1 0 0 0-.714 1.7.75.75 0 1 1-1.072 1.05A2.5 2.5 0 0 1 0 10.5"/>')
        assert DarkwebModule._public_ipv4_in(forgejo)[0] == []
        # Long path data: the coordinate that matches can sit hundreds of
        # characters after the attribute opened, which is why the look-back for
        # this test is wider than the context window.
        long_path = ('<path d="M0 0' + ' 1.5 2.25' * 120
                     + ' 5.142.75.75 0 1 1-1.498"/>')
        assert DarkwebModule._public_ipv4_in(long_path)[0] == []
        # An address in an ordinary attribute is still an address: the gate is
        # the geometry attribute, not "inside markup".
        for markup in ('<meta name="origin" content="behind 8.8.8.8">',
                       '<a href="http://8.8.8.8/admin">panel</a>',
                       '<div data-host="8.8.8.8">'):
            assert '8.8.8.8' in DarkwebModule._public_ipv4_in(markup)[0], markup

    def test_page_text_needs_the_address_used_as_a_host(self):
        """The denylist can only name the noise already seen, and the corpus
        keeps producing more: 81chan's footer reads `yonga 1.0.2.1` — a product
        version tag with no version keyword in front of it, so every guard above
        passed it, and it was promoted to a candidate operator IP and enriched
        into an unrelated APNIC network.

        So page text carries the burden the other way round: an address there is
        a leak when the page uses it AS a host. Headers and misconfig bodies stay
        permissive — those are network output already, so a bare address in them
        is the leak.
        """
        footer = '<p class="footer">- yonga 1.0.2.1 - </p>'
        assert DarkwebModule._public_ipv4_in(footer, require_host_use=True)[0] == []
        assert DarkwebModule._public_ipv4_in(footer)[0] == ['1.0.2.1']   # header path

        # The genuine self-declared clearnet host on that very same site, in the
        # site's own words, still lands.
        declared = ('sitenin a&ccedil;&#305;k a&#287; adresi: http://78.17.212.207/ '
                    'sitenin TOR &ouml;zel a&#287; adresi')
        assert DarkwebModule._public_ipv4_in(declared, require_host_use=True)[0] \
            == ['78.17.212.207']
        for text in ('MySQL host 8.8.8.8 refused', 'proxy_pass http://8.8.8.8/;',
                     'connect to 8.8.8.8:8443 for the backend',
                     'X-Real-IP: 8.8.8.8'):
            assert DarkwebModule._public_ipv4_in(text, require_host_use=True)[0] \
                == ['8.8.8.8'], text

    def test_redirects_follow_this_onion_and_stop_anywhere_else(self):
        """Two failures with one gate between them.

        Unfollowed, the big clearnet-backed onions answer `/` with a 307 to
        their `www.` vhost and the capture is a 168-byte redirect stub recorded
        as a live site that publishes nothing — worse than an error, because it
        reads as a real observation.

        Followed too far, a `Location:` pointing at clearnet is a request we must
        not make: it leaves Tor for a host the target chose, which is a
        deanonymising fetch. Any vhost of the same 56-char address is still one
        hidden service and is fine.

        A Location naming a DIFFERENT hidden service is refused for a third
        reason, and the one this gate is easiest to lose: the fetch would be
        safe — still Tor — but it would read another operator's page into this
        market's capture and hand every artifact on it to this target.
        """
        import asyncio
        onion = 'r' * 56 + '.onion'
        module = DarkwebModule()

        async def noop(*a, **k):
            return []

        module._crawl_pages = noop
        module._probe_misconfigs = noop

        async def no_favicon(*a, **k):
            return {}

        module._favicon_pivot = no_favicon

        def run(chain):
            seen = []

            async def fake_fetch(url):
                seen.append(url)
                return chain.get(url, (None, {}, ''))

            module._fetch_full = fake_fetch
            return asyncio.run(module._fetch_target_onion(onion)), seen

        result, seen = run({
            f'http://{onion}/': (307, {'Location': f'http://www.{onion}/'}, ''),
            f'http://www.{onion}/': (301, {'Location': f'http://www.{onion}/en'}, ''),
            f'http://www.{onion}/en': (200, {'Server': 'nginx'},
                                       '<title>Home</title>op@morke.ru'),
        })
        assert result.success and result.data['title'] == 'Home'
        assert result.data['emails'] == ['op@morke.ru']    # the real page was read

        # A clearnet Location is never requested, and what was already captured
        # is what gets reported.
        result, seen = run({
            f'http://{onion}/': (302, {'Location': 'https://mail.riseup.net/'},
                                 '<title>Gone</title>'),
        })
        assert all('.onion' in url for url in seen), seen
        assert result.success and result.data['title'] == 'Gone'

        # Another hidden service is not this one. The redirect is not followed,
        # and the address the stub links to stays an ordinary published link —
        # LINKS_TO, which no funnel scores — never a common-ownership claim.
        other = checksummed_onion('b')
        result, seen = run({
            f'http://{onion}/': (301, {'Location': f'http://{other}/'},
                                 f'<title>Moved</title><a href="http://{other}/">go</a>'),
        })
        assert seen == [f'http://{onion}/']
        assert result.success and result.data['http_status'] == 301
        assert result.data['url'] == f'http://{onion}/'
        assert result.data['onion_addresses_found'] == [other]

    def test_a_page_with_more_artifacts_than_the_old_caps_persists_all_of_them(self):
        """Collection must not silently drop evidence it already extracted.

        onion_addresses_found/clearnet_hosts_referenced/emails/ethereum_addresses
        used to be sliced to [:10]/[:40]/[:20]/[:20] right here in the
        collector, before evidence.ingest() ever sees the payload
        (evidence.ARTIFACT_MAP reads this exact dict — a slice here IS
        evidence loss, not a display choice). A directory page listing more
        than the old cap silently lost the rest with no record they ever
        existed: onion_links_found kept the true count while
        onion_addresses_found kept only the first 10 values. The crawl is
        already bounded (MAX_CRAWL_PAGES=8, CRAWL_BUDGET_SECONDS=180), so the
        slice bought nothing.
        """
        import asyncio
        onion = 'r' * 56 + '.onion'
        module = DarkwebModule()

        async def noop_list(*a, **k):
            return []

        async def noop_dict(*a, **k):
            return {}

        module._probe_misconfigs = noop_list
        module._favicon_pivot = noop_dict
        module._crawl_pages = noop_list      # everything lives on the root page

        n_onions, n_hosts, n_emails, n_eth = 15, 45, 25, 25
        onions = [checksummed_onion(c) for c in 'abcdefghijklmno'][:n_onions]
        hosts = [f'host{i}.opsec{i}.net' for i in range(n_hosts)]
        emails = [f'op{i}@opsec{i}.net' for i in range(n_emails)]
        eths = [f'0x{i:040x}' for i in range(n_eth)]

        html = '<title>Directory</title>' + ' '.join(
            f'<a href="http://{o}">{o}</a>' for o in onions) + ' ' + ' '.join(
            f'<a href="https://{h}/">{h}</a>' for h in hosts) + ' ' + \
            ' '.join(emails) + ' ' + ' '.join(eths)

        async def fake_fetch(url):
            return 200, {'Server': 'nginx'}, html

        module._fetch_full = fake_fetch

        result = asyncio.run(module._fetch_target_onion(onion))

        assert result.success
        # The list AND its count metadata agree, and both match what was
        # actually on the page — not a cap.
        assert result.data['onion_links_found'] == n_onions
        assert sorted(result.data['onion_addresses_found']) == sorted(onions)
        assert sorted(result.data['clearnet_hosts_referenced']) == sorted(hosts)
        assert sorted(result.data['emails']) == sorted(emails)
        assert len(result.data['ethereum_addresses']) == n_eth

    def test_a_catch_all_site_exposes_nothing(self):
        """81chan answers every unknown path with its 17 kB front page, so
        `/server-status`, `/server-info` and `/status` all read as exposed —
        and the `yonga 1.0.2.1` version tag in that page's footer was filed as a
        leaked host IP at confidence 0.9, which is HOSTED_ON, the strongest
        claim the IP model makes. A soft 404 is indistinguishable from a real
        exposure by the response alone, so the probe also asks for a path that
        cannot exist and reports nothing if that answers too."""
        import asyncio
        module = DarkwebModule()

        def run(responder):
            module._fetch_full = responder
            return asyncio.run(module._probe_misconfigs('http://x.onion'))

        async def catch_all(url):
            return 200, {}, '<html>front page ... yonga 1.0.2.1 ...</html>'

        assert run(catch_all) == []

        async def real_exposure(url):
            if url.endswith('/server-status'):
                return 200, {}, 'Server at 8.8.8.8 Port 80'
            return 404, {}, 'not found'

        found = run(real_exposure)
        assert [(f['path'], f['leaked_ips']) for f in found] \
            == [('/server-status', ['8.8.8.8'])]

    def test_an_exposed_git_config_yields_its_remote(self):
        """Both bodies are the real files, fetched over Tor from the two corpus
        targets that expose `/.git/config`. The probe already retrieved them and
        read nothing out but IP addresses, so the account a deployment pulls
        from — the strongest thing an exposed config carries — was discarded.

        The scp form is here because it is not a URL and `urlsplit` cannot parse
        it: `git@github.com:acct/repo` has the account after a colon, and read
        as a URL the whole thing collapses into a scheme-less path.
        """
        import asyncio
        module = DarkwebModule()

        async def exposed(url):
            if url.endswith('/.git/config'):
                return 200, {}, (
                    '[core]\n\trepositoryformatversion = 0\n'
                    '[remote "origin"]\n'
                    '\turl = ssh://git@git.disroot.org/coldxenine/deepswarm.git\n'
                    '\tfetch = +refs/heads/*:refs/remotes/origin/*\n')
            return 404, {}, 'not found'

        module._fetch_full = exposed
        found = asyncio.run(module._probe_misconfigs('http://x.onion'))
        assert [f['git_remotes'] for f in found] == [[{
            'url': 'ssh://git@git.disroot.org/coldxenine/deepswarm.git',
            'host': 'git.disroot.org', 'repository': 'deepswarm',
            'account': 'coldxenine'}]]

        # The second real exposure: the remote is a vhost of the site's OWN
        # onion, so the host carries nothing new and only the account does.
        nowhere = ('[remote "origin"]\n\turl = http://git.'
                   + checksummed_onion('n') + '/nihilist/nowhere-website.git\n')
        assert DarkwebModule._git_remotes(nowhere)[0]['account'] == 'nihilist'

        # scp-style, and a remote naming no account at all — inventing one out
        # of the repository name would attribute a site to a project.
        assert DarkwebModule._git_remotes(
            '\turl = git@github.com:someone/theme.git\n')[0]['account'] == 'someone'
        assert 'account' not in DarkwebModule._git_remotes(
            '\turl = https://code.example.net/repo.git\n')[0]
        assert DarkwebModule._git_remotes('nothing here') == []

    def test_an_open_directory_yields_its_listed_entries(self):
        """OnionScan's "open directories" check: a path the site never links
        to but that autoindex still serves. Detected off the title, which is
        the one thing mod_autoindex and nginx's autoindex agree on."""
        import asyncio
        module = DarkwebModule()

        async def exposed(url):
            if url.endswith('/backup/'):
                return 200, {}, (
                    '<title>Index of /backup/</title>'
                    '<a href="../">Parent Directory</a>'
                    '<a href="site-2026-01.tar.gz">site-2026-01.tar.gz</a>'
                    '<a href="keys.asc">keys.asc</a>')
            return 404, {}, 'not found'

        module._fetch_full = exposed
        found = asyncio.run(module._probe_misconfigs('http://x.onion'))
        assert len(found) == 1
        assert found[0]['path'] == '/backup/'
        assert found[0]['directory_listing'] is True
        assert found[0]['listed_entries'] == ['keys.asc', 'site-2026-01.tar.gz']

    def test_apache_mod_status_is_labeled_not_parsed_for_vhosts(self):
        """/server-status was already probed for leaked_ips; this only checks
        that a real mod_status body gets flagged, and that an ordinary 200 on
        the same path (no Apache banner) does not."""
        import asyncio
        module = DarkwebModule()

        async def exposed(url):
            if url.endswith('/server-status'):
                return 200, {}, '<title>Apache Status</title>Apache Server Status for x'
            return 404, {}, 'not found'

        module._fetch_full = exposed
        found = asyncio.run(module._probe_misconfigs('http://x.onion'))
        assert found[0]['apache_mod_status'] is True
        assert 'vhosts' not in found[0]

        async def unrelated_200(url):
            if url.endswith('/server-status'):
                return 200, {}, 'nothing to see here'
            return 404, {}, 'not found'

        module._fetch_full = unrelated_200
        found = asyncio.run(module._probe_misconfigs('http://x.onion'))
        assert 'apache_mod_status' not in found[0]

    def test_onion_lookup_survives_a_response_that_is_not_an_object(self):
        """One odd answer must not cost the whole sweep.

        Measured on a live run against nowhere.moe: the endpoint answered one
        address with a bare JSON list, `data.get('id')` raised, and the
        exception took down the lookup for every OTHER address in the same
        call — the source came back failed with nothing in it.
        """
        import asyncio
        module = DarkwebModule()
        bodies = {'a': [], 'b': {'id': 'known.onion', 'first_seen': '2024-01-01',
                                 'last_seen': '2026-08-01'}}
        good, bad = checksummed_onion('b'), checksummed_onion('a')

        async def fetch_json(url, **kw):
            return bodies['b' if good[:8] in url else 'a']

        module.fetch_json = fetch_json
        r = asyncio.run(module._search_onion_lookup([bad, good]))
        assert r.success and r.data['known'] == 1
        assert r.data['results'][0]['first_seen'] == '2024-01-01'
        assert r.data['unknown'] == [bad]

    def test_exonerator_never_reports_unknown_as_not_a_relay(self):
        """ExoneraTor answers three ways and the third one is not a negative.

        Both strings here are the real page. "Server problem — the database
        appears to be empty" is what an address outside its relay data returns
        (8.8.8.8 and 1.1.1.1 both do), and "Date parameter too recent" is what
        yesterday returns, because descriptors reach the archive on a delay.
        Read either as "not a relay" and the control quietly stops firing
        exactly where it knows least.
        """
        import asyncio
        from cybertrace.modules.ip_module import IPModule
        module = IPModule()

        def run(body):
            async def fetch(url, **kw):
                return body
            module.fetch = fetch
            return asyncio.run(module._check_exonerator('171.25.193.25'))

        found = run('<p>Summary</p><h3>Result is positive</h3> We found one or more')
        assert found.success and found.data['tor_relay'] is True
        assert found.data['checked_date']

        clear = run('<h3>Result is negative</h3> We did not find IP address')
        assert clear.success and clear.data['tor_relay'] is False

        for unknown in ('<h3>Server problem</h3> The database appears to be empty.',
                        '<h3>Date parameter too recent</h3> may not yet contain',
                        None):
            answer = run(unknown)
            assert not answer.success and 'NOT a negative' in answer.error, unknown
            assert answer.data == {}

    def test_validated_excludes_onion_slices(self):
        onion = 'a' * 56 + '.onion'
        values, _ = DarkwebModule._validated(
            html := f"visit {onion}", DarkwebModule._RE_BTC, norm_btc,
            exclude=html)
        assert values == []

    def test_pivot_targets_caps_and_labels(self):
        data = {
            'emails': ['a@x.com', 'b@x.com', 'c@x.com', 'd@x.com'],
            'bitcoin_addresses': ['1abc'],
            'ethereum_addresses': ['0xdef'],
        }
        jobs = DarkwebModule._pivot_targets(data, cap=3)
        assert ('email', 'a@x.com') in jobs
        assert ('email', 'd@x.com') not in jobs  # capped at 3 per kind
        assert ('bitcoin', '1abc') in jobs and ('bitcoin', '0xdef') in jobs

    def test_pivot_targets_empty_when_no_artifacts(self):
        assert DarkwebModule._pivot_targets({}) == []

    def test_pivot_targets_ip_and_username(self):
        data = {
            'emails': ['darkoperator@proton.me', 'admin@x.com', 'ab@x.com'],
            'candidate_operator_ips': ['8.8.8.8', '1.1.1.1'],
        }
        jobs = DarkwebModule._pivot_targets(data, cap=3)
        assert ('ip', '8.8.8.8') in jobs and ('ip', '1.1.1.1') in jobs
        # local-part becomes a username; role account + too-short are dropped
        assert ('username', 'darkoperator') in jobs
        assert ('username', 'admin') not in jobs
        assert ('username', 'ab') not in jobs

    def test_extract_pgp_keys_falls_back_to_payload_hash(self):
        # Not a parseable OpenPGP packet — id degrades to the payload hash.
        block = (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            "Version: GnuPG v2\n\n"
            + "mQENBFabcd" * 20 + "\n=Ab12\n"
            "-----END PGP PUBLIC KEY BLOCK-----"
        )
        keys = DarkwebModule._extract_pgp_keys(block + "\n" + block)  # same key twice
        assert len(keys) == 1 and len(keys[0]['key_id']) == 16
        assert 'fingerprint' not in keys[0]
        assert DarkwebModule._extract_pgp_keys("no key here") == []

    def test_extract_pgp_keys_uses_true_fingerprint(self):
        """A re-armored export of one key must yield ONE node, not two.

        This is what makes a shared PGP key the strongest cross-market signal:
        a clone re-exporting a copied key changes every byte of the armor but
        cannot change the fingerprint.
        """
        import base64, hashlib

        body = b'\x04' + b'\x5f\x00\x00\x00' + b'\x01' + b'\xab' * 60  # v4 pubkey packet
        packet = b'\x98' + bytes([len(body)]) + body                   # old-format tag 6
        b64 = base64.b64encode(packet).decode()
        expected = hashlib.sha1(
            b'\x99' + len(body).to_bytes(2, 'big') + body).hexdigest().upper()

        armor_a = (f"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{b64}\n"
                   "-----END PGP PUBLIC KEY BLOCK-----")
        # same key, different armor: extra header, different line wrapping, CRC
        wrapped = "\n".join(b64[i:i + 24] for i in range(0, len(b64), 24))
        armor_b = (f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v2\n\n"
                   f"{wrapped}\n=Ab12\n-----END PGP PUBLIC KEY BLOCK-----")

        keys = DarkwebModule._extract_pgp_keys(armor_a + "\n" + armor_b)
        assert len(keys) == 1, "re-armored key must not split into two entities"
        assert keys[0]['key_id'] == f"PGP:{expected}"
        assert keys[0]['fingerprint'] == expected

    def test_extract_pgp_keys_preserves_the_armored_block(self):
        """The extractor must retain the full armored block, not just the
        fingerprint. evidence.ingest reads key_created_at/key_expires_at
        straight from the packet bytes (normalize.pgp_key_times) and has
        nothing to parse without the block surviving extraction."""
        from .test_evidence import _armor, _pubkey_packet
        key_block = _armor(_pubkey_packet((1 << 2047) | 0x9999))
        html = f"<div class='contact'>Our PGP key:<br>{key_block}<br>End of key</div>"
        keys = DarkwebModule._extract_pgp_keys(html)
        assert len(keys) == 1
        assert keys[0]['armored'] == key_block
        assert keys[0]['fingerprint']

    def test_extract_pgp_keys_context_is_a_page_snippet_not_the_block(self):
        """context must show WHERE the key sat on the page, like every other
        artifact's evidence map — not dump the (large) armored bytes into the
        observation, which would defeat the point of a human-checkable snippet."""
        from .test_evidence import _armor, _pubkey_packet
        key_block = _armor(_pubkey_packet((1 << 2047) | 0x8888))
        html = f"<div class='contact'>Reach us securely:<br>{key_block}<br>Thanks!</div>"
        keys = DarkwebModule._extract_pgp_keys(html)
        ctx = keys[0]['context']
        assert 'Reach us securely' in ctx
        assert 'Thanks!' in ctx
        assert key_block not in ctx
        assert len(ctx) <= 200

    def test_extract_pgp_keys_oversized_block_fails_closed(self):
        """A block far past any real single-key export must not be stored
        truncated — a truncated block would still 'parse' (the packet reader
        stops cleanly rather than raising) and could misreport the key it
        claims to be. The record keeps its identity (fingerprint); only the
        raw armor is withheld.

        Built as many repeats of one valid packet (not spliced-in noise) so
        the whole thing stays valid base64 end to end — a keyring export with
        one real key repeated is exactly the kind of oversized-but-genuinely-
        parseable input the bound has to refuse anyway.
        """
        from .test_evidence import _armor, _pubkey_packet
        packet = _pubkey_packet((1 << 2047) | 0x7777)
        bulky = _armor(packet * 2000)  # far past the 128 KiB bound
        assert len(bulky) > DarkwebModule._MAX_PGP_ARMOR_BYTES
        html = f"<div class='pgp'>{bulky}</div>"
        keys = DarkwebModule._extract_pgp_keys(html)
        assert len(keys) == 1
        assert 'armored' not in keys[0]
        assert keys[0].get('fingerprint')

    @pytest.mark.skipif(not evolution.index_available(),
                        reason="Evolution PGP index not built (call build_index() once)")
    def test_extract_pgp_keys_pivots_a_real_key_against_evolution(self):
        """Section 11's live pivot end to end: a REAL vendor key from the
        recovered 2,429-fingerprint Evolution corpus, reflowed and dropped
        into synthetic page HTML the same shape a live onion crawl would
        produce, must round-trip through the same fingerprint parser a real
        crawl uses (norm_pgp) and come back tagged as an
        EXTERNAL_DATASET_MATCH -- not a synthetic fixture standing in for one.
        """
        rec = next(evolution.iter_vendor_pgp_fingerprints())
        reflowed = evolution._reflow_armor(rec["armored_original"])
        html = f"<div class='pgp'>Our key:<br>{reflowed}<br>Verify before paying.</div>"
        keys = DarkwebModule._extract_pgp_keys(html)
        assert len(keys) == 1
        assert keys[0]["fingerprint"] == rec["fingerprint"]
        assert keys[0]["evolution_dataset_match"] is True
        assert keys[0]["evolution_vendor_count"] >= 1
        # A dataset match is a label to display, never a role: it must not
        # promote a merely-displayed key to 'signing', or affect anything
        # about how the key is otherwise ingested.
        assert keys[0]["role"] == "displayed"

    def test_extract_pgp_keys_degrades_silently_without_the_dataset(self, monkeypatch):
        """No dataset, no index, or both: extraction must still succeed with a
        real fingerprint and simply carry no evolution_* fields — the same
        degrade-quietly discipline bitcoin_module._check_ellipticpp follows
        for a missing local dataset, applied at the point evolution is
        actually called rather than through a SourceResult."""
        from .test_evidence import _armor, _pubkey_packet
        monkeypatch.setattr(evolution, "available", lambda: False)
        key_block = _armor(_pubkey_packet((1 << 2047) | 0x6666))
        keys = DarkwebModule._extract_pgp_keys(f"<div>{key_block}</div>")
        assert len(keys) == 1
        assert keys[0].get("fingerprint")
        assert "evolution_dataset_match" not in keys[0]

    def test_favicon_hash_matches_shodan_scheme(self):
        import base64, mmh3
        # Shodan's http.favicon.hash = mmh3.hash(base64.encodebytes(icon_bytes)).
        icon = b'\x00\x01\x02\x03fake-icon'
        assert mmh3.hash(base64.encodebytes(icon)) == mmh3.hash(base64.encodebytes(icon))


class TestDarkwebTLSCertProbe:
    """Onion TLS cert capture (_fetch_tls_cert_der): must degrade to None on
    any connection/handshake failure — most onions never offer TLS at all —
    and must fingerprint whatever cert a Tor SOCKS5 connection does receive.
    Tests the blocking half directly rather than through the async wrapper,
    since the thing worth pinning is the socket/ssl error handling, not the
    executor plumbing."""

    def test_connection_refused_degrades_to_none(self, monkeypatch):
        module = DarkwebModule()

        class FakeSocket:
            def set_proxy(self, *a, **k): pass
            def settimeout(self, *a, **k): pass
            def connect(self, *a, **k): raise OSError('connection refused')
            def close(self): pass

        monkeypatch.setattr('socks.socksocket', FakeSocket)
        assert module._fetch_tls_cert_der('x' * 56 + '.onion') is None

    def test_presented_cert_is_returned_for_fingerprinting(self, monkeypatch):
        module = DarkwebModule()
        der_bytes = b'\x30\x82fake-der-cert-bytes'

        class FakeTLSSocket:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def getpeercert(self, binary_form=False): return der_bytes

        class FakeContext:
            def __init__(self, *a, **k): pass
            def wrap_socket(self, sock, server_hostname=None): return FakeTLSSocket()

        class FakeSocket:
            def set_proxy(self, *a, **k): pass
            def settimeout(self, *a, **k): pass
            def connect(self, *a, **k): pass
            def close(self): pass

        monkeypatch.setattr('socks.socksocket', FakeSocket)
        monkeypatch.setattr('ssl.SSLContext', FakeContext)
        der = module._fetch_tls_cert_der('x' * 56 + '.onion')
        assert der == der_bytes


class TestDarkwebCrawl:
    """Bounded same-onion crawl: only "/" made a login wall look artifact-free."""

    HOST = 'a' * 56 + '.onion'
    OTHER = 'b' * 56 + '.onion'

    def test_links_stay_on_the_target_onion(self):
        html = (
            f'<a href="/contact">c</a><a href="rules.html#top">r</a>'
            f'<a href="http://{self.OTHER}/vendor">other onion</a>'
            f'<a href="https://evil.example/x">clearnet</a>'
            f'<a href="mailto:op@example.com">mail</a>'
            f'<a href="/logo.png">img</a><a href="/contact#again">dup</a>'
        )
        links = DarkwebModule._same_onion_links(f'http://{self.HOST}/', html, self.HOST)
        # Off-host links would attribute another site's artifacts to this operator.
        assert links == [f'http://{self.HOST}/contact', f'http://{self.HOST}/rules.html']

    def test_links_preserve_https_when_the_page_was_served_over_https(self):
        """_crawl_pages has no redirect-follower of its own — only the caller's
        front-page fetch does. A link rebuilt as http on an https-only onion
        re-triggers the same redirect the front page already resolved, and
        since nothing follows it there, the page comes back as an unfollowed
        307 stub instead of real content. Reproduced live against EFF's
        onion: every discovered subpage stubbed out this way before the fix.
        """
        html = '<a href="/contact">c</a>'
        links = DarkwebModule._same_onion_links(f'https://{self.HOST}/', html, self.HOST)
        assert links == [f'https://{self.HOST}/contact']

    def test_links_are_kept_when_the_site_serves_from_a_www_vhost(self):
        """`www.<addr>.onion` is the same hidden service as `<addr>.onion`, and
        the big wiki-backed onions redirect to it. Their own links are absolute
        and carry the `www.`, so comparing against the address we asked for
        rejects every one of them: the crawl stops at the front page and the
        site is recorded as live with nothing published.

        Measured on Whonix — one page and no artifacts before, eight pages and
        the donation wallet after.
        """
        served = f'www.{self.HOST}'
        html = (f'<a href="http://{served}/wiki/Donate">d</a>'
                f'<a href="http://{self.OTHER}/x">other onion</a>')
        assert DarkwebModule._same_onion_links(f'http://{served}/', html, served) == \
            [f'http://{served}/wiki/Donate']
        # The host gate itself is unchanged: another onion is still refused.
        assert not DarkwebModule._same_onion_links(
            f'http://{served}/', f'<a href="http://{self.OTHER}/x">o</a>', served)

    def test_crawl_is_bounded_and_aggregates_artifacts_across_pages(self):
        import asyncio

        # A landing page with nothing on it — the exact case that used to report
        # zero artifacts — linking to pages that each carry one.
        pages = {
            '/': '<a href="/contact">c</a><a href="/vendor">v</a><a href="/faq">f</a>'
                 '<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>'
                 '<a href="/d">d</a><a href="/e">e</a><a href="/f">f</a>',
            '/contact': 'mail <a href="/deep">deep</a> support@shop.li',
            '/vendor': 'pay 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
            '/faq': 'nothing here',
        }
        module = DarkwebModule()
        fetched = []

        async def fake_fetch_full(url):
            path = url.split(self.HOST, 1)[1] or '/'
            fetched.append(path)
            return (200, {}, pages.get(path, 'filler')) if path in pages or path.startswith('/') \
                else (None, {}, '')

        module._fetch_full = fake_fetch_full
        crawled = asyncio.run(module._crawl_pages(f'http://{self.HOST}', self.HOST, pages['/']))

        assert len(crawled) == DarkwebModule.MAX_CRAWL_PAGES - 1  # "/" is the caller's
        assert len(set(fetched)) == len(fetched), 'a URL must not be fetched twice'
        # Artifact-bearing paths are crawled ahead of generic ones.
        assert set(fetched[:3]) == {'/contact', '/vendor', '/faq'}

        found = [module._extract_artifacts(html, self.HOST) for _u, _s, html in crawled]
        assert 'support@shop.li' in [e for f in found for e in f['emails']]
        assert '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2' in \
            [b for f in found for b in f['bitcoin_addresses']]


class TestDirectoryDiscovery:
    """dark.fail pairs a heading with the addresses under it.

    The parser is regression-tested against that real shape because the previous
    one — anchor tags whose href IS the onion — matched nothing on the live page
    and quietly returned zero services on every run, while the code above it
    reported directory discovery as working.
    """

    PAGE = """
    <h4><a href="/riseup">Riseup</a></h4>
      <div class="online"><ul>
        <li class="online status1"><code>http://vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion</code></li>
      </ul></div>
    <h4><a href="/proton">Protonmail &amp; more</a></h4>
      <code>https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion</code>
    <h4><a href="/nothing">No Address Here</a></h4>
      <p>offline</p>
    """

    def _parse(self, html):
        import asyncio
        module = DarkwebModule()

        async def fake_fetch(url, **kwargs):
            return html

        module.fetch = fake_fetch
        return asyncio.run(module._parse_dark_fail())

    def test_headings_pair_with_the_addresses_below_them(self):
        services = self._parse(self.PAGE)
        assert services == {
            'Riseup': 'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion',
            'Protonmail & more':
                'protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion',
        }

    def test_anchor_href_layout_still_works(self):
        """The fallback: directories that do link straight at the onion."""
        onion = 'a' * 56 + '.onion'
        assert self._parse(f'<a href="http://{onion}/">Some Market</a>') == \
            {'Some Market': onion}


class TestIndianModule:
    """Test Indian module."""

    def test_module_attributes(self):
        module = IndianModule()
        assert module.name == 'indian'
        assert 'indian' in module.supported_types

    def test_detect_indian_type_gstin(self):
        module = IndianModule()
        assert module._detect_indian_type("22AAAAA0000A1Z5") == 'gstin'

    def test_detect_indian_type_pan(self):
        module = IndianModule()
        assert module._detect_indian_type("ABCDE1234F") == 'pan'

    def test_detect_indian_type_vehicle(self):
        module = IndianModule()
        assert module._detect_indian_type("MH12AB1234") == 'vehicle'

    def test_detect_indian_type_name(self):
        module = IndianModule()
        assert module._detect_indian_type("John Doe") == 'name'


# ---------------------------------------------------------------------------#
# The six OSINT collectors below (phone, geoint, ip, image, breach, social)  #
# had zero dedicated tests before Loop 25 (Loop 24 §2/§10.2). They dead-end  #
# before the graph (Loop 11 §4/§10 — investigator-facing output only), so    #
# the risk a defect here poses is under-reporting a raw collector value to   #
# an investigator, never a false attribution. Coverage below exercises each  #
# source's malformed/empty/failure paths directly against the real parsing  #
# code (fetch_json/fetch monkeypatched, no network), per Loop 25 Phase 6.    #
# ---------------------------------------------------------------------------#


class TestPhoneModule:
    def test_module_attributes(self):
        module = PhoneModule()
        assert module.name == 'phone'
        assert 'phone' in module.supported_types

    def test_parses_a_valid_number(self):
        import asyncio
        module = PhoneModule()
        result = asyncio.run(module._parse_with_phonenumbers('+14155552671'))
        assert result.success is True
        assert result.data['valid'] is True
        assert result.data['e164'] == '+14155552671'
        assert result.data['country_code'] == '+1'

    def test_garbage_input_reports_failure_not_a_crash(self):
        import asyncio
        module = PhoneModule()
        result = asyncio.run(module._parse_with_phonenumbers('not-a-phone-number'))
        assert result.success is False

    def test_free_carrier_lookup_parses_a_valid_response(self):
        import asyncio
        module = PhoneModule()
        async def fake_fetch_json(url, **kwargs):
            return {'countryCode': 'US', 'carrierName': 'Verizon', 'numberType': 'MOBILE',
                    'countryName': 'United States', 'city': 'New York'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._free_carrier_lookup('+14155552671'))
        assert result.success is True
        assert result.data['carrier'] == 'Verizon'
        assert result.data['line_type'] == 'mobile'

    def test_free_carrier_lookup_falls_back_to_phonenumbers_when_the_api_fails(self):
        import asyncio
        module = PhoneModule()
        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._free_carrier_lookup('+14155552671'))
        assert result.success is True
        assert result.data['source_api'] == 'phonenumbers_fallback'

    def test_free_carrier_lookup_reports_failure_when_nothing_usable_comes_back(self):
        import asyncio
        module = PhoneModule()
        async def fake_fetch_json(url, **kwargs):
            return {'unexpected': 'shape'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._free_carrier_lookup('garbage-not-a-real-number'))
        assert result.success is False

    def test_numverify_parses_a_valid_response(self):
        import asyncio
        module = PhoneModule()
        async def fake_fetch_json(url, **kwargs):
            return {'valid': True, 'number': '14155552671', 'carrier': 'Verizon',
                    'country_name': 'United States', 'line_type': 'mobile'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_numverify('+14155552671'))
        assert result.success is True
        assert result.data['valid'] is True
        assert result.data['carrier'] == 'Verizon'

    def test_numverify_reports_a_genuinely_invalid_number(self):
        import asyncio
        module = PhoneModule()
        async def fake_fetch_json(url, **kwargs):
            return {'valid': False, 'number': '123'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_numverify('123'))
        assert result.success is True
        assert result.data['valid'] is False

    def test_numverify_api_error_is_not_reported_as_an_invalid_number(self):
        """Regression: APILayer's error envelope ({'success': false, 'error':
        {...}}) has no 'valid' key either, so before the fix `not data.get(
        'valid')` reported a bad API key / exhausted quota as a confidently-
        checked 'this number is invalid' result -- an API failure silently
        becoming a successful finding."""
        import asyncio
        module = PhoneModule()
        async def fake_fetch_json(url, **kwargs):
            return {'success': False,
                    'error': {'code': 101, 'type': 'invalid_access_key',
                              'info': 'You have not supplied a valid API access key.'}}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_numverify('+14155552671'))
        assert result.success is False
        assert 'valid API access key' in result.error


class TestGeointModule:
    def test_module_attributes(self):
        module = GeointModule()
        assert module.name == 'geoint'
        assert 'coordinates' in module.supported_types

    def test_detect_type_coordinates(self):
        assert GeointModule._detect_type('51.5074,-0.1278') == 'coordinates'

    def test_detect_type_ip(self):
        assert GeointModule._detect_type('8.8.8.8') == 'ip'

    def test_detect_type_falls_back_to_address(self):
        assert GeointModule._detect_type('221B Baker Street, London') == 'address'

    def test_parse_coordinates_valid(self):
        assert GeointModule._parse_coordinates('51.5074,-0.1278') == (51.5074, -0.1278)

    def test_parse_coordinates_malformed_returns_none_none(self):
        assert GeointModule._parse_coordinates('not,coordinates') == (None, None)

    def test_parse_coordinates_wrong_arity_returns_none_none(self):
        assert GeointModule._parse_coordinates('1,2,3') == (None, None)

    def test_reverse_geocode_parses_a_valid_response(self):
        import asyncio
        module = GeointModule()
        async def fake_fetch_json(url, **kwargs):
            return {'display_name': 'London, UK', 'lat': '51.5', 'lon': '-0.1',
                    'address': {'city': 'London', 'country': 'United Kingdom',
                                'country_code': 'gb'}}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._reverse_geocode(51.5, -0.1))
        assert result.success is True
        assert result.data['city'] == 'London'

    def test_reverse_geocode_reports_failure_on_an_error_response(self):
        import asyncio
        module = GeointModule()
        async def fake_fetch_json(url, **kwargs):
            return {'error': 'Unable to geocode'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._reverse_geocode(999, 999))
        assert result.success is False

    def test_reverse_geocode_reports_failure_when_the_fetch_itself_fails(self):
        import asyncio
        module = GeointModule()
        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._reverse_geocode(51.5, -0.1))
        assert result.success is False

    def test_forward_geocode_reports_failure_on_a_non_list_response(self):
        import asyncio
        module = GeointModule()
        async def fake_fetch_json(url, **kwargs):
            return {'unexpected': 'a dict, not the documented list'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._forward_geocode('nowhere at all'))
        assert result.success is False

    def test_geolocate_ip_reports_failure_on_a_bogon_address(self):
        import asyncio
        module = GeointModule()
        async def fake_fetch_json(url, **kwargs):
            return {'ip': '127.0.0.1', 'bogon': True}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._geolocate_ip('127.0.0.1'))
        assert result.success is False

    def test_get_timezone_falls_back_to_a_longitude_estimate_when_the_api_fails(self):
        import asyncio
        module = GeointModule()
        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._get_timezone(51.5, -0.1))
        assert result.success is True
        assert result.data['source'] == 'longitude_estimate'

    def test_equator_and_prime_meridian_coordinates_survive_the_summary(self):
        """Regression: `{'lat': lat, 'lon': lon} if lat and lon else None`
        treated a legitimate 0.0 latitude or longitude (equator / prime
        meridian) as falsy and silently dropped real, successfully-resolved
        coordinates from the summary an investigator reads."""
        module = GeointModule()
        result = ModuleResult(target='0,0', target_type='coordinates', module='geoint')
        summary = module._build_summary(
            result, lat=0.0, lon=0.0, resolved_address=None, target_type='coordinates')
        assert summary['coordinates'] == {'lat': 0.0, 'lon': 0.0}

    def test_search_reports_a_parse_error_for_unparseable_coordinates(self):
        import asyncio
        module = GeointModule()
        result = asyncio.run(module.search('garbage', target_type='coordinates'))
        assert 'error' in result.summary


class TestIPModule:
    def test_module_attributes(self):
        module = IPModule()
        assert module.name == 'ip'
        assert 'ip' in module.supported_types

    def test_ipinfo_parses_a_valid_response(self):
        import asyncio
        module = IPModule()
        async def fake_fetch_json(url, **kwargs):
            return {'ip': '8.8.8.8', 'city': 'Mountain View', 'country': 'US',
                    'org': 'AS15169 Google LLC', 'loc': '37.4,-122.1'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_ipinfo('8.8.8.8'))
        assert result.success is True
        assert result.data['org'] == 'Google LLC'
        assert result.data['asn'] == 'AS15169'

    def test_ipinfo_reports_failure_on_a_bogon_address(self):
        import asyncio
        module = IPModule()
        async def fake_fetch_json(url, **kwargs):
            return {'ip': '10.0.0.1', 'bogon': True}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_ipinfo('10.0.0.1'))
        assert result.success is False

    def test_ip_api_reports_failure_on_a_non_success_status(self):
        import asyncio
        module = IPModule()
        async def fake_fetch_json(url, **kwargs):
            return {'status': 'fail', 'message': 'invalid query'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_ip_api('not-an-ip'))
        assert result.success is False

    def test_greynoise_classifies_not_seen(self):
        import asyncio
        module = IPModule()
        async def fake_fetch_json(url, **kwargs):
            return {'message': 'IP not observed scanning the internet or '
                                'contained in RIOT data set.'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_greynoise('1.2.3.4'))
        assert result.success is True
        assert result.data['seen'] is False

    def test_greynoise_reports_failure_on_no_response(self):
        import asyncio
        module = IPModule()
        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_greynoise('1.2.3.4'))
        assert result.success is False

    def test_threatfox_no_result_is_a_successful_negative(self):
        import asyncio
        module = IPModule()
        async def fake_fetch_json(url, **kwargs):
            return {'query_status': 'no_result'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_threatfox('1.2.3.4'))
        assert result.success is True
        assert result.data['found'] is False

    def test_threatfox_unexpected_status_reports_failure_not_a_false_negative(self):
        import asyncio
        module = IPModule()
        async def fake_fetch_json(url, **kwargs):
            return {'query_status': 'illegal_search_term'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_threatfox('1.2.3.4'))
        assert result.success is False

    def test_abuseipdb_reports_failure_on_a_malformed_response(self):
        import asyncio
        module = IPModule()
        module.config.api_keys.abuseipdb = 'testkey'
        try:
            async def fake_fetch_json(url, **kwargs):
                return {'errors': [{'detail': 'bad key'}]}
            module.fetch_json = fake_fetch_json
            result = asyncio.run(module._check_abuseipdb('1.2.3.4'))
            assert result.success is False
        finally:
            module.config.api_keys.abuseipdb = None

    def test_exonerator_distinguishes_positive_negative_and_unanswerable(self):
        import asyncio
        module = IPModule()

        async def fake_fetch_positive(url, **kwargs):
            return 'blah blah Result is positive blah'
        module.fetch = fake_fetch_positive
        positive = asyncio.run(module._check_exonerator('1.2.3.4'))
        assert positive.success is True
        assert positive.data['tor_relay'] is True

        async def fake_fetch_negative(url, **kwargs):
            return 'blah blah Result is negative blah'
        module.fetch = fake_fetch_negative
        negative = asyncio.run(module._check_exonerator('1.2.3.4'))
        assert negative.success is True
        assert negative.data['tor_relay'] is False

        async def fake_fetch_unanswerable(url, **kwargs):
            return 'Server problem, no data for this range'
        module.fetch = fake_fetch_unanswerable
        unanswerable = asyncio.run(module._check_exonerator('1.2.3.4'))
        assert unanswerable.success is False
        assert 'NOT a negative result' in unanswerable.error

    def test_risk_level_escalates_with_abuse_score(self):
        module = IPModule()
        result = ModuleResult(target='1.2.3.4', target_type='ip', module='ip')
        result.sources['abuseipdb'] = SourceResult(
            source='abuseipdb', success=True,
            data={'abuse_confidence_score': 90, 'is_tor': False})
        summary = module._build_summary(result)
        assert summary['risk_level'] == 'critical'


class TestImageModule:
    def test_module_attributes(self):
        module = ImageModule()
        assert module.name == 'image'
        assert 'image' in module.supported_types

    def test_resolve_target_missing_local_file_returns_none(self):
        import asyncio
        module = ImageModule()
        path, temp = asyncio.run(module._resolve_target('/no/such/file.jpg'))
        assert path is None
        assert temp is None

    def test_resolve_target_existing_local_file(self, tmp_path):
        import asyncio
        module = ImageModule()
        f = tmp_path / 'photo.jpg'
        f.write_bytes(b'not a real jpeg, just bytes')
        path, temp = asyncio.run(module._resolve_target(str(f)))
        assert path == str(f)
        assert temp is None  # local path -- no temp file to clean up

    def test_dms_to_decimal_valid(self):
        result = ImageModule._dms_to_decimal((40, 26, 46), 'N')
        assert result == pytest.approx(40.446111, abs=1e-5)

    def test_dms_to_decimal_negates_for_south_and_west(self):
        result = ImageModule._dms_to_decimal((40, 26, 46), 'S')
        assert result < 0

    def test_dms_to_decimal_none_input_returns_none(self):
        assert ImageModule._dms_to_decimal(None, 'N') is None

    def test_dms_to_decimal_malformed_tuple_returns_none_not_a_crash(self):
        assert ImageModule._dms_to_decimal((1, 2), 'N') is None  # wrong arity

    def test_parse_exiftool_output_negates_south_and_west(self):
        module = ImageModule()
        raw = {'GPSLatitude': '33.8688', 'GPSLatitudeRef': 'S',
               'GPSLongitude': '151.2093', 'GPSLongitudeRef': 'W', 'Make': 'Apple'}
        data = module._parse_exiftool_output(raw)
        assert data['gps_latitude'] == -33.8688
        assert data['gps_longitude'] == -151.2093
        assert data['has_gps'] is True

    def test_parse_exiftool_output_no_gps_fields(self):
        module = ImageModule()
        data = module._parse_exiftool_output({'Make': 'Apple', 'Model': 'iPhone'})
        assert data['has_gps'] is False
        assert 'gps_latitude' not in data

    def test_parse_exiftool_output_malformed_gps_does_not_crash(self):
        module = ImageModule()
        raw = {'GPSLatitude': 'not-a-number', 'GPSLongitude': 'also-not-a-number'}
        data = module._parse_exiftool_output(raw)
        assert data['has_gps'] is False

    def test_compute_hashes_missing_file_returns_none(self):
        assert ImageModule._compute_hashes('/no/such/file.jpg') is None

    def test_compute_hashes_matches_known_content(self, tmp_path):
        import hashlib
        f = tmp_path / 'test.bin'
        f.write_bytes(b'hello world')
        result = ImageModule._compute_hashes(str(f))
        assert result['md5'] == hashlib.md5(b'hello world').hexdigest()
        assert result['size'] == 11

    def test_query_malwarebazaar_hash_not_found(self):
        import asyncio
        module = ImageModule()
        async def fake_fetch_json(url, **kwargs):
            return {'query_status': 'hash_not_found'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._query_malwarebazaar('deadbeef'))
        assert result == {'found': False}

    def test_query_malwarebazaar_reports_none_on_no_response(self):
        import asyncio
        module = ImageModule()
        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._query_malwarebazaar('deadbeef'))
        assert result is None

    def test_generate_reverse_image_search_links_for_a_url(self):
        import asyncio
        module = ImageModule()
        result = asyncio.run(
            module._generate_reverse_image_search_links('https://example.com/photo.jpg'))
        assert result.success is True
        assert 'google_lens' in result.data['links']

    def test_generate_reverse_image_search_links_for_a_local_file(self):
        import asyncio
        module = ImageModule()
        result = asyncio.run(
            module._generate_reverse_image_search_links('/tmp/photo.jpg'))
        assert 'upload local file' in result.data['links']['tineye']


class TestSocialModule:
    def test_module_attributes(self):
        module = SocialModule()
        assert module.name == 'social'
        assert 'username' in module.supported_types

    def test_reddit_profile_found_and_parsed(self):
        import asyncio
        module = SocialModule()
        async def fake_fetch_json(url, **kwargs):
            if 'about.json' in url:
                return {'kind': 't2', 'data': {'name': 'torvalds', 'id': 'abc',
                                                 'comment_karma': 100, 'link_karma': 50}}
            return {'data': {'children': []}}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._search_reddit('torvalds'))
        assert result.success is True
        assert result.data['profile_found'] is True
        assert result.data['profile']['total_karma'] == 150

    def test_reddit_profile_not_found_search_still_parsed(self):
        import asyncio
        module = SocialModule()
        async def fake_fetch_json(url, **kwargs):
            if 'about.json' in url:
                return {'kind': None}  # not t2 -- account doesn't exist
            return {'data': {'children': [
                {'kind': 't3', 'data': {'title': 'a post', 'permalink': '/r/x/1'}}
            ]}}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._search_reddit('nonexistent_user_xyz'))
        assert result.success is True
        assert result.data['profile_found'] is False
        assert result.data['search_post_count'] == 1

    def test_reddit_malformed_search_response_does_not_crash(self):
        import asyncio
        module = SocialModule()
        async def fake_fetch_json(url, **kwargs):
            if 'about.json' in url:
                return None
            return {'data': None}  # 'data' present but null, not the documented dict
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._search_reddit('someone'))
        assert result.success is True
        assert result.data['search_post_count'] == 0

    def test_bluesky_profile_found(self):
        import asyncio
        module = SocialModule()
        async def fake_fetch_json(url, **kwargs):
            if 'getProfile' in url:
                return {'did': 'did:plc:abc', 'handle': 'user.bsky.social',
                         'followersCount': 10}
            return {'posts': []}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._search_bluesky('user.bsky.social'))
        assert result.success is True
        assert result.data['profile']['handle'] == 'user.bsky.social'

    def test_bluesky_profile_not_found_does_not_crash(self):
        import asyncio
        module = SocialModule()
        async def fake_fetch_json(url, **kwargs):
            return {'error': 'ProfileNotFound'}  # no 'did' key
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._search_bluesky('nonexistent'))
        assert result.success is True
        assert result.data['profile_found'] is False

    def test_mastodon_reports_failure_on_no_response(self):
        import asyncio
        module = SocialModule()
        async def fake_fetch_json(url, **kwargs):
            return None
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._search_mastodon('someone'))
        assert result.success is False

    def test_mastodon_handles_missing_sections_gracefully(self):
        import asyncio
        module = SocialModule()
        async def fake_fetch_json(url, **kwargs):
            # Real zero-result shape: keys present, all empty -- not a bare {}.
            return {'accounts': [], 'statuses': [], 'hashtags': []}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._search_mastodon('someone'))
        assert result.success is True
        assert result.data['account_count'] == 0

    def test_github_user_not_found_still_returns_success_with_no_profile(self):
        import asyncio
        module = SocialModule()
        async def fake_fetch_json(url, **kwargs):
            return {'message': 'Not Found'}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._search_github('this_user_should_not_exist_xyz'))
        assert result.success is True
        assert result.data['profile_found'] is False

    def test_github_profile_found_surfaces_repos(self):
        import asyncio
        module = SocialModule()
        async def fake_fetch_json(url, **kwargs):
            if '/repos?' in url:
                return [{'name': 'linux', 'full_name': 'torvalds/linux',
                          'stargazers_count': 1}]
            return {'login': 'torvalds', 'id': 1, 'public_repos': 1}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._search_github('torvalds'))
        assert result.success is True
        assert result.data['profile']['login'] == 'torvalds'
        assert result.data['repo_count'] == 1

    def test_telegram_no_token_degrades_gracefully(self):
        import asyncio
        module = SocialModule()
        module.config.api_keys.telegram_bot = None
        result = asyncio.run(module._search_telegram('somechannel'))
        assert result.success is False

    def test_telegram_chat_not_found_is_a_successful_negative(self):
        import asyncio
        module = SocialModule()
        module.config.api_keys.telegram_bot = 'testtoken'
        try:
            async def fake_fetch_json(url, **kwargs):
                return {'ok': False, 'description': 'Bad Request: chat not found'}
            module.fetch_json = fake_fetch_json
            result = asyncio.run(module._search_telegram('@nonexistent'))
            assert result.success is True
            assert result.data['found'] is False
        finally:
            module.config.api_keys.telegram_bot = None


class TestBreachModule:
    def test_module_attributes(self):
        module = BreachModule()
        assert module.name == 'breach'
        assert 'email' in module.supported_types

    def test_hibp_no_key_degrades_gracefully(self):
        import asyncio
        module = BreachModule()
        module.config.api_keys.hibp = None
        result = asyncio.run(module._check_hibp('user@example.com'))
        assert result.success is False

    def test_hibp_parses_a_valid_breach_list(self):
        import asyncio, json as _json
        module = BreachModule()
        module.config.api_keys.hibp = 'testkey'
        try:
            async def fake_fetch(url, **kwargs):
                return _json.dumps([{'Name': 'Adobe', 'Title': 'Adobe',
                                      'Domain': 'adobe.com', 'BreachDate': '2013-10-04',
                                      'PwnCount': 152445165,
                                      'DataClasses': ['Email addresses', 'Passwords']}])
            module.fetch = fake_fetch
            result = asyncio.run(module._check_hibp('user@example.com'))
            assert result.success is True
            assert result.data['found'] is True
            assert result.data['breach_count'] == 1
            assert result.data['has_password_data'] is True
        finally:
            module.config.api_keys.hibp = None

    def test_hibp_404_with_no_body_reports_not_found(self):
        import asyncio
        module = BreachModule()
        module.config.api_keys.hibp = 'testkey'
        try:
            async def fake_fetch(url, **kwargs):
                return ''  # HIBP returns an empty body on 404
            module.fetch = fake_fetch
            result = asyncio.run(module._check_hibp('user@example.com'))
            assert result.success is True
            assert result.data['found'] is False
        finally:
            module.config.api_keys.hibp = None

    def test_hibp_never_calls_the_removed_broken_fetch_json_path(self):
        """Regression: _check_hibp used to make a guaranteed-to-fail
        fetch_json() call before its real fetch() call -- fetch_json() does
        not accept an ok_statuses kwarg at all, so passing it raised inside
        aiohttp on every single lookup, was swallowed by fetch_json's own
        generic except-clause, and the (always-None) result was never even
        read. That wasted one HTTP attempt against a paid, rate-limited API
        (HIBP) on every email lookup for nothing."""
        import asyncio
        module = BreachModule()
        module.config.api_keys.hibp = 'testkey'
        try:
            async def failing_fetch_json(url, **kwargs):
                raise AssertionError('fetch_json should not be called by _check_hibp')
            async def fake_fetch(url, **kwargs):
                return ''
            module.fetch_json = failing_fetch_json
            module.fetch = fake_fetch
            result = asyncio.run(module._check_hibp('user@example.com'))
            assert result.success is True
        finally:
            module.config.api_keys.hibp = None

    def test_breach_directory_parses_a_valid_response(self):
        import asyncio
        module = BreachModule()
        async def fake_fetch_json(url, **kwargs):
            return {'success': True, 'result': [{'sources': ['Adobe'], 'sha1': 'abc123'}]}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_breach_directory('user@example.com'))
        assert result.success is True
        assert result.data['found'] is True
        assert result.data['has_password_data'] is True

    def test_breach_directory_reports_not_found_on_an_unsuccessful_response(self):
        import asyncio
        module = BreachModule()
        async def fake_fetch_json(url, **kwargs):
            return {'success': False}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_breach_directory('user@example.com'))
        assert result.success is True
        assert result.data['found'] is False

    def test_leakcheck_distinguishes_not_found_from_a_real_error(self):
        import asyncio
        module = BreachModule()
        module.config.api_keys.leakcheck = 'testkey'
        try:
            async def fake_fetch_json(url, **kwargs):
                return {'success': False, 'error': 'Not found'}
            module.fetch_json = fake_fetch_json
            result = asyncio.run(module._check_leakcheck('user@example.com'))
            assert result.success is True
            assert result.data['found'] is False
        finally:
            module.config.api_keys.leakcheck = None

    def test_leakcheck_reports_a_genuine_api_error_as_a_failure(self):
        import asyncio
        module = BreachModule()
        module.config.api_keys.leakcheck = 'testkey'
        try:
            async def fake_fetch_json(url, **kwargs):
                return {'success': False, 'error': 'Rate limit exceeded'}
            module.fetch_json = fake_fetch_json
            result = asyncio.run(module._check_leakcheck('user@example.com'))
            assert result.success is False
        finally:
            module.config.api_keys.leakcheck = None

    def test_psbdmp_handles_a_dict_shaped_response(self):
        import asyncio
        module = BreachModule()
        async def fake_fetch_json(url, **kwargs):
            return {'data': [{'id': 'abc123', 'tags': 'leak', 'length': 500}]}
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_psbdmp('user@example.com'))
        assert result.success is True
        assert result.data['paste_count'] == 1
        assert result.data['pastes'][0]['url'] == 'https://pastebin.com/abc123'

    def test_psbdmp_handles_a_list_shaped_response(self):
        import asyncio
        module = BreachModule()
        async def fake_fetch_json(url, **kwargs):
            return [{'id': 'xyz', 'tags': '', 'length': 10}]
        module.fetch_json = fake_fetch_json
        result = asyncio.run(module._check_psbdmp('user@example.com'))
        assert result.success is True
        assert result.data['paste_count'] == 1

    def test_intelx_search_initiation_failure_reports_failure(self):
        import asyncio
        module = BreachModule()
        module.config.api_keys.intelx = 'testkey'
        try:
            async def fake_fetch_json(url, **kwargs):
                return {}  # no 'id' -- search never started
            module.fetch_json = fake_fetch_json
            result = asyncio.run(module._check_intelx('user@example.com'))
            assert result.success is False
        finally:
            module.config.api_keys.intelx = None


class TestDataClasses:
    """Test data classes."""

    def test_source_result_creation(self):
        result = SourceResult(
            source='test',
            success=True,
            data={'key': 'value'},
        )
        assert result.source == 'test'
        assert result.success is True
        assert result.data == {'key': 'value'}

    def test_source_result_to_dict(self):
        result = SourceResult(source='test', success=True)
        d = result.to_dict()
        assert d['source'] == 'test'
        assert d['success'] is True

    def test_module_result_creation(self):
        result = ModuleResult(
            target='test@example.com',
            target_type='email',
            module='email',
        )
        assert result.target == 'test@example.com'
        assert result.target_type == 'email'

    def test_module_result_success_count(self):
        result = ModuleResult(target='test', target_type='test', module='test')
        result.sources['s1'] = SourceResult(source='s1', success=True)
        result.sources['s2'] = SourceResult(source='s2', success=False)
        result.sources['s3'] = SourceResult(source='s3', success=True)
        assert result.success_count == 2
        assert result.total_count == 3


class TestMaigretReportParsing:
    """maigret's 'simple' report nests status inside a dict, not a bare string."""

    def test_nested_status_dict(self):
        data = {
            'GitHub': {
                'status': {'status': 'Claimed', 'site_name': 'GitHub'},
                'url_user': 'https://github.com/torvalds',
            },
            'Nowhere': {'status': {'status': 'Available'}, 'url_user': None},
        }
        found = UsernameModule._parse_maigret_report(data)
        assert found == [{
            'site': 'GitHub',
            'url': 'https://github.com/torvalds',
            'status': 'Claimed',
        }]

    def test_plain_string_status_still_works(self):
        data = {'X': {'status': 'Claimed', 'url_user': 'https://x.com/a'}}
        assert len(UsernameModule._parse_maigret_report(data)) == 1

    def test_ignores_malformed_entries(self):
        data = {'a': 'not-a-dict', 'b': {'status': None}, 'c': {}}
        assert UsernameModule._parse_maigret_report(data) == []


class TestSourceProgress:
    """run_sources renders live status without changing what it records."""

    @staticmethod
    def _run(sources, show_progress=False):
        import asyncio
        module = get_module('bitcoin')
        module.show_progress = show_progress
        result = ModuleResult(target='t', target_type='x', module='m')
        asyncio.run(module.run_sources(sources, result))
        return result

    def test_results_survive_the_progress_wrapper(self):
        async def ok():
            return {'found': 1}

        async def boom():
            raise ValueError("nope")

        async def opted_out():
            return None

        result = self._run([('a', ok()), ('b', boom()), ('c', opted_out())])
        assert result.sources['a'].success and result.sources['a'].data == {'found': 1}
        assert not result.sources['b'].success and 'nope' in result.sources['b'].error
        assert 'c' not in result.sources  # None is dropped, not a phantom failure

    def test_nested_search_does_not_open_a_second_display(self, monkeypatch):
        """The darkweb pivot runs a whole sub-search inside a source; rich
        allows only one live display, so the inner one must render nothing."""
        import cybertrace.modules.base as base

        monkeypatch.setenv('FORCE_COLOR', '1')  # make Console.is_terminal true

        async def _noop():
            return {'ok': True}

        async def inner():
            assert base._display_active is True  # outer owns the display
            nested = get_module('bitcoin')
            nested.show_progress = True
            inner_result = ModuleResult(target='t', target_type='x', module='m')
            # A second live display would raise rich.errors.LiveError here.
            await nested.run_sources([('leaf', _noop())], inner_result)
            return inner_result.sources['leaf'].data

        result = self._run([('outer', inner())], show_progress=True)
        assert result.sources['outer'].success
        assert base._display_active is False  # released on exit

    def test_labels_report_each_outcome(self):
        from cybertrace.modules.base import BaseModule as B
        assert '✓' in B._progress_label('a', SourceResult(source='a', success=True))
        assert '○' in B._progress_label('a', SourceResult(source='a', success=False,
                                                          error='down'))
        assert '✗' in B._progress_label('a', ValueError('x'))
        assert 'skipped' in B._progress_label('a', None)
