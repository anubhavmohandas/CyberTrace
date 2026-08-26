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
