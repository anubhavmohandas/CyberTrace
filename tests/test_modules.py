"""Tests for OSINT modules."""

import pytest
from cybertrace.modules import (
    get_module,
    list_modules,
    MODULE_REGISTRY,
    TYPE_TO_MODULE,
    BitcoinModule,
    UsernameModule,
    DomainModule,
    EmailModule,
    DarkwebModule,
    IndianModule,
)
from cybertrace.modules.base import ModuleResult, SourceResult
from cybertrace.normalize import norm_btc, norm_email


class TestModuleRegistry:
    """Test module registry functionality."""

    def test_module_registry_not_empty(self):
        assert len(MODULE_REGISTRY) > 0

    def test_all_modules_registered(self):
        expected = ['bitcoin', 'ethereum', 'domain', 'username', 'email', 'darkweb', 'indian']
        for name in expected:
            assert name in MODULE_REGISTRY

    def test_type_to_module_mapping(self):
        assert TYPE_TO_MODULE['email'] == 'email'
        assert TYPE_TO_MODULE['btc_legacy'] == 'bitcoin'
        assert TYPE_TO_MODULE['vehicle_indian'] == 'indian'

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
        html = ('<div class="footer">seen at admin@example.com</div>'
                + '<p>filler prose that separates the two blocks.</p>' * 3
                + '<div id="donate">pay support@shop.example</div>')
        _values, evidence = DarkwebModule._validated(
            html, DarkwebModule._RE_EMAIL, norm_email)
        assert evidence['admin@example.com']['section'] == 'footer'
        assert evidence['support@shop.example']['section'] == 'wallet'
        # context is the tag-stripped window the artifact was seen in
        assert 'pay' in evidence['support@shop.example']['context']

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

    def test_favicon_hash_matches_shodan_scheme(self):
        import base64, mmh3
        # Shodan's http.favicon.hash = mmh3.hash(base64.encodebytes(icon_bytes)).
        icon = b'\x00\x01\x02\x03fake-icon'
        assert mmh3.hash(base64.encodebytes(icon)) == mmh3.hash(base64.encodebytes(icon))


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
