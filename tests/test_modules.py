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
