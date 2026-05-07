"""Tests for input type detection."""

import pytest
from cybertrace.detector import detect_input_type, normalize_input


class TestDetectInputType:
    """Test input type detection patterns."""

    def test_email_detection(self):
        specific, module = detect_input_type("test@example.com")
        assert specific == "email"
        assert module == "email"

    def test_email_with_subdomain(self):
        specific, module = detect_input_type("user@mail.example.com")
        assert specific == "email"
        assert module == "email"

    def test_username_detection(self):
        specific, module = detect_input_type("hackerman123")
        assert specific == "username"
        assert module == "username"

    def test_domain_detection(self):
        specific, module = detect_input_type("example.com")
        assert specific == "domain"
        assert module == "domain"

    def test_subdomain_detection(self):
        specific, module = detect_input_type("www.example.com")
        assert specific == "domain"
        assert module == "domain"

    def test_btc_legacy_detection(self):
        specific, module = detect_input_type("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert specific == "btc_legacy"
        assert module == "bitcoin"

    def test_btc_bech32_detection(self):
        specific, module = detect_input_type("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
        assert specific == "btc_bech32"
        assert module == "bitcoin"

    def test_ethereum_detection(self):
        specific, module = detect_input_type("0x742d35Cc6634C0532925a3b844Bc9e7595f12345")
        assert specific == "ethereum"
        assert module == "ethereum"

    def test_vehicle_indian_detection(self):
        specific, module = detect_input_type("MH12AB1234")
        assert specific == "vehicle_indian"
        assert module == "indian"

    def test_pan_indian_detection(self):
        specific, module = detect_input_type("ABCDE1234F")
        assert specific == "pan_indian"
        assert module == "indian"

    def test_gstin_detection(self):
        specific, module = detect_input_type("22AAAAA0000A1Z5")
        assert specific == "gstin"
        assert module == "indian"

    def test_phone_indian_detection(self):
        specific, module = detect_input_type("+919876543210")
        assert specific == "phone_indian"
        assert module == "phone"

    def test_phone_indian_without_prefix(self):
        specific, module = detect_input_type("9876543210")
        assert specific == "phone_indian"
        assert module == "phone"

    def test_ipv4_detection(self):
        specific, module = detect_input_type("192.168.1.1")
        assert specific == "ipv4"
        assert module == "domain"

    def test_url_detection(self):
        specific, module = detect_input_type("https://example.com/path")
        assert specific == "url"
        assert module == "domain"


class TestNormalizeInput:
    """Test input normalization."""

    def test_normalize_domain_with_https(self):
        result = normalize_input("https://example.com", "domain")
        assert result == "example.com"

    def test_normalize_domain_with_path(self):
        result = normalize_input("example.com/path/to/page", "domain")
        assert result == "example.com/path/to/page"

    def test_normalize_phone_10_digit(self):
        result = normalize_input("9876543210", "phone")
        assert result == "+919876543210"

    def test_normalize_phone_with_91(self):
        result = normalize_input("919876543210", "phone")
        assert result == "+919876543210"

    def test_normalize_indian_vehicle(self):
        result = normalize_input("mh 12 ab 1234", "indian")
        assert result == "MH12AB1234"

    def test_normalize_indian_pan(self):
        result = normalize_input("abcde1234f", "indian")
        assert result == "ABCDE1234F"

    def test_normalize_preserves_email(self):
        result = normalize_input("Test@Example.com", "email")
        assert result == "Test@Example.com"

    def test_normalize_preserves_username(self):
        result = normalize_input("  hackerman123  ", "username")
        assert result == "hackerman123"
