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
        # IPs route to the dedicated ip module (geo/ASN/abuse/Shodan), not domain.
        specific, module = detect_input_type("192.168.1.1")
        assert specific == "ipv4"
        assert module == "ip"

    def test_ipv6_detection(self):
        specific, module = detect_input_type("2001:4860:4860::8888")
        assert specific == "ipv6"
        assert module == "ip"

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


# --- Loop 12: unsupported-chain boundary --------------------------------------
#
# Every address here is real and publicly checkable. The non-Bitcoin ones are
# taken from OFAC's SDN publication of 2026-08-26, where 50 of 1,007 designated
# digital-currency addresses fell through this detector into `username` and were
# handed to a 3000+ social-site sweep — after which "no VASP path" read to an
# investigator exactly like a cleared wallet.

import pytest

from cybertrace.detector import UNSUPPORTED_CHAINS, chain_caveat, detect_input_type

# (address, expected specific_type, what it really is)
REAL_UNSUPPORTED = [
    ("44dZUJ7w1T3fKAvFW8XyXUVoAGSbFvXef2wcbnsjNKGWYo6ZgLwSCJvfeFRHWLnKQMcVUwWLZLQHQvXbNjMWfjXm1LKgWFN",
     "monero", "OFAC SDN, ISIL Khorasan"),
    ("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "solana", "Solana USDC mint"),
    ("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L", "dogecoin", "Dogecoin"),
    ("ltc1qsl9wyhaqfnq7d0zdgdqf6dcv3drxvtq6c0hnvz", "litecoin", "Litecoin bech32"),
    ("XnQFhFYFhqRHDF8dnPZg1oGKvNhpVUgWZP", "dash", "Dash"),
]


@pytest.mark.parametrize("address,expected,what", REAL_UNSUPPORTED)
def test_unsupported_chain_addresses_are_named_not_swept_as_usernames(address, expected, what):
    specific, module = detect_input_type(address)
    assert (specific, module) == (expected, "unsupported_chain"), what
    # The refusal has to say which chain, or it is just a different silence.
    caveat = chain_caveat(specific)
    assert UNSUPPORTED_CHAINS[specific] in caveat
    assert "not looked at" in caveat and "nothing found" in caveat


def test_supported_chains_still_win_over_the_new_patterns():
    """The unsupported tier is checked after btc/eth/tron on purpose: a base58
    Bitcoin address must never be captured by the Solana or Litecoin pattern."""
    for address, expected in (
            ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc_legacy"),
            ("34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo", "btc_legacy"),
            ("bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h", "btc_bech32"),
            ("0xdAC17F958D2ee523a2206206994597C13D831ec7", "ethereum"),
            ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "tron"),
    ):
        assert detect_input_type(address)[0] == expected, address


def test_ordinary_usernames_are_not_captured_as_crypto_addresses():
    """The cost of the new tier must not be paid by the username path."""
    # "j.doe" is deliberately absent: it has matched `domain` since long
    # before this tier existed (".doe" is TLD-shaped), which is a different
    # question from the one this test asks.
    for name in ("hackerman123", "torvalds", "admin", "Xavier",
                 "DreadPirateRoberts", "rmilburn", "Lolita_fan"):
        assert detect_input_type(name) == ("username", "username"), name


def test_an_evm_address_carries_the_single_chain_caveat():
    """0x is valid on every EVM network and CyberTrace queries Ethereum mainnet
    only. OFAC lists 0x4f47bc49… under BOTH Arbitrum and BNB Chain, so this is
    a measured gap, not a hypothetical one. Not a refusal — Ethereum IS
    supported — but the limitation has to travel with the answer."""
    specific, module = detect_input_type("0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c")
    assert (specific, module) == ("ethereum", "ethereum")
    caveat = chain_caveat(specific)
    assert "Ethereum mainnet only" in caveat
    assert "absence of a VASP path is not evidence of absence" in caveat


def test_a_supported_chain_carries_no_caveat():
    assert chain_caveat("btc_legacy") == ""
    assert chain_caveat("tron") == ""
