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


# --- unsupported-chain boundary --------------------------------------
#
# Every address here is real and publicly checkable. The non-Bitcoin ones are
# taken from OFAC's SDN publication of 2026-08-26, where 50 of 1,007 designated
# digital-currency addresses fell through this detector into `username` and were
# handed to a 3000+ social-site sweep — after which "no VASP path" read to an
# investigator exactly like a cleared wallet.


from cybertrace.detector import UNSUPPORTED_CHAINS, chain_caveat

# (address, expected specific_type, what it really is)
REAL_UNSUPPORTED = [
    ("44dZUJ7w1T3fKAvFW8XyXUVoAGSbFvXef2wcbnsjNKGWYo6ZgLwSCJvfeFRHWLnKQMcVUwWLZLQHQvXbNjMWfjXm1LKgWFN",
     "monero", "OFAC SDN, ISIL Khorasan"),
    # Solana is deliberately ABSENT here (Loop 38 Section 8): solana_module.py
    # gives it a real collector now, so it moved to
    # test_supported_chains_still_win_over_the_new_patterns below instead of
    # this refusal-path list.
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
    """The unsupported tier is checked after btc/eth/tron/solana on purpose:
    a base58 Bitcoin address must never be captured by the Litecoin pattern,
    and a real Solana address (its own base58 shape, no distinguishing
    prefix) must resolve to 'solana', not fall into the Litecoin/Dash/Ripple
    patterns checked right after it in DETECTION_ORDER."""
    for address, expected in (
            ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc_legacy"),
            ("34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo", "btc_legacy"),
            ("bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h", "btc_bech32"),
            ("0xdAC17F958D2ee523a2206206994597C13D831ec7", "ethereum"),
            ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "tron"),
            ("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "solana"),  # real USDC mint
    ):
        assert detect_input_type(address)[0] == expected, address


def test_solana_routes_to_its_own_module_type():
    """Solana is a supported chain now (Loop 38 Section 8), not a refusal --
    module_type must be 'solana', matching MODULE_REGISTRY['solana']."""
    assert detect_input_type(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v") == ("solana", "solana")
    # 'solana' must NOT appear in UNSUPPORTED_CHAINS any more.
    assert "solana" not in UNSUPPORTED_CHAINS
    assert chain_caveat("solana") == ""


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


# Loop 58: a string can be the right length and prefix for a Base58Check
# chain and still not be a real address -- either it uses a character
# outside Base58 (0/O/I/l), or it uses the right alphabet with the wrong
# checksum bytes. Neither must be swept into the username/social path just
# because they fail the strict pattern, and a dataset/benchmark row *labeling*
# one of these a wallet does not make it one -- this is the exact string from
# the Kaggle corpus that motivated the fix.
_KAGGLE_INVALID_BTC = "19e6aqs6ru2ei5r3cuzcfmcklq78uksmry"


def test_shape_only_match_is_named_invalid_not_swept_to_username():
    from cybertrace.detector import checksum_valid

    specific, module = detect_input_type(_KAGGLE_INVALID_BTC)
    assert (specific, module) == ("btc_legacy_shape", "invalid_address")
    caveat = chain_caveat(specific, _KAGGLE_INVALID_BTC)
    assert "Not a valid Bitcoin address" in caveat
    assert "0, O, I, l" in caveat
    # checksum_valid is format-agnostic: a shape-only match was never a real
    # base58 string to begin with, so there's nothing to decode.
    assert checksum_valid(specific, _KAGGLE_INVALID_BTC) is True

    specific_t, module_t = detect_input_type("T" + "1" * 32 + "l")
    assert (specific_t, module_t) == ("tron_shape", "invalid_address")
    assert "Not a valid TRON address" in chain_caveat(specific_t, "T" + "1" * 32 + "l")


def test_real_addresses_never_match_the_shape_only_patterns():
    """The shape patterns are checked strictly after the real ones in
    DETECTION_ORDER -- a genuine address must always win first."""
    assert detect_input_type("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == ("btc_legacy", "bitcoin")
    assert detect_input_type("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t") == ("tron", "tron")


def test_checksum_valid_catches_a_wrong_checksum_with_a_real_alphabet():
    """Same format detect_input_type accepts, wrong checksum bytes -- the
    regex alone cannot see this; only real Base58Check (normalize.norm_btc/
    norm_tron) can. This is the gap format-only detection cannot close."""
    from cybertrace.detector import checksum_valid

    real_btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    bad_checksum_btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
    assert detect_input_type(bad_checksum_btc) == ("btc_legacy", "bitcoin")  # regex still matches
    assert checksum_valid("btc_legacy", real_btc) is True
    assert checksum_valid("btc_legacy", bad_checksum_btc) is False
    assert chain_caveat("btc_legacy", real_btc) == ""
    caveat = chain_caveat("btc_legacy", bad_checksum_btc)
    assert "fails checksum" in caveat

    real_tron = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    bad_checksum_tron = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6s"
    assert checksum_valid("tron", real_tron) is True
    assert checksum_valid("tron", bad_checksum_tron) is False
    assert "fails checksum" in chain_caveat("tron", bad_checksum_tron)


def test_checksum_valid_is_always_true_without_a_real_checksum_scheme():
    """EVM/Solana have no stronger check than the regex today (documented,
    deliberate -- see normalize.py) -- checksum_valid must not invent one."""
    from cybertrace.detector import checksum_valid

    assert checksum_valid("ethereum", "0x0000000000000000000000000000000000000000") is True
    assert checksum_valid("solana", "not-even-base58-shaped") is True
    assert checksum_valid("username", "hackerman123") is True


def test_chain_caveat_without_a_value_skips_the_checksum_check():
    """`value` is optional -- a caller only asking about format (no address on
    hand) gets no checksum verdict, not a crash or a false negative."""
    assert chain_caveat("btc_legacy") == ""
