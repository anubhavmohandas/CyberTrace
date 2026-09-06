"""Input type detection using regex patterns."""

import re
from typing import Tuple

PATTERNS = {
    # Coordinates — lat,lon (decimal degrees)
    'coordinates': re.compile(r'^-?\d{1,3}\.\d+\s*,\s*-?\d{1,3}\.\d+$'),

    # Image/file paths
    'image_file': re.compile(r'^.+\.(jpe?g|png|gif|bmp|tiff?|webp|heic|raw|cr2|nef|arw)$', re.IGNORECASE),

    # Email - standard format
    'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    
    # Phone numbers
    'phone_indian': re.compile(r'^(?:\+?91|0)?[6-9]\d{9}$'),
    'phone_intl': re.compile(r'^\+[1-9]\d{6,14}$'),
    
    # Cryptocurrency
    'btc_legacy': re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'),
    'btc_bech32': re.compile(r'^bc1[a-z0-9]{39,59}$'),
    'ethereum': re.compile(r'^0x[a-fA-F0-9]{40}$'),
    'tron': re.compile(r'^T[a-km-zA-HJ-NP-Z1-9]{33}$'),

    # Cryptocurrency on chains CyberTrace has NO collector for. Matched on
    # purpose so they can be REFUSED by name instead of falling through to the
    # `username` catch-all, which handed them to a 3000+ social-site sweep and
    # then reported "no VASP path" -- a false negative that reads to an
    # investigator exactly like a cleared wallet.
    #
    # Measured against the OFAC SDN publication of 2026-08-26: of 1,007 real
    # designated digital-currency addresses, 50 (5.0%) landed in `username`.
    # Every pattern below is anchored to a format a supported chain cannot
    # produce, and all of them are checked AFTER btc/eth/tron so a supported
    # chain always wins.
    'monero': re.compile(r'^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$'),
    'litecoin': re.compile(r'^(?:ltc1[a-z0-9]{39,59}|[LM][a-km-zA-HJ-NP-Z1-9]{26,34})$'),
    'bitcoin_cash': re.compile(r'^(?:bitcoincash:)?[qp][a-z0-9]{41}$'),
    'dogecoin': re.compile(r'^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$'),
    'dash': re.compile(r'^X[1-9A-HJ-NP-Za-km-z]{33}$'),
    'zcash': re.compile(r'^(?:t1[a-km-zA-HJ-NP-Z1-9]{33}|zs1[a-z0-9]{75})$'),
    'ripple': re.compile(r'^r[1-9A-HJ-NP-Za-km-z]{24,34}$'),

    # Solana: CyberTrace HAS a collector for this one (solana_module.py,
    # Loop 38 Section 8) -- checked separately from UNSUPPORTED_CHAINS
    # below, not folded into that dict. Base58 with no distinguishing
    # prefix, so it is pinned to the 43-44 characters an ed25519 pubkey
    # actually encodes to. Narrow on purpose: a shorter base58 string is far
    # more likely to be a username -- a real but unusually short Solana
    # address (many leading zero bytes) falls through to `username` rather
    # than being force-matched here, the same tradeoff norm_sol documents.
    'solana': re.compile(r'^[1-9A-HJ-NP-Za-km-z]{43,44}$'),


    # Domains & URLs
    # Onion — bare host, or the full URL users actually paste (scheme/subdomain/
    # port/path). The subdomain group is what lets www.<addr>.onion reach the
    # darkweb module instead of falling through to the clearnet domain module.
    'onion': re.compile(r'^(?:https?://)?(?:[a-z0-9-]+\.)*[a-z2-7]{16,56}\.onion(?::\d+)?(?:/.*)?$', re.IGNORECASE),
    'domain': re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'),
    'url': re.compile(r'^https?://[^\s]+$'),
    
    # Indian identifiers
    'vehicle_indian': re.compile(r'^[A-Z]{2}[0-9]{1,2}[A-Z]{0,3}[0-9]{4}$', re.IGNORECASE),
    'pan_indian': re.compile(r'^[A-Z]{5}[0-9]{4}[A-Z]$', re.IGNORECASE),
    'gstin': re.compile(r'^\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d][Z][A-Z\d]$', re.IGNORECASE),
    'aadhaar': re.compile(r'^\d{4}\s?\d{4}\s?\d{4}$'),
    
    # Network
    'ipv4': re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'),
    # IPv6: supports full, compressed (::), and mixed notations
    'ipv6': re.compile(
        r'^('
        r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'          # full 8 groups
        r'([0-9a-fA-F]{1,4}:){1,7}:|'                          # trailing ::
        r':([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{0,4}|'         # leading ::
        r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'         # one :: in middle
        r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
        r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
        r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
        r'[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}|'
        r'::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|'  # IPv4-mapped
        r'::1|::'                                                # loopback / unspecified
        r')$'
    ),
}

# Detection priority - checked in order
DETECTION_ORDER = [
    ('coordinates', 'geoint'),
    ('image_file', 'image'),
    ('email', 'email'),
    ('phone_indian', 'phone'),
    ('phone_intl', 'phone'),
    ('btc_bech32', 'bitcoin'),
    ('btc_legacy', 'bitcoin'),
    ('ethereum', 'ethereum'),
    ('tron', 'tron'),
    ('solana', 'solana'),
    # Recognized, and refused by name -- see UNSUPPORTED_CHAINS.
    ('monero', 'unsupported_chain'),
    ('litecoin', 'unsupported_chain'),
    ('bitcoin_cash', 'unsupported_chain'),
    ('dogecoin', 'unsupported_chain'),
    ('dash', 'unsupported_chain'),
    ('zcash', 'unsupported_chain'),
    ('ripple', 'unsupported_chain'),
    ('onion', 'darkweb'),
    ('gstin', 'indian'),
    ('pan_indian', 'indian'),
    ('vehicle_indian', 'indian'),
    ('aadhaar', 'indian'),
    ('ipv4', 'ip'),
    ('ipv6', 'ip'),
    ('url', 'domain'),
    ('domain', 'domain'),
]


# specific_type -> the chain it really is, for the ones nothing here can trace.
# Kept as data rather than prose so a caller can name the chain in a refusal.
# 'solana' is deliberately absent -- solana_module.py gives it a real
# collector (Loop 38 Section 8), so it now routes like btc/eth/tron instead
# of through this refusal path.
UNSUPPORTED_CHAINS = {
    'monero': 'Monero', 'litecoin': 'Litecoin', 'bitcoin_cash': 'Bitcoin Cash',
    'dogecoin': 'Dogecoin', 'dash': 'Dash', 'zcash': 'Zcash',
    'ripple': 'XRP Ledger',
}


def chain_caveat(specific_type: str) -> str:
    """The limitation that must travel with a detection, or '' if there is none.

    Two different failures, one entry point, because every consumer -- module
    dispatch, evidence.label_exchange, correlate.wallet_trace_report -- already
    routes through detect_input_type and each was silently papering over one of
    them:

    unsupported chain   there is no collector, so "no VASP path" would mean
                        "never looked", and the two must not read alike.
    EVM ambiguity       a 0x address is valid on Ethereum, BNB Chain, Polygon,
                        Arbitrum and every other EVM network, and the string
                        cannot say which. The same key controls all of them, so
                        this is not a false ownership claim -- but activity is
                        queried against Ethereum mainnet ONLY, so a BNB or
                        Polygon suspect reports no counterparties and no VASP
                        path, which reads as a cleared wallet.

    Both are real, not hypothetical: OFAC's SDN publication of 2026-08-26 lists
    0x4f47bc496083c727c5fbe3ce9cdf2b0f6496270c under BOTH Arbitrum and BNB
    Chain, and 50 of its 1,007 digital-currency addresses are on chains in
    UNSUPPORTED_CHAINS.
    """
    if specific_type in UNSUPPORTED_CHAINS:
        return (f"{UNSUPPORTED_CHAINS[specific_type]} is not a supported chain: "
                f"CyberTrace has no collector for it, so no transaction, "
                f"counterparty or VASP conclusion can be drawn — this is "
                f"'not looked at', not 'nothing found'.")
    if specific_type == 'ethereum':
        return ("0x addresses are queried against Ethereum mainnet only. The "
                "same address is valid on BNB Chain, Polygon, Arbitrum and "
                "other EVM networks, and activity there is NOT searched by "
                "default — absence of a VASP path is not evidence of "
                "absence. Re-run with --type bnb or --type polygon if you "
                "know which of those two this address is really on "
                "(Arbitrum and other EVM chains are still unsearched either "
                "way).")
    return ""


def btc_address_family(address: str) -> str:
    """Bitcoin address family from its prefix alone -- Legacy/P2SH/Native
    SegWit/Taproot. Format only, same caveat as chain_caveat: this says what
    shape the string is, never whether it has ever been used on-chain (that
    needs a real query -- see BitcoinModule / `cybertrace search`)."""
    a = address.strip().lower()
    if a.startswith('bc1p'):
        return 'Taproot (P2TR)'
    if a.startswith('bc1'):
        return 'Native SegWit (P2WPKH/P2WSH)'
    if a.startswith('3'):
        return 'P2SH (often SegWit-nested)'
    if a.startswith('1'):
        return 'Legacy (P2PKH)'
    return 'unknown'


def detect_input_type(input_str: str) -> Tuple[str, str]:
    """
    Detect the type of input string.
    
    Returns:
        Tuple of (specific_type, module_type)
        e.g., ('btc_legacy', 'bitcoin') or ('email', 'email')
    """
    cleaned = input_str.strip()
    
    # Remove common prefixes for phone detection
    phone_cleaned = re.sub(r'^[\s\-\.\(\)]+', '', cleaned)
    phone_cleaned = re.sub(r'[\s\-\.\(\)]+', '', phone_cleaned)
    
    for pattern_name, module_type in DETECTION_ORDER:
        pattern = PATTERNS[pattern_name]

        # Use startswith instead of 'in' substring check — avoids scanning the
        # full string on every iteration; matters for batch target processing
        test_str = phone_cleaned if pattern_name.startswith('phone') else cleaned

        if pattern.match(test_str):
            return (pattern_name, module_type)
    
    # Default: treat as username
    return ('username', 'username')


def normalize_input(input_str: str, input_type: str) -> str:
    """Normalize input based on detected type."""
    cleaned = input_str.strip()
    
    if input_type == 'phone':
        # Remove formatting, ensure proper prefix
        digits = re.sub(r'[^\d+]', '', cleaned)
        if digits.startswith('91') and len(digits) == 12:
            return '+' + digits
        if digits.startswith('0') and len(digits) == 11:
            return '+91' + digits[1:]
        if len(digits) == 10 and digits[0] in '6789':
            return '+91' + digits
        if not digits.startswith('+'):
            return '+' + digits
        return digits
    
    if input_type == 'darkweb':
        # Bare onion host — drop scheme, port and path so evidence artifacts
        # from a pasted URL match those from a bare address.
        host = re.sub(r'^https?://', '', cleaned, flags=re.IGNORECASE).split('/')[0]
        host = host.split(':')[0].lower()
        # Subdomain labels are vhost routing, not identity — the Tor circuit is
        # built to the .onion address itself — so www.<addr>.onion and the bare
        # <addr>.onion are the same target and must normalize to one key.
        return '.'.join(host.split('.')[-2:])

    if input_type == 'domain':
        # Remove protocol if present
        cleaned = re.sub(r'^https?://', '', cleaned)
        cleaned = cleaned.rstrip('/')
        return cleaned.lower()
    
    if input_type in ('indian',):
        # Uppercase for Indian identifiers
        return cleaned.upper().replace(' ', '').replace('-', '')
    
    return cleaned


if __name__ == '__main__':
    v3 = 'a' * 56 + '.onion'
    for form in (v3, f'http://{v3}', f'https://{v3}/market/vendor', f'HTTP://{v3.upper()}:8080',
                 f'www.{v3}', f'https://www.{v3}/', f'HTTPS://WWW.{v3.upper()}',
                 f'mail.sub.{v3}:8080/inbox'):
        assert detect_input_type(form) == ('onion', 'darkweb'), form
        assert normalize_input(form, 'darkweb') == v3, form
    assert detect_input_type('https://example.com/path') == ('url', 'domain')
    assert detect_input_type('www.example.com') == ('domain', 'domain')
    # Too short to be a real onion address — must stay off the darkweb path.
    assert detect_input_type('facebook.onion') == ('domain', 'domain')
    # Real TRON mainnet address (the USDT-TRC20 contract) — a genuine base58
    # string, not one shaped to merely satisfy the regex.
    assert detect_input_type('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t') == ('tron', 'tron')

    # Quick test
    tests = [
        'test@example.com',
        '+919876543210',
        '9876543210',
        '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
        '0x742d35Cc6634C0532925a3b844Bc9e7595f',
        'example.com',
        'MH12AB1234',
        'ABCDE1234F',
        'hackerman123',
        'abc123def456.onion',
    ]
    
    for t in tests:
        specific, module = detect_input_type(t)
        print(f'{t:50} -> {specific:15} ({module})')
