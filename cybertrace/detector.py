"""Input type detection using regex patterns."""

import re
from typing import Tuple

PATTERNS = {
    # Email - standard format
    'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    
    # Phone numbers
    'phone_indian': re.compile(r'^(?:\+?91|0)?[6-9]\d{9}$'),
    'phone_intl': re.compile(r'^\+[1-9]\d{6,14}$'),
    
    # Cryptocurrency
    'btc_legacy': re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'),
    'btc_bech32': re.compile(r'^bc1[a-z0-9]{39,59}$'),
    'ethereum': re.compile(r'^0x[a-fA-F0-9]{40}$'),
    
    # Domains & URLs
    'onion': re.compile(r'^[a-z2-7]{16,56}\.onion$'),
    'domain': re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'),
    'url': re.compile(r'^https?://[^\s]+$'),
    
    # Indian identifiers
    'vehicle_indian': re.compile(r'^[A-Z]{2}[0-9]{1,2}[A-Z]{0,3}[0-9]{4}$', re.IGNORECASE),
    'pan_indian': re.compile(r'^[A-Z]{5}[0-9]{4}[A-Z]$', re.IGNORECASE),
    'gstin': re.compile(r'^\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d][Z][A-Z\d]$', re.IGNORECASE),
    'aadhaar': re.compile(r'^\d{4}\s?\d{4}\s?\d{4}$'),
    
    # Network
    'ipv4': re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'),
    'ipv6': re.compile(r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'),
}

# Detection priority - checked in order
DETECTION_ORDER = [
    ('email', 'email'),
    ('phone_indian', 'phone'),
    ('phone_intl', 'phone'),
    ('btc_bech32', 'bitcoin'),
    ('btc_legacy', 'bitcoin'),
    ('ethereum', 'ethereum'),
    ('onion', 'darkweb'),
    ('gstin', 'indian'),
    ('pan_indian', 'indian'),
    ('vehicle_indian', 'indian'),
    ('aadhaar', 'indian'),
    ('ipv4', 'domain'),
    ('ipv6', 'domain'),
    ('url', 'domain'),
    ('domain', 'domain'),
]


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
        
        # Use phone-cleaned version for phone patterns
        test_str = phone_cleaned if 'phone' in pattern_name else cleaned
        
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
