"""Utility functions for CyberTrace."""

import re
import socket
from typing import Optional
from urllib.parse import urlparse


def is_valid_email(email: str) -> bool:
    """Check if string is a valid email address."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def is_valid_domain(domain: str) -> bool:
    """Check if string is a valid domain name."""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc.lower()
        # Try parsing without scheme
        if '/' in url:
            return url.split('/')[0].lower()
        return url.lower()
    except Exception:
        return None


def sanitize_filename(name: str) -> str:
    """Sanitize string for use as filename."""
    # Remove or replace unsafe characters
    safe = re.sub(r'[^\w\-_\.]', '_', name)
    # Remove multiple underscores
    safe = re.sub(r'_+', '_', safe)
    return safe[:255]  # Max filename length


def truncate(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """Truncate text to max length with suffix."""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def format_bytes(num_bytes: int) -> str:
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def mask_sensitive(text: str, visible_chars: int = 4) -> str:
    """Mask sensitive data, keeping only first/last few chars visible."""
    if len(text) <= visible_chars * 2:
        return '*' * len(text)
    return text[:visible_chars] + '*' * (len(text) - visible_chars * 2) + text[-visible_chars:]


__all__ = [
    'is_valid_email',
    'is_valid_domain',
    'is_valid_ipv4',
    'extract_domain',
    'sanitize_filename',
    'truncate',
    'format_bytes',
    'mask_sensitive',
]
