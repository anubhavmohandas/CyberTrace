"""Module registry - exports all OSINT modules."""

from typing import Dict, Optional, Type

from .base import BaseModule
from .bitcoin_module import BitcoinModule
from .domain_module import DomainModule
from .username_module import UsernameModule
from .email_module import EmailModule
from .darkweb_module import DarkwebModule
from .indian_module import IndianModule
from .phone_module import PhoneModule
from .ip_module import IPModule
from .image_module import ImageModule
from .breach_module import BreachModule
from .geoint_module import GeointModule
from .social_module import SocialModule


# Registry of all available modules
MODULE_REGISTRY: Dict[str, Type[BaseModule]] = {
    'bitcoin': BitcoinModule,
    'ethereum': BitcoinModule,   # Same module handles both
    'domain': DomainModule,
    'username': UsernameModule,
    'email': EmailModule,
    'darkweb': DarkwebModule,
    'indian': IndianModule,
    'phone': PhoneModule,
    'ip': IPModule,
    'image': ImageModule,
    'breach': BreachModule,
    'geoint': GeointModule,
    'social': SocialModule,
}

# Input type to module mapping
TYPE_TO_MODULE: Dict[str, str] = {
    # Email
    'email': 'email',
    # Phone
    'phone': 'phone',
    'phone_indian': 'phone',
    'phone_intl': 'phone',
    # Identity / Social
    'username': 'username',
    'name': 'social',
    # Domain / URL
    'domain': 'domain',
    'url': 'domain',
    # IP
    'ipv4': 'ip',
    'ipv6': 'ip',
    # Crypto
    'bitcoin': 'bitcoin',
    'btc_legacy': 'bitcoin',
    'btc_bech32': 'bitcoin',
    'ethereum': 'ethereum',
    # Dark Web
    'onion': 'darkweb',
    'darkweb': 'darkweb',
    # Indian identifiers
    'vehicle_indian': 'indian',
    'pan_indian': 'indian',
    'gstin': 'indian',
    'aadhaar': 'indian',
    # New modules
    'image': 'image',
    'file': 'image',
    'coordinates': 'geoint',
    'address': 'geoint',
    'breach': 'breach',
    'social': 'social',
}


def get_module(input_type: str) -> Optional[BaseModule]:
    """
    Get appropriate module instance for input type.
    
    Args:
        input_type: The detected input type (from detector)
        
    Returns:
        Instantiated module or None if not supported
    """
    module_name = TYPE_TO_MODULE.get(input_type, input_type)
    module_class = MODULE_REGISTRY.get(module_name)
    
    if module_class:
        return module_class()
    
    return None


def get_all_modules() -> Dict[str, BaseModule]:
    """Get instances of all available modules."""
    return {name: cls() for name, cls in MODULE_REGISTRY.items()}


def list_modules() -> Dict[str, str]:
    """List all modules with descriptions."""
    return {
        name: cls.description
        for name, cls in MODULE_REGISTRY.items()
    }


__all__ = [
    'BaseModule',
    'BitcoinModule',
    'DomainModule',
    'UsernameModule',
    'EmailModule',
    'DarkwebModule',
    'IndianModule',
    'PhoneModule',
    'IPModule',
    'ImageModule',
    'BreachModule',
    'GeointModule',
    'SocialModule',
    'get_module',
    'get_all_modules',
    'list_modules',
    'MODULE_REGISTRY',
    'TYPE_TO_MODULE',
]
