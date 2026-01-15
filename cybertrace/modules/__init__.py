"""Module registry - exports all OSINT modules."""

from typing import Dict, Optional, Type

from .base import BaseModule
from .bitcoin_module import BitcoinModule
from .domain_module import DomainModule
from .username_module import UsernameModule
from .email_module import EmailModule
from .darkweb_module import DarkwebModule
from .indian_module import IndianModule


# Registry of all available modules
MODULE_REGISTRY: Dict[str, Type[BaseModule]] = {
    'bitcoin': BitcoinModule,
    'ethereum': BitcoinModule,  # Same module handles both
    'domain': DomainModule,
    'username': UsernameModule,
    'email': EmailModule,
    'darkweb': DarkwebModule,
    'indian': IndianModule,
}

# Input type to module mapping
TYPE_TO_MODULE: Dict[str, str] = {
    'email': 'email',
    'phone': 'phone',  # TODO: implement phone module
    'phone_indian': 'phone',
    'phone_intl': 'phone',
    'username': 'username',
    'domain': 'domain',
    'url': 'domain',
    'ipv4': 'domain',
    'ipv6': 'domain',
    'bitcoin': 'bitcoin',
    'btc_legacy': 'bitcoin',
    'btc_bech32': 'bitcoin',
    'ethereum': 'ethereum',
    'onion': 'darkweb',
    'vehicle_indian': 'indian',
    'pan_indian': 'indian',
    'gstin': 'indian',
    'aadhaar': 'indian',
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
    'get_module',
    'get_all_modules',
    'list_modules',
    'MODULE_REGISTRY',
    'TYPE_TO_MODULE',
]
