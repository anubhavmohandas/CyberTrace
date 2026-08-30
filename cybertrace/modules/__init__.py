"""Module registry - exports all OSINT modules."""

from typing import Dict, Optional, Tuple, Type

from ..detector import detect_input_type, normalize_input
from .base import BaseModule
from .bitcoin_module import BitcoinModule
from .tron_module import TronModule
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
    # Only reachable via an explicit --type bnb/--type polygon override -- a
    # bare 0x address auto-detects 'ethereum' by construction (detect_input_
    # type cannot tell the three EVM chains apart from the string alone; see
    # detector.chain_caveat). Same BitcoinModule, which reads target_type off
    # its own search() options to pick the right explorer -- see that
    # method's docstring.
    'bnb': BitcoinModule,
    'polygon': BitcoinModule,
    'tron': TronModule,
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
    'bnb': 'bnb',
    'polygon': 'polygon',
    'tron': 'tron',
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


def resolve_module_for_target(
    target: str, input_type: str = 'auto'
) -> Tuple[Optional[BaseModule], str, str, str]:
    """Detect/normalize TARGET and resolve the module that should search it.

    Shared by the CLI `search` command and the API's /api/search endpoint so
    the type-detection and multi-shape-module remap logic (see
    test_cli_target_type.py) lives in exactly one place.

    Returns (module, normalized_target, specific_type, module_type). module
    is None if module_type has no registered module.
    """
    if input_type == 'auto':
        specific_type, module_type = detect_input_type(target)
    else:
        module_type = input_type
        specific_type = input_type

    normalized = normalize_input(target, module_type)
    module = get_module(module_type)

    # A module may accept several target shapes (breach, social); an explicit
    # `--type breach` names the MODULE, not one of its own shapes, so it is
    # never a member of module.supported_types. Detect what the STRING
    # actually looks like and use that category instead, or every multi-shape
    # module's options.get('target_type', <default>) silently takes the wrong
    # branch (breach defaulted every `--type breach` search to 'email'). A
    # module whose override already names one of its own shapes (geoint's
    # `--type address`/`--type coordinates`) is left untouched — geoint has no
    # detector pattern for free-text addresses, so re-detecting would replace
    # a valid override with the 'username' fallback.
    if module is not None and specific_type not in getattr(module, 'supported_types', ()):
        _, detected_category = detect_input_type(target)
        if detected_category in getattr(module, 'supported_types', ()):
            specific_type = detected_category

    return module, normalized, specific_type, module_type


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
    'TronModule',
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
    'resolve_module_for_target',
    'get_all_modules',
    'list_modules',
    'MODULE_REGISTRY',
    'TYPE_TO_MODULE',
]
