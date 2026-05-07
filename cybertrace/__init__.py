"""
CyberTrace - Multi-Layer OSINT Investigation Tool

Search across Surface Web, Deep Web, and Dark Web simultaneously
to build comprehensive profiles from minimal input.
"""

__version__ = "1.0.0"
__author__ = "Anubhav Mohandas"

from .cli import main
from .detector import detect_input_type, normalize_input
from .config import config
from .modules import get_module, list_modules

__all__ = [
    'main',
    'detect_input_type',
    'normalize_input',
    'config',
    'get_module',
    'list_modules',
]
