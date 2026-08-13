"""Configuration management for CyberTrace."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any
from dotenv import load_dotenv

from cybertrace.api_key_registry import APIKeys, API_KEYS  # noqa: F401

# Load .env from project root
load_dotenv()


@dataclass
class TorConfig:
    """Tor proxy configuration."""
    enabled: bool = False
    socks_host: str = '127.0.0.1'
    socks_port: int = 9050
    control_port: int = 9051
    password: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> 'TorConfig':
        return cls(
            enabled=os.getenv('TOR_ENABLED', 'false').lower() == 'true',
            socks_host=os.getenv('TOR_SOCKS_HOST', '127.0.0.1'),
            socks_port=int(os.getenv('TOR_SOCKS_PORT', '9050')),
            control_port=int(os.getenv('TOR_CONTROL_PORT', '9051')),
            password=os.getenv('TOR_PASSWORD'),
        )
    
    @property
    def proxy_url(self) -> str:
        return f'socks5h://{self.socks_host}:{self.socks_port}'
    
    @property
    def proxies(self) -> Dict[str, str]:
        return {
            'http': self.proxy_url,
            'https': self.proxy_url,
        }


@dataclass
class Config:
    """Main configuration class."""
    api_keys: APIKeys = field(default_factory=APIKeys.from_env)
    tor: TorConfig = field(default_factory=TorConfig.from_env)
    
    # Paths
    data_dir: Path = field(default_factory=lambda: Path('./data'))
    cache_dir: Path = field(default_factory=lambda: Path('./data/cache'))
    
    # Settings
    cache_ttl_hours: int = 24
    request_timeout: int = 30
    # Budget for external CLI tools (maigret/sherlock/holehe). Maigret sweeps
    # 3000+ sites; under ~120s it returns only a fraction of them.
    tool_timeout: int = 300
    max_concurrent: int = 10
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    def __post_init__(self):
        # Create directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def load(cls) -> 'Config':
        """Load configuration from environment."""
        return cls(
            api_keys=APIKeys.from_env(),
            tor=TorConfig.from_env(),
            cache_ttl_hours=int(os.getenv('CACHE_TTL_HOURS', '24')),
            request_timeout=int(os.getenv('REQUEST_TIMEOUT', '30')),
            tool_timeout=int(os.getenv('TOOL_TIMEOUT', '300')),
            max_concurrent=int(os.getenv('MAX_CONCURRENT', '10')),
        )
    
    def print_status(self):
        """Print configuration status."""
        self.api_keys.print_status()
        print(f"  Tor:     {'Enabled' if self.tor.enabled else 'Disabled'}")
        print(f"  Cache:   {self.cache_ttl_hours}h TTL")
        print(f"  Timeout: {self.request_timeout}s\n")


# Global config instance
config = Config.load()
