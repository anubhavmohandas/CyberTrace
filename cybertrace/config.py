"""Configuration management for CyberTrace."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# Load .env from project root
load_dotenv()


@dataclass
class APIKeys:
    """API key storage."""
    virustotal: Optional[str] = None
    shodan: Optional[str] = None
    urlscan: Optional[str] = None
    github: Optional[str] = None
    emailrep: Optional[str] = None
    intelx: Optional[str] = None
    hunter: Optional[str] = None
    numverify: Optional[str] = None
    twilio_sid: Optional[str] = None
    twilio_token: Optional[str] = None
    dehashed: Optional[str] = None
    telegram_bot: Optional[str] = None
    twocaptcha: Optional[str] = None
    etherscan: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> 'APIKeys':
        return cls(
            virustotal=os.getenv('VIRUSTOTAL_API_KEY'),
            shodan=os.getenv('SHODAN_API_KEY'),
            urlscan=os.getenv('URLSCAN_API_KEY'),
            github=os.getenv('GITHUB_TOKEN'),
            emailrep=os.getenv('EMAILREP_API_KEY'),
            intelx=os.getenv('INTELX_API_KEY'),
            hunter=os.getenv('HUNTER_API_KEY'),
            numverify=os.getenv('NUMVERIFY_API_KEY'),
            twilio_sid=os.getenv('TWILIO_SID'),
            twilio_token=os.getenv('TWILIO_TOKEN'),
            dehashed=os.getenv('DEHASHED_API_KEY'),
            telegram_bot=os.getenv('TELEGRAM_BOT_TOKEN'),
            twocaptcha=os.getenv('TWOCAPTCHA_API_KEY'),
            etherscan=os.getenv('ETHERSCAN_API_KEY'),
        )
    
    def get(self, key: str) -> Optional[str]:
        return getattr(self, key, None)
    
    def has(self, key: str) -> bool:
        val = self.get(key)
        return val is not None and val.strip() != ''
    
    def status(self) -> Dict[str, bool]:
        """Return status of all API keys."""
        return {
            name: self.has(name)
            for name in self.__dataclass_fields__.keys()
        }


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
            max_concurrent=int(os.getenv('MAX_CONCURRENT', '10')),
        )
    
    def print_status(self):
        """Print configuration status."""
        print("\n=== CyberTrace Configuration ===\n")
        
        print("API Keys:")
        for name, available in self.api_keys.status().items():
            icon = "✓" if available else "✗"
            print(f"  [{icon}] {name}")
        
        print(f"\nTor: {'Enabled' if self.tor.enabled else 'Disabled'}")
        print(f"Cache TTL: {self.cache_ttl_hours}h")
        print(f"Timeout: {self.request_timeout}s")


# Global config instance
config = Config.load()
