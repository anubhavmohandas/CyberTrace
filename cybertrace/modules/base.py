"""Base module class for all OSINT modules."""

import asyncio
import aiohttp
import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

from ..config import config


@dataclass
class SourceResult:
    """Result from a single source."""
    source: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict:
        return {
            'source': self.source,
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'timestamp': self.timestamp.isoformat(),
        }


@dataclass
class ModuleResult:
    """Aggregated result from a module."""
    target: str
    target_type: str
    module: str
    sources: Dict[str, SourceResult] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    related: List[str] = field(default_factory=list)  # Related targets to investigate
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    
    @property
    def success_count(self) -> int:
        return sum(1 for s in self.sources.values() if s.success)
    
    @property
    def total_count(self) -> int:
        return len(self.sources)
    
    @property
    def duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    def to_dict(self) -> dict:
        return {
            'target': self.target,
            'target_type': self.target_type,
            'module': self.module,
            'sources': {k: v.to_dict() for k, v in self.sources.items()},
            'summary': self.summary,
            'related': self.related,
            'stats': {
                'success': self.success_count,
                'total': self.total_count,
                'duration_sec': self.duration,
            }
        }


class BaseModule(ABC):
    """Base class for all OSINT modules."""
    
    name: str = "base"
    description: str = "Base module"
    supported_types: Set[str] = set()
    
    def __init__(self):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        await self._create_session()
        return self
    
    async def __aexit__(self, *args):
        await self._close_session()
    
    async def _create_session(self):
        """Create aiohttp session with default settings."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': self.config.user_agent},
            )
    
    async def _close_session(self):
        """Close aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    @property
    def session(self) -> aiohttp.ClientSession:
        """Get current session (must be in async context)."""
        if self._session is None:
            raise RuntimeError("Session not initialized. Use 'async with' context.")
        return self._session
    
    @abstractmethod
    async def search(self, target: str, **options) -> ModuleResult:
        """
        Run the search. Must be implemented by subclasses.
        
        Args:
            target: The search target (normalized)
            **options: Module-specific options
            
        Returns:
            ModuleResult with all findings
        """
        pass
    
    def can_handle(self, input_type: str) -> bool:
        """Check if this module can handle the input type."""
        return input_type in self.supported_types
    
    # HTTP utilities
    
    async def fetch(
        self,
        url: str,
        method: str = 'GET',
        **kwargs
    ) -> Optional[str]:
        """
        Fetch URL and return text content.
        
        Returns None on error (doesn't raise).
        """
        try:
            async with self.session.request(method, url, **kwargs) as resp:
                if resp.status == 200:
                    return await resp.text()
                return None
        except Exception:
            return None
    
    async def fetch_json(
        self,
        url: str,
        method: str = 'GET',
        **kwargs
    ) -> Optional[dict]:
        """
        Fetch URL and parse JSON response.
        
        Returns None on error (doesn't raise).
        """
        try:
            async with self.session.request(method, url, **kwargs) as resp:
                if resp.status == 200:
                    return await resp.json()
                return None
        except Exception:
            return None
    
    async def check_exists(self, url: str, **kwargs) -> bool:
        """Check if a URL returns 200 OK."""
        try:
            async with self.session.head(url, allow_redirects=True, **kwargs) as resp:
                return resp.status == 200
        except Exception:
            return False
    
    # Utility methods
    
    @staticmethod
    def md5(text: str) -> str:
        """Get MD5 hash of text."""
        return hashlib.md5(text.encode().lower()).hexdigest()
    
    @staticmethod
    def sha256(text: str) -> str:
        """Get SHA256 hash of text."""
        return hashlib.sha256(text.encode()).hexdigest()
    
    async def run_sources(
        self,
        sources: List[tuple],  # List of (name, coroutine)
        result: ModuleResult,
    ) -> None:
        """
        Run multiple source coroutines concurrently and add to result.
        
        Args:
            sources: List of (source_name, coroutine) tuples
            result: ModuleResult to update
        """
        if not sources:
            return
        
        # Run all sources concurrently
        tasks = [coro for _, coro in sources]
        names = [name for name, _ in sources]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for name, res in zip(names, results):
            if isinstance(res, Exception):
                result.sources[name] = SourceResult(
                    source=name,
                    success=False,
                    error=str(res),
                )
            elif isinstance(res, SourceResult):
                result.sources[name] = res
            elif isinstance(res, dict):
                result.sources[name] = SourceResult(
                    source=name,
                    success=bool(res),
                    data=res,
                )
            else:
                result.sources[name] = SourceResult(
                    source=name,
                    success=False,
                    error="Invalid return type",
                )
