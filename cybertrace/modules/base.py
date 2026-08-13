"""Base module class for all OSINT modules."""

import asyncio
import aiohttp
import hashlib
import json
import logging
import shutil
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from pathlib import Path
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

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
        self._session: Optional[aiohttp.ClientSession] = None      # direct / clearnet
        self._tor_session: Optional[aiohttp.ClientSession] = None  # via Tor SOCKS5
        self._tor_lock = asyncio.Lock()

    async def __aenter__(self):
        await self._create_session()
        return self

    async def __aexit__(self, *args):
        await self._close_session()

    def _build_connector(self, tor: bool) -> aiohttp.TCPConnector:
        """
        Build an aiohttp connector. Must be called from a running event loop.

        CVE-2026-34525 (CWE-20): aiohttp <3.13.4 improperly validates URLs,
        allowing malformed user-supplied IPs/domains to trigger unexpected
        behaviour. Version bump is the primary fix; connector limits add
        defence-in-depth by capping connections to malformed targets.
        CVE-2026-47265 (CWE-346): aiohttp <3.14.0 fails to validate redirect
        origins. Primary fix is the version bump; redirects are also disabled
        per-request in fetch/fetch_json (allow_redirects is a request kwarg,
        not a ClientSession one). Both connectors below carry the same limits
        and ssl=True so the defence-in-depth is identical on either path.
        """
        if tor:
            # Route via Tor's SOCKS5 proxy. rdns=True forces DNS resolution at
            # the proxy (what socks5h means) — mandatory, since .onion addresses
            # cannot be resolved locally. aiohttp has no native SOCKS support,
            # so aiohttp_socks supplies a TCPConnector subclass.
            try:
                from aiohttp_socks import ProxyConnector, ProxyType
            except ImportError as e:
                raise RuntimeError(
                    "A .onion fetch (or TOR_ENABLED=true) needs aiohttp_socks, "
                    "which is not installed. Run: pip install aiohttp_socks"
                ) from e
            return ProxyConnector(
                proxy_type=ProxyType.SOCKS5,
                host=self.config.tor.socks_host,
                port=self.config.tor.socks_port,
                rdns=True,
                limit=10,
                limit_per_host=5,
                ssl=True,
            )
        return aiohttp.TCPConnector(limit=10, limit_per_host=5, ssl=True)

    def _new_session(self, tor: bool) -> aiohttp.ClientSession:
        return aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.request_timeout),
            connector=self._build_connector(tor=tor),
            connector_owner=True,
        )

    async def _create_session(self):
        """Create the direct (clearnet) session; also the Tor session if
        anonymise-all is on, so the sync `session` property can return it."""
        if self._session is None or self._session.closed:
            self._session = self._new_session(tor=False)
        if self.config.tor.enabled:
            await self._get_tor_session()

    async def _get_tor_session(self) -> aiohttp.ClientSession:
        """Lazily create the shared Tor SOCKS5 session (built on first .onion
        fetch). Lock-guarded so concurrent gather() calls build it only once."""
        if self._tor_session is None or self._tor_session.closed:
            async with self._tor_lock:
                if self._tor_session is None or self._tor_session.closed:
                    self._tor_session = self._new_session(tor=True)
        return self._tor_session

    @staticmethod
    def _is_onion(url: str) -> bool:
        host = urlsplit(url).hostname or ''
        return host.lower().endswith('.onion')

    async def _session_for(self, url: str) -> aiohttp.ClientSession:
        """
        Per-URL routing: a .onion host always goes through Tor (the only way to
        reach it); clearnet goes direct unless TOR_ENABLED anonymises everything.

        This is why a global Tor switch is wrong for this tool: forcing the
        clearnet indexes (Ahmia, PSBDMP, ransomwhat…) through Tor exit nodes
        makes several of them unreachable. Onion-only routing keeps both working.
        """
        if self._is_onion(url) or self.config.tor.enabled:
            return await self._get_tor_session()
        if self._session is None:
            raise RuntimeError("Session not initialized. Use 'async with' context.")
        return self._session

    async def _close_session(self):
        """Close both sessions."""
        for s in (self._session, self._tor_session):
            if s and not s.closed:
                await s.close()

    @property
    def session(self) -> aiohttp.ClientSession:
        """Current default session (must be in async context). Returns the Tor
        session when anonymise-all is on, else the direct one. Per-URL routing
        in fetch/fetch_json/check_exists overrides this for .onion targets."""
        if self.config.tor.enabled and self._tor_session and not self._tor_session.closed:
            return self._tor_session
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
        retries: int = 2,
        retry_delay: float = 1.0,
        ok_statuses: tuple = (200,),
        **kwargs
    ) -> Optional[str]:
        """
        Fetch URL and return text content.

        Retries with exponential backoff on transient errors (429, 5xx).
        Returns None on error (doesn't raise).
        """
        kwargs.setdefault('allow_redirects', False)  # CVE-2026-47265
        session = await self._session_for(url)  # .onion -> Tor, clearnet -> direct
        for attempt in range(retries + 1):
            try:
                async with session.request(method, url, **kwargs) as resp:
                    if resp.status in ok_statuses:
                        return await resp.text()
                    # Retry on rate limit or server errors
                    if resp.status in (429, 500, 502, 503, 504) and attempt < retries:
                        await asyncio.sleep(retry_delay * (2 ** attempt))
                        continue
                    return None
            except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as e:
                logger.debug("fetch transient error [%s] attempt %d/%d: %s", url, attempt + 1, retries + 1, e)
                if attempt < retries:
                    await asyncio.sleep(retry_delay * (2 ** attempt))
                    continue
                return None
            except Exception as e:
                logger.warning("fetch unexpected error [%s]: %s", url, e)
                return None
        return None

    async def fetch_json(
        self,
        url: str,
        method: str = 'GET',
        retries: int = 2,
        retry_delay: float = 1.0,
        **kwargs
    ) -> Optional[dict]:
        """
        Fetch URL and parse JSON response.

        Retries with exponential backoff on transient errors (429, 5xx).
        Returns None on error (doesn't raise).
        """
        kwargs.setdefault('allow_redirects', False)  # CVE-2026-47265
        session = await self._session_for(url)  # .onion -> Tor, clearnet -> direct
        for attempt in range(retries + 1):
            try:
                async with session.request(method, url, **kwargs) as resp:
                    if resp.status == 200:
                        return await resp.json(content_type=None)
                    if resp.status in (429, 500, 502, 503, 504) and attempt < retries:
                        await asyncio.sleep(retry_delay * (2 ** attempt))
                        continue
                    return None
            except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as e:
                logger.debug("fetch_json transient error [%s] attempt %d/%d: %s", url, attempt + 1, retries + 1, e)
                if attempt < retries:
                    await asyncio.sleep(retry_delay * (2 ** attempt))
                    continue
                return None
            except Exception as e:
                logger.warning("fetch_json unexpected error [%s]: %s", url, e)
                return None
        return None

    async def check_exists(self, url: str, **kwargs) -> bool:
        """Check if a URL returns 200 OK."""
        try:
            session = await self._session_for(url)  # .onion -> Tor, clearnet -> direct
            async with session.head(url, allow_redirects=True, **kwargs) as resp:
                return resp.status == 200
        except Exception:
            return False

    # Utility methods

    @staticmethod
    def which(tool: str) -> Optional[str]:
        """
        Absolute path to a bundled OSINT CLI tool, or None.

        maigret/sherlock/holehe are installed as console scripts next to the
        running interpreter. PATH alone only finds them when the venv has been
        activated, so fall back to sys.executable's directory — otherwise
        `venv/bin/cybertrace` silently reports the tools as missing.
        """
        return shutil.which(tool) or shutil.which(tool, path=str(Path(sys.executable).parent))

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
