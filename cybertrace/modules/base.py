"""Base module class for all OSINT modules."""

import asyncio
import aiohttp
import hashlib
import logging
import shutil
import sys
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, fields as _dataclass_fields
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from pathlib import Path
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

from ..config import config
from ..safety import BlockedContent, is_blocked_url, scrub

# Only the outermost run_sources() renders: rich permits one live display at a
# time, and the darkweb operator pivot runs whole sub-module searches inside a
# source. asyncio is single-threaded here, so a plain flag is enough.
_display_active = False


def _redact_secrets(text: str) -> str:
    """Strip every configured API key value out of `text` before it can ever
    reach a log line. Root-cause fix, not a per-caller patch: most APIs take
    a key as a query param or header (never logged raw here), but a
    URL-embedded-key scheme (e.g. NodeReal's
    https://bsc-mainnet.nodereal.io/v1/{key}) puts the live secret directly
    in the request URL -- and fetch/fetch_json below log that URL (and any
    exception's own str(), which some aiohttp errors also embed the URL in)
    on every transient/unexpected error. Scans every APIKeys field rather
    than special-casing NodeReal, so a future URL-embedded-key integration is
    covered by construction, not by remembering to add it here."""
    for f in _dataclass_fields(config.api_keys):
        value = getattr(config.api_keys, f.name)
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


# HTTP statuses treated as transient and worth a retry. 430 is not an IANA-
# registered code, but Blockchair uses it live for its own rate-limit/IP-
# blacklist condition (confirmed live: api.blockchair.com returns 430 with
# body {"context":{"error":"...temporary blacklisted due to exceeding usage
# of API resources..."}} under burst load) -- without it here, a Blockchair
# rate limit was never retried and fetch/fetch_json's next line (`return
# None`) let it fall straight through to "no data returned", indistinguishable
# from the address genuinely having no data. Shared by fetch and fetch_json
# so both retry paths stay in sync rather than drifting as two literal tuples.
_RETRYABLE_STATUSES = (429, 430, 500, 502, 503, 504)


def _safe_predicate(predicate, body) -> bool:
    """Run a caller-supplied retryable_body predicate defensively: a
    predicate written against one API's error shape (dict with an 'error'
    key, say) must not crash fetch_json when a different, well-formed 200
    body (a list, a bare string) doesn't match that shape."""
    try:
        return bool(predicate(body))
    except Exception:
        return False


@dataclass
class SourceResult:
    """Result from a single source."""
    source: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

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
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    # Identifies this one invocation of search(), distinct from every other —
    # including a re-run against the same target. evidence.ingest() carries it
    # onto every snapshot minted from this result, so two investigation runs
    # that observed the same artifact stay distinguishable in the store.
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)

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
            'run_id': self.run_id,
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
        self.show_progress = True  # CLI clears this for -q
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

        Also the single URL safety gate: every HTTP helper here and in the
        modules awaits this before it can send anything, so one check covers
        them all. BlockedContent lands in each caller's existing `except`,
        making a refused URL behave exactly like an unreachable one.
        """
        if is_blocked_url(url):
            raise BlockedContent("URL refused by content-safety gate")
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
        try:
            session = await self._session_for(url)  # .onion -> Tor, clearnet -> direct
        except BlockedContent:
            return None  # resolved outside the retry loop, so caught explicitly
        for attempt in range(retries + 1):
            try:
                async with session.request(method, url, **kwargs) as resp:
                    if resp.status in ok_statuses:
                        return scrub(await resp.text(), url)
                    # Retry on rate limit or server errors
                    if resp.status in _RETRYABLE_STATUSES and attempt < retries:
                        await asyncio.sleep(retry_delay * (2 ** attempt))
                        continue
                    return None
            except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as e:
                logger.debug("fetch transient error [%s] attempt %d/%d: %s",
                            _redact_secrets(url), attempt + 1, retries + 1, _redact_secrets(str(e)))
                if attempt < retries:
                    await asyncio.sleep(retry_delay * (2 ** attempt))
                    continue
                return None
            except Exception as e:
                logger.warning("fetch unexpected error [%s]: %s", _redact_secrets(url), _redact_secrets(str(e)))
                return None
        return None

    async def fetch_json(
        self,
        url: str,
        method: str = 'GET',
        retries: int = 2,
        retry_delay: float = 1.0,
        retryable_body: Optional[Any] = None,
        **kwargs
    ) -> Optional[dict]:
        """
        Fetch URL and parse JSON response.

        Retries with exponential backoff on transient errors (429, 5xx).
        Returns None on error (doesn't raise).

        `retryable_body`, when given, is called on every HTTP-200 JSON body
        before it's accepted: `retryable_body(body) -> bool`. Several real
        APIs here (NodeReal's JSON-RPC, Etherscan's REST shape) report rate
        limiting IN-BAND -- HTTP 200 with an error/rate-limit message inside
        the JSON -- so the plain status-code retry above never sees it as
        transient and neither retries nor backs off. A body the predicate
        flags is treated exactly like a 429: retried with the same backoff,
        then given up on (as the body itself, not None) once `retries` is
        exhausted -- so a permanently malformed body can't loop forever, and
        the caller's own error-message parsing still runs on the final
        attempt's body exactly as before. Callers that don't pass it keep
        today's behavior unchanged.
        """
        kwargs.setdefault('allow_redirects', False)  # CVE-2026-47265
        try:
            session = await self._session_for(url)  # .onion -> Tor, clearnet -> direct
        except BlockedContent:
            return None  # resolved outside the retry loop, so caught explicitly
        for attempt in range(retries + 1):
            try:
                async with session.request(method, url, **kwargs) as resp:
                    if resp.status == 200:
                        body = await resp.json(content_type=None)
                        if (retryable_body is not None and attempt < retries
                                and _safe_predicate(retryable_body, body)):
                            await asyncio.sleep(retry_delay * (2 ** attempt))
                            continue
                        return body
                    if resp.status in _RETRYABLE_STATUSES and attempt < retries:
                        await asyncio.sleep(retry_delay * (2 ** attempt))
                        continue
                    return None
            except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as e:
                logger.debug("fetch_json transient error [%s] attempt %d/%d: %s",
                            _redact_secrets(url), attempt + 1, retries + 1, _redact_secrets(str(e)))
                if attempt < retries:
                    await asyncio.sleep(retry_delay * (2 ** attempt))
                    continue
                return None
            except Exception as e:
                logger.warning("fetch_json unexpected error [%s]: %s",
                               _redact_secrets(url), _redact_secrets(str(e)))
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

        names = [name for name, _ in sources]
        results = await self._gather_with_progress(sources)

        for name, res in zip(names, results):
            if res is None:
                continue  # source opted out (nothing to look up) — not a failure
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

    # Progress rendering

    @staticmethod
    def _progress_label(name: str, res: Any) -> str:
        """Finished-row text: what the source was, and how it landed."""
        from rich.markup import escape

        if isinstance(res, Exception):
            return f"[red]✗[/] {name} — {escape(str(res) or type(res).__name__)[:70]}"
        if res is None:
            return f"[dim]–[/] {name} — skipped"
        ok = res.success if isinstance(res, SourceResult) else bool(res)
        if ok:
            return f"[green]✓[/] {name}"
        error = getattr(res, 'error', None)
        detail = f" — {escape(error)[:70]}" if error else " — no data"
        return f"[yellow]○[/] {name}{detail}"

    async def _gather_with_progress(self, sources: List[tuple]) -> List[Any]:
        """
        Run the source coroutines concurrently, with a live per-source row on
        stderr so a slow search (a Tor fetch runs tens of seconds) never looks
        hung. Exceptions come back as values, as gather(return_exceptions=True).

        Nothing is drawn when stderr is not a terminal — piped/redirected output
        stays clean — nor under -q, nor for a nested search inside a source.
        """
        global _display_active
        from rich.console import Console
        from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

        console = Console(stderr=True)
        show = self.show_progress and console.is_terminal and not _display_active
        _display_active |= show
        try:
            with Progress(
                SpinnerColumn(finished_text=' '),
                TextColumn('{task.description}'),
                TimeElapsedColumn(),
                console=console,
                disable=not show,
            ) as progress:
                tasks = {name: progress.add_task(name, total=1) for name, _ in sources}

                async def run(name: str, coro):
                    try:
                        res = await coro
                    except Exception as e:  # recorded as a failed source by the caller
                        res = e
                    progress.update(tasks[name], completed=1,
                                    description=self._progress_label(name, res))
                    return res

                return await asyncio.gather(*(run(n, c) for n, c in sources))
        finally:
            if show:
                _display_active = False
