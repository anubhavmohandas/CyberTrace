"""Dark web OSINT module."""

import asyncio
import base64
import hashlib
import ipaddress
import logging
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus, unquote

from ..normalize import (
    norm_btc, norm_domain, norm_email, norm_eth, norm_onion, norm_pgp, norm_xmr,
)
from .base import BaseModule, ModuleResult, SourceResult

logger = logging.getLogger(__name__)

# Where on the page an artifact was seen. A BTC address under "donate" is the
# operator's; the same string in passing prose is a mention. Checked against the
# raw HTML window, so class="footer" / id="wallet" count as evidence too.
_SECTION_RULES = (
    ('wallet', re.compile(r'wallet|donate|payment|deposit|escrow|bitcoin|monero', re.I)),
    ('contact', re.compile(r'contact|support|abuse|admin|reach us', re.I)),
    ('pgp', re.compile(r'pgp|gpg|public key|signature', re.I)),
    ('footer', re.compile(r'footer|copyright|&copy;|©|terms', re.I)),
)


class DarkwebModule(BaseModule):
    """
    Dark web intelligence via clearnet gateways and onion directories.

    SUCCESS RATE: 70% - Clearnet gateways work reliably.

    APPROACH:
    1. Fetch CURRENT verified .onion links from directory sites (addresses change!)
    2. Search dark web indexes via clearnet (Ahmia, DarkSearch, etc.)
    3. Optionally search via Tor if enabled

    Sources:
    - dark.fail (PGP-verified current onion links)
    - onion.live (curated directory)
    - tor.taxi (verified links)
    - Ahmia.fi (clearnet search of indexed onion sites)
    - DarkSearch.io (dark web search API)
    - Torch (via clearnet gateway)
    - IntelligenceX (if API key)
    """

    name = "darkweb"
    description = "Dark web OSINT via clearnet gateways"
    supported_types = {'darkweb', 'username', 'email', 'bitcoin'}

    # Clearnet directories that provide CURRENT verified .onion addresses
    # NEVER hardcode .onion URLs - always fetch from these!
    ONION_DIRECTORIES = {
        'dark.fail': 'https://dark.fail/',
        'onion.live': 'https://onion.live/',
        'tor.taxi': 'https://tor.taxi/',
        'darkweblinks': 'https://darkweblinks.io/',
    }

    # Dark web search engines (clearnet gateways)
    SEARCH_ENGINES = {
        'ahmia': 'https://ahmia.fi/search/?q={query}',
        'torch': 'https://torsearch.io/search?q={query}',  # Clearnet mirror
        'dargle': 'https://www.dargle.net/search?q={query}',  # Onion link directory search
        'haystack': 'https://haystak.io/search?q={query}',  # If available
    }

    async def search(self, target: str, **options) -> ModuleResult:
        """Search dark web sources for target.

        Uses clearnet gateways and indexes including Ahmia, Dargle, Torch,
        and other public dark web indexes. No Tor required.
        """

        result = ModuleResult(
            target=target,
            # Hardcoded like domain_module does with 'domain' — CLI never
            # threads a target_type option through to modules, so relying on
            # options.get() here always fell back to 'unknown' regardless of
            # what the detector actually identified.
            target_type='darkweb',
            module=self.name,
        )

        # Phase 0: If the target IS an onion address, visit it directly over Tor.
        # fetch() auto-routes .onion through Tor (needs a running Tor proxy).
        onion_host = target.replace('http://', '').replace('https://', '').split('/')[0].lower()
        sources = []
        if onion_host.endswith('.onion'):
            sources.append(('target_onion', self._fetch_target_onion(onion_host)))

        # Phase 1: Fetch current onion directories (for reference)
        sources.append(('onion_directories', self._fetch_onion_directories()))

        # Phase 2: Search dark web indexes
        sources.extend([
            ('ahmia', self._search_ahmia(target)),
            ('dargle', self._search_dargle(target)),
            ('torch', self._search_torch(target)),
        ])

        # Phase 3: IntelligenceX if API key available
        if self.config.api_keys.has('intelx'):
            sources.append(('intelx', self._search_intelx(target)))

        # Phase 4: RansomLook — free, no key, useful for domain/company targets
        sources.append(('ransomwhat', self._search_ransomwhat(target)))

        # Phase 5: Real paste site search via PSBDMP
        sources.append(('paste_sites', self._search_paste_sites(target)))

        await self.run_sources(sources, result)

        # Phase 6: Validate onion addresses discovered in Phase 2
        # Collect all onion addresses found across sources
        discovered_onions = set()
        for source_result in result.sources.values():
            if source_result.success and source_result.data:
                for addr in source_result.data.get('onion_addresses_found', []):
                    discovered_onions.add(addr)
                for item in source_result.data.get('results', []):
                    if isinstance(item, dict) and item.get('onion_url'):
                        onion_match = re.search(r'([a-z2-7]{56}\.onion)', item['onion_url'])
                        if onion_match:
                            discovered_onions.add(onion_match.group(1))

        if discovered_onions:
            onion_result = await self._search_onion_lookup(list(discovered_onions))
            result.sources['onion_lookup'] = onion_result

        # Phase 7: Auto-pivot operator artifacts (emails, crypto) found on the
        # live onion into their own modules for a one-command operator profile.
        live = result.sources.get('target_onion')
        if live and live.success:
            pivot = await self._pivot_operator_artifacts(live.data)
            if pivot:
                result.sources['operator_pivot'] = pivot

        # Build summary
        result.summary = self._build_summary(result)
        result.end_time = datetime.utcnow()

        return result

    # --- Operator de-anonymisation: artifacts a live onion site leaks ---
    _RE_URL = re.compile(r'https?://([a-zA-Z0-9._~-]+(?::\d+)?)')
    _RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    _RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    _RE_BTC = re.compile(r'\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
    _RE_ETH = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
    _RE_XMR = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')
    _RE_ANALYTICS = re.compile(r'\b(?:UA-\d{4,}-\d+|G-[A-Z0-9]{6,}|GTM-[A-Z0-9]{4,})\b')
    _RE_ONION = re.compile(r'[a-z2-7]{56}\.onion', re.IGNORECASE)
    _RE_TITLE = re.compile(r'<title[^>]*>([^<]+)</title>', re.IGNORECASE)
    _RE_PGP = re.compile(
        r'-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----',
        re.DOTALL,
    )
    # Generic role mailboxes — not operator handles, so they don't seed a username pivot.
    _ROLE_LOCALPARTS = frozenset({
        'admin', 'administrator', 'support', 'info', 'contact', 'sales',
        'help', 'abuse', 'noreply', 'no-reply', 'root', 'mail', 'office',
        'hello', 'team', 'security', 'billing', 'orders', 'webmaster', 'postmaster',
    })
    # Endpoints that commonly leak the real backend IP when misconfigured.
    _MISCONFIG_PATHS = (
        '/server-status', '/server-info', '/.git/config', '/.env',
        '/phpinfo.php', '/info.php', '/status', '/robots.txt',
    )

    @staticmethod
    def _validated(html: str, pattern: 're.Pattern', normalizer,
                   exclude: str = '') -> Tuple[List[str], Dict[str, Dict[str, str]]]:
        """Regex hits that survive normalize.py, plus where each was seen.

        Validation is the gate the whole evidence model rests on: a regex is
        shape-matching, not proof, so an address failing its checksum must never
        become a graph node. Otherwise two markets quoting the same malformed
        string correlate into a shared "operator" that does not exist.

        Returns the raw values (canonical form is the graph's job) and an
        evidence map {value: {section, context}} for the edges built from them.
        """
        # occam: section = keyword hit in a fixed ±70 char window, first rule
        # wins. Two blocks closer than that can cross-attribute (a footer address
        # beside a donate box reads as 'wallet'). Upgrade to real DOM ancestry
        # only if misattributed sections start moving confidence wrongly.
        values: List[str] = []
        evidence: Dict[str, Dict[str, str]] = {}
        for m in pattern.finditer(html):
            raw = m.group(0)
            if raw in evidence or (exclude and raw in exclude):
                continue
            if normalizer(raw) is None:
                continue
            before, after = html[max(0, m.start() - 70):m.start()], html[m.end():m.end() + 70]
            # Classify on the surroundings only: 'admin@x.com' in a footer is a
            # footer artifact, and letting the value match its own section rule
            # would relabel it 'contact' on the strength of its local-part.
            around = f"{before} {after}"
            evidence[raw] = {
                'section': next((n for n, rx in _SECTION_RULES if rx.search(around)), 'body'),
                'context': re.sub(
                    r'\s+', ' ', re.sub(r'<[^>]+>', ' ', f"{before}{raw}{after}")).strip()[:200],
            }
            values.append(raw)
        return sorted(values), evidence

    @staticmethod
    def _extract_pgp_keys(html: str) -> List[Dict[str, str]]:
        """Capture armored PGP public keys on the page and give each a stable id.

        The id is the true OpenPGP fingerprint (normalize.pgp_fingerprint parses
        the packets), which is what makes a shared key the strongest cross-market
        signal in the graph: a clone re-exporting a copied key changes every byte
        of the armor but never the fingerprint. Keyserver lookup of the
        operator's identities happens on the email pivot
        (email_module._check_pgp_keyservers).
        """
        # occam: keys the parser can't read (v3, truncated armor) fall back to a
        # payload hash — still stable for identical exports, just not re-export
        # proof. Upgrade: extend normalize._packets if v3 keys ever show up.
        seen: Dict[str, Dict[str, str]] = {}
        for m in DarkwebModule._RE_PGP.finditer(html):
            payload = re.sub(r'\s+', '', ''.join(
                ln for ln in m.group(1).splitlines() if ':' not in ln
            ))
            if len(payload) < 64:  # too short to be a real key block
                continue
            fpr = norm_pgp(m.group(0))
            if fpr:
                seen.setdefault(fpr, {'key_id': fpr, 'fingerprint': fpr.removeprefix('PGP:')})
            else:
                kid = hashlib.sha256(payload.encode()).hexdigest()[:16]
                seen.setdefault(kid, {'key_id': kid})
        return list(seen.values())

    @staticmethod
    def _usernames_from_emails(emails: List[str]) -> List[str]:
        """Email local-parts are candidate operator handles (plan: email ->
        username). Drop generic role accounts and too-short/noisy strings."""
        out: List[str] = []
        for e in emails:
            local = e.split('@', 1)[0].lower()
            if local in DarkwebModule._ROLE_LOCALPARTS or len(local) < 4:
                continue
            if not re.fullmatch(r'[a-z0-9._-]+', local):
                continue
            if local not in out:
                out.append(local)
        return out

    @staticmethod
    def _public_ipv4(candidates) -> List[str]:
        """Keep only routable public IPv4s — drop private/loopback/reserved."""
        out = []
        for ip in candidates:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version == 4 and not (
                addr.is_private or addr.is_loopback or addr.is_reserved
                or addr.is_multicast or addr.is_link_local or addr.is_unspecified
            ):
                out.append(str(addr))
        return sorted(set(out))

    async def _fetch_full(self, url: str) -> Tuple[Optional[int], Dict[str, str], str]:
        """Fetch url (.onion auto-routes through Tor) returning status, headers,
        text. Unlike fetch(), this preserves response headers — needed for the
        server fingerprint and clock-skew signals. Returns (None, {}, '') on error."""
        try:
            session = await self._session_for(url)
            async with session.request('GET', url, allow_redirects=False) as resp:
                text = await resp.text(errors='ignore')
                return resp.status, dict(resp.headers), text
        except Exception as e:  # unreachable / Tor down / timeout
            logger.debug("onion fetch failed [%s]: %s", url, e)
            return None, {}, ''

    async def _fetch_bytes(self, url: str) -> Optional[bytes]:
        """Fetch raw bytes (used for favicon hashing). None on non-200/error."""
        try:
            session = await self._session_for(url)
            async with session.request('GET', url, allow_redirects=False) as resp:
                return await resp.read() if resp.status == 200 else None
        except Exception:
            return None

    async def _fetch_target_onion(self, onion_host: str) -> SourceResult:
        """
        Visit the target .onion directly over Tor and mine it for operator
        de-anonymisation signals — the core of the problem statement.

        fetch auto-routes .onion through Tor (BaseModule._session_for), so a
        running Tor proxy (SOCKS 127.0.0.1:9050) is required. Extracts:
          - server/framework fingerprint (Server, X-Powered-By, cookies, ETag…)
          - clock skew: the onion's Date header vs our UTC (correlation signal)
          - clearnet hosts referenced in the page (leaked operator infra)
          - operator PII/financial/tracking: emails, BTC/ETH/XMR, GA/GTM IDs, PGP
          - leaked public IPv4 in headers or body (a real-host slip)
          - common server misconfigs (/server-status, /.git/config …) that leak IPs
          - favicon -> Shodan pivot: candidate CLEARNET IPs serving the same icon

        Candidate operator IPs (leaked + favicon pivot) are surfaced so the
        analyst can pivot into the ip/domain modules.
        """
        base = f"http://{onion_host}"
        status, headers, html = await self._fetch_full(f"{base}/")

        if status is None:
            return SourceResult(
                source='target_onion',
                success=False,
                error=(
                    'Onion unreachable — site is down, or Tor is not running. '
                    f'Start Tor (SOCKS on {self.config.tor.socks_host}:'
                    f'{self.config.tor.socks_port}) and retry.'
                ),
            )

        title_m = self._RE_TITLE.search(html)
        title = title_m.group(1).strip()[:200] if title_m else ''

        # Server / framework fingerprint from response headers.
        fingerprint = {
            k: headers[k] for k in (
                'Server', 'X-Powered-By', 'Via', 'X-Runtime', 'X-Generator',
                'X-AspNet-Version', 'ETag', 'Last-Modified',
            ) if headers.get(k)
        }
        cookie_names = re.findall(r'(\w+)=', headers.get('Set-Cookie', ''))
        if cookie_names:
            fingerprint['cookie_names'] = list(dict.fromkeys(cookie_names))

        # Clock skew: onion server's clock vs ours. A stable non-zero skew is a
        # correlation signal against clearnet hosts with the same drift.
        clock_skew = None
        if headers.get('Date'):
            try:
                server_dt = parsedate_to_datetime(headers['Date'])
                clock_skew = round(
                    (datetime.now(server_dt.tzinfo) - server_dt).total_seconds(), 1
                )
            except Exception:
                pass

        # Clearnet hosts referenced on the page (leaked operator infrastructure).
        # norm_domain rejects onions and anything that isn't a real hostname.
        clearnet_hosts = sorted({
            d for d in (norm_domain(h) for h in self._RE_URL.findall(html)) if d
        })

        # Operator artifacts, each gated by its normalizer so only values that
        # actually validate (base58check, bech32, block-base58, RFC-shaped mail)
        # can become graph entities. Drop BTC matches that are really a slice of
        # an onion address (base32 overlaps base58) before validating.
        onion_tokens = ''.join(self._RE_ONION.findall(html))
        btc, ev_btc = self._validated(html, self._RE_BTC, norm_btc, exclude=onion_tokens)
        emails, ev_email = self._validated(html, self._RE_EMAIL, norm_email)
        eth, ev_eth = self._validated(html, self._RE_ETH, norm_eth)
        xmr, ev_xmr = self._validated(html, self._RE_XMR, norm_xmr)
        analytics = sorted(set(self._RE_ANALYTICS.findall(html)))
        artifact_evidence = {**ev_btc, **ev_email, **ev_eth, **ev_xmr}

        # Leaked public IPv4 in headers or body — a direct real-host slip.
        header_blob = ' '.join(str(v) for v in headers.values())
        leaked_ips = self._public_ipv4(
            self._RE_IPV4.findall(header_blob) + self._RE_IPV4.findall(html)
        )

        # Misconfig probes + favicon/Shodan pivot (each best-effort).
        misconfigs = await self._probe_misconfigs(base)
        favicon = await self._favicon_pivot(base, html)

        candidate_ips = sorted(
            set(leaked_ips)
            | {m['ip'] for m in favicon.get('shodan_matches', []) if m.get('ip')}
            | {ip for mc in misconfigs for ip in mc.get('leaked_ips', [])}
        )

        onion_links = [
            a for a in dict.fromkeys(
                norm_onion(x) for x in self._RE_ONION.findall(html)
            ) if a and a != onion_host
        ]

        return SourceResult(
            source='target_onion',
            success=True,
            data={
                'online': True,
                'url': f"{base}/",
                'http_status': status,
                'title': title,
                'page_bytes': len(html),
                'server_fingerprint': fingerprint,
                'clock_skew_seconds': clock_skew,
                'clearnet_hosts_referenced': clearnet_hosts[:40],
                'emails': emails[:20],
                'bitcoin_addresses': btc[:20],
                'ethereum_addresses': eth[:20],
                'monero_addresses': xmr[:20],
                'analytics_ids': analytics[:20],
                'pgp_keys': self._extract_pgp_keys(html),
                'leaked_public_ipv4': leaked_ips,
                'misconfigurations': misconfigs,
                'favicon': favicon,
                'candidate_operator_ips': candidate_ips,
                'onion_links_found': len(onion_links),
                'onion_addresses_found': onion_links[:10],
                # {value: {section, context}} — where on the page each artifact
                # was seen, so graph edges carry evidence and not just a link.
                'artifact_evidence': artifact_evidence,
            },
        )

    async def _probe_misconfigs(self, base: str) -> List[Dict[str, Any]]:
        """Probe common info-leak endpoints; report any that return 200 and the
        public IPs found in their bodies. Runs concurrently over Tor."""
        async def probe(path: str) -> Optional[Dict[str, Any]]:
            status, _headers, body = await self._fetch_full(f"{base}{path}")
            if status == 200 and body:
                return {
                    'path': path,
                    'status': status,
                    'bytes': len(body),
                    'leaked_ips': self._public_ipv4(self._RE_IPV4.findall(body)),
                }
            return None

        results = await asyncio.gather(*(probe(p) for p in self._MISCONFIG_PATHS))
        return [r for r in results if r]

    async def _favicon_pivot(self, base: str, html: str) -> Dict[str, Any]:
        """
        Hash the site's favicon (Shodan's mmh3-of-base64 scheme) and search
        Shodan for clearnet hosts serving the same icon. A match is a strong
        candidate for the operator's real (de-anonymised) server.

        Classic hidden-service de-anon: operators reuse the same favicon on a
        misconfigured clearnet box that Shodan has already indexed.
        """
        m = re.search(
            r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*href=["\']([^"\']+)["\']',
            html, re.IGNORECASE,
        )
        href = m.group(1) if m else '/favicon.ico'
        if href.startswith('http') and '.onion' not in href.lower():
            return {'note': 'favicon served from external host; pivot skipped', 'declared': href}
        if href.startswith('http'):
            fav_url = href
        elif href.startswith('//'):
            fav_url = 'http:' + href
        else:
            fav_url = base + (href if href.startswith('/') else '/' + href)

        fav = await self._fetch_bytes(fav_url)
        if not fav:
            return {'favicon_url': fav_url, 'note': 'no favicon retrieved'}

        try:
            import mmh3  # Shodan's exact hash; correct-on-edge-cases beats reimplementing
        except ImportError:
            return {'favicon_url': fav_url, 'note': 'mmh3 not installed (pip install mmh3)'}

        fav_hash = mmh3.hash(base64.encodebytes(fav))
        out = {
            'favicon_url': fav_url,
            'favicon_mmh3': fav_hash,
            'shodan_query': f'http.favicon.hash:{fav_hash}',
        }

        key = self.config.api_keys.get('shodan')
        if not key:
            out['note'] = 'no Shodan key — run the shodan_query manually at shodan.io'
            return out

        sd = await self.fetch_json(
            f"https://api.shodan.io/shodan/host/search?key={key}"
            f"&query=http.favicon.hash:{fav_hash}"
        )
        if not sd:
            out['note'] = 'Shodan returned nothing (or plan lacks the search API)'
            return out

        out['shodan_total'] = sd.get('total', 0)
        out['shodan_matches'] = [
            {
                'ip': h.get('ip_str'),
                'port': h.get('port'),
                'org': h.get('org'),
                'isp': h.get('isp'),
                'hostnames': h.get('hostnames', []),
                'country': (h.get('location') or {}).get('country_name'),
            }
            for h in sd.get('matches', [])[:10]
        ]
        return out

    async def _fetch_onion_directories(self) -> SourceResult:
        """
        Fetch current verified .onion links from directory sites.

        CRITICAL: Onion addresses change frequently. NEVER hardcode them.
        Always fetch current addresses from verified clearnet directories.
        """
        all_services = {}
        directories_checked = []

        # Fetch from dark.fail (PGP-verified)
        try:
            darkfail_services = await self._parse_dark_fail()
            if darkfail_services:
                all_services.update(darkfail_services)
                directories_checked.append('dark.fail')
        except Exception:
            pass

        # Fetch from onion.live
        try:
            onionlive_services = await self._parse_onion_live()
            if onionlive_services:
                all_services.update(onionlive_services)
                directories_checked.append('onion.live')
        except Exception:
            pass

        return SourceResult(
            source='onion_directories',
            success=len(all_services) > 0,
            data={
                'directories_checked': directories_checked,
                'services_found': len(all_services),
                'services': dict(list(all_services.items())[:20]),  # Top 20
                'note': 'Current verified .onion addresses. Use these instead of hardcoded URLs.',
            },
        )

    async def _parse_dark_fail(self) -> Dict[str, str]:
        """
        Parse dark.fail for PGP-verified .onion addresses.

        dark.fail provides cryptographically verified current onion addresses
        for major dark web services.
        """
        url = "https://dark.fail/"
        html = await self.fetch(url)

        if not html:
            return {}

        services = {}

        # Only trust anchor tags that link directly to a valid v3 onion
        # address. The previous version also ran an unanchored proximity
        # pattern (`([A-Za-z0-9\s]+)[\s\S]*?([a-z2-7]{56}\.onion)`) meant to
        # catch "service name ... onion address" pairs outside <a> tags.
        # Because `[\s\S]*?` matches across the whole document lazily, it
        # regularly grabbed unrelated page text as the "name" — in practice
        # this was seen capturing '<!DOCTYPE html>' itself as a service name.
        # Anchor-tag extraction is the only reliable signal here.
        pattern = r'<a[^>]+href="[^"]*?([a-z2-7]{56}\.onion)[^"]*"[^>]*>([^<]+)</a>'
        matches = re.findall(pattern, html, re.IGNORECASE)

        for onion, name in matches:
            clean_name = self._clean_scraped_name(name)
            if clean_name:
                services[clean_name] = onion

        return services

    async def _parse_onion_live(self) -> Dict[str, str]:
        """Parse onion.live directory."""
        url = "https://onion.live/"
        html = await self.fetch(url)

        if not html:
            return {}

        services = {}

        # Extract onion links with their titles
        pattern = r'<a[^>]*href="[^"]*?([a-z2-7]{56}\.onion)[^"]*"[^>]*>([^<]+)</a>'
        matches = re.findall(pattern, html, re.IGNORECASE)

        for onion, title in matches:
            clean_title = self._clean_scraped_name(title)
            if clean_title:
                services[clean_title] = onion

        return services

    _SCRAPED_NAME_DENYLIST = {
        'doctype html', 'html', 'head', 'body', 'script', 'style', 'title',
        'home', 'search', 'about', 'next', 'prev', 'previous', 'menu',
    }

    def _clean_scraped_name(self, raw: str, max_len: int = 50) -> Optional[str]:
        """
        Normalize a name/title scraped from HTML and reject obvious junk.

        Regex-scraped anchor text can pick up markup boilerplate (e.g. a
        stray '<!DOCTYPE html>' match) or bare navigation labels ('Home',
        'Search'). This filters those out so callers don't store garbage as
        a legitimate service/result name.
        """
        clean = re.sub(r'\s+', ' ', raw).strip()
        if len(clean) < 2:
            return None
        if clean.lower() in self._SCRAPED_NAME_DENYLIST:
            return None
        return clean[:max_len]

    async def _search_ahmia(self, query: str) -> SourceResult:
        """
        Search Ahmia.fi - the most reliable clearnet dark web search.

        Ahmia is a legitimate search engine that indexes .onion sites
        while filtering out illegal content.
        """
        encoded_query = quote_plus(query)
        url = f"https://ahmia.fi/search/?q={encoded_query}"

        html = await self.fetch(url)

        if not html:
            return SourceResult(
                source='ahmia',
                success=False,
                error='No response from Ahmia',
            )

        results = []

        # Parse search results
        # Ahmia shows results with redirect URLs containing the actual .onion
        redirect_pattern = r'redirect_url=([^&"]+)'
        title_pattern = r'<h4[^>]*>([^<]+)</h4>'
        desc_pattern = r'<p[^>]*class="[^"]*result[^"]*"[^>]*>([^<]+)</p>'

        # Extract redirect URLs (contain actual .onion addresses)
        redirects = re.findall(redirect_pattern, html)
        titles = re.findall(title_pattern, html)
        descriptions = re.findall(desc_pattern, html)

        for i, redirect in enumerate(redirects[:20]):
            try:
                decoded_url = unquote(redirect)
                result_item = {
                    'onion_url': decoded_url,
                    'title': titles[i].strip() if i < len(titles) else 'Unknown',
                    'description': descriptions[i].strip()[:200] if i < len(descriptions) else '',
                }
                results.append(result_item)
            except Exception:
                continue

        # Also extract any direct .onion mentions
        onion_pattern = r'([a-z2-7]{56}\.onion)'
        onion_addresses = set(re.findall(onion_pattern, html, re.IGNORECASE))

        return SourceResult(
            source='ahmia',
            success=True,
            data={
                'result_count': len(results),
                'results': results,
                'onion_addresses_found': list(onion_addresses)[:10],
                'search_url': url,
            },
        )

    async def _search_dargle(self, query: str) -> SourceResult:
        """
        Search Dargle (dargle.net) — a live clearnet dark web index.

        Dargle indexes .onion sites and exposes them via a clearnet search
        interface. Parses HTML results to extract onion links and titles.
        """
        encoded_query = quote_plus(query)
        url = f"https://www.dargle.net/search?q={encoded_query}"

        html = await self.fetch(url)

        if not html:
            return SourceResult(
                source='dargle',
                success=False,
                error='No response from Dargle',
            )

        results = []

        # Extract result blocks — Dargle wraps each result in a div/article
        # with a title link and optional description
        # Pattern 1: anchor tags containing .onion URLs
        link_pattern = r'<a[^>]+href=["\']([^"\']*(?:[a-z2-7]{56}\.onion|\.onion)[^"\']*)["\'][^>]*>([^<]{1,120})</a>'
        matches = re.findall(link_pattern, html, re.IGNORECASE)

        seen_onions: set = set()
        for href, link_text in matches:
            clean_title = link_text.strip()
            if not clean_title or len(clean_title) < 3:
                continue
            # Skip navigation/UI links (very short or generic)
            if clean_title.lower() in ('home', 'search', 'about', 'next', 'prev', 'previous', '»', '«'):
                continue
            onion_match = re.search(r'([a-z2-7]{56}\.onion)', href, re.IGNORECASE)
            onion_url = href if '.onion' in href else None
            onion_addr = onion_match.group(1) if onion_match else None
            if onion_addr and onion_addr in seen_onions:
                continue
            if onion_addr:
                seen_onions.add(onion_addr)
            results.append({
                'title': clean_title[:100],
                'onion_url': onion_url,
                'description': '',
            })

        # Pattern 2: if the above yields nothing, try broader extraction
        if not results:
            # Look for any .onion address near a readable title in the page
            block_pattern = r'([a-z2-7]{56}\.onion)'
            raw_onions = re.findall(block_pattern, html, re.IGNORECASE)
            # Try to find titles close to these onion addresses
            for onion in list(dict.fromkeys(raw_onions))[:20]:  # deduplicate, cap 20
                # Search for a title tag or heading near this onion address
                idx = html.find(onion)
                snippet = html[max(0, idx - 300):idx + len(onion) + 50]
                title_match = re.search(r'>([^<]{5,80})</(?:a|h[1-6]|span|div)', snippet)
                title = title_match.group(1).strip() if title_match else 'Unknown'
                if onion not in seen_onions:
                    seen_onions.add(onion)
                    results.append({
                        'title': title[:100],
                        'onion_url': f'http://{onion}',
                        'description': '',
                    })

        onion_addresses = list(seen_onions)

        return SourceResult(
            source='dargle',
            success=True,
            data={
                'result_count': len(results),
                'results': results[:20],
                'onion_addresses_found': onion_addresses[:10],
                'search_url': url,
            },
        )

    async def _search_torch(self, query: str) -> SourceResult:
        """
        Search Torch via clearnet mirror.

        Torch is one of the oldest dark web search engines.
        """
        encoded_query = quote_plus(query)
        # Try multiple possible clearnet mirrors
        mirrors = [
            f"https://torsearch.io/search?q={encoded_query}",
            f"https://torchsearch.io/?q={encoded_query}",
        ]

        for mirror_url in mirrors:
            html = await self.fetch(mirror_url)
            if html:
                break
        else:
            return SourceResult(
                source='torch',
                success=False,
                error='No Torch mirror available',
            )

        results = []
        seen_onions: set = set()

        # Pair each onion address with the title from the SAME anchor tag.
        # The previous version scraped onions and titles with two independent
        # regex passes, then zipped them positionally by index — since
        # `onions` came from iterating a `set` (unordered) and `titles` came
        # from a completely separate pass over the whole page, the title
        # attached to a given onion had no real relationship to it. Site nav
        # links ('Clearnet', 'Search - Amnesia') ended up attached to
        # unrelated onion addresses, including the search mirror's own UI.
        link_pattern = r'<a[^>]+href="[^"]*?([a-z2-7]{56}\.onion)[^"]*"[^>]*>([^<]{1,120})</a>'
        matches = re.findall(link_pattern, html, re.IGNORECASE)

        for onion, title in matches:
            clean_title = self._clean_scraped_name(title, max_len=100)
            if not clean_title:
                continue
            if onion in seen_onions:
                continue
            seen_onions.add(onion)
            results.append({
                'onion_url': f"http://{onion}",
                'title': clean_title,
            })

        return SourceResult(
            source='torch',
            success=len(results) > 0,
            data={
                'result_count': len(results),
                'results': results[:20],
                # Previously omitted — meant the phase-6 onion validation
                # step in search() had to fall back to re-deriving addresses
                # from results[].onion_url instead of this field, and the
                # summary's unique_onion_addresses never included torch hits.
                'onion_addresses_found': list(seen_onions)[:10],
            },
        )

    async def _search_ransomwhat(self, query: str) -> SourceResult:
        """
        Search RansomLook (ransomwhat.telemetry.ltd) for ransomware victim mentions.

        Free API, no key required. Tracks active ransomware groups and their victims.
        Useful when target is a domain or company name.

        API: https://api.ransomwhat.telemetry.ltd
        """
        base_url = "https://api.ransomwhat.telemetry.ltd"

        # Strip subdomain noise — search by root domain or plain name
        search_term = query.lower().replace('www.', '').split('/')[0]

        try:
            # Fetch all victims and filter client-side — API has no search param
            data = await self.fetch_json(f"{base_url}/victims")
        except Exception as e:
            return SourceResult(source='ransomwhat', success=False, error=str(e))

        if not data:
            return SourceResult(source='ransomwhat', success=False, error='No response from ransomwhat API')

        victims = data if isinstance(data, list) else data.get('data', [])

        matches = []
        for victim in victims:
            name = victim.get('post_title', '') or victim.get('victim', '') or ''
            website = victim.get('website', '') or ''
            if (search_term in name.lower()) or (search_term in website.lower()):
                matches.append({
                    'victim': name,
                    'group': victim.get('group_name', 'Unknown'),
                    'website': website,
                    'published': victim.get('post_date', ''),
                    'country': victim.get('country', ''),
                    'activity': victim.get('activity', ''),
                    'description': (victim.get('description', '') or '')[:200],
                })

        return SourceResult(
            source='ransomwhat',
            success=True,
            data={
                'result_count': len(matches),
                'results': matches,
                'note': 'Matches from RansomLook ransomware victim database',
            },
        )

    async def _search_onion_lookup(self, onion_addresses: List[str]) -> SourceResult:
        """
        Validate and enrich onion addresses via onion.al API.

        Free API, no key required. Returns online status, title, description,
        and last-seen timestamp for each onion address.

        API: https://onion.al/api/{onion_address}
        """
        if not onion_addresses:
            return SourceResult(
                source='onion_lookup',
                success=False,
                error='No onion addresses to validate',
            )

        base_url = "https://onion.al/api"
        results = []

        for onion in onion_addresses[:10]:  # Cap to avoid hammering the API
            clean = onion.replace('http://', '').replace('https://', '').split('/')[0]
            try:
                data = await self.fetch_json(f"{base_url}/{clean}")
                if data:
                    results.append({
                        'onion': clean,
                        'online': data.get('online', False),
                        'title': data.get('title', ''),
                        'description': (data.get('description', '') or '')[:200],
                        'last_seen': data.get('last_online', ''),
                        'first_seen': data.get('first_online', ''),
                    })
            except Exception:
                results.append({'onion': clean, 'online': None, 'error': 'lookup failed'})

        online_count = sum(1 for r in results if r.get('online') is True)

        return SourceResult(
            source='onion_lookup',
            success=len(results) > 0,
            data={
                'checked': len(results),
                'online': online_count,
                'offline': len(results) - online_count,
                'results': results,
            },
        )

    async def _search_intelx(self, query: str) -> SourceResult:
        """
        Search IntelligenceX for pastes, leaks, and dark web content.
        """
        api_key = self.config.api_keys.get('intelx')
        if not api_key:
            return SourceResult(source='intelx', success=False, error='No API key')

        search_url = "https://2.intelx.io/phonebook/search"

        headers = {
            'x-key': api_key,
            'Content-Type': 'application/json',
        }

        payload = {
            'term': query,
            'maxresults': 20,
            'media': 0,
            'sort': 4,
            'terminate': [],
        }

        try:
            async with self.session.post(search_url, headers=headers, json=payload) as resp:
                if resp.status != 200:
                    return SourceResult(
                        source='intelx',
                        success=False,
                        error=f'API returned {resp.status}',
                    )
                data = await resp.json()
        except Exception as e:
            return SourceResult(source='intelx', success=False, error=str(e))

        search_id = data.get('id')
        if not search_id:
            return SourceResult(
                source='intelx',
                success=True,
                data={'result_count': 0, 'results': []},
            )

        # Fetch results
        results_url = f"https://2.intelx.io/phonebook/search/result?id={search_id}&limit=20"

        try:
            async with self.session.get(results_url, headers=headers) as resp:
                if resp.status == 200:
                    results_data = await resp.json()
                else:
                    return SourceResult(source='intelx', success=False, error='Failed to fetch results')
        except Exception as e:
            return SourceResult(source='intelx', success=False, error=str(e))

        selectors = results_data.get('selectors', [])

        results = []
        for item in selectors[:20]:
            results.append({
                'value': item.get('selectorvalue'),
                'type': item.get('selectortypeh'),
            })

        return SourceResult(
            source='intelx',
            success=True,
            data={
                'result_count': len(results),
                'results': results,
            },
        )

    async def _search_paste_sites(self, query: str) -> SourceResult:
        """
        Search paste sites via PSBDMP.ws — a real indexed paste search API.

        Free API, no key required. Indexes Pastebin, GitHub Gist, and others.
        API: https://psbdmp.ws/api/v3/search/{query}
        """
        encoded = quote_plus(query)
        url = f"https://psbdmp.ws/api/v3/search/{encoded}"

        try:
            data = await self.fetch_json(url)
        except Exception as e:
            return SourceResult(source='paste_sites', success=False, error=str(e))

        if not data:
            return SourceResult(source='paste_sites', success=False, error='No response from PSBDMP')

        items = data if isinstance(data, list) else data.get('data', [])

        results = []
        for item in items[:20]:
            results.append({
                'id': item.get('id', ''),
                'url': f"https://pastebin.com/{item.get('id', '')}" if item.get('id') else '',
                'tags': item.get('tags', ''),
                'length': item.get('length', 0),
                'time': item.get('time', ''),
            })

        return SourceResult(
            source='paste_sites',
            success=True,
            data={
                'result_count': len(results),
                'results': results,
                'source_api': 'PSBDMP.ws',
            },
        )

    async def get_current_onion(self, service_name: str) -> Optional[str]:
        """
        Get the CURRENT verified .onion address for a known service.

        IMPORTANT: Always use this instead of hardcoding onion addresses!
        Addresses change frequently, especially after takedowns.

        Args:
            service_name: Name of the service (e.g., 'dread', 'tor66')

        Returns:
            Current .onion address or None if not found
        """
        # Fetch from dark.fail first (most reliable)
        services = await self._parse_dark_fail()

        # Case-insensitive search
        for name, onion in services.items():
            if service_name.lower() in name.lower():
                return onion

        # Try onion.live as fallback
        services = await self._parse_onion_live()
        for name, onion in services.items():
            if service_name.lower() in name.lower():
                return onion

        return None

    @staticmethod
    def _pivot_targets(data: Dict[str, Any], cap: int = 3) -> List[Tuple[str, str]]:
        """Pick operator artifacts worth pivoting into other modules, capped per
        kind to bound external calls. ETH addresses go to the bitcoin module too
        (it auto-detects the coin); email local-parts become candidate usernames;
        candidate operator IPs get RDAP/ASN/geo enrichment via the ip module."""
        emails = (data.get('emails') or [])[:cap]
        crypto = (
            (data.get('bitcoin_addresses') or []) + (data.get('ethereum_addresses') or [])
        )[:cap]
        ips = (data.get('candidate_operator_ips') or [])[:cap]
        usernames = DarkwebModule._usernames_from_emails(data.get('emails') or [])[:cap]
        return (
            [('email', e) for e in emails]
            + [('bitcoin', c) for c in crypto]
            + [('ip', ip) for ip in ips]
            + [('username', u) for u in usernames]
        )

    async def _pivot_operator_artifacts(self, data: Dict[str, Any]) -> Optional[SourceResult]:
        """
        Feed emails / crypto addresses found on the live onion into their own
        modules and collect a compact profile — the one-command operator sweep.

        Only runs when artifacts exist, so a clean/hardened target adds no cost.
        """
        jobs = self._pivot_targets(data)
        if not jobs:
            return None

        from . import get_module  # lazy: avoids modules/__init__ import cycle

        async def run(kind: str, target: str) -> Dict[str, Any]:
            module = get_module(kind)
            if module is None:
                return {'target': target, 'type': kind, 'error': 'no module'}
            try:
                async with module as m:
                    r = await m.search(target)
                return {
                    'target': target,
                    'type': r.target_type,
                    'sources_ok': f"{r.success_count}/{r.total_count}",
                    'summary': r.summary,
                }
            except Exception as e:
                return {'target': target, 'type': kind, 'error': str(e)}

        results = await asyncio.gather(*(run(k, t) for k, t in jobs))
        return SourceResult(
            source='operator_pivot',
            success=True,
            data={'pivoted': len(results), 'results': results},
        )

    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        """Build summary from all source results."""
        total_mentions = 0
        all_results = []
        all_onions = set()
        ransomware_hits = []
        paste_hits = []
        onion_validation = {}

        for source, res in result.sources.items():
            if not res.success:
                continue
            data = res.data

            count = data.get('result_count', 0)
            total_mentions += count

            # Collect results
            for item in data.get('results', []):
                all_results.append({'source': source, **item})

            # Collect unique .onion addresses
            for addr in data.get('onion_addresses_found', []):
                all_onions.add(addr)

            # Ransomware victim hits
            if source == 'ransomwhat' and data.get('results'):
                ransomware_hits = data['results']

            # Paste site hits
            if source == 'paste_sites' and data.get('results'):
                paste_hits = data['results']

            # Onion validation summary
            if source == 'onion_lookup':
                onion_validation = {
                    'checked': data.get('checked', 0),
                    'online': data.get('online', 0),
                    'offline': data.get('offline', 0),
                    'live_services': [
                        r for r in data.get('results', []) if r.get('online')
                    ],
                }

        summary = {
            'target': result.target,
            'total_mentions': total_mentions,
            'sources_searched': len([s for s in result.sources.values() if s.success]),
            'unique_onion_addresses': list(all_onions)[:10],
            'sample_results': all_results[:15],
            'search_guidance': {
                'tor_browser': 'Download from torproject.org for direct .onion access',
                'verified_links': 'Always get current .onion addresses from dark.fail',
                'safety': 'Use Tor Browser, never provide personal info, use VPN as extra layer',
            },
            'note': 'Results from clearnet indexes. Direct Tor access may reveal more.',
        }

        if ransomware_hits:
            summary['ransomware_exposure'] = {
                'hit_count': len(ransomware_hits),
                'groups_involved': list({h['group'] for h in ransomware_hits}),
                'victims': ransomware_hits[:5],
            }

        if paste_hits:
            summary['paste_exposure'] = {
                'hit_count': len(paste_hits),
                'sample_pastes': paste_hits[:5],
            }

        if onion_validation:
            summary['onion_validation'] = onion_validation

        # Operator de-anonymisation intel from the live onion visit — the headline
        # result for this tool. Surfaced up top so candidate IPs aren't buried.
        live = result.sources.get('target_onion')
        if live and live.success:
            d = live.data
            summary['operator_intel'] = {
                'live_url': d.get('url'),
                'title': d.get('title'),
                'candidate_operator_ips': d.get('candidate_operator_ips'),
                'server_fingerprint': d.get('server_fingerprint'),
                'clock_skew_seconds': d.get('clock_skew_seconds'),
                'clearnet_hosts_referenced': d.get('clearnet_hosts_referenced'),
                'emails': d.get('emails'),
                'crypto': {
                    'bitcoin': d.get('bitcoin_addresses'),
                    'ethereum': d.get('ethereum_addresses'),
                    'monero': d.get('monero_addresses'),
                },
                'analytics_ids': d.get('analytics_ids'),
                'pgp_keys': d.get('pgp_keys'),
                'favicon_shodan': d.get('favicon', {}).get('shodan_matches'),
                'misconfigurations': d.get('misconfigurations'),
            }

        pivot = result.sources.get('operator_pivot')
        if pivot and pivot.success:
            summary['operator_pivots'] = pivot.data.get('results')

        # Evidence graph: typed nodes + confidence-scored edges over the artifacts
        # above. Only attached when a live onion produced something to graph, so a
        # hardened/unreachable target stays quiet. Lazy import avoids a cycle.
        from ..graph import build_graph
        g = build_graph(result)
        if g.nodes:
            summary['evidence_graph'] = g.to_dict()

        return summary
