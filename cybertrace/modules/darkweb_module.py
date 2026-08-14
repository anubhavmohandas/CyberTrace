"""Dark web OSINT module."""

import asyncio
import base64
import hashlib
import ipaddress
import logging
import re
import time
from datetime import datetime
from email.utils import parsedate_to_datetime
from html import unescape
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus, unquote, urljoin, urlsplit, urlunsplit

from ..normalize import (
    NON_ATTRIBUTIVE_SECTIONS, dom_simhash, norm_btc, norm_domain, norm_email,
    norm_eth, norm_onion, norm_pgp, norm_xmr, pgp_certifiers, pgp_signature_issuers,
)
from ..safety import scrub
from .base import BaseModule, ModuleResult, SourceResult

logger = logging.getLogger(__name__)

# Markers that HEAD a quoted block, so they sit above the artifact rather than
# beside it — see _validated, which gives these a wider look-back than any other
# section rule gets.
_QUOTED_LEAD = re.compile(
    r'wrote:|-{2,}\s*(?:original|forwarded)\s+message|in reply to|&gt;\s*&gt;', re.I)
# Those plus the attributions that appear right next to the artifact, for the
# narrow window. One pattern string, so the two windows cannot drift apart.
_QUOTED_NEAR = re.compile(
    _QUOTED_LEAD.pattern + r'|written by|authored by|\bauthor\s*:|all copies', re.I)

# Where on the page an artifact was seen. A BTC address under "donate" is the
# operator's; the same string in passing prose is a mention. Checked against the
# raw HTML window, so class="footer" / id="wallet" count as evidence too.
_SECTION_RULES = (
    # Checked first, because it overrides every rule under it: content the page
    # reproduces rather than authors. A mailing-list archive is the case that
    # forced this — Riseup's list archive quotes a message carrying a script
    # header, `script MICRO-CAL (V4.2) par Amroune Selim (amrounix@gmail.com)`,
    # and that address was minted as an operator artifact, pivoted to a
    # username, and pivoted again to the GitHub and Gravatar of a person with no
    # connection to the site. An address inside quoted content belongs to
    # whoever was quoted. Denylisting Gmail would not have caught it; provenance
    # does. Downstream: evidence.ingest demotes the edge to MENTIONS and
    # _pivot_targets refuses to enrich it.
    ('quoted', _QUOTED_NEAR),
    # Mailing-list membership, for the same reason and with the same effect.
    # Riseup's list manager renders the logged-in user's own address into its
    # menu — `<a href="mailto:honeytroll@riseup.net">` beside a link captioned
    # `subscribers` — and that address was minted as a Riseup operator artifact,
    # pivoted to a username, and pivoted again across 26 social sites. It is a
    # subscriber of a list the site hosts. Naming the roster VOCABULARY is what
    # separates it from the operator's own `abuse@` on the same page; nothing
    # about the address itself does.
    # occam: the ±70 window below, unlike 'quoted'. A roster heading further up
    # than that is missed; widening it would demote genuine contact addresses on
    # any page that also happens to mention a list. Upgrade to DOM ancestry with
    # the quoted rule if list pages start leaking members again.
    ('roster', re.compile(
        r'subscriber|subscribed\s+to|list[-_](?:user|admin)|your_lists|login_menu'
        r'|list\s+(?:owner|member|moderator)|roster', re.I)),
    ('wallet', re.compile(r'wallet|donate|payment|deposit|escrow|bitcoin|monero', re.I)),
    ('contact', re.compile(r'contact|support|abuse|admin|reach us', re.I)),
    ('pgp', re.compile(r'pgp|gpg|public key|signature', re.I)),
    ('footer', re.compile(r'footer|copyright|&copy;|©|terms', re.I)),
)

# Surroundings that make a regex hit not an artifact at all, whatever it
# validates as. Decided from what is AROUND the match, never from the value:
# both families below are generated strings, so a denylist would have to name
# Reddit's Sentry key and every icon path in advance and would still miss the
# next one. The shape is the tell, and the shape is in the context.

# `https://<key>@<host>/…` — the userinfo of a URL authority is a credential,
# not a mailbox. Reddit's Sentry DSN minted
# `9f057df6115a4bb488c08ea12a835e6e@error-tracking.<onion>` as an EMAIL, one
# pivot short of a keyserver lookup on an address nobody can receive mail at.
# The character class stops at quotes and angle brackets, so an ordinary
# `<a href="https://x.com">mail@x.com</a>` is untouched.
_URL_USERINFO = re.compile(r'[a-z][a-z0-9+.\-]*://[^\s"\'<>]*$', re.I)

# A dotted quad that is one slice of a longer dotted-numeric run, or that
# follows a version marker, is not an address. Measured: Reddit's page carries
# the SVG path `c0 .5.4.9.9.9h14.2`, out of which `5.4.9.9` was extracted,
# enriched through the ip module into a Telefonica DSL line, and offered as the
# market's candidate operator IP — a real subscriber's address attached to a
# site they have nothing to do with.
_DOTTED_QUAD = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}')
_VERSION_LEAD = re.compile(
    r'\.$'                                   # mid-run: `.5.4.9.9`
    r'|[A-Za-z]/$'                           # `PHP/5.4.9.9` — not `http://1.2.3.4`
    r'|\b(?:version|ver|release|build|rev|sdk)\b[^\w]{0,3}$', re.I)
_VERSION_TAIL = re.compile(r'^\.\d')         # `5.4.9.9.9h` — the run continues


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
            # Through run_sources for its progress row: probing every discovered
            # onion over Tor can outlast phases 0-5 combined.
            await self.run_sources(
                [('onion_lookup', self._search_onion_lookup(list(discovered_onions)))],
                result,
            )

        # Phase 7: Auto-pivot operator artifacts (emails, crypto) found on the
        # live onion into their own modules for a one-command operator profile.
        live = result.sources.get('target_onion')
        if live and live.success:
            # Returns None when there are no artifacts to pivot; run_sources
            # drops a None rather than recording a phantom failed source.
            await self.run_sources(
                [('operator_pivot', self._pivot_operator_artifacts(live.data))],
                result,
            )

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

    # Bounded same-onion crawl. Budget is wall-clock for the whole crawl; each
    # request is separately capped by config.request_timeout.
    MAX_CRAWL_PAGES = 8
    MAX_CRAWL_DEPTH = 2
    CRAWL_BUDGET_SECONDS = 180
    _RE_HREF = re.compile(r'''href\s*=\s*["']([^"'>]+)''', re.I)
    _SKIP_EXT = re.compile(
        r'\.(?:png|jpe?g|gif|svg|ico|css|js|pdf|zip|gz|7z|exe|mp4|webm|woff2?)$', re.I)
    # Crawled before generic pages: this is where operators put the artifacts.
    _PRIORITY_PATH = re.compile(
        r'contact|pgp|gpg|key|about|vendor|profile|support|faq|rule|help|abuse'
        r'|donat|payment|wallet', re.I)

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
            before, after = html[max(0, m.start() - 70):m.start()], html[m.end():m.end() + 70]
            # Context gate, before validation: these two shapes normalize
            # perfectly well and are still not artifacts. See _URL_USERINFO and
            # _DOTTED_QUAD for the captures that forced each.
            if '@' in raw and _URL_USERINFO.search(before):
                continue
            if _DOTTED_QUAD.fullmatch(raw) and (_VERSION_LEAD.search(before)
                                                or _VERSION_TAIL.match(after)):
                continue
            if normalizer(raw) is None:
                continue
            # Classify on the surroundings only: 'admin@x.com' in a footer is a
            # footer artifact, and letting the value match its own section rule
            # would relabel it 'contact' on the strength of its local-part.
            around = f"{before} {after}"
            # 'quoted' is the one rule that gets a wider look-back. A quote
            # marker heads the block it introduces — `On <date>, X wrote:`, an
            # opening <blockquote> — so it sits above the address rather than
            # beside it, and ±70 would only catch a quoted address by luck. The
            # other rules keep the narrow window on purpose: a `donate` heading
            # 500 chars up says nothing about the address down here.
            # occam: 600-char look-back, and an open <blockquote> is detected by
            # comparing the last opening tag to the last closing one rather than
            # by parsing. A quote that opened further up than that is missed.
            # Upgrade to real DOM ancestry if quoted artifacts still get through.
            section = next((n for n, rx in _SECTION_RULES if rx.search(around)), 'body')
            lead = html[max(0, m.start() - 600):m.start()]
            if section != 'quoted' and (_QUOTED_LEAD.search(lead)
                                        or lead.rfind('<blockquote') > lead.rfind('</blockquote')):
                section = 'quoted'
            evidence[raw] = {
                'section': section,
                'context': re.sub(
                    r'\s+', ' ', re.sub(r'<[^>]+>', ' ', f"{before}{raw}{after}")).strip()[:200],
            }
            values.append(raw)
        return sorted(values), evidence

    @staticmethod
    def _extract_pgp_keys(html: str) -> List[Dict[str, Any]]:
        """Capture armored PGP public keys on the page, each with its role.

        The id is the true OpenPGP fingerprint (normalize.pgp_fingerprint parses
        the packets), which is what makes a shared key the strongest cross-market
        signal in the graph: a clone re-exporting a copied key changes every byte
        of the armor but never the fingerprint. Keyserver lookup of the
        operator's identities happens on the email pivot
        (email_module._check_pgp_keyservers).

        Role is the part that survives cloning. "A key block is on the page" is
        exactly what a copycat reproduces; a *signature* on the page issued by
        that key is not, because it needs the secret half. So a key is recorded
        as SIGNING when the page also carries a signature it issued, and
        otherwise by where it was published (contact block, payment block, or
        merely displayed). evidence.ingest turns SIGNING into a different edge
        type, and the clone guard reads it before calling shared use shared
        control.
        """
        # occam: keys the parser can't read (v3, truncated armor) fall back to a
        # payload hash — still stable for identical exports, just not re-export
        # proof. Upgrade: extend normalize._packets if v3 keys ever show up.
        issuers = {i.upper() for i in pgp_signature_issuers(html)}
        seen: Dict[str, Dict[str, Any]] = {}
        for m in DarkwebModule._RE_PGP.finditer(html):
            payload = re.sub(r'\s+', '', ''.join(
                ln for ln in m.group(1).splitlines() if ':' not in ln
            ))
            if len(payload) < 64:  # too short to be a real key block
                continue
            block = m.group(0)
            fpr = norm_pgp(block)
            around = f"{html[max(0, m.start() - 160):m.start()]} {html[m.end():m.end() + 160]}"
            section = next((n for n, rx in _SECTION_RULES if rx.search(around)), 'body')
            if fpr:
                bare = fpr.removeprefix('PGP:')
                record: Dict[str, Any] = {'key_id': fpr, 'fingerprint': bare,
                                          'certifiers': pgp_certifiers(block)}
                signed = bool(issuers & {bare, bare[-16:]})
            else:
                record = {'key_id': hashlib.sha256(payload.encode()).hexdigest()[:16]}
                signed = False
            record['role'] = ('signing' if signed else
                              {'wallet': 'payment', 'contact': 'contact',
                               'pgp': 'displayed'}.get(section, 'displayed'))
            record['section'] = section
            seen.setdefault(record['key_id'], record)
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

    @staticmethod
    def _norm_public_ipv4(value: str) -> Optional[str]:
        """One routable public IPv4 or None — the per-value half of
        _public_ipv4, so contextual extraction can use it as a normalizer."""
        return (DarkwebModule._public_ipv4([value]) or [None])[0]

    @classmethod
    def _public_ipv4_in(cls, text: str) -> Tuple[List[str], Dict[str, Dict[str, str]]]:
        """Public IPv4 in some text, gated on context like every other artifact.

        A bare `findall` here is what let SVG path coordinates become a leaked
        operator IP: an address is the one artifact class with no checksum to
        fail, so where it was seen is the ONLY validation available. Routing it
        through _validated also earns it a section and a context snippet, which
        is what stops a quoted or roster address reaching the ip-module pivot.
        """
        return cls._validated(text, cls._RE_IPV4, cls._norm_public_ipv4)

    async def _fetch_full(self, url: str) -> Tuple[Optional[int], Dict[str, str], str]:
        """Fetch url (.onion auto-routes through Tor) returning status, headers,
        text. Unlike fetch(), this preserves response headers — needed for the
        server fingerprint and clock-skew signals. Returns (None, {}, '') on error."""
        try:
            session = await self._session_for(url)
            async with session.request('GET', url, allow_redirects=False) as resp:
                # scrub, not fetch()'s: this path keeps headers, so it bypasses
                # the base helper and needs the content gate applied here too.
                text = scrub(await resp.text(errors='ignore'), url)
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

    async def _tor_socks_up(self) -> bool:
        """True if something is listening on the configured Tor SOCKS port.
        Separates 'Tor is down' from 'the onion is down' — opposite conclusions
        for the analyst, and the fetch error alone can't tell them apart."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.tor.socks_host,
                                        self.config.tor.socks_port),
                timeout=3,
            )
            writer.close()
            return True
        except Exception:
            return False

    @classmethod
    def _same_onion_links(cls, page_url: str, html: str, onion_host: str) -> List[str]:
        """Links on the page that stay on THIS onion host, absolute and deduped.

        Leaving the host would attribute another site's emails and wallets to
        this operator, which is exactly the false link the evidence model exists
        to prevent — so the host check is the gate, not a filter to relax.
        """
        links: List[str] = []
        for href in cls._RE_HREF.findall(html):
            href = href.strip().replace('&amp;', '&')
            if not href or href.startswith(('mailto:', 'javascript:', 'tel:', 'data:', '#')):
                continue
            parts = urlsplit(urljoin(page_url, href))
            if parts.scheme not in ('http', 'https'):
                continue
            if (parts.hostname or '') != onion_host:
                continue
            if cls._SKIP_EXT.search(parts.path):
                continue
            # Fragment dropped: /vendor and /vendor#top are one page, one fetch.
            links.append(urlunsplit(('http', onion_host, parts.path or '/', parts.query, '')))
        return list(dict.fromkeys(links))

    async def _crawl_pages(self, base: str, onion_host: str,
                           root_html: str) -> List[Tuple[str, int, str]]:
        """Breadth-first crawl of the target's own pages. Returns (url, status, html).

        Fetching only "/" is why sparse landings and login walls looked like
        artifact-free sites: the contact, vendor, rules and PGP pages are where
        the operator's email, wallet and key actually live.
        """
        # occam: sequential fetches — one Tor circuit, in-order BFS, and a slow
        # hidden service is the bottleneck anyway. Parallelise per depth level
        # only if crawl time becomes the limit on corpus size.
        seen = {f"{base}/"}
        frontier = [(u, 1) for u in self._same_onion_links(f"{base}/", root_html, onion_host)]
        deadline = time.monotonic() + self.CRAWL_BUDGET_SECONDS
        out: List[Tuple[str, int, str]] = []

        while frontier and len(out) < self.MAX_CRAWL_PAGES - 1:
            if time.monotonic() > deadline:
                logger.debug("crawl budget spent on %s after %d pages", onion_host, len(out))
                break
            # Shallow first, artifact-bearing paths ahead of generic ones: the
            # page budget is normally much smaller than the site.
            frontier.sort(key=lambda p: (p[1], not self._PRIORITY_PATH.search(p[0])))
            url, depth = frontier.pop(0)
            if url in seen:
                continue
            seen.add(url)
            status, _headers, html = await self._fetch_full(url)
            if status is None or not html:
                continue          # unreachable, or a bodyless redirect to a login
            out.append((url, status, html))
            if depth < self.MAX_CRAWL_DEPTH:
                frontier.extend(
                    (u, depth + 1)
                    for u in self._same_onion_links(url, html, onion_host)
                    if u not in seen
                )
        return out

    def _extract_artifacts(self, html: str, onion_host: str) -> Dict[str, Any]:
        """Operator artifacts on one page. Every value is gated by its normalizer
        (base58check, bech32, RFC-shaped mail) so only things that actually
        validate can become graph entities."""
        # BTC matches that are really a slice of an onion address (base32 overlaps
        # base58) are excluded before validation.
        onion_tokens = ''.join(self._RE_ONION.findall(html))
        btc, ev_btc = self._validated(html, self._RE_BTC, norm_btc, exclude=onion_tokens)
        emails, ev_email = self._validated(html, self._RE_EMAIL, norm_email)
        eth, ev_eth = self._validated(html, self._RE_ETH, norm_eth)
        xmr, ev_xmr = self._validated(html, self._RE_XMR, norm_xmr)
        ips, ev_ip = self._public_ipv4_in(html)
        return {
            'emails': emails,
            'bitcoin_addresses': btc,
            'ethereum_addresses': eth,
            'monero_addresses': xmr,
            'analytics_ids': sorted(set(self._RE_ANALYTICS.findall(html))),
            'pgp_keys': self._extract_pgp_keys(html),
            # norm_domain rejects onions and anything that isn't a real hostname.
            'clearnet_hosts_referenced': sorted({
                d for d in (norm_domain(h) for h in self._RE_URL.findall(html)) if d
            }),
            'onion_addresses_found': [
                a for a in dict.fromkeys(norm_onion(x) for x in self._RE_ONION.findall(html))
                if a and a != onion_host
            ],
            'leaked_public_ipv4': ips,
            'artifact_evidence': {**ev_btc, **ev_email, **ev_eth, **ev_xmr, **ev_ip},
        }

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
        url = f"{base}/"
        status, headers, html = await self._fetch_full(url)

        # _fetch_full keeps allow_redirects=False because the misconfig probes
        # need to tell "not exposed" from "bounced to a login". The target's own
        # front page is the one place the destination is what we came for, and a
        # redirect is how the big clearnet-backed onions actually serve: Reddit
        # answers http://<addr> with 307 -> https://<addr>, then 301 ->
        # https://www.<addr>, then 302 -> the page. Unfollowed, that captures a
        # 168-byte redirect stub and reports it as a live site with no
        # artifacts, which is worse than an error because it reads as a real
        # capture of a site that publishes nothing.
        #
        # Never off this onion, though. A Location pointing at clearnet is a
        # request we must not make: it would leave Tor for a host the target
        # chose, which is a deanonymising fetch, not a redirect. Any vhost of
        # the same 56-char address is fine — that is still one hidden service,
        # and it is exactly where these redirects lead.
        for _ in range(4):
            if status not in (301, 302, 303, 307, 308):
                break
            parts = urlsplit(urljoin(url, headers.get('Location', '')))
            if parts.scheme not in ('http', 'https') or \
                    '.'.join((parts.hostname or '').split('.')[-2:]) != onion_host:
                break
            url = urlunsplit(parts)
            base = f"{parts.scheme}://{parts.netloc}"
            status, headers, html = await self._fetch_full(url)

        if status is None:
            socks = f'{self.config.tor.socks_host}:{self.config.tor.socks_port}'
            return SourceResult(
                source='target_onion',
                success=False,
                error=(
                    f'Onion unreachable via Tor ({socks} is up) — the site is '
                    'down, gone, or refusing us.'
                    if await self._tor_socks_up() else
                    f'Tor is NOT running — nothing listening on {socks}. '
                    'Start Tor and retry; this says nothing about the target.'
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

        # Crawl the site's own pages before extracting: a login wall or a sparse
        # landing page otherwise reports an artifact-free operator.
        pages = [(f"{base}/", status, html)] + \
            await self._crawl_pages(base, onion_host, html)

        agg: Dict[str, List[str]] = {
            k: [] for k in (
                'emails', 'bitcoin_addresses', 'ethereum_addresses', 'monero_addresses',
                'analytics_ids', 'clearnet_hosts_referenced', 'onion_addresses_found',
                'leaked_public_ipv4',
            )
        }
        pgp_keys: Dict[str, Dict[str, str]] = {}
        artifact_evidence: Dict[str, Dict[str, str]] = {}
        page_records: List[Dict[str, Any]] = []

        for page_url, page_status, page_html in pages:
            found = self._extract_artifacts(page_html, onion_host)
            for key, values in agg.items():
                values.extend(v for v in found[key] if v not in values)
            for key in found['pgp_keys']:
                pgp_keys.setdefault(key['key_id'], key)
            path = urlsplit(page_url).path or '/'
            # First sighting wins: the page an artifact was published on, not the
            # last page that happened to repeat it in a nav bar or footer.
            for raw, where in found['artifact_evidence'].items():
                artifact_evidence.setdefault(raw, {**where, 'page': path})
            page_title = self._RE_TITLE.search(page_html)
            page_records.append({
                'url': page_url,
                'path': path,
                'status': page_status,
                'bytes': len(page_html),
                'title': page_title.group(1).strip()[:120] if page_title else '',
                # Forensic anchor per page, not per site: an artifact that
                # appeared on /contact for one crawl and vanished on the next is
                # provable against this hash alone. The raw HTML is not retained
                # (it is hostile content), so the digest is what remains.
                'sha256': hashlib.sha256(page_html.encode('utf-8', 'ignore')).hexdigest(),
                # Template identity, independent of wording — see
                # normalize.dom_simhash. This is what the clone guard compares.
                'dom_simhash': dom_simhash(page_html),
                'artifacts': {k: len(v) for k, v in found.items()
                              if k != 'artifact_evidence' and v},
            })

        # Sorted so a re-crawl in a different order still hashes to the same
        # snapshot — evidence.insert_snapshot diffs on the canonical payload.
        clearnet_hosts = sorted(agg['clearnet_hosts_referenced'])
        emails = sorted(agg['emails'])
        btc = sorted(agg['bitcoin_addresses'])
        eth = sorted(agg['ethereum_addresses'])
        xmr = sorted(agg['monero_addresses'])
        analytics = sorted(agg['analytics_ids'])
        onion_links = sorted(agg['onion_addresses_found'])

        # Leaked public IPv4 in headers or any crawled body — a real-host slip.
        header_blob = ' '.join(str(v) for v in headers.values())
        header_ips, ev_header_ip = self._public_ipv4_in(header_blob)
        artifact_evidence.update(
            {ip: {**where, 'page': 'response headers'}
             for ip, where in ev_header_ip.items() if ip not in artifact_evidence})
        leaked_ips = sorted(set(agg['leaked_public_ipv4']) | set(header_ips))

        # Misconfig probes + favicon/Shodan pivot (each best-effort).
        misconfigs = await self._probe_misconfigs(base)
        favicon = await self._favicon_pivot(base, html)

        candidate_ips = sorted(
            set(leaked_ips)
            | {m['ip'] for m in favicon.get('shodan_matches', []) if m.get('ip')}
            | {ip for mc in misconfigs for ip in mc.get('leaked_ips', [])}
        )

        return SourceResult(
            source='target_onion',
            success=True,
            data={
                'online': True,
                'url': f"{base}/",
                'http_status': status,
                'title': title,
                'page_bytes': len(html),
                'pages_fetched': len(pages),
                # Per-page provenance: which URL each artifact class came from.
                # Lands in the target_onion snapshot, so a leak that appeared on
                # one crawl and vanished on the next is provable per page.
                'pages': page_records,
                'server_fingerprint': fingerprint,
                'clock_skew_seconds': clock_skew,
                'clearnet_hosts_referenced': clearnet_hosts[:40],
                'emails': emails[:20],
                'bitcoin_addresses': btc[:20],
                'ethereum_addresses': eth[:20],
                'monero_addresses': xmr[:20],
                'analytics_ids': analytics[:20],
                'pgp_keys': list(pgp_keys.values()),
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
                    'leaked_ips': self._public_ipv4_in(body)[0],
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

        # dark.fail lists each service as a heading that links to its own
        # verification page, with the addresses below it in <code> blocks:
        #
        #     <h4><a href="/riseup">Riseup</a></h4> ... <code>http://vww6...onion</code>
        #
        # The heading href is a relative path, never the onion, so the
        # anchor-href pattern below matches nothing on this site — it returned
        # zero services for every run until this was measured against the live
        # page. Splitting on the headings and reading the addresses out of the
        # section each one owns is what actually pairs a name to an address.
        sections = re.split(r'<h4><a href="[^"]*">([^<]+)</a></h4>', html)
        for i in range(1, len(sections) - 1, 2):
            name = self._clean_scraped_name(unescape(sections[i]))
            onions = re.findall(r'<code>[^<]*?([a-z2-7]{56}\.onion)', sections[i + 1])
            if name and onions:
                services[name] = onions[0]          # first is the primary address

        # Kept as the fallback for layouts that do link straight to the onion.
        # Only anchor tags: an earlier unanchored proximity pattern matched
        # across the whole document and captured '<!DOCTYPE html>' as a name.
        for onion, name in re.findall(
                r'<a[^>]+href="[^"]*?([a-z2-7]{56}\.onion)[^"]*"[^>]*>([^<]+)</a>',
                html, re.IGNORECASE):
            clean_name = self._clean_scraped_name(unescape(name))
            if clean_name:
                services.setdefault(clean_name, onion)

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
        # Artifacts belonging to somebody else — quoted third-party content, a
        # list subscriber — are never enriched. Enrichment is the step that
        # turns a string into a named person (keyserver, GitHub, Gravatar), so
        # they have to be stopped before it, not scored down after. See
        # _SECTION_RULES and normalize.NON_ATTRIBUTIVE_SECTIONS.
        borrowed = {v for v, where in (data.get('artifact_evidence') or {}).items()
                    if where.get('section') in NON_ATTRIBUTIVE_SECTIONS}
        own_emails = [e for e in (data.get('emails') or []) if e not in borrowed]
        emails = own_emails[:cap]
        crypto = [
            c for c in (data.get('bitcoin_addresses') or [])
            + (data.get('ethereum_addresses') or []) if c not in borrowed
        ][:cap]
        # IPs carry evidence too now that they are extracted contextually, so an
        # address read out of a quoted mail header gets the same refusal.
        ips = [i for i in (data.get('candidate_operator_ips') or [])
               if i not in borrowed][:cap]
        usernames = DarkwebModule._usernames_from_emails(own_emails)[:cap]
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
                'pages_fetched': d.get('pages_fetched'),
                'pages': d.get('pages'),
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
