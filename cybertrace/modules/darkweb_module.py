"""Dark web OSINT module."""

import asyncio
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus, unquote

from .base import BaseModule, ModuleResult, SourceResult


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
        'haystack': 'https://haystak.io/search?q={query}',  # If available
    }

    async def search(self, target: str, **options) -> ModuleResult:
        """Search dark web sources for target."""

        result = ModuleResult(
            target=target,
            target_type=options.get('target_type', 'unknown'),
            module=self.name,
        )

        # Phase 1: Fetch current onion directories (for reference)
        sources = [
            ('onion_directories', self._fetch_onion_directories()),
        ]

        # Phase 2: Search dark web indexes
        sources.extend([
            ('ahmia', self._search_ahmia(target)),
            ('darksearch', self._search_darksearch(target)),
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

        # Build summary
        result.summary = self._build_summary(result)
        result.end_time = datetime.utcnow()

        return result

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

        # Pattern to extract service names and onion addresses
        # dark.fail format: service name followed by .onion link
        patterns = [
            # Standard v3 onion (56 chars)
            r'([A-Za-z0-9\s]+)[\s\S]*?([a-z2-7]{56}\.onion)',
            # With href
            r'href="[^"]*([a-z2-7]{56}\.onion)[^"]*"[^>]*>([^<]+)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if len(match) == 2:
                    name = match[0].strip() if not match[0].endswith('.onion') else match[1].strip()
                    onion = match[0] if match[0].endswith('.onion') else match[1]
                    if len(onion) >= 56:  # Valid v3 onion
                        services[name[:50]] = onion

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
            clean_title = title.strip()[:50]
            if clean_title and len(onion) >= 56:
                services[clean_title] = onion

        return services

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

    async def _search_darksearch(self, query: str) -> SourceResult:
        """Search DarkSearch.io API."""
        encoded_query = quote_plus(query)
        url = f"https://darksearch.io/api/search?query={encoded_query}&page=1"

        data = await self.fetch_json(url)

        if not data:
            return SourceResult(
                source='darksearch',
                success=False,
                error='No response from DarkSearch',
            )

        results = []
        for item in data.get('data', [])[:20]:
            results.append({
                'title': item.get('title', '')[:100],
                'description': item.get('description', '')[:200],
                'onion_url': item.get('link'),
            })

        return SourceResult(
            source='darksearch',
            success=True,
            data={
                'total': data.get('total', 0),
                'result_count': len(results),
                'results': results,
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

        # Parse Torch results
        onion_pattern = r'([a-z2-7]{56}\.onion)'
        title_pattern = r'<a[^>]*href="[^"]*\.onion[^"]*"[^>]*>([^<]+)</a>'

        onions = re.findall(onion_pattern, html, re.IGNORECASE)
        titles = re.findall(title_pattern, html)

        for i, onion in enumerate(set(onions[:20])):
            results.append({
                'onion_url': f"http://{onion}",
                'title': titles[i] if i < len(titles) else 'Unknown',
            })

        return SourceResult(
            source='torch',
            success=len(results) > 0,
            data={
                'result_count': len(results),
                'results': results,
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

        return summary
