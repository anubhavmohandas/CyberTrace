"""Breach and paste intelligence OSINT module.

Searches breach databases, paste sites, and leak indexes for a given
email, username, phone, or domain target.

Sources (no key required):
- BreachDirectory (free public API)
- PSBDMP paste search (free public API)

Sources (API key required):
- HaveIBeenPwned v3 (hibp key — paid, ~$4/month)
- LeakCheck (leakcheck key — free tier 10/day)
- IntelligenceX (intelx key — free or paid tier)
"""

import asyncio
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

from .base import BaseModule, ModuleResult, SourceResult


class BreachModule(BaseModule):
    """
    Breach, paste, and leak intelligence across multiple data sources.

    SUCCESS RATE: 75% — free sources cover paste/breach directory lookups.
    HIBP and IntelX significantly improve coverage when keys are present.

    Supported target types:
    - email     — full breach + paste search
    - username  — paste + IntelX search
    - phone     — paste + IntelX search
    - domain    — breach directory + paste + IntelX search
    """

    name = "breach"
    description = "Breach database, paste, and leak intelligence"
    supported_types = {'email', 'username', 'phone', 'domain'}

    async def search(self, target: str, **options) -> ModuleResult:
        """
        Search breach sources for the given target.

        Args:
            target: Email, username, phone number, or domain string.
            **options: Accepts 'target_type' override.

        Returns:
            ModuleResult with per-source breach/paste findings and aggregate summary.
        """
        target_type = options.get('target_type', 'email')
        normalized = target.strip().lower()

        result = ModuleResult(
            target=normalized,
            target_type=target_type,
            module=self.name,
        )

        sources: List[tuple] = []

        # ── Email-specific sources ────────────────────────────────────────
        if target_type == 'email':
            sources.append(('breach_directory', self._check_breach_directory(normalized)))

            if self.config.api_keys.has('hibp'):
                sources.append(('hibp', self._check_hibp(normalized)))

            if self.config.api_keys.has('leakcheck'):
                sources.append(('leakcheck', self._check_leakcheck(normalized)))

        # ── Universal sources (work on any target type) ───────────────────
        sources.append(('psbdmp', self._check_psbdmp(normalized)))

        if self.config.api_keys.has('intelx'):
            sources.append(('intelx', self._check_intelx(normalized)))

        await self.run_sources(sources, result)

        result.summary = self._build_summary(result)
        result.end_time = datetime.utcnow()

        return result

    # ------------------------------------------------------------------ #
    # Sources                                                              #
    # ------------------------------------------------------------------ #

    async def _check_hibp(self, email: str) -> SourceResult:
        """
        HaveIBeenPwned v3 breach check.

        Requires a paid API key (hibp). The k-anonymity password endpoint
        at api.pwnedpasswords.com checks passwords, NOT email addresses,
        so we only run this source when a key is present.

        Docs: https://haveibeenpwned.com/API/v3#BreachesForAccount
        """
        api_key = self.config.api_keys.get('hibp')
        if not api_key:
            return SourceResult(source='hibp', success=False, error='No HIBP API key')

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}"
        headers = {
            'hibp-api-key': api_key,
            'User-Agent': 'CyberTrace OSINT Tool',
        }

        # fetch_json only ever treats status==200 as success, and HIBP's 404
        # (email not found in any breach) is itself a valid, billable result —
        # so this uses fetch() with an explicit ok_statuses to see both.
        raw_text = await self.fetch(url, headers=headers, retries=1, ok_statuses=(200, 404))

        if raw_text is None:
            return SourceResult(source='hibp', success=False, error='No response from HIBP')

        import json
        try:
            parsed_data = json.loads(raw_text)
        except (json.JSONDecodeError, ValueError):
            # 404 returns no body — email not found in any breach
            return SourceResult(
                source='hibp',
                success=True,
                data={'found': False, 'breach_count': 0, 'breaches': []},
            )

        if not isinstance(parsed_data, list):
            return SourceResult(
                source='hibp',
                success=True,
                data={'found': False, 'breach_count': 0, 'breaches': []},
            )

        breaches = []
        for b in parsed_data:
            breaches.append({
                'name': b.get('Name'),
                'title': b.get('Title'),
                'domain': b.get('Domain') or None,
                'breach_date': b.get('BreachDate') or None,
                'added_date': b.get('AddedDate') or None,
                'pwn_count': b.get('PwnCount'),
                'data_classes': b.get('DataClasses', []),
                'is_verified': b.get('IsVerified', False),
                'is_sensitive': b.get('IsSensitive', False),
                'is_spam_list': b.get('IsSpamList', False),
                'has_password_data': 'Passwords' in (b.get('DataClasses') or []),
            })

        return SourceResult(
            source='hibp',
            success=True,
            data={
                'found': True,
                'breach_count': len(breaches),
                'breaches': breaches,
                'has_password_data': any(b['has_password_data'] for b in breaches),
            },
        )

    async def _check_breach_directory(self, email: str) -> SourceResult:
        """
        BreachDirectory public API — free, no key required.

        Returns breach names and partial credential hints where this
        email/username appeared.

        API: https://breachdirectory.org/api
        """
        url = f"https://breachdirectory.org/api?func=auto&term={quote_plus(email)}"
        headers = {'User-Agent': 'CyberTrace OSINT Research Tool'}

        data = await self.fetch_json(url, headers=headers, retries=1)

        if not data:
            return SourceResult(
                source='breach_directory',
                success=False,
                error='No response from BreachDirectory',
            )

        if not data.get('success'):
            return SourceResult(
                source='breach_directory',
                success=True,
                data={'found': False, 'breach_count': 0, 'breaches': []},
            )

        results = data.get('result', [])
        breaches: List[Dict[str, Any]] = []
        has_password_data = False

        for entry in results[:30]:
            sources_list = entry.get('sources', [])
            if not isinstance(sources_list, list):
                sources_list = [sources_list] if sources_list else []

            has_pw = bool(entry.get('password') or entry.get('sha1'))
            if has_pw:
                has_password_data = True

            breaches.append({
                'sources': sources_list,
                'has_password': has_pw,
                'sha1_partial': entry.get('sha1') or None,
            })

        return SourceResult(
            source='breach_directory',
            success=True,
            data={
                'found': True,
                'breach_count': len(results),
                'breaches': breaches,
                'has_password_data': has_password_data,
            },
        )

    async def _check_leakcheck(self, email: str) -> SourceResult:
        """
        LeakCheck.io public API — free tier: 10 queries/day with key.

        Docs: https://leakcheck.io/api
        """
        api_key = self.config.api_keys.get('leakcheck')
        if not api_key:
            return SourceResult(
                source='leakcheck',
                success=False,
                error='No LeakCheck API key',
            )

        url = f"https://leakcheck.io/api/public?key={api_key}&check={quote_plus(email)}"
        headers = {'User-Agent': 'CyberTrace OSINT Tool'}

        data = await self.fetch_json(url, headers=headers, retries=1)

        if not data:
            return SourceResult(
                source='leakcheck',
                success=False,
                error='No response from LeakCheck',
            )

        if not data.get('success'):
            msg = data.get('error', 'Unknown error')
            # "Not found" is a valid response
            if 'not found' in str(msg).lower():
                return SourceResult(
                    source='leakcheck',
                    success=True,
                    data={'found': False, 'breach_count': 0},
                )
            return SourceResult(source='leakcheck', success=False, error=msg)

        raw_sources = data.get('sources', [])
        sources_parsed: List[Dict[str, Any]] = []
        has_password_data = False

        for src in raw_sources:
            if isinstance(src, dict):
                has_pw = bool(src.get('password'))
                if has_pw:
                    has_password_data = True
                sources_parsed.append({
                    'name': src.get('name'),
                    'date': src.get('date') or None,
                    'unverified': src.get('unverified', False),
                    'has_password': has_pw,
                })
            elif isinstance(src, str):
                sources_parsed.append({'name': src})

        return SourceResult(
            source='leakcheck',
            success=True,
            data={
                'found': bool(sources_parsed),
                'breach_count': len(sources_parsed),
                'sources': sources_parsed,
                'has_password_data': has_password_data,
            },
        )

    async def _check_psbdmp(self, query: str) -> SourceResult:
        """
        PSBDMP paste search — free, no key required.

        Indexes Pastebin, GitHub Gist, and other paste sites.
        API: https://psbdmp.ws/api/v3/search/{query}
        """
        encoded = quote_plus(query)
        url = f"https://psbdmp.ws/api/v3/search/{encoded}"

        data = await self.fetch_json(url, retries=1)

        if not data:
            return SourceResult(
                source='psbdmp',
                success=False,
                error='No response from PSBDMP',
            )

        items = data if isinstance(data, list) else data.get('data', [])

        pastes: List[Dict[str, Any]] = []
        for item in items[:25]:
            paste_id = item.get('id', '')
            pastes.append({
                'id': paste_id,
                'url': f"https://pastebin.com/{paste_id}" if paste_id else None,
                'tags': item.get('tags', ''),
                'length': item.get('length', 0),
                'time': item.get('time', ''),
            })

        return SourceResult(
            source='psbdmp',
            success=True,
            data={
                'found': len(pastes) > 0,
                'paste_count': len(pastes),
                'pastes': pastes,
            },
        )

    async def _check_intelx(self, query: str) -> SourceResult:
        """
        IntelligenceX phonebook/breach search.

        Targets breach and paste content specifically. Uses the intelligent
        search endpoint (deeper than phonebook) to surface full records.

        Requires intelx API key.
        """
        api_key = self.config.api_keys.get('intelx')
        if not api_key:
            return SourceResult(source='intelx', success=False, error='No IntelX API key')

        search_url = "https://2.intelx.io/intelligent/search"
        headers = {
            'x-key': api_key,
            'Content-Type': 'application/json',
        }
        payload = {
            'term': query,
            'maxresults': 20,
            'media': 0,
            'target': 0,         # all buckets
            'timeout': 10,
            'datefrom': '',
            'dateto': '',
            'sort': 2,           # date desc
            'terminate': [],
        }

        search_data = await self.fetch_json(
            search_url, method='POST', json=payload, headers=headers
        )

        if not search_data or not search_data.get('id'):
            return SourceResult(
                source='intelx',
                success=False,
                error='IntelX search initiation failed',
            )

        search_id = search_data['id']

        # Wait for IntelX to process the search (async indexer)
        await asyncio.sleep(3)

        results_url = (
            f"https://2.intelx.io/intelligent/search/result"
            f"?id={search_id}&limit=20&offset=0"
        )
        result_data = await self.fetch_json(results_url, headers=headers)

        if not result_data:
            return SourceResult(
                source='intelx',
                success=False,
                error='IntelX results fetch failed',
            )

        records = result_data.get('records', [])

        if not records:
            return SourceResult(
                source='intelx',
                success=True,
                data={'found': False, 'result_count': 0, 'records': []},
            )

        parsed_records: List[Dict[str, Any]] = []
        for rec in records[:15]:
            parsed_records.append({
                'name': rec.get('name'),
                'date': rec.get('date'),
                'type': rec.get('type'),
                'bucket': rec.get('bucket'),
                'media': rec.get('media'),
                'storageid': rec.get('storageid'),
            })

        return SourceResult(
            source='intelx',
            success=True,
            data={
                'found': True,
                'result_count': len(records),
                'records': parsed_records,
            },
        )

    # ------------------------------------------------------------------ #
    # Summary                                                              #
    # ------------------------------------------------------------------ #

    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            'target': result.target,
            'total_breach_count': 0,
            'in_breach_db': False,
            'has_password_data': False,
            'paste_hits': 0,
            'intelx_hits': 0,
            'sources_with_data': [],
        }

        breach_counts: List[int] = []

        # ── HIBP ──────────────────────────────────────────────────────────
        hibp = result.sources.get('hibp')
        if hibp and hibp.success and hibp.data.get('found'):
            count = hibp.data.get('breach_count', 0)
            breach_counts.append(count)
            summary['in_breach_db'] = True
            summary['sources_with_data'].append('hibp')
            summary['hibp_breach_count'] = count
            if hibp.data.get('has_password_data'):
                summary['has_password_data'] = True
            # Surface breach names as related targets
            for b in hibp.data.get('breaches', [])[:5]:
                if b.get('domain'):
                    result.related.append(b['domain'])

        # ── BreachDirectory ───────────────────────────────────────────────
        bd = result.sources.get('breach_directory')
        if bd and bd.success and bd.data.get('found'):
            count = bd.data.get('breach_count', 0)
            breach_counts.append(count)
            summary['in_breach_db'] = True
            summary['sources_with_data'].append('breach_directory')
            if bd.data.get('has_password_data'):
                summary['has_password_data'] = True

        # ── LeakCheck ─────────────────────────────────────────────────────
        lc = result.sources.get('leakcheck')
        if lc and lc.success and lc.data.get('found'):
            count = lc.data.get('breach_count', 0)
            breach_counts.append(count)
            summary['in_breach_db'] = True
            summary['sources_with_data'].append('leakcheck')
            if lc.data.get('has_password_data'):
                summary['has_password_data'] = True

        # ── PSBDMP ────────────────────────────────────────────────────────
        psbdmp = result.sources.get('psbdmp')
        if psbdmp and psbdmp.success:
            paste_count = psbdmp.data.get('paste_count', 0)
            summary['paste_hits'] = paste_count
            if paste_count > 0:
                summary['sources_with_data'].append('psbdmp')

        # ── IntelX ────────────────────────────────────────────────────────
        intelx = result.sources.get('intelx')
        if intelx and intelx.success and intelx.data.get('found'):
            hits = intelx.data.get('result_count', 0)
            summary['intelx_hits'] = hits
            if hits > 0:
                summary['sources_with_data'].append('intelx')
                summary['in_breach_db'] = True

        # ── Aggregate ─────────────────────────────────────────────────────
        summary['total_breach_count'] = max(breach_counts) if breach_counts else 0

        # Risk tier
        total = summary['total_breach_count'] + summary['paste_hits'] + summary['intelx_hits']
        if total >= 10 or summary['has_password_data']:
            summary['risk_level'] = 'high'
        elif total >= 3:
            summary['risk_level'] = 'medium'
        elif total >= 1:
            summary['risk_level'] = 'low'
        else:
            summary['risk_level'] = 'none'

        return summary
