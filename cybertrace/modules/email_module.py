"""Email OSINT module."""

import asyncio
import shutil
from datetime import datetime
from typing import Any, Dict, List, Optional
import json
import re

from .base import BaseModule, ModuleResult, SourceResult


class EmailModule(BaseModule):
    """
    Email address investigation.
    
    SUCCESS RATE: 70% - Holehe works well, some sources may block.
    
    Sources:
    - Gravatar (profile pic, info)
    - Holehe (120+ site registration check)
    - GitHub commits
    - PGP keyservers
    - HaveIBeenPwned (web scrape, API is paid)
    - Google dorking
    """
    
    name = "email"
    description = "Email address OSINT"
    supported_types = {'email'}
    
    async def search(self, target: str, **options) -> ModuleResult:
        """Search email across sources."""

        email = target.lower().strip()

        result = ModuleResult(
            target=email,
            target_type='email',
            module=self.name,
        )

        # Core sources (always run)
        sources = [
            ('gravatar', self._check_gravatar(email)),
            ('github_commits', self._check_github_commits(email)),
            ('pgp_keys', self._check_pgp_keyservers(email)),
            ('breach_directory', self._check_breach_directory(email)),
        ]

        # Holehe if available
        if shutil.which('holehe'):
            sources.append(('holehe', self._run_holehe(email)))

        # Optional API sources
        if self.config.api_keys.has('emailrep'):
            sources.append(('emailrep', self._check_emailrep(email)))

        if self.config.api_keys.has('hunter'):
            sources.append(('hunter', self._check_hunter(email)))

        # Breach intelligence (replaces broken HIBP scrape)
        if self.config.api_keys.has('dehashed'):
            sources.append(('dehashed', self._check_dehashed(email)))

        if self.config.api_keys.has('intelx'):
            sources.append(('intelx', self._check_intelx(email)))

        await self.run_sources(sources, result)

        # Build summary
        result.summary = self._build_summary(result)
        result.end_time = datetime.utcnow()

        return result
    
    async def _check_gravatar(self, email: str) -> SourceResult:
        """Check Gravatar for profile."""
        email_hash = self.md5(email)
        
        # Check if profile exists (404 if not)
        profile_url = f"https://www.gravatar.com/{email_hash}.json"
        
        data = await self.fetch_json(profile_url)
        
        if data and 'entry' in data:
            entry = data['entry'][0]
            
            parsed = {
                'exists': True,
                'profile_url': f"https://gravatar.com/{email_hash}",
                'avatar_url': f"https://gravatar.com/avatar/{email_hash}",
                'display_name': entry.get('displayName'),
                'username': entry.get('preferredUsername'),
                'about': entry.get('aboutMe'),
                'location': entry.get('currentLocation'),
            }
            
            # Extract linked accounts
            accounts = []
            for acc in entry.get('accounts', []):
                accounts.append({
                    'service': acc.get('shortname'),
                    'url': acc.get('url'),
                    'username': acc.get('username'),
                })
            if accounts:
                parsed['linked_accounts'] = accounts
            
            # Photos
            photos = entry.get('photos', [])
            if photos:
                parsed['photos'] = [p.get('value') for p in photos]
            
            return SourceResult(source='gravatar', success=True, data=parsed)
        
        # Check if just avatar exists
        avatar_url = f"https://gravatar.com/avatar/{email_hash}?d=404"
        exists = await self.check_exists(avatar_url)
        
        return SourceResult(
            source='gravatar',
            success=True,
            data={
                'exists': exists,
                'avatar_url': f"https://gravatar.com/avatar/{email_hash}" if exists else None,
            },
        )
    
    async def _check_github_commits(self, email: str) -> SourceResult:
        """Search GitHub for commits by this email."""
        # Use GitHub search (works without auth but rate limited)
        url = f"https://api.github.com/search/commits?q=author-email:{email}"
        
        headers = {'Accept': 'application/vnd.github.cloak-preview+json'}
        if self.config.api_keys.has('github'):
            headers['Authorization'] = f"token {self.config.api_keys.get('github')}"
        
        data = await self.fetch_json(url, headers=headers)
        
        if not data:
            return SourceResult(source='github_commits', success=False, error='Rate limited or no results')
        
        total_count = data.get('total_count', 0)
        
        if total_count == 0:
            return SourceResult(
                source='github_commits',
                success=True,
                data={'commit_count': 0, 'usernames': [], 'repos': []},
            )
        
        # Extract usernames and repos
        usernames = set()
        repos = set()
        
        for item in data.get('items', [])[:20]:
            author = item.get('author')
            if author:
                usernames.add(author.get('login'))
            
            repo = item.get('repository', {})
            if repo:
                repos.add(repo.get('full_name'))
        
        return SourceResult(
            source='github_commits',
            success=True,
            data={
                'commit_count': total_count,
                'usernames': list(usernames),
                'repos': list(repos)[:10],
            },
        )
    
    async def _check_pgp_keyservers(self, email: str) -> SourceResult:
        """Search PGP keyservers for public keys."""
        servers = [
            f"https://keys.openpgp.org/vks/v1/by-email/{email}",
            f"https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index&options=mr",
        ]
        
        keys_found = []
        
        for server_url in servers:
            try:
                text = await self.fetch(server_url)
                if text:
                    # OpenPGP returns key directly
                    if 'BEGIN PGP PUBLIC KEY' in str(text):
                        keys_found.append({
                            'server': 'keys.openpgp.org',
                            'has_key': True,
                        })
                    # Ubuntu keyserver returns index
                    elif 'pub:' in str(text):
                        keys_found.append({
                            'server': 'keyserver.ubuntu.com',
                            'has_key': True,
                        })
            except Exception:
                pass
        
        return SourceResult(
            source='pgp_keys',
            success=True,
            data={
                'has_pgp_key': len(keys_found) > 0,
                'keys': keys_found,
            },
        )
    
    async def _run_holehe(self, email: str) -> SourceResult:
        """Run Holehe tool to check 120+ sites."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'holehe', email, '--only-used',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            
            output = stdout.decode()
            
            # Parse holehe output
            # Format: [+] site.com
            registered = []
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('[+]'):
                    # Extract site name
                    site = line.replace('[+]', '').strip()
                    if site:
                        registered.append(site)
            
            return SourceResult(
                source='holehe',
                success=True,
                data={
                    'registered_count': len(registered),
                    'registered_sites': registered,
                },
            )
            
        except asyncio.TimeoutError:
            return SourceResult(source='holehe', success=False, error='Timed out')
        except Exception as e:
            return SourceResult(source='holehe', success=False, error=str(e))
    
    async def _check_emailrep(self, email: str) -> SourceResult:
        """Check EmailRep.io for reputation."""
        api_key = self.config.api_keys.get('emailrep')
        if not api_key:
            return SourceResult(source='emailrep', success=False, error='No API key')
        
        url = f"https://emailrep.io/{email}"
        headers = {'Key': api_key, 'User-Agent': 'CyberTrace OSINT'}
        
        data = await self.fetch_json(url, headers=headers)
        
        if not data:
            return SourceResult(source='emailrep', success=False, error='No response')
        
        return SourceResult(
            source='emailrep',
            success=True,
            data={
                'reputation': data.get('reputation'),
                'suspicious': data.get('suspicious'),
                'references': data.get('references'),
                'details': data.get('details', {}),
            },
        )
    
    async def _check_hunter(self, email: str) -> SourceResult:
        """Check Hunter.io for email verification."""
        api_key = self.config.api_keys.get('hunter')
        if not api_key:
            return SourceResult(source='hunter', success=False, error='No API key')
        
        url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}"
        
        data = await self.fetch_json(url)
        
        if not data or 'data' not in data:
            return SourceResult(source='hunter', success=False, error='Invalid response')
        
        result_data = data['data']
        
        return SourceResult(
            source='hunter',
            success=True,
            data={
                'status': result_data.get('status'),
                'result': result_data.get('result'),
                'score': result_data.get('score'),
                'disposable': result_data.get('disposable'),
                'webmail': result_data.get('webmail'),
                'mx_records': result_data.get('mx_records'),
                'smtp_server': result_data.get('smtp_server'),
            },
        )
    
    async def _check_breach_directory(self, email: str) -> SourceResult:
        """
        BreachDirectory public API — free, no key needed.
        Returns breach names where this email appeared.
        API: https://breachdirectory.org
        """
        url = f"https://breachdirectory.org/api?func=auto&term={email}"
        headers = {'User-Agent': 'CyberTrace OSINT Research Tool'}

        data = await self.fetch_json(url, headers=headers, retries=1)

        if not data:
            return SourceResult(source='breach_directory', success=False, error='No response')

        if not data.get('success'):
            return SourceResult(
                source='breach_directory',
                success=True,
                data={'found': False, 'breach_count': 0},
            )

        results = data.get('result', [])
        breaches = []
        for entry in results[:20]:
            breaches.append({
                'source': entry.get('sources', [entry.get('source', 'unknown')]),
                'has_password': bool(entry.get('password') or entry.get('sha1')),
                'sha1': entry.get('sha1') or None,
            })

        return SourceResult(
            source='breach_directory',
            success=True,
            data={
                'found': True,
                'breach_count': len(results),
                'breaches': breaches,
            },
        )

    async def _check_dehashed(self, email: str) -> SourceResult:
        """
        DeHashed API — breach database search.
        Requires API key (dehashed.com).
        """
        api_key = self.config.api_keys.get('dehashed')
        if not api_key:
            return SourceResult(source='dehashed', success=False, error='No API key')

        url = f"https://api.dehashed.com/search?query=email:{email}&size=10"
        # DeHashed uses HTTP Basic Auth: username=email, password=api_key
        import base64
        credentials = base64.b64encode(f"{email}:{api_key}".encode()).decode()
        headers = {
            'Authorization': f"Basic {credentials}",
            'Accept': 'application/json',
        }

        data = await self.fetch_json(url, headers=headers)

        if not data:
            return SourceResult(source='dehashed', success=False, error='No response')

        if data.get('total') == 0:
            return SourceResult(
                source='dehashed',
                success=True,
                data={'found': False, 'total': 0},
            )

        entries = data.get('entries', [])
        parsed_entries = []
        for entry in entries[:10]:
            parsed_entries.append({
                'id': entry.get('id'),
                'email': entry.get('email'),
                'username': entry.get('username') or None,
                'password': entry.get('password') or None,   # plaintext if available
                'hashed_password': entry.get('hashed_password') or None,
                'name': entry.get('name') or None,
                'vin': entry.get('vin') or None,
                'address': entry.get('address') or None,
                'phone': entry.get('phone') or None,
                'database_name': entry.get('database_name'),
            })

        return SourceResult(
            source='dehashed',
            success=True,
            data={
                'found': True,
                'total': data.get('total', len(entries)),
                'entries': parsed_entries,
            },
        )

    async def _check_intelx(self, email: str) -> SourceResult:
        """
        IntelligenceX (IntelX) search — indexes dark web, paste sites, leaks.
        Requires free or paid API key from intelx.io.
        """
        api_key = self.config.api_keys.get('intelx')
        if not api_key:
            return SourceResult(source='intelx', success=False, error='No API key')

        search_url = "https://2.intelx.io/intelligent/search"
        headers = {'x-key': api_key, 'Content-Type': 'application/json'}
        payload = {
            'term': email,
            'maxresults': 20,
            'media': 0,
            'target': 0,
            'timeout': 10,
            'datefrom': '',
            'dateto': '',
            'sort': 2,
            'terminate': [],
        }

        # Step 1: Start search
        search_data = await self.fetch_json(
            search_url, method='POST', json=payload, headers=headers
        )

        if not search_data or not search_data.get('id'):
            return SourceResult(source='intelx', success=False, error='Search initiation failed')

        search_id = search_data['id']

        # Step 2: Poll for results with exponential backoff (max 5 attempts, capped at 10s)
        results_url = f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=20&offset=0"
        result_data = None
        for poll_attempt in range(5):
            await asyncio.sleep(min(2 ** poll_attempt, 10))
            result_data = await self.fetch_json(results_url, headers=headers)
            if result_data and result_data.get('records'):
                break

        if not result_data:
            return SourceResult(source='intelx', success=False, error='Results fetch failed')

        records = result_data.get('records', [])

        if not records:
            return SourceResult(
                source='intelx',
                success=True,
                data={'found': False, 'result_count': 0},
            )

        parsed_records = []
        for rec in records[:10]:
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

    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        """Build summary from all source results."""
        summary: Dict[str, Any] = {
            'email': result.target,
            'domain': result.target.split('@')[1] if '@' in result.target else None,
            'has_gravatar': False,
            'github_usernames': [],
            'registered_sites': [],
            'has_pgp_key': False,
            'reputation': None,
            'breach_count': 0,
            'in_breach_db': False,
        }

        for source, res in result.sources.items():
            if not res.success:
                continue
            data = res.data

            if source == 'gravatar':
                summary['has_gravatar'] = data.get('exists', False)
                if data.get('display_name'):
                    summary['gravatar_name'] = data['display_name']
                if data.get('linked_accounts'):
                    for acc in data['linked_accounts']:
                        if acc.get('username'):
                            result.related.append(acc['username'])

            elif source == 'github_commits':
                summary['github_usernames'] = data.get('usernames', [])
                summary['github_repos'] = data.get('repos', [])
                result.related.extend(data.get('usernames', []))

            elif source == 'holehe':
                summary['registered_sites'] = data.get('registered_sites', [])
                summary['registered_count'] = data.get('registered_count', 0)

            elif source == 'pgp_keys':
                summary['has_pgp_key'] = data.get('has_pgp_key', False)

            elif source == 'emailrep':
                summary['reputation'] = data.get('reputation')
                summary['suspicious'] = data.get('suspicious')

            elif source == 'breach_directory':
                if data.get('found'):
                    summary['in_breach_db'] = True
                    summary['breach_count'] = max(
                        summary['breach_count'], data.get('breach_count', 0)
                    )

            elif source == 'dehashed':
                if data.get('found'):
                    summary['in_breach_db'] = True
                    summary['breach_count'] = max(
                        summary['breach_count'], data.get('total', 0)
                    )
                    # Surface usernames from breach records for cross-correlation
                    for entry in data.get('entries', []):
                        if entry.get('username'):
                            result.related.append(entry['username'])

            elif source == 'intelx':
                if data.get('found'):
                    summary['in_breach_db'] = True
                    summary['intelx_hits'] = data.get('result_count', 0)

        return summary
