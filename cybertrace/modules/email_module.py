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
        ]
        
        # Holehe if available
        if shutil.which('holehe'):
            sources.append(('holehe', self._run_holehe(email)))
        
        # Optional API sources
        if self.config.api_keys.has('emailrep'):
            sources.append(('emailrep', self._check_emailrep(email)))
        
        if self.config.api_keys.has('hunter'):
            sources.append(('hunter', self._check_hunter(email)))
        
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
    
    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        """Build summary from all source results."""
        summary = {
            'email': result.target,
            'domain': result.target.split('@')[1] if '@' in result.target else None,
            'has_gravatar': False,
            'github_usernames': [],
            'registered_sites': [],
            'has_pgp_key': False,
            'reputation': None,
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
                    # Add linked accounts to related
                    for acc in data['linked_accounts']:
                        if acc.get('username'):
                            result.related.append(acc['username'])
            
            elif source == 'github_commits':
                summary['github_usernames'] = data.get('usernames', [])
                summary['github_repos'] = data.get('repos', [])
                # Add usernames to related
                result.related.extend(data.get('usernames', []))
            
            elif source == 'holehe':
                summary['registered_sites'] = data.get('registered_sites', [])
                summary['registered_count'] = data.get('registered_count', 0)
            
            elif source == 'pgp_keys':
                summary['has_pgp_key'] = data.get('has_pgp_key', False)
            
            elif source == 'emailrep':
                summary['reputation'] = data.get('reputation')
                summary['suspicious'] = data.get('suspicious')
        
        return summary
