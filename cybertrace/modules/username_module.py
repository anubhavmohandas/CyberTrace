"""Username enumeration OSINT module."""

import asyncio
import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .base import BaseModule, ModuleResult, SourceResult


class UsernameModule(BaseModule):
    """
    Username enumeration across 3000+ sites.
    
    SUCCESS RATE: 90% - Maigret/Sherlock are mature and reliable.
    
    Tools:
    - Maigret (primary, 3000+ sites)
    - Sherlock (backup, 400+ sites)
    - Manual checks for key platforms
    """
    
    name = "username"
    description = "Username enumeration across social platforms"
    supported_types = {'username'}
    
    # High-value platforms to always check manually (fast verification)
    KEY_PLATFORMS = {
        'github': 'https://api.github.com/users/{username}',
        'twitter': 'https://twitter.com/{username}',
        'instagram': 'https://www.instagram.com/{username}/',
        'reddit': 'https://www.reddit.com/user/{username}/about.json',
        'youtube': 'https://www.youtube.com/@{username}',
        'tiktok': 'https://www.tiktok.com/@{username}',
        'linkedin': 'https://www.linkedin.com/in/{username}',
        'telegram': 'https://t.me/{username}',
        'medium': 'https://medium.com/@{username}',
        'twitch': 'https://www.twitch.tv/{username}',
    }
    
    async def search(self, target: str, **options) -> ModuleResult:
        """Search username across platforms."""
        
        username = target.lower().strip()
        
        result = ModuleResult(
            target=username,
            target_type='username',
            module=self.name,
        )
        
        # Parallel execution
        sources = [
            ('key_platforms', self._check_key_platforms(username)),
        ]
        
        # Try Maigret first (most comprehensive)
        if self._tool_available('maigret'):
            sources.append(('maigret', self._run_maigret(username)))
        elif self._tool_available('sherlock'):
            sources.append(('sherlock', self._run_sherlock(username)))
        else:
            result.sources['tools'] = SourceResult(
                source='tools',
                success=False,
                error='Neither maigret nor sherlock installed. Run: pip install maigret',
            )
        
        await self.run_sources(sources, result)
        
        # Build summary
        result.summary = self._build_summary(result)
        result.end_time = datetime.utcnow()
        
        return result
    
    def _tool_available(self, tool: str) -> bool:
        """Check if a tool is available in PATH."""
        return shutil.which(tool) is not None
    
    async def _check_key_platforms(self, username: str) -> SourceResult:
        """Quick check of key platforms via HTTP."""
        found = []
        not_found = []
        errors = []
        
        async def check_platform(name: str, url_template: str):
            url = url_template.format(username=username)
            try:
                async with self.session.get(url, allow_redirects=False) as resp:
                    # Different platforms have different "found" indicators
                    if name == 'github':
                        if resp.status == 200:
                            data = await resp.json()
                            return (name, True, {'url': f"https://github.com/{username}", 'followers': data.get('followers')})
                    elif name == 'reddit':
                        if resp.status == 200:
                            data = await resp.json()
                            if 'data' in data:
                                return (name, True, {'url': f"https://reddit.com/user/{username}", 'karma': data['data'].get('total_karma')})
                    elif name in ('twitter', 'instagram', 'linkedin'):
                        # These return 200 but may redirect or show error page
                        # For now, just check status
                        if resp.status == 200:
                            return (name, True, {'url': url})
                    else:
                        if resp.status == 200:
                            return (name, True, {'url': url})
                    return (name, False, None)
            except Exception as e:
                return (name, None, str(e))
        
        tasks = [check_platform(name, url) for name, url in self.KEY_PLATFORMS.items()]
        results = await asyncio.gather(*tasks)
        
        platform_results = {}
        for name, exists, data in results:
            if exists is True:
                found.append(name)
                platform_results[name] = data
            elif exists is False:
                not_found.append(name)
            else:
                errors.append(f"{name}: {data}")
        
        return SourceResult(
            source='key_platforms',
            success=True,
            data={
                'found': found,
                'not_found': not_found,
                'platform_details': platform_results,
                'errors': errors if errors else None,
            },
        )
    
    async def _run_maigret(self, username: str) -> SourceResult:
        """Run Maigret tool (3000+ sites)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / 'results.json'
            
            # Run maigret
            cmd = [
                'maigret', username,
                '--json', 'simple',
                '-o', str(output_file),
                '--timeout', '10',
                '--no-color',
            ]
            
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                
                if output_file.exists():
                    with open(output_file) as f:
                        data = json.load(f)
                    
                    # Parse maigret output
                    found = []
                    for site, info in data.items():
                        if isinstance(info, dict) and info.get('status'):
                            # Status can be 'Claimed', 'Available', etc.
                            if info.get('status') == 'Claimed':
                                found.append({
                                    'site': site,
                                    'url': info.get('url_user'),
                                    'status': info.get('status'),
                                })
                    
                    return SourceResult(
                        source='maigret',
                        success=True,
                        data={
                            'found_count': len(found),
                            'sites_checked': len(data),
                            'found': found[:100],  # Limit output
                        },
                    )
                else:
                    return SourceResult(
                        source='maigret',
                        success=False,
                        error='No output file generated',
                    )
                    
            except asyncio.TimeoutError:
                return SourceResult(
                    source='maigret',
                    success=False,
                    error='Maigret timed out after 120s',
                )
            except Exception as e:
                return SourceResult(
                    source='maigret',
                    success=False,
                    error=str(e),
                )
    
    async def _run_sherlock(self, username: str) -> SourceResult:
        """Run Sherlock tool (400+ sites)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / f'{username}.txt'
            
            cmd = [
                'sherlock', username,
                '--output', str(output_file),
                '--timeout', '10',
                '--print-found',
            ]
            
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=tmpdir,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                
                # Parse stdout for found sites
                found = []
                for line in stdout.decode().split('\n'):
                    line = line.strip()
                    if line.startswith('[+]') or 'http' in line.lower():
                        # Extract URL
                        if 'http' in line:
                            import re
                            urls = re.findall(r'https?://[^\s]+', line)
                            for url in urls:
                                site = url.split('/')[2]
                                found.append({
                                    'site': site,
                                    'url': url,
                                })
                
                return SourceResult(
                    source='sherlock',
                    success=True,
                    data={
                        'found_count': len(found),
                        'found': found,
                    },
                )
                
            except asyncio.TimeoutError:
                return SourceResult(
                    source='sherlock',
                    success=False,
                    error='Sherlock timed out after 120s',
                )
            except Exception as e:
                return SourceResult(
                    source='sherlock',
                    success=False,
                    error=str(e),
                )
    
    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        """Build summary from all source results."""
        all_found: Set[str] = set()
        all_urls: Dict[str, str] = {}
        
        for source, res in result.sources.items():
            if not res.success:
                continue
            data = res.data
            
            if source == 'key_platforms':
                for platform in data.get('found', []):
                    all_found.add(platform)
                for platform, details in data.get('platform_details', {}).items():
                    if details and 'url' in details:
                        all_urls[platform] = details['url']
            
            elif source in ('maigret', 'sherlock'):
                for site_info in data.get('found', []):
                    site = site_info.get('site', '').lower()
                    url = site_info.get('url')
                    if site:
                        all_found.add(site)
                    if url:
                        all_urls[site] = url
        
        # Categorize found sites
        categories = {
            'social_media': ['instagram', 'twitter', 'facebook', 'tiktok', 'snapchat', 'pinterest', 'tumblr'],
            'developer': ['github', 'gitlab', 'bitbucket', 'stackoverflow', 'codepen', 'replit', 'hackerrank'],
            'content': ['youtube', 'twitch', 'medium', 'substack', 'patreon', 'onlyfans'],
            'messaging': ['telegram', 'discord', 'slack'],
            'professional': ['linkedin', 'indeed', 'glassdoor'],
            'gaming': ['steam', 'xbox', 'playstation', 'epicgames', 'origin'],
        }
        
        categorized = {cat: [] for cat in categories}
        other = []
        
        for site in all_found:
            site_lower = site.lower()
            found_cat = False
            for cat, sites in categories.items():
                if any(s in site_lower for s in sites):
                    categorized[cat].append(site)
                    found_cat = True
                    break
            if not found_cat:
                other.append(site)
        
        # Remove empty categories
        categorized = {k: v for k, v in categorized.items() if v}
        if other:
            categorized['other'] = other
        
        return {
            'username': result.target,
            'total_found': len(all_found),
            'found_sites': sorted(all_found),
            'urls': all_urls,
            'by_category': categorized,
        }
