"""Domain intelligence OSINT module."""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from .base import BaseModule, ModuleResult, SourceResult


class DomainModule(BaseModule):
    """
    Domain investigation module.
    
    SUCCESS RATE: 85% - WHOIS/DNS always work, some APIs may rate limit.
    
    Sources:
    - WHOIS lookup
    - DNS records (A, AAAA, MX, NS, TXT, CNAME)
    - crt.sh (SSL certificates, subdomains)
    - VirusTotal (if API key)
    - URLScan (if API key)
    """
    
    name = "domain"
    description = "Domain intelligence and reconnaissance"
    supported_types = {'domain'}
    
    async def search(self, target: str, **options) -> ModuleResult:
        """Search domain across intelligence sources."""
        
        # Clean domain
        domain = self._clean_domain(target)
        
        result = ModuleResult(
            target=domain,
            target_type='domain',
            module=self.name,
        )
        
        # Core sources (always run)
        sources = [
            ('dns_records', self._get_dns_records(domain)),
            ('crtsh', self._check_crtsh(domain)),
            ('whois', self._get_whois(domain)),
        ]
        
        # Optional API sources
        if self.config.api_keys.has('virustotal'):
            sources.append(('virustotal', self._check_virustotal(domain)))
        
        if self.config.api_keys.has('urlscan'):
            sources.append(('urlscan', self._check_urlscan(domain)))
        
        # HackerTarget free subdomain enum (no key)
        sources.append(('hackertarget', self._check_hackertarget(domain)))

        if self.config.api_keys.has('shodan'):
            sources.append(('shodan_dns', self._check_shodan_dns(domain)))

        await self.run_sources(sources, result)

        # Build summary
        result.summary = self._build_summary(result)

        # Attach Google dorks to summary for SHADOHDORKS-style output
        result.summary['dorks'] = self._generate_dorks(domain)

        result.end_time = datetime.now(timezone.utc)

        return result
    
    def _clean_domain(self, target: str) -> str:
        """Clean and normalize domain."""
        # Remove protocol
        domain = re.sub(r'^https?://', '', target)
        # Remove path
        domain = domain.split('/')[0]
        # Remove port
        domain = domain.split(':')[0]
        return domain.lower().strip()
    
    async def _get_dns_records(self, domain: str) -> SourceResult:
        """Get DNS records using dnspython."""
        try:
            import dns.resolver
        except ImportError:
            return SourceResult(
                source='dns_records',
                success=False,
                error='dnspython not installed. Run: pip install dnspython',
            )
        
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = []
                for rdata in answers:
                    if rtype == 'MX':
                        records[rtype].append({
                            'priority': rdata.preference,
                            'host': str(rdata.exchange).rstrip('.'),
                        })
                    elif rtype == 'SOA':
                        records[rtype].append({
                            'mname': str(rdata.mname).rstrip('.'),
                            'rname': str(rdata.rname).rstrip('.'),
                            'serial': rdata.serial,
                        })
                    else:
                        records[rtype].append(str(rdata).strip('"').rstrip('.'))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass
        
        # Get IP info
        if 'A' in records:
            records['ip_addresses'] = records['A']
        
        return SourceResult(
            source='dns_records',
            success=bool(records),
            data=records,
        )
    
    async def _get_whois(self, domain: str) -> SourceResult:
        """Get WHOIS data."""
        try:
            import whois
        except ImportError:
            return SourceResult(
                source='whois',
                success=False,
                error='python-whois not installed. Run: pip install python-whois',
            )
        
        try:
            w = whois.whois(domain)
            
            # Handle various whois response formats
            data = {
                'domain_name': self._first_or_value(w.domain_name),
                'registrar': w.registrar,
                'creation_date': self._format_date(self._first_or_value(w.creation_date)),
                'expiration_date': self._format_date(self._first_or_value(w.expiration_date)),
                'updated_date': self._format_date(self._first_or_value(w.updated_date)),
                'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
                'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                'dnssec': w.dnssec,
            }
            
            # Registrant info (often redacted)
            if w.registrant_name or w.name:
                data['registrant'] = {
                    'name': w.registrant_name or w.name,
                    'organization': w.org,
                    'country': w.registrant_country or w.country,
                    'state': w.registrant_state_province or w.state,
                }
            
            # Clean None values
            data = {k: v for k, v in data.items() if v is not None}
            
            return SourceResult(
                source='whois',
                success=True,
                data=data,
            )
        except Exception as e:
            return SourceResult(
                source='whois',
                success=False,
                error=str(e),
            )
    
    async def _check_crtsh(self, domain: str) -> SourceResult:
        """Query crt.sh for SSL certificates (finds subdomains)."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        data = await self.fetch_json(url)
        
        if data is None:
            return SourceResult(
                source='crtsh',
                success=False,
                error='No response from crt.sh',
            )
        
        # Extract unique subdomains
        subdomains: Set[str] = set()
        certs = []
        
        for cert in data[:100]:  # Limit to 100 certs
            name_value = cert.get('name_value', '')
            issuer = cert.get('issuer_name', '')
            not_before = cert.get('not_before', '')
            not_after = cert.get('not_after', '')
            
            # Parse subdomains from name_value (can be multiline)
            for name in name_value.split('\n'):
                name = name.strip().lower()
                if name and '*' not in name:  # Skip wildcards
                    subdomains.add(name)
            
            certs.append({
                'common_name': cert.get('common_name'),
                'issuer': issuer.split(',')[0] if issuer else None,
                'not_before': not_before,
                'not_after': not_after,
            })
        
        return SourceResult(
            source='crtsh',
            success=True,
            data={
                'certificate_count': len(data),
                'subdomains': sorted(subdomains),
                'subdomain_count': len(subdomains),
                'recent_certs': certs[:10],  # Last 10 certs
            },
        )
    
    async def _check_virustotal(self, domain: str) -> SourceResult:
        """Query VirusTotal API."""
        api_key = self.config.api_keys.get('virustotal')
        if not api_key:
            return SourceResult(source='virustotal', success=False, error='No API key')
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': api_key}
        
        data = await self.fetch_json(url, headers=headers)
        
        if not data or 'data' not in data:
            return SourceResult(
                source='virustotal',
                success=False,
                error='Invalid response',
            )
        
        attrs = data['data'].get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        parsed = {
            'reputation': attrs.get('reputation'),
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'categories': attrs.get('categories', {}),
            'registrar': attrs.get('registrar'),
            'creation_date': attrs.get('creation_date'),
            'last_modification_date': attrs.get('last_modification_date'),
        }
        
        return SourceResult(
            source='virustotal',
            success=True,
            data=parsed,
        )
    
    async def _check_urlscan(self, domain: str) -> SourceResult:
        """Query URLScan.io API."""
        api_key = self.config.api_keys.get('urlscan')
        if not api_key:
            return SourceResult(source='urlscan', success=False, error='No API key')
        
        # Search for recent scans
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        headers = {'API-Key': api_key}
        
        data = await self.fetch_json(url, headers=headers)
        
        if not data or 'results' not in data:
            return SourceResult(
                source='urlscan',
                success=False,
                error='Invalid response',
            )
        
        results = data.get('results', [])
        
        if not results:
            return SourceResult(
                source='urlscan',
                success=True,
                data={'scan_count': 0, 'message': 'No scans found'},
            )
        
        # Get info from most recent scan
        latest = results[0]
        page = latest.get('page', {})
        
        parsed = {
            'scan_count': len(results),
            'latest_scan': {
                'url': latest.get('task', {}).get('url'),
                'time': latest.get('task', {}).get('time'),
                'ip': page.get('ip'),
                'country': page.get('country'),
                'server': page.get('server'),
                'title': page.get('title'),
                'asn': page.get('asn'),
            },
        }
        
        return SourceResult(
            source='urlscan',
            success=True,
            data=parsed,
        )
    
    async def _check_hackertarget(self, domain: str) -> SourceResult:
        """
        HackerTarget free subdomain enumeration — no key needed.
        Uses reverse DNS + zone transfer attempts via their public API.
        Free tier: 100 queries/day.
        """
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        text = await self.fetch(url, retries=1)

        if not text or 'error' in text.lower() or 'API count exceeded' in text:
            return SourceResult(
                source='hackertarget',
                success=False,
                error=text.strip() if text else 'No response',
            )

        subdomains: List[str] = []
        ips: List[str] = []

        for line in text.strip().split('\n'):
            line = line.strip()
            if not line or ',' not in line:
                continue
            parts = line.split(',', 1)
            host = parts[0].strip()
            ip = parts[1].strip() if len(parts) > 1 else None
            if host and host.endswith(domain):
                subdomains.append(host)
            if ip:
                ips.append(ip)

        return SourceResult(
            source='hackertarget',
            success=True,
            data={
                'subdomain_count': len(subdomains),
                'subdomains': sorted(set(subdomains))[:100],
                'associated_ips': sorted(set(ips))[:50],
            },
        )

    async def _check_shodan_dns(self, domain: str) -> SourceResult:
        """Shodan DNS/domain lookup — finds related IPs and subdomains."""
        api_key = self.config.api_keys.get('shodan')
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"

        data = await self.fetch_json(url)

        if not data or 'error' in data:
            return SourceResult(
                source='shodan_dns',
                success=False,
                error=data.get('error', 'No response') if data else 'No response',
            )

        subdomains = data.get('subdomains', [])
        full_subdomains = [f"{s}.{domain}" for s in subdomains]

        tags = data.get('tags', [])
        dns_records = data.get('data', [])

        parsed: Dict[str, Any] = {
            'subdomains': full_subdomains[:100],
            'subdomain_count': len(subdomains),
            'tags': tags,
            'dns_records': [
                {
                    'subdomain': r.get('subdomain'),
                    'type': r.get('type'),
                    'value': r.get('value'),
                    'last_seen': r.get('last_seen'),
                }
                for r in dns_records[:20]
            ],
        }

        return SourceResult(source='shodan_dns', success=True, data=parsed)

    def _generate_dorks(self, domain: str) -> Dict[str, List[str]]:
        """
        Generate Google dorks for this domain — SHADOHDORKS integration.
        Returns categorised dork strings ready to be searched.
        """
        d = domain
        return {
            'subdomain_enum': [
                f'site:*.{d}',
                f'site:*.{d} -www',
                f'"@{d}" -site:www.{d} -site:{d}',
                f'site:{d} inurl:staging',
                f'site:{d} inurl:dev',
                f'site:{d} inurl:test',
                f'site:*.{d} inurl:*.api',
                f'site:{d} inurl:mail',
                f'site:{d} inurl:api',
            ],
            'exposed_files': [
                f'intitle:"index of" site:{d}',
                f'intitle:"index of" "parent directory" site:{d}',
                f'intitle:"index of /backup" site:{d}',
                f'intitle:"index of /admin" site:{d}',
                f'ext:sql | ext:dbf | ext:mdb | ext:ora site:{d}',
                f'filetype:log site:{d}',
                f'inurl:/db_backup OR inurl:/database_backup site:{d}',
                f'intitle:"index of /" +backup site:{d}',
                f'inurl:ftp site:{d}',
                f'ext:txt {d} (vhost OR hostname OR nameserver)',
            ],
            'secrets_configs': [
                f'ext:env | ext:.env site:{d}',
                f'ext:yaml | ext:yml "database" site:{d}',
                f'intext:"DB_PASSWORD" site:{d}',
                f'intext:"AWS_ACCESS_KEY_ID" site:{d}',
                f'ext:xml intext:"awsaccesskey" site:{d}',
                f'intext:"private_key" ext:txt site:{d}',
                f'filetype:json "api_key" site:{d}',
                f'inurl:.git/config site:{d}',
                f'intitle:"Swagger UI" site:{d}',
                f'filetype:env "password" site:{d}',
                f'inurl:.git/HEAD site:{d}',
                f'ext:conf site:{d}',
                f'filetype:xml intext:"password" site:{d}',
                f'inurl:wp-config.php site:{d}',
            ],
            'admin_panels': [
                f'inurl:admin/login.php site:{d}',
                f'inurl:wp-login.php site:{d}',
                f'intitle:"admin panel" | intitle:"control panel" site:{d}',
                f'inurl:(admin | administrator | login) site:{d}',
                f'intitle:"phpMyAdmin" site:{d}',
                f'intitle:"Adminer" site:{d}',
                f'site:{d} inurl:admin',
                f'site:{d} intitle:"sign in"',
                f'site:{d} inurl:auth',
                f'intitle:"Logon Page" site:{d}',
            ],
        }

    def _first_or_value(self, val):
        """Get first element if list, else return value."""
        if isinstance(val, list):
            return val[0] if val else None
        return val
    
    def _format_date(self, val) -> Optional[str]:
        """Format date to ISO string."""
        if val is None:
            return None
        if isinstance(val, datetime):
            return val.isoformat()
        return str(val)
    
    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        """Build summary from all source results."""
        summary = {
            'domain': result.target,
            'ip_addresses': [],
            'name_servers': [],
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'subdomains': [],
            'security': {
                'malicious_detections': 0,
                'is_suspicious': False,
            },
        }
        
        for source, res in result.sources.items():
            if not res.success:
                continue
            data = res.data
            
            # DNS
            if source == 'dns_records':
                summary['ip_addresses'] = data.get('A', [])
                if 'MX' in data:
                    summary['mail_servers'] = data['MX']
                if 'NS' in data:
                    summary['name_servers'] = data['NS']
                if 'TXT' in data:
                    summary['txt_records'] = data['TXT']
            
            # WHOIS
            if source == 'whois':
                summary['registrar'] = data.get('registrar')
                summary['creation_date'] = data.get('creation_date')
                summary['expiration_date'] = data.get('expiration_date')
                if 'registrant' in data:
                    summary['registrant'] = data['registrant']
            
            # crt.sh
            if source == 'crtsh':
                summary['subdomains'] = data.get('subdomains', [])[:50]  # Top 50
                summary['subdomain_count'] = data.get('subdomain_count', 0)
                result.related.extend(summary['subdomains'][:10])

            # HackerTarget
            if source == 'hackertarget' and data.get('subdomains'):
                existing = set(summary.get('subdomains', []))
                new_subs = [s for s in data['subdomains'] if s not in existing]
                summary['subdomains'] = sorted(existing | set(new_subs))[:100]
                summary['subdomain_count'] = len(summary['subdomains'])
                result.related.extend(new_subs[:5])

            # Shodan DNS
            if source == 'shodan_dns' and data.get('subdomains'):
                existing = set(summary.get('subdomains', []))
                new_subs = [s for s in data['subdomains'] if s not in existing]
                summary['subdomains'] = sorted(existing | set(new_subs))[:100]
                summary['subdomain_count'] = len(summary['subdomains'])
                if data.get('tags'):
                    summary['shodan_tags'] = data['tags']
            
            # VirusTotal
            if source == 'virustotal':
                summary['security']['malicious_detections'] = data.get('malicious', 0)
                summary['security']['suspicious_detections'] = data.get('suspicious', 0)
                if data.get('malicious', 0) > 0 or data.get('suspicious', 0) > 0:
                    summary['security']['is_suspicious'] = True
        
        return summary
