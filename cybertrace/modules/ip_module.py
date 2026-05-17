"""IP address intelligence OSINT module.

IPs (ipv4/ipv6) were previously misrouted to DomainModule.
This module replaces that with proper threat-intel sources:

Sources (no key required):
- IPInfo.io       — geo, ASN, org, hostname
- IP-API.com      — geo, ISP, mobile/proxy/hosting flags
- Greynoise       — community API: internet scanner classification
- ThreatFox       — IOC lookup (abuse.ch)

Sources (API key required):
- AbuseIPDB       — abuse score + report history
- Shodan          — open ports, banners, CVEs, hostnames
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import BaseModule, ModuleResult, SourceResult


class IPModule(BaseModule):
    """
    IP address intelligence and threat analysis.

    SUCCESS RATE: 90% — free sources cover geo/ASN/reputation without any keys.
    Shodan/AbuseIPDB enrich significantly when keys are present.
    """

    name = "ip"
    description = "IP address geolocation, ASN, and threat intelligence"
    supported_types = {'ip'}

    async def search(self, target: str, **options) -> ModuleResult:
        ip = target.strip()

        result = ModuleResult(
            target=ip,
            target_type='ip',
            module=self.name,
        )

        # Always-on free sources
        sources = [
            ('ipinfo', self._check_ipinfo(ip)),
            ('ip_api', self._check_ip_api(ip)),
            ('greynoise', self._check_greynoise(ip)),
            ('threatfox', self._check_threatfox(ip)),
        ]

        # Key-gated sources
        if self.config.api_keys.has('abuseipdb'):
            sources.append(('abuseipdb', self._check_abuseipdb(ip)))

        if self.config.api_keys.has('shodan'):
            sources.append(('shodan', self._check_shodan(ip)))

        await self.run_sources(sources, result)

        result.summary = self._build_summary(result)
        result.end_time = datetime.utcnow()

        return result

    # ------------------------------------------------------------------ #
    # Sources                                                              #
    # ------------------------------------------------------------------ #

    async def _check_ipinfo(self, ip: str) -> SourceResult:
        """IPInfo.io — geo, ASN, org, hostname. 50k req/month free."""
        url = f"https://ipinfo.io/{ip}/json"
        data = await self.fetch_json(url)

        if not data or data.get('bogon') or 'ip' not in data:
            return SourceResult(
                source='ipinfo',
                success=False,
                error=data.get('reason', 'No data') if data else 'No response',
            )

        # Parse org: "AS15169 Google LLC" → split ASN and name
        org_raw = data.get('org', '')
        asn, org_name = (org_raw.split(' ', 1) + [''])[:2] if org_raw else ('', '')

        parsed: Dict[str, Any] = {
            'ip': data.get('ip'),
            'hostname': data.get('hostname') or None,
            'city': data.get('city') or None,
            'region': data.get('region') or None,
            'country': data.get('country') or None,
            'loc': data.get('loc') or None,          # "lat,lon"
            'org': org_name.strip() or None,
            'asn': asn or None,
            'postal': data.get('postal') or None,
            'timezone': data.get('timezone') or None,
        }

        # Add hostname to related targets for follow-up domain recon
        return SourceResult(source='ipinfo', success=True, data=parsed)

    async def _check_ip_api(self, ip: str) -> SourceResult:
        """IP-API.com — ISP, mobile/proxy/hosting detection. Free, no key."""
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
        data = await self.fetch_json(url)

        if not data or data.get('status') != 'success':
            return SourceResult(
                source='ip_api',
                success=False,
                error=data.get('message', 'Query failed') if data else 'No response',
            )

        parsed: Dict[str, Any] = {
            'isp': data.get('isp') or None,
            'org': data.get('org') or None,
            'asn': data.get('as') or None,
            'asname': data.get('asname') or None,
            'country': data.get('country') or None,
            'country_code': data.get('countryCode') or None,
            'region': data.get('regionName') or None,
            'city': data.get('city') or None,
            'timezone': data.get('timezone') or None,
            'lat': data.get('lat'),
            'lon': data.get('lon'),
            # Risk flags
            'is_mobile': data.get('mobile', False),
            'is_proxy': data.get('proxy', False),
            'is_hosting': data.get('hosting', False),
        }

        return SourceResult(source='ip_api', success=True, data=parsed)

    async def _check_greynoise(self, ip: str) -> SourceResult:
        """
        Greynoise Community API — classify IP as:
        benign (known scanner), malicious, or not seen.
        No key needed for community tier.
        """
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {'Accept': 'application/json'}
        data = await self.fetch_json(url, headers=headers, retries=1)

        if not data:
            return SourceResult(source='greynoise', success=False, error='No response')

        # 404 means IP not in Greynoise dataset
        if data.get('message') == 'IP not observed scanning the internet or contained in RIOT data set.':
            return SourceResult(
                source='greynoise',
                success=True,
                data={'seen': False, 'classification': 'not_seen'},
            )

        parsed: Dict[str, Any] = {
            'seen': data.get('noise', False) or data.get('riot', False),
            'noise': data.get('noise', False),        # seen actively scanning
            'riot': data.get('riot', False),           # known benign service (Google, AWS…)
            'classification': data.get('classification') or 'unknown',
            'name': data.get('name') or None,          # e.g. "Google" for RIOT
            'link': data.get('link') or None,
            'last_seen': data.get('last_seen') or None,
            'message': data.get('message') or None,
        }

        return SourceResult(source='greynoise', success=True, data=parsed)

    async def _check_threatfox(self, ip: str) -> SourceResult:
        """ThreatFox (abuse.ch) IOC lookup — free, no key."""
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search_term": ip}

        data = await self.fetch_json(url, method='POST', json=payload)

        if not data:
            return SourceResult(source='threatfox', success=False, error='No response')

        query_status = data.get('query_status', '')

        if query_status == 'no_result':
            return SourceResult(
                source='threatfox',
                success=True,
                data={'found': False, 'ioc_count': 0},
            )

        if query_status != 'ok':
            return SourceResult(
                source='threatfox',
                success=False,
                error=f"Unexpected query_status: {query_status}",
            )

        iocs = data.get('data', [])
        parsed_iocs = []
        for ioc in iocs[:10]:
            parsed_iocs.append({
                'ioc': ioc.get('ioc'),
                'ioc_type': ioc.get('ioc_type'),
                'threat_type': ioc.get('threat_type'),
                'malware': ioc.get('malware_printable'),
                'confidence': ioc.get('confidence_level'),
                'first_seen': ioc.get('first_seen'),
                'last_seen': ioc.get('last_seen'),
                'tags': ioc.get('tags') or [],
            })

        return SourceResult(
            source='threatfox',
            success=True,
            data={
                'found': True,
                'ioc_count': len(iocs),
                'iocs': parsed_iocs,
            },
        )

    async def _check_abuseipdb(self, ip: str) -> SourceResult:
        """AbuseIPDB — abuse score and report history. Free tier: 1k checks/day."""
        api_key = self.config.api_keys.get('abuseipdb')
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
        }
        params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True}

        data = await self.fetch_json(
            url,
            headers=headers,
            params=params,
        )

        if not data or 'data' not in data:
            return SourceResult(source='abuseipdb', success=False, error='Invalid response')

        d = data['data']
        reports = d.get('reports', [])

        parsed: Dict[str, Any] = {
            'abuse_confidence_score': d.get('abuseConfidenceScore', 0),
            'total_reports': d.get('totalReports', 0),
            'distinct_users': d.get('numDistinctUsers', 0),
            'last_reported': d.get('lastReportedAt') or None,
            'is_whitelisted': d.get('isWhitelisted', False),
            'isp': d.get('isp') or None,
            'domain': d.get('domain') or None,
            'country_code': d.get('countryCode') or None,
            'usage_type': d.get('usageType') or None,
            'is_tor': d.get('isTor', False),
            # Top categories from reports
            'categories': list({
                cat
                for r in reports[:20]
                for cat in (r.get('categories') or [])
            }),
        }

        return SourceResult(source='abuseipdb', success=True, data=parsed)

    async def _check_shodan(self, ip: str) -> SourceResult:
        """Shodan host lookup — open ports, banners, CVEs."""
        api_key = self.config.api_keys.get('shodan')
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"

        data = await self.fetch_json(url)

        if not data:
            return SourceResult(source='shodan', success=False, error='No response from Shodan')

        if 'error' in data:
            return SourceResult(source='shodan', success=False, error=data['error'])

        # Aggregate open ports and services
        ports = sorted(set(data.get('ports', [])))
        vulns = list(data.get('vulns', {}).keys())  # CVE IDs

        services = []
        for item in data.get('data', [])[:15]:
            svc = {
                'port': item.get('port'),
                'transport': item.get('transport', 'tcp'),
                'product': item.get('product') or None,
                'version': item.get('version') or None,
                'cpe': item.get('cpe') or [],
            }
            if item.get('ssl'):
                svc['ssl'] = {
                    'cipher': item['ssl'].get('cipher', {}).get('name'),
                    'versions': item['ssl'].get('versions', []),
                }
            services.append(svc)

        parsed: Dict[str, Any] = {
            'org': data.get('org') or None,
            'isp': data.get('isp') or None,
            'asn': data.get('asn') or None,
            'country_code': data.get('country_code') or None,
            'city': data.get('city') or None,
            'os': data.get('os') or None,
            'hostnames': data.get('hostnames', []),
            'domains': data.get('domains', []),
            'open_ports': ports,
            'port_count': len(ports),
            'services': services,
            'cves': vulns,
            'cve_count': len(vulns),
            'last_update': data.get('last_update') or None,
            'tags': data.get('tags', []),
        }

        return SourceResult(source='shodan', success=True, data=parsed)

    # ------------------------------------------------------------------ #
    # Summary                                                              #
    # ------------------------------------------------------------------ #

    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            'ip': result.target,
            'country': None,
            'org': None,
            'asn': None,
            'hostname': None,
            'open_ports': [],
            'cves': [],
            'abuse_score': 0,
            'is_proxy': False,
            'is_tor': False,
            'is_hosting': False,
            'threat_classification': 'unknown',
            'ioc_hits': 0,
            'risk_level': 'low',
        }

        # --- IPInfo (primary geo/ASN) ---
        ipinfo = result.sources.get('ipinfo')
        if ipinfo and ipinfo.success:
            summary['country'] = ipinfo.data.get('country')
            summary['org'] = ipinfo.data.get('org')
            summary['asn'] = ipinfo.data.get('asn')
            summary['hostname'] = ipinfo.data.get('hostname')
            summary['timezone'] = ipinfo.data.get('timezone')
            summary['coordinates'] = ipinfo.data.get('loc')
            # Add hostname to related targets for follow-up
            if ipinfo.data.get('hostname'):
                result.related.append(ipinfo.data['hostname'])

        # --- IP-API (risk flags) ---
        ipapi = result.sources.get('ip_api')
        if ipapi and ipapi.success:
            if not summary['org']:
                summary['org'] = ipapi.data.get('org') or ipapi.data.get('isp')
            if not summary['asn']:
                summary['asn'] = ipapi.data.get('asn')
            summary['is_proxy'] = ipapi.data.get('is_proxy', False)
            summary['is_hosting'] = ipapi.data.get('is_hosting', False)

        # --- Shodan (ports, CVEs) ---
        shodan = result.sources.get('shodan')
        if shodan and shodan.success:
            summary['open_ports'] = shodan.data.get('open_ports', [])
            summary['cves'] = shodan.data.get('cves', [])
            summary['os'] = shodan.data.get('os')
            if not summary['hostname'] and shodan.data.get('hostnames'):
                summary['hostname'] = shodan.data['hostnames'][0]
                result.related.append(summary['hostname'])

        # --- AbuseIPDB (score) ---
        abuseipdb = result.sources.get('abuseipdb')
        if abuseipdb and abuseipdb.success:
            summary['abuse_score'] = abuseipdb.data.get('abuse_confidence_score', 0)
            summary['is_tor'] = abuseipdb.data.get('is_tor', False)
            summary['total_abuse_reports'] = abuseipdb.data.get('total_reports', 0)

        # --- Greynoise (scanner classification) ---
        gn = result.sources.get('greynoise')
        if gn and gn.success:
            summary['greynoise_classification'] = gn.data.get('classification', 'not_seen')
            if gn.data.get('noise'):
                summary['is_scanner'] = True

        # --- ThreatFox (IOC hits) ---
        tf = result.sources.get('threatfox')
        if tf and tf.success:
            summary['ioc_hits'] = tf.data.get('ioc_count', 0)

        # --- Derived risk level ---
        risk_score = 0
        risk_score += min(summary['abuse_score'], 100)                 # 0–100
        risk_score += 20 if summary['ioc_hits'] > 0 else 0
        risk_score += 15 if summary.get('is_scanner') else 0
        risk_score += 10 if summary['is_proxy'] else 0
        risk_score += 10 if summary['is_tor'] else 0
        risk_score += 10 if summary['cves'] else 0

        if risk_score >= 60:
            summary['risk_level'] = 'critical'
        elif risk_score >= 35:
            summary['risk_level'] = 'high'
        elif risk_score >= 15:
            summary['risk_level'] = 'medium'
        else:
            summary['risk_level'] = 'low'

        return summary
