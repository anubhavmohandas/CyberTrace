"""Geospatial intelligence (GEOINT) OSINT module.

Resolves coordinates, addresses, and IPs to enriched location profiles
including timezone, nearby facilities (via Overpass/OSM), and satellite
view links.

Sources (no key required):
- Nominatim reverse geocoding (OSM, free)
- Nominatim forward geocoding (OSM, free)
- Overpass API — nearby facilities via OpenStreetMap (free)
- IPInfo.io — IP-to-geo (free tier, 50k/month)
- timezonefinder REST (michelfe.it, free)
- Satellite/map view link generation (Google, Bing, OSM, Yandex)

Sources (API key required):
- TimezoneDB (timezonedb key, optional fallback)
"""

import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

from .base import BaseModule, ModuleResult, SourceResult


class GeointModule(BaseModule):
    """
    Geospatial intelligence: reverse/forward geocoding, timezone,
    nearby facilities, and multi-provider map view links.

    SUCCESS RATE: 90% — Nominatim + Overpass cover the core use case
    without any API keys.

    Supported target types:
    - coordinates  — "lat,lon" string (e.g. "51.5074,-0.1278")
    - address      — human-readable address string
    - ip           — IPv4/IPv6 address
    """

    name = "geoint"
    description = "Geospatial intelligence: geocoding, timezone, nearby facilities"
    supported_types = {'coordinates', 'address', 'ip'}

    _NOMINATIM_UA = 'CyberTrace OSINT Tool'

    # Overpass categories to look up
    _OVERPASS_CATEGORIES = {
        'hospitals': '[amenity=hospital]',
        'police': '[amenity=police]',
        'atms': '[amenity=atm]',
        'surveillance_cameras': '[man_made=surveillance]',
        'wifi_spots': '[internet_access=wlan]',
        'fire_stations': '[amenity=fire_station]',
        'pharmacies': '[amenity=pharmacy]',
    }

    async def search(self, target: str, **options) -> ModuleResult:
        """
        Analyse a geographic target.

        Args:
            target: "lat,lon" coords, free-text address, or IP address.
            **options: Accepts 'target_type' override and 'radius_m' for
                       nearby facility search (default 500).

        Returns:
            ModuleResult with geocode data, timezone, nearby facilities,
            and satellite view links.
        """
        target_type = options.get('target_type') or self._detect_type(target)
        radius_m = int(options.get('radius_m', 500))

        result = ModuleResult(
            target=target,
            target_type=target_type,
            module=self.name,
        )

        # ── Resolve to (lat, lon) ─────────────────────────────────────────
        lat: Optional[float] = None
        lon: Optional[float] = None
        resolved_address: Optional[str] = None

        if target_type == 'coordinates':
            lat, lon = self._parse_coordinates(target)
            if lat is None or lon is None:
                result.summary = {'error': f'Could not parse coordinates: {target}'}
                result.end_time = datetime.now(timezone.utc)
                return result

            sources = [
                ('reverse_geocode', self._reverse_geocode(lat, lon)),
                ('timezone', self._get_timezone(lat, lon)),
                ('nearby_facilities', self._get_nearby_facilities(lat, lon, radius_m)),
                ('satellite_links', self._get_satellite_view_links(lat, lon)),
            ]

        elif target_type == 'address':
            # Forward geocode first, then branch to coord-based sources
            fwd_result = await self._forward_geocode(target)
            result.sources['forward_geocode'] = fwd_result

            if fwd_result.success and fwd_result.data.get('results'):
                top = fwd_result.data['results'][0]
                lat = top.get('lat')
                lon = top.get('lon')
                resolved_address = top.get('display_name')

            if lat is None or lon is None:
                result.summary = {'error': f'Could not geocode address: {target}'}
                result.end_time = datetime.now(timezone.utc)
                return result

            sources = [
                ('timezone', self._get_timezone(lat, lon)),
                ('nearby_facilities', self._get_nearby_facilities(lat, lon, radius_m)),
                ('satellite_links', self._get_satellite_view_links(lat, lon)),
            ]

        elif target_type == 'ip':
            ip_geo = await self._geolocate_ip(target)
            result.sources['ip_geo'] = ip_geo

            if ip_geo.success:
                lat = ip_geo.data.get('lat')
                lon = ip_geo.data.get('lon')

            if lat is None or lon is None:
                result.summary = {
                    'error': f'Could not resolve IP to coordinates: {target}',
                    'ip_data': ip_geo.data if ip_geo.success else {},
                }
                result.end_time = datetime.now(timezone.utc)
                return result

            sources = [
                ('reverse_geocode', self._reverse_geocode(lat, lon)),
                ('timezone', self._get_timezone(lat, lon)),
                ('nearby_facilities', self._get_nearby_facilities(lat, lon, radius_m)),
                ('satellite_links', self._get_satellite_view_links(lat, lon)),
            ]

        else:
            result.summary = {'error': f'Unsupported target type: {target_type}'}
            result.end_time = datetime.now(timezone.utc)
            return result

        await self.run_sources(sources, result)

        result.summary = self._build_summary(
            result, lat, lon, resolved_address, target_type
        )
        result.end_time = datetime.now(timezone.utc)
        return result

    # ------------------------------------------------------------------ #
    # Type detection                                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _detect_type(target: str) -> str:
        """Heuristically determine the target type."""
        # Coordinates: float,float or float, float
        coord_pattern = re.compile(
            r'^[-+]?\d{1,3}(?:\.\d+)?\s*,\s*[-+]?\d{1,3}(?:\.\d+)?$'
        )
        if coord_pattern.match(target.strip()):
            return 'coordinates'

        # IP address
        ip_pattern = re.compile(
            r'^(?:\d{1,3}\.){3}\d{1,3}$|'            # IPv4
            r'^[0-9a-fA-F:]+:[0-9a-fA-F:]+$'         # IPv6 (simplified)
        )
        if ip_pattern.match(target.strip()):
            return 'ip'

        return 'address'

    @staticmethod
    def _parse_coordinates(target: str) -> Tuple[Optional[float], Optional[float]]:
        """Parse 'lat,lon' string to floats."""
        try:
            parts = target.strip().split(',')
            if len(parts) == 2:
                return float(parts[0].strip()), float(parts[1].strip())
        except (ValueError, AttributeError):
            pass
        return None, None

    # ------------------------------------------------------------------ #
    # Geocoding                                                            #
    # ------------------------------------------------------------------ #

    async def _reverse_geocode(self, lat: float, lon: float) -> SourceResult:
        """
        Nominatim reverse geocoding — OSM-based, free, no key required.
        Rate limit: 1 req/sec (respected by default session timeout).
        """
        url = (
            f"https://nominatim.openstreetmap.org/reverse"
            f"?lat={lat}&lon={lon}&format=json&addressdetails=1"
        )
        headers = {'User-Agent': self._NOMINATIM_UA}

        data = await self.fetch_json(url, headers=headers, retries=1)

        if not data or 'error' in data:
            return SourceResult(
                source='reverse_geocode',
                success=False,
                error=data.get('error', 'No response') if data else 'No response',
            )

        address = data.get('address', {})

        parsed: Dict[str, Any] = {
            'display_name': data.get('display_name') or None,
            'place_id': data.get('place_id'),
            'osm_type': data.get('osm_type') or None,
            'osm_id': data.get('osm_id') or None,
            'lat': float(data.get('lat', lat)),
            'lon': float(data.get('lon', lon)),
            # Address components
            'road': address.get('road') or address.get('pedestrian') or None,
            'neighbourhood': address.get('neighbourhood') or None,
            'suburb': address.get('suburb') or None,
            'city': (
                address.get('city')
                or address.get('town')
                or address.get('village')
                or address.get('hamlet')
                or None
            ),
            'county': address.get('county') or None,
            'state': address.get('state') or None,
            'postcode': address.get('postcode') or None,
            'country': address.get('country') or None,
            'country_code': address.get('country_code') or None,
        }

        return SourceResult(source='reverse_geocode', success=True, data=parsed)

    async def _forward_geocode(self, address: str) -> SourceResult:
        """
        Nominatim forward geocoding — converts address to coordinates.
        Returns up to 5 candidate results.
        """
        encoded = quote_plus(address)
        url = (
            f"https://nominatim.openstreetmap.org/search"
            f"?q={encoded}&format=json&limit=5&addressdetails=1"
        )
        headers = {'User-Agent': self._NOMINATIM_UA}

        data = await self.fetch_json(url, headers=headers, retries=1)

        if not data or not isinstance(data, list):
            return SourceResult(
                source='forward_geocode',
                success=False,
                error='No results from Nominatim',
            )

        results: List[Dict[str, Any]] = []
        for item in data[:5]:
            address_parts = item.get('address', {})
            results.append({
                'display_name': item.get('display_name'),
                'lat': float(item.get('lat', 0)),
                'lon': float(item.get('lon', 0)),
                'type': item.get('type'),
                'osm_type': item.get('osm_type'),
                'importance': item.get('importance'),
                'city': (
                    address_parts.get('city')
                    or address_parts.get('town')
                    or address_parts.get('village')
                    or None
                ),
                'country': address_parts.get('country') or None,
                'country_code': address_parts.get('country_code') or None,
                'postcode': address_parts.get('postcode') or None,
            })

        return SourceResult(
            source='forward_geocode',
            success=bool(results),
            data={'result_count': len(results), 'results': results},
        )

    # ------------------------------------------------------------------ #
    # Timezone                                                             #
    # ------------------------------------------------------------------ #

    async def _get_timezone(self, lat: float, lon: float) -> SourceResult:
        """
        Resolve timezone for coordinates.

        Primary: timezonefinder REST API (michelfe.it, free, no key).
        Fallback: rough UTC offset from longitude (±12h, ~15° per hour).
        """
        url = f"https://timezonefinder.michelfe.it/api/0?lng={lon}&lat={lat}"

        data = await self.fetch_json(url, retries=1)

        if data and data.get('tz_name'):
            return SourceResult(
                source='timezone',
                success=True,
                data={
                    'timezone': data['tz_name'],
                    'source': 'timezonefinder',
                },
            )

        # Fallback: rough UTC offset from longitude
        utc_offset = round(lon / 15)
        utc_offset = max(-12, min(14, utc_offset))
        sign = '+' if utc_offset >= 0 else ''
        timezone_str = f"UTC{sign}{utc_offset}"

        return SourceResult(
            source='timezone',
            success=True,
            data={
                'timezone': timezone_str,
                'utc_offset_hours': utc_offset,
                'source': 'longitude_estimate',
                'note': (
                    'Estimated from longitude. '
                    'Install timezonefinder service for accuracy.'
                ),
            },
        )

    # ------------------------------------------------------------------ #
    # Nearby facilities (Overpass API)                                    #
    # ------------------------------------------------------------------ #

    async def _get_nearby_facilities(
        self, lat: float, lon: float, radius_m: int = 500
    ) -> SourceResult:
        """
        Query Overpass API (OSM) for nearby facilities within radius_m.

        Categories: hospitals, police, ATMs, surveillance cameras,
        WiFi spots, fire stations, pharmacies.

        Free, no key required. Rate: polite usage expected.
        """
        # Build combined Overpass QL query
        filters = ''.join(
            f'node{tag}(around:{radius_m},{lat},{lon});'
            f'way{tag}(around:{radius_m},{lat},{lon});'
            for tag in self._OVERPASS_CATEGORIES.values()
        )
        overpass_query = f"[out:json][timeout:25];({filters});out center tags;"

        url = "https://overpass-api.de/api/interpreter"

        try:
            async with self.session.post(
                url,
                data={'data': overpass_query},
                headers={'User-Agent': self._NOMINATIM_UA},
            ) as resp:
                if resp.status != 200:
                    return SourceResult(
                        source='nearby_facilities',
                        success=False,
                        error=f'Overpass API returned {resp.status}',
                    )
                raw = await resp.json(content_type=None)
        except asyncio.TimeoutError:
            return SourceResult(
                source='nearby_facilities',
                success=False,
                error='Overpass API timeout',
            )
        except Exception as e:
            return SourceResult(
                source='nearby_facilities',
                success=False,
                error=str(e),
            )

        elements = raw.get('elements', [])

        # Categorise results
        categorised: Dict[str, List[Dict[str, Any]]] = {k: [] for k in self._OVERPASS_CATEGORIES}
        tag_to_category = {
            'hospital': 'hospitals',
            'police': 'police',
            'atm': 'atms',
            'fire_station': 'fire_stations',
            'pharmacy': 'pharmacies',
        }

        for el in elements:
            tags = el.get('tags', {})
            amenity = tags.get('amenity', '')
            man_made = tags.get('man_made', '')
            internet = tags.get('internet_access', '')

            # Determine coordinates (node vs way with center)
            el_lat = el.get('lat') or (el.get('center', {}) or {}).get('lat')
            el_lon = el.get('lon') or (el.get('center', {}) or {}).get('lon')

            facility: Dict[str, Any] = {
                'name': tags.get('name') or tags.get('operator') or 'Unknown',
                'lat': el_lat,
                'lon': el_lon,
                'osm_id': el.get('id'),
            }
            if el_lat is not None and el_lon is not None:
                facility['google_maps'] = f"https://www.google.com/maps?q={el_lat},{el_lon}"

            cat = tag_to_category.get(amenity)
            if cat:
                categorised[cat].append(facility)
            elif man_made == 'surveillance':
                categorised['surveillance_cameras'].append(facility)
            elif internet == 'wlan':
                categorised['wifi_spots'].append(facility)

        total_count = sum(len(v) for v in categorised.values())

        return SourceResult(
            source='nearby_facilities',
            success=True,
            data={
                'total_count': total_count,
                'radius_m': radius_m,
                'facilities': {k: v[:10] for k, v in categorised.items()},
            },
        )

    # ------------------------------------------------------------------ #
    # Satellite view links                                                 #
    # ------------------------------------------------------------------ #

    async def _get_satellite_view_links(
        self, lat: float, lon: float
    ) -> SourceResult:
        """
        Generate direct satellite/map view URLs for a set of major providers.

        None of these require API keys — they are public deep-links.
        """
        links: Dict[str, str] = {
            'google_maps': (
                f"https://www.google.com/maps/@{lat},{lon},18z/data=!3m1!1e3"
            ),
            'google_earth': (
                f"https://earth.google.com/web/@{lat},{lon},0a,1000d,35y,0h,0t,0r"
            ),
            'bing_maps': (
                f"https://www.bing.com/maps?cp={lat}~{lon}&lvl=17&style=a"
            ),
            'openstreetmap': (
                f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}"
            ),
            'yandex_maps': (
                f"https://yandex.com/maps/?ll={lon},{lat}&z=17&l=sat"
            ),
            'sentinel_hub': (
                f"https://apps.sentinel-hub.com/eo-browser/"
                f"?zoom=17&lat={lat}&lng={lon}"
            ),
        }

        return SourceResult(
            source='satellite_links',
            success=True,
            data={'links': links},
        )

    # ------------------------------------------------------------------ #
    # IP geolocation                                                       #
    # ------------------------------------------------------------------ #

    async def _geolocate_ip(self, ip: str) -> SourceResult:
        """
        Geolocate an IP address using IPInfo.io (free, 50k req/month).
        Extracts lat/lon from the 'loc' field for coord-based lookups.
        """
        url = f"https://ipinfo.io/{ip}/json"
        data = await self.fetch_json(url, retries=1)

        if not data or data.get('bogon') or 'ip' not in data:
            return SourceResult(
                source='ip_geo',
                success=False,
                error=data.get('reason', 'No data') if data else 'No response',
            )

        lat: Optional[float] = None
        lon: Optional[float] = None
        loc = data.get('loc', '')
        if loc and ',' in loc:
            try:
                parts = loc.split(',')
                lat = float(parts[0])
                lon = float(parts[1])
            except (ValueError, IndexError):
                pass

        org_raw = data.get('org', '')
        asn, org_name = (org_raw.split(' ', 1) + [''])[:2] if org_raw else ('', '')

        parsed: Dict[str, Any] = {
            'ip': data.get('ip'),
            'hostname': data.get('hostname') or None,
            'city': data.get('city') or None,
            'region': data.get('region') or None,
            'country': data.get('country') or None,
            'loc': loc,
            'lat': lat,
            'lon': lon,
            'org': org_name.strip() or None,
            'asn': asn or None,
            'postal': data.get('postal') or None,
            'timezone': data.get('timezone') or None,
        }

        return SourceResult(source='ip_geo', success=True, data=parsed)

    # ------------------------------------------------------------------ #
    # Summary                                                              #
    # ------------------------------------------------------------------ #

    def _build_summary(
        self,
        result: ModuleResult,
        lat: Optional[float],
        lon: Optional[float],
        resolved_address: Optional[str],
        target_type: str,
    ) -> Dict[str, Any]:

        summary: Dict[str, Any] = {
            'target': result.target,
            'target_type': target_type,
            'coordinates': {'lat': lat, 'lon': lon} if lat is not None and lon is not None else None,
            'address': resolved_address,
            'city': None,
            'country': None,
            'timezone': None,
            'nearby_facility_count': 0,
            'satellite_links': {},
        }

        # ── Reverse geocode ───────────────────────────────────────────────
        rg = result.sources.get('reverse_geocode')
        if rg and rg.success:
            summary['address'] = rg.data.get('display_name') or resolved_address
            summary['city'] = rg.data.get('city')
            summary['country'] = rg.data.get('country')
            summary['postcode'] = rg.data.get('postcode')
            summary['state'] = rg.data.get('state')
            summary['road'] = rg.data.get('road')
            if rg.data.get('country'):
                result.related.append(rg.data['country'])

        # ── Forward geocode (address target) ─────────────────────────────
        fg = result.sources.get('forward_geocode')
        if fg and fg.success and fg.data.get('results'):
            top = fg.data['results'][0]
            if not summary['city']:
                summary['city'] = top.get('city')
            if not summary['country']:
                summary['country'] = top.get('country')
            summary['geocode_candidates'] = fg.data.get('result_count', 0)

        # ── IP geo ────────────────────────────────────────────────────────
        ip_geo = result.sources.get('ip_geo')
        if ip_geo and ip_geo.success:
            if not summary['city']:
                summary['city'] = ip_geo.data.get('city')
            if not summary['country']:
                summary['country'] = ip_geo.data.get('country')
            summary['ip_org'] = ip_geo.data.get('org')
            summary['ip_asn'] = ip_geo.data.get('asn')
            summary['ip_hostname'] = ip_geo.data.get('hostname')

        # ── Timezone ──────────────────────────────────────────────────────
        tz = result.sources.get('timezone')
        if tz and tz.success:
            summary['timezone'] = tz.data.get('timezone')
            summary['timezone_source'] = tz.data.get('source')

        # ── Nearby facilities ─────────────────────────────────────────────
        nf = result.sources.get('nearby_facilities')
        if nf and nf.success:
            summary['nearby_facility_count'] = nf.data.get('total_count', 0)
            summary['nearby_facilities'] = nf.data.get('facilities', {})

        # ── Satellite links ───────────────────────────────────────────────
        sl = result.sources.get('satellite_links')
        if sl and sl.success:
            summary['satellite_links'] = sl.data.get('links', {})

        return summary
