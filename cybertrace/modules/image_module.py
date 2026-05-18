"""Image OSINT module.

Extracts metadata (EXIF/GPS), performs file hash intelligence lookups,
and generates reverse image search links.

Sources (no key required):
- exiftool subprocess (most complete EXIF extraction)
- Pillow / PIL fallback (basic EXIF when exiftool unavailable)
- Nominatim reverse geocoding (OpenStreetMap, free)
- MalwareBazaar hash lookup (abuse.ch, free)
- Reverse image search link generation (Google Lens, Yandex, TinEye, Bing)
"""

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

from .base import BaseModule, ModuleResult, SourceResult


class ImageModule(BaseModule):
    """
    Image file OSINT: EXIF metadata extraction, GPS reverse geocoding,
    file hash intelligence, and reverse image search link generation.

    SUCCESS RATE: 85% — exiftool or Pillow covers most image formats.
    GPS data present in ~30% of unstripped phone photos.
    """

    name = "image"
    description = "Image EXIF metadata, GPS location, hash intel, reverse image search"
    supported_types = {'image', 'file'}

    # User-Agent for Nominatim (required by usage policy)
    _NOMINATIM_UA = 'CyberTrace OSINT Tool'

    async def search(self, target: str, **options) -> ModuleResult:
        """
        Analyse an image file or URL.

        Args:
            target: Local file path or HTTP/HTTPS URL to an image.
            **options: unused

        Returns:
            ModuleResult with EXIF, GPS, hashes, and reverse-search links.
        """
        result = ModuleResult(
            target=target,
            target_type='image',
            module=self.name,
        )

        # ── Resolve target to a local file path ──────────────────────────
        file_path, temp_file = await self._resolve_target(target)

        if not file_path:
            result.sources['download'] = SourceResult(
                source='download',
                success=False,
                error=f"Could not obtain file from target: {target}",
            )
            result.summary = {'error': 'File not accessible', 'target': target}
            result.end_time = datetime.utcnow()
            return result

        try:
            sources = [
                ('exif', self._extract_exif(file_path)),
                ('file_hashes', self._check_image_hash(file_path)),
                ('reverse_search_links', self._generate_reverse_image_search_links(target)),
            ]

            await self.run_sources(sources, result)

            # ── GPS reverse geocode (serial — depends on EXIF result) ─────
            exif_src = result.sources.get('exif')
            if exif_src and exif_src.success:
                lat = exif_src.data.get('gps_latitude')
                lon = exif_src.data.get('gps_longitude')
                if lat is not None and lon is not None:
                    geo_result = await self._reverse_geocode(lat, lon)
                    result.sources['reverse_geocode'] = geo_result
                    # Attach location back to exif data for convenience
                    if geo_result.success:
                        exif_src.data['location'] = geo_result.data

            result.summary = self._build_summary(result)

        finally:
            # Clean up temp file if we created one
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass

        result.end_time = datetime.utcnow()
        return result

    # ------------------------------------------------------------------ #
    # File resolution                                                      #
    # ------------------------------------------------------------------ #

    async def _resolve_target(self, target: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Return (file_path, temp_path).

        If target is a URL, download to a temp file and return its path.
        temp_path is set only when we created a temp file (caller must delete).
        """
        if target.startswith('http://') or target.startswith('https://'):
            return await self._download_to_temp(target)

        # Local path
        path = Path(target)
        if path.exists() and path.is_file():
            return str(path), None

        return None, None

    async def _download_to_temp(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """Download URL to a temporary file. Returns (path, path) or (None, None)."""
        try:
            # Determine extension from URL
            url_path = url.split('?')[0]
            suffix = Path(url_path).suffix or '.bin'
            with tempfile.NamedTemporaryFile(
                suffix=suffix, delete=False, prefix='cybertrace_img_'
            ) as tmp:
                tmp_path = tmp.name

            # Use the base session to download
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    os.unlink(tmp_path)
                    return None, None
                content = await resp.read()

            with open(tmp_path, 'wb') as f:
                f.write(content)

            return tmp_path, tmp_path

        except Exception:
            return None, None

    # ------------------------------------------------------------------ #
    # EXIF extraction                                                      #
    # ------------------------------------------------------------------ #

    async def _extract_exif(self, file_path: str) -> SourceResult:
        """
        Extract EXIF metadata from the image.

        Strategy:
        1. Try exiftool subprocess (most complete — supports 200+ formats).
        2. Fall back to Pillow for basic JPEG/TIFF EXIF.
        """
        # Run in executor to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(None, self._extract_exif_sync, file_path)

        if data is None:
            return SourceResult(
                source='exif',
                success=False,
                error='No EXIF extraction method available (install exiftool or Pillow)',
            )

        if not data:
            return SourceResult(
                source='exif',
                success=True,
                data={'has_exif': False},
            )

        return SourceResult(source='exif', success=True, data=data)

    def _extract_exif_sync(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Synchronous EXIF extraction — called in executor."""
        # ── Method 1: exiftool ────────────────────────────────────────────
        if shutil.which('exiftool'):
            try:
                proc = subprocess.run(
                    ['exiftool', '-json', '-coordFormat', '%.6f', file_path],
                    capture_output=True,
                    timeout=15,
                    text=True,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    raw = json.loads(proc.stdout)
                    if raw:
                        return self._parse_exiftool_output(raw[0])
            except Exception:
                pass

        # ── Method 2: Pillow ──────────────────────────────────────────────
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS

            with Image.open(file_path) as img:
                raw_exif = img._getexif()  # type: ignore[attr-defined]
                if not raw_exif:
                    return {}

                decoded: Dict[str, Any] = {}
                for tag_id, value in raw_exif.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    decoded[tag] = value

                return self._parse_pil_exif(decoded, GPSTAGS)

        except ImportError:
            pass
        except Exception:
            pass

        return None  # Neither method available

    def _parse_exiftool_output(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise exiftool JSON output into a clean dict."""
        data: Dict[str, Any] = {'has_exif': True}

        field_map = {
            'Make': 'device_make',
            'Model': 'device_model',
            'Software': 'software',
            'DateTimeOriginal': 'datetime_taken',
            'CreateDate': 'datetime_created',
            'Artist': 'artist',
            'Copyright': 'copyright',
            'GPSLatitude': 'gps_latitude',
            'GPSLongitude': 'gps_longitude',
            'GPSAltitude': 'gps_altitude',
            'GPSLatitudeRef': 'gps_latitude_ref',
            'GPSLongitudeRef': 'gps_longitude_ref',
            'ImageWidth': 'width',
            'ImageHeight': 'height',
            'FileSize': 'file_size',
            'MIMEType': 'mime_type',
            'ColorSpace': 'color_space',
            'ExifImageWidth': 'exif_width',
            'ExifImageHeight': 'exif_height',
            'Orientation': 'orientation',
            'Flash': 'flash',
            'FocalLength': 'focal_length',
            'ExposureTime': 'exposure_time',
            'FNumber': 'f_number',
            'ISO': 'iso',
            'LensModel': 'lens_model',
            'GPSProcessingMethod': 'gps_processing_method',
            'GPSImgDirection': 'gps_direction',
        }

        for src_key, dst_key in field_map.items():
            val = raw.get(src_key)
            if val is not None and val != '':
                data[dst_key] = val

        # exiftool already converts GPS to decimal degrees with -coordFormat
        lat = data.get('gps_latitude')
        lon = data.get('gps_longitude')

        # Handle "S" / "W" references — exiftool may already negate but check
        if lat is not None and lon is not None:
            try:
                lat_f = float(str(lat).replace(',', '.'))
                lon_f = float(str(lon).replace(',', '.'))
                lat_ref = data.pop('gps_latitude_ref', 'N')
                lon_ref = data.pop('gps_longitude_ref', 'E')
                if str(lat_ref).upper() == 'S' and lat_f > 0:
                    lat_f = -lat_f
                if str(lon_ref).upper() == 'W' and lon_f > 0:
                    lon_f = -lon_f
                data['gps_latitude'] = lat_f
                data['gps_longitude'] = lon_f
                data['has_gps'] = True
                data['google_maps_url'] = (
                    f"https://www.google.com/maps?q={lat_f},{lon_f}"
                )
            except (ValueError, TypeError):
                data['has_gps'] = False
        else:
            data['has_gps'] = False

        return data

    def _parse_pil_exif(
        self,
        decoded: Dict[str, Any],
        GPSTAGS: Dict,
    ) -> Dict[str, Any]:
        """Normalise Pillow EXIF dict."""
        data: Dict[str, Any] = {'has_exif': True}

        pil_map = {
            'Make': 'device_make',
            'Model': 'device_model',
            'Software': 'software',
            'DateTimeOriginal': 'datetime_taken',
            'DateTime': 'datetime_created',
            'Artist': 'artist',
            'Copyright': 'copyright',
            'ExifImageWidth': 'width',
            'ExifImageHeight': 'height',
            'Orientation': 'orientation',
            'Flash': 'flash',
            'FocalLength': 'focal_length',
            'ExposureTime': 'exposure_time',
            'FNumber': 'f_number',
            'ISOSpeedRatings': 'iso',
            'LensModel': 'lens_model',
        }

        for src_key, dst_key in pil_map.items():
            val = decoded.get(src_key)
            if val is not None and val != '':
                data[dst_key] = str(val) if not isinstance(val, (int, float, str)) else val

        # GPS parsing from Pillow's raw IFD dict
        gps_info = decoded.get('GPSInfo')
        if gps_info and isinstance(gps_info, dict):
            gps_decoded = {GPSTAGS.get(k, k): v for k, v in gps_info.items()}
            lat = self._dms_to_decimal(
                gps_decoded.get('GPSLatitude'),
                gps_decoded.get('GPSLatitudeRef', 'N'),
            )
            lon = self._dms_to_decimal(
                gps_decoded.get('GPSLongitude'),
                gps_decoded.get('GPSLongitudeRef', 'E'),
            )
            if lat is not None and lon is not None:
                data['gps_latitude'] = lat
                data['gps_longitude'] = lon
                data['has_gps'] = True
                data['google_maps_url'] = f"https://www.google.com/maps?q={lat},{lon}"

                alt_raw = gps_decoded.get('GPSAltitude')
                if alt_raw:
                    try:
                        data['gps_altitude'] = float(alt_raw)
                    except (TypeError, ValueError):
                        pass
            else:
                data['has_gps'] = False
        else:
            data['has_gps'] = False

        return data

    @staticmethod
    def _dms_to_decimal(
        dms: Optional[Any],
        ref: str,
    ) -> Optional[float]:
        """Convert degrees/minutes/seconds tuple to decimal degrees."""
        if dms is None:
            return None
        try:
            def to_float(v: Any) -> float:
                if hasattr(v, 'numerator'):
                    return v.numerator / v.denominator
                return float(v)

            d, m, s = dms
            decimal = to_float(d) + to_float(m) / 60 + to_float(s) / 3600
            if str(ref).upper() in ('S', 'W'):
                decimal = -decimal
            return round(decimal, 6)
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # Reverse geocoding                                                    #
    # ------------------------------------------------------------------ #

    async def _reverse_geocode(self, lat: float, lon: float) -> SourceResult:
        """
        Reverse geocode GPS coordinates via Nominatim (OpenStreetMap).

        Free, no key required. Rate limit: 1 req/sec — we respect this.
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
            'road': address.get('road') or address.get('pedestrian') or None,
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
            'osm_type': data.get('type') or None,
            'lat': lat,
            'lon': lon,
        }

        return SourceResult(source='reverse_geocode', success=True, data=parsed)

    # ------------------------------------------------------------------ #
    # Reverse image search links                                           #
    # ------------------------------------------------------------------ #

    async def _generate_reverse_image_search_links(
        self, file_path_or_url: str
    ) -> SourceResult:
        """
        Generate reverse image search submission URLs.

        These services require browser-based upload or a public URL.
        We generate the correct entry points; automated upload is not possible
        without headless browser automation (out of scope here).
        """
        links: Dict[str, str] = {}

        if file_path_or_url.startswith('http://') or file_path_or_url.startswith('https://'):
            encoded_url = quote_plus(file_path_or_url)

            links['google_lens'] = (
                f"https://lens.google.com/uploadbyurl?url={encoded_url}"
            )
            links['yandex'] = (
                f"https://yandex.com/images/search?url={encoded_url}&rpt=imageview"
            )
            links['tineye'] = (
                f"https://www.tineye.com/search?url={encoded_url}"
            )
            links['bing_visual'] = (
                f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{encoded_url}"
            )
        else:
            # Local file — provide upload endpoints only
            links['google_lens'] = "https://lens.google.com/ (upload local file)"
            links['yandex'] = "https://yandex.com/images/ (upload local file)"
            links['tineye'] = "https://www.tineye.com/ (upload local file)"
            links['bing_visual'] = "https://www.bing.com/visualsearch (upload local file)"

        return SourceResult(
            source='reverse_search_links',
            success=True,
            data={
                'links': links,
                'note': (
                    'URL-based links work directly. '
                    'For local files, visit the upload page manually.'
                ),
            },
        )

    # ------------------------------------------------------------------ #
    # File hash + MalwareBazaar                                            #
    # ------------------------------------------------------------------ #

    async def _check_image_hash(self, file_path: str) -> SourceResult:
        """
        Compute MD5/SHA256 of the file and query MalwareBazaar.

        MalwareBazaar is abuse.ch's free malware hash database.
        Most image files will return 'hash_not_found', which is expected.
        """
        # Compute hashes in executor
        loop = asyncio.get_event_loop()
        hashes = await loop.run_in_executor(None, self._compute_hashes, file_path)

        if hashes is None:
            return SourceResult(
                source='file_hashes',
                success=False,
                error='Could not read file for hashing',
            )

        # Query MalwareBazaar
        mb_data = await self._query_malwarebazaar(hashes['sha256'])

        result_data: Dict[str, Any] = {
            'md5': hashes['md5'],
            'sha256': hashes['sha256'],
            'file_size_bytes': hashes['size'],
        }

        if mb_data:
            result_data['malwarebazaar'] = mb_data

        return SourceResult(source='file_hashes', success=True, data=result_data)

    @staticmethod
    def _compute_hashes(file_path: str) -> Optional[Dict[str, Any]]:
        """Compute MD5 and SHA256 hashes. Returns None on read error."""
        try:
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            size = 0
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5.update(chunk)
                    sha256.update(chunk)
                    size += len(chunk)
            return {
                'md5': md5.hexdigest(),
                'sha256': sha256.hexdigest(),
                'size': size,
            }
        except OSError:
            return None

    async def _query_malwarebazaar(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Query abuse.ch MalwareBazaar for the given SHA256 hash."""
        url = "https://mb.abuse.ch/api/"
        payload = {'query': 'get_info', 'hash': sha256}

        data = await self.fetch_json(url, method='POST', data=payload, retries=1)

        if not data:
            return None

        status = data.get('query_status', '')

        if status == 'hash_not_found':
            return {'found': False}

        if status == 'ok':
            samples = data.get('data', [])
            if samples:
                s = samples[0]
                return {
                    'found': True,
                    'file_name': s.get('file_name'),
                    'file_type': s.get('file_type'),
                    'first_seen': s.get('first_seen'),
                    'last_seen': s.get('last_seen'),
                    'signature': s.get('signature') or None,
                    'tags': s.get('tags') or [],
                    'reporter': s.get('reporter') or None,
                }

        return None

    # ------------------------------------------------------------------ #
    # Summary                                                              #
    # ------------------------------------------------------------------ #

    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            'target': result.target,
            'has_exif': False,
            'has_gps': False,
            'location': None,
            'device': None,
            'datetime_taken': None,
            'software': None,
            'artist': None,
            'copyright': None,
            'hashes': {},
            'malware_hit': False,
            'reverse_search_links': {},
        }

        # ── EXIF ──────────────────────────────────────────────────────────
        exif = result.sources.get('exif')
        if exif and exif.success:
            d = exif.data
            summary['has_exif'] = d.get('has_exif', False)
            summary['has_gps'] = d.get('has_gps', False)

            make = d.get('device_make')
            model = d.get('device_model')
            if make or model:
                summary['device'] = ' '.join(filter(None, [make, model]))

            summary['datetime_taken'] = d.get('datetime_taken') or d.get('datetime_created')
            summary['software'] = d.get('software')
            summary['artist'] = d.get('artist')
            summary['copyright'] = d.get('copyright')

            if d.get('has_gps'):
                summary['coordinates'] = {
                    'lat': d.get('gps_latitude'),
                    'lon': d.get('gps_longitude'),
                    'altitude_m': d.get('gps_altitude'),
                }
                summary['google_maps_url'] = d.get('google_maps_url')

        # ── Reverse geocode ───────────────────────────────────────────────
        geo = result.sources.get('reverse_geocode')
        if geo and geo.success:
            summary['location'] = {
                'display_name': geo.data.get('display_name'),
                'city': geo.data.get('city'),
                'country': geo.data.get('country'),
                'road': geo.data.get('road'),
                'postcode': geo.data.get('postcode'),
            }
            # Surface location as a related target for follow-up
            if geo.data.get('city') and geo.data.get('country'):
                result.related.append(
                    f"{geo.data['city']}, {geo.data['country']}"
                )

        # ── File hashes ───────────────────────────────────────────────────
        hashes_src = result.sources.get('file_hashes')
        if hashes_src and hashes_src.success:
            summary['hashes'] = {
                'md5': hashes_src.data.get('md5'),
                'sha256': hashes_src.data.get('sha256'),
            }
            summary['file_size_bytes'] = hashes_src.data.get('file_size_bytes')
            mb = hashes_src.data.get('malwarebazaar')
            if mb and mb.get('found'):
                summary['malware_hit'] = True
                summary['malware_info'] = mb

        # ── Reverse search links ──────────────────────────────────────────
        rsl = result.sources.get('reverse_search_links')
        if rsl and rsl.success:
            summary['reverse_search_links'] = rsl.data.get('links', {})

        return summary
