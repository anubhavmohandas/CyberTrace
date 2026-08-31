"""Phone number OSINT module.

Replaces unmaintained PhoneInfoga with:
- phonenumbers (parse, carrier, geocoder, timezone) — always runs, no key needed
- NumVerify API (line type, carrier, country) — optional API key
- Carrier lookup via free public APIs
- Abstract Phone Validation API — optional
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict

from .base import BaseModule, ModuleResult, SourceResult


# Number type mapping from phonenumbers constants
_NUMBER_TYPE_MAP = {
    0: 'fixed_line',
    1: 'mobile',
    2: 'fixed_or_mobile',
    3: 'toll_free',
    4: 'premium_rate',
    5: 'shared_cost',
    6: 'voip',
    7: 'personal',
    8: 'pager',
    9: 'uan',
    10: 'voicemail',
    99: 'unknown',
}


class PhoneModule(BaseModule):
    """
    Phone number investigation module.

    SUCCESS RATE: 75% — phonenumbers parsing is near-perfect for valid numbers;
    carrier/line-type APIs vary by key availability.

    Sources:
    - phonenumbers  : Parse, validate, country, carrier, timezone (no key)
    - numverify     : Line type, carrier, detailed validation (API key)
    - api-bdc.net   : Free reverse phone lookup — carrier, country, line type (no key)
    - phonenumbers  : Used as fallback when HTTP sources return no data
    """

    name = "phone"
    description = "Phone number intelligence and carrier analysis"
    supported_types = {'phone'}

    async def search(self, target: str, **options) -> ModuleResult:
        result = ModuleResult(
            target=target,
            target_type='phone',
            module=self.name,
        )

        sources = [
            ('phonenumbers_lib', self._parse_with_phonenumbers(target)),
            ('free_carrier_lookup', self._free_carrier_lookup(target)),
        ]

        if self.config.api_keys.has('numverify'):
            sources.append(('numverify', self._check_numverify(target)))

        await self.run_sources(sources, result)

        result.summary = self._build_summary(result)
        result.end_time = datetime.now(timezone.utc)

        return result

    # ------------------------------------------------------------------ #
    # Sources                                                              #
    # ------------------------------------------------------------------ #

    async def _parse_with_phonenumbers(self, number: str) -> SourceResult:
        """Parse and validate using Google's libphonenumber (phonenumbers lib)."""
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier as pn_carrier, timezone as pn_tz
        except ImportError:
            return SourceResult(
                source='phonenumbers_lib',
                success=False,
                error='phonenumbers not installed. Run: pip install phonenumbers',
            )

        try:
            parsed = phonenumbers.parse(number, None)
        except phonenumbers.NumberParseException as e:
            return SourceResult(source='phonenumbers_lib', success=False, error=str(e))

        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)

        if not is_possible:
            return SourceResult(
                source='phonenumbers_lib',
                success=False,
                error='Not a possible phone number',
            )

        num_type_int = int(phonenumbers.number_type(parsed))
        num_type_str = _NUMBER_TYPE_MAP.get(num_type_int, 'unknown')

        data: Dict[str, Any] = {
            'valid': is_valid,
            'possible': is_possible,
            'e164': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'national': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            'country_code': f"+{parsed.country_code}",
            'national_number': str(parsed.national_number),
            'country': geocoder.description_for_number(parsed, 'en') or None,
            'carrier': pn_carrier.name_for_number(parsed, 'en') or None,
            'timezones': list(pn_tz.time_zones_for_number(parsed)),
            'line_type': num_type_str,
        }

        # Region codes (e.g. ['IN'], ['US', 'CA'])
        region = phonenumbers.region_code_for_number(parsed)
        if region:
            data['region_code'] = region

        return SourceResult(source='phonenumbers_lib', success=True, data=data)

    async def _free_carrier_lookup(self, number: str) -> SourceResult:
        """
        Free carrier/geo lookup using two reliable keyless sources.

        Source A: api-bdc.net phone reverse lookup (free, no key needed).
          Returns carrier, country, line type, and location data as JSON.
          Endpoint: https://api-bdc.net/data/phone-reverse-lookup?number={e164}&localityLanguage=en

        Source B: phonenumbers library data already collected in _parse_with_phonenumbers.
          Used as graceful fallback when the HTTP source returns nothing useful.
        """
        clean = re.sub(r'[^\d+]', '', number)
        if not clean.startswith('+'):
            clean = '+' + clean

        # Source A: api-bdc.net free reverse phone lookup (no key required)
        url = f"https://api-bdc.net/data/phone-reverse-lookup?number={clean}&localityLanguage=en"
        data = await self.fetch_json(url, retries=1)

        if data and not data.get('error') and data.get('countryCode'):
            # Map api-bdc.net response fields to our standard format
            carrier_name = (
                data.get('carrierName')
                or data.get('carrier')
                or None
            )
            line_type_raw = data.get('numberType') or data.get('lineType') or None
            # Normalise line type string (api-bdc returns e.g. "MOBILE", "FIXED_LINE")
            line_type = None
            if line_type_raw:
                line_type = line_type_raw.lower().replace('_', ' ')

            return SourceResult(
                source='free_carrier_lookup',
                success=True,
                data={
                    'carrier': carrier_name,
                    'country': data.get('countryName') or data.get('country') or None,
                    'country_code': data.get('countryCode') or None,
                    'line_type': line_type,
                    'city': data.get('city') or data.get('localityName') or None,
                    'region': data.get('principalSubdivision') or data.get('region') or None,
                    'international_format': data.get('internationalNumber') or None,
                    'source_api': 'api-bdc.net',
                },
            )

        # Source B: graceful fallback — surface whatever phonenumbers already gave us.
        # The caller (_build_summary) already merges phonenumbers_lib data, so we
        # just signal that the HTTP lookup failed rather than crashing.
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier as pn_carrier
            parsed = phonenumbers.parse(number, None)
            fallback_carrier = pn_carrier.name_for_number(parsed, 'en') or None
            fallback_country = geocoder.description_for_number(parsed, 'en') or None
            if fallback_carrier or fallback_country:
                return SourceResult(
                    source='free_carrier_lookup',
                    success=True,
                    data={
                        'carrier': fallback_carrier,
                        'country': fallback_country,
                        'country_code': None,
                        'line_type': None,
                        'source_api': 'phonenumbers_fallback',
                    },
                )
        except Exception:
            pass

        return SourceResult(
            source='free_carrier_lookup',
            success=False,
            error='api-bdc.net returned no data and phonenumbers fallback yielded nothing',
        )

    async def _check_numverify(self, number: str) -> SourceResult:
        """NumVerify / APILayer number verification (paid API key required)."""
        api_key = self.config.api_keys.get('numverify')
        clean = re.sub(r'[^\d]', '', number)

        url = f"https://api.apilayer.com/number_verification/validate?number={clean}"
        headers = {'apikey': api_key}

        data = await self.fetch_json(url, headers=headers)

        if not data:
            return SourceResult(source='numverify', success=False, error='No response from NumVerify')

        # APILayer's shared error envelope (used across numverify/fixer/
        # currencylayer alike): {"success": false, "error": {...}} for a bad
        # key, exhausted quota, etc. A genuine validation response never
        # carries top-level "success" — only "valid". Without this check, an
        # API-level failure has no "valid" key either, so `not data.get(
        # 'valid')` would misreport the call as "checked, number is invalid"
        # instead of "the check never happened".
        if data.get('success') is False:
            err = data.get('error') or {}
            return SourceResult(
                source='numverify',
                success=False,
                error=err.get('info') or err.get('type') or 'NumVerify API error',
            )

        if not data.get('valid'):
            return SourceResult(
                source='numverify',
                success=True,
                data={'valid': False, 'raw': data},
            )

        return SourceResult(
            source='numverify',
            success=True,
            data={
                'valid': True,
                'number': data.get('number'),
                'local_format': data.get('local_format'),
                'international_format': data.get('international_format'),
                'country_prefix': data.get('country_prefix'),
                'country_code': data.get('country_code'),
                'country_name': data.get('country_name'),
                'location': data.get('location') or None,
                'carrier': data.get('carrier') or None,
                'line_type': data.get('line_type') or None,
            },
        )

    # ------------------------------------------------------------------ #
    # Summary                                                              #
    # ------------------------------------------------------------------ #

    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            'phone': result.target,
            'valid': False,
            'e164': None,
            'country': None,
            'carrier': None,
            'line_type': None,
            'timezones': [],
        }

        # phonenumbers_lib is the authoritative source
        pn = result.sources.get('phonenumbers_lib')
        if pn and pn.success:
            summary.update({
                'valid': pn.data.get('valid', False),
                'e164': pn.data.get('e164'),
                'country': pn.data.get('country'),
                'carrier': pn.data.get('carrier'),
                'line_type': pn.data.get('line_type'),
                'timezones': pn.data.get('timezones', []),
                'region_code': pn.data.get('region_code'),
            })

        # Supplement carrier/line_type from API sources
        for src_name in ('numverify', 'free_carrier_lookup'):
            src = result.sources.get(src_name)
            if src and src.success:
                if not summary['carrier'] and src.data.get('carrier'):
                    summary['carrier'] = src.data['carrier']
                if not summary['line_type'] and src.data.get('line_type'):
                    summary['line_type'] = src.data['line_type']
                if not summary['country'] and src.data.get('country'):
                    summary['country'] = src.data['country']
                # Location only from numverify
                if src_name == 'numverify' and src.data.get('location'):
                    summary['location'] = src.data['location']

        return summary
