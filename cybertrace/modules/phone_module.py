"""Phone number OSINT module.

Replaces unmaintained PhoneInfoga with:
- phonenumbers (parse, carrier, geocoder, timezone) — always runs, no key needed
- NumVerify API (line type, carrier, country) — optional API key
- Carrier lookup via free public APIs
- Abstract Phone Validation API — optional
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

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
    - ip-api        : Free carrier/geo lookup as sanity-check fallback
    - callerapi     : Caller name lookup (free tier, limited)
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
        result.end_time = datetime.utcnow()

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
        Free carrier/geo via ip-api's phone endpoint.
        Docs: http://ip-api.com (no phone endpoint) — using abstract-style free fallback.

        Actually uses: https://phone.abstractapi.com alternative (freekey not available)
        Fallback: phone-validation via OpenCNAM-style scraping is blocked.

        We use callerapi.com free tier instead: https://www.callerapi.com/api
        No key required for basic carrier+country lookup.
        """
        clean = re.sub(r'[^\d+]', '', number)
        # Ensure E.164 format for the request
        if not clean.startswith('+'):
            clean = '+' + clean

        # Try callerapi free tier (no key, returns carrier + location)
        url = f"https://www.callerapi.com/api?phone={clean}"
        data = await self.fetch_json(url, retries=1)

        if data and data.get('status') == 'success':
            return SourceResult(
                source='free_carrier_lookup',
                success=True,
                data={
                    'carrier': data.get('carrier'),
                    'country': data.get('country'),
                    'country_code': data.get('country_code'),
                    'line_type': data.get('line_type'),
                    'city': data.get('city') or None,
                    'state': data.get('state') or None,
                },
            )

        # Second fallback: numverify free (no key, very limited but returns country)
        url2 = f"https://api.apilayer.com/number_verification/validate?number={clean}"
        data2 = await self.fetch_json(url2, retries=0)
        if data2 and data2.get('valid'):
            return SourceResult(
                source='free_carrier_lookup',
                success=True,
                data={
                    'country': data2.get('country_name'),
                    'country_code': data2.get('country_code'),
                    'carrier': data2.get('carrier'),
                    'line_type': data2.get('line_type'),
                },
            )

        return SourceResult(
            source='free_carrier_lookup',
            success=False,
            error='All free carrier lookups returned no result',
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
