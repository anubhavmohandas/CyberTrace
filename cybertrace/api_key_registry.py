"""
API key management for CyberTrace.

All keys are optional. CyberTrace degrades gracefully — free/no-key sources
still run. Keys unlock rate-limited or paywalled APIs.

To configure: copy .env.example -> .env and fill in what you have.
Check status at runtime:
    from cybertrace.api_key_registry import API_KEYS
    API_KEYS.print_status()
"""

import os
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class APIKeys:
    """
    Central API key registry, organized by intelligence domain.

    Usage:
        API_KEYS.has('virustotal')      -> bool
        API_KEYS.get('shodan')          -> str | None
        API_KEYS.print_status()         -> formatted table
    """

    # ── Dark Web & Threat Intelligence ────────────────────────────────────────
    intelx: Optional[str] = None
    # https://intelx.io — darknet + breach + paste search
    # Free tier: limited queries/day. Best single dark web OSINT source.

    # ── Domain & IP Intelligence ──────────────────────────────────────────────
    virustotal: Optional[str] = None
    # https://virustotal.com — malware/URL/domain/IP reputation
    # Free tier: 500 req/day

    shodan: Optional[str] = None
    # https://shodan.io — internet-wide port/service scanning
    # Free tier: 100 queries/month

    urlscan: Optional[str] = None
    # https://urlscan.io — URL/domain sandbox scanning
    # Free tier: 5000 scans/day

    abuseipdb: Optional[str] = None
    # https://www.abuseipdb.com/register — IP abuse score + report history
    # Free tier: 1000 checks/day

    greynoise: Optional[str] = None
    # https://viz.greynoise.io/signup — classifies IPs as scanner/benign/malicious
    # Community tier: free with registration

    # ── Email Intelligence ────────────────────────────────────────────────────
    emailrep: Optional[str] = None
    # https://emailrep.io — email reputation, breach exposure, social footprint
    # Free tier: 100 queries/day

    hunter: Optional[str] = None
    # https://hunter.io — email finder + verifier by domain
    # Free tier: 25 verifications/month

    # ── Breach Databases ──────────────────────────────────────────────────────
    hibp: Optional[str] = None
    # https://haveibeenpwned.com/API/Key — breach lookup for email addresses
    # Paid key required for v3 breachedaccount endpoint. ~$4/month.

    dehashed: Optional[str] = None
    # https://dehashed.com — breach DB with plaintext/hashed passwords
    # Paid only (no free tier). Most comprehensive breach source available.

    leakcheck: Optional[str] = None
    # https://leakcheck.io — breach lookup with free tier
    # Good alternative to DeHashed

    # ── Phone Intelligence ────────────────────────────────────────────────────
    numverify: Optional[str] = None
    # https://numverify.com — phone validation + carrier/location lookup
    # Free tier: 100 lookups/month

    twilio_sid: Optional[str] = None
    twilio_token: Optional[str] = None
    # https://twilio.com — carrier lookup, number type (VoIP/mobile/landline)
    # Pay-per-use

    # ── Cryptocurrency / Blockchain ───────────────────────────────────────────
    etherscan: Optional[str] = None
    # https://etherscan.io — Etherscan API V2: one key covers Ethereum,
    # Polygon, and 50+ other EVM chains via a `chainid` query param (see
    # bitcoin_module._EVM_CHAIN_IDS). BscScan/PolygonScan's own separate
    # free-tier keys and domains are retired — confirmed live, both now
    # answer "switch to Etherscan API V2" regardless of any key — so there
    # is no separate bscscan/polygonscan field here any more.
    # Free tier: 5 calls/sec, Ethereum + Polygon; BNB Smart Chain (chainid
    # 56) is gated behind a PAID Etherscan plan even under V2 (confirmed
    # live: "Free API access is not supported for this chain") — see
    # `nodereal` below for the free BNB path this codebase actually uses.

    nodereal: Optional[str] = None
    # https://dashboard.nodereal.io — MegaNode: BNB Smart Chain's free
    # transaction-history source (Etherscan V2's free tier does not cover
    # BNB — see `etherscan` above). Different protocol from every other key
    # here: JSON-RPC 2.0 POST to https://bsc-mainnet.nodereal.io/v1/{key}
    # (`nr_getTransactionByAddress`), not the REST module=account&action=...
    # shape. Free tier: 3 API keys, 100M monthly compute units, no card.

    chainabuse: Optional[str] = None
    # https://docs.chainabuse.com — community-reported scam/abuse address database
    # Requires an organization API key (no free self-serve tier at signup)

    trongrid: Optional[str] = None
    # https://www.trongrid.io — TRON (TRX) account/transaction data
    # Free tier works unauthenticated; a key just raises the rate limit

    # ── Social Media & Identity ───────────────────────────────────────────────
    github: Optional[str] = None
    # https://github.com/settings/tokens — public repo/user/commit OSINT
    # Free: 5000 req/hour authenticated vs 60 unauthenticated

    telegram_bot: Optional[str] = None
    # https://t.me/BotFather — Telegram bot token for channel/group OSINT

    # ── Automation / Captcha ──────────────────────────────────────────────────
    twocaptcha: Optional[str] = None
    # https://2captcha.com — captcha solving for Indian portal lookups (Vahan etc.)
    # ~$2-3 per 1000 captchas

    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> 'APIKeys':
        """Load all keys from environment variables."""
        return cls(
            # Dark Web
            intelx=os.getenv('INTELX_API_KEY'),
            # Domain & IP
            virustotal=os.getenv('VIRUSTOTAL_API_KEY'),
            shodan=os.getenv('SHODAN_API_KEY'),
            urlscan=os.getenv('URLSCAN_API_KEY'),
            abuseipdb=os.getenv('ABUSEIPDB_API_KEY'),
            greynoise=os.getenv('GREYNOISE_API_KEY'),
            # Email
            emailrep=os.getenv('EMAILREP_API_KEY'),
            hunter=os.getenv('HUNTER_API_KEY'),
            # Breach DBs
            hibp=os.getenv('HIBP_API_KEY'),
            dehashed=os.getenv('DEHASHED_API_KEY'),
            leakcheck=os.getenv('LEAKCHECK_API_KEY'),
            # Phone
            numverify=os.getenv('NUMVERIFY_API_KEY'),
            twilio_sid=os.getenv('TWILIO_SID'),
            twilio_token=os.getenv('TWILIO_TOKEN'),
            # Crypto
            etherscan=os.getenv('ETHERSCAN_API_KEY'),
            nodereal=os.getenv('NODEREAL_API_KEY'),
            chainabuse=os.getenv('CHAINABUSE_API_KEY'),
            trongrid=os.getenv('TRONGRID_API_KEY'),
            # Social
            github=os.getenv('GITHUB_TOKEN'),
            telegram_bot=os.getenv('TELEGRAM_BOT_TOKEN'),
            # Automation
            twocaptcha=os.getenv('TWOCAPTCHA_API_KEY'),
        )

    def get(self, key: str) -> Optional[str]:
        """Get a key value by name."""
        return getattr(self, key, None)

    def has(self, key: str) -> bool:
        """Return True if key is set and non-empty."""
        val = self.get(key)
        return val is not None and val.strip() != ''

    def status(self) -> Dict[str, bool]:
        """Return {key_name: is_set} for all keys."""
        return {
            name: self.has(name)
            for name in self.__dataclass_fields__.keys()
        }

    def print_status(self) -> None:
        """Print a formatted status table grouped by category."""
        categories = {
            'Dark Web & Threat Intel': ['intelx'],
            'Domain & IP':            ['virustotal', 'shodan', 'urlscan', 'abuseipdb', 'greynoise'],
            'Email':                  ['emailrep', 'hunter'],
            'Breach Databases':       ['hibp', 'dehashed', 'leakcheck'],
            'Phone':                  ['numverify', 'twilio_sid', 'twilio_token'],
            'Crypto / Blockchain':    ['etherscan', 'nodereal', 'chainabuse', 'trongrid'],
            'Social & Identity':      ['github', 'telegram_bot'],
            'Automation':             ['twocaptcha'],
        }

        print("\n=== CyberTrace API Keys ===\n")
        for category, keys in categories.items():
            print(f"  {category}")
            for key in keys:
                icon = "✓" if self.has(key) else "✗"
                print(f"    [{icon}] {key}")
        print()

        configured = sum(1 for k in self.__dataclass_fields__ if self.has(k))
        total = len(self.__dataclass_fields__)
        print(f"  {configured}/{total} keys configured\n")


# Global singleton — import and use directly anywhere in the codebase
API_KEYS: APIKeys = APIKeys.from_env()
