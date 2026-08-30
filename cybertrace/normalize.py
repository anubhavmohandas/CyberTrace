"""Canonical forms for every artifact that becomes an evidence-graph entity.

One rule the whole evidence model rests on: **no normalized value, no entity,
no edge.** Extractors are regex-shaped and therefore noisy; a value only earns
an identity here once it validates. That is what stops two markets quoting the
same malformed string from correlating into a shared "operator".

Every function returns the canonical string or None. Canonical forms:

    PGP      PGP:<40 or 64 uppercase hex>   true OpenPGP fingerprint
    BTC      BTC:<address>                  base58check or bech32 verified
    XMR      XMR:<address>                  base58, 69 bytes, network prefix
    ETH      ETH:0x<40 lowercase hex>
    TRX      TRX:<address>                  base58check, 0x41 mainnet prefix
    email    lowercase
    ip       canonical form via ipaddress
    onion    lowercase v3
    domain   lowercase, scheme/port/path stripped
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional

# --- base58 ------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


def b58decode(s: str) -> Optional[bytes]:
    """Decode base58; None if any character is outside the alphabet."""
    n = 0
    for c in s:
        i = _B58_INDEX.get(c)
        if i is None:
            return None
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def b58encode(data: bytes) -> str:
    """Encode bytes as base58 -- the encode side of b58decode above.

    Nothing here mints a BTC/XMR address (this tool only ever validates ones
    already given to it), but tron_hex_to_address needs it: TronGrid's own API
    hands back TRON addresses as raw hex, and re-encoding to the base58check
    T... form is the only way a counterparty pulled from a transaction matches
    the TRX_ADDRESS entity norm_tron would mint for the same address.
    """
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


# --- bech32 (BIP-173) --------------------------------------------------------

_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _bech32_valid(addr: str) -> bool:
    """BIP-173 checksum. Worth the 15 lines: bech32 has no other validation, so
    without the polymod any 'bc1' + charset noise would mint a BTC entity."""
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return False
    hrp, data = addr[:pos], addr[pos + 1:]
    values = []
    for c in data:
        i = _BECH32.find(c)
        if i < 0:
            return False
        values.append(i)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    chk = 1
    for v in expanded + values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= _BECH32_GEN[i] if (top >> i) & 1 else 0
    return chk == 1


# --- OpenPGP -----------------------------------------------------------------

def _armor_payload(block: str) -> Optional[bytes]:
    """Base64 body of an armored block: armor headers, blank line and the CRC24
    line all dropped, so re-wrapped exports of one key decode identically."""
    lines, started = [], False
    for line in block.splitlines():
        s = line.strip()
        if s.startswith("-----BEGIN PGP"):
            started = True
            continue
        if s.startswith("-----END PGP"):
            break
        if not started or not s or s.startswith("=") or ":" in s:
            continue  # armor header / CRC24 / padding
        lines.append(s)
    if not lines:
        return None
    import binascii
    try:
        return binascii.a2b_base64("".join(lines))
    except binascii.Error:
        return None


def _packets(data: bytes) -> Iterator[tuple]:
    """Yield (tag, body) for each OpenPGP packet. Stops at anything malformed
    rather than raising — input is scraped from hostile pages."""
    i = 0
    while i < len(data):
        b = data[i]
        i += 1
        if not b & 0x80:
            return
        if b & 0x40:                                  # new format (RFC 4880 4.2.2)
            tag = b & 0x3F
            if i >= len(data):
                return
            first = data[i]
            i += 1
            if first < 192:
                size = first
            elif first < 224:
                if i >= len(data):
                    return
                size = ((first - 192) << 8) + data[i] + 192
                i += 1
            elif first == 255:
                size = int.from_bytes(data[i:i + 4], "big")
                i += 4
            else:
                return                                # partial-length: unsupported
        else:                                         # old format (4.2.1)
            tag = (b >> 2) & 0x0F
            lentype = b & 0x03
            if lentype == 3:
                return                                # indeterminate length
            width = (1, 2, 4)[lentype]
            size = int.from_bytes(data[i:i + width], "big")
            i += width
        if size < 0 or i + size > len(data):
            return
        yield tag, data[i:i + size]
        i += size


def _key_fingerprint(body: bytes) -> Optional[str]:
    """Fingerprint of one key packet body (primary or subkey), uppercase hex.

    RFC 4880 §12.2 (v4): SHA-1 over 0x99 || 2-octet body length || packet body.
    RFC 9580 §5.2.2 (v6): SHA-256 over 0x9b || 4-octet body length || body.
    """
    if not body:
        return None
    if body[0] == 4:
        return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()
    if body[0] == 6:
        return hashlib.sha256(b"\x9b" + len(body).to_bytes(4, "big") + body).hexdigest().upper()
    return None                                       # v3 and earlier: not supported


def pgp_fingerprint(block: str) -> Optional[str]:
    """True OpenPGP fingerprint of the primary public key, uppercase hex.

    This is the identity the cross-market clone guard turns on, which is why it
    is a real fingerprint and not a hash of the armor: a clone re-exporting the
    copied key changes the armor bytes but never the fingerprint.
    """
    raw = _armor_payload(block)
    if not raw:
        return None
    for tag, body in _packets(raw):
        if tag == 6:                                  # 6 = public key packet
            return _key_fingerprint(body)
    return None


def _key_creation_time(body: bytes) -> Optional[int]:
    """Creation time of one key packet body, Unix epoch seconds, or None.

    RFC 4880 5.5.2 (v4) / RFC 9580 5.5.2 (v6): byte 0 is the key version, bytes
    1-4 the 4-octet creation time — same offset for both, so one read covers
    either. v3 and truncated bodies are unsupported, same as _key_fingerprint.
    """
    if not body or body[0] not in (4, 6) or len(body) < 5:
        return None
    return int.from_bytes(body[1:5], "big")


def _epoch_to_iso(ts: Optional[int]) -> Optional[str]:
    """Unix timestamp -> UTC ISO 8601, or None if it cannot be a real date.

    Packet bytes are scraped from hostile pages; a value that overflows a
    calendar date must come back as 'unavailable', never as a fabricated one.
    """
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def pgp_key_times(block: str) -> Dict[str, Optional[str]]:
    """Creation and expiration time of the primary public key, straight from
    the packet bytes — never inferred from when a page happened to be crawled.

    created_at is the key packet's own creation-time field. expires_at has no
    field of its own on a v4/v6 key (that was v3-only); instead it comes from
    the Key Expiration Time subpacket (type 9, seconds after creation) on the
    key's own most recent self-signature — the same resolution rule a real
    OpenPGP implementation uses once a key has been re-certified. A signature
    only counts toward this if its issuer actually resolves to this key's own
    fingerprint; an un-attributed or third-party signature's expiration claim
    is not evidence about when THIS key expires.

    Either field is None ('unavailable') when the block does not parse or
    carries no such subpacket. A Key Expiration Time of 0 explicitly means
    'does not expire' (RFC 4880 5.2.3.6) and also yields expires_at=None —
    that is a real value, not a missing one, but this call site has no use for
    the distinction.
    """
    raw = _armor_payload(block)
    if not raw:
        return {"created_at": None, "expires_at": None}
    packets = list(_packets(raw))
    created, own = None, set()
    for tag, body in packets:
        if tag == 6 and created is None:              # primary key: first one wins
            created = _key_creation_time(body)
        if tag in (6, 14):                            # public key, public subkey
            fpr = _key_fingerprint(body)
            if fpr:
                own |= {fpr, fpr[-16:]}
    best_seconds, best_created = None, -1
    for tag, body in packets:
        if tag != 2:                                  # 2 = signature
            continue
        info = _parse_signature(body)
        if not info or info["key_expiration_seconds"] is None:
            continue
        issuer = info["issuer"]
        is_self = issuer is not None and (issuer in own or issuer[-16:] in own)
        if not is_self:
            continue
        marker = info["sig_created_at"] or 0
        if marker >= best_created:                    # most recent self-cert wins
            best_created, best_seconds = marker, info["key_expiration_seconds"]
    expires_at = (_epoch_to_iso(created + best_seconds)
                  if created is not None and best_seconds else None)
    return {"created_at": _epoch_to_iso(created), "expires_at": expires_at}


# --- OpenPGP signatures ------------------------------------------------------
#
# A displayed key is the one thing a clone can copy perfectly, so "this market
# shows key K" is the weakest possible PGP evidence. Who *signed* what is the
# part a clone cannot fake: a third-party certification on a key, or a signed
# announcement, both require the other key's secret half. These two parsers are
# what let the graph tell those apart — see evidence.ARTIFACT_MAP consumers.

# Signature types that assert something about an identity (RFC 4880 §5.2.1):
# 0x10-0x13 certify a User ID, 0x1F is a direct key signature. Subkey bindings
# (0x18) and revocations are deliberately excluded: a binding is self-made, so
# it says nothing about a second party.
_CERT_SIG_TYPES = frozenset({0x10, 0x11, 0x12, 0x13, 0x1F})

_SUBPKT_SIG_CREATION_TIME = 2
_SUBPKT_KEY_EXPIRATION = 9
_SUBPKT_ISSUER_KEYID = 16
_SUBPKT_ISSUER_FPR = 33


def _subpackets(data: bytes) -> Iterator[tuple]:
    """Yield (type, body) for each signature subpacket. Stops at malformed."""
    i = 0
    while i < len(data):
        first = data[i]
        i += 1
        if first < 192:
            length = first
        elif first < 255:
            if i >= len(data):
                return
            length = ((first - 192) << 8) + data[i] + 192
            i += 1
        else:
            length = int.from_bytes(data[i:i + 4], "big")
            i += 4
        if length < 1 or i + length > len(data):
            return
        yield data[i], data[i + 1:i + length]
        i += length


def _parse_signature(body: bytes) -> Optional[dict]:
    """sig_type, issuer and the two time-bearing subpackets for one signature
    packet body: Signature Creation Time (type 2, every real signature carries
    one) and Key Expiration Time (type 9, seconds after the signed key's own
    creation — only present on a self-signature that sets an expiry).

    Issuer is the 40/64-hex fingerprint when the signature carries one, else the
    16-hex long key id. Preferring the fingerprint matters downstream: norm_pgp
    keeps key ids in a weaker namespace, so a signature that names a fingerprint
    resolves onto the same node as the key itself instead of an alias.
    """
    if len(body) < 6:
        return None
    version = body[0]
    if version in (4, 5):
        sig_type, count_width = body[1], 2
    elif version == 6:
        sig_type, count_width = body[1], 4
    else:
        return None                                   # v3: issuer is at a fixed offset,
                                                      # and v3 keys are long dead
    i = 4
    issuer = None
    sig_created_at = None
    key_expiration_seconds = None
    for _ in range(2):                                # hashed, then unhashed area
        if i + count_width > len(body):
            break
        size = int.from_bytes(body[i:i + count_width], "big")
        i += count_width
        area, i = body[i:i + size], i + size
        for sub_type, sub_body in _subpackets(area):
            if sub_type == _SUBPKT_ISSUER_FPR and len(sub_body) >= 21:
                issuer = sub_body[1:].hex().upper()    # leading byte is key version
            elif sub_type == _SUBPKT_ISSUER_KEYID and len(sub_body) == 8 and not issuer:
                issuer = sub_body.hex().upper()
            elif sub_type == _SUBPKT_SIG_CREATION_TIME and len(sub_body) == 4:
                sig_created_at = int.from_bytes(sub_body, "big")
            elif sub_type == _SUBPKT_KEY_EXPIRATION and len(sub_body) == 4:
                key_expiration_seconds = int.from_bytes(sub_body, "big")
    return {"sig_type": sig_type, "issuer": issuer, "sig_created_at": sig_created_at,
            "key_expiration_seconds": key_expiration_seconds}


def _sig_issuer(body: bytes) -> Optional[tuple]:
    """(sig_type, issuer) for one signature packet body. Thin view over
    _parse_signature for the two callers that only need identity."""
    info = _parse_signature(body)
    return (info["sig_type"], info["issuer"]) if info and info["issuer"] else None


def _armor_blocks(text: str, kind: str) -> Iterator[str]:
    """Every `-----BEGIN PGP <kind>-----` … `-----END …` block in some text."""
    return (m.group(0) for m in re.finditer(
        rf"-----BEGIN PGP {kind}-----.*?-----END PGP {kind}-----", text, re.DOTALL))


def pgp_certifier_details(block: str) -> List[dict]:
    """Third-party certifications on this public key, each with the issuer and
    that signature's own Signature Creation Time where the packet carries one.

    Same self-signature exclusion as pgp_certifiers, kept as a separate
    function rather than changing that one's return shape: evidence.ingest and
    the corpus payload format both depend on 'certifiers' staying a plain list
    of issuer strings, and this is the richer view for callers that want the
    per-signature timestamp instead.
    """
    raw = _armor_payload(block)
    if not raw:
        return []
    packets = list(_packets(raw))
    own = set()
    for tag, body in packets:
        if tag in (6, 14):                            # public key, public subkey
            fpr = _key_fingerprint(body)
            if fpr:
                own |= {fpr, fpr[-16:]}
    out = []
    for tag, body in packets:
        if tag != 2:                                  # 2 = signature
            continue
        info = _parse_signature(body)
        if not info or not info["issuer"]:
            continue
        issuer = info["issuer"]
        if info["sig_type"] in _CERT_SIG_TYPES and issuer not in own and issuer[-16:] not in own:
            out.append({"issuer": issuer,
                        "sig_created_at": _epoch_to_iso(info["sig_created_at"])})
    return out


def pgp_certifiers(block: str) -> list:
    """Keys that certified this public key, excluding its own self-signatures.

    A third-party certification is the strongest successor signal the graph has:
    the holder of the certifying key's secret half vouched for this one. Cloning
    a displayed key copies these packets too, so the certification is evidence
    about the *key*, never on its own about the site displaying it.
    """
    return sorted({d["issuer"] for d in pgp_certifier_details(block)})


def pgp_signature_issuers(text: str) -> list:
    """Issuers of every detached/clearsigned PGP SIGNATURE block in some text.

    An operator who signs an announcement proves current control of the key.
    That is the role a copied key cannot supply, which is why the collector
    records it separately from "a key block was on the page".
    """
    out = []
    for block in _armor_blocks(text, "SIGNATURE"):
        raw = _armor_payload(block)
        if not raw:
            continue
        for tag, body in _packets(raw):
            if tag != 2:
                continue
            parsed = _sig_issuer(body)
            if parsed and parsed[1]:
                out.append(parsed[1])
    return sorted(set(out))


# --- public normalizers ------------------------------------------------------

def norm_pgp(value: str) -> Optional[str]:
    """Armored block -> PGP:<fingerprint>. Also accepts a bare fingerprint, or
    a 16-hex long key id in its own PGP:KEYID: namespace.

    The namespace split is deliberate. A key id (or the payload hash the
    collector falls back to when armor won't parse) identifies a key far more
    weakly than a fingerprint does, so it must never land on the same node and
    silently inherit a fingerprint's evidential weight. Two ids collapse into
    one identity only when something proves they are the same key.
    """
    value = value.strip()
    if "-----BEGIN PGP" in value:
        fpr = pgp_fingerprint(value)
        return f"PGP:{fpr}" if fpr else None
    bare = value.replace(" ", "").upper().removeprefix("PGP:").removeprefix("0X")
    if re.fullmatch(r"[0-9A-F]{40}|[0-9A-F]{64}", bare):
        return f"PGP:{bare}"
    if re.fullmatch(r"[0-9A-F]{16}", bare):
        return f"PGP:KEYID:{bare}"
    return None


def norm_btc(addr: str) -> Optional[str]:
    addr = addr.strip()
    low = addr.lower()
    if low.startswith(("bc1", "tb1")):
        return f"BTC:{low}" if _bech32_valid(low) else None
    raw = b58decode(addr)
    if raw is None or len(raw) != 25:
        return None
    if raw[0] not in (0x00, 0x05):                    # P2PKH / P2SH mainnet
        return None
    if hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        return None
    return f"BTC:{addr}"


# Monero does NOT use plain base58: it encodes in 8-byte blocks of 11 chars,
# with a short final block. Decoding the whole string as one integer (the
# Bitcoin scheme) yields the wrong bytes, so the two need separate decoders.
_XMR_BLOCK_BYTES = {11: 8, 10: 7, 9: 6, 7: 5, 6: 4, 5: 3, 3: 2, 2: 1}

# Address type prefixes: standard / integrated / subaddress, per network.
_XMR_PREFIXES = {18, 19, 42, 53, 54, 63, 24, 25, 36}


def _xmr_b58decode(s: str) -> Optional[bytes]:
    out = bytearray()
    for i in range(0, len(s), 11):
        block = s[i:i + 11]
        width = _XMR_BLOCK_BYTES.get(len(block))
        if width is None:
            return None
        n = 0
        for c in block:
            idx = _B58_INDEX.get(c)
            if idx is None:
                return None
            n = n * 58 + idx
        if n >= 1 << (8 * width):                     # block overflows its width
            return None
        out += n.to_bytes(width, "big")
    return bytes(out)


def norm_xmr(addr: str) -> Optional[str]:
    """Monero: block-base58 to a known length and network/type prefix.

    Structural validation only — unlike norm_btc this does NOT prove the
    address is real. A 95-char base58 run with a valid leading prefix passes.

    occam: no checksum. Monero's is Keccak-256, which is NOT hashlib.sha3_256
    (different padding byte), so verifying it costs ~35 lines of hand-rolled
    permutation for one coin, and nothing installed provides it. The residual
    risk is a junk XMR node in one dossier: to become a false *correlation* the
    same random 95-char string would have to appear on two markets. Upgrade:
    add keccak-256 and check raw[-4:] if false XMR entities ever appear.
    """
    addr = addr.strip()
    if not 94 <= len(addr) <= 107:
        return None
    raw = _xmr_b58decode(addr)
    if raw is None or len(raw) not in (69, 77):       # standard/sub, integrated
        return None
    if raw[0] not in _XMR_PREFIXES:
        return None
    return f"XMR:{addr}"


def _norm_evm(prefix: str, addr: str) -> Optional[str]:
    """occam: lowercased, EIP-55 mixed-case checksum unverified — same Keccak
    cost as XMR above. 0x + 40 hex is already a tight filter.

    `prefix` is only this normalized value's own dedup namespace, not a chain
    claim -- upsert_entity already dedups on (etype, normalized_value), so
    ETH_ADDRESS/BNB_ADDRESS/POLYGON_ADDRESS entities for the identical string
    never collide regardless of this prefix. It exists so a raw DB read never
    shows a BNB address normalized as "ETH:0x..." -- see norm_bnb/norm_polygon
    and detector.chain_caveat for why the string alone can never say which of
    the three chains a 0x address is actually on.
    """
    addr = addr.strip().lower()
    return f"{prefix}:{addr}" if re.fullmatch(r"0x[0-9a-f]{40}", addr) else None


def norm_eth(addr: str) -> Optional[str]:
    return _norm_evm("ETH", addr)


def norm_bnb(addr: str) -> Optional[str]:
    return _norm_evm("BNB", addr)


def norm_polygon(addr: str) -> Optional[str]:
    return _norm_evm("POLYGON", addr)


def norm_tron(addr: str) -> Optional[str]:
    """TRON base58check: same double-SHA256 checksum scheme norm_btc verifies,
    a 0x41 mainnet prefix byte in place of BTC's 0x00/0x05, 25 raw bytes total."""
    addr = addr.strip()
    raw = b58decode(addr)
    if raw is None or len(raw) != 25:
        return None
    if raw[0] != 0x41:
        return None
    if hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        return None
    return f"TRX:{addr}"


def tron_hex_to_address(hex_addr: str) -> Optional[str]:
    """21-byte hex (0x41 prefix + 20-byte pubkey hash) -> base58check T...

    TronGrid's own transaction payloads (owner_address/to_address, and the
    ABI-encoded recipient inside a TRC20 transfer's calldata) are all hex, not
    the T... form CyberTrace's TRX_ADDRESS entities use — see
    modules/tron_module.py. None on anything that isn't a well-formed TRON
    hex address, so a malformed value degrades to "no counterparty" rather
    than minting a garbage entity.
    """
    try:
        raw = bytes.fromhex(hex_addr)
    except ValueError:
        return None
    if len(raw) != 21 or raw[0] != 0x41:
        return None
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return b58encode(raw + checksum)


# File extensions that land in the TLD slot when scraping HTML: `logo@2x.webp`
# is a retina asset filename, not a mailbox. This guard is why the list exists —
# a false email seeds a false local-part username, which seeds false social
# accounts, so one bad extraction multiplies into a whole invented subgraph.
_NON_TLD = frozenset("""
webp png jpg jpeg gif svg ico bmp tif tiff avif
css js mjs json xml map woff woff2 ttf eot otf
html htm php asp aspx jsp cgi
mp3 mp4 webm ogg wav avi mov pdf zip gz tar rar
py rb sh txt md yml yaml toml lock
""".split())

# TLD is alphabetic or punycode — never digits, never a hyphen. `foo@bar.2x`
# never reaches the extension list because the shape already fails.
_EMAIL_RE = re.compile(r"[^@\s]+@(?:[^@\s.]+\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})")

# RFC 2606 reserved names plus the placeholder domains that actually appear in
# signup instructions on these sites. Rejecting them here rather than at scoring
# time is the point: an accepted `mail@example.org` is pivoted into a keyserver
# lookup, and the real people whose keys carry that documentation address get
# pulled into the case as operator candidates. A false artifact must never reach
# enrichment, because enrichment turns it into someone else's identity.
_PLACEHOLDER_DOMAINS = frozenset("""
example.com example.net example.org example.edu esample.org
domain.tld domain.com yourdomain.com mydomain.com site.com
""".split())
_PLACEHOLDER_TLDS = frozenset("example test invalid localhost local tld".split())
# `test1@`, `user2@` — a trailing digit is how a doc example enumerates accounts.
_PLACEHOLDER_WORDS = (
    r"test|example|sample|user|username|youremail|your-email|yourname|email"
    r"|someone|somebody|foo|bar|baz|firstname|lastname|changeme|placeholder"
    r"|john\.?doe|jane\.?doe"
)
# …and a local part built ONLY out of those words is still a placeholder however
# many are strung together: Cock.li's webmail prints `example-test@cock.li` into
# its login field, which the single-word form accepted as a real mailbox one
# pivot short of a keyserver lookup. A part that mixes in anything else —
# `bar-support@` — fails the full match and is kept.
_PLACEHOLDER_LOCAL_RE = re.compile(
    rf"(?:{_PLACEHOLDER_WORDS})\d*(?:[-_.](?:{_PLACEHOLDER_WORDS})\d*)*"
)


def _registrable(domain: str) -> str:
    """Last two labels. Not a PSL lookup — `foo.co.uk` reads as `co.uk` — which
    is fine for both callers: they compare against explicit stoplists, so an
    over-broad suffix simply fails to match rather than banning a real host."""
    return ".".join(domain.rsplit(".", 2)[-2:])


def norm_email(value: str) -> Optional[str]:
    """A plausible domain is required, not merely `something@something.tld`.

    occam: no IANA TLD list — nothing installed carries one and a vendored copy
    goes stale, rejecting new gTLDs. Shape + extension blocklist catches the
    asset-filename family that actually appears in scraped pages. Upgrade to a
    real TLD allowlist if false emails survive in some other shape.
    """
    value = value.strip().strip(".,;:<>()[]").lower()
    if not _EMAIL_RE.fullmatch(value) or len(value) > 254:
        return None
    local, domain = value.rsplit("@", 1)
    if domain.rpartition(".")[2] in _NON_TLD:
        return None
    # A local-part that opens or closes on `-` or `.` is a fragment, not a
    # mailbox. Riseup's list instructions read `listname-subscribe@lists.riseup
    # .net`, and the extractor — starting at the first character it can match —
    # took `-subscribe@lists.riseup.net`, an address belonging to no one, and
    # minted it as an operator artifact. Leading/trailing/doubled dots are
    # invalid dot-atom outright (RFC 5322 3.2.3). Catching the shape covers the
    # whole `-request@`/`-owner@`/`-bounces@` family, which naming the two
    # observed strings would not.
    if local[0] in "-." or local[-1] in "-." or ".." in local:
        return None
    # Documentation, not a mailbox — never let it reach the keyserver pivot.
    if (domain in _PLACEHOLDER_DOMAINS
            or _registrable(domain) in _PLACEHOLDER_DOMAINS
            or domain.rpartition(".")[2] in _PLACEHOLDER_TLDS
            or _PLACEHOLDER_LOCAL_RE.fullmatch(local)):
        return None
    # A mailbox AT page furniture is page furniture. The stoplist below already
    # declares these hosts to be things any two unrelated sites cite, and that
    # reasoning does not stop at the hostname: `gettor@torproject.org` is a Tor
    # download instruction, not somebody's contact address, and an address at a
    # code host or a standards body belongs to that organisation rather than to
    # whoever printed it.
    #
    # Measured, and it is the case this whole corpus exists to catch. SecureDrop
    # ships that gettor address in its Tor install instructions, so four
    # independently-operated newsrooms — CBC, Forbes, The Guardian, ProPublica —
    # published the same mailbox. EMAIL is a full-control artifact class, so the
    # engine promoted it to an OPERATOR candidate spanning all four at 0.47,
    # against 0.58 for the genuine DNMX pair. Commonness could not save it and
    # never could: with 5 of the world's SecureDrop instances in the corpus, the
    # platform's own address measures as RARE (0.67, well over the 0.5 floor).
    # That is the general shape of the problem — a corpus never holds enough of
    # a family for frequency alone to expose the family's furniture.
    if domain in _BOILERPLATE_DOMAINS or _registrable(domain) in _BOILERPLATE_DOMAINS:
        return None
    # An onion mailbox is a real operator pivot, so it is accepted — but only for
    # an address that is actually an onion. `user@example.onion` is documentation.
    if domain.endswith(".onion") and norm_onion(domain) is None:
        return None
    return value


def norm_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


# Page sections whose artifacts belong to somebody other than the operator. A
# value here is still real and still worth recording — it is simply evidence
# about whoever was quoted or subscribed, so it must never carry an edge that
# says the site *controls* it, and must never reach enrichment, which is the
# step that turns a string into a named person.
#
#   quoted  content the page reproduces: a forwarded message, a pasted header
#   roster  mailing-list membership: a subscriber, list user or list admin —
#           roles that belong to USERS of a list service, not to whoever runs it
#   demo    a program's output pasted into a walkthrough: gpg key-generation
#           prompts, monero-wallet-cli transcripts. The cast of a tutorial, and
#           on nowhere.moe's OPSEC Bible it reached the keyserver — see
#           darkweb_module._DEMO_LEAD for the measurement
#
# Lives here rather than beside the section rules in darkweb_module because both
# the collector (which refuses to pivot them) and evidence.ingest (which demotes
# their edge to MENTIONS) have to agree on the set, and drift between those two
# is silent: the artifact would keep its operator edge while looking suppressed.
NON_ATTRIBUTIVE_SECTIONS = frozenset({"quoted", "roster", "demo"})


def _v3_checksum_ok(label: str) -> bool:
    """Verify the checksum a v3 address carries in its own bytes.

    A v3 label decodes to pubkey(32) || checksum(2) || version(1), where the
    checksum is SHA3-256(".onion checksum" || pubkey || version)[:2]. Tor
    enforces this before it will build a circuit, so every address that was ever
    reachable passes and rejecting the rest costs no real service.

    What it stops is a whole class of phantom entity. Directories corrupt the
    addresses they display on purpose — tor.taxi mangles a character in every
    link it prints, "unclickable for your safety" — so a page listing 140 sites
    yields 140 addresses that no one operates. Read as observations they are
    entities like any other: they inflate the commonness denominators, and each
    one is a plausible-looking sibling of the real address it was derived from.
    A typo'd or phish-bait address arrives the same way.
    """
    try:
        raw = base64.b32decode(label.upper())
    except binascii.Error:
        return False
    if len(raw) != 35 or raw[34] != 3:
        return False
    return hashlib.sha3_256(b".onion checksum" + raw[:32] + b"\x03").digest()[:2] == raw[32:34]


def norm_onion(value: str) -> Optional[str]:
    """v3 only. v2 was retired in 2021 and its 16-char form collides with far
    too much base32-looking page text to be worth accepting.

    Subdomain labels are dropped, matching detector.normalize_input: the circuit
    is built to the .onion address itself, so `www.<addr>.onion` — the form
    Facebook and Reddit publish — is the same hidden service and must resolve to
    one node, not a second one that never correlates with the first.

    The address must also verify its own checksum: shape alone is not identity,
    and a corrupted address is not a service. See _v3_checksum_ok.
    """
    value = value.strip().lower().removeprefix("http://").removeprefix("https://")
    value = value.split("/", 1)[0].split(":", 1)[0]
    value = ".".join(value.split(".")[-2:])
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", value):
        return None
    return value if _v3_checksum_ok(value[:56]) else None


_DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+"
)


# Standards bodies, code hosts, CDNs, browsers, the Tor Project itself: page
# furniture that any two sites cite without being related. Admitting them as
# DOMAIN entities is what manufactures "shared infrastructure" between markets
# and then a SUCCESSOR hypothesis on top of it, so the stoplist has to apply
# before the entity exists, not at scoring time where the edge already ranks.
#
# The second block was measured on the v5 corpus, where each of these was the
# ONLY thing joining two unrelated targets: `ogp.me` (an Open Graph namespace
# declared in a meta prefix) paired Blockchair with Riseup, `t.me` paired
# Blockchair with the Tor Project, `duckduckgo.com` paired Riseup with the Tor
# Project, `bitcoin.it` paired Endchan with Riseup, and the WordPress pingback
# and stats hosts paired the two DNMX addresses for a reason that has nothing to
# do with their operator. Note what is NOT here: only the *host* is ever kept —
# norm_domain drops the path — so `t.me/someone` cannot carry an operator handle
# either way, and stoplisting the host loses no identity that ever existed.
#
# Two kinds of domain are deliberately NOT here, and both would do real damage:
#
#   a platform's own domain (onionmail.info, lynxchan.com) — that is the
#   ecosystem signal. Refusing it as an entity would leave two servers of one
#   mail platform sharing nothing, so the engine would rank them UNRELATED by
#   accident instead of reporting SHARED_PLATFORM and saying why. Commonness
#   scoring, not a stoplist, is what keeps a platform domain from reading as an
#   operator — see correlate.contradictions_from_commonness.
#
#   a domain some target IS (blockchair.com, facebook.com, reddit.com). Every
#   one of those is a plausible onion target, and its clearnet name is that
#   operator's own identity, not furniture on its own site.
#
# occam: a named list, no PSL and no crawl-frequency model. Commonness scoring in
# correlate.entity_discrimination is the general mechanism; this list is only for
# furniture that must never become an entity at all. Add to it from measured
# false pairs, never speculatively.
_BOILERPLATE_DOMAINS = frozenset("""
w3.org w.org wordpress.org wordpress.com schema.org unicode.org ietf.org
torproject.org getmonero.org bitcoin.org gnupg.org openpgp.org letsencrypt.org
github.com github.io gitlab.com sourceforge.net npmjs.com jquery.com
google.com googleapis.com gstatic.com googletagmanager.com google-analytics.com
mozilla.org wikipedia.org wikimedia.org archive.org archive.is creativecommons.org
cloudflare.com jsdelivr.net unpkg.com bootstrapcdn.com fontawesome.com

ogp.me purl.org xmlns.com rssboard.org phrasewise.com pingomatic.com
wp-statistics.com automattic.com gravatar.com
gnu.org fsf.org apache.org nginx.org debian.org ubuntu.com python.org nodejs.org
perl.org php.net mysql.com postgresql.org bitcoin.it
duckduckgo.com bing.com startpage.com searx.me yandex.com
t.me telegram.org telegram.me twitter.com x.com instagram.com
youtube.com youtu.be linkedin.com mastodon.social matrix.org
signal.org whatsapp.com paypal.com patreon.com opencollective.com
""".split())


# Addresses of other overlay networks. `.onion` was already refused here — an
# onion has its own entity type — and the same reasoning covers the rest: an I2P
# b32 or a Lokinet address is a network identifier, not a clearnet host, so
# admitting it as a DOMAIN buries it in the one entity class whose whole meaning
# is "a name in the DNS a subpoena can reach".
#
# Measured on the v5+v6 corpus, where two of them were already entities shared by
# two targets each: `4oymiquy…b32.i2p` (two imageboards linking one eepsite) and
# `kqrtg5wz…loki`. `_registrable` also mangles them — the last two labels of a
# b32 address are `b32.i2p`, so every eepsite in a corpus would group into one
# namespace and draw the multi-host bonus meant for an operator's own subdomains.
_OVERLAY_TLDS = frozenset({"onion", "i2p", "loki", "exit", "bit"})


def norm_domain(value: str) -> Optional[str]:
    value = value.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if value.rpartition(".")[2] in _OVERLAY_TLDS:
        return None                                   # another network's address
    if norm_ip(value):
        # A literal address in a URL is a host, and there is already an entity
        # type and an extractor for that. Admitted here it became a second,
        # weaker copy of the same fact under the wrong type — and `_registrable`
        # bucketed 78.17.212.207 as "212.207", so two unrelated addresses in one
        # /16 would have grouped as one namespace and drawn the multi-host
        # context bonus meant for an operator's own subdomains.
        return None
    if not _DOMAIN_RE.fullmatch(value):
        return None
    # RFC 2606 documentation names, same list norm_email already refuses. The
    # asymmetry was the defect: `webmaster@example.com` was correctly no mailbox
    # while `example.com` beside it became a DOMAIN entity, and two sites whose
    # docs quote the same example host would then share it. Measured — zzzchan's
    # FAQ prints `example.com` in an instruction — and a documentation name is
    # the one host guaranteed to appear on unrelated sites for unrelated reasons.
    if (value in _PLACEHOLDER_DOMAINS
            or _registrable(value) in _PLACEHOLDER_DOMAINS
            or value.rpartition(".")[2] in _PLACEHOLDER_TLDS):
        return None
    if value in _BOILERPLATE_DOMAINS or _registrable(value) in _BOILERPLATE_DOMAINS:
        return None
    return value


def norm_username(value: str) -> Optional[str]:
    """Case preserved — handles are case-sensitive on some platforms — but the
    entity key lowercases, so 'Op' and 'op' still collapse to one node."""
    value = value.strip()[:64]
    return value if re.fullmatch(r"[A-Za-z0-9._-]{3,64}", value) else None


def norm_asn(value: str) -> Optional[str]:
    """`AS15169`, `15169` and `AS15169 Google LLC` are one network, and the
    enrichment sources disagree on which form they hand back — collapse them so a
    provider doesn't become three nodes that never converge.

    Anchored on purpose: a bare digit anywhere in a company name ('Level 3
    Parent, LLC') is not an AS number.
    """
    value = (value or "").strip()
    m = re.fullmatch(r"(?:AS)?(\d{1,10})", value, re.I) or \
        re.match(r"AS(\d{1,10})\b", value, re.I)
    return f"AS{int(m.group(1))}" if m else None


# --- page structure ----------------------------------------------------------

_TAG_RE = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9]{0,14})\b", re.A)
_CLASS_RE = re.compile(r'class\s*=\s*["\']([^"\']{1,200})["\']', re.I)
_SHINGLE = 4


def dom_simhash(html: str) -> Optional[str]:
    """64-bit simhash of a page's structure, as 16 hex chars.

    Built from tag-name shingles and class tokens — the template — never from
    the prose. Two markets running one operator's copied build match here even
    after every word on the page is rewritten, and two unrelated sites running
    the same off-the-shelf software match too. That second case is the whole
    reason this is a *similarity* input and not an identity: it feeds the clone
    guard, which weighs it against temporal precedence, rather than minting an
    entity that two independent sites would share.

    occam: simhash over shingles, not a tree edit distance. One 64-bit number
    per page, comparable with a popcount, no parser and no dependency. Upgrade
    to real DOM ancestry only if template families stop separating.
    """
    tags = _TAG_RE.findall(html or "")
    if len(tags) < _SHINGLE:
        return None
    tokens = ["|".join(t.lower() for t in tags[i:i + _SHINGLE])
              for i in range(len(tags) - _SHINGLE + 1)]
    tokens += [f"class:{c}" for attr in _CLASS_RE.findall(html or "")
               for c in attr.lower().split()[:8]]
    bits = [0] * 64
    for token in tokens:
        digest = int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")
        for b in range(64):
            bits[b] += 1 if digest >> b & 1 else -1
    return f"{sum(1 << b for b in range(64) if bits[b] > 0):016x}"


def simhash_similarity(a: Optional[str], b: Optional[str]) -> float:
    """1.0 identical structure, 0.0 nothing in common. None on either side -> 0.

    The floor is not 0 in practice. Every HTML document shares html/head/body/a
    shingles, so unrelated real pages measure around 0.62 — on the corpus,
    unrelated sites landed at 0.62-0.64 and two onions of one service at 0.68.
    Read this as a *relative* measure inside that band, never as a percentage of
    shared content, and calibrate any threshold against a corpus rather than
    against intuition about what 0.6 ought to mean.
    """
    if not a or not b:
        return 0.0
    try:
        distance = bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return 0.0
    return round(1.0 - distance / 64.0, 4)


NORMALIZERS = {
    "PGP_KEY": norm_pgp,
    "ASN": norm_asn,
    "BTC_ADDRESS": norm_btc,
    "XMR_ADDRESS": norm_xmr,
    "ETH_ADDRESS": norm_eth,
    "BNB_ADDRESS": norm_bnb,
    "POLYGON_ADDRESS": norm_polygon,
    "TRX_ADDRESS": norm_tron,
    "EMAIL": norm_email,
    "IP": norm_ip,
    "ONION_ADDRESS": norm_onion,
    "DOMAIN": norm_domain,
    "USERNAME": norm_username,
}


def normalize(etype: str, value: str) -> Optional[str]:
    """Normalize by entity type. Types without a validator pass through trimmed."""
    fn = NORMALIZERS.get(etype)
    if fn is None:
        value = (value or "").strip()
        return value or None
    try:
        return fn(value)
    except Exception:                                 # scraped input; never fatal
        return None
