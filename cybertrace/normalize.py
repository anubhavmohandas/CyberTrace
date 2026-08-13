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
    email    lowercase
    ip       canonical form via ipaddress
    onion    lowercase v3
    domain   lowercase, scheme/port/path stripped
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Iterator, Optional

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


def pgp_fingerprint(block: str) -> Optional[str]:
    """True OpenPGP fingerprint of the primary public key, uppercase hex.

    RFC 4880 §12.2 (v4): SHA-1 over 0x99 || 2-octet body length || packet body.
    RFC 9580 §5.2.2 (v6): SHA-256 over 0x9b || 4-octet body length || body.

    This is the identity the cross-market clone guard turns on, which is why it
    is a real fingerprint and not a hash of the armor: a clone re-exporting the
    copied key changes the armor bytes but never the fingerprint.
    """
    raw = _armor_payload(block)
    if not raw:
        return None
    for tag, body in _packets(raw):
        if tag != 6 or not body:                      # 6 = public key packet
            continue
        version = body[0]
        if version == 4:
            head = b"\x99" + len(body).to_bytes(2, "big")
            return hashlib.sha1(head + body).hexdigest().upper()
        if version == 6:
            head = b"\x9b" + len(body).to_bytes(4, "big")
            return hashlib.sha256(head + body).hexdigest().upper()
        return None                                   # v3 and earlier: not supported
    return None


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


def norm_eth(addr: str) -> Optional[str]:
    """occam: lowercased, EIP-55 mixed-case checksum unverified — same Keccak
    cost as XMR above. 0x + 40 hex is already a tight filter."""
    addr = addr.strip().lower()
    return f"ETH:{addr}" if re.fullmatch(r"0x[0-9a-f]{40}", addr) else None


_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+")


def norm_email(value: str) -> Optional[str]:
    value = value.strip().strip(".,;:<>()[]").lower()
    return value if _EMAIL_RE.fullmatch(value) and len(value) <= 254 else None


def norm_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def norm_onion(value: str) -> Optional[str]:
    """v3 only. v2 was retired in 2021 and its 16-char form collides with far
    too much base32-looking page text to be worth accepting."""
    value = value.strip().lower().removeprefix("http://").removeprefix("https://")
    value = value.split("/", 1)[0].split(":", 1)[0]
    return value if re.fullmatch(r"[a-z2-7]{56}\.onion", value) else None


_DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+"
)


def norm_domain(value: str) -> Optional[str]:
    value = value.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if value.endswith(".onion"):
        return None                                   # an onion is not a domain entity
    return value if _DOMAIN_RE.fullmatch(value) else None


def norm_username(value: str) -> Optional[str]:
    """Case preserved — handles are case-sensitive on some platforms — but the
    entity key lowercases, so 'Op' and 'op' still collapse to one node."""
    value = value.strip()[:64]
    return value if re.fullmatch(r"[A-Za-z0-9._-]{3,64}", value) else None


NORMALIZERS = {
    "PGP_KEY": norm_pgp,
    "BTC_ADDRESS": norm_btc,
    "XMR_ADDRESS": norm_xmr,
    "ETH_ADDRESS": norm_eth,
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
