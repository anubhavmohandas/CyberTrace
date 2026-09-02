"""OFAC SDN Advanced XML offline adapter (US Treasury's own sanctions list,
including typed "Digital Currency Address - <ASSET>" identifiers).

Read-only over external_data/ofac/original/sdn_advanced.xml (streamed with
xml.etree.ElementTree.iterparse, never loaded whole -- same discipline as
exchange_tags.py's zipfile streaming). US Government Work, public domain;
see external_data/ofac/manifest.json.

SAFETY BOUNDARY -- same class as exchange_tags.py's, one level up: this is a
GOVERNMENT designation of a specific address, not a third-party tagpack
guess, so it is its own attribution level (REGULATORY_ATTESTED in
correlate.py) rather than a re-labeling of TAG_ATTESTED. It is still an
assertion about ONE address, never proof that a counterparty of that address
shares the same designation, and never proof of a VASP-ownership
relationship -- some designated parties here (Hydra Market, Blender.io) are
a darknet market and a mixer, not VASPs at all. Nothing here imports
EvidenceStore or ingest(); only evidence.label_exchange, on an analyst's own
say-so, may ever write an EXCHANGE_DEPOSIT edge. Pinned by
tests/test_integrations.py the same way as ellipticpp/evolution/exchange_tags.
"""

from __future__ import annotations

import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from . import _freshness
from ..normalize import norm_bnb, norm_btc, norm_eth, norm_sol, norm_tron

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "external_data" / "ofac"
XML_PATH = DATA_DIR / "original" / "sdn_advanced.xml"
MANIFEST_PATH = DATA_DIR / "manifest.json"
INDEX_PATH = DATA_DIR / "index.sqlite"
_SOURCE_PATHS = (XML_PATH,)

# OFAC's own FeatureType label -> the currency code the rest of CyberTrace
# uses. Only chains CyberTrace has an entity type for -- everything else the
# SDN schema carries (ARB, USDT, XMR, ...) is read and dropped at index-build
# time, same restriction as exchange_tags.py's _NORMALIZERS. Confirmed against
# the real local sdn_advanced.xml (2026-08-30 publication): "BNB" and "BSC"
# both appear as FeatureType labels for the identical BNB Smart Chain address
# space, so both map to the one BNB_ADDRESS currency code -- there is no
# separate "MATIC"/"Polygon" FeatureType anywhere in that file, so Polygon
# gets no entry here (nothing to map, not an oversight; see docs/LOOP34
# Module 2/3 report). "SOL" (Loop 38 Section 8) is real too: 1 FeatureType,
# 4 designated addresses across 3 entities (Sokolovski Rolan, Rashevskyi
# Dmytro x2, SHPS Shelbit) -- checked directly against this file, not
# assumed from the schema's asset-type list alone.
_ASSET_TO_CURRENCY = {"XBT": "BTC", "ETH": "ETH", "BNB": "BNB", "BSC": "BNB",
                      "TRX": "TRX", "SOL": "SOL"}
_NORMALIZERS = {"BTC": norm_btc, "ETH": norm_eth, "BNB": norm_bnb, "TRX": norm_tron,
                "SOL": norm_sol}


def manifest() -> Dict[str, Any]:
    """Provenance metadata: source, license, publication date, checksum."""
    import json
    return json.loads(MANIFEST_PATH.read_text())


def available() -> bool:
    """Whether the SDN Advanced XML was actually downloaded into original/."""
    return XML_PATH.exists()


def index_available() -> bool:
    """Whether the local lookup index has been built (see build_index)."""
    return INDEX_PATH.exists()


def is_stale() -> bool:
    """True if the index doesn't match the SDN Advanced XML's current
    size/mtime -- including an index built before this tracking existed, or
    one with no index at all. See _freshness.py for why size+mtime (not a
    full content hash) and why an unknown state reads as stale rather than
    fresh. A caller (e.g. bitcoin_module._check_exchange_tags's OFAC
    sibling, or a case-level report) should surface this rather than
    silently querying a possibly-obsolete sanctions list."""
    return _freshness.is_stale(INDEX_PATH, _SOURCE_PATHS)


def _local(tag: str) -> str:
    """Strip the ADVANCED_XML namespace off an element tag."""
    return tag.rpartition("}")[2]


def _iter_address_rows() -> Iterator[tuple]:
    """One row per (address, currency) digital-currency identifier found on
    any designated party, canonicalized, BTC/ETH/TRX only.

    Single streaming pass over the ~120MB file: FeatureType IDs -> currency
    codes are read from <ReferenceValueSets> (near the top) as they're seen,
    so by the time <DistinctParty> elements start (the bulk of the file)
    the mapping is already complete -- document order guarantees this, it
    is not assumed. Each DistinctParty's own name/alias/feature subtree is
    still fully attached when its "end" event fires (nothing inside it has
    been cleared yet), so one party is read directly off that subtree with
    no separate state machine, then cleared to bound memory the same way
    effbot's iterparse-memory pattern does.
    """
    currency_by_featuretype: Dict[str, str] = {}
    ns: Optional[str] = None   # "{namespace-uri}", read off the first element
                               # seen -- xml.etree's "{*}tag" wildcard iter()
                               # does not match here (CPython 3.14), so the
                               # real namespace has to be spelled out.
    for event, elem in ET.iterparse(str(XML_PATH), events=("end",)):
        if ns is None and "}" in elem.tag:
            ns = elem.tag.rpartition("}")[0] + "}"
        tag = _local(elem.tag)
        if tag == "FeatureType":
            label = elem.text or ""
            if label.startswith("Digital Currency Address - "):
                asset = label.rsplit(" - ", 1)[-1].strip()
                currency = _ASSET_TO_CURRENCY.get(asset)
                if currency:
                    currency_by_featuretype[elem.get("ID", "")] = currency
            elem.clear()
            continue

        if tag != "DistinctParty":
            continue

        profile_id = elem.get("FixedRef", "")
        primary_name = None
        aliases: List[str] = []
        for alias in elem.iter(ns + "Alias"):
            parts = [p.text for p in alias.iter(ns + "NamePartValue") if p.text]
            name = " ".join(parts).strip()
            if not name:
                continue
            if alias.get("Primary") == "true" and primary_name is None:
                primary_name = name
            elif name not in aliases:
                aliases.append(name)
        if primary_name is None and aliases:
            primary_name = aliases.pop(0)

        if primary_name:
            for feature in elem.iter(ns + "Feature"):
                currency = currency_by_featuretype.get(feature.get("FeatureTypeID", ""))
                if currency is None:
                    continue
                norm_fn = _NORMALIZERS[currency]
                for detail in feature.iter(ns + "VersionDetail"):
                    if not detail.text:
                        continue
                    canon = norm_fn(detail.text.strip())
                    if canon is None:
                        continue
                    yield (canon.split(":", 1)[1], currency, primary_name,
                           "; ".join(aliases), profile_id)
        elem.clear()


def build_index(force: bool = False) -> Path:
    """Build a local read-only SQLite index over the SDN Advanced XML, so a
    single-address lookup is an indexed query instead of a 126MB XML scan.

    A one-time, offline step -- not run implicitly by lookup_address, which
    raises a clear error instead if the index is missing, same contract as
    exchange_tags.build_index.

    force=False (the default) does the cheapest thing that keeps the index
    honest: an index whose recorded fingerprint still matches the XML's
    current size/mtime is returned as-is; one with NO recorded fingerprint
    (built before freshness tracking existed) is stamped with the current
    fingerprint in place rather than re-parsed -- the data hasn't changed,
    only the tracking is new, so paying for a full rescan would be pure
    waste. Only a fingerprint that has actually changed -- the raw XML was
    genuinely replaced -- triggers a real rebuild. force=True always rebuilds.
    """
    current_fp = _freshness.source_fingerprint(_SOURCE_PATHS)
    if INDEX_PATH.exists() and not force:
        recorded_fp = _freshness.read_fingerprint(INDEX_PATH)
        if recorded_fp == current_fp:
            return INDEX_PATH
        if recorded_fp is None:
            _freshness.stamp(INDEX_PATH, current_fp)
            return INDEX_PATH
    # A real rebuild is about to trust this file's bytes -- verify against
    # the manifest's own recorded checksum first (Loop 39 Section 5) so a
    # corrupted/truncated local XML never silently becomes a queryable index.
    expected = manifest()["distribution_channel"]["archive_sha256"]
    _freshness.verify_checksum(XML_PATH, expected)
    tmp_path = INDEX_PATH.with_suffix(".sqlite.building")
    tmp_path.unlink(missing_ok=True)
    conn = sqlite3.connect(tmp_path)
    try:
        conn.executescript("""
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE addresses (
                address TEXT NOT NULL, currency TEXT, entity_name TEXT,
                aliases TEXT, profile_id TEXT
            );
        """)
        conn.executemany(
            "INSERT INTO addresses (address, currency, entity_name, aliases, profile_id) "
            "VALUES (?,?,?,?,?)", _iter_address_rows())
        conn.execute("CREATE INDEX idx_ofac_address ON addresses(address)")
        conn.commit()
    finally:
        conn.close()
    _freshness.stamp(tmp_path, current_fp)
    tmp_path.replace(INDEX_PATH)
    return INDEX_PATH


def lookup_address(address: str, currency: str) -> List[Dict[str, Any]]:
    """Every OFAC digital-currency-address record for `address` on `currency`
    ('BTC'/'ETH'/'TRX'), or [] if none.

    Raises RuntimeError if build_index() has not been run yet -- same
    "don't silently fall back to a slow scan" contract as
    exchange_tags.lookup_address.
    """
    if not index_available():
        raise RuntimeError(
            "OFAC SDN lookup index not built yet -- call "
            "cybertrace.integrations.ofac.build_index() once first "
            "(offline, one-time, a few seconds).")
    norm_fn = _NORMALIZERS.get(currency.upper())
    canon = norm_fn(address) if norm_fn else None
    if canon is None:
        return []
    bare = canon.split(":", 1)[1]
    conn = sqlite3.connect(f"file:{INDEX_PATH}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT currency, entity_name, aliases, profile_id FROM addresses "
            "WHERE address=?", (bare,)).fetchall()
    finally:
        conn.close()
    return [{"currency": r[0], "entity_name": r[1], "aliases": r[2], "profile_id": r[3]}
            for r in rows]


def ofac_labels(addresses: Dict[str, List[str]]) -> Dict[str, Dict[str, Any]]:
    """{raw address -> {"entity_name", "profile_id"}} for every input this
    SDN publication carries a digital-currency-address record for.
    `addresses` is {"BTC": [...], "ETH": [...], "TRX": [...]}.

    Batched for the same reason exchange_tags.exchange_labels is: the caller
    (correlate._vasp_endpoints) asks about every address in a case at once.

    Unlike exchange_labels, there is no category filter here -- OFAC's
    schema has no exchange/market/mixer taxonomy, every row is a government
    designation regardless of what kind of service the party operated. The
    caller is responsible for phrasing this as "OFAC-designated entity", not
    "VASP" -- see this module's docstring.

    Returns {} -- never raises -- when the archive or its index is absent,
    so a reader degrades to "no regulatory attribution available" instead of
    branching on two availability predicates.
    """
    if not (available() and index_available()):
        return {}
    by_canon: Dict[str, str] = {}
    for currency, values in addresses.items():
        norm_fn = _NORMALIZERS.get(currency.upper())
        if norm_fn is None:
            continue
        for raw in values:
            canon = norm_fn(raw)
            if canon is not None:
                by_canon.setdefault(canon.split(":", 1)[1], raw)
    if not by_canon:
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    conn = sqlite3.connect(f"file:{INDEX_PATH}?mode=ro", uri=True)
    try:
        keys = list(by_canon)
        for i in range(0, len(keys), 400):        # SQLITE_MAX_VARIABLE_NUMBER
            chunk = keys[i:i + 400]
            marks = ",".join("?" * len(chunk))
            for addr, entity_name, profile_id in conn.execute(
                    f"SELECT address, entity_name, profile_id FROM addresses "
                    f"WHERE address IN ({marks})", tuple(chunk)):
                raw = by_canon[addr]
                hit = out.get(raw)
                if hit is None:
                    # First record is the primary designation, same as
                    # before. Real corpus data (the Nov-2018 SamSam
                    # ransomware sanctions action, profiles 38419/38420,
                    # sharing BTC address 1H939dom7i4WDLCKyGbXUp3fs9CSTNRzgL)
                    # shows one address CAN carry two distinct government
                    # designations at once -- also_designated keeps the rest
                    # visible instead of silently dropping them, without
                    # changing this dict's shape for the one caller that only
                    # ever reads entity_name/profile_id.
                    out[raw] = {"entity_name": entity_name, "profile_id": profile_id,
                               "also_designated": []}
                elif profile_id != hit["profile_id"]:
                    hit["also_designated"].append(
                        {"entity_name": entity_name, "profile_id": profile_id})
    finally:
        conn.close()
    return out
