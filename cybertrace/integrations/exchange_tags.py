"""GraphSense TagPacks offline adapter (community-contributed public address
tags: exchange, ransomware, sanctions, mixer, scam, and other categories).

Read-only over external_data/exchange_tags/original/graphsense-tagpacks.zip
(never extracted to disk -- streamed with `zipfile`, same as evolution.py).
MIT licensed (confirmed via the GitHub API) -- unlike Elliptic++ this dataset
is openly redistributable; see external_data/exchange_tags/manifest.json.

exchange_labels/vasp_disclosed_labels read category='exchange' only (VASP
attribution); service_tags reads a disjoint, non-VASP set -- mixing_service,
defi, defi_dex, coinjoin (see _SERVICE_CATEGORIES) -- kept out of VASP
attribution entirely, never merged into the same field.

SAFETY BOUNDARY -- same class as ellipticpp.py's, applied to a second, public
dataset: a tag here is a THIRD PARTY's public claim about an address (a
contributed tagpack entry), never CyberTrace's own finding and never proof of
control. lookup_address IS called live, per address, from bitcoin_module.py
and tron_module.py -- but only to write exchange_tag_* as non-attributive
entity metadata via evidence.enrich_bitcoin, never a relationship. Nothing
here imports EvidenceStore or ingest(); only evidence.label_exchange, on an
analyst's own say-so, may ever write an EXCHANGE_DEPOSIT edge -- see that
function's docstring. Pinned by tests/test_integrations.py the same way as
ellipticpp/evolution.
"""

from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ..normalize import norm_btc, norm_eth, norm_tron

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "external_data" / "exchange_tags"
ZIP_PATH = DATA_DIR / "original" / "graphsense-tagpacks.zip"
MANIFEST_PATH = DATA_DIR / "manifest.json"
INDEX_PATH = DATA_DIR / "index.sqlite"

_PACKS_PREFIX = "graphsense-tagpacks-master/packs/"

# Only chains CyberTrace has an entity type for. Everything else the corpus
# carries (EOS, LTC, ...) is read and dropped at index-build time -- see the
# manifest's schema_notes -- rather than kept for a lookup path nothing calls.
_NORMALIZERS = {"BTC": norm_btc, "ETH": norm_eth, "TRX": norm_tron}


def manifest() -> Dict[str, Any]:
    """Provenance metadata: source, license, commit, checksum, citation."""
    return json.loads(MANIFEST_PATH.read_text())


def available() -> bool:
    """Whether the archive was actually downloaded into original/."""
    return ZIP_PATH.exists()


def index_available() -> bool:
    """Whether the local lookup index has been built (see build_index)."""
    return INDEX_PATH.exists()


def _iter_tag_rows() -> Iterator[tuple]:
    """One row per (address, pack) tag, canonicalized address, BTC/ETH/TRX only.

    A malformed or unsupported-chain tag is skipped, not raised -- this reads
    86 independently-contributed YAML files, and one bad row must not fail
    the whole index build.
    """
    import yaml  # local import: only build_index needs the parser

    with zipfile.ZipFile(ZIP_PATH) as z:
        names = [n for n in z.namelist()
                 if n.startswith(_PACKS_PREFIX) and n.endswith(".yaml")]
        for name in names:
            try:
                doc = yaml.safe_load(z.read(name))
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict):
                continue
            pack = Path(name).stem
            defaults = {k: doc.get(k) for k in
                       ("currency", "category", "label", "actor", "source")}
            for tag in (doc.get("tags") or []):
                if not isinstance(tag, dict) or not tag.get("address"):
                    continue
                currency = str(tag.get("currency") or defaults["currency"] or "").upper()
                norm_fn = _NORMALIZERS.get(currency)
                if norm_fn is None:
                    continue
                canon = norm_fn(str(tag["address"]))
                if canon is None:
                    continue
                yield (canon.split(":", 1)[1], currency,
                       tag.get("category") or defaults["category"],
                       tag.get("label") or defaults["label"],
                       tag.get("actor") or defaults["actor"],
                       tag.get("source") or defaults["source"],
                       pack)


def build_index(force: bool = False) -> Path:
    """Build a local read-only SQLite index over the tagpack archive, so a
    single-address lookup is an indexed query instead of a 86-file YAML scan.

    A one-time, seconds-long offline step (this corpus is far smaller than
    Elliptic++'s) -- not run implicitly by lookup_address, which raises a
    clear error instead if the index is missing, same contract as
    ellipticpp.lookup_wallet.
    """
    if INDEX_PATH.exists() and not force:
        return INDEX_PATH
    tmp_path = INDEX_PATH.with_suffix(".sqlite.building")
    tmp_path.unlink(missing_ok=True)
    conn = sqlite3.connect(tmp_path)
    try:
        conn.executescript("""
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE tags (
                address TEXT NOT NULL, currency TEXT, category TEXT,
                label TEXT, actor TEXT, source TEXT, pack TEXT
            );
        """)
        conn.executemany(
            "INSERT INTO tags (address, currency, category, label, actor, source, pack) "
            "VALUES (?,?,?,?,?,?,?)", _iter_tag_rows())
        conn.execute("CREATE INDEX idx_tags_address ON tags(address)")
        conn.commit()
    finally:
        conn.close()
    tmp_path.replace(INDEX_PATH)
    return INDEX_PATH


def lookup_address(address: str, currency: str) -> List[Dict[str, Any]]:
    """Every tag recorded for `address` on `currency` ('BTC'/'ETH'/'TRX'), or
    [] if none. `address` is canonicalized the same way build_index stored it,
    so casing/format differences (an ETH mixed-case checksum, say) never cause
    a miss on an address that's actually indexed.

    Raises RuntimeError if build_index() has not been run yet -- same
    "don't silently fall back to a slow scan" contract as
    ellipticpp.lookup_wallet.
    """
    if not index_available():
        raise RuntimeError(
            "GraphSense TagPacks lookup index not built yet -- call "
            "cybertrace.integrations.exchange_tags.build_index() once first "
            "(offline, one-time, a few seconds).")
    norm_fn = _NORMALIZERS.get(currency.upper())
    canon = norm_fn(address) if norm_fn else None
    if canon is None:
        return []
    bare = canon.split(":", 1)[1]
    conn = sqlite3.connect(f"file:{INDEX_PATH}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT currency, category, label, actor, source, pack FROM tags "
            "WHERE address=?", (bare,)).fetchall()
    finally:
        conn.close()
    return [{"currency": r[0], "category": r[1], "label": r[2], "actor": r[3],
             "source": r[4], "pack": r[5]} for r in rows]


# Non-VASP service/category intelligence this project surfaces alongside
# exchange attribution -- GraphSense TagPacks' own category vocabulary, not a
# taxonomy CyberTrace invented. Any other category this corpus carries (miner,
# gambling, wallet_service, defi_lending, black_list, ...) is read and dropped
# in service_tags below on purpose: extend this set, not a caller, once a new
# category has independently earned investigator surfacing.
_SERVICE_CATEGORIES = {"mixing_service", "defi", "defi_dex", "coinjoin"}


def _canon_index(addresses: Dict[str, List[str]]) -> Dict[str, str]:
    """canonical bare address -> the raw value the caller passed in, for every
    (currency, address) pair this project has a normalizer for. Shared by
    exchange_labels and vasp_disclosed_labels -- both batch the same way, and
    both read against the same tags table connecting to the same index."""
    by_canon: Dict[str, str] = {}
    for currency, values in addresses.items():
        norm_fn = _NORMALIZERS.get(currency.upper())
        if norm_fn is None:
            continue
        for raw in values:
            canon = norm_fn(raw)
            if canon is not None:
                by_canon.setdefault(canon.split(":", 1)[1], raw)
    return by_canon


def exchange_labels(addresses: Dict[str, List[str]]) -> Dict[str, Dict[str, Any]]:
    """{raw address -> {"label", "pack"}} for every input this corpus tags
    category='exchange'. `addresses` is {"BTC": [...], "ETH": [...], ...}.

    Batched because the caller (correlate.wallet_exchange_paths) asks about
    every address in a case at once and lookup_address opens its own
    connection per call.

    Returns {} -- never raises -- when the archive or its index is absent, so
    a reader can degrade to "no third-party attribution available" instead of
    branching on two availability predicates. That is the same degradation
    contract bitcoin_module._check_exchange_tags already has, moved to where
    a non-module caller needs it.

    SAFETY: this is the *suggestion* half of nearest-exchange attribution and
    the module docstring's boundary applies unchanged -- an answer here is a
    third party's public claim about an address, so a caller must present it
    as its own attribution class and must never write it as an
    EXCHANGE_DEPOSIT edge. Only evidence.label_exchange does that, on an
    analyst's own say-so.
    """
    if not (available() and index_available()):
        return {}
    by_canon = _canon_index(addresses)
    if not by_canon:
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    conn = sqlite3.connect(f"file:{INDEX_PATH}?mode=ro", uri=True)
    try:
        keys = list(by_canon)
        for i in range(0, len(keys), 400):        # SQLITE_MAX_VARIABLE_NUMBER
            chunk = keys[i:i + 400]
            marks = ",".join("?" * len(chunk))
            for addr, label, pack in conn.execute(
                    f"SELECT address, label, pack FROM tags "
                    f"WHERE address IN ({marks}) AND lower(category)='exchange'",
                    tuple(chunk)):
                raw = by_canon[addr]
                # First tag wins, and packs are read in whatever order the
                # index returns them -- a second tagpack naming the same
                # exchange adds no information worth a merge policy here.
                out.setdefault(raw, {"label": label, "pack": pack})
    finally:
        conn.close()
    return out


# Of this corpus's 21 distinct `source` domains for category='exchange'
# tags, these two are the ones independently verified -- not merely
# domain-plausible, but cross-checked against a second, independent record:
# Bitfinex's own verified X/Twitter account linking this exact GitHub repo,
# and contemporaneous news coverage (CoinDesk and others) of BitMEX's
# November 2022 proof-of-reserves publication.
# Binance/Huobi/KuCoin/Deribit/Bybit/OKX are real-looking by domain pattern
# alone and were explicitly left unverified -- adding them here on
# domain-plausibility would be exactly the unearned precision this
# project's REGULATORY_ATTESTED/TAG_ATTESTED split already refuses. Extend
# this dict only after independently corroborating a new source the same
# way -- not on domain pattern alone.
_VASP_DISCLOSED_SOURCES: Dict[str, str] = {
    "https://github.com/bitfinexcom/pub/blob/main/wallets.txt": "Bitfinex",
    "https://s3-eu-west-1.amazonaws.com/public.bitmex.com/data/porl/"
    "20221115-reserves-763269-20221115D113036434534000.yaml": "BitMEX",
}


def service_tags(addresses: Dict[str, List[str]]) -> Dict[str, List[Dict[str, Any]]]:
    """{raw address -> [{"category", "label", "pack"}, ...]} for every input
    this corpus tags under a non-VASP service category CyberTrace surfaces --
    mixing_service, defi, defi_dex, coinjoin (see _SERVICE_CATEGORIES). One
    address can carry more than one hit (a coinjoin wallet also flagged by a
    second pack, say), so unlike exchange_labels this returns a list per
    address rather than the first tag.

    Same batching and degradation contract as exchange_labels: returns {} --
    never raises -- when the archive or its index is absent.

    SAFETY: same boundary as exchange_labels and vasp_disclosed_labels -- a
    hit here is a third party's public claim that an address is a
    mixer/DeFi/CoinJoin service, never CyberTrace's own finding. Unlike an
    exchange tag it is not even a VASP *candidate*: a caller must never let
    this populate `exchange`, nearest-VASP attribution, direct_vasp_contacts,
    or secondary_vasp_contacts -- it is service/category intelligence, kept
    in a field of its own.
    """
    if not (available() and index_available()):
        return {}
    by_canon = _canon_index(addresses)
    if not by_canon:
        return {}

    out: Dict[str, List[Dict[str, Any]]] = {}
    conn = sqlite3.connect(f"file:{INDEX_PATH}?mode=ro", uri=True)
    try:
        keys = list(by_canon)
        cats = sorted(_SERVICE_CATEGORIES)
        cat_marks = ",".join("?" * len(cats))
        for i in range(0, len(keys), 400):        # SQLITE_MAX_VARIABLE_NUMBER
            chunk = keys[i:i + 400]
            marks = ",".join("?" * len(chunk))
            for addr, category, label, pack in conn.execute(
                    f"SELECT address, category, label, pack FROM tags "
                    f"WHERE address IN ({marks}) AND lower(category) IN ({cat_marks})",
                    tuple(chunk) + tuple(cats)):
                raw = by_canon[addr]
                out.setdefault(raw, []).append(
                    {"category": category.lower(), "label": label, "pack": pack})
    finally:
        conn.close()
    return out


def vasp_disclosed_labels(addresses: Dict[str, List[str]]) -> Dict[str, Dict[str, Any]]:
    """{raw address -> {"brand", "role", "source"}} for every input tagged
    under a `source` this project has independently verified (see
    _VASP_DISCLOSED_SOURCES) as the VASP's OWN publication of the address --
    not a third party's guess about which VASP an address belongs to.

    `role` is this corpus's `label` text (e.g. "bitfinex BTC cold wallet",
    "bitmex reserve wallet") -- the disclosure's own description of what kind
    of wallet this is, not this project's inference.

    Same batching, degradation, and safety contract as exchange_labels:
    returns {} when the archive/index is absent, and a VASP disclosing an
    address is still not proof it owns every address that transacts with it
    -- the caller must never write this as an EXCHANGE_DEPOSIT edge either.
    """
    if not (available() and index_available()):
        return {}
    by_canon = _canon_index(addresses)
    if not by_canon:
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    conn = sqlite3.connect(f"file:{INDEX_PATH}?mode=ro", uri=True)
    try:
        keys = list(by_canon)
        sources = list(_VASP_DISCLOSED_SOURCES)
        source_marks = ",".join("?" * len(sources))
        for i in range(0, len(keys), 400):        # SQLITE_MAX_VARIABLE_NUMBER
            chunk = keys[i:i + 400]
            marks = ",".join("?" * len(chunk))
            for addr, label, source in conn.execute(
                    f"SELECT address, label, source FROM tags "
                    f"WHERE address IN ({marks}) AND lower(category)='exchange' "
                    f"AND source IN ({source_marks})",
                    tuple(chunk) + tuple(sources)):
                raw = by_canon[addr]
                out.setdefault(raw, {"brand": _VASP_DISCLOSED_SOURCES[source],
                                     "role": label, "source": source})
    finally:
        conn.close()
    return out
