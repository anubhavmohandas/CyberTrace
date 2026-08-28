"""GraphSense TagPacks offline adapter (community-contributed public address
tags: exchange, ransomware, sanctions, mixer, scam, and other categories).

Read-only over external_data/exchange_tags/original/graphsense-tagpacks.zip
(never extracted to disk -- streamed with `zipfile`, same as evolution.py).
MIT licensed (confirmed via the GitHub API) -- unlike Elliptic++ this dataset
is openly redistributable; see external_data/exchange_tags/manifest.json.

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
