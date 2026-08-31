"""Evolution marketplace offline adapter (forum + market + co-posting network,
2014-2015). Boekhout, Blokland & Takes -- Zenodo 10.5281/zenodo.10171217.

Read-only, streamed directly out of external_data/evolution/original/
data-and-readme.zip via `zipfile` (never extracted to disk -- market/listings.tsv
alone is 732MB uncompressed, and nothing here needs the whole table at once).
License is CC-BY-4.0 (confirmed via the Zenodo API record) -- see
external_data/evolution/manifest.json for the citation to use.

SAFETY BOUNDARY (see the brief, Section 10): this dataset conflates several
things that CyberTrace's evidence model keeps apart on purpose --

    same forum account   (forum/user.tsv uid)
    same vendor account   (market/vendors.tsv vid)
    same matched identity (forum-market/user-matching.tsv: one uid <-> one vid,
                            Evolution's OWN account-linkage fact)
    same co-posting pair  (network/edges-*.tsv: posted in the same topic)

None of these is a CyberTrace SAME_OPERATOR claim about any investigation
target -- they describe structure INSIDE this one dataset. Every record here
carries dataset_label/provenance="OFFLINE_DATASET" and nothing in this module
imports EvidenceStore or ingest() -- pinned by tests/test_integrations.py.

Offline research/evaluation only, per the brief's Section 8: forum/post.tsv is
real free text and is the corpus a future stylometry experiment (Section 15)
would train against -- nothing here scores it.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from . import _freshness
from ..normalize import pgp_fingerprint

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "external_data" / "evolution"
ZIP_PATH = DATA_DIR / "original" / "data-and-readme.zip"
MANIFEST_PATH = DATA_DIR / "manifest.json"
INDEX_PATH = DATA_DIR / "index.sqlite"
_SOURCE_PATHS = (ZIP_PATH,)

# Python's csv default field limit (131072 bytes) is too small for real rows
# in this dataset -- measured: some forum/post.tsv posts (long PGP-signed
# messages) exceed it and raise "field larger than field limit" partway
# through a stream, not at row 1, so this has to be set before any _rows()
# read rather than caught per-caller. 10MB comfortably covers the largest
# real field here with headroom, without csv.field_size_limit(sys.maxsize)'s
# platform-dependent OverflowError risk on a 32-bit C long.
csv.field_size_limit(10_000_000)


def manifest() -> Dict[str, Any]:
    """Provenance metadata: source, license, checksums, citation."""
    return json.loads(MANIFEST_PATH.read_text())


def available() -> bool:
    """Whether the dataset zip was actually downloaded."""
    return ZIP_PATH.exists()


def _rows(member: str) -> Iterator[Dict[str, str]]:
    with zipfile.ZipFile(ZIP_PATH) as zf, zf.open(member) as raw:
        yield from csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8", errors="replace"),
                                  delimiter="\t")


def iter_forum_users() -> Iterator[Dict[str, Any]]:
    for row in _rows("forum/user.tsv"):
        yield {"source": "evolution", "provenance": "OFFLINE_DATASET",
               "entity_type": "FORUM_ACCOUNT", **row}


def iter_forum_posts() -> Iterator[Dict[str, Any]]:
    """The real free-text corpus (post.tsv, ~298MB, ~600K posts). This is
    what a stylometry feasibility check (Section 15) would run against --
    nothing here does that scoring."""
    for row in _rows("forum/post.tsv"):
        yield {"source": "evolution", "provenance": "OFFLINE_DATASET",
               "entity_type": "FORUM_POST", **row}


def iter_vendors() -> Iterator[Dict[str, Any]]:
    """market/vendors.tsv -- includes a pgp_key column (often a full armored
    block) that can be matched against normalize.pgp_fingerprint the same way
    a live darkweb crawl's PGP extraction is."""
    for row in _rows("market/vendors.tsv"):
        yield {"source": "evolution", "provenance": "OFFLINE_DATASET",
               "entity_type": "FORUM_ACCOUNT", **row}


# The TSV export strips every literal newline out of pgp_key -- confirmed by
# reading the real field, not assumed: a properly wrapped armored block would
# split into dozens of csv.reader lines, and every row here is exactly one.
# That collapses "-----BEGIN...-----", "Version: ...", the base64 body and
# "-----END...-----" onto a single line, and normalize._armor_payload reads
# armor line by line -- its first line-startswith("-----BEGIN PGP") check
# swallows the *entire* flattened string in one `continue`, so every one of
# these keys silently failed to parse (measured: 0/2000 fingerprints before
# this fix). _reflow_armor reconstructs a real multi-line block so the
# existing parser -- unmodified -- can read it, the same way it reads a
# normally-wrapped key from a live page.
_ARMOR_BLOCK = re.compile(r"-----BEGIN (PGP [A-Z ]+?)-----(.*)-----END \1-----", re.DOTALL)
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}")


def _reflow_armor(block: str) -> Optional[str]:
    """Rewrap a newline-stripped armored block into one `_armor_payload` can
    read: BEGIN/END on their own lines, base64 body wrapped at 64 columns.

    The base64 body is found as the single longest run of base64-alphabet
    characters inside the BEGIN/END markers -- reliable because armor header
    lines ("Version: GnuPG v2.0.14 (GNU/Linux)") are short and broken up by
    spaces/colons/parens, while the key body is one uninterrupted run of
    thousands of characters. Padding is recomputed from the body's own length
    rather than trusted from the source text: the flattened export glues the
    body's `=` padding directly against the CRC24 checksum's leading `=`
    (`...c==/UZx-----END...`), and splitting that boundary by pattern-matching
    is less reliable than simply deriving the correct padding from `len(body)
    % 4`, which is always right and makes the checksum irrelevant --
    _armor_payload discards checksum lines unconditionally anyway.
    """
    m = _ARMOR_BLOCK.search(block)
    if not m:
        return None
    kind, inner = m.group(1), m.group(2)
    runs = _BASE64_RUN.findall(inner)
    if not runs:
        return None
    body = max(runs, key=len)
    body += "=" * ((-len(body)) % 4)
    wrapped = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN {kind}-----\n\n{wrapped}\n-----END {kind}-----"


def vendor_pgp_fingerprint(pgp_key: str) -> Optional[str]:
    """True OpenPGP fingerprint of a vendors.tsv pgp_key field, or None.

    None both for a field that carries no key and for one this cannot parse
    -- a PGP PRIVATE KEY BLOCK (246 in this dataset: a vendor pasted the wrong
    key into a public listing field) parses to no tag-6 packet by design,
    same as normalize.pgp_fingerprint on any secret-key block; some public
    blocks are genuinely truncated in the source scrape and stay unparseable
    no matter how they're rewrapped. Measured on the real dataset: 32,304 of
    54,294 PGP PUBLIC KEY BLOCK rows resolve to a fingerprint (2,429 distinct
    keys -- the same vendor's key repeats across scrape snapshots).
    """
    if not pgp_key or "BEGIN PGP" not in pgp_key or "PRIVATE KEY" in pgp_key:
        return None
    reflowed = _reflow_armor(pgp_key)
    return pgp_fingerprint(reflowed) if reflowed else None


def iter_vendor_pgp_fingerprints() -> Iterator[Dict[str, Any]]:
    """One record per vendor row with a parseable public key: vid, username,
    the true fingerprint and the dataset's own original armored text
    (preserved verbatim, per the brief's Section 9/11 provenance
    requirements) -- rows whose key does not parse are skipped, not yielded
    as a null fingerprint, so a caller never has to filter None back out."""
    for row in iter_vendors():
        fpr = vendor_pgp_fingerprint(row.get("pgp_key") or "")
        if not fpr:
            continue
        yield {"source": "evolution", "provenance": "OFFLINE_DATASET",
               "entity_type": "PGP_KEY", "fingerprint": fpr,
               "vid": row.get("vid"), "username": row.get("username"),
               "armored_original": row.get("pgp_key")}


def match_pgp_fingerprint(fingerprint: str) -> List[dict]:
    """Vendor records in Evolution whose key resolves to this fingerprint, or
    [] if none do -- the offline half of the Section 9 experiment ("does
    CyberTrace's own normalized PGP identity show up in this historical
    corpus"). The caller classifies a hit as EXTERNAL_DATASET_MATCH, never as
    stronger evidence than that: a vendor holding a key in 2014-2015 says
    nothing about who holds it now.

    occam: O(n) scan over ~54K rows (a few seconds) -- fine for an occasional
    offline check; see lookup_pgp_fingerprint for the indexed, live-pivot path
    (darkweb_module._extract_pgp_keys calls that one, not this one).
    """
    fingerprint = fingerprint.upper()
    return [r for r in iter_vendor_pgp_fingerprints() if r["fingerprint"] == fingerprint]


def index_available() -> bool:
    """Whether the local PGP-fingerprint lookup index has been built (see
    build_index)."""
    return INDEX_PATH.exists()


def is_stale() -> bool:
    """True if the index doesn't match data-and-readme.zip's current
    size/mtime -- including an index built before this tracking existed, or
    one with no index at all. See _freshness.py and ofac.is_stale (same
    mechanism, DOI-pinned archive here instead of a periodically republished
    one -- staleness in practice means "the local zip was replaced", not
    "Zenodo published a new version")."""
    return _freshness.is_stale(INDEX_PATH, _SOURCE_PATHS)


def build_index(force: bool = False) -> Path:
    """Build a local read-only SQLite index of vendor PGP fingerprints, so a
    live-crawl lookup (darkweb_module._extract_pgp_keys, one call per key
    found on a page) is an indexed query instead of the ~54K-row armor-reflow
    scan match_pgp_fingerprint does.

    A one-time, few-minutes offline step (2,429 distinct fingerprints among
    54,294 vendor rows -- see vendor_pgp_fingerprint's docstring for that
    count) -- not run implicitly by lookup_pgp_fingerprint, which raises a
    clear error instead if the index is missing, the same discipline
    ellipticpp.build_index/lookup_wallet already established: a silent
    fallback to the O(n) scan would make the "efficient lookup" this index
    exists for invisible until a live crawl stalled on it.

    force=False (the default) mirrors ofac/exchange_tags/ellipticpp: an index
    whose recorded fingerprint still matches the zip's current size/mtime is
    returned as-is; one with no recorded fingerprint (built before freshness
    tracking existed) is stamped in place rather than re-parsed -- the data
    hasn't changed, only the tracking is new. Only a fingerprint that has
    actually changed triggers a real rebuild. force=True always rebuilds.

    The index itself stays local context (external_data/evolution/, already
    gitignored, and *.sqlite is gitignored globally) -- a cache over the
    dataset, not a copy of it into CyberTrace's own evidence.db.
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
    # corrupted/truncated local zip never silently becomes a queryable index.
    # Zenodo's own published md5 sits alongside this in the manifest but is
    # not re-checked here -- sha256_local is what was actually measured
    # against THIS local file at download time, the same integrity claim
    # is_stale's fingerprint makes, just content- instead of stat-based.
    expected = next(f["sha256_local"] for f in manifest()["files"]
                    if f["local"] == "original/data-and-readme.zip")
    _freshness.verify_checksum(ZIP_PATH, expected)
    tmp_path = INDEX_PATH.with_suffix(".sqlite.building")
    tmp_path.unlink(missing_ok=True)
    conn = sqlite3.connect(tmp_path)
    try:
        conn.executescript("""
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE vendor_pgp (
                fingerprint TEXT NOT NULL, vid TEXT, username TEXT,
                armored_original TEXT
            );
        """)
        conn.executemany(
            "INSERT INTO vendor_pgp (fingerprint, vid, username, armored_original) "
            "VALUES (?,?,?,?)",
            ((r["fingerprint"], r["vid"], r["username"], r["armored_original"])
             for r in iter_vendor_pgp_fingerprints()))
        conn.execute("CREATE INDEX idx_vendor_pgp_fingerprint ON vendor_pgp(fingerprint)")
        conn.commit()
    finally:
        conn.close()
    _freshness.stamp(tmp_path, current_fp)
    tmp_path.replace(INDEX_PATH)
    return INDEX_PATH


def lookup_pgp_fingerprint(fingerprint: str) -> List[dict]:
    """Indexed equivalent of match_pgp_fingerprint -- O(log n), not a scan of
    every vendor row. Same result shape, same EXTERNAL_DATASET_MATCH-only
    classification; this is the one darkweb_module calls per key found on a
    live page.

    Raises RuntimeError if build_index() has not been run yet -- see
    ellipticpp.lookup_wallet for why that is a hard failure rather than a
    silent fallback to the slow scan.
    """
    if not index_available():
        raise RuntimeError(
            "Evolution PGP lookup index not built yet -- call "
            "cybertrace.integrations.evolution.build_index() once first "
            "(offline, one-time, a few minutes).")
    fingerprint = fingerprint.upper()
    conn = sqlite3.connect(f"file:{INDEX_PATH}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT fingerprint, vid, username, armored_original FROM vendor_pgp "
            "WHERE fingerprint=?", (fingerprint,)).fetchall()
    finally:
        conn.close()
    return [{"source": "evolution", "provenance": "OFFLINE_DATASET",
             "entity_type": "PGP_KEY", "fingerprint": row[0],
             "vid": row[1], "username": row[2], "armored_original": row[3]}
            for row in rows]


def iter_listings() -> Iterator[Dict[str, Any]]:
    for row in _rows("market/listings.tsv"):
        yield {"source": "evolution", "provenance": "OFFLINE_DATASET", **row}


def iter_user_matching() -> Iterator[Dict[str, Any]]:
    """forum uid <-> market vid, Evolution's own same-platform-account
    linkage -- dataset ground truth about ONE platform's accounts, not a
    CyberTrace operator claim. See module docstring."""
    for row in _rows("forum-market/user-matching.tsv"):
        yield {"source": "evolution", "provenance": "OFFLINE_DATASET",
               "relationship_type": "SAME_PLATFORM_ACCOUNT", **row}


def iter_identity_nodes() -> Iterator[Dict[str, Any]]:
    """network/nodes.tsv -- one row per matched identity: up to three forum
    uids (uid, secondary_uid, tertiary_uid) Evolution's own record ties to one
    match_id across account changes. Same scope as iter_user_matching: this is
    dataset-internal same-platform-account linkage, not a CyberTrace claim."""
    for row in _rows("network/nodes.tsv"):
        yield {"source": "evolution", "provenance": "OFFLINE_DATASET",
               "relationship_type": "SAME_PLATFORM_ACCOUNT", **row}


def iter_network_edges(month: Optional[str] = None) -> Iterator[Dict[str, Any]]:
    """Co-posting network edges: uid Source -> uid Target, Weight, timestamp.
    `month` filters to one file, e.g. "2014-3"; omitted iterates every month
    2014-1..2014-12, 2015-1..2015-3, in that order.

    An edge means two accounts posted in the same topic -- proximity, not a
    proven message exchange, and never a control claim on its own.
    """
    months = [month] if month else (
        [f"2014-{m}" for m in range(1, 13)] + [f"2015-{m}" for m in range(1, 4)])
    for m in months:
        for row in _rows(f"network/edges-{m}.tsv"):
            yield {"source": "evolution", "provenance": "OFFLINE_DATASET", "month": m, **row}


def forum_market_link_count() -> int:
    """Offline evaluation experiment: how many forum accounts Evolution's own
    records tie to a vendor account -- the positive-control size available
    for validating a same-platform-account correlation experiment."""
    return sum(1 for _ in iter_user_matching())
