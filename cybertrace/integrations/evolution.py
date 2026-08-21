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
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "external_data" / "evolution"
ZIP_PATH = DATA_DIR / "original" / "data-and-readme.zip"
MANIFEST_PATH = DATA_DIR / "manifest.json"


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
