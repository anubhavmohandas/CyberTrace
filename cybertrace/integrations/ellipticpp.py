"""Elliptic++ offline adapter (Bitcoin transaction/wallet graph, KDD'23).

Read-only over external_data/ellipticpp/original/*.csv (9 files, ~2.1GB,
never modified in place). License is UNKNOWN (no LICENSE file anywhere in
the dataset's distribution) -- see external_data/ellipticpp/manifest.json.

SAFETY BOUNDARY (see the brief, Section 7): a wallets_classes.csv class of
1 ("illicit") is the dataset authors' own classification of that address IN
ISOLATION, built for a fraud-detection paper. It is a `dataset_label`, not
CyberTrace evidence, and must never be written as SAME_OPERATOR, OWNER, or
OPERATOR_CONFIRMED for any target -- see tests/test_integrations.py, which
pins that nothing in this module imports EvidenceStore or ingest().

Offline use only (research/evaluation), per the brief's Section 8: no
runtime enrichment path, no ML training here, no SUCCESSOR_SIGNALS changes.
Streamed row-by-row (stdlib csv, not pandas) -- these files run 2-700MB each
and nothing here needs the whole table in memory at once.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "external_data" / "ellipticpp"
ORIGINAL_DIR = DATA_DIR / "original"
MANIFEST_PATH = DATA_DIR / "manifest.json"

# Elliptic/Elliptic++ convention, both datasets: 1=illicit, 2=licit, 3=unknown.
CLASS_NAMES = {"1": "illicit", "2": "licit", "3": "unknown"}


def manifest() -> Dict[str, Any]:
    """Provenance metadata: source, license status, checksums, citation."""
    return json.loads(MANIFEST_PATH.read_text())


def available() -> bool:
    """Whether the dataset was actually downloaded into original/."""
    return (ORIGINAL_DIR / "wallets_features_classes_combined.csv").exists()


def _rows(filename: str) -> Iterator[Dict[str, str]]:
    with open(ORIGINAL_DIR / filename, newline="", encoding="utf-8") as f:
        yield from csv.DictReader(f)


def iter_wallets() -> Iterator[Dict[str, Any]]:
    """One row per (address, time step): normalized_address, dataset_label,
    time_step, features (the raw named behavioral columns)."""
    for row in _rows("wallets_features_classes_combined.csv"):
        features = {k: v for k, v in row.items()
                    if k not in ("address", "Time step", "class")}
        yield {
            "source": "ellipticpp",
            "provenance": "OFFLINE_DATASET",
            "entity_type": "BTC_ADDRESS",
            "address": row["address"],
            "time_step": row.get("Time step"),
            "dataset_label": row.get("class"),
            "dataset_label_name": CLASS_NAMES.get(row.get("class"), "unknown"),
            "features": features,
        }


def iter_transactions() -> Iterator[Dict[str, Any]]:
    """One row per (txId, time step): dataset_label joined in from
    txs_classes.csv (loaded once -- 203K rows, ~2MB, cheap)."""
    classes: Dict[str, str] = {r["txId"]: r["class"] for r in _rows("txs_classes.csv")}
    for row in _rows("txs_features.csv"):
        tx_id = row["txId"]
        features = {k: v for k, v in row.items() if k not in ("txId", "Time step")}
        label = classes.get(tx_id)
        yield {
            "source": "ellipticpp",
            "provenance": "OFFLINE_DATASET",
            "entity_type": "TRANSACTION",
            "tx_id": tx_id,
            "time_step": row.get("Time step"),
            "dataset_label": label,
            "dataset_label_name": CLASS_NAMES.get(label, "unknown"),
            "features": features,
        }


def iter_addr_addr_edges() -> Iterator[Dict[str, str]]:
    """input_address -> output_address, one edge per shared transaction."""
    for row in _rows("AddrAddr_edgelist.csv"):
        yield {"source_address": row["input_address"], "target_address": row["output_address"]}


def iter_tx_tx_edges() -> Iterator[Dict[str, str]]:
    """txId1 -> txId2, a Bitcoin money-flow edge."""
    for row in _rows("txs_edgelist.csv"):
        yield {"source_tx": row["txId1"], "target_tx": row["txId2"]}


def wallet_label_counts() -> Dict[str, int]:
    """Offline evaluation experiment #1: class distribution. Illicit/licit
    are a small minority of the 822,942 addresses -- worth confirming
    directly rather than trusting the README's summary table."""
    counts: Dict[str, int] = {"illicit": 0, "licit": 0, "unknown": 0}
    seen: set = set()
    for row in _rows("wallets_classes.csv"):
        if row["address"] in seen:
            continue
        seen.add(row["address"])
        counts[CLASS_NAMES.get(row["class"], "unknown")] += 1
    return counts


def lookup_wallet(address: str) -> Optional[Dict[str, Any]]:
    """First matching row for one address, or None. O(n) scan -- fine for an
    occasional offline lookup, not for repeated calls over many addresses."""
    for row in iter_wallets():
        if row["address"] == address:
            return row
    return None
