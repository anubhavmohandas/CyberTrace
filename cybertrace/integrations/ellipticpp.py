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

This module itself is offline-only: no ML training here, no SUCCESSOR_SIGNALS
changes, nothing that reaches past lookup_wallet/wallet_neighbors. lookup_wallet
IS called live, per address, from bitcoin_module.BitcoinModule._check_ellipticpp
-- but only to write dataset_label as non-attributive entity metadata via
evidence.enrich_bitcoin, never a relationship, so the safety boundary above
still holds; see that function's docstring.
Streamed row-by-row (stdlib csv, not pandas) -- these files run 2-700MB each
and nothing here needs the whole table in memory at once.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "external_data" / "ellipticpp"
ORIGINAL_DIR = DATA_DIR / "original"
MANIFEST_PATH = DATA_DIR / "manifest.json"
INDEX_PATH = DATA_DIR / "index.sqlite"

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


def index_available() -> bool:
    """Whether the local lookup index has been built (see build_index)."""
    return INDEX_PATH.exists()


def _dedupe_wallets(columns: List[str]) -> Iterator[tuple]:
    """One row per address for the index, not one per (address, time step).

    wallets_features_classes_combined.csv carries a genuine time series (an
    address's behavioral features at each time step it was observed), but
    lookup_wallet only ever needs the latest snapshot -- the most complete
    lifetime-aggregate view -- plus which time steps were observed at all.
    Storing every intermediate snapshot's 55-feature blob in the index (1.27M
    rows) for data no query reads back would triple the index for nothing;
    this collapses it to one row per address (~823K) up front, in memory,
    before anything is written to disk.

    features is stored as a JSON array in `columns` order rather than a JSON
    object: the object form repeats all 55 (verbose) column names on every one
    of 823K rows, which measured out to being the index's single largest
    component -- larger than deduping the time series saved. The array form
    plus the one `columns` row in `meta` carries the same information.
    """
    latest: Dict[str, tuple] = {}   # address -> (time_step_int, label, features)
    steps: Dict[str, list] = {}     # address -> [time_step, ...] in file order
    for row in iter_wallets():
        addr = row["address"]
        ts_raw = row.get("time_step")
        try:
            ts = int(float(ts_raw))
        except (TypeError, ValueError):
            ts = -1
        steps.setdefault(addr, []).append(ts_raw)
        cur = latest.get(addr)
        if cur is None or ts >= cur[0]:
            latest[addr] = (ts, row["dataset_label"], row["features"])
    for addr, (_, label, features) in latest.items():
        ordered = [features.get(c) for c in columns]
        yield (addr, label, json.dumps(ordered, separators=(",", ":")),
               ",".join(steps[addr]))


def build_index(force: bool = False) -> Path:
    """Build a local read-only SQLite index over the wallet and address-graph
    CSVs, so a single-address lookup is an indexed query instead of a full
    scan of a 600MB+ file.

    A one-time, minutes-long offline step (823K addresses after dedup, 2.87M
    address edges) -- not run implicitly by lookup_wallet/wallet_neighbors,
    which raise a clear error instead if the index is missing. That keeps a
    live enrichment call from stalling for minutes the first time it runs; see
    bitcoin_module.BitcoinModule._check_ellipticpp.

    The index itself stays local context (external_data/ellipticpp/, already
    gitignored, and *.sqlite is gitignored globally) -- it is a cache over the
    dataset, not a copy of it into CyberTrace's own evidence.db.
    """
    if INDEX_PATH.exists() and not force:
        return INDEX_PATH
    with open(ORIGINAL_DIR / "wallets_features_classes_combined.csv",
              newline="", encoding="utf-8") as f:
        header = next(csv.reader(f))
    columns = [c for c in header if c not in ("address", "Time step", "class")]

    tmp_path = INDEX_PATH.with_suffix(".sqlite.building")
    tmp_path.unlink(missing_ok=True)
    conn = sqlite3.connect(tmp_path)
    try:
        conn.executescript("""
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE wallets (
                address TEXT NOT NULL, dataset_label TEXT,
                features TEXT, time_steps TEXT
            );
            CREATE TABLE addr_edges (
                input_address TEXT NOT NULL, output_address TEXT NOT NULL
            );
        """)
        conn.execute("INSERT INTO meta (key, value) VALUES ('feature_columns', ?)",
                     (json.dumps(columns),))
        conn.executemany(
            "INSERT INTO wallets (address, dataset_label, features, time_steps) "
            "VALUES (?,?,?,?)", _dedupe_wallets(columns))
        conn.executemany(
            "INSERT INTO addr_edges (input_address, output_address) VALUES (?,?)",
            ((e["source_address"], e["target_address"]) for e in iter_addr_addr_edges()))
        conn.executescript("""
            CREATE INDEX idx_wallets_address ON wallets(address);
            CREATE INDEX idx_edges_input ON addr_edges(input_address);
            CREATE INDEX idx_edges_output ON addr_edges(output_address);
        """)
        conn.commit()
    finally:
        conn.close()
    tmp_path.replace(INDEX_PATH)
    return INDEX_PATH


def lookup_wallet(address: str) -> Optional[Dict[str, Any]]:
    """Compact external-context result for one address, or None if it never
    appears in the dataset. Indexed -- O(log n), not a file scan.

    class is address-level in the source data (one label per address, see
    wallets_classes.csv). time_steps says which points in the dataset's
    timeline observed this address; features is the LATEST time step's row,
    whose lifetime-aggregate columns are the most complete (see build_index /
    _dedupe_wallets, which collapses the source's per-time-step rows to this
    one before the index is ever written).

    Raises RuntimeError if build_index() has not been run yet -- silently
    falling back to the O(n) scan would make the "efficient lookup" this index
    exists for invisible until someone profiles a slow investigation.
    """
    if not index_available():
        raise RuntimeError(
            "Elliptic++ lookup index not built yet -- call "
            "cybertrace.integrations.ellipticpp.build_index() once first "
            "(offline, one-time, several minutes).")
    conn = sqlite3.connect(f"file:{INDEX_PATH}?mode=ro", uri=True)
    try:
        columns = json.loads(conn.execute(
            "SELECT value FROM meta WHERE key='feature_columns'").fetchone()[0])
        row = conn.execute(
            "SELECT dataset_label, features, time_steps FROM wallets "
            "WHERE address=?", (address,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    label, features_json, time_steps_csv = row
    time_steps = time_steps_csv.split(",") if time_steps_csv else []
    return {
        "source": "ellipticpp",
        "provenance": "OFFLINE_DATASET",
        "entity_type": "BTC_ADDRESS",
        "address": address,
        "dataset_label": label,
        "dataset_label_name": CLASS_NAMES.get(label, "unknown"),
        "time_steps": time_steps,
        "record_count": len(time_steps),
        "features": dict(zip(columns, json.loads(features_json))),
    }


def wallet_neighbors(address: str, limit: int = 50) -> List[str]:
    """Addresses connected to this one in the AddrAddr co-transaction graph
    (both directions, deduped) -- offline research/evaluation only. Never fed
    into CyberTrace's own PART_OF_CLUSTER edges: those come from live co-spend
    evidence (a stronger evidentiary class -- common-input-ownership over a
    real transaction, see evidence.enrich_bitcoin), and this dataset's edges
    must not be conflated with them.

    Raises RuntimeError if build_index() has not been run yet (see
    lookup_wallet).
    """
    if not index_available():
        raise RuntimeError(
            "Elliptic++ lookup index not built yet -- call "
            "cybertrace.integrations.ellipticpp.build_index() once first "
            "(offline, one-time, several minutes).")
    conn = sqlite3.connect(f"file:{INDEX_PATH}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT output_address FROM addr_edges WHERE input_address=? "
            "UNION SELECT input_address FROM addr_edges WHERE output_address=? "
            "LIMIT ?", (address, address, limit)).fetchall()
    finally:
        conn.close()
    return [r[0] for r in rows if r[0] != address]
