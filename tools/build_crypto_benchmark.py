#!/usr/bin/env python3
"""Loop 52 (+ Loop 54 addendum) crypto benchmark builder: independently-
sourced, differently-labeled, differently-licensed datasets normalized into
one schema for future anomaly/behavioral research -- NOT a replacement for
Loop 45's deterministic VASP attribution, which this script never touches.

    python tools/build_crypto_benchmark.py                  # default: 3000-address Ethereum sample
    python tools/build_crypto_benchmark.py --max-addresses 500 --skip-ethereum
    python tools/build_crypto_benchmark.py --refresh         # retry addresses cached as "failed"
    python tools/build_crypto_benchmark.py --skip-babd13     # if BABD-13.csv isn't present locally

BABD-13 (Loop 54): 544,462 Bitcoin addresses, 13-class taxonomy, Kaggle-only
(no unauthenticated download path -- manually supplied, see
external_data/babd13/manifest.json). Kept in its OWN ground_truth_label
vocabulary and its own output/balanced files, never blended with Elliptic's
ILLICIT/LICIT/UNKNOWN convention (see load_babd13_wallets).

Bitcoin: external_data/ellipticpp/original/ (already local, verified,
checksummed -- see that manifest.json). Transaction-level rows are anonymized
by the source itself (opaque txId + 182 aggregate features, no raw address);
wallet-level rows carry real base58 addresses and 58 precomputed behavioral
columns. Both populations, plus their exact raw/deduplicated/unique counts,
are documented in docs/CRYPTO_DATASET.md -- do not describe the wallet
file's 1,268,260 raw rows as "unique wallets"; only 822,942 addresses are
unique, and only 920,691 rows survive full-row deduplication.

Ethereum: a curated scam/non-scam address list from
external_data/ethereum_fraud_activity (acquired here on first run, CC-BY-4.0,
see that manifest.json), enriched with REAL behavioral features from
CyberTrace's own already-configured live Etherscan integration
(BitcoinModule._fetch_evm_account_txs) -- a bounded, cached, resumable
sample (--max-addresses, default 3000), never the full ~115k address list in
one run. The sampled set is deterministic and stable across runs (same first
N stratified addresses every time, see sample_ethereum_addresses), and a
local fetch cache (external_data/ethereum_fraud_activity/
etherscan_fetch_cache.json) means a plain re-run makes ZERO new Etherscan
calls once that sample is fully cached -- raising --max-addresses later only
fetches the newly-added addresses. A fetch failure is recorded as
fetch_status="failed" with features=None and is retried only with
--refresh; it is never silently read as "zero activity" (spec section 6).
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import gzip
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import requests

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from cybertrace.modules.bitcoin_module import BitcoinModule  # noqa: E402

ELLIPTICPP_DIR = _REPO_ROOT / "external_data" / "ellipticpp" / "original"
ETH_DIR = _REPO_ROOT / "external_data" / "ethereum_fraud_activity"
ETH_ORIGINAL_DIR = ETH_DIR / "original"
ETH_LABEL_URL = ("https://huggingface.co/datasets/fesevu/ethereum_fraud_dataset_by_activity/"
                  "resolve/main/addr_labels_balanced.csv.zst")
ETH_CACHE_PATH = ETH_DIR / "etherscan_fetch_cache.json"
BABD13_DIR = _REPO_ROOT / "external_data" / "babd13" / "original"
OUT_DIR = _REPO_ROOT / "data" / "crypto_benchmark"

DEFAULT_SAMPLE_SIZE = 3000
FETCH_DELAY_SECONDS = 0.25  # Etherscan free tier is 5 req/s; this leaves headroom
_LABEL_MAP = {"1": "ILLICIT", "2": "LICIT", "3": "UNKNOWN"}
_ELLIPTIC_PROVENANCE = ("Elmougy & Liu, KDD'23 (Elliptic++); "
                         "external_data/ellipticpp/manifest.json")
_ETHEREUM_PROVENANCE = ("fesevu/ethereum_fraud_dataset_by_activity (CC-BY-4.0); "
                         "external_data/ethereum_fraud_activity/manifest.json")
# Index order independently verified against arXiv 2204.05746 Table I's own
# per-class address counts (see external_data/babd13/manifest.json) -- not
# assumed from the column order alone.
_LABEL_MAP_BABD13 = {
    "0": "BLACKMAIL", "1": "CYBER_SECURITY_SERVICE", "2": "DARKNET_MARKET",
    "3": "CENTRALIZED_EXCHANGE", "4": "P2P_FINANCIAL_INFRASTRUCTURE",
    "5": "P2P_FINANCIAL_SERVICE", "6": "GAMBLING", "7": "GOVERNMENT_CRIMINAL_BLACKLIST",
    "8": "MONEY_LAUNDERING", "9": "PONZI_SCHEME", "10": "MINING_POOL",
    "11": "TUMBLER", "12": "INDIVIDUAL_WALLET",
}
_BABD13_PROVENANCE = ("Xiang et al., IEEE TIFS 2024 (BABD-13), labels sourced from "
                       "WalletExplorer via the authors' own scraper; "
                       "external_data/babd13/manifest.json")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_float(value: str) -> Optional[float]:
    """Some Elliptic++ aggregate feature columns (~17 of 182, e.g.
    in_txs_degree/out_txs_degree/total_BTC/fees/size) are genuinely empty
    for a subset of real transactions -- missing data, not zero. Keeps that
    distinction (None) instead of crashing or fabricating a 0.0."""
    return float(value) if value != "" else None


def compute_behavior_flags(tx_count: Optional[float], max_value: Optional[float],
                            in_degree: Optional[float], out_degree: Optional[float]) -> List[str]:
    """Derived independently of ground_truth_label -- a LICIT/UNKNOWN row can
    carry these same flags without becoming FRAUD/ILLICIT (spec section 19).
    Thresholds are documented heuristics, not a fitted percentile.

    occam: fixed thresholds, not a per-population percentile fit -- upgrade
    to percentile-based cutoffs if a real research use needs population-
    relative rather than absolute thresholds.
    """
    flags = []
    if tx_count is not None and tx_count >= 100:
        flags.append("HIGH_ACTIVITY")
    if max_value is not None and max_value >= 10:
        flags.append("HIGH_VALUE")
    if out_degree is not None and out_degree >= 10:
        flags.append("FAN_OUT")
    if in_degree is not None and in_degree >= 10:
        flags.append("FAN_IN")
    return flags


# === B1: Bitcoin -- Elliptic++ (local, already verified, no download) =====

def _require_ellipticpp() -> None:
    if not (ELLIPTICPP_DIR / "txs_classes.csv").exists():
        raise FileNotFoundError(
            f"{ELLIPTICPP_DIR} is missing the Elliptic++ corpus -- this is an existing, "
            "already-integrated offline dataset (see external_data/ellipticpp/manifest.json), "
            "not something this script acquires. Run whatever previously populated it.")


def load_elliptic_transactions() -> List[dict]:
    """Transaction-node rows: opaque txId + 182 anonymized features (the
    source itself never exposes a raw address at this granularity) plus
    graph degree derived from txs_edgelist.csv."""
    _require_ellipticpp()
    classes: Dict[str, str] = {}
    with open(ELLIPTICPP_DIR / "txs_classes.csv", newline="") as f:
        for row in csv.DictReader(f):
            classes[row["txId"]] = row["class"]

    degree: Dict[str, Dict] = defaultdict(lambda: {"in": 0, "out": 0, "peers": set()})
    with open(ELLIPTICPP_DIR / "txs_edgelist.csv", newline="") as f:
        for row in csv.DictReader(f):
            a, b = row["txId1"], row["txId2"]
            degree[a]["out"] += 1
            degree[a]["peers"].add(b)
            degree[b]["in"] += 1
            degree[b]["peers"].add(a)

    rows = []
    with open(ELLIPTICPP_DIR / "txs_features.csv", newline="") as f:
        reader = csv.DictReader(f)
        feature_cols = [c for c in reader.fieldnames if c not in ("txId", "Time step")]
        for row in reader:
            tx_id = row["txId"]
            cls = classes.get(tx_id, "3")
            d = degree.get(tx_id, {"in": 0, "out": 0, "peers": set()})
            timestep = int(row["Time step"])
            rows.append({
                "source": "ellipticpp_local", "chain": "bitcoin",
                "entity_type": "transaction_node", "entity_id": tx_id,
                "timestep": timestep,
                "ground_truth_label": _LABEL_MAP[cls], "source_label": cls,
                "label_confidence": "HIGH" if cls in ("1", "2") else "NONE",
                "label_provenance": _ELLIPTIC_PROVENANCE,
                "fetch_status": "success", "fetch_reason": None, "fetched_at": None,
                "features": {c: _to_float(row[c]) for c in feature_cols},
                "graph_features": {"in_degree": d["in"], "out_degree": d["out"],
                                    "unique_counterparties": len(d["peers"])},
                "behavior_flags": compute_behavior_flags(
                    None, None, d["in"], d["out"]),
                "split": "train" if timestep <= 34 else ("val" if timestep <= 42 else "test"),
            })
    return rows


def load_elliptic_wallets() -> tuple:
    """Wallet rows: real base58 addresses + 58 precomputed behavioral
    columns. The published file has 1,268,260 raw rows but only 822,942
    unique addresses; full-row dedup drops it to 920,691 -- returns
    (deduplicated_rows, raw_row_count) so the quality report can state all
    three numbers distinctly rather than calling any of them "unique wallets"."""
    _require_ellipticpp()
    classes: Dict[str, str] = {}
    with open(ELLIPTICPP_DIR / "wallets_classes.csv", newline="") as f:
        for row in csv.DictReader(f):
            classes[row["address"]] = row["class"]

    seen = set()
    raw_count = 0
    rows = []
    with open(ELLIPTICPP_DIR / "wallets_features_classes_combined.csv", newline="") as f:
        reader = csv.DictReader(f)
        feature_cols = [c for c in reader.fieldnames if c not in ("address", "Time step", "class")]
        for row in reader:
            raw_count += 1
            key = tuple(row[c] for c in reader.fieldnames)
            if key in seen:
                continue
            seen.add(key)
            addr = row["address"]
            cls = classes.get(addr, row["class"])
            timestep = int(row["Time step"])
            features = {c: _to_float(row[c]) for c in feature_cols}
            rows.append({
                "source": "ellipticpp_local", "chain": "bitcoin", "entity_type": "wallet",
                "entity_id": addr, "timestep": timestep,
                "ground_truth_label": _LABEL_MAP.get(cls, "UNKNOWN"), "source_label": cls,
                "label_confidence": "HIGH" if cls in ("1", "2") else "NONE",
                "label_provenance": _ELLIPTIC_PROVENANCE,
                "fetch_status": "success", "fetch_reason": None, "fetched_at": None,
                "features": features,
                "behavior_flags": compute_behavior_flags(
                    features.get("total_txs"), features.get("btc_transacted_max"),
                    features.get("num_txs_as receiver"), features.get("num_txs_as_sender")),
                "split": "train" if timestep <= 34 else ("val" if timestep <= 42 else "test"),
            })
    return rows, raw_count


# === B1b: Bitcoin -- BABD-13 (local, user-supplied, no download) ==========

def _require_babd13() -> None:
    if not (BABD13_DIR / "BABD-13.csv").exists():
        raise FileNotFoundError(
            f"{BABD13_DIR} is missing BABD-13.csv -- this is a Kaggle-only dataset with no "
            "unauthenticated download path (see external_data/babd13/manifest.json); it must "
            "be downloaded manually and placed there, not fetched by this script.")


def load_babd13_wallets() -> tuple:
    """Address-level rows with BABD-13's own 13-class taxonomy, kept as its
    own ground_truth_label vocabulary rather than coerced into Elliptic's
    ILLICIT/LICIT/UNKNOWN -- same precedent as Ethereum's FRAUD/LICIT
    (spec section 4): different source, different labeling convention,
    never silently blended.

    1,414 accounts (real data defect, verified -- see manifest) carry
    mutually CONFLICTING labels across duplicate rows. These are never
    resolved by picking one arbitrarily: every row for such an account gets
    ground_truth_label="LABEL_CONFLICT" and is excluded from the balanced
    subset, so a downstream consumer can never be handed a false single
    answer for an address the source itself contradicts on.

    Returns (deduplicated_rows, raw_row_count), matching
    load_elliptic_wallets's own contract.
    """
    _require_babd13()
    by_account: Dict[str, list] = defaultdict(list)
    raw_count = 0
    feature_cols: List[str] = []
    with open(BABD13_DIR / "BABD-13.csv", newline="") as f:
        reader = csv.DictReader(f)
        feature_cols = [c for c in reader.fieldnames if c not in ("account", "SW", "label")]
        for row in reader:
            raw_count += 1
            by_account[row["account"]].append(row)

    rows = []
    for account, acct_rows in by_account.items():
        distinct_labels = {r["label"] for r in acct_rows}
        conflict = len(distinct_labels) > 1
        # De-duplicate byte-identical repeats of the same row; a conflicting
        # account keeps one row per distinct label so both claims stay visible.
        seen_keys = set()
        kept = []
        for r in acct_rows:
            key = (r["SW"], r["label"]) if conflict else tuple(r[c] for c in reader.fieldnames)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            kept.append(r)
        for r in kept:
            features = {c: _to_float(r[c]) for c in feature_cols}
            rows.append({
                "source": "babd13_local", "chain": "bitcoin", "entity_type": "wallet",
                "entity_id": account, "timestep": None,
                "ground_truth_label": "LABEL_CONFLICT" if conflict
                                       else _LABEL_MAP_BABD13.get(r["label"], "UNKNOWN"),
                "source_label": r["label"] if not conflict else ",".join(sorted(distinct_labels)),
                "label_confidence": "CONFLICT" if conflict
                                     else ("STRONG" if r["SW"] == "SA" else "WEAK"),
                "label_provenance": _BABD13_PROVENANCE,
                "fetch_status": "success", "fetch_reason": None, "fetched_at": None,
                "features": features,
                # occam: BABD-13's 148 columns are indicator-category codes
                # (PAIa.../S...), not named tx-count/max-value/degree fields
                # like Elliptic's -- guessing a mapping risks a wrong flag,
                # so behavior_flags is left empty here rather than guessed.
                # Upgrade path: decode column semantics from the paper's own
                # indicator tables if this benchmark starts using BABD-13
                # for flag-based (not just label-based) research.
                "behavior_flags": [],
                "split": "source_held_out_train"
                         if int(hashlib.sha256(account.encode()).hexdigest(), 16) % 10 < 7
                         else "source_held_out_test",
            })
    return rows, raw_count


# === B2: Ethereum -- fesevu labels + live Etherscan enrichment ============

def acquire_ethereum_labels(force: bool = False) -> Path:
    """Idempotent: downloads + decompresses only if the CSV isn't already
    there. requests is an existing project dependency (requirements.txt),
    not a new one; decompression uses the system zstd/unzstd binary."""
    csv_path = ETH_ORIGINAL_DIR / "addr_labels_balanced.csv"
    if csv_path.exists() and not force:
        return csv_path
    ETH_ORIGINAL_DIR.mkdir(parents=True, exist_ok=True)
    zst_path = ETH_ORIGINAL_DIR / "addr_labels_balanced.csv.zst"
    resp = requests.get(ETH_LABEL_URL, timeout=60)
    resp.raise_for_status()
    zst_path.write_bytes(resp.content)
    subprocess.run(["unzstd", "-f", str(zst_path), "-o", str(csv_path)], check=True)
    return csv_path


def load_ethereum_labels(csv_path: Path) -> List[dict]:
    rows = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("is_scam") not in ("0", "1"):
                continue  # malformed row -- skip rather than guess a label
            rows.append(row)
    return rows


def _load_fetch_cache() -> dict:
    if ETH_CACHE_PATH.exists():
        return json.loads(ETH_CACHE_PATH.read_text())
    return {}


def _save_fetch_cache(cache: dict) -> None:
    ETH_CACHE_PATH.write_text(json.dumps(cache, indent=2, sort_keys=True))


async def _fetch_one_address(module: BitcoinModule, address: str) -> dict:
    """Real behavioral features from the last 20 native transactions
    (BitcoinModule._fetch_evm_account_txs's own bounded-sample design, not
    full history). A failure never becomes "zero activity" -- see the
    status field."""
    txs, error = await module._fetch_evm_account_txs(address, "ethereum", "txlist")
    if txs is None:
        return {"status": "failed", "reason": error, "features": None}
    if not txs:
        return {"status": "success", "reason": None, "features": {
            "transaction_count": 0, "avg_value_eth": None, "min_value_eth": None,
            "max_value_eth": None, "active_days": 0.0,
            "unique_sent_to": 0, "unique_received_from": 0, "unique_counterparties": 0,
            "contract_calls": 0, "failed_tx_ratio": None,
        }}
    me = address.lower()
    values = [int(t.get("value") or 0) / 1e18 for t in txs]
    timestamps = [int(t["timeStamp"]) for t in txs if t.get("timeStamp")]
    sent_to, received_from = set(), set()
    for t in txs:
        frm, to = (t.get("from") or "").lower(), (t.get("to") or "").lower()
        if frm == me and to and to != me:
            sent_to.add(to)
        elif to == me and frm and frm != me:
            received_from.add(frm)
    contract_calls = sum(1 for t in txs if (t.get("input") or "0x") not in ("0x", ""))
    failed = sum(1 for t in txs if t.get("isError") == "1")
    active_days = (max(timestamps) - min(timestamps)) / 86400 if len(timestamps) > 1 else 0.0
    return {"status": "success", "reason": None, "features": {
        "transaction_count": len(txs),
        "avg_value_eth": round(sum(values) / len(values), 8),
        "min_value_eth": round(min(values), 8),
        "max_value_eth": round(max(values), 8),
        "active_days": round(active_days, 2),
        "unique_sent_to": len(sent_to), "unique_received_from": len(received_from),
        "unique_counterparties": len(sent_to | received_from),
        "contract_calls": contract_calls,
        "failed_tx_ratio": round(failed / len(txs), 4),
    }}


def _build_ethereum_row(label_row: dict, fetch_result: dict) -> dict:
    is_scam = label_row["is_scam"] == "1"
    features = fetch_result.get("features")
    flags = (compute_behavior_flags(
        features.get("transaction_count"), features.get("max_value_eth"),
        features.get("unique_received_from"), features.get("unique_sent_to"))
        if fetch_result["status"] == "success" else [])
    return {
        "source": "fesevu_ethereum_fraud_activity+live_etherscan", "chain": "ethereum",
        "entity_type": "wallet", "entity_id": label_row["address"],
        "is_contract": label_row.get("is_contract") == "1",
        "ground_truth_label": "FRAUD" if is_scam else "LICIT",
        "source_label": label_row["is_scam"], "scam_category": label_row.get("description") or None,
        "label_confidence": "HIGH", "label_provenance": _ETHEREUM_PROVENANCE,
        "fetch_status": fetch_result["status"], "fetch_reason": fetch_result.get("reason"),
        "fetched_at": fetch_result.get("fetched_at"),
        "features": features, "behavior_flags": flags,
        # Source-held-out split, not random-shuffle -- deterministic on the
        # address itself so re-running never reassigns a row's split. Uses
        # sha256, not Python's built-in hash(), which is process-randomized
        # (PYTHONHASHSEED) and would silently reshuffle every split on
        # every invocation.
        "split": "source_held_out_train"
                 if int(hashlib.sha256(label_row["address"].encode()).hexdigest(), 16) % 10 < 7
                 else "source_held_out_test",
    }


def sample_ethereum_addresses(labels: List[dict], sample_size: int) -> List[dict]:
    """Deterministic and stable: always the same first `sample_size`
    stratified addresses (half scam, half licit, in the source file's own
    order), regardless of cache state. This is what makes the cache in
    enrich_ethereum_addresses actually save API calls instead of chasing a
    moving target -- an earlier version selected "the next N addresses not
    yet in the cache", which meant every re-run advanced to a fresh batch
    instead of converging; caught by re-running the same command twice and
    finding the cache had grown by another full batch, not stayed put."""
    scam = [r for r in labels if r["is_scam"] == "1"]
    licit = [r for r in labels if r["is_scam"] == "0"]
    half = sample_size // 2
    return scam[:half] + licit[:sample_size - half]


_CACHE_SAVE_EVERY = 25  # persist progress periodically, not only at the end -- an
                        # interrupted run must not lose everything it already fetched


async def enrich_ethereum_addresses(labels: List[dict], refresh: bool) -> List[dict]:
    """Cached + resumable (spec section 6 + Loop 52 review corrections): an
    address already cached as "success" costs zero new API calls on a
    re-run; "failed" is retried only with --refresh. Relies on `labels`
    being sample_ethereum_addresses's fixed, deterministic sample -- fetching
    the same set on every call is what lets this converge to zero new calls
    once that set is fully cached, rather than growing forever.

    Saves the cache to disk every _CACHE_SAVE_EVERY new fetches (not only
    once at the end) -- a 3000-address run takes minutes at
    FETCH_DELAY_SECONDS pacing, and an interrupted run (Ctrl-C, crash) must
    resume from where it actually got to, not from zero.
    """
    cache = _load_fetch_cache()
    new_fetches = 0
    out = []
    async with BitcoinModule() as module:
        for label_row in labels:
            addr = label_row["address"]
            cached = cache.get(addr)
            need_fetch = cached is None or (refresh and cached.get("status") == "failed")
            if need_fetch:
                result = await _fetch_one_address(module, addr)
                result["fetched_at"] = utcnow()
                cache[addr] = result
                new_fetches += 1
                if new_fetches % _CACHE_SAVE_EVERY == 0:
                    _save_fetch_cache(cache)
                await asyncio.sleep(FETCH_DELAY_SECONDS)
            else:
                result = cached
            out.append(_build_ethereum_row(label_row, result))
    _save_fetch_cache(cache)
    print(f"  {new_fetches} new Etherscan fetches this run "
          f"({len(labels) - new_fetches} already cached)")
    return out


# === Balanced research subset (Dataset B) =================================

def build_balanced_subset(btc_wallets: List[dict], eth_rows: List[dict]) -> List[dict]:
    """Controlled-balance sample, kept separate from the realistic files
    (spec section 20) -- for model training/experiments, not evaluation."""
    by_label: Dict[str, List[dict]] = defaultdict(list)
    for r in btc_wallets:
        by_label[r["ground_truth_label"]].append(r)
    cap = min(len(v) for v in by_label.values())
    balanced_btc = [r for label in by_label for r in by_label[label][:cap]]

    eth_success = [r for r in eth_rows if r["fetch_status"] == "success"]
    eth_by_label = defaultdict(list)
    for r in eth_success:
        eth_by_label[r["ground_truth_label"]].append(r)
    eth_cap = min((len(v) for v in eth_by_label.values()), default=0)
    balanced_eth = [r for label in eth_by_label for r in eth_by_label[label][:eth_cap]]

    return balanced_btc + balanced_eth


def build_babd13_balanced_subset(babd13_wallets: List[dict]) -> List[dict]:
    """Kept out of build_balanced_subset deliberately: BABD-13 uses its own
    13-class taxonomy (plus LABEL_CONFLICT), not Elliptic's ILLICIT/LICIT/
    UNKNOWN -- capping across both label spaces in one balance pass would
    silently treat e.g. "GAMBLING" and "ILLICIT" as comparable classes,
    which they are not. LABEL_CONFLICT rows are excluded outright: a
    balanced *training* subset must never hand a model an address the
    source itself gave two different answers for."""
    clean = [r for r in babd13_wallets if r["ground_truth_label"] != "LABEL_CONFLICT"]
    by_label: Dict[str, List[dict]] = defaultdict(list)
    for r in clean:
        by_label[r["ground_truth_label"]].append(r)
    cap = min((len(v) for v in by_label.values()), default=0)
    return [r for label in by_label for r in by_label[label][:cap]]


# === Quality report =========================================================

def _label_counts(rows: List[dict]) -> dict:
    counts: Dict[str, int] = defaultdict(int)
    for r in rows:
        counts[r["ground_truth_label"]] += 1
    return dict(counts)


def build_quality_report(btc_tx: List[dict], btc_wallets: List[dict], btc_wallet_raw_count: int,
                          eth_rows: List[dict], babd13_wallets: Optional[List[dict]] = None,
                          babd13_raw_count: int = 0) -> dict:
    fetch_counts: Dict[str, int] = defaultdict(int)
    for r in eth_rows:
        fetch_counts[r["fetch_status"]] += 1
    babd13_wallets = babd13_wallets or []
    conflict_accounts = {r["entity_id"] for r in babd13_wallets
                          if r["ground_truth_label"] == "LABEL_CONFLICT"}
    return {
        "generated_at": utcnow(),
        "sources": {
            "elliptic_transactions": {
                "source": "ellipticpp_local", "raw_rows": len(btc_tx),
                "unique_ids": len(btc_tx), "label_counts": _label_counts(btc_tx),
            },
            "elliptic_wallets": {
                "source": "ellipticpp_local", "raw_rows": btc_wallet_raw_count,
                "deduplicated_rows": len(btc_wallets),
                "duplicate_rows_removed": btc_wallet_raw_count - len(btc_wallets),
                "unique_addresses": len({r["entity_id"] for r in btc_wallets}),
                "label_counts": _label_counts(btc_wallets),
            },
            "ethereum_fesevu_live": {
                "source": "fesevu_ethereum_fraud_activity+live_etherscan",
                "sampled_addresses": len(eth_rows),
                "fetch_status_counts": dict(fetch_counts),
                "label_counts": _label_counts(eth_rows),
            },
            "babd13_wallets": {
                "source": "babd13_local", "raw_rows": babd13_raw_count,
                "deduplicated_rows": len(babd13_wallets),
                "unique_addresses": len({r["entity_id"] for r in babd13_wallets}),
                "label_conflict_accounts": len(conflict_accounts),
                "label_counts": _label_counts(babd13_wallets),
                "confidence_counts": dict(
                    (k, sum(1 for r in babd13_wallets if r["label_confidence"] == k))
                    for k in ("STRONG", "WEAK", "CONFLICT")),
            },
        },
        "cross_source_duplicate_addresses": len(
            {r["entity_id"] for r in btc_wallets} & {r["entity_id"] for r in eth_rows}),
        "babd13_x_elliptic_overlap_addresses": len(
            {r["entity_id"] for r in babd13_wallets} & {r["entity_id"] for r in btc_wallets}),
        "totals": {"total_rows": len(btc_tx) + len(btc_wallets) + len(eth_rows) + len(babd13_wallets)},
        "deferred_sources": {
            "cryptoxchain_500k": "HuggingFace-gated (needs a logged-in account with granted "
                                  "access); no ungated multi-chain equivalent found. Revisit if "
                                  "access is granted or an alternative surfaces.",
            "kaggle_ethereum_fraud_detection_vagifa": "Superseded by "
                                  "fesevu/ethereum_fraud_dataset_by_activity (CC-BY-4.0, "
                                  "documented pipeline, not Kaggle-gated).",
            "kaggle_multi_crypto_anomaly_detection_2025": "Could not verify existence/contents "
                                  "via unauthenticated fetch (Kaggle search is JS-rendered); per "
                                  "its own description ~88% derived from Elliptic (already the "
                                  "authoritative local source) with only ~10k incremental "
                                  "Ethereum rows.",
            "huggingface_1_62b_row_ethereum_dataset": "Not confidently located; fesevu already "
                                  "fills the independent-Ethereum-source role for this loop.",
            "kaggle_bitcoin_wallet_classification_43_6m": "Kaggle-gated (no API credentials in "
                                  "this environment) AND, independent of access, lower-trust than "
                                  "BABD-13: single-uploader dataset with no peer-reviewed paper, "
                                  "whose own description states most labels derive from stale "
                                  "WalletExplorer-era blocks. Not pursued even if access is later "
                                  "provided, unless independent label verification surfaces.",
            "diam_multigraphs_huggingface": "Verified real and freely downloadable (CIKM'24 "
                                  "paper, ungated HF repo, 4 files totaling 1.73GB -- checked via "
                                  "direct HTTP HEAD requests, not assumed). NOT fetched: graph-"
                                  "structured (needs torch/torch_geometric, neither installed), "
                                  "and nothing in this project consumes graph-ML data yet. "
                                  "Acquiring 1.73GB with no consumer is exactly the kind of "
                                  "speculative scaffolding this benchmark has avoided elsewhere. "
                                  "Revisit if a graph-ML loop is actually started.",
        },
    }


def write_jsonl(path: Path, rows: List[dict]) -> None:
    """Gzipped -- a real run's row count (900k+ Bitcoin wallet rows, each
    with 58 float features) produces multi-GB of plain JSONL (repeated key
    names on every line, no shared schema); gzip cut a measured sample by
    ~14x. `.jsonl.gz` reads back with gzip.open(path, "rt")."""
    path = path.with_suffix(path.suffix + ".gz")
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--max-addresses", type=int, default=DEFAULT_SAMPLE_SIZE,
                         help="target sample size -- stable across runs (same first N "
                              "stratified addresses every time); raising it later only "
                              "fetches the newly-added addresses, already-cached ones are free")
    parser.add_argument("--refresh", action="store_true",
                         help="retry addresses cached as failed (never re-fetches a success)")
    parser.add_argument("--skip-ethereum", action="store_true",
                         help="Bitcoin only -- for fast local iteration, no network")
    parser.add_argument("--skip-babd13", action="store_true",
                         help="Skip BABD-13 -- for runs where the manually-supplied CSV isn't present")
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = parser.parse_args()

    print("Loading Elliptic++ transaction nodes...")
    btc_tx = load_elliptic_transactions()
    print(f"  {len(btc_tx)} transaction nodes")

    print("Loading Elliptic++ wallets...")
    btc_wallets, btc_wallet_raw_count = load_elliptic_wallets()
    print(f"  {btc_wallet_raw_count} raw rows -> {len(btc_wallets)} after dedup")

    babd13_wallets: List[dict] = []
    babd13_raw_count = 0
    if not args.skip_babd13 and (BABD13_DIR / "BABD-13.csv").exists():
        print("Loading BABD-13 wallets...")
        babd13_wallets, babd13_raw_count = load_babd13_wallets()
        n_conflict = sum(1 for r in babd13_wallets if r["ground_truth_label"] == "LABEL_CONFLICT")
        print(f"  {babd13_raw_count} raw rows -> {len(babd13_wallets)} unique addresses "
              f"({n_conflict} with conflicting labels, kept but excluded from balancing)")

    eth_rows: List[dict] = []
    if not args.skip_ethereum:
        print("Acquiring Ethereum label index (fesevu, cached after first run)...")
        eth_csv = acquire_ethereum_labels()
        eth_labels = load_ethereum_labels(eth_csv)
        print(f"  {len(eth_labels)} labeled addresses available")
        sampled = sample_ethereum_addresses(eth_labels, args.max_addresses)
        print(f"  target sample: {len(sampled)} addresses...")
        eth_rows = asyncio.run(enrich_ethereum_addresses(sampled, args.refresh))
        statuses = defaultdict(int)
        for r in eth_rows:
            statuses[r["fetch_status"]] += 1
        print(f"  {dict(statuses)}")

    write_jsonl(args.out_dir / "bitcoin_transactions_realistic.jsonl", btc_tx)
    write_jsonl(args.out_dir / "bitcoin_wallets_realistic.jsonl", btc_wallets)
    write_jsonl(args.out_dir / "ethereum_wallets_realistic.jsonl", eth_rows)
    balanced = build_balanced_subset(btc_wallets, eth_rows)
    write_jsonl(args.out_dir / "balanced_subset.jsonl", balanced)

    if babd13_wallets:
        write_jsonl(args.out_dir / "babd13_wallets_realistic.jsonl", babd13_wallets)
        babd13_balanced = build_babd13_balanced_subset(babd13_wallets)
        write_jsonl(args.out_dir / "babd13_wallets_balanced.jsonl", babd13_balanced)

    report = build_quality_report(btc_tx, btc_wallets, btc_wallet_raw_count, eth_rows,
                                   babd13_wallets, babd13_raw_count)
    (args.out_dir / "quality_report.json").write_text(json.dumps(report, indent=2))
    print(f"\nWrote {report['totals']['total_rows']} total rows to {args.out_dir}")
    print(json.dumps(report["totals"], indent=2))


if __name__ == "__main__":
    main()
