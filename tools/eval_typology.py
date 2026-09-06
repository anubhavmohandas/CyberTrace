#!/usr/bin/env python3
"""Benchmark cybertrace.typology's behavioral signals (Loop 53) against the
Loop 52 crypto benchmark's own ground-truth flags -- never a synthetic
wallet presented as real-world evidence.

    python tools/eval_typology.py

**What is actually comparable, and what is not.** `tools/build_crypto_
benchmark.py`'s own `compute_behavior_flags` produces exactly four flags --
HIGH_ACTIVITY, HIGH_VALUE, FAN_OUT, FAN_IN -- from four aggregate features
per wallet (Elliptic++ for Bitcoin, fesevu+live Etherscan for Ethereum).
typology.py's own threshold CONSTANTS for these four signals were chosen to
match those exact numbers (see typology.py's own module docstring) precisely
so this comparison is meaningful. BURST_ACTIVITY/RAPID_FORWARDING/
DORMANT_TO_ACTIVE/PEEL_CHAIN_LIKE/CONSOLIDATION/DISPERSAL have NO comparable
label in this benchmark -- Elliptic++'s address-level features carry no
individual per-transaction timestamp sequence, only aggregates -- and are
reported NOT_EVALUATED with that reason stated, never a fabricated score.

**How the comparison is run.** typology.py's real functions (`_high_activity`,
`_high_value`, `_fan`) are called through a small `_BenchmarkWalletStore`
that answers `metadata()`/`transactions_for()` from the SAME benchmark row's
own aggregate features the benchmark's own `compute_behavior_flags` reads --
never a second, independently-invented number. This tests threshold
AGREEMENT given the same underlying facts, not an end-to-end live pipeline
(that is what tests/test_typology.py's real-EvidenceStore tests already
cover). Per-transaction rows synthesized here are clearly synthetic INPUT
data standing in for aggregate counts already present in the benchmark
row -- never presented as real transaction evidence, and never written to
any EvidenceStore.

**A documented benchmark-methodology inconsistency, not something this
script silently papers over**: the benchmark's own compute_behavior_flags
call sites differ per chain -- Bitcoin's FAN_OUT/FAN_IN read a TRANSACTION-
COUNT (`num_txs_as_sender`/`num_txs_as receiver`), Ethereum's read a
DISTINCT-COUNTERPARTY-COUNT (`unique_sent_to`/`unique_received_from`); and
the same numeric HIGH_VALUE threshold (10) is applied to both BTC and ETH
despite them being very different real-world values. Both are the existing
Loop 52 benchmark's own choices, restated here, not introduced by this loop.

**Measured result, verified by hand**: HIGH_VALUE precision is 1.0 but
recall is ~0.84 on the real balanced_subset -- confirmed (by direct count)
to be exactly the 239 real Ethereum HIGH_VALUE-flagged wallets out of 1524
total, 100% of which typology.py's own BTC-only restriction on this signal
(see typology.py's own docstring, matching attribution.wallet_fingerprint's
documented limitation) correctly declines to score. Not a bug: a deliberate,
now-quantified boundary, kept rather than "fixed" by inventing an ETH
threshold this codebase has no calibrated basis for.

**Investigated, not integrated**: Elliptic2 (elliptic.co/elliptic2, CC-BY-4.0)
labels money-laundering SUBGRAPHS (licit vs. suspicious cross-cluster paths)
with continuous features binned for IP protection -- a real, credible,
well-documented dataset, but subgraph-level and feature-obfuscated, not a
fit for this loop's wallet-level, real-valued typology signals without
substantial rework. Not pulled in.
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybertrace.typology import (  # noqa: E402
    DETECTED, FAN_IN, FAN_OUT, HIGH_ACTIVITY, HIGH_VALUE,
    _fan, _high_activity, _high_value,
)

BENCHMARK_DIR = ROOT / "data" / "crypto_benchmark"
BALANCED_SUBSET = BENCHMARK_DIR / "balanced_subset.jsonl.gz"

# Signals this benchmark can score, and why the rest cannot -- see module
# docstring. Never silently omitted: NOT_EVALUATED is reported explicitly
# for each one in print_report.
_COMPARABLE = (HIGH_ACTIVITY, HIGH_VALUE, FAN_OUT, FAN_IN)
_NOT_COMPARABLE = {
    "BURST_ACTIVITY": "no per-transaction timestamp sequence in Elliptic++/fesevu "
                      "address-level aggregate features.",
    "RAPID_FORWARDING": "same reason as BURST_ACTIVITY.",
    "DORMANT_TO_ACTIVE": "same reason as BURST_ACTIVITY.",
    "PEEL_CHAIN_LIKE": "same reason as BURST_ACTIVITY; also inherently a multi-wallet "
                       "pattern this benchmark's per-wallet rows cannot express.",
    "CONSOLIDATION": "compute_behavior_flags computes no net-flow-ratio label at all.",
    "DISPERSAL": "same reason as CONSOLIDATION.",
}


class _BenchmarkWalletStore:
    """Answers typology.py's own `metadata`/`transactions_for` reads from
    ONE benchmark row's aggregate features -- see module docstring. Never a
    real EvidenceStore, never written anywhere."""

    def __init__(self, tx_count: Optional[float], max_value: Optional[float],
                asset: str, sent_count: Optional[float], received_count: Optional[float]):
        self._tx_count = int(tx_count) if tx_count is not None else None
        self._max_value = max_value
        self._asset = asset
        self._sent = int(sent_count) if sent_count is not None else 0
        self._received = int(received_count) if received_count is not None else 0

    def metadata(self, entity_id):
        return {"tx_count": self._tx_count} if self._tx_count is not None else {}

    def transactions_for(self, entity_id, limit=2000):
        # HIGH_VALUE's max_value is attached to an EXISTING row rather than
        # appended as a new one -- appending would inflate the FAN_OUT/
        # FAN_IN row COUNT by one for every wallet that has any recorded
        # value at all, contaminating those signals' evaluation with a
        # synthesis artifact that has nothing to do with real fan-out/in.
        out_rows = [{"tx_hash": f"synthetic_out_{i}", "direction": "OUT",
                    "counterparty": f"synthetic_peer_out_{i}", "asset": self._asset,
                    "value": None, "timestamp": None} for i in range(self._sent)]
        in_rows = [{"tx_hash": f"synthetic_in_{i}", "direction": "IN",
                   "counterparty": f"synthetic_peer_in_{i}", "asset": self._asset,
                   "value": None, "timestamp": None} for i in range(self._received)]
        if self._max_value is not None:
            if out_rows:
                out_rows[-1]["value"] = self._max_value
            else:
                out_rows.append({"tx_hash": "synthetic_max_value", "direction": "OUT",
                                "counterparty": "synthetic_peer_max", "asset": self._asset,
                                "value": self._max_value, "timestamp": None})
        return (out_rows + in_rows)[:limit]


def _row_features(row: dict) -> Optional[dict]:
    """Normalize one benchmark wallet row's chain-specific feature names
    into (tx_count, max_value, asset, sent_count, received_count) -- the
    exact fields each chain's own compute_behavior_flags call site reads
    (see module docstring's benchmark-methodology note)."""
    f = row.get("features") or {}
    if row.get("chain") == "bitcoin":
        return {"tx_count": f.get("total_txs"), "max_value": f.get("btc_transacted_max"),
                "asset": "BTC", "sent_count": f.get("num_txs_as_sender"),
                "received_count": f.get("num_txs_as receiver")}
    if row.get("chain") == "ethereum":
        return {"tx_count": f.get("transaction_count"), "max_value": f.get("max_value_eth"),
                "asset": "ETH", "sent_count": f.get("unique_sent_to"),
                "received_count": f.get("unique_received_from")}
    return None


def _predict(row: dict) -> Dict[str, bool]:
    feats = _row_features(row)
    if feats is None:
        return {}
    store = _BenchmarkWalletStore(feats["tx_count"], feats["max_value"], feats["asset"],
                                  feats["sent_count"], feats["received_count"])
    md = store.metadata("wallet")
    out = {}
    ha = _high_activity(md)
    out[HIGH_ACTIVITY] = bool(ha and ha["status"] == DETECTED)
    hv = _high_value(store, "wallet")
    out[HIGH_VALUE] = bool(hv and hv["status"] == DETECTED)
    fo = _fan(store, "wallet", md, "OUT", FAN_OUT)
    out[FAN_OUT] = bool(fo and fo["status"] == DETECTED)
    fi = _fan(store, "wallet", md, "IN", FAN_IN)
    out[FAN_IN] = bool(fi and fi["status"] == DETECTED)
    return out


def load_wallet_rows(path: Path = BALANCED_SUBSET) -> List[dict]:
    if not path.exists():
        return []
    rows = []
    with gzip.open(path, "rt") as fh:
        for line in fh:
            row = json.loads(line)
            if row.get("entity_type") == "wallet":
                rows.append(row)
    return rows


def _prf(tp: int, fp: int, fn: int) -> tuple:
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)
         if precision and recall and (precision + recall) else None)
    return precision, recall, f1


def evaluate(rows: List[dict]) -> dict:
    counts = {s: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for s in _COMPARABLE}
    chain_counts: Dict[str, int] = {}
    for row in rows:
        chain_counts[row.get("chain", "?")] = chain_counts.get(row.get("chain", "?"), 0) + 1
        predicted = _predict(row)
        if not predicted:
            continue
        truth_flags = set(row.get("behavior_flags") or [])
        for signal in _COMPARABLE:
            pred = predicted.get(signal, False)
            actual = signal in truth_flags
            if pred and actual:
                counts[signal]["tp"] += 1
            elif pred and not actual:
                counts[signal]["fp"] += 1
            elif not pred and actual:
                counts[signal]["fn"] += 1
            else:
                counts[signal]["tn"] += 1

    report = {"total_wallet_rows": len(rows), "chain_distribution": chain_counts, "signals": {}}
    for signal, c in counts.items():
        support = c["tp"] + c["fn"]
        total = sum(c.values())
        precision, recall, f1 = _prf(c["tp"], c["fp"], c["fn"])
        fpr = c["fp"] / (c["fp"] + c["tn"]) if (c["fp"] + c["tn"]) else None
        report["signals"][signal] = {
            "support": support, "total_scored": total,
            "precision": round(precision, 4) if precision is not None else None,
            "recall": round(recall, 4) if recall is not None else None,
            "f1": round(f1, 4) if f1 is not None else None,
            "false_positive_rate": round(fpr, 4) if fpr is not None else None,
            "counts": c,
        }
    report["not_evaluated"] = _NOT_COMPARABLE
    return report


def print_report(report: dict) -> int:
    print(f"Loop 53 typology evaluation -- {report['total_wallet_rows']} wallet rows "
         f"({report['chain_distribution']})")
    print()
    if report["total_wallet_rows"] == 0:
        print(f"[!] No wallet rows found -- is {BALANCED_SUBSET} present? "
             "(run tools/build_crypto_benchmark.py once, offline, first)", file=sys.stderr)
        return 1
    print("Comparable signals (benchmark provides a matching ground-truth flag):")
    for signal, m in report["signals"].items():
        print(f"  {signal}: support={m['support']}/{m['total_scored']} "
             f"precision={m['precision']} recall={m['recall']} f1={m['f1']} "
             f"fpr={m['false_positive_rate']}")
    print()
    print("NOT_EVALUATED (no comparable benchmark label -- see reason):")
    for signal, reason in report["not_evaluated"].items():
        print(f"  {signal}: {reason}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    rows = load_wallet_rows()
    report = evaluate(rows)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["total_wallet_rows"] else 1
    return print_report(report)


if __name__ == "__main__":
    raise SystemExit(main())
