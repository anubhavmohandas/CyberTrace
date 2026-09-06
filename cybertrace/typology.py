"""Deterministic, explainable behavioral typology signals (Loop 53).

Same discipline as risk.py/attribution.py, applied to a different question:
not "how risky is this wallet" (risk.py) and not "which VASP does this wallet
plausibly touch" (attribution.py), but "does this wallet's own transaction
pattern look like a named typology an investigator should look at."

**No opaque ML, no learned weight.** Every signal here is a named, documented
threshold test over real data this codebase already collected -- either the
Loop 53 `transactions` table (real per-transaction rows -- see evidence.py's
schema comment) or `attribution.wallet_fingerprint`'s existing aggregate
features. Two of `tools/build_crypto_benchmark.py`'s four threshold-derived
labels (HIGH_ACTIVITY's tx_count>=100, HIGH_VALUE's single-tx>=10 BTC, and the
FAN_IN/FAN_OUT tx-count thresholds) are kept numerically IN SYNC with that
module's own `compute_behavior_flags` (not imported -- cybertrace/ does not
depend on tools/ -- but literally the same numbers) precisely so a wallet's
production signal and its Loop 52 benchmark label are comparable in
tools/eval_typology.py.

**Anomaly is not crime.** `severity` is ANOMALOUS / SUSPICIOUS_PATTERN /
HIGH_RISK_SIGNAL -- never CRIMINAL/FRAUDSTER/MONEY_LAUNDERER. This module
answers "is this pattern unusual", never "is this wallet guilty of X".

**Never fabricate.** A signal that needs real per-transaction timestamps
(BURST_ACTIVITY, RAPID_FORWARDING, DORMANT_TO_ACTIVE, PEEL_CHAIN_LIKE) is
`NOT_EVALUATED` with a stated reason for any wallet the `transactions` table
has no rows for (searched before Loop 53 shipped, or every provider came back
empty) -- never approximated from the coarser first_seen/last_seen window as
if it were the same thing. A signal that DID run but found nothing is simply
absent from the returned list (same "no forced answer" discipline as
attribution.vasp_candidates), not a manufactured "NOT_PRESENT" entry for
every signal on every call.

**PEEL_CHAIN_LIKE is the weakest-grounded signal here by construction.** A
real peel chain is a MULTI-WALLET pattern (repeated partial forwarding across
a chain of addresses) that only a multi-hop graph traversal could actually
confirm -- see investigation_graph.py/crypto_investigation.py for that layer.
This module can only see ONE wallet's own transaction list, so what it flags
is a single-wallet proxy (a large inbound receipt followed by several smaller
outbound sends to distinct counterparties in quick succession) -- a
suggestive shape, not a confirmed chain. occam: heuristic proxy, upgrade to
real multi-hop peel detection if the fund-flow graph layer ever needs it.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Optional

TYPOLOGY_POLICY_VERSION = "typology-v1"

FAN_IN = "FAN_IN"
FAN_OUT = "FAN_OUT"
HIGH_ACTIVITY = "HIGH_ACTIVITY"
HIGH_VALUE = "HIGH_VALUE"
CONSOLIDATION = "CONSOLIDATION"
DISPERSAL = "DISPERSAL"
BURST_ACTIVITY = "BURST_ACTIVITY"
RAPID_FORWARDING = "RAPID_FORWARDING"
DORMANT_TO_ACTIVE = "DORMANT_TO_ACTIVE"
PEEL_CHAIN_LIKE = "PEEL_CHAIN_LIKE"

ALL_SIGNALS = (FAN_IN, FAN_OUT, HIGH_ACTIVITY, HIGH_VALUE, CONSOLIDATION, DISPERSAL,
              BURST_ACTIVITY, RAPID_FORWARDING, DORMANT_TO_ACTIVE, PEEL_CHAIN_LIKE)

# Severity vocabulary is deliberately never CRIMINAL/FRAUDSTER/MONEY_LAUNDERER
# -- see module docstring.
ANOMALOUS = "ANOMALOUS"
SUSPICIOUS_PATTERN = "SUSPICIOUS_PATTERN"
HIGH_RISK_SIGNAL = "HIGH_RISK_SIGNAL"
_SEVERITY_ORDER = (ANOMALOUS, SUSPICIOUS_PATTERN, HIGH_RISK_SIGNAL)

DETECTED = "DETECTED"
NOT_EVALUATED = "NOT_EVALUATED"

# POLICY-DEFINED, not empirically calibrated -- same admission risk.py's
# LEVEL_THRESHOLDS and attribution.py's _STRENGTH_THRESHOLDS both already
# make. HIGH_ACTIVITY/HIGH_VALUE/FAN_* values are kept numerically identical
# to tools/build_crypto_benchmark.py's compute_behavior_flags -- see module
# docstring for why.
_HIGH_ACTIVITY_MIN_TX = 100
_HIGH_VALUE_MIN_BTC = 10.0
_FAN_MIN_COUNT = 10

_CONSOLIDATION_MIN_COUNTERPARTIES = 5  # same floor as attribution._behavioral_note
_CONSOLIDATION_MIN_INFLOW_RATIO = 0.6
_DISPERSAL_MAX_INFLOW_RATIO = 0.4

_BURST_WINDOW_SECONDS = 3600
_BURST_MIN_TX = 5
_RAPID_FORWARD_WINDOW_SECONDS = 3600
_RAPID_FORWARD_MIN_VALUE_RATIO = 0.5  # OUT must move at least half of the IN's value
_DORMANT_MIN_GAP_DAYS = 180
_DORMANT_REACTIVATION_MIN_TX = 2
_DORMANT_REACTIVATION_WINDOW_SECONDS = 86400
_PEEL_MIN_HOPS = 4
_PEEL_MAX_OUT_RATIO = 0.5  # each peel leg must be well under the triggering inflow


def _severity_and_confidence(value: float, threshold: float) -> tuple:
    """Deterministic escalation shared by every threshold-based signal below:
    ANOMALOUS at the threshold, SUSPICIOUS_PATTERN at 3x, HIGH_RISK_SIGNAL at
    10x. `confidence` rises linearly from 0.5 at the threshold to a 0.95
    ceiling at 2x -- a policy scale, same "never a probability" discipline as
    risk.py's risk_score, not a statistically fitted number."""
    ratio = value / threshold if threshold else 0
    if ratio >= 10:
        severity = HIGH_RISK_SIGNAL
    elif ratio >= 3:
        severity = SUSPICIOUS_PATTERN
    else:
        severity = ANOMALOUS
    confidence = round(min(0.95, 0.5 + max(0.0, ratio - 1.0) * 0.45), 2)
    return severity, confidence


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _signal(signal: str, status: str, severity: Optional[str] = None,
           confidence: Optional[float] = None, evidence: Optional[list] = None,
           explanation: str = "") -> dict:
    return {
        "policy_version": TYPOLOGY_POLICY_VERSION,
        "signal": signal, "status": status, "severity": severity,
        "confidence": confidence, "evidence": evidence or [], "explanation": explanation,
    }


def _high_activity(metadata: dict) -> Optional[dict]:
    tx_count = metadata.get("tx_count")
    if tx_count is None:
        return _signal(HIGH_ACTIVITY, NOT_EVALUATED,
                       explanation="no tx_count recorded for this wallet.")
    if tx_count < _HIGH_ACTIVITY_MIN_TX:
        return None
    severity, confidence = _severity_and_confidence(tx_count, _HIGH_ACTIVITY_MIN_TX)
    return _signal(HIGH_ACTIVITY, DETECTED, severity, confidence,
                   evidence=[{"tx_count": tx_count}],
                   explanation=f"{tx_count} total transactions recorded, at or above the "
                              f"{_HIGH_ACTIVITY_MIN_TX}-transaction threshold.")


def _high_value(store, entity_id: str) -> Optional[dict]:
    rows = [r for r in store.transactions_for(entity_id) if r.get("asset") == "BTC"
           and r.get("value") is not None]
    if not rows:
        return _signal(HIGH_VALUE, NOT_EVALUATED,
                       explanation="no per-transaction BTC value data recorded for this "
                                  "wallet (this signal is BTC-only, same limitation "
                                  "attribution.wallet_fingerprint documents).")
    top = max(rows, key=lambda r: r["value"])
    if top["value"] < _HIGH_VALUE_MIN_BTC:
        return None
    severity, confidence = _severity_and_confidence(top["value"], _HIGH_VALUE_MIN_BTC)
    return _signal(HIGH_VALUE, DETECTED, severity, confidence,
                   evidence=[{"tx_hash": top["tx_hash"], "value_btc": top["value"]}],
                   explanation=f"a single transaction moved {top['value']:.4f} BTC, at or "
                              f"above the {_HIGH_VALUE_MIN_BTC:.0f} BTC threshold.")


def _fan(store, entity_id: str, metadata: dict, direction: str, signal_name: str) -> Optional[dict]:
    """FAN_OUT (direction='OUT')/FAN_IN (direction='IN'). Prefers the real
    per-transaction count from the `transactions` table (directly comparable
    to compute_behavior_flags' num_txs_as_sender/receiver); falls back to the
    coarser distinct-counterparty-ADDRESS count (sent_to_addresses/
    received_from_addresses, available for every wallet since Loop 34) when
    no per-transaction rows exist yet -- a different, not-benchmark-
    comparable basis, said so in `explanation` rather than silently
    conflated."""
    tx_rows = [r for r in store.transactions_for(entity_id) if r.get("direction") == direction]
    if tx_rows:
        count = len(tx_rows)
        basis = f"{count} recorded transaction(s) in the {direction} direction"
        evidence = [{"tx_hash": r["tx_hash"], "counterparty": r.get("counterparty")}
                   for r in tx_rows[:20]]
    else:
        key = "sent_to_addresses" if direction == "OUT" else "received_from_addresses"
        peers = metadata.get(key)
        if not peers:
            return _signal(signal_name, NOT_EVALUATED,
                           explanation="no per-transaction records and no counterparty "
                                      "address list recorded for this wallet.")
        count = len(peers) if isinstance(peers, list) else 0
        basis = (f"{count} distinct counterparty address(es) on record (no per-transaction "
                f"rows yet -- this is a distinct-address count, not a transaction count, "
                f"and is not directly comparable to the benchmark's tx-count definition)")
        evidence = [{"counterparty": p} for p in (peers if isinstance(peers, list) else [])[:20]]
    if count < _FAN_MIN_COUNT:
        return None
    severity, confidence = _severity_and_confidence(count, _FAN_MIN_COUNT)
    return _signal(signal_name, DETECTED, severity, confidence, evidence=evidence,
                   explanation=f"{basis}, at or above the {_FAN_MIN_COUNT}-count threshold.")


def _consolidation_dispersal(store, entity_id: str) -> List[dict]:
    """Promotes attribution.py's own `_behavioral_note` thresholds (same
    numbers, same 'never creates a candidate alone' discipline) from a
    contextual annotation into first-class CONSOLIDATION/DISPERSAL signals."""
    from .attribution import wallet_fingerprint
    fp = wallet_fingerprint(store, entity_id)
    n, ratio = fp.get("counterparty_count"), fp.get("net_flow_ratio")
    if ratio is None:
        return [_signal(CONSOLIDATION, NOT_EVALUATED,
                        explanation="wallet_fingerprint has no total_received/total_sent "
                                   "for this wallet (BTC-only source).")]
    out = []
    if n is not None and n >= _CONSOLIDATION_MIN_COUNTERPARTIES:
        if ratio >= _CONSOLIDATION_MIN_INFLOW_RATIO:
            out.append(_signal(
                CONSOLIDATION, DETECTED, ANOMALOUS, round(min(0.9, ratio), 2),
                evidence=[{"counterparty_count": n, "net_flow_ratio": ratio}],
                explanation=f"{n} distinct counterparties, net inflow ratio {ratio} -- "
                           f"funds are net accumulating from many sources."))
        elif ratio <= _DISPERSAL_MAX_INFLOW_RATIO:
            out.append(_signal(
                DISPERSAL, DETECTED, ANOMALOUS, round(min(0.9, 1 - ratio), 2),
                evidence=[{"counterparty_count": n, "net_flow_ratio": ratio}],
                explanation=f"{n} distinct counterparties, net inflow ratio {ratio} -- "
                           f"funds are net dispersing to many destinations."))
    return out


def _burst_activity(rows: List[dict]) -> Optional[dict]:
    timed = sorted((r for r in rows if _parse_ts(r.get("timestamp"))),
                  key=lambda r: r["timestamp"])
    if not timed:
        return _signal(BURST_ACTIVITY, NOT_EVALUATED,
                       explanation="no timestamped transactions recorded for this wallet.")
    times = [_parse_ts(r["timestamp"]) for r in timed]
    best_count, best_window = 0, []
    left = 0
    for right in range(len(times)):
        while (times[right] - times[left]).total_seconds() > _BURST_WINDOW_SECONDS:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count, best_window = count, timed[left:right + 1]
    if best_count < _BURST_MIN_TX:
        return None
    severity, confidence = _severity_and_confidence(best_count, _BURST_MIN_TX)
    return _signal(BURST_ACTIVITY, DETECTED, severity, confidence,
                   evidence=[{"tx_hash": r["tx_hash"], "timestamp": r["timestamp"]}
                            for r in best_window[:20]],
                   explanation=f"{best_count} transactions within a "
                              f"{_BURST_WINDOW_SECONDS // 60}-minute window, at or above "
                              f"the {_BURST_MIN_TX}-transaction burst threshold.")


def _rapid_forwarding(rows: List[dict]) -> Optional[dict]:
    ins = sorted((r for r in rows if r.get("direction") == "IN" and r.get("value") is not None
                 and _parse_ts(r.get("timestamp"))), key=lambda r: r["timestamp"])
    outs = sorted((r for r in rows if r.get("direction") == "OUT" and r.get("value") is not None
                  and _parse_ts(r.get("timestamp"))), key=lambda r: r["timestamp"])
    if not ins or not outs:
        return _signal(RAPID_FORWARDING, NOT_EVALUATED,
                       explanation="no timestamped, valued IN/OUT transaction pair "
                                  "recorded for this wallet.")
    for inc in ins:
        in_ts = _parse_ts(inc["timestamp"])
        for out in outs:
            out_ts = _parse_ts(out["timestamp"])
            if out_ts <= in_ts:
                continue
            gap = (out_ts - in_ts).total_seconds()
            if gap > _RAPID_FORWARD_WINDOW_SECONDS:
                break
            if out.get("counterparty") == inc.get("counterparty"):
                continue  # a refund/round-trip to the same peer, not forwarding onward
            if out["value"] >= inc["value"] * _RAPID_FORWARD_MIN_VALUE_RATIO:
                confidence = round(min(0.9, 0.5 + (1 - gap / _RAPID_FORWARD_WINDOW_SECONDS) * 0.4), 2)
                return _signal(
                    RAPID_FORWARDING, DETECTED, SUSPICIOUS_PATTERN, confidence,
                    evidence=[{"in_tx_hash": inc["tx_hash"], "out_tx_hash": out["tx_hash"],
                              "gap_seconds": int(gap)}],
                    explanation=f"received funds were forwarded onward within "
                               f"{int(gap // 60)} minute(s), moving "
                               f"{out['value'] / inc['value']:.0%} of the inbound value "
                               f"to a different counterparty.")
    return None


def _dormant_to_active(rows: List[dict]) -> Optional[dict]:
    timed = sorted((r for r in rows if _parse_ts(r.get("timestamp"))),
                  key=lambda r: r["timestamp"])
    if len(timed) < 2:
        return _signal(DORMANT_TO_ACTIVE, NOT_EVALUATED,
                       explanation="fewer than two timestamped transactions recorded for "
                                  "this wallet.")
    times = [_parse_ts(r["timestamp"]) for r in timed]
    best_gap_days, best_idx = 0, None
    for i in range(1, len(times)):
        gap_days = (times[i] - times[i - 1]).total_seconds() / 86400
        if gap_days > best_gap_days:
            best_gap_days, best_idx = gap_days, i
    if best_gap_days < _DORMANT_MIN_GAP_DAYS:
        return None
    reactivation_end = times[best_idx] + timedelta(seconds=_DORMANT_REACTIVATION_WINDOW_SECONDS)
    following = [t for t in times[best_idx:] if t <= reactivation_end]
    if len(following) < _DORMANT_REACTIVATION_MIN_TX:
        return None
    severity, confidence = _severity_and_confidence(best_gap_days, _DORMANT_MIN_GAP_DAYS)
    return _signal(
        DORMANT_TO_ACTIVE, DETECTED, severity, confidence,
        evidence=[{"tx_hash": timed[best_idx]["tx_hash"], "dormant_days": round(best_gap_days)}],
        explanation=f"wallet was inactive for {round(best_gap_days)} day(s), then had "
                   f"{len(following)} transaction(s) within "
                   f"{_DORMANT_REACTIVATION_WINDOW_SECONDS // 3600}h of reactivating.")


def _peel_chain_like(rows: List[dict]) -> Optional[dict]:
    """Single-wallet proxy only -- see module docstring's own ceiling note."""
    ins = [r for r in rows if r.get("direction") == "IN" and r.get("value") is not None]
    outs = sorted((r for r in rows if r.get("direction") == "OUT" and r.get("value") is not None
                  and _parse_ts(r.get("timestamp"))), key=lambda r: r["timestamp"])
    if not ins or len(outs) < _PEEL_MIN_HOPS:
        return _signal(PEEL_CHAIN_LIKE, NOT_EVALUATED,
                       explanation="no valued inbound transaction, or fewer than "
                                  f"{_PEEL_MIN_HOPS} valued outbound transactions, "
                                  "recorded for this wallet.")
    largest_in = max(r["value"] for r in ins)
    run, best_run = [], []
    seen_peers = set()
    for r in outs:
        if r["value"] <= largest_in * _PEEL_MAX_OUT_RATIO and r.get("counterparty") not in seen_peers:
            run.append(r)
            seen_peers.add(r.get("counterparty"))
        else:
            if len(run) > len(best_run):
                best_run = run
            run, seen_peers = [], set()
    if len(run) > len(best_run):
        best_run = run
    if len(best_run) < _PEEL_MIN_HOPS:
        return None
    severity, confidence = _severity_and_confidence(len(best_run), _PEEL_MIN_HOPS)
    # This heuristic is structurally capped at SUSPICIOUS_PATTERN -- it is a
    # single-wallet proxy for a genuinely multi-wallet pattern, so it should
    # never present as the most severe possible signal on its own.
    if severity == HIGH_RISK_SIGNAL:
        severity = SUSPICIOUS_PATTERN
    return _signal(
        PEEL_CHAIN_LIKE, DETECTED, severity, confidence,
        evidence=[{"tx_hash": r["tx_hash"], "value": r["value"], "counterparty": r["counterparty"]}
                 for r in best_run[:20]],
        explanation=f"{len(best_run)} sequential outbound transactions, each under "
                   f"{_PEEL_MAX_OUT_RATIO:.0%} of the largest inbound receipt, each to a "
                   f"distinct counterparty -- a single-wallet shape consistent with (but "
                   f"not confirmation of) a peel chain; see investigation_graph.py for "
                   f"multi-hop confirmation.")


def typology_signals(store, entity_id: Optional[str]) -> List[dict]:
    """The full behavioral typology result for one wallet. Returns a list:
    one entry per DETECTED signal, plus one NOT_EVALUATED entry per signal
    whose required data is genuinely missing -- a checked-and-absent signal
    is simply not in the list (see module docstring)."""
    if not entity_id:
        return [_signal(s, NOT_EVALUATED, explanation="wallet was never searched into "
                        "this case.") for s in ALL_SIGNALS]
    metadata = store.metadata(entity_id) or {}
    rows = store.transactions_for(entity_id)

    out: List[dict] = []
    for fn in (lambda: _high_activity(metadata), lambda: _high_value(store, entity_id),
              lambda: _fan(store, entity_id, metadata, "OUT", FAN_OUT),
              lambda: _fan(store, entity_id, metadata, "IN", FAN_IN)):
        s = fn()
        if s:
            out.append(s)
    out.extend(_consolidation_dispersal(store, entity_id))
    for fn in (lambda: _burst_activity(rows), lambda: _rapid_forwarding(rows),
              lambda: _dormant_to_active(rows), lambda: _peel_chain_like(rows)):
        s = fn()
        if s:
            out.append(s)
    return out


def demo() -> None:
    """Runnable self-check -- Occam's mandatory smallest-thing-that-fails
    check for this module's branch-heavy detectors."""
    class _FakeStore:
        def __init__(self, metadata, transactions):
            self._metadata, self._transactions = metadata, transactions

        def metadata(self, entity_id):
            return self._metadata

        def transactions_for(self, entity_id):
            return self._transactions

        def _one(self, *a, **k):
            return None

    # No wallet at all.
    assert all(s["status"] == NOT_EVALUATED for s in typology_signals(_FakeStore({}, []), None))

    # High activity + high value + fan-out, all real data.
    txs = [{"tx_hash": f"h{i}", "direction": "OUT", "counterparty": f"peer{i}",
           "asset": "BTC", "value": 1.0, "timestamp": f"2026-01-01T00:0{i % 6}:00+00:00"}
          for i in range(12)]
    txs.append({"tx_hash": "big", "direction": "IN", "counterparty": "whale",
               "asset": "BTC", "value": 15.0, "timestamp": "2025-12-31T00:00:00+00:00"})
    store = _FakeStore({"tx_count": 150}, txs)
    signals = {s["signal"]: s for s in typology_signals(store, "e1")}
    assert signals[HIGH_ACTIVITY]["status"] == DETECTED
    assert signals[HIGH_VALUE]["status"] == DETECTED
    assert signals[FAN_OUT]["status"] == DETECTED
    assert signals[BURST_ACTIVITY]["status"] == DETECTED
    assert all(s["severity"] in _SEVERITY_ORDER for s in signals.values() if s["status"] == DETECTED)

    # Insufficient data stays NOT_EVALUATED, never a fabricated result.
    empty_store = _FakeStore({}, [])
    empty_signals = {s["signal"]: s for s in typology_signals(empty_store, "e2")}
    assert empty_signals[HIGH_ACTIVITY]["status"] == NOT_EVALUATED
    assert empty_signals[BURST_ACTIVITY]["status"] == NOT_EVALUATED

    print("typology.demo(): all assertions passed")


if __name__ == "__main__":
    demo()
