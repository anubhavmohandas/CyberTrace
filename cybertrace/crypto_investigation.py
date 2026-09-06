"""Canonical crypto investigation composition (Loop 53).

The single entrypoint CLI/API/GUI all call: `investigate_wallet`. Composes
layers that mostly already existed (fund-flow/VASP attribution/risk, via
`correlate.wallet_trace_report`) with what Loop 53 actually adds -- a
canonical transaction list, an investigation graph, behavioral typology
signals, confirmed/candidate cross-chain labeling, a chronological timeline,
and LEA recommendations -- into ONE result, so a caller never has to
reconstruct the workflow by hand from six different function calls.

**This module computes nothing new about attribution or control.** It reads
`wallet_trace_report`'s own `vasp_investigation`/`risk` fields verbatim.
Multi-hop tracing here is fund-flow tracing (the `path`/graph edges), never
ownership -- see investigation_graph.py's own docstring for the same
invariant restated at the graph layer. Loop 46 (ML attribution) and Loop 47
(multi-hop OWNERSHIP attribution) remain rejected and are not reintroduced
anywhere in this module.

**Cross-chain confirmed vs candidate**, the one piece of new vocabulary this
loop introduces (see `cross_chain_events`): `BRIDGE_CONFIRMED`/
`SWAP_CONFIRMED` are real live transactions (`cross_chain_module.py`'s four
sources, already recorded via `cybertrace trace-cross-chain`);
`CROSS_CHAIN_CANDIDATE` is `correlate.cross_chain_links`' same-entity-corpus
grouping -- no live transaction, never promoted to confirmed.

**Bounded.** `max_hops` follows the existing convention threaded through
`correlate.py`/`cli.py`; `max_transactions`/`max_addresses` bound the new
transaction/graph reads added here. No new provider call is made by this
module -- it reads the `transactions` table and the corpora other modules
already populate.
"""
from __future__ import annotations

from typing import List, Optional

from . import lea_actions, typology
from .investigation_graph import build_from_wallet_trace
from .risk import score_wallet_risk

INVESTIGATION_POLICY_VERSION = "crypto-investigation-v1"

BRIDGE_CONFIRMED = "BRIDGE_CONFIRMED"
SWAP_CONFIRMED = "SWAP_CONFIRMED"
CROSS_CHAIN_CANDIDATE = "CROSS_CHAIN_CANDIDATE"

DEFAULT_MAX_HOPS = 4
DEFAULT_MAX_TRANSACTIONS = 500
DEFAULT_MAX_ADDRESSES = 250

FOUND, PARTIAL, NOT_FOUND, NOT_CHECKED = "FOUND", "PARTIAL", "NOT_FOUND", "NOT_CHECKED"


def normalize_transactions(store, entity_id: Optional[str],
                           max_transactions: int = DEFAULT_MAX_TRANSACTIONS) -> List[dict]:
    """Canonical per-transaction view for one wallet: the Loop 53
    `transactions` table's own rows, bounded, oldest first. `entity_id` is
    None (wallet never searched into this case) returns an empty list --
    callers distinguish that from a genuinely-empty real result via
    `transaction_status` (see `investigate_wallet`), never by this list
    alone."""
    if not entity_id:
        return []
    return store.transactions_for(entity_id, limit=max_transactions)


def _transaction_status(entity_id: Optional[str], rows: List[dict]) -> str:
    if not entity_id:
        return NOT_CHECKED
    if not rows:
        return NOT_FOUND  # wallet was searched; this case simply recorded none
    if any(r.get("status") == "PARTIAL" for r in rows):
        return PARTIAL
    return FOUND


def cross_chain_events(store, wallet_address: str, chain: Optional[str],
                       entity_id: Optional[str]) -> List[dict]:
    """Confirmed (live transaction) and candidate (corpus grouping only)
    cross-chain events for one wallet -- see module docstring for the
    confirmed/candidate distinction this function's whole job is to state
    explicitly rather than blur."""
    events: List[dict] = []
    for link in store.cross_chain_tx_links_for(wallet_address):
        events.append({
            "event_type": BRIDGE_CONFIRMED if link.get("mechanism") == "BRIDGE" else SWAP_CONFIRMED,
            "mechanism": link.get("mechanism"),
            "source_chain": link.get("source_chain"), "source_address": link.get("source_address"),
            "source_tx": link.get("source_tx"),
            "dest_chain": link.get("dest_chain"), "dest_address": link.get("dest_address"),
            "dest_tx": link.get("dest_tx"), "evidence_ref": link.get("evidence_ref"),
            "tx_timestamp": link.get("tx_timestamp"), "source_api": link.get("source_api"),
            "status": link.get("status"), "confidence": "HIGH_CONFIDENCE",
        })

    if entity_id:
        from .correlate import cross_chain_links
        for group in cross_chain_links(store):
            member_ids = {m["entity_id"] for m in group["members"]}
            if entity_id not in member_ids:
                continue
            for m in group["members"]:
                if m["entity_id"] == entity_id:
                    continue
                events.append({
                    "event_type": CROSS_CHAIN_CANDIDATE, "mechanism": None,
                    "source_chain": chain, "source_address": wallet_address,
                    "source_tx": None, "dest_chain": m["chain"], "dest_address": m["value"],
                    "dest_tx": None, "evidence_ref": None, "tx_timestamp": None,
                    "source_api": "correlate.cross_chain_links", "status": None,
                    "confidence": "LOW_CONFIDENCE",
                    "attribution": group["attribution"], "entity_name": group["entity_name"],
                })
    return events


def investigation_timeline(wallet_trace: Optional[dict], transactions: List[dict],
                           typology_signals: List[dict], events: List[dict]) -> List[dict]:
    """Chronological merge of transactions, VASP exposure, typology signals,
    and cross-chain events -- every entry keeps its own source/evidence so a
    reader never loses provenance by reading the timeline instead of the
    underlying field. Entries with no timestamp (many typology signals,
    corpus-grouping cross-chain candidates) are listed last, un-ordered
    among themselves, rather than dropped."""
    timed: List[dict] = []
    untimed: List[dict] = []

    for tx in transactions:
        entry = {
            "timestamp": tx.get("timestamp"),
            "title": f"{tx.get('direction')} {tx.get('value')} {tx.get('asset')} "
                    f"({tx.get('counterparty') or 'unknown counterparty'})",
            "kind": "TRANSACTION", "source": tx.get("provider"),
            "evidence": [{"tx_hash": tx.get("tx_hash")}],
        }
        (timed if entry["timestamp"] else untimed).append(entry)

    if wallet_trace:
        vi = wallet_trace.get("vasp_investigation") or {}
        if vi.get("primary_vasp"):
            untimed.append({
                "timestamp": None,
                "title": f"VASP exposure: {vi['primary_vasp']} "
                        f"({vi.get('attribution_tier')}, control {vi.get('control_status')})",
                "kind": "VASP_EXPOSURE", "source": "vasp_investigation",
                "evidence": vi.get("evidence") or [],
            })

    for signal in typology_signals:
        if signal.get("status") != "DETECTED":
            continue
        ts = None
        if signal.get("evidence") and isinstance(signal["evidence"], list):
            for e in signal["evidence"]:
                if isinstance(e, dict) and e.get("timestamp"):
                    ts = e["timestamp"]
                    break
        entry = {"timestamp": ts, "title": f"Behavioral signal: {signal['signal']} "
                                          f"({signal.get('severity')})",
                "kind": "TYPOLOGY", "source": "typology", "evidence": signal.get("evidence") or []}
        (timed if ts else untimed).append(entry)

    for ev in events:
        entry = {
            "timestamp": ev.get("tx_timestamp"),
            "title": f"Cross-chain {ev['event_type']}: {ev.get('source_chain')} -> "
                    f"{ev.get('dest_chain') or 'unknown'} via {ev.get('source_api')}",
            "kind": "CROSS_CHAIN", "source": ev.get("source_api"),
            "evidence": [ev.get("evidence_ref")] if ev.get("evidence_ref") else [],
        }
        (timed if entry["timestamp"] else untimed).append(entry)

    timed.sort(key=lambda e: e["timestamp"])
    return timed + untimed


def _reconstruct_hit(wallet_trace: dict) -> Optional[dict]:
    """A risk.score_wallet_risk-shaped `hit` dict, reconstructed from fields
    `wallet_trace_report` already returns -- no new query. None when the
    wallet has no VASP-attributed endpoint at all (wallet_trace['exchange']
    is None), matching wallet_exchange_paths' own "absent, not a hit with
    nulls" contract."""
    if not wallet_trace.get("exchange"):
        return None
    return {
        "hops": wallet_trace["hops"], "exchange": wallet_trace["exchange"],
        "attribution": wallet_trace["attribution"],
        "attribution_source": wallet_trace["attribution_source"],
        "confidence": wallet_trace["exchange_confidence"],
        "direct_vasp_contacts": wallet_trace.get("direct_vasp_contacts") or [],
        "secondary_vasp_contacts": wallet_trace.get("secondary_vasp_contacts") or [],
        "evidence_ids": wallet_trace.get("evidence_ids") or [],
    }


def enriched_risk(store, wallet_trace: dict, typology_signals: List[dict]) -> dict:
    """risk.score_wallet_risk re-run with the Loop 53 BEHAVIORAL category
    armed -- reconstructs `hit`/`service_tags` from wallet_trace's own
    already-computed fields (see `_reconstruct_hit`), issuing no new query.
    Distinct from `wallet_trace['risk']` (the pre-Loop-53 baseline, left
    byte-identical for every existing caller) -- this is the composed
    result's own, richer risk view."""
    return score_wallet_risk(
        store, wallet_trace["entity_id"], wallet_trace["address"],
        _reconstruct_hit(wallet_trace), wallet_trace.get("service_tags") or [],
        typology_signals=typology_signals)


def investigate_wallet(store, address: str, chain: Optional[str] = None,
                       max_hops: int = DEFAULT_MAX_HOPS,
                       max_transactions: int = DEFAULT_MAX_TRANSACTIONS,
                       max_addresses: int = DEFAULT_MAX_ADDRESSES) -> Optional[dict]:
    """The canonical Loop 53 investigation result for one wallet. Returns
    None if `address` was never searched into this case (same contract as
    `correlate.wallet_trace_report`, which this wraps)."""
    from .correlate import wallet_trace_report
    wallet_trace = wallet_trace_report(store, address, max_hops=max_hops, chain=chain)
    if wallet_trace is None:
        return None

    entity_id = wallet_trace["entity_id"]
    wallet_address = wallet_trace["address"]
    resolved_chain = wallet_trace["chain"]

    transactions = normalize_transactions(store, entity_id, max_transactions=max_transactions)
    tx_status = _transaction_status(entity_id, transactions)

    graph = build_from_wallet_trace(wallet_trace, transactions=transactions,
                                    cross_chain_events=cross_chain_events(
                                        store, wallet_address, resolved_chain, entity_id),
                                    max_transactions=max_transactions, max_addresses=max_addresses)
    typology_signals = typology.typology_signals(store, entity_id)
    events = cross_chain_events(store, wallet_address, resolved_chain, entity_id)
    timeline = investigation_timeline(wallet_trace, transactions, typology_signals, events)
    actions = lea_actions.recommended_actions_for_wallet(wallet_trace, typology_signals, events)
    risk = enriched_risk(store, wallet_trace, typology_signals)

    return {
        "policy_version": INVESTIGATION_POLICY_VERSION,
        "address": wallet_address, "chain": resolved_chain, "entity_id": entity_id,
        "max_hops": max_hops, "max_transactions": max_transactions, "max_addresses": max_addresses,
        "wallet_trace": wallet_trace,
        "transactions": transactions, "transaction_status": tx_status,
        "graph": graph.to_dict(), "graph_summary": graph.summary(),
        "typology_signals": typology_signals,
        "cross_chain_events": events,
        "timeline": timeline,
        "recommended_actions": actions,
        "risk": risk,
        "vasp_investigation": wallet_trace.get("vasp_investigation"),
    }


def demo() -> None:
    """Runnable self-check against a real EvidenceStore (in-memory shape),
    exercising the full compose path end to end."""
    import tempfile
    from .evidence import EvidenceStore

    with tempfile.TemporaryDirectory() as d:
        with EvidenceStore(f"{d}/demo.db") as store:
            addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
            eid = store.upsert_entity("BTC_ADDRESS", addr)
            store.set_metadata(eid, tx_count=5)
            store.record_transactions(eid, addr, "BTC_ADDRESS", "bitcoin", [
                {"tx_hash": "h1", "direction": "OUT", "counterparty": "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                 "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T00:00:00+00:00"},
            ])
            result = investigate_wallet(store, addr, chain="BTC_ADDRESS")
            assert result is not None
            assert result["address"] == addr
            assert result["transaction_status"] == "FOUND"
            assert len(result["transactions"]) == 1
            assert "graph_summary" in result
            assert isinstance(result["typology_signals"], list)
            assert isinstance(result["recommended_actions"], list)

            never_searched = investigate_wallet(store, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
            assert never_searched is None

    print("crypto_investigation.demo(): all assertions passed")


if __name__ == "__main__":
    demo()
