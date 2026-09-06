"""LEA (law-enforcement-audience) recommended actions for a wallet/VASP
investigation result (Loop 53).

`correlate.recommended_actions` covers darkweb OSINT candidate roles
(OPERATOR/CERTIFICATE/NAMESERVER/ASN/...) and has no branch for a wallet or
VASP finding at all -- this is that missing branch, same plain-function
shape (read fields a caller already computed, return a list, no new
evidence, no new query) but structured per recommendation
(`{action, reason, evidence, confidence, source}`) rather than a bare
string, since an LEA action needs its own confidence/evidence distinct from
the wallet's overall risk score.

**These are investigative recommendations, not legal conclusions.** Every
action names the exact field(s) that triggered it; none of them assert
wrongdoing. `VASP_DISCLOSURE_TARGET` means "there is a real VASP relationship
worth a disclosure request", not "this VASP holds stolen funds".
"""
from __future__ import annotations

from typing import List, Optional

VASP_DISCLOSURE_TARGET = "VASP_DISCLOSURE_TARGET"
FREEZING_PRESERVATION_TARGET = "FREEZING_PRESERVATION_TARGET"
HIGH_VALUE_FUND_PATH = "HIGH_VALUE_FUND_PATH"
IMPORTANT_INTERMEDIARY = "IMPORTANT_INTERMEDIARY"
CROSS_CHAIN_FOLLOW_UP = "CROSS_CHAIN_FOLLOW_UP"
REQUIRES_ANALYST_REVIEW = "REQUIRES_ANALYST_REVIEW"

_HIGH_VALUE_BTC_THRESHOLD = 1.0  # same order of magnitude as typology.HIGH_VALUE's
                                 # own 10 BTC single-tx bar, applied to total path value


def _action(action: str, reason: str, evidence: Optional[list], confidence: str,
           source: str) -> dict:
    return {"action": action, "reason": reason, "evidence": evidence or [],
           "confidence": confidence, "source": source}


def recommended_actions_for_wallet(wallet_trace: dict, typology: Optional[List[dict]] = None,
                                   cross_chain: Optional[List[dict]] = None) -> List[dict]:
    """Actions for one wallet, read off fields `crypto_investigation.
    investigate_wallet` already computed -- `wallet_trace` is a
    `correlate.wallet_trace_report` result (or None), `typology` is
    `typology.typology_signals`' output, `cross_chain` is
    `crypto_investigation.cross_chain_events`' output."""
    if not wallet_trace:
        return []
    actions: List[dict] = []
    vi = wallet_trace.get("vasp_investigation") or {}
    risk = wallet_trace.get("risk") or {}

    if vi.get("primary_vasp"):
        actions.append(_action(
            VASP_DISCLOSURE_TARGET,
            f"Wallet has {vi.get('confidence')} exposure to {vi['primary_vasp']} "
            f"({vi.get('attribution_tier')}) -- a disclosure request to this VASP is "
            "the concrete next step to identify the account holder.",
            evidence=vi.get("evidence"), confidence=vi.get("status") or "STRONG_CANDIDATE",
            source="vasp_investigation"))

    if vi.get("control_status") == "ESTABLISHED" and risk.get("risk_level") in ("HIGH", "CRITICAL"):
        actions.append(_action(
            FREEZING_PRESERVATION_TARGET,
            f"Control of this address by {vi.get('primary_vasp')} is ESTABLISHED and "
            f"overall risk is {risk.get('risk_level')} -- a preservation/freezing "
            "request naming this specific address is actionable now.",
            evidence=vi.get("control_evidence"), confidence="HIGH_CONFIDENCE",
            source="vasp_investigation+risk"))

    if wallet_trace.get("exchange") and wallet_trace.get("hops", 0) and wallet_trace["hops"] > 1:
        actions.append(_action(
            IMPORTANT_INTERMEDIARY,
            f"{wallet_trace['hops']} intermediary hop(s) separate this wallet from "
            f"{wallet_trace['exchange']} -- the intermediate addresses on `path` are "
            "candidates for their own trace, not merely transit.",
            evidence=[{"path": wallet_trace.get("path")}], confidence="MEDIUM_CONFIDENCE",
            source="wallet_exchange_paths"))

    # `cross_chain` is crypto_investigation.cross_chain_events' own output --
    # the single source for both confirmed (BRIDGE_CONFIRMED/SWAP_CONFIRMED,
    # a real live transaction) and candidate (corpus grouping only) events,
    # read the same way regardless of caller (CLI/API single-wallet path or
    # correlate._attach_crypto_investigation's case-wide report path).
    for ev in (cross_chain or []):
        if ev.get("event_type") == "CROSS_CHAIN_CANDIDATE":
            actions.append(_action(
                CROSS_CHAIN_FOLLOW_UP,
                f"A corpus-level grouping (not a live transaction) links this wallet to "
                f"{ev.get('dest_address')} on {ev.get('dest_chain')} via the same "
                f"{ev.get('attribution')} evidence -- worth checking, not yet confirmed.",
                evidence=[ev], confidence="LOW_CONFIDENCE", source="correlate.cross_chain_links"))
        else:
            actions.append(_action(
                CROSS_CHAIN_FOLLOW_UP,
                f"Real {(ev.get('mechanism') or 'cross-chain').lower()} activity via "
                f"{ev.get('source_api')} links this wallet to "
                f"{ev.get('dest_chain') or 'another chain'} -- follow the destination "
                "address on that chain.",
                evidence=[ev], confidence="HIGH_CONFIDENCE", source="cross_chain_module"))

    for signal in (typology or []):
        if signal.get("status") != "DETECTED":
            continue
        if signal.get("severity") == "HIGH_RISK_SIGNAL":
            actions.append(_action(
                REQUIRES_ANALYST_REVIEW,
                f"Behavioral signal {signal['signal']} reached HIGH_RISK_SIGNAL severity: "
                f"{signal.get('explanation')}",
                evidence=signal.get("evidence"), confidence="MEDIUM_CONFIDENCE",
                source="typology"))

    if vi.get("status") == "AMBIGUOUS_NEEDS_REVIEW":
        actions.append(_action(
            REQUIRES_ANALYST_REVIEW,
            "Multiple independently-sourced VASP attribution claims exist for this "
            "wallet or address -- an analyst should resolve which (if any) is correct "
            "before relying on the primary candidate.",
            evidence=vi.get("evidence"), confidence="MEDIUM_CONFIDENCE",
            source="vasp_investigation"))

    if risk.get("risk_score") is not None and risk["risk_score"] >= 50:
        # HIGH_VALUE_FUND_PATH: an OFAC/flow-reach signal already scored by
        # risk.py at meaningful weight -- reusing its own contribution
        # detail rather than re-deriving a value threshold here.
        for c in risk.get("risk_contributions", []):
            if c.get("category") == "SANCTIONS" and c.get("dimension") == "FLOW":
                actions.append(_action(
                    HIGH_VALUE_FUND_PATH,
                    f"This wallet's fund-flow path reaches a sanctioned entity: "
                    f"{c.get('detail')}",
                    evidence=[c], confidence="HIGH_CONFIDENCE", source="risk"))
                break

    return actions


def demo() -> None:
    """Runnable self-check."""
    trace = {
        "exchange": "Binance", "hops": 3, "path": ["a", "b", "c", "Binance"],
        "vasp_investigation": {"primary_vasp": "Binance", "confidence": "HIGH",
                               "attribution_tier": "VASP_DISCLOSED", "evidence": [],
                               "status": "STRONG_CANDIDATE",
                               "control_status": "ESTABLISHED", "control_evidence": []},
        "risk": {"risk_level": "HIGH", "risk_score": 80, "risk_contributions": []},
    }
    actions = recommended_actions_for_wallet(trace)
    kinds = {a["action"] for a in actions}
    assert VASP_DISCLOSURE_TARGET in kinds
    assert FREEZING_PRESERVATION_TARGET in kinds
    assert IMPORTANT_INTERMEDIARY in kinds

    assert recommended_actions_for_wallet(None) == []

    confirmed_event = [{"event_type": "BRIDGE_CONFIRMED", "mechanism": "BRIDGE",
                        "source_api": "wormholescan", "dest_chain": "ETH_ADDRESS"}]
    actions = recommended_actions_for_wallet(trace, cross_chain=confirmed_event)
    assert any(a["action"] == CROSS_CHAIN_FOLLOW_UP and a["confidence"] == "HIGH_CONFIDENCE"
              for a in actions)

    candidate_event = [{"event_type": "CROSS_CHAIN_CANDIDATE", "dest_chain": "ETH_ADDRESS",
                        "dest_address": "0xabc", "attribution": "TAG_ATTESTED"}]
    actions = recommended_actions_for_wallet(trace, cross_chain=candidate_event)
    assert any(a["action"] == CROSS_CHAIN_FOLLOW_UP and a["confidence"] == "LOW_CONFIDENCE"
              for a in actions)

    print("lea_actions.demo(): all assertions passed")


if __name__ == "__main__":
    demo()
