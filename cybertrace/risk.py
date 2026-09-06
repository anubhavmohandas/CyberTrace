"""Explainable risk scoring: policy-driven, additive to wallet/VASP output.

Answers one question for an investigator: *given the evidence CyberTrace
actually has, how should this wallet be prioritized, and why?* It never
answers "this wallet belongs to a criminal" -- see the invariants below.

CyberTrace already keeps three concepts separate and this module adds a
fourth without collapsing any of them:

    reachability confidence (wallet_exchange_paths' hop-decay `confidence`)
        != VASP attribution tier (ANALYST_ASSERTED/REGULATORY_ATTESTED/...)
        != risk score (this module)

Design, one paragraph each:

**No hardcoded final scores.** Every number below is a named RULE with a
documented `why`, not a bare `{"SANCTIONS": 90}` map. `score_wallet_risk`
computes a score by summing RULE contributions over deduplicated FEATURES
(underlying facts) -- nothing assigns a final number to a category directly.

**Fact-level dedup, not label-count.** A GraphSense pack tagging one
address `mixing_service` twice, or an OFAC designation cited from two
fields, is ONE feature (keyed by `fact_key`), scored once. Repetition of
the same underlying fact never inflates the score; see `_add_feature`.

**Source strength is explicit.** Every rule states `source_strength`:
REGULATORY_AUTHORITATIVE (OFAC SDN) > CURATED_DISCLOSURE (Chainabuse
trusted reports) > THIRD_PARTY_ATTRIBUTION (GraphSense tags, Elliptic++
dataset labels). VASP-attribution tiers (TAG_ATTESTED etc.) are a
different axis entirely and are never reused as a risk weight -- see
`SUPPORTED categories not derived from VASP attribution` below.

**Direct vs contextual.** Every rule states `signal_type`. A regulatory
designation or an explicit fraud report is DIRECT evidence about the
address. A mixer/CoinJoin/DeFi interaction is CONTEXTUAL -- present
because an investigator should see it, weighted low, and structurally
incapable of reaching CRITICAL on its own (see CATEGORY_CAP).

**Wallet vs flow.** `wallet_risk` scores facts about the traced address's
own identity (it IS an OFAC record, it IS a reported scam). `flow_risk`
scores facts about what its funds touched (it REACHES a sanctioned
entity, its path crosses a tagged mixer). `overall_risk` is the canonical
score: the SAME policy run once over the deduplicated union of both
dimensions' features -- not `wallet_risk.score + flow_risk.score`, which
could double an entity's OFAC designation if it were ever reachable from
both directions. This is exercised by
tests/test_risk.py::test_overall_is_not_the_naive_sum_of_wallet_and_flow.

**Unknown is a state, not zero.** No qualifying feature at all ->
`risk_level = "INSUFFICIENT_EVIDENCE"`, `risk_score = None`. Zero is a
number that means "we checked and it was low"; this codebase refuses to
manufacture that claim from an empty result set (global invariant 8).

**Category ceilings are policy, not statistics.** CATEGORY_CAP and
LEVEL_THRESHOLDS are labelled POLICY-DEFINED throughout this module
because they are: chosen so a purely contextual (mixer/DeFi) wallet
cannot reach HIGH and a bare regulatory designation alone reaches
CRITICAL, and documented here rather than fit to any labelled dataset.
`risk_score` is a policy scale, never a probability -- see RISK_POLICY_VERSION.

**No opaque ML.** Every contribution traces to one RULES entry and one
FEATURE with cited evidence/attribution_source -- reconstructible by hand
from `risk_reasons` alone, per rule `reconstruct_score`.

**Temporal model: snapshot-based, undocumented decay not invented.**
Evidence here (OFAC designation date, GraphSense tag, dataset label) has
no uniform "when does this stop mattering" answer in the data CyberTrace
holds, and correlate.py itself invents no such policy for VASP
attribution either. `score_wallet_risk` scores the CURRENT evidence state
only; a re-run after new evidence is ingested is a new snapshot, not a
decayed update of the old one.

**No mitigation invented.** Investigated: the only human-verdict table in
this codebase, `analyst_feedback`, is keyed to `candidates` rows, and
`candidates.ctype` is only ever OPERATOR/INFRA/IP (see
correlate.save_candidates) -- a wallet entity never becomes a candidate,
so no analyst verdict can ever be joined to a traced address today. This
module adds no mitigating signal rather than inventing one for symmetry;
see the Loop 36 report for the full note.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

RISK_POLICY_VERSION = "risk-v1"

# --- taxonomy ------------------------------------------------------------

SANCTIONS = "SANCTIONS"
FRAUD = "FRAUD"
MIXING = "MIXING"
COINJOIN = "COINJOIN"
DEFI = "DEFI"
UNKNOWN = "UNKNOWN"
# Loop 53: typology.py's own DETECTED signals (FAN_OUT/RAPID_FORWARDING/
# BURST_ACTIVITY/PEEL_CHAIN_LIKE), the first real, non-VASP-attribution,
# non-third-party-tag behavioral evidence source this codebase has -- see
# CONTEXTUAL_BEHAVIORAL below, declared since Loop 36 for exactly this.
BEHAVIORAL = "BEHAVIORAL"

SUPPORTED_CATEGORIES = (SANCTIONS, FRAUD, MIXING, COINJOIN, DEFI, UNKNOWN, BEHAVIORAL)

# Categories the PS2 problem statement names that this policy deliberately
# does NOT score, and why -- so "unsupported" is a documented, stable fact
# an investigator can read, not an accidental omission. Extending this list
# requires a genuine new evidence source, not a keyword match on OFAC's
# free-text entity_name (see integrations/ofac.py -- its own docstring
# confirms the schema carries no program/category taxonomy at all).
UNSUPPORTED_CATEGORIES: Dict[str, str] = {
    "RANSOMWARE": "OFAC SDN records carry no program/category field in what "
                  "integrations/ofac.py extracts -- only entity_name, aliases and "
                  "profile_id. Telling a ransomware designation apart from any other "
                  "would require fragile keyword-matching on a free-text name field, "
                  "which this policy refuses to do.",
    "DARKNET": "no darknet-market-specific evidence source is wired into scoring. "
               "OFAC designations of darknet markets (e.g. Hydra Market) are folded "
               "into SANCTIONS undifferentiated by business type, same as every "
               "other designation.",
    "TERRORISM_FINANCING": "no evidence source available anywhere in this codebase "
                           "asserts a terrorism-financing finding.",
    "MONEY_LAUNDERING": "multi-hop movement is reachability, not a laundering "
                        "finding -- wallet_trace_report's own docstring refuses to "
                        "say 'layering' for the same reason.",
    "LAYERING": "same reason as MONEY_LAUNDERING: intermediate hops are "
               "intermediate hops, not an asserted typology. A future typology "
               "module may consume risk_features; this loop does not build it.",
    "CROSS_CHAIN": "real transaction-level cross-chain evidence exists since Loop 42/44 "
                  "(cross_chain_module.py) and is surfaced to an investigator via "
                  "crypto_investigation.cross_chain_events -- but a confirmed cross-chain "
                  "hop landing on a VASP-attributed address is exposure, exactly like a "
                  "same-chain hop (see VASP_EXPOSURE below): it must not score risk just "
                  "for crossing a chain boundary. The one case that WOULD be a genuine new "
                  "SANCTIONS signal -- a confirmed bridge/swap landing on a REGULATORY_"
                  "ATTESTED (OFAC) address on the destination chain -- needs a destination-"
                  "chain attribution lookup this loop does not build; DEFERRED rather than "
                  "half-implemented under time pressure against sanctions.flow_reach.v1's "
                  "own careful invariants.",
    "VASP_EXPOSURE": "VASP attribution is a reachability/attribution concept kept "
                     "deliberately separate from risk (global invariant: risk score "
                     "!= VASP attribution). An ordinary VASP relationship -- any "
                     "hop count, any attribution tier except REGULATORY_ATTESTED -- "
                     "is a lead for a disclosure request, not a risk signal, and "
                     "this policy assigns it no score regardless of how many "
                     "distinct VASPs a wallet reaches.",
}

# --- axes ------------------------------------------------------------------

WALLET, FLOW = "WALLET", "FLOW"
DIRECT_SIGNAL, CONTEXTUAL_SIGNAL = "DIRECT", "CONTEXTUAL"
REGULATORY_AUTHORITATIVE = "REGULATORY_AUTHORITATIVE"
CURATED_DISCLOSURE = "CURATED_DISCLOSURE"
THIRD_PARTY_ATTRIBUTION = "THIRD_PARTY_ATTRIBUTION"
# Declared for the taxonomy's completeness (source-strength must distinguish
# four tiers per the Loop 36 spec) but unused by any RULE below: nothing in
# this codebase currently produces a *behavioral* signal (e.g. "unusual
# transaction pattern") independent of a named third party's tag. Using it
# on a GraphSense tag would overstate what that source actually is.
CONTEXTUAL_BEHAVIORAL = "CONTEXTUAL_BEHAVIORAL"

INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
LOW, MODERATE, HIGH, CRITICAL = "LOW", "MODERATE", "HIGH", "CRITICAL"

# POLICY-DEFINED, not empirically calibrated (no labelled ground-truth corpus
# exists to fit this against -- same admission correlate.EXCHANGE_HOP_DECAY's
# own comment makes for its prior). A quartered 0-100 scale, chosen so the
# score audit test has round numbers to check by hand.
LEVEL_THRESHOLDS = ((25, LOW), (50, MODERATE), (75, HIGH), (101, CRITICAL))

# POLICY-DEFINED per-category ceiling: how much of the 0-100 scale one
# category can ever contribute, regardless of how many distinct facts it
# holds. Keeps a purely contextual wallet (mixer/DeFi tags only) below HIGH,
# and lets a single regulatory designation alone reach CRITICAL -- see each
# RULES entry's own "why" for the per-rule rationale these ceilings enforce.
CATEGORY_CAP: Dict[str, int] = {
    SANCTIONS: 90,
    FRAUD: 25,
    MIXING: 20,
    COINJOIN: 15,
    DEFI: 6,
    UNKNOWN: 8,
    # Loop 53: a fresh, uncalibrated signal source (no labelled corpus
    # backs these thresholds beyond typology.py's own documented policy
    # numbers) -- capped below MIXING so a wallet flagged only on
    # transaction-shape heuristics cannot alone reach HIGH.
    BEHAVIORAL: 15,
}

# --- rules -------------------------------------------------------------------
# Every numeric contribution in this module originates from exactly one row
# here. Add a category by adding a rule with a `why`, never by adding a
# number somewhere else.

RULES: Dict[str, dict] = {
    "sanctions.self_designation.v1": {
        "category": SANCTIONS, "dimension": WALLET, "signal_type": DIRECT_SIGNAL,
        "source_strength": REGULATORY_AUTHORITATIVE, "base": 80,
        "why": "A government (OFAC SDN) designation of this exact address is the "
               "strongest, most authoritative evidence class CyberTrace has -- the "
               "same source correlate.REGULATORY_ATTESTED ranks above every "
               "VASP-attribution source except an analyst's own citation. Fixed "
               "base, not scaled by hop count or repetition: a wallet cannot be "
               "'more designated', so one occurrence is the entire fact.",
    },
    "sanctions.flow_reach.v1": {
        "category": SANCTIONS, "dimension": FLOW, "signal_type": DIRECT_SIGNAL,
        "source_strength": REGULATORY_AUTHORITATIVE, "base": 40,
        "why": "Contact with an OFAC-designated entity -- via the wallet's own "
               "nearest-VASP path, or a self-attributed suspect's separate "
               "direct/secondary VASP relationship -- is direct evidence (the "
               "designation is authoritative), scaled by the SAME hop-decay "
               "confidence correlate.wallet_exchange_paths already computes "
               "(EXCHANGE_HOP_DECAY ** hops) rather than inventing a second decay "
               "model: a designation reached through several intermediary wallets "
               "is weaker evidence about THIS wallet than a direct deposit.",
    },
    "fraud.chainabuse.v1": {
        "category": FRAUD, "dimension": WALLET, "signal_type": DIRECT_SIGNAL,
        "source_strength": CURATED_DISCLOSURE, "base": 15,
        "why": "A Chainabuse scam report is a curated, named-source disclosure of "
               "an explicit fraud finding about this exact address -- direct "
               "evidence, but from a community-verification platform rather than a "
               "government, so it ranks below REGULATORY_AUTHORITATIVE. Fixed base "
               "for the underlying 'this address was reported' fact regardless of "
               "how many metadata fields cite it.",
    },
    "fraud.chainabuse.corroboration.v1": {
        "category": FRAUD, "dimension": WALLET, "signal_type": DIRECT_SIGNAL,
        "source_strength": CURATED_DISCLOSURE, "base": 2,
        "why": "Additional independent trusted reporters raise confidence in the "
               "SAME underlying finding fraud.chainabuse.v1 already scored -- not a "
               "second, independent fraud event. +2 per corroborating trusted "
               "report, capped at 5 reports (+10) so report volume alone cannot "
               "drive FRAUD to its ceiling without the base finding.",
    },
    "service.mixing.v1": {
        "category": MIXING, "dimension": FLOW, "signal_type": CONTEXTUAL_SIGNAL,
        "source_strength": THIRD_PARTY_ATTRIBUTION, "base": 12,
        "why": "A GraphSense mixing_service tag is a third party's public claim "
               "about one address on the path (exchange_tags.py's own documented "
               "boundary: 'never CyberTrace's own finding'), and mixer interaction "
               "alone is not proof of criminality (global invariant). Contextual, "
               "low base, low category ceiling -- structurally incapable alone of "
               "reaching HIGH.",
    },
    "service.coinjoin.v1": {
        "category": COINJOIN, "dimension": FLOW, "signal_type": CONTEXTUAL_SIGNAL,
        "source_strength": THIRD_PARTY_ATTRIBUTION, "base": 8,
        "why": "CoinJoin is a privacy technique with substantial legitimate use; "
               "weighted below a generic mixing_service tag for that reason. "
               "Contextual signal, never alone sufficient to leave LOW.",
    },
    "service.defi.v1": {
        "category": DEFI, "dimension": FLOW, "signal_type": CONTEXTUAL_SIGNAL,
        "source_strength": THIRD_PARTY_ATTRIBUTION, "base": 3,
        "why": "DeFi/DEX/lending interaction is ordinary financial activity for a "
               "large share of on-chain users (global invariant: DeFi != "
               "criminality by itself). Minimal weight: present for investigator "
               "visibility, not as a meaningful score driver.",
    },
    "dataset.illicit_classification.v1": {
        "category": UNKNOWN, "dimension": WALLET, "signal_type": CONTEXTUAL_SIGNAL,
        "source_strength": THIRD_PARTY_ATTRIBUTION, "base": 8,
        "why": "Elliptic++ (KDD'23) gives only a binary illicit/licit/unknown label "
               "with no stated typology, verification method, or license -- the "
               "weakest source this policy scores. Filed under UNKNOWN because the "
               "label itself claims no specific illicit category.",
    },
    # Loop 53: typology.py's own DETECTED signals -- the first rule in this
    # module to use CONTEXTUAL_BEHAVIORAL (declared unused since Loop 36).
    # WALLET dimension: these describe this address's OWN transaction shape,
    # not what its funds later touched. Anomaly != crime (typology.py's own
    # invariant): a behavioral shape is present-for-visibility, low base,
    # low category ceiling -- structurally incapable of reaching HIGH alone,
    # same discipline as service.mixing.v1.
    "behavior.fan_out.v1": {
        "category": BEHAVIORAL, "dimension": WALLET, "signal_type": CONTEXTUAL_SIGNAL,
        "source_strength": CONTEXTUAL_BEHAVIORAL, "base": 6,
        "why": "A high-fan-out transaction shape (typology.FAN_OUT) is consistent with "
               "several legitimate patterns (payroll, an exchange hot wallet, a mixer) as "
               "well as fund dispersal -- contextual signal only, never itself a finding.",
    },
    "behavior.rapid_forwarding.v1": {
        "category": BEHAVIORAL, "dimension": WALLET, "signal_type": CONTEXTUAL_SIGNAL,
        "source_strength": CONTEXTUAL_BEHAVIORAL, "base": 8,
        "why": "Funds received and forwarded onward within the hour (typology."
               "RAPID_FORWARDING) is a shape associated with pass-through wallets, but "
               "also ordinary custodial/hot-wallet operation -- weighted above a bare "
               "fan-out shape since the value-conservation match is more specific.",
    },
    "behavior.burst_activity.v1": {
        "category": BEHAVIORAL, "dimension": WALLET, "signal_type": CONTEXTUAL_SIGNAL,
        "source_strength": CONTEXTUAL_BEHAVIORAL, "base": 4,
        "why": "A transaction burst (typology.BURST_ACTIVITY) alone says only that "
               "activity clustered in time -- the weakest of the behavioral signals, "
               "present for visibility.",
    },
    "behavior.peel_chain_like.v1": {
        "category": BEHAVIORAL, "dimension": WALLET, "signal_type": CONTEXTUAL_SIGNAL,
        "source_strength": CONTEXTUAL_BEHAVIORAL, "base": 5,
        "why": "typology.PEEL_CHAIN_LIKE is itself a single-wallet PROXY for a genuinely "
               "multi-wallet pattern (see that module's own docstring) -- weighted low "
               "and structurally capped, reflecting that it is the weakest-grounded "
               "signal typology.py produces.",
    },
}

# typology.py signal name -> the risk.py rule it feeds, for DETECTED signals
# only (NOT_EVALUATED/absent signals contribute nothing -- see
# _extract_behavioral_features). Deliberately a small, named subset: not
# every typology signal is risk-worthy (HIGH_ACTIVITY/HIGH_VALUE/
# CONSOLIDATION/DISPERSAL/FAN_IN/DORMANT_TO_ACTIVE describe scale or
# direction, not a shape any rule here claims is risk-relevant).
_BEHAVIORAL_RULE = {
    "FAN_OUT": "behavior.fan_out.v1",
    "RAPID_FORWARDING": "behavior.rapid_forwarding.v1",
    "BURST_ACTIVITY": "behavior.burst_activity.v1",
    "PEEL_CHAIN_LIKE": "behavior.peel_chain_like.v1",
}

# category -> GraphSense service_tags category strings that map to it.
_SERVICE_RULE = {
    "mixing_service": "service.mixing.v1",
    "coinjoin": "service.coinjoin.v1",
    "defi": "service.defi.v1",
    "defi_dex": "service.defi.v1",
    "defi_lending": "service.defi.v1",
}


def _add_feature(features: Dict[tuple, dict], fact_key: tuple, **feature) -> None:
    """Register one underlying fact, deduplicated by `fact_key`.

    A fact seen twice (two metadata fields citing the same OFAC record, two
    tagpacks naming the same mixing address) is ONE feature: the stronger
    occurrence (higher raw_confidence) wins, never both.
    """
    existing = features.get(fact_key)
    if existing is None or feature.get("raw_confidence", 1.0) > existing.get("raw_confidence", 1.0):
        features[fact_key] = {"fact_key": fact_key, **feature}


def _extract_features(wallet_entity_id: str, wallet_address: str,
                      hit: Optional[dict], service_tags: List[dict],
                      metadata: dict, typology_signals: Optional[List[dict]] = None
                      ) -> Dict[tuple, dict]:
    """Every deduplicated risk-relevant fact this wallet's already-computed
    evidence supports. Reads only what callers already computed
    (wallet_exchange_paths' `hit`, `service_tags`, `store.metadata`, and --
    Loop 53, additive, optional -- `typology_signals`) -- no new traversal,
    no new integration call. `typology_signals` defaults to None so every
    existing caller (wallet_trace_report's own score_wallet_risk call) is
    byte-identical to before this loop.
    """
    from .correlate import REGULATORY_ATTESTED, EXCHANGE_HOP_DECAY

    features: Dict[tuple, dict] = {}

    # --- WALLET dimension: facts about this address's own identity ---------
    if hit and hit["hops"] == 0 and hit["attribution"] == REGULATORY_ATTESTED:
        _add_feature(
            features, ("SANCTIONS", "self", hit["attribution_source"]),
            rule_id="sanctions.self_designation.v1", entity_id=wallet_entity_id,
            address=wallet_address, evidence_ids=hit.get("evidence_ids") or [],
            attribution_source=hit["attribution_source"], raw_confidence=1.0,
            detail=f"this address is itself an OFAC SDN digital-currency-address "
                   f"record for {hit['exchange']}")

    if metadata.get("reported_scam"):
        cats = metadata.get("chainabuse_scam_categories") or []
        _add_feature(
            features, ("FRAUD", "self", wallet_entity_id),
            rule_id="fraud.chainabuse.v1", entity_id=wallet_entity_id,
            address=wallet_address, evidence_ids=[],
            attribution_source="Chainabuse scam report(s) recorded against this address",
            raw_confidence=1.0,
            detail="address has Chainabuse scam report(s)"
                   + (f" ({', '.join(cats)})" if cats else ""))
        count = min(int(metadata.get("chainabuse_trusted_report_count") or 0), 5)
        if count:
            _add_feature(
                features, ("FRAUD", "self", "corroboration", wallet_entity_id),
                rule_id="fraud.chainabuse.corroboration.v1", entity_id=wallet_entity_id,
                address=wallet_address, evidence_ids=[],
                attribution_source="Chainabuse trusted-reporter count",
                raw_confidence=count,  # carries the count for base*count in scoring
                detail=f"{count} independent Chainabuse trusted report(s) corroborate "
                       f"the same finding above")

    if metadata.get("ellipticpp_dataset_label_name") == "illicit":
        _add_feature(
            features, ("UNKNOWN", "ellipticpp", wallet_entity_id),
            rule_id="dataset.illicit_classification.v1", entity_id=wallet_entity_id,
            address=wallet_address, evidence_ids=[],
            attribution_source="Elliptic++ dataset (KDD'23 research corpus, license unstated)",
            raw_confidence=1.0,
            detail="Elliptic++ dataset classifies this address as illicit "
                   "(binary label, no stated typology)")

    # --- FLOW dimension: facts about what this address's funds touched -----
    if hit and hit["hops"] > 0 and hit["attribution"] == REGULATORY_ATTESTED:
        _add_feature(
            features, ("SANCTIONS", "flow", hit["attribution_source"]),
            rule_id="sanctions.flow_reach.v1", entity_id=wallet_entity_id,
            address=wallet_address, evidence_ids=hit.get("evidence_ids") or [],
            attribution_source=hit["attribution_source"], raw_confidence=hit["confidence"],
            detail=f"traced path reaches an OFAC-designated entity "
                   f"({hit['exchange']}) at {hit['hops']} hop(s), direction "
                   f"{hit['direction']}")

    if hit:
        for contact in (hit.get("direct_vasp_contacts") or []) + (hit.get("secondary_vasp_contacts") or []):
            if contact["attribution"] != REGULATORY_ATTESTED:
                continue
            hops = contact.get("hops", 1)
            _add_feature(
                features, ("SANCTIONS", "flow", contact["attribution_source"]),
                rule_id="sanctions.flow_reach.v1", entity_id=wallet_entity_id,
                address=wallet_address, evidence_ids=contact.get("evidence_ids") or [],
                attribution_source=contact["attribution_source"],
                raw_confidence=round(EXCHANGE_HOP_DECAY ** hops, 4),
                detail=f"this self-attributed wallet separately transacts with "
                       f"another OFAC-designated entity ({contact['exchange']}) at "
                       f"{hops} hop(s), direction {contact['direction']}")

    for tag in service_tags or []:
        rule_id = _SERVICE_RULE.get(tag["category"])
        if rule_id is None:
            continue
        rule = RULES[rule_id]
        # "hop" is present on _attach_wallet_service_intelligence's case-level
        # rows but not on wallet_trace_report's single-wallet service_tags
        # (see correlate.py -- the two call sites build this list differently
        # and only one numbers hops); tolerate its absence rather than assume
        # the richer shape.
        hop_phrase = f" at hop {tag['hop']}" if "hop" in tag else ""
        _add_feature(
            features, (rule["category"], tag["entity_id"], tag["category"]),
            rule_id=rule_id, entity_id=tag["entity_id"], address=tag["value"],
            evidence_ids=tag.get("evidence_ids") or [],
            attribution_source=tag["attribution_source"], raw_confidence=1.0,
            detail=f"transaction path intersects a GraphSense-tagged "
                   f"{tag['category']}{hop_phrase}: {tag['label']}")

    for signal in typology_signals or []:
        if signal.get("status") != "DETECTED":
            continue
        rule_id = _BEHAVIORAL_RULE.get(signal.get("signal"))
        if rule_id is None:
            continue
        # raw_confidence carries typology's own [0,1] confidence -- a real,
        # bounded number from that module's own policy, not invented here.
        _add_feature(
            features, ("BEHAVIORAL", wallet_entity_id, signal["signal"]),
            rule_id=rule_id, entity_id=wallet_entity_id, address=wallet_address,
            evidence_ids=[], attribution_source="typology.py",
            raw_confidence=signal.get("confidence") or 0.5,
            detail=f"typology signal {signal['signal']} ({signal.get('severity')}): "
                   f"{signal.get('explanation')}")

    return features


def _contribution(feature: dict) -> dict:
    # amount = base_amount * multiplier holds for every rule, always -- but
    # "multiplier" is a 0..1 confidence for every rule except
    # fraud.chainabuse.corroboration.v1, where raw_confidence deliberately
    # carries a raw report count (see that rule's own "+2 per report" `why`)
    # so it can exceed 1. A reader assuming multiplier<=1 would misread e.g.
    # multiplier: 3 there as a data error rather than "3 corroborating reports".
    rule = RULES[feature["rule_id"]]
    base = rule["base"]
    confidence = feature.get("raw_confidence", 1.0)
    amount = round(base * confidence)
    return {
        "rule_id": feature["rule_id"], "category": rule["category"],
        "dimension": rule["dimension"], "signal_type": rule["signal_type"],
        "source_strength": rule["source_strength"], "fact_key": feature["fact_key"],
        "base_amount": base, "multiplier": confidence, "amount": amount,
        "entity_id": feature.get("entity_id"), "address": feature.get("address"),
        "attribution_source": feature.get("attribution_source"),
        "evidence_ids": list(feature.get("evidence_ids") or []),
        "detail": feature.get("detail"), "why": rule["why"],
    }


def _score(contributions: List[dict]) -> dict:
    """Apply category ceilings, sum, clip to the 0-100 policy scale, and
    assign a level -- every clip recorded as its own adjustment line so the
    final number is always `raw_total - sum(adjustments)`, never a hidden
    subtraction. See tests/test_risk.py::test_final_score_audit.
    """
    by_category: Dict[str, List[dict]] = defaultdict(list)
    for c in contributions:
        by_category[c["category"]].append(c)

    kept: List[dict] = []
    adjustments: List[dict] = []
    raw_total = 0
    for category, items in by_category.items():
        cap = CATEGORY_CAP.get(category, 0)
        running = 0
        for c in sorted(items, key=lambda c: -c["amount"]):
            raw_total += c["amount"]
            room = max(cap - running, 0)
            applied = max(min(c["amount"], room), 0)
            running += applied
            kept.append({**c, "applied_amount": applied})
            if applied != c["amount"]:
                adjustments.append({
                    "category": category, "rule_id": c["rule_id"], "fact_key": c["fact_key"],
                    "clipped_from": c["amount"], "clipped_to": applied,
                    "reason": f"{category} category ceiling ({cap}) reached under "
                              f"policy {RISK_POLICY_VERSION}",
                })

    capped_total = sum(c["applied_amount"] for c in kept)
    score = min(capped_total, 100)
    if capped_total > 100:
        adjustments.append({
            "category": None, "rule_id": None, "fact_key": None,
            "clipped_from": capped_total, "clipped_to": 100,
            "reason": f"total score ceiling (100) reached under policy "
                      f"{RISK_POLICY_VERSION}",
        })

    level = INSUFFICIENT_EVIDENCE
    if kept:
        for ceiling, name in LEVEL_THRESHOLDS:
            if score < ceiling:
                level = name
                break

    return {
        "score": score if kept else None, "raw_total": raw_total, "level": level,
        "categories": sorted({c["category"] for c in kept}),
        "contributions": sorted(kept, key=lambda c: -c["applied_amount"]),
        "adjustments": adjustments,
    }


def _reasons(scored: dict) -> List[str]:
    """Human-readable explanation generated FROM `scored["contributions"]` --
    never a separately hardcoded string. See reconstruct_score for the
    machine-checkable version of the same claim.
    """
    lines = []
    for c in scored["contributions"]:
        sign = "+" if c["applied_amount"] >= 0 else ""
        lines.append(
            f"{sign}{c['applied_amount']} {c['category']} — {c['detail']} "
            f"(rule {c['rule_id']}, {c['signal_type'].lower()}, "
            f"source {c['source_strength']}) [{c['attribution_source']}]")
    for a in scored["adjustments"]:
        lines.append(f"adjustment: {a['clipped_from']} -> {a['clipped_to']} "
                     f"({a['reason']})")
    if scored["score"] is None:
        lines.append(
            "No qualifying risk evidence found under " + RISK_POLICY_VERSION +
            " (no OFAC designation, no fraud report, no GraphSense mixing/"
            "CoinJoin/DeFi tag, no third-party illicit-dataset classification). "
            "This is INSUFFICIENT_EVIDENCE, not a finding of low risk.")
    else:
        lines.append(f"Total: {scored['raw_total']} raw -> {scored['score']} "
                     f"(policy {RISK_POLICY_VERSION}) -> {scored['level']}")
    return lines


def _evidence(store, scored: dict) -> List[dict]:
    """Resolve every contribution's evidence_ids to checkable records via the
    SAME resolver every other claim in this codebase uses -- never a second
    resolver. Contributions whose evidence_ids is [] (OFAC/GraphSense/dataset
    citations) carry no observation rows by construction; their
    attribution_source string IS the citation, exactly like every other
    REGULATORY_ATTESTED/TAG_ATTESTED read in correlate.py.
    """
    from .correlate import evidence_chain
    out = []
    for c in scored["contributions"]:
        resolved = evidence_chain(store, c["evidence_ids"]) if c["evidence_ids"] else []
        out.append({"rule_id": c["rule_id"], "fact_key": c["fact_key"],
                    "attribution_source": c["attribution_source"], "resolved": resolved})
    return out


def _view(scored: dict) -> dict:
    return {
        "score": scored["score"], "level": scored["level"],
        "categories": scored["categories"],
        "contributions": scored["contributions"],
        "features": [c["fact_key"] for c in scored["contributions"]],
    }


def score_wallet_risk(store, wallet_entity_id: str, wallet_address: str,
                      hit: Optional[dict], service_tags: List[dict],
                      typology_signals: Optional[List[dict]] = None) -> dict:
    """The risk object for one traced wallet.

    `hit` is the wallet_exchange_paths() row for this wallet (may be None if
    it has no path to a VASP-attributed address). `service_tags` is the same
    list wallet_trace_report/_attach_wallet_risk already computed via
    correlate._path_service_tags -- passed in rather than recomputed, so this
    function issues no new GraphSense/OFAC query of its own.

    `typology_signals` (Loop 53, optional, default None) is
    `typology.typology_signals`'s own output for this wallet -- omitted by
    every pre-Loop-53 caller (wallet_trace_report's own call site), which
    keeps their result byte-identical to before this loop. Callers that want
    the BEHAVIORAL category (crypto_investigation.investigate_wallet) pass
    it explicitly.

    Returns risk_score/risk_level/risk_policy_version/risk_categories plus
    wallet_risk/flow_risk/overall_risk sub-views (see module docstring for
    why overall_risk is not their sum) and risk_evidence for lineage.
    """
    metadata = store.metadata(wallet_entity_id) if wallet_entity_id else {}
    features = _extract_features(wallet_entity_id, wallet_address, hit,
                                 service_tags, metadata, typology_signals)

    all_contribs = [_contribution(f) for f in features.values()]
    wallet_contribs = [c for c in all_contribs if c["dimension"] == WALLET]
    flow_contribs = [c for c in all_contribs if c["dimension"] == FLOW]

    overall = _score(all_contribs)
    wallet_scored = _score(wallet_contribs)
    flow_scored = _score(flow_contribs)

    return {
        "risk_policy_version": RISK_POLICY_VERSION,
        "risk_score": overall["score"],
        "risk_level": overall["level"],
        "risk_categories": overall["categories"],
        "risk_features": [c["fact_key"] for c in overall["contributions"]],
        "risk_contributions": overall["contributions"],
        "risk_reasons": _reasons(overall),
        "risk_evidence": _evidence(store, overall),
        "wallet_risk": _view(wallet_scored),
        "flow_risk": _view(flow_scored),
    }


def reconstruct_score(risk: dict) -> Optional[int]:
    """Recompute risk_score from risk_contributions alone, with no access to
    RULES or the original evidence -- the machine-checkable form of "can an
    investigator reconstruct this by hand". Used by the score-audit test;
    exported for any caller that wants to verify a stored/serialized risk
    object was not tampered with or hand-edited.
    """
    if not risk["risk_contributions"]:
        return None
    return min(sum(c["applied_amount"] for c in risk["risk_contributions"]), 100)
