"""Loop 48 -- VASP exposure vs. VASP control/ownership, as separate claims.
Loop 49 -- `investigate()`: the canonical, investigator-ready result built
on top of `classify()`, wired into production (`correlate.wallet_trace_
report`, `correlate.run_correlation`, `cli.py`, the Markdown/HTML dossiers,
the GUI Wallets tab). Moved here from `experiments/vasp_control_attribution/`
now that a real production consumer exists -- see docs/LOOP49.md; `classify()`
itself is byte-for-byte the same policy Loop 48 validated, untouched by the
move.

Not a new attribution algorithm. This module reads evidence that
`correlate.wallet_exchange_paths` / `correlate.unattributed_wallet_candidates`
(Loop 45/47's own production and rejected engines) already computed, and
answers a question neither of them states explicitly:

    "this wallet interacted with VASP X" (EXPOSURE)
        is not
    "this wallet is owned/controlled by VASP X" (CONTROL)

Both engines already carry the evidence needed to tell these apart --
`proximity` (AT_VASP / DIRECT / INDIRECT) and the 4-tier `attribution` axis
(ANALYST_ASSERTED / REGULATORY_ATTESTED / VASP_DISCLOSED / TAG_ATTESTED) are
already orthogonal to each other and to `risk.py`'s scoring (see docs/LOOP48.md
section 2 for the full audit). What is missing is a single place that states
the CONTROL/EXPOSURE boundary as an explicit, testable policy rather than
leaving a reader to infer it from `proximity` alone -- and one production
terminology fix (cli.py's "Nearest VASP: X" headline, now carrying proximity
on the same line) for the one place that audit found the boundary blurred.

Policy (the only new decision this module makes; see docs/LOOP48.md section 5
for why each line is drawn where it is):

    proximity == AT_VASP, attribution == VASP_DISCLOSED   -> CONTROL ESTABLISHED, HIGH
    proximity == AT_VASP, attribution == ANALYST_ASSERTED  -> CONTROL ESTABLISHED, MEDIUM
    proximity == AT_VASP, attribution == TAG_ATTESTED      -> CONTROL NOT_ESTABLISHED
                                                               (exposure only -- a
                                                               third-party guess is
                                                               not ownership evidence)
    proximity in (DIRECT, INDIRECT), any tier               -> CONTROL NOT_ESTABLISHED,
                                                               always (Invariants 1/2)
    attribution == REGULATORY_ATTESTED                      -> REGULATORY context only,
                                                               never VASP control or
                                                               exposure by itself
                                                               (Invariant 3)
    candidate-only evidence (attribution.vasp_candidates,
    no wallet_exchange_paths hit at all)                    -> CONTROL NOT_ESTABLISHED,
                                                               always -- attribution.py's
                                                               own ATTESTED status is
                                                               never assigned by that
                                                               module (see its own
                                                               vasp_candidates docstring)

No new query, no new graph traversal, no ML, no learned weight -- reuses the
exact `hit` (one `wallet_exchange_paths` row) and `candidate`
(`attribution.vasp_candidates` result) dicts a caller already has.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# Re-exported rather than re-declared: this module's whole point is that it
# never invents a competing vocabulary for what correlate.py/attribution.py
# already name precisely.
AT_VASP, DIRECT, INDIRECT = "AT_VASP", "DIRECT", "INDIRECT"
ANALYST_ASSERTED = "ANALYST_ASSERTED"
REGULATORY_ATTESTED = "REGULATORY_ATTESTED"
VASP_DISCLOSED = "VASP_DISCLOSED"
TAG_ATTESTED = "TAG_ATTESTED"

CONTROL_POLICY_VERSION = "vasp-control-v1"

ESTABLISHED = "ESTABLISHED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
CONTROL_UNKNOWN = "UNKNOWN"

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"

# Provenance catalogue (brief section 8), extended by exactly one tag
# (CANDIDATE_VASP_EXPOSURE) that the brief's own list did not anticipate:
# attribution.py's counterparty/cross-chain fingerprint signals are real
# exposure evidence but are not a graph hop count, so tagging them
# DIRECT_VASP_EXPOSURE or MULTI_HOP_VASP_EXPOSURE would misstate their origin.
DIRECT_VASP_EXPOSURE = "DIRECT_VASP_EXPOSURE"
MULTI_HOP_VASP_EXPOSURE = "MULTI_HOP_VASP_EXPOSURE"
CANDIDATE_VASP_EXPOSURE = "CANDIDATE_VASP_EXPOSURE"
TAG_ATTESTED_WEAK_SIGNAL = "TAG_ATTESTED_WEAK_SIGNAL"
VASP_DISCLOSED_CONTROL = "VASP_DISCLOSED_CONTROL"
INDEPENDENT_OWNERSHIP = "INDEPENDENT_OWNERSHIP"
REGULATORY_CONTEXT = "REGULATORY_ATTESTED"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

# Policy-defined bucketing of hop distance into an exposure-confidence label
# -- same "POLICY-DEFINED, not empirically calibrated" admission attribution.py
# and risk.py both already make for their own bucket boundaries; not fit to
# any benchmark, not tuned against section 11's numbers below.
_INDIRECT_HIGH_CONFIDENCE_MAX_HOPS = 1  # unreachable: DIRECT is always hops==1
_INDIRECT_MEDIUM_CONFIDENCE_MAX_HOPS = 2


def _exposure_confidence_for_hop(proximity: str, hops: int) -> str:
    if proximity == DIRECT:
        return HIGH
    return MEDIUM if hops <= _INDIRECT_MEDIUM_CONFIDENCE_MAX_HOPS else LOW


def _candidate(brand: str, evidence: List[str]) -> dict:
    return {"brand": brand, "evidence": evidence}


def _classify_at_vasp(hit: dict) -> dict:
    """hit['proximity'] == AT_VASP and hit['attribution'] != REGULATORY_ATTESTED
    -- the suspect address itself is one of the four attributed-address
    tiers. Genuinely different control strength per tier; see module
    docstring for why each line is drawn where it is."""
    brand, tier, source = hit["exchange"], hit["attribution"], hit["attribution_source"]
    if tier == VASP_DISCLOSED:
        return {
            "exposure_candidates": [brand], "exposure_confidence": HIGH,
            "exposure_evidence": [DIRECT_VASP_EXPOSURE],
            "control_candidates": [brand], "control_status": ESTABLISHED,
            "control_confidence": HIGH,
            "control_evidence": [f"{VASP_DISCLOSED_CONTROL}: {source}"],
        }
    if tier == ANALYST_ASSERTED:
        return {
            "exposure_candidates": [brand], "exposure_confidence": HIGH,
            "exposure_evidence": [DIRECT_VASP_EXPOSURE],
            "control_candidates": [brand], "control_status": ESTABLISHED,
            "control_confidence": MEDIUM,
            "control_evidence": [f"{INDEPENDENT_OWNERSHIP}: {source}"],
        }
    # TAG_ATTESTED: a third-party community tagpack guess that this exact
    # address is the VASP's -- real exposure evidence (the address itself
    # carries a public tag), but Loop 45's own audit found this corpus
    # contains mislabeled entries (etherscan-wordcloud-exchange: token
    # contracts tagged as exchanges), so a bare tag is never promoted to
    # control.
    return {
        "exposure_candidates": [brand], "exposure_confidence": LOW,
        "exposure_evidence": [TAG_ATTESTED_WEAK_SIGNAL],
        "control_candidates": [brand], "control_status": NOT_ESTABLISHED,
        "control_confidence": None,
        "control_evidence": [f"third-party tag only, not independently corroborated: {source}"],
    }


def _classify_reachability(hit: dict) -> dict:
    """hit['proximity'] in (DIRECT, INDIRECT) -- the suspect reached a VASP-
    attributed address through 1+ hops. Reachability, never control,
    regardless of tier or hop count (Invariants 1/2) -- this branch never
    returns ESTABLISHED under any input."""
    brand, hops, proximity = hit["exchange"], hit["hops"], hit["proximity"]
    tag = DIRECT_VASP_EXPOSURE if proximity == DIRECT else MULTI_HOP_VASP_EXPOSURE
    return {
        "exposure_candidates": [brand],
        "exposure_confidence": _exposure_confidence_for_hop(proximity, hops),
        "exposure_evidence": [tag],
        "control_candidates": [brand], "control_status": NOT_ESTABLISHED,
        "control_confidence": None,
        "control_evidence": [f"{hops}-hop reachability is not ownership evidence"],
    }


_SIGNAL_TAG = {
    "attribution.counterparty_overlap.v1": CANDIDATE_VASP_EXPOSURE,
    "attribution.cross_chain_corroboration.v1": CANDIDATE_VASP_EXPOSURE,
}


def _classify_candidate(candidate: dict) -> dict:
    """attribution.vasp_candidates() result for a wallet with no
    wallet_exchange_paths hit at all. Never ESTABLISHED: that module's own
    ATTESTED status is declared but never assigned (see its docstring) --
    this function enforces the same rule one layer up rather than trusting
    every future caller to remember it."""
    if candidate is None or candidate.get("primary_candidate") is None:
        return None
    brands = [candidate["primary_candidate"]] + [c["brand"] for c in candidate.get("also_attributed", [])]
    tags = sorted({_SIGNAL_TAG.get(s["rule_id"], CANDIDATE_VASP_EXPOSURE)
                  for s in candidate.get("supporting_signals", [])}) or [CANDIDATE_VASP_EXPOSURE]
    return {
        "exposure_candidates": brands, "exposure_confidence": candidate["strength"],
        "exposure_evidence": tags,
        "control_candidates": brands, "control_status": NOT_ESTABLISHED,
        "control_confidence": None,
        "control_evidence": ["counterparty/cross-chain correlation only, "
                             "never ownership -- attribution.py's own ATTESTED "
                             "status is never reached by this signal source"],
    }


def classify(hit: Optional[dict], candidate: Optional[dict] = None) -> dict:
    """The Loop 48 verdict for one wallet's relationship to a VASP.

    `hit` -- one `correlate.wallet_exchange_paths()` row for this wallet, or
    None if that function found nothing.
    `candidate` -- `attribution.vasp_candidates()`'s result for this wallet
    (only meaningful when `hit` is None; production's own
    `unattributed_wallet_candidates` never calls attribution.py for a wallet
    that already has a `hit`).

    Returns the section-18 shape: wallet-relationship fields plus a plain-
    English `verdict` sentence pair, never a single collapsed score.
    """
    regulatory_context = {"designated": False, "entity": None}
    exposure = {"exposure_candidates": [], "exposure_confidence": None, "exposure_evidence": []}
    control = {"control_candidates": [], "control_status": CONTROL_UNKNOWN,
              "control_confidence": None, "control_evidence": []}

    if hit is not None:
        if hit["attribution"] == REGULATORY_ATTESTED:
            regulatory_context = {"designated": True, "entity": hit["exchange"],
                                  "attribution_source": hit["attribution_source"]}
        elif hit["proximity"] == AT_VASP:
            result = _classify_at_vasp(hit)
            exposure = {k: result[k] for k in exposure}
            control = {k: result[k] for k in control}
            control["control_status"] = result["control_status"]
        else:
            result = _classify_reachability(hit)
            exposure = {k: result[k] for k in exposure}
            control = {k: result[k] for k in control}
            control["control_status"] = result["control_status"]

        # A secondary genuinely-different VASP the suspect also touches
        # (direct_vasp_contacts/secondary_vasp_contacts) -- each classified
        # by its OWN tier, never inheriting the primary row's. Ambiguity
        # (adversarial Test 3) is preserved as multiple exposure_candidates,
        # never collapsed to one.
        for contact in (hit.get("direct_vasp_contacts", []) + hit.get("secondary_vasp_contacts", [])):
            if contact["attribution"] == REGULATORY_ATTESTED:
                continue
            if contact["exchange"] not in exposure["exposure_candidates"]:
                contact_hops = contact.get("hops", 1)
                contact_proximity = DIRECT if contact_hops <= 1 else INDIRECT
                exposure["exposure_candidates"].append(contact["exchange"])
                exposure["exposure_evidence"].append(
                    MULTI_HOP_VASP_EXPOSURE if contact_hops > 1 else DIRECT_VASP_EXPOSURE)
                # None only when the PRIMARY hit carried no exposure of its
                # own (REGULATORY_ATTESTED on the suspect itself) -- a real
                # contact-only exposure finding must not surface with an
                # unset confidence (found live by this script's own ablation
                # report, population C: OFAC_POLYANIN's real Binance deposit).
                if exposure["exposure_confidence"] is None:
                    exposure["exposure_confidence"] = _exposure_confidence_for_hop(
                        contact_proximity, contact_hops)
                # A contact is, by construction, a peer of the suspect --
                # never the suspect's own address -- so it can never be an
                # AT_VASP self-attribution and can never establish control
                # (Invariants 1/2). This is the only place control_status
                # can still be CONTROL_UNKNOWN with real exposure evidence
                # already found (the primary hit was REGULATORY_ATTESTED, so
                # neither _classify_at_vasp nor _classify_reachability ran):
                # resolve it to NOT_ESTABLISHED rather than leave a real
                # exposure finding paired with an unresolved control field.
                if control["control_status"] == CONTROL_UNKNOWN:
                    control["control_status"] = NOT_ESTABLISHED
                    control["control_candidates"] = [contact["exchange"]]
                    control["control_evidence"] = [
                        "reachability through an OFAC-designated wallet is not ownership evidence"]

        if hit.get("also_attributed"):
            for extra in hit["also_attributed"]:
                if extra.get("attribution") == REGULATORY_ATTESTED and not regulatory_context["designated"]:
                    regulatory_context = {"designated": True, "entity": extra["exchange"],
                                          "attribution_source": extra.get("attribution_source")}
    elif candidate is not None:
        result = _classify_candidate(candidate)
        if result:
            exposure = {k: result[k] for k in exposure}
            control = {k: result[k] for k in control}
            control["control_status"] = result["control_status"]

    if not exposure["exposure_candidates"] and not regulatory_context["designated"]:
        exposure["exposure_evidence"] = [INSUFFICIENT_EVIDENCE]
        control["control_evidence"] = [INSUFFICIENT_EVIDENCE]

    provenance = sorted(set(exposure["exposure_evidence"]) | set(
        e.split(":")[0].strip() for e in control["control_evidence"]))
    if regulatory_context["designated"]:
        provenance.append(REGULATORY_CONTEXT)
    provenance = sorted(set(provenance))

    verdict = _verdict_sentence(exposure, control, regulatory_context)

    return {
        "policy_version": CONTROL_POLICY_VERSION,
        "exposure_candidates": exposure["exposure_candidates"],
        "exposure_confidence": exposure["exposure_confidence"],
        "exposure_evidence": exposure["exposure_evidence"],
        "control_candidates": control["control_candidates"],
        "control_status": control["control_status"],
        "control_confidence": control["control_confidence"],
        "control_evidence": control["control_evidence"],
        "regulatory_context": regulatory_context,
        "provenance": provenance,
        "verdict": verdict,
    }


def _verdict_sentence(exposure: dict, control: dict, regulatory: dict) -> str:
    parts = []
    if regulatory["designated"]:
        parts.append(f"Wallet is OFAC-designated ({regulatory['entity']}).")
    if exposure["exposure_candidates"]:
        names = ", ".join(exposure["exposure_candidates"])
        parts.append(f"Wallet has {exposure['exposure_confidence']} exposure to {names}.")
    else:
        parts.append("No VASP exposure evidence found.")
    if control["control_status"] == ESTABLISHED:
        names = ", ".join(control["control_candidates"])
        parts.append(f"Control/ownership by {names} IS established "
                     f"({control['control_confidence']} confidence).")
    elif exposure["exposure_candidates"]:
        parts.append("VASP control/ownership is NOT established.")
    return " ".join(parts)


# --- Loop 49: canonical, investigator-ready result -------------------------
# Wraps classify() (unchanged Loop 48 policy) into the single structure an
# investigator-facing surface (CLI/Markdown/HTML/GUI) actually renders --
# envelope fields only (status, primary/candidate VASPs, evidence,
# cross-chain corroboration, limitations), never a change to the exposure/
# control policy above. See docs/LOOP49.md.

INVESTIGATION_POLICY_VERSION = "vasp-investigation-v1"

STRONG_CANDIDATE = "STRONG_CANDIDATE"
WEAK_CANDIDATE = "WEAK_CANDIDATE"
AMBIGUOUS_NEEDS_REVIEW = "AMBIGUOUS_NEEDS_REVIEW"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

_CROSS_CHAIN_RULE = "attribution.cross_chain_corroboration.v1"


def _competing_hit_brands(hit: Optional[dict]) -> List[str]:
    """Real, non-regulatory `also_attributed` brands only -- a second OFAC
    profile sharing this address (e.g. SamSam ransomware, two designated
    parties, one BTC address) is a real regulatory conflict, never VASP-
    attribution ambiguity: OFAC is not a VASP source (Loop 45's own
    Invariant 3, enforced here exactly as `attribution._ground_truth_hit`
    enforces it for the candidate engine). `candidate['also_attributed']`
    needs no equivalent filter -- attribution.vasp_candidates() only ever
    builds brands through that same `_ground_truth_hit` filter, so it can
    never carry a regulatory entry, and classify() already folds it into
    exposure_candidates for that branch."""
    if not hit:
        return []
    return [e["exchange"] for e in (hit.get("also_attributed") or [])
           if e.get("attribution") != REGULATORY_ATTESTED]


def _status(exposure_candidates: List[str], exposure_confidence: Optional[str],
           ambiguous: bool) -> str:
    if not exposure_candidates:
        return INSUFFICIENT_EVIDENCE
    if ambiguous:
        return AMBIGUOUS_NEEDS_REVIEW
    return STRONG_CANDIDATE if exposure_confidence in (HIGH, MEDIUM) else WEAK_CANDIDATE


def _evidence_from_hit(store, hit: dict) -> List[dict]:
    """One evidence item per already-computed relationship on this hit --
    the primary endpoint, every direct/secondary VASP contact, and every
    competing same-address claim. No new query beyond resolving each item's
    own `evidence_ids` (correlate.evidence_chain -- the same resolver
    risk.py's own evidence lineage already uses); no manufactured identifier."""
    from .correlate import evidence_chain

    def _item(c: dict, proximity: Optional[str], hops: Optional[int],
             note: Optional[str] = None) -> dict:
        ids = c.get("evidence_ids") or []
        return {"brand": c["exchange"], "attribution_tier": c.get("attribution"),
               "attribution_source": c.get("attribution_source"),
               "proximity": proximity, "hops": hops, "note": note,
               "resolved_evidence": evidence_chain(store, ids) if ids else []}

    items = [_item(hit, hit["proximity"], hit["hops"])]
    for c in hit.get("direct_vasp_contacts", []):
        items.append(_item(c, DIRECT, c.get("hops", 1)))
    for c in hit.get("secondary_vasp_contacts", []):
        items.append(_item(c, INDIRECT, c.get("hops")))
    for c in hit.get("also_attributed", []):
        items.append(_item(c, hit["proximity"], hit["hops"],
                           note="competing claim on the same address"))
    return items


def _evidence_from_candidate(store, candidate: dict) -> List[dict]:
    """One evidence item per attribution.vasp_candidates() supporting signal
    -- that module's own per-brand dedup (_score_brand) already collapsed
    repeated peers/rules, so no further dedup happens here."""
    from .correlate import evidence_chain
    items = []
    for s in candidate.get("supporting_signals", []):
        ids = s.get("evidence_ids") or []
        items.append({"brand": s["brand"], "attribution_tier": s.get("attribution"),
                     "attribution_source": s.get("attribution_source"),
                     "proximity": None, "hops": None, "note": s.get("detail"),
                     "resolved_evidence": evidence_chain(store, ids) if ids else []})
    return items


def _cross_chain_evidence(candidate: Optional[dict]) -> List[dict]:
    """Real bridge/swap corroboration only (attribution.py's own
    cross_chain_corroboration.v1 rule), deduplicated by the underlying
    (chain, address, reference) triple -- aggregation, never inflation.
    Empty for hit-based (already-reachable) wallets: attribution.py's
    cross-chain check is scoped to wallets wallet_exchange_paths found
    nothing for at all (see that module's own docstring); computing an
    equivalent for an already-attributed wallet would be new scope this
    loop does not add."""
    if not candidate:
        return []
    seen, out = set(), []
    for s in candidate.get("supporting_signals", []):
        if s.get("rule_id") != _CROSS_CHAIN_RULE:
            continue
        key = (s.get("peer_chain"), s.get("peer_address"), s.get("evidence_ref"))
        if key in seen:
            continue
        seen.add(key)
        out.append({"brand": s["brand"], "chain": s.get("peer_chain"),
                   "address": s.get("peer_address"), "mechanism": s.get("mechanism"),
                   "evidence_ref": s.get("evidence_ref")})
    return out


def _limitations(result: dict, ambiguous: bool) -> List[str]:
    """Fixed, deterministic caveats restating invariants this codebase
    already enforces elsewhere (Invariants 1-3, see module docstring) --
    never a new policy decision."""
    out = []
    if result["exposure_candidates"] and result["control_status"] != ESTABLISHED:
        out.append("Exposure evidence establishes a transaction relationship; "
                   "it does not by itself establish wallet ownership or control.")
    if result["regulatory_context"]["designated"]:
        out.append("A regulatory (OFAC) designation is a government determination, "
                   "not a VASP-attribution or ownership claim.")
    if ambiguous:
        out.append("Multiple independently-sourced attribution claims exist for this "
                   "wallet or address; treat the primary candidate as provisional "
                   "pending investigator review.")
    if not result["exposure_candidates"] and not result["regulatory_context"]["designated"]:
        out.append("No qualifying VASP exposure evidence was found -- this is "
                   "insufficient evidence, not a finding of no relationship.")
    return out


def investigate(store, wallet_address: str, chain: Optional[str],
                hit: Optional[dict] = None, candidate: Optional[dict] = None) -> dict:
    """The canonical VASP investigation result for one wallet (Loop 49).

    Wraps `classify(hit, candidate)` -- exposure/control/regulatory/
    provenance/verdict, unchanged -- with the envelope an investigator-facing
    surface actually renders: which VASP is primary, whether that identity is
    itself contested, the underlying evidence (deduplicated, provenance-
    tagged), and the plain-English limitations `verdict` alone does not spell
    out.

    `hit` is one `correlate.wallet_exchange_paths()` row; `candidate` is one
    `attribution.vasp_candidates()` result -- exactly the two inputs
    `classify` itself takes, already computed by every caller
    (`correlate.wallet_trace_report`, `correlate.run_correlation`'s
    `_attach_vasp_investigation*`). No new query, no new graph traversal, no
    change to Loop 45/47/48's own policy.
    """
    result = classify(hit, candidate)
    competing = _competing_hit_brands(hit)
    ambiguous = bool(competing) or bool(candidate and candidate.get("also_attributed"))

    candidates = list(result["exposure_candidates"])
    for brand in competing:
        if brand not in candidates:
            candidates.append(brand)

    if hit is not None:
        evidence = _evidence_from_hit(store, hit)
    elif candidate is not None:
        evidence = _evidence_from_candidate(store, candidate)
    else:
        evidence = []

    return {
        "policy_version": INVESTIGATION_POLICY_VERSION,
        "wallet": wallet_address,
        "chain": chain,
        "status": _status(result["exposure_candidates"], result["exposure_confidence"], ambiguous),
        "primary_vasp": candidates[0] if candidates else None,
        "candidate_vasps": candidates[1:],
        "confidence": result["exposure_confidence"],
        "relationship_type": "EXPOSURE" if candidates else None,
        "proximity": hit["proximity"] if hit else None,
        "hops": hit["hops"] if hit else None,
        "attribution_tier": hit["attribution"] if hit else None,
        "evidence": evidence,
        "cross_chain_evidence": _cross_chain_evidence(candidate),
        "regulatory_context": result["regulatory_context"],
        "control_status": result["control_status"],
        "control_confidence": result["control_confidence"],
        "control_evidence": result["control_evidence"],
        "limitations": _limitations(result, ambiguous),
        "provenance": result["provenance"],
        "verdict": result["verdict"],
    }


# --- Loop 50: case-level VASP relationship aggregation ---------------------
# Groups the wallet-level investigate() result already attached to every
# wallet_exchange_paths()/unattributed_wallet_candidates() row (Loop 49, see
# correlate._attach_vasp_investigation*) by VASP brand name. Not a new
# attribution algorithm: no new query, no new graph traversal, no wallet-to-
# wallet correlation. Shared VASP exposure is a fact about a VASP, never
# evidence that two wallets share an owner -- see docs/LOOP50.md.

RELATIONSHIP_POLICY_VERSION = "vasp-relationships-v1"

DIRECT_EXPOSURE = "DIRECT_EXPOSURE"
INDIRECT_EXPOSURE = "INDIRECT_EXPOSURE"
CANDIDATE_EXPOSURE = "CANDIDATE_EXPOSURE"


def _relationship_type(proximity: Optional[str]) -> str:
    if proximity in (AT_VASP, DIRECT):
        return DIRECT_EXPOSURE
    if proximity == INDIRECT:
        return INDIRECT_EXPOSURE
    return CANDIDATE_EXPOSURE  # no graph hop at all -- attribution.py's own fingerprint signal


def _wallet_vasp_relationships(vi: Optional[dict]) -> List[dict]:
    """One record per (wallet, VASP-brand) pair already named in an
    investigate() result -- pure reshaping of vi['evidence']/primary_vasp/
    candidate_vasps, no new query, no new evidence.

    Control can only ever attach to the primary brand (index 0):
    candidate_vasps are, by construction, secondary contacts -- a peer of the
    suspect wallet, never its own address (see classify()'s own comment on
    direct_vasp_contacts/secondary_vasp_contacts) -- so they can never be an
    AT_VASP self-attribution and can never establish control.
    """
    if not vi or not vi.get("primary_vasp"):
        return []
    proximity_by_brand: Dict[str, Optional[str]] = {}
    evidence_by_brand: Dict[str, List[dict]] = {}
    for item in vi.get("evidence", []):
        brand = item["brand"]
        evidence_by_brand.setdefault(brand, []).append(item)
        proximity_by_brand.setdefault(brand, item.get("proximity"))

    brands = [vi["primary_vasp"], *vi.get("candidate_vasps", [])]
    out = []
    for i, brand in enumerate(brands):
        brand_evidence = evidence_by_brand.get(brand, [])
        out.append({
            "vasp": brand,
            "relationship_type": _relationship_type(proximity_by_brand.get(brand)),
            "exposure_confidence": vi.get("confidence"),
            "proximity": proximity_by_brand.get(brand),
            "hops": brand_evidence[0].get("hops") if brand_evidence else None,
            "attribution_tier": brand_evidence[0].get("attribution_tier") if brand_evidence else None,
            "control_status": vi["control_status"] if i == 0 else NOT_ESTABLISHED,
            "control_confidence": vi.get("control_confidence") if i == 0 else None,
            "regulatory_context": vi.get("regulatory_context"),
            "evidence": brand_evidence,
            "provenance": vi.get("provenance"),
        })
    return out


def aggregate_vasp_relationships(wallet_paths: List[dict],
                                 candidate_wallets: List[dict]) -> List[dict]:
    """Loop 50: the case-level VASP relationship view.

    Groups every traced wallet's own investigate() result (already attached
    by correlate._attach_vasp_investigation / _attach_vasp_investigation_
    candidates) by VASP brand name. Reads no wallet-to-wallet edge and no
    clustering/correlation signal, so it structurally cannot turn "wallet A
    and wallet B both reached Binance" into "A and B are the same actor" --
    the output is keyed by (VASP, wallet) pairs, never by a merged identity.

    Per-wallet detail (relationship type, exposure confidence, control,
    regulatory context, evidence) is preserved in full inside each VASP's
    `wallets` list -- never collapsed into a single score.
    """
    by_vasp: Dict[str, list] = {}
    for w in list(wallet_paths) + list(candidate_wallets):
        for rel in _wallet_vasp_relationships(w.get("vasp_investigation")):
            by_vasp.setdefault(rel["vasp"], []).append({
                "wallet": w["value"], "chain": w["chain"], "entity_id": w["entity_id"],
                **{k: v for k, v in rel.items() if k != "vasp"},
            })

    relationships = []
    for vasp in sorted(by_vasp):
        wallets = by_vasp[vasp]
        relationships.append({
            "policy_version": RELATIONSHIP_POLICY_VERSION,
            "vasp": vasp,
            "wallet_count": len(wallets),
            "direct_exposure_count": sum(1 for w in wallets if w["relationship_type"] == DIRECT_EXPOSURE),
            "indirect_exposure_count": sum(1 for w in wallets if w["relationship_type"] == INDIRECT_EXPOSURE),
            "candidate_exposure_count": sum(1 for w in wallets if w["relationship_type"] == CANDIDATE_EXPOSURE),
            "control_established_count": sum(1 for w in wallets if w["control_status"] == ESTABLISHED),
            "wallets": wallets,
        })
    return relationships


def demo() -> None:
    """Runnable self-check -- Occam's mandatory smallest-thing-that-fails
    check for a branch-heavy classification function. Not the full
    negative-control suite (that lives in test_vasp_control_attribution.py,
    real-corpus-backed); this is the fast, dependency-free sanity pass."""
    # Case A: direct interaction, TAG_ATTESTED (exposure only)
    hit = {"exchange": "Binance", "attribution": TAG_ATTESTED, "attribution_source": "tag",
          "proximity": DIRECT, "hops": 1, "direct_vasp_contacts": [], "secondary_vasp_contacts": []}
    r = classify(hit)
    assert r["control_status"] == NOT_ESTABLISHED
    assert r["exposure_candidates"] == ["Binance"]

    # Case C: explicit VASP_DISCLOSED ownership evidence
    hit = {"exchange": "Binance", "attribution": VASP_DISCLOSED, "attribution_source": "self-disclosure",
          "proximity": AT_VASP, "hops": 0, "direct_vasp_contacts": [], "secondary_vasp_contacts": []}
    r = classify(hit)
    assert r["control_status"] == ESTABLISHED and r["control_confidence"] == HIGH

    # Case D: OFAC -> exposure to a VASP, control never established
    hit = {"exchange": "SUEX OTC S.R.O.", "attribution": REGULATORY_ATTESTED,
          "attribution_source": "OFAC SDN", "proximity": AT_VASP, "hops": 0,
          "direct_vasp_contacts": [{"exchange": "Binance", "attribution": TAG_ATTESTED,
                                    "attribution_source": "tag", "hops": 1}],
          "secondary_vasp_contacts": []}
    r = classify(hit)
    assert r["regulatory_context"]["designated"] is True
    assert "Binance" in r["exposure_candidates"]
    assert r["control_status"] == NOT_ESTABLISHED

    # No evidence at all
    r = classify(None, None)
    assert r["exposure_evidence"] == [INSUFFICIENT_EVIDENCE]
    assert r["control_status"] == CONTROL_UNKNOWN

    # Loop 49: investigate() -- same cases, through the canonical envelope.
    vi = investigate(None, "3BitMEXReserve...", "BTC_ADDRESS", hit={
        "exchange": "Binance", "attribution": VASP_DISCLOSED,
        "attribution_source": "Binance self-disclosure (hot wallet): binance.com",
        "proximity": AT_VASP, "hops": 0, "direct_vasp_contacts": [],
        "secondary_vasp_contacts": [], "also_attributed": []})
    assert vi["primary_vasp"] == "Binance" and vi["status"] == STRONG_CANDIDATE
    assert vi["control_status"] == ESTABLISHED

    vi = investigate(None, "1Customer...", "BTC_ADDRESS", hit={
        "exchange": "Binance", "attribution": TAG_ATTESTED, "attribution_source": "tag",
        "proximity": DIRECT, "hops": 1, "direct_vasp_contacts": [],
        "secondary_vasp_contacts": [], "also_attributed": []})
    assert vi["status"] == STRONG_CANDIDATE and vi["control_status"] == NOT_ESTABLISHED

    vi = investigate(None, "1Nothing...", "BTC_ADDRESS")
    assert vi["status"] == INSUFFICIENT_EVIDENCE and vi["primary_vasp"] is None

    # Two OFAC profiles sharing an address: a real regulatory conflict, never
    # VASP-attribution ambiguity (OFAC is not a VASP source).
    vi = investigate(None, "1SharedOfacAddr...", "BTC_ADDRESS", hit={
        "exchange": "SamSam Group A", "attribution": REGULATORY_ATTESTED,
        "attribution_source": "OFAC SDN", "proximity": AT_VASP, "hops": 0,
        "direct_vasp_contacts": [], "secondary_vasp_contacts": [],
        "also_attributed": [{"exchange": "SamSam Group B", "attribution": REGULATORY_ATTESTED,
                             "attribution_source": "OFAC SDN", "evidence_ids": []}]})
    assert vi["status"] == INSUFFICIENT_EVIDENCE and vi["candidate_vasps"] == []

    # Two analysts naming different VASPs on the same address: real
    # VASP-attribution ambiguity, preserved rather than picking a winner.
    vi = investigate(None, "1SharedAnalystAddr...", "BTC_ADDRESS", hit={
        "exchange": "Binance", "attribution": ANALYST_ASSERTED, "attribution_source": "analyst A",
        "proximity": AT_VASP, "hops": 0, "direct_vasp_contacts": [],
        "secondary_vasp_contacts": [],
        "also_attributed": [{"exchange": "Kraken", "attribution": ANALYST_ASSERTED,
                             "attribution_source": "analyst B", "evidence_ids": []}]})
    assert vi["status"] == AMBIGUOUS_NEEDS_REVIEW
    assert set([vi["primary_vasp"]] + vi["candidate_vasps"]) == {"Binance", "Kraken"}

    # Loop 50: two unrelated wallets both reaching Binance never becomes one
    # merged wallet-to-wallet claim, and direct/indirect stay distinguishable.
    vi_a = investigate(None, "1DirectA...", "BTC_ADDRESS", hit={
        "exchange": "Binance", "attribution": TAG_ATTESTED, "attribution_source": "tag",
        "proximity": DIRECT, "hops": 1, "direct_vasp_contacts": [],
        "secondary_vasp_contacts": [], "also_attributed": []})
    vi_b = investigate(None, "1IndirectB...", "BTC_ADDRESS", hit={
        "exchange": "Binance", "attribution": TAG_ATTESTED, "attribution_source": "tag",
        "proximity": INDIRECT, "hops": 2, "direct_vasp_contacts": [],
        "secondary_vasp_contacts": [], "also_attributed": []})
    a_row = {"value": "1DirectA...", "chain": "BTC_ADDRESS", "entity_id": "a", "vasp_investigation": vi_a}
    b_row = {"value": "1IndirectB...", "chain": "BTC_ADDRESS", "entity_id": "b", "vasp_investigation": vi_b}
    rels = aggregate_vasp_relationships([a_row, b_row], [])
    assert len(rels) == 1 and rels[0]["vasp"] == "Binance"
    assert rels[0]["wallet_count"] == 2
    assert rels[0]["direct_exposure_count"] == 1 and rels[0]["indirect_exposure_count"] == 1
    assert rels[0]["control_established_count"] == 0
    wallet_ids = {w["entity_id"] for w in rels[0]["wallets"]}
    assert wallet_ids == {"a", "b"}, "shared VASP exposure must list distinct wallets, never merge them"
    assert not any("same_actor" in w or "common_owner" in w for w in rels[0]["wallets"])
    assert aggregate_vasp_relationships([], []) == []

    print("vasp_investigation.demo(): all assertions passed")


if __name__ == "__main__":
    demo()
