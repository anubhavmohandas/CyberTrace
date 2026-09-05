"""Deterministic bounded multi-hop VASP evidence engine (Loop 47) --
REJECTED, Decision C. See docs/LOOP47.md for the full benchmark and
reasoning; experiments/multi_hop_attribution/README.md for why this lives
here and not in cybertrace/. Production attribution is still solely
`cybertrace/attribution.py` (Loop 45) -- this module is not imported by any
of it, the CLI, or the GUI.

Loop 45's `attribution.vasp_candidates` answers "what does this wallet's
DIRECT (1-hop) counterparty/cross-chain evidence say" for a wallet with no
graph path of its own to a VASP-attributed address. Loop 46 tried an ML/
similarity engine as a second opinion and it was rejected (Decision C,
docs/LOOP46.md, experiments/ml_attribution/) -- too many false positives for
one over-represented brand.

Loop 47 asks a narrower, still-deterministic question: does looking past
hop 1 -- suspect -> intermediary -> ... -> known VASP address, bounded and
explainable -- find real evidence `attribution.py` cannot see today?

**This is not filling a gap `wallet_exchange_paths` already closes.**
`correlate.wallet_exchange_paths`/`unattributed_wallet_candidates` already
run a bounded (max_hops=4 in production) BFS that dead-ends at any
VASP-attributed node, so a wallet that ever reaches this module's intended
caller (`tools/eval_attribution.py --live`'s MASKED benchmark, or a future
`unattributed_wallet_candidates`-style caller) has, by that same production
bound, no path of length <=4 to any VASP node in the UNMASKED graph. What
*is* still unexplored: `tools/eval_attribution.py`'s masked benchmark hides
one address's own ground truth and its whole cospend cluster, then calls
`attribution.vasp_candidates` with only that wallet's 1-hop `peers` -- a
2- or 3-hop path to a DIFFERENT surviving address of the same brand is
never looked for at all. That is this module's actual target, not "wallets
production has already given up on."

**Reuses `correlate`'s graph, does not rebuild one.** Traversal reads
`correlate._adjacency`'s existing undirected+flow adjacency dict and
`correlate._vasp_endpoints`'s existing endpoint knowledge -- the exact same
inputs `_secondary_vasp_reach`/`wallet_exchange_paths` already read. No new
store query, no second graph representation.

**Shortest-path BFS, not all-simple-paths enumeration.** Like
`_secondary_vasp_reach`, this keeps ONE global `visited` set across the
whole traversal (not per-path), so each reachable node is arrived at via
exactly one shortest path -- the same choice `_secondary_vasp_reach`/
`wallet_exchange_paths` already made, for the same reason section 7 of the
Loop 47 brief gives: unbounded path enumeration on a real transaction graph
is combinatorial, not merely large. Consequence: "multiple independent
paths to VASP X" in this module's output means multiple *distinct*
VASP-attributed addresses of brand X, each reached via its own shortest
path -- not the same address reached two different ways.

**OFAC is never a reachable endpoint.** `correlate._vasp_endpoints` returns
REGULATORY_ATTESTED (OFAC) entries in the same dict as real VASP tiers;
`_vasp_only_endpoints` below drops them before traversal ever starts, so a
suspect three hops from a sanctioned address cannot even be discovered by
this engine, let alone scored -- same structural exclusion as
`attribution._ground_truth_hit`.

**Independence and hub-dependence are evidence-shape facts, not scoring
tweaks.** Two paths to the same brand that share an intermediate node are
not two confirmations (section 12) -- only disjoint-intermediate-node paths
stack in `_score_brand`; a shared-node path is kept in `contributions` for
explainability with `applied_amount=0`. A node whose own adjacency degree
exceeds `_HUB_DEGREE_THRESHOLD` (an omnibus/hot-wallet/mixer shape) gets its
path's contribution discounted by `_HUB_PENALTY_FACTOR` and flagged
`hub_dependent` -- section 13's shared-service problem.

**No opaque score.** Same discipline as `risk.py`/`attribution.py`: every
contribution traces to one `RULES` entry with a `why`; the summed number is
an internal bucketing device that never leaves this module as a percentage
or confidence. Output strength is HIGH/MEDIUM/LOW; output verdict is
PRIMARY/AMBIGUOUS/INSUFFICIENT_EVIDENCE (section 14) -- never a forced
guess when evidence is thin or ambiguous.

No ML, no learned weights, no `ML_INFERENCE` tier -- Loop 46 already closed
that door. Every path this module reports is a real, cited transaction
chain in the evidence store.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

MULTI_HOP_POLICY_VERSION = "multi-hop-attribution-v1"

# Configurable, not hard-coded per call site (Loop 47 brief section 7) --
# every caller (engine, benchmark, tests) reads this one default.
MAX_HOPS_DEFAULT = 3
# Refused outright above this, regardless of what a caller passes -- section
# 25's "maximum hop depth enforced" as a hard floor under the configurable
# default, not just a convention callers could bypass by mistake.
MAX_HOPS_HARD_CEILING = 6

# occam: global explored-node budget, not per-account/per-hop-level -- a
# single-wallet traversal on this codebase's real graphs (largest observed
# hub: 1.19M-tx BitMEX/Binance hot wallet) stays orders of magnitude under
# this in practice; raise it if a real case legitimately needs more before
# assuming the bound is wrong. Recorded on the result as `truncated` rather
# than silently returning a partial answer.
_MAX_NODES_EXPLORED = 20_000

# An intermediate wallet this well-connected is exchange/mixer/omnibus
# infrastructure shaped, not a personal relationship -- POLICY-DEFINED, same
# admission as attribution.py's own RULES ("no labelled corpus exists to fit
# this against yet"). Applied only to nodes STRICTLY BETWEEN suspect and
# VASP endpoint, never to the endpoint itself (a VASP's own hot wallet is
# supposed to have high degree; that is not this problem).
_HUB_DEGREE_THRESHOLD = 25
_HUB_PENALTY_FACTOR = 0.3

VERDICT_PRIMARY = "PRIMARY"
VERDICT_AMBIGUOUS = "AMBIGUOUS"
VERDICT_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

MULTI_HOP_INFERENCE = "MULTI_HOP_INFERENCE"  # provenance tag, section 15 --
# never CONFIRMED/ATTESTED: an N-hop chain of real transactions corroborated
# by a known VASP endpoint, not a direct relationship or a VASP's own claim.

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"

# base(hop) = round(30 * HOP_DECAY**(hop-1)) -- 30 at hop 1 matches
# attribution.py's own counterparty_overlap.v1 base (a 1-hop multi-hop path
# IS a direct counterparty relationship; this module is only ever the
# authority for hop>=2 in production, but scores hop 1 the same way for a
# coherent ablation baseline). HOP_DECAY reuses correlate.EXCHANGE_HOP_DECAY
# rather than a second decay constant -- one prior for "how much does
# distance discount evidence" across the codebase.
def _hop_base(hop: int) -> int:
    from cybertrace.correlate import EXCHANGE_HOP_DECAY
    return round(30 * (EXCHANGE_HOP_DECAY ** (hop - 1)))


def _rule_id(hop: int) -> str:
    return f"multi_hop.path_{hop}hop.v1"


def _rules_for(max_hops: int) -> Dict[str, dict]:
    """RULES table generated for hops 1..max_hops -- same greppable
    rule_id/base/why shape as attribution.RULES, generated rather than
    hand-enumerated so MAX_HOPS_HARD_CEILING doesn't require six near-
    duplicate dict entries kept in sync by hand."""
    return {
        _rule_id(hop): {
            "hop": hop, "base": _hop_base(hop),
            "why": f"A real {hop}-hop chain of transactions (TRANSACTED_WITH/"
                   f"SENT_FUNDS_TO/PART_OF_CLUSTER) connects this wallet to an "
                   f"address independently attributed to this brand. Weighted "
                   f"at {_hop_base(hop)}/30 of a direct (1-hop) counterparty "
                   f"touch -- correlate.EXCHANGE_HOP_DECAY's own hop-decay "
                   f"prior, reused rather than a second one invented here.",
        }
        for hop in range(1, max_hops + 1)
    }


# Per-brand ceiling on summed independent-path contributions -- same
# omnibus-guard reasoning as attribution._SIGNAL_CAP: sheer path COUNT must
# not manufacture HIGH by itself.
_BRAND_SCORE_CAP = 70

_STRENGTH_THRESHOLDS = ((30, LOW), (70, MEDIUM), (None, HIGH))

# PRIMARY requires the top brand to clear the runner-up by both a relative
# margin and an absolute floor -- close scores (within margin) are AMBIGUOUS
# rather than a coin-flip primary (section 14: "must not guess simply
# because one candidate has a marginal numerical advantage").
_PRIMARY_MARGIN_RATIO = 1.5
_PRIMARY_MARGIN_ABS = 10


def _tier_multiplier(attribution_tier: str) -> float:
    """Reuses attribution.py's own TAG_ATTESTED discount -- one definition of
    "how much do we trust a third-party tagpack vs. a VASP's own disclosure"
    across both attribution engines, not two that could silently disagree."""
    from cybertrace.attribution import _tier_multiplier as _shared
    return _shared(attribution_tier)


def _vasp_only_endpoints(exchange_of: Dict[str, dict]) -> Dict[str, dict]:
    """`exchange_of` with every REGULATORY_ATTESTED (OFAC) entry dropped --
    same structural exclusion as attribution._ground_truth_hit, applied once
    here rather than per-hit so a traversal can never even discover an OFAC
    node as a destination (section: "OFAC structurally excluded")."""
    from cybertrace.correlate import REGULATORY_ATTESTED
    return {eid: hit for eid, hit in exchange_of.items()
            if hit["attribution"] != REGULATORY_ATTESTED}


def multi_hop_paths(adjacency: Dict[str, Dict[str, tuple]], exchange_of: Dict[str, dict],
                    start: str, max_hops: int = MAX_HOPS_DEFAULT) -> Dict[str, object]:
    """Every VASP-attributed address reachable from `start` within
    `max_hops`, one shortest path each, dead-ending traversal at any
    VASP-attributed node (never walking through one) -- the same rule
    `_secondary_vasp_reach` uses, generalized to keep every brand's every
    reachable address instead of only the nearest occurrence per brand.

    Returns {"paths": [ {vasp, entity_id, attribution, attribution_source,
    hops, path, intermediate_nodes, direction, hub_dependent, evidence_ids},
    ... ], "truncated": bool, "nodes_explored": int}.

    `path` is the full entity_id chain [start, ..., vasp_entity_id];
    `intermediate_nodes` is `path[1:-1]` -- the wallets strictly between
    suspect and VASP endpoint, exposed separately because independence/hub
    scoring both key off exactly this set, and re-slicing `path` at two call
    sites risked disagreeing about which end is which.
    """
    max_hops = min(max(1, max_hops), MAX_HOPS_HARD_CEILING)
    vasp_endpoints = _vasp_only_endpoints(exchange_of)

    paths: List[dict] = []
    visited = {start}
    frontier = [(start, [start], [])]
    nodes_explored = 1
    truncated = False

    for hop in range(1, max_hops + 1):
        next_frontier = []
        for node, path, ev_ids in frontier:
            for peer, (hop_obs, flows) in sorted(adjacency.get(node, {}).items()):
                if peer in visited:
                    continue
                if nodes_explored >= _MAX_NODES_EXPLORED:
                    truncated = True
                    break
                visited.add(peer)
                nodes_explored += 1
                new_path = path + [peer]
                new_ev = ev_ids + list(hop_obs)
                hit = vasp_endpoints.get(peer)
                if hit is not None:
                    intermediates = new_path[1:-1]
                    hub_dependent = any(
                        len(adjacency.get(n, {})) > _HUB_DEGREE_THRESHOLD
                        for n in intermediates)
                    from cybertrace.correlate import _direction
                    paths.append({
                        "vasp": hit["exchange"], "entity_id": peer,
                        "attribution": hit["attribution"],
                        "attribution_source": hit["attribution_source"],
                        "hops": hop, "path": new_path,
                        "intermediate_nodes": intermediates,
                        "direction": _direction(flows),
                        "hub_dependent": hub_dependent,
                        "evidence_ids": new_ev + list(hit.get("evidence_ids") or []),
                    })
                    continue  # dead end -- never walk through a VASP node
                next_frontier.append((peer, new_path, new_ev))
            if truncated:
                break
        if truncated:
            break
        frontier = next_frontier
        if not frontier:
            break

    return {"paths": paths, "truncated": truncated, "nodes_explored": nodes_explored}


def _independent_paths(brand_paths: List[dict]) -> Tuple[List[dict], List[dict]]:
    """Split one brand's discovered paths into (independent, dependent) --
    section 12. Greedy by (hops asc, entity_id) so the nearest/most-cited
    path wins a contested intermediate node; a later path sharing ANY
    intermediate node with an already-accepted path is dependent -- kept for
    explainability, excluded from the score."""
    ordered = sorted(brand_paths, key=lambda p: (p["hops"], p["entity_id"]))
    independent, dependent = [], []
    used_nodes: set = set()
    for p in ordered:
        nodes = set(p["intermediate_nodes"])
        if nodes and nodes & used_nodes:
            dependent.append(p)
            continue
        independent.append(p)
        used_nodes |= nodes
    return independent, dependent


def _score_brand(brand_paths: List[dict], rules: Dict[str, dict]) -> dict:
    """Sum this brand's INDEPENDENT paths under rule base * tier multiplier *
    hub penalty, capped at _BRAND_SCORE_CAP -- same shape as
    attribution._score_brand/risk._score. Dependent paths are appended with
    applied_amount=0 so a caller can still see every real path found."""
    independent, dependent = _independent_paths(brand_paths)

    contributions = []
    running = 0
    for p in sorted(independent, key=lambda p: p["hops"]):
        rule = rules[_rule_id(p["hops"])]
        amount = rule["base"] * _tier_multiplier(p["attribution"])
        if p["hub_dependent"]:
            amount *= _HUB_PENALTY_FACTOR
        amount = round(amount)
        room = max(_BRAND_SCORE_CAP - running, 0)
        applied = max(min(amount, room), 0)
        running += applied
        contributions.append({**p, "rule_id": _rule_id(p["hops"]), "raw_amount": amount,
                              "applied_amount": applied, "independent": True})
    for p in dependent:
        contributions.append({**p, "rule_id": _rule_id(p["hops"]), "raw_amount": 0,
                              "applied_amount": 0, "independent": False})
    return {"score": running, "contributions": contributions}


def _strength(score: int) -> str:
    for ceiling, name in _STRENGTH_THRESHOLDS:
        if ceiling is None or score < ceiling:
            return name
    return HIGH


def multi_hop_candidates(adjacency: Dict[str, Dict[str, tuple]], exchange_of: Dict[str, dict],
                         start: str, max_hops: int = MAX_HOPS_DEFAULT) -> dict:
    """The multi-hop VASP candidate verdict for one wallet, from real
    transaction-chain evidence alone.

    `adjacency`/`exchange_of` are the caller's already-built
    `correlate._adjacency`/`correlate._vasp_endpoints` outputs (never
    requeried here, same discipline as attribution.vasp_candidates). `start`
    must not itself already be a `exchange_of` hit -- a wallet that is
    already attributed has nothing for this module to add.

    Returns {policy_version, verdict, primary_candidate, strength,
    candidates: [{brand, score_strength, contributions}, ...],
    truncated, nodes_explored}. `candidates` always lists every brand with
    real evidence, ordered strongest first, regardless of verdict --
    `primary_candidate` is None under AMBIGUOUS/INSUFFICIENT_EVIDENCE even
    though `candidates` may be non-empty (section 14: never guess).
    """
    max_hops = min(max(1, max_hops), MAX_HOPS_HARD_CEILING)
    rules = _rules_for(max_hops)
    reach = multi_hop_paths(adjacency, exchange_of, start, max_hops)

    by_brand: Dict[str, List[dict]] = {}
    for p in reach["paths"]:
        by_brand.setdefault(p["vasp"], []).append(p)

    scored = []
    for brand, brand_paths in by_brand.items():
        result = _score_brand(brand_paths, rules)
        if result["score"] <= 0:
            continue
        scored.append({"brand": brand, "score": result["score"],
                       "strength": _strength(result["score"]),
                       "contributions": result["contributions"]})
    scored.sort(key=lambda b: (-b["score"], b["brand"]))

    if not scored:
        verdict = VERDICT_INSUFFICIENT_EVIDENCE
        primary = None
    elif len(scored) == 1:
        verdict = VERDICT_PRIMARY
        primary = scored[0]["brand"]
    else:
        top, runner_up = scored[0]["score"], scored[1]["score"]
        clears_margin = (top >= runner_up * _PRIMARY_MARGIN_RATIO
                         and top - runner_up >= _PRIMARY_MARGIN_ABS)
        if clears_margin:
            verdict = VERDICT_PRIMARY
            primary = scored[0]["brand"]
        else:
            verdict = VERDICT_AMBIGUOUS
            primary = None

    return {
        "policy_version": MULTI_HOP_POLICY_VERSION,
        "provenance": MULTI_HOP_INFERENCE,
        "verdict": verdict,
        "primary_candidate": primary,
        "strength": scored[0]["strength"] if (verdict == VERDICT_PRIMARY and scored) else None,
        "candidates": [{"brand": b["brand"], "strength": b["strength"],
                        "contributions": b["contributions"]} for b in scored],
        "max_hops": max_hops,
        "truncated": reach["truncated"], "nodes_explored": reach["nodes_explored"],
    }
