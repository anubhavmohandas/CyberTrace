"""Historical investigation memory: "have I seen this evidence before, what
happened last time, and does that matter?"

Retrieval and context only, over persistence that already exists —
entities/observations/snapshots for evidence, candidates/analyst_feedback for
outcomes. Memory never decides malicious/benign and never emits SAME_OPERATOR
on its own; every row is provenanced and every classification is one this
module is willing to explain. The one thing memory IS allowed to do that a
pure lookup would not is adjust correlate.py's discrimination weights from
recorded analyst feedback (see correlate.feedback_discrimination) — that is a
deliberate, narrow, additive exception granted for this feature, not memory
quietly becoming a second scorer: the multiplier is folded into the existing
commonness-discount slot, is a no-op with zero feedback rows, and never
manufactures a candidate memory.py itself found.

    EXACT        identity-bearing artifact (PGP key, email, username, wallet,
                 analytics id — exactly the types correlate.SHARED_ARTIFACTS
                 treats as attribution-eligible) reused on a different target.
    CONTEXTUAL   shared infrastructure/ecosystem artifact (domain, favicon,
                 IP, certificate, nameserver, ASN, hosting/VPN provider, HTTP
                 fingerprint) reused on a different target — the same set
                 correlate.py already refuses to score as attribution
                 (NON_ATTRIBUTIVE_SIGNALS) or scores only as INFRA. IP is
                 here in full, not only its VPN_IP/TOR_RELAY egress classes:
                 a hosting provider assigns an address, an operator does not
                 choose it, so a bare IP is shared infrastructure exactly
                 like a shared domain or favicon (see correlate.py's
                 NON_ATTRIBUTIVE_SIGNALS comment for the measured case).
    PRIOR_REFERENCE  this exact target was named by another market's
                 DISCOVERED_VIA edge before — discovery provenance, not
                 evidence anyone controls it.
    PRIOR_CASE   a candidate the correlation engine already scored, on a
                 previous run, for an artifact seen on this target — plus any
                 analyst_feedback recorded against it since.
    RELATED      an artifact on this target has an existing graph edge to
                 something not on this target — one hop, not a fuzzy score.

Every row is labeled `"attribution": "NOT ESTABLISHED BY MEMORY"` so a caller
can never forward one as a SAME_OPERATOR claim by accident.

SIMILAR (fuzzy/derived similarity) is still not implemented: no justifying
case in corpus/labels.toml, and Phase 7's own priority order puts it last.
"""

from __future__ import annotations

import json
from typing import Dict, List

from .correlate import NON_ATTRIBUTIVE_SIGNALS, SHARED_ARTIFACTS
from .evidence import EvidenceStore

# Infra/ecosystem types with no entry in SHARED_ARTIFACTS at all — they only
# ever feed candidate_infra()/candidate_ips(), never successor scoring.
_INFRA_TYPES = frozenset({"ASN", "HOSTING_PROVIDER", "VPN_PROVIDER",
                          "CERTIFICATE", "NAMESERVER", "HTTP_FINGERPRINT"})

# The boundary is read off correlate.py, not redrawn here: an artifact type
# memory calls EXACT is exactly one correlate.py's own successor scoring is
# willing to treat as attribution-eligible.
CONTEXTUAL_TYPES = frozenset(
    etype for signal, etype in SHARED_ARTIFACTS if signal in NON_ATTRIBUTIVE_SIGNALS
) | _INFRA_TYPES

# Node types that describe the target/case itself, not an artifact on it —
# never a memory hit in their own right.
_NON_ARTIFACT_TYPES = frozenset({"MARKET", "ONION_ADDRESS", "PAGE", "DOCUMENT",
                                 "OPERATOR_CANDIDATE", "CRYPTO_CLUSTER", "EXCHANGE"})

# Infra classes worth a temporal timeline: has the market's own hosting
# changed over time (rotation), or reappeared after a gap (reuse)?
_TEMPORAL_TYPES = frozenset({"IP", "DOMAIN", "NAMESERVER", "CERTIFICATE",
                             "ASN", "HOSTING_PROVIDER"})

# IP classes that describe egress the target does not control (VPN, a Tor
# relay) rather than a host it runs — see evidence.classify_ip and
# recommended_actions()'s own VPN_IP/TOR_RELAY caveat.
_NON_ATTRIBUTIVE_IP_CLASSES = frozenset({"VPN_IP", "TOR_RELAY"})


def _classify(etype: str, ip_class: str = "") -> str:
    if etype == "IP" and ip_class in _NON_ATTRIBUTIVE_IP_CLASSES:
        return "CONTEXTUAL"
    return "CONTEXTUAL" if etype in CONTEXTUAL_TYPES else "EXACT"


def _target_artifacts(store: EvidenceStore, target_id: str) -> List[dict]:
    """Entities with an OK observation on this target, excluding node types
    that describe the target/case itself rather than an artifact on it."""
    placeholders = ",".join("?" * len(_NON_ARTIFACT_TYPES))
    return store._all(
        f"SELECT DISTINCT e.entity_id, e.etype, e.normalized_value, e.raw_value, "
        f"       e.metadata "
        f"FROM entities e "
        f"JOIN observations o ON o.entity_id = e.entity_id "
        f"JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        f"WHERE s.target_id=? AND s.status='OK' AND e.etype NOT IN ({placeholders})",
        (target_id, *_NON_ARTIFACT_TYPES))


def feedback_history(store: EvidenceStore, entity_id: str) -> List[dict]:
    """Every analyst verdict on record for this entity, most recent first —
    the Analyst Feedback / False-Positive / Negative memory classes. A
    REJECTED or BENIGN verdict does not erase the artifact; it is a caveat a
    reader (and correlate.feedback_discrimination) should weigh alongside it."""
    return [dict(r) for r in store.feedback_for_entity(entity_id)]


def historical_matches(store: EvidenceStore, target_url: str) -> List[dict]:
    """Artifacts ever observed on `target_url` (OK snapshots, any point in
    time) that were also observed, at some point, on a DIFFERENT target
    already in the store.

    One row per (entity, other target): deliberately not deduplicated past
    that, so `summarize()` can aggregate without losing the per-target
    observations a reader might want to inspect. first_seen/last_seen come
    from real `observations.observed_at` values (the collector's own
    timestamp), never from when a row happened to be inserted — so ingestion
    order within one `correlate` call cannot invent a false "earlier".

    Each row also carries `prior_feedback`: any analyst verdict already on
    file for this exact entity, so a reader sees "seen before AND already
    reviewed" in one place instead of cross-referencing case_history().
    """
    target = store._one("SELECT target_id FROM targets WHERE url=?", (target_url,))
    if not target:
        return []
    target_id = target["target_id"]

    out = []
    for ent in _target_artifacts(store, target_id):
        ip_class = ""
        if ent["etype"] == "IP" and ent["metadata"]:
            ip_class = json.loads(ent["metadata"]).get("ip_class", "")
        others = store._all(
            "SELECT t.url, MIN(o.observed_at) AS first_seen, "
            "       MAX(o.observed_at) AS last_seen "
            "FROM observations o "
            "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
            "JOIN targets t ON t.target_id = s.target_id "
            "WHERE o.entity_id=? AND s.status='OK' AND t.target_id != ? "
            "GROUP BY t.target_id", (ent["entity_id"], target_id))
        if not others:
            continue
        feedback = feedback_history(store, ent["entity_id"])
        for other in others:
            out.append({
                "classification": _classify(ent["etype"], ip_class),
                "etype": ent["etype"],
                "value": ent["normalized_value"],
                "raw_value": ent["raw_value"],
                "entity_id": ent["entity_id"],
                "current_target": target_url,
                "previous_target": other["url"],
                "first_seen": other["first_seen"],
                "last_seen": other["last_seen"],
                "source": "prior CyberTrace investigation",
                "attribution": "NOT ESTABLISHED BY MEMORY",
                "prior_feedback": feedback,
            })
    return sorted(out, key=lambda r: (r["classification"], r["etype"], r["value"],
                                      r["previous_target"]))


def prior_references(store: EvidenceStore, target_url: str) -> List[dict]:
    """Other markets that named `target_url` via DISCOVERED_VIA before — an
    index co-ranking it, not a link either site published. Being discovered
    by A establishes no control by A; see correlate.CONTEXT_WEIGHT."""
    onion = store.find_entity("ONION_ADDRESS", target_url)
    if not onion:
        return []
    rows = store._all(
        "SELECT me.normalized_value AS discovered_by, rel.first_seen, rel.last_seen "
        "FROM relationships rel "
        "JOIN entities me ON me.entity_id = rel.source_entity_id "
        "WHERE rel.target_entity_id=? AND rel.rtype='DISCOVERED_VIA' "
        "  AND me.normalized_value != ?",
        (onion, target_url.lower()))
    return [{
        "classification": "PRIOR_REFERENCE",
        "current_target": target_url,
        "previous_target": r["discovered_by"],
        "first_seen": r["first_seen"],
        "last_seen": r["last_seen"],
        "source": "prior CyberTrace investigation",
        "attribution": "NOT ESTABLISHED BY MEMORY",
    } for r in rows]


def case_history(store: EvidenceStore, target_url: str) -> List[dict]:
    """Historical Case Memory: candidates the correlation engine already
    scored, on a PREVIOUS `correlate` pass over this store, for any artifact
    ever observed on `target_url` — plus any analyst_feedback recorded since.
    Reads correlate.py's own persisted output (the `candidates` table); does
    not re-run or re-score anything."""
    target = store._one("SELECT target_id FROM targets WHERE url=?", (target_url,))
    if not target:
        return []
    rows = store._all(
        "SELECT DISTINCT c.candidate_id, c.ctype, c.entity_id, c.confidence, "
        "       c.assessment, c.updated_at, e.etype, e.normalized_value "
        "FROM candidates c "
        "JOIN entities e ON e.entity_id = c.entity_id "
        "JOIN observations o ON o.entity_id = c.entity_id "
        "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        "WHERE s.target_id=? AND s.status='OK'", (target["target_id"],))
    out = []
    for r in rows:
        out.append({
            "classification": "PRIOR_CASE",
            "candidate_id": r["candidate_id"], "role": r["ctype"],
            "etype": r["etype"], "value": r["normalized_value"],
            "confidence": r["confidence"], "assessment": r["assessment"],
            "last_scored": r["updated_at"],
            "analyst_feedback": [dict(v) for v in store.feedback_for(r["candidate_id"])],
            "attribution": "NOT ESTABLISHED BY MEMORY",
        })
    return out


def relationship_context(store: EvidenceStore, target_url: str) -> List[dict]:
    """RELATED: artifacts on `target_url` that already have a graph edge to
    something NOT on this target — one hop through `relationships`, read as
    context. Never a second attribution path: correlate.py already decides
    which edge types carry weight (FUNNELS/CONTEXT_WEIGHT); this only reports
    that an edge exists."""
    target = store._one("SELECT target_id FROM targets WHERE url=?", (target_url,))
    if not target:
        return []
    out = []
    for ent in _target_artifacts(store, target["target_id"]):
        neighbors = store._all(
            "SELECT r.rtype, other.entity_id, other.etype, other.normalized_value "
            "FROM relationships r "
            "JOIN entities other ON other.entity_id = "
            "  CASE WHEN r.source_entity_id=:eid THEN r.target_entity_id "
            "       ELSE r.source_entity_id END "
            "WHERE (r.source_entity_id=:eid OR r.target_entity_id=:eid) "
            "  AND r.status='ACTIVE' AND other.entity_id != :eid",
            {"eid": ent["entity_id"]})
        for n in neighbors:
            if n["etype"] in _NON_ARTIFACT_TYPES:
                continue  # "this artifact is on a market" isn't new context
            out.append({
                "classification": "RELATED",
                "etype": ent["etype"], "value": ent["normalized_value"],
                "related_rtype": n["rtype"], "related_etype": n["etype"],
                "related_value": n["normalized_value"],
                "current_target": target_url,
                "attribution": "NOT ESTABLISHED BY MEMORY",
            })
    return out


def temporal_infra_timeline(store: EvidenceStore, target_url: str) -> List[dict]:
    """Temporal Memory: this target's own infra artifacts (IP, domain,
    nameserver, certificate, ASN, hosting provider), each with when it was
    first/last seen ON THIS TARGET. More than one distinct value for the same
    etype is a rotation/reuse candidate — reported as data, not flagged as
    suspicious; memory does not decide what a rotation means."""
    target = store._one("SELECT target_id FROM targets WHERE url=?", (target_url,))
    if not target:
        return []
    placeholders = ",".join("?" * len(_TEMPORAL_TYPES))
    rows = store._all(
        f"SELECT e.etype, e.normalized_value AS value, MIN(o.observed_at) AS first_seen, "
        f"       MAX(o.observed_at) AS last_seen "
        f"FROM entities e JOIN observations o ON o.entity_id = e.entity_id "
        f"JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        f"WHERE s.target_id=? AND s.status='OK' AND e.etype IN ({placeholders}) "
        f"GROUP BY e.entity_id ORDER BY e.etype, first_seen",
        (target["target_id"], *_TEMPORAL_TYPES))
    return [dict(r) for r in rows]


def pattern_overlap(store: EvidenceStore, target_url: str) -> List[dict]:
    """Behavioral/Pattern Memory + Explainable Retrieval: per previous
    target, how many of the CURRENT target's distinct artifacts it also
    shares, out of how many the current target has in total — e.g. "4/6
    characteristics match market-alpha.onion". Built entirely from
    historical_matches(); no new query, no similarity model, no score."""
    matches = historical_matches(store, target_url)
    if not matches:
        return []
    target = store._one("SELECT target_id FROM targets WHERE url=?", (target_url,))
    total = len(_target_artifacts(store, target["target_id"]))

    by_target: Dict[str, set] = {}
    for m in matches:
        by_target.setdefault(m["previous_target"], set()).add((m["etype"], m["value"]))

    out = [{
        "previous_target": prev,
        "matched": len(shared),
        "total": total,
        "matched_artifacts": sorted(f"{etype}:{value}" for etype, value in shared),
        "explanation": f"{len(shared)}/{total} characteristics match {prev}",
    } for prev, shared in by_target.items()]
    return sorted(out, key=lambda r: (-r["matched"], r["previous_target"]))


def summarize(matches: List[dict]) -> List[dict]:
    """Aggregate per (etype, value): how many previous targets, first/last
    seen across all of them, and whether any analyst feedback is on file.
    Phase 10's "seen on 3 previous targets" without losing the per-target
    rows — call historical_matches() again to inspect what was aggregated
    away."""
    groups: Dict[tuple, dict] = {}
    for m in matches:
        key = (m["classification"], m.get("etype"), m.get("value"))
        g = groups.setdefault(key, {
            "classification": m["classification"], "etype": m.get("etype"),
            "value": m.get("value"), "raw_value": m.get("raw_value"),
            "previous_targets": [], "first_seen": None, "last_seen": None,
            "prior_feedback": m.get("prior_feedback") or [],
        })
        g["previous_targets"].append(m["previous_target"])
        if m["first_seen"] and (g["first_seen"] is None or m["first_seen"] < g["first_seen"]):
            g["first_seen"] = m["first_seen"]
        if m["last_seen"] and (g["last_seen"] is None or m["last_seen"] > g["last_seen"]):
            g["last_seen"] = m["last_seen"]
    for g in groups.values():
        g["previous_targets"] = sorted(set(g["previous_targets"]))
    return sorted(groups.values(), key=lambda g: (g["classification"], g["etype"], g["value"]))


def _feedback_note(feedback: List[dict]) -> str:
    if not feedback:
        return ""
    latest = max(feedback, key=lambda f: f["recorded_at"])
    return (f" [analyst: {latest['outcome']}"
           f"{' by ' + latest['analyst'] if latest.get('analyst') else ''}]")


def render_markdown(target_url: str, matches: List[dict], references: List[dict],
                    cases: List[dict] = (), related: List[dict] = (),
                    patterns: List[dict] = ()) -> List[str]:
    """Lines for a `HISTORICAL MEMORY` section, or [] if there is nothing to
    show. Caller appends these after correlate.render_markdown's own output —
    never merges into it, so a reader can never mistake memory context for a
    governed correlation candidate."""
    if not any((matches, references, cases, related, patterns)):
        return []
    lines = ["## Historical memory", "",
             f"_prior-investigation context for `{target_url}` — retrieval only, "
             "never establishes SAME_OPERATOR_", ""]
    for g in summarize(matches):
        n = len(g["previous_targets"])
        where = g["previous_targets"][0] if n == 1 else f"{n} previous targets"
        lines.append(f"- [{g['classification']}] {g['etype']} `{g['value']}` — "
                     f"previously observed on {where} "
                     f"(first seen {g['first_seen'] or '?'}, last seen {g['last_seen'] or '?'})"
                     f"{_feedback_note(g['prior_feedback'])}")
    for r in references:
        lines.append(f"- [PRIOR_REFERENCE] named by `{r['previous_target']}` "
                     f"via a prior index result (first seen {r['first_seen'] or '?'})")
    if cases:
        lines.append("")
        lines.append("_Prior correlation-engine conclusions for artifacts on this target:_")
        for c in cases:
            note = _feedback_note(c["analyst_feedback"])
            lines.append(f"- [PRIOR_CASE] {c['candidate_id']} ({c['role']}) "
                         f"{c['etype']} `{c['value']}` — confidence {c['confidence']:.2f} "
                         f"as of {c['last_scored']}{note}")
    if related:
        lines.append("")
        lines.append("_Related evidence (one graph hop, context only):_")
        for r in related[:20]:
            lines.append(f"- [RELATED] {r['etype']} `{r['value']}` "
                         f"--{r['related_rtype']}--> {r['related_etype']} `{r['related_value']}`")
    if patterns:
        lines.append("")
        lines.append("_Pattern overlap:_")
        for p in patterns:
            lines.append(f"- {p['explanation']}")
    lines.append("")
    return lines
