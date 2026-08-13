"""M5: ranked, auditable candidates from the evidence store.

    OPERATOR  identity entity (PGP / email / username) behind one or more markets
    INFRA     cert / nameserver / ASN / provider / domain shared by 2+ markets
    IP        infrastructure IP with cross-market convergence

Read-mostly over EvidenceStore. The only writes are derived claims, each one
carrying its own observation so it stays walkable back to a hashed snapshot:
SUCCESSOR_OF edges, contradiction findings, and rows in `candidates`.

Two rules this layer inherits and must not break:

**Convergence, not a single tell.** A candidate's score is a noisy-OR over
independent funnels, so three mediocre signals outrank one loud one. Weights are
priors, not calibration — there is no ground truth to fit against.

**The clone guard outranks correlation.** `evidence.detect_clones` decides
whether a shared key means shared control or shared copying. A pair it called
CLONE_SUSPECT can never become a SUCCESSOR_OF edge here; it is recorded as a
contradiction against the candidates that relied on it instead.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set

from .evidence import EvidenceStore, detect_clones, utcnow

# Which edges count as which funnel. Keyed on the relationship types `ingest()`
# actually writes — a funnel keyed on a type nothing produces scores every
# entity at zero while still looking like a working engine.
FUNNELS: Dict[str, Set[str]] = {
    "f1_contact":   {"USES_EMAIL", "USES_USERNAME", "USES_TELEGRAM", "USES_PHONE"},
    "f2_pgp_reuse": {"USES_PGP", "SIGNED_BY", "CROSS_SIGNS"},
    "f3_crypto":    {"USES_BTC", "USES_XMR", "USES_ETH", "PART_OF_CLUSTER"},
    "f4_cross_plat": {"ASSOCIATED_WITH"},
    "f5_clearnet":  {"HOSTED_ON", "CANDIDATE_IP", "RESOLVES_TO", "BELONGS_TO_ASN",
                     "OWNED_BY", "USES_CERT", "USES_NS", "USES_ANALYTICS", "MENTIONS"},
}

# Relative prior per funnel: a reused key is worth more than a referenced host.
FUNNEL_WEIGHT = {"f1_contact": 1.0, "f2_pgp_reuse": 1.3, "f3_crypto": 1.2,
                 "f4_cross_plat": 0.7, "f5_clearnet": 0.9}

FUNNEL_OF = {rtype: f for f, rtypes in FUNNELS.items() for rtype in rtypes}

# Edges written by ingest() carry no weight, so an observation's confidence is
# the real signal strength; this is only the floor when an edge has neither.
DEFAULT_CONF = 0.6

# Successor signals and the weight each contributes to the noisy-OR.
SUCCESSOR_SIGNALS = {
    "signed_by":        1.5,   # A's key signed B's key
    "shared_pgp_key":   1.3,
    "shared_btc":       1.1,
    "shared_xmr":       1.1,
    "shared_email":     0.9,
    "shared_ip":        0.9,
    "shared_username":  0.7,
    "shared_analytics": 0.7,
    "shared_domain":    0.4,
    "temporal_handoff": 0.5,   # B first seen within 90d after A went quiet
    "temporal_overlap": 0.2,   # both live at once — weak, and cuts against succession
}

# M5's own derived claims are snapshotted against this pseudo-target so they
# carry provenance like anything else. It is excluded everywhere markets are
# enumerated: left in, a second pass would see its MARKET observations as a
# market sharing artifacts with every real one and invent successor pairs.
DERIVED_TARGET = "m5.correlate.local"

SHARED_ARTIFACTS = (
    ("shared_pgp_key", "PGP_KEY"), ("shared_btc", "BTC_ADDRESS"),
    ("shared_xmr", "XMR_ADDRESS"), ("shared_email", "EMAIL"),
    ("shared_ip", "IP"), ("shared_username", "USERNAME"),
    ("shared_analytics", "ANALYTICS_ID"), ("shared_domain", "DOMAIN"),
)


def _entity(store: EvidenceStore, entity_id: str):
    return store._one(
        "SELECT entity_id, etype, normalized_value, metadata FROM entities "
        "WHERE entity_id=?", (entity_id,))


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    """ISO timestamp -> aware UTC datetime, or None.

    Collectors emit both naive and offset-aware stamps; comparing the two raises,
    and these comparisons decide successor direction, so naive is read as UTC
    rather than allowed to blow up a whole correlation pass.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --- resolution --------------------------------------------------------------

def canonical_entity_key(store: EvidenceStore, entity_id: str) -> str:
    """Fold a PGP long key id into the fingerprint node that provably owns it.

    normalize.py keeps `PGP:KEYID:` in its own namespace so a weak id never
    inherits a fingerprint's evidential weight, and only collapses the two when
    something proves they are the same key. A v4/v6 fingerprint's low 64 bits
    ARE the long key id, so the fingerprint itself is that proof — the one merge
    this layer is allowed to make. Everything else resolves to itself.
    """
    row = _entity(store, entity_id)
    if not row or row["etype"] != "PGP_KEY":
        return entity_id
    value = row["normalized_value"]             # upsert_entity stores lowercase
    if not value.startswith("pgp:keyid:"):
        return entity_id
    hit = store._one(
        "SELECT entity_id FROM entities WHERE etype='PGP_KEY' "
        "AND normalized_value NOT LIKE 'pgp:keyid:%' "
        "AND substr(normalized_value, -16)=? LIMIT 1", (value.rsplit(":", 1)[-1],))
    return hit["entity_id"] if hit else entity_id


def username_aliases(store: EvidenceStore, min_sim: float = 0.82) -> List[dict]:
    """Near-duplicate handles across markets (casing, leet, typo-squats).

    Reported, never merged: `dread_op` and `dread_0p` may be one person or a
    squatter trading on the resemblance, and only a human can tell.

    occam: O(n^2) SequenceMatcher over distinct usernames. Fine for the hundreds
    a market corpus yields; if it ever reaches thousands, block on the first
    character or a trigram index before comparing.
    """
    rows = store._all(
        "SELECT entity_id, normalized_value FROM entities WHERE etype='USERNAME'")
    out = []
    for i, a in enumerate(rows):
        for b in rows[i + 1:]:
            sim = SequenceMatcher(None, a["normalized_value"], b["normalized_value"]).ratio()
            if sim >= min_sim:
                out.append({"a": a["entity_id"], "b": b["entity_id"],
                            "a_value": a["normalized_value"],
                            "b_value": b["normalized_value"], "similarity": round(sim, 3)})
    return sorted(out, key=lambda r: -r["similarity"])


# --- convergence -------------------------------------------------------------

def markets_for_entity(store: EvidenceStore, entity_id: str) -> List[str]:
    """Targets where this entity was actually observed (not merely linked)."""
    rows = store._all(
        "SELECT DISTINCT s.target_id FROM observations o "
        "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        "JOIN targets t ON t.target_id = s.target_id "
        "WHERE o.entity_id=? AND t.url != ?", (entity_id, DERIVED_TARGET))
    return sorted(r["target_id"] for r in rows)


def _observation_confidence(store: EvidenceStore, obs_ids: List[str]) -> Dict[str, float]:
    if not obs_ids:
        return {}
    marks = ",".join("?" * len(obs_ids))
    return {r["observation_id"]: r["confidence"] for r in store._all(
        f"SELECT observation_id, confidence FROM observations "
        f"WHERE observation_id IN ({marks})", tuple(obs_ids))}


def entity_funnel_profile(store: EvidenceStore, entity_id: str) -> dict:
    """Per-funnel best confidence plus the observations backing it.

    Strength comes from the observation, not the edge: `_link()` writes edges
    without a weight, so scoring on `relationships.weight` would compare None to
    a float on real ingested data and rank nothing.
    """
    rows = store._all(
        "SELECT r.rtype, r.weight, ev.observation_ids FROM relationships r "
        "LEFT JOIN evidence ev ON ev.relationship_id = r.rel_id "
        "WHERE r.status='ACTIVE' AND (r.source_entity_id=? OR r.target_entity_id=?)",
        (entity_id, entity_id))

    parsed = [(r["rtype"], r["weight"], json.loads(r["observation_ids"] or "[]"))
              for r in rows]
    conf_of = _observation_confidence(
        store, [o for _, _, ids in parsed for o in ids])

    funnels = {f: {"best_conf": 0.0, "evidence_ids": [], "rel_types": set()}
               for f in FUNNELS}
    for rtype, weight, obs_ids in parsed:
        funnel = FUNNEL_OF.get(rtype)
        if funnel is None:
            continue                        # HAS_ADDRESS etc: definitional, no signal
        confs = [conf_of[o] for o in obs_ids if o in conf_of]
        conf = max(confs) if confs else (weight if weight is not None else DEFAULT_CONF)
        slot = funnels[funnel]
        slot["best_conf"] = max(slot["best_conf"], conf)
        slot["evidence_ids"] += obs_ids
        slot["rel_types"].add(rtype)

    # noisy-OR: independent funnels compound, so convergent weak signals beat a
    # lone strong claim. Capped per funnel so nothing reaches certainty.
    residual = 1.0
    for name, slot in funnels.items():
        residual *= 1.0 - min(0.99, slot["best_conf"] * FUNNEL_WEIGHT[name])
        slot["rel_types"] = sorted(slot["rel_types"])   # keep the result JSON-clean
    active = {f: s for f, s in funnels.items() if s["best_conf"] > 0}
    return {
        "funnels": active,
        "markets": markets_for_entity(store, entity_id),
        "total_conf": round(1.0 - residual, 4),
        "n_funnels": len(active),
    }


def _candidate(store: EvidenceStore, role: str, row, profile: dict) -> dict:
    return {
        "role": role, "etype": row["etype"], "entity_id": row["entity_id"],
        "value": row["normalized_value"], "score": profile["total_conf"],
        "n_funnels": profile["n_funnels"], "markets": profile["markets"],
        "n_markets": len(profile["markets"]), "funnels": profile["funnels"],
    }


def candidate_operators(store: EvidenceStore, min_conf: float = 0.35) -> List[dict]:
    """Ranked OPERATOR candidates: keys, emails, handles."""
    out = []
    for row in store._all(
            "SELECT entity_id, etype, normalized_value FROM entities "
            "WHERE etype IN ('PGP_KEY','EMAIL','USERNAME')"):
        if canonical_entity_key(store, row["entity_id"]) != row["entity_id"]:
            continue                        # alias: score belongs to the fingerprint
        profile = entity_funnel_profile(store, row["entity_id"])
        if profile["total_conf"] >= min_conf and profile["markets"]:
            out.append(_candidate(store, "OPERATOR", row, profile))
    return sorted(out, key=lambda c: (-c["score"], -c["n_funnels"]))


def candidate_infra(store: EvidenceStore, min_markets: int = 2) -> List[dict]:
    """Infrastructure shared by 2+ markets — the handoff points worth a warrant."""
    out = []
    for row in store._all(
            "SELECT entity_id, etype, normalized_value FROM entities WHERE etype IN "
            "('CERTIFICATE','NAMESERVER','ASN','HOSTING_PROVIDER','DOMAIN','ANALYTICS_ID')"):
        profile = entity_funnel_profile(store, row["entity_id"])
        if len(profile["markets"]) >= min_markets:
            out.append(_candidate(store, "INFRA", row, profile))
    return sorted(out, key=lambda c: (-c["score"], -c["n_markets"]))


def candidate_ips(store: EvidenceStore, min_markets: int = 2) -> List[dict]:
    """IPs converging across markets. ip_class is carried through from metadata
    because a VPN egress and an origin host warrant very different next steps."""
    out = []
    for row in store._all(
            "SELECT entity_id, etype, normalized_value, metadata FROM entities "
            "WHERE etype='IP'"):
        profile = entity_funnel_profile(store, row["entity_id"])
        if len(profile["markets"]) < min_markets:
            continue
        meta = json.loads(row["metadata"] or "{}")
        out.append(_candidate(store, "IP", row, profile) |
                   {"ip_class": meta.get("ip_class", "UNKNOWN"),
                    "asn": meta.get("asn"), "org": meta.get("org")})
    return sorted(out, key=lambda c: (-c["score"], -c["n_markets"]))


# --- successors --------------------------------------------------------------

def market_artifact_map(store: EvidenceStore) -> Dict[str, Dict[str, Set[str]]]:
    """target_id -> {etype: {entity_id}} over everything observed there."""
    out: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    for r in store._all(
            "SELECT s.target_id, o.entity_id, e.etype FROM observations o "
            "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
            "JOIN entities e ON e.entity_id = o.entity_id "
            "JOIN targets t ON t.target_id = s.target_id "
            "WHERE t.url != ?", (DERIVED_TARGET,)):
        out[r["target_id"]][r["etype"]].add(r["entity_id"])
    return out


def market_windows(store: EvidenceStore) -> Dict[str, dict]:
    """target_id -> url plus the first/last time anything was captured there."""
    return {r["target_id"]: {
        "url": r["url"],
        "first": _parse_ts(r["first_seen"]), "last": _parse_ts(r["last_seen"])}
        for r in store._all(
            "SELECT t.target_id, t.url, MIN(s.observed_at) AS first_seen, "
            "       MAX(s.observed_at) AS last_seen "
            "FROM targets t JOIN snapshots s ON s.target_id = t.target_id "
            "WHERE t.url != ? GROUP BY t.target_id", (DERIVED_TARGET,))}


def _candidate_pairs(artifacts: Dict[str, Dict[str, Set[str]]]) -> List[tuple]:
    """Market pairs that share at least one artifact.

    Inverted index rather than comparing every market against every other: pairs
    only exist where an artifact is actually reused, so a corpus of hundreds of
    markets stays linear in shared artifacts instead of quadratic in markets.
    """
    holders = defaultdict(set)
    for target_id, by_type in artifacts.items():
        for entity_ids in by_type.values():
            for entity_id in entity_ids:
                holders[entity_id].add(target_id)
    pairs = set()
    for targets in holders.values():
        ordered = sorted(targets)
        for i, a in enumerate(ordered):
            for b in ordered[i + 1:]:
                pairs.add((a, b))
    return sorted(pairs)


def _observations_of(store: EvidenceStore, target_id: str, entity_id: str) -> List[str]:
    return [r["observation_id"] for r in store._all(
        "SELECT o.observation_id FROM observations o "
        "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        "WHERE s.target_id=? AND o.entity_id=?", (target_id, entity_id))]


def _pair_signals(store: EvidenceStore, artifacts: dict, windows: dict,
                  a_id: str, b_id: str) -> List[dict]:
    """Every successor signal joining two markets, with its evidence."""
    a, b = artifacts[a_id], artifacts[b_id]
    signals = []

    # A key on A signing a key on B is the strongest directional evidence there
    # is: it is the outgoing operator vouching for the incoming one.
    for key_a in a.get("PGP_KEY", set()):
        for key_b in b.get("PGP_KEY", set()):
            for r in store._all(
                    "SELECT r.rel_id, ev.observation_ids FROM relationships r "
                    "LEFT JOIN evidence ev ON ev.relationship_id = r.rel_id "
                    "WHERE r.rtype='SIGNED_BY' AND r.source_entity_id=? "
                    "AND r.target_entity_id=?", (key_a, key_b)):
                signals.append({
                    "signal": "signed_by", "weight": SUCCESSOR_SIGNALS["signed_by"],
                    "direction": "a_to_b",
                    "evidence": json.loads(r["observation_ids"] or "[]"),
                    "detail": "a key on A signed a key on B"})

    for name, etype in SHARED_ARTIFACTS:
        for entity_id in a.get(etype, set()) & b.get(etype, set()):
            row = _entity(store, entity_id)
            signals.append({
                "signal": name, "weight": SUCCESSOR_SIGNALS[name], "direction": None,
                "evidence": (_observations_of(store, a_id, entity_id)
                             + _observations_of(store, b_id, entity_id)),
                "detail": f"{etype} {row['normalized_value'][:48]} on both"})

    # Pairs arrive ordered by target_id, which is a hash — so which market is
    # older has to be decided here. Reading the gap in the arbitrary pair order
    # turns a clean handoff into an "overlap", which argues against succession
    # rather than for it, and costs the pair its directional hint.
    wa, wb = windows.get(a_id) or {}, windows.get(b_id) or {}
    if wa.get("first") and wb.get("first") and wa.get("last") and wb.get("last"):
        older, newer, direction = ((wa, wb, "a_to_b") if wa["first"] <= wb["first"]
                                   else (wb, wa, "b_to_a"))
        gap = newer["first"] - older["last"]
        if gap > timedelta(0):
            if gap <= timedelta(days=90):
                signals.append({
                    "signal": "temporal_handoff",
                    "weight": SUCCESSOR_SIGNALS["temporal_handoff"],
                    "direction": direction, "evidence": [],
                    "detail": (f"{newer['url']} first captured {gap.days}d after "
                               f"{older['url']} went quiet")})
        else:
            signals.append({
                "signal": "temporal_overlap", "weight": SUCCESSOR_SIGNALS["temporal_overlap"],
                "direction": None, "evidence": [],
                "detail": "capture windows overlap — both live at once"})
    return signals


def _market_entity(store: EvidenceStore, target_id: str) -> Optional[str]:
    row = store._one("SELECT url FROM targets WHERE target_id=?", (target_id,))
    if not row:
        return None
    return store.find_entity("MARKET", row["url"]) or store.upsert_entity("MARKET", row["url"])


def _derived_snapshot(store: EvidenceStore, payload: Any) -> str:
    """A hashed, timestamped snapshot for this pass's derived claims.

    Conclusions get the same provenance treatment as collected bytes: an M5 edge
    resolves through its observation to a snapshot recording what the pass saw,
    so a re-run that changes a verdict is visible rather than silent.
    """
    target_id = store.upsert_target("m5.correlate.local", label="m5:correlation")
    return store.insert_snapshot(target_id, payload, collector="m5:correlate")


def detect_successors(store: EvidenceStore, min_score: float = 0.5,
                      clone_pairs: Optional[Set[frozenset]] = None) -> List[dict]:
    """Ranked successor hypotheses; writes SUCCESSOR_OF edges older -> newer.

    A pair the clone guard called CLONE_SUSPECT is refused an edge no matter how
    strongly it scores: every artifact it shares is explained by the later site
    copying the earlier one, and promoting that to succession attributes a
    clone's activity to its victim.
    """
    artifacts = market_artifact_map(store)
    windows = market_windows(store)
    clone_pairs = clone_pairs or set()
    results = []

    for a_id, b_id in _candidate_pairs(artifacts):
        signals = _pair_signals(store, artifacts, windows, a_id, b_id)
        if not signals:
            continue
        residual = 1.0
        for s in signals:
            residual *= 1.0 - min(0.99, s["weight"])
        score = round(1.0 - residual, 4)
        if score < min_score:
            continue

        urls = frozenset({(windows.get(a_id) or {}).get("url"),
                          (windows.get(b_id) or {}).get("url")})
        if urls in clone_pairs:
            results.append({"source_market": a_id, "target_market": b_id,
                            "source_url": (windows.get(a_id) or {}).get("url"),
                            "target_url": (windows.get(b_id) or {}).get("url"),
                            "score": score, "suppressed": "CLONE_SUSPECT",
                            "signals": [s["signal"] for s in signals],
                            "evidence_ids": []})
            continue

        # Direction: an explicit directional signal wins; otherwise the market
        # seen first is the predecessor.
        first_a = (windows.get(a_id) or {}).get("first")
        first_b = (windows.get(b_id) or {}).get("first")
        if any(s["direction"] == "b_to_a" for s in signals):
            src, dst = b_id, a_id
        elif any(s["direction"] == "a_to_b" for s in signals):
            src, dst = a_id, b_id
        elif first_a and first_b and first_b < first_a:
            src, dst = b_id, a_id
        else:
            src, dst = a_id, b_id

        src_entity, dst_entity = _market_entity(store, src), _market_entity(store, dst)
        if not (src_entity and dst_entity):
            continue
        snapshot = _derived_snapshot(store, {"pair": [src, dst], "score": score,
                                             "signals": [s["detail"] for s in signals]})
        obs = store.insert_observation(
            snapshot, dst_entity, method="m5:successor", section="SUCCESSOR",
            context="; ".join(s["detail"] for s in signals), confidence=score)
        evidence = list(dict.fromkeys(
            [o for s in signals for o in s["evidence"]] + [obs]))
        rel = store.upsert_relationship(src_entity, dst_entity, "SUCCESSOR_OF",
                                        source_label="m5:correlate", weight=score)
        store.add_evidence(rel, evidence, note=f"successor score {score}")
        results.append({"source_market": src, "target_market": dst,
                        "source_url": (windows.get(src) or {}).get("url"),
                        "target_url": (windows.get(dst) or {}).get("url"),
                        "score": score, "suppressed": None, "rel_id": rel,
                        "signals": [s["signal"] for s in signals],
                        "evidence_ids": evidence})
    return sorted(results, key=lambda r: -r["score"])


# --- contradictions ----------------------------------------------------------

def contradictions_from_clones(store: EvidenceStore, clones: List[dict]) -> List[dict]:
    """Clone verdicts, restated as constraints on attribution.

    A CLONE_SUSPECT pair is the standing objection to any candidate whose score
    leans on artifacts those two markets share: the reuse is copying, not shared
    control. Carried per-candidate so a dossier can never present the inference
    without the objection to it.

    occam: derived entirely from the existing clone guard. The other rules worth
    having — one identity bound to unrelated keys, one key claiming unrelated
    handles — need identity-to-key edges (ASSOCIATED_WITH) that no collector
    writes yet; add them here once a keyserver or forum collector produces them.
    """
    flags = []
    for f in clones:
        if f["ftype"] != "CLONE_SUSPECT":
            continue
        flags.append({
            "rule": "shared_artifacts_explained_by_cloning", "severity": "HIGH",
            "markets": [f["earlier"], f["later"]], "shared_key": f["shared_key"],
            "similarity": f["similarity"], "finding_id": f["finding_id"],
            "detail": (f"{f['later']} copied {f['earlier']} (page similarity "
                       f"{f['similarity']:.2f}); shared artifacts do not evidence "
                       f"shared control")})
    return flags


# --- dossiers ----------------------------------------------------------------

def evidence_chain(store: EvidenceStore, observation_ids) -> List[dict]:
    """Expand observation ids into records a reader can check independently."""
    out, seen = [], set()
    for oid in observation_ids or []:
        if oid in seen:
            continue
        seen.add(oid)
        row = store._one(
            "SELECT o.observation_id, o.extraction_method, o.section, o.context, "
            "       o.confidence, o.observed_at, s.snapshot_id, s.sha256, s.collector, "
            "       t.url FROM observations o "
            "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
            "JOIN targets t ON t.target_id = s.target_id "
            "WHERE o.observation_id=?", (oid,))
        if row:
            out.append(dict(row))
    return sorted(out, key=lambda e: -e["confidence"])


def confidence_level(role: str, score: float, n_signal: int) -> str:
    """Deliberately hard to reach HIGH: one funnel is never enough, whatever it
    scores, because a single artifact type is exactly what a clone can copy."""
    if role == "OPERATOR":
        if score >= 0.90 and n_signal >= 2:
            return "HIGH"
        return "MEDIUM" if score >= 0.60 else "LOW"
    if score >= 0.70 and n_signal >= 3:
        return "HIGH"
    return "MEDIUM" if score >= 0.50 and n_signal >= 2 else "LOW"


def recommended_actions(role: str, etype: str, value: str, markets: List[str],
                        ip_class: str = "UNKNOWN") -> List[str]:
    if role == "OPERATOR":
        return [
            f"Preservation request for `{value}` at every platform it touched "
            "(mail provider, forum, wallet service), via legal process",
            "Cluster the crypto addresses linked to this identity and check "
            "cash-out points against exchange KYC",
            "Check the key against public keyservers, keybase and signed commits "
            "for a long-lived identity anchor",
            f"Watch the {len(markets)} linked market(s) for renewed reuse after any "
            "takedown — that is the successor early warning",
        ]
    if etype == "CERTIFICATE":
        return ["Request issuance records from the CA (subscriber, order, payment)",
                "Pivot through Certificate Transparency for other domains on this serial"]
    if etype == "NAMESERVER":
        return ["Passive-DNS pivot: enumerate every domain ever delegated here"]
    if etype in ("ASN", "HOSTING_PROVIDER"):
        return [f"Approach the abuse desk at `{value}` for subscriber and contract "
                "records covering the observed IPs"]
    if etype == "ANALYTICS_ID":
        return ["Pivot the analytics id across public crawls — one account id "
                "across two markets is an operator-level tell"]
    if etype == "DOMAIN":
        return ["Pull historical WHOIS and passive DNS for registrant and hosting churn"]
    if role == "IP":
        actions = ["Request netflow/subscriber retention covering the first-seen "
                   "windows of the linked markets",
                   "Check historical abuse reporting for context on the host"]
        if ip_class == "VPN_IP":
            actions.append("Flagged VPN egress: provider logs may not exist — confirm "
                           "retention before building on this")
        return actions
    return []


def limitations(role: str, etype: str, has_contradiction: bool) -> List[str]:
    out = ["Correlation is probabilistic: shared artifacts evidence shared "
           "infrastructure or personnel, never a proven identity",
           "Collected from published sources; nothing here establishes who "
           "physically operated a machine"]
    if role == "OPERATOR":
        out.append("Identity artifacts can be planted — a rival or a honeypot can "
                   "publish someone else's key or address")
    if etype in ("CERTIFICATE", "HOSTING_PROVIDER", "ASN"):
        out.append("Shared hosting and CDNs produce this same overlap with no "
                   "relationship between the sites")
    if has_contradiction:
        out.append("A clone finding contradicts part of this candidate's support — "
                   "read the contradictions before relying on the score")
    return out


def build_dossier(store: EvidenceStore, cand: dict, aliases: List[dict],
                  contradictions: List[dict], windows: Dict[str, dict]) -> dict:
    urls = sorted((windows.get(t) or {}).get("url", t) for t in cand["markets"])
    relevant = [c for c in contradictions if set(c["markets"]) & set(urls)]
    n_signal = cand["n_funnels"] if cand["role"] == "OPERATOR" else cand["n_markets"]
    chain = evidence_chain(
        store, [o for f in cand["funnels"].values() for o in f["evidence_ids"]])
    prefix = {"OPERATOR": "OP", "INFRA": "IN"}.get(cand["role"], "IP")
    return {
        "candidate_id": f"{prefix}-{cand['entity_id'][-8:]}",
        "role": cand["role"],
        "confidence_level": confidence_level(cand["role"], cand["score"], n_signal),
        "score": cand["score"],
        "entity": {"etype": cand["etype"], "value": cand["value"],
                   "entity_id": cand["entity_id"]},
        "markets": urls,
        "funnels": {f: {"best_conf": round(v["best_conf"], 3),
                        "rel_types": sorted(v["rel_types"])}
                    for f, v in cand["funnels"].items()},
        "evidence_count": len(chain),
        "key_evidence": chain[:8],
        "aliases": [a for a in aliases
                    if cand["entity_id"] in (a["a"], a["b"])],
        "contradictions": relevant,
        "ip_class": cand.get("ip_class"),
        "recommended_actions": recommended_actions(
            cand["role"], cand["etype"], cand["value"], urls,
            cand.get("ip_class") or "UNKNOWN"),
        "limitations": limitations(cand["role"], cand["etype"], bool(relevant)),
    }


def save_candidates(store: EvidenceStore, dossiers: List[dict]) -> None:
    """Persist to the `candidates` table, supporting and contradicting kept apart
    so a later run cannot quietly drop the objections to a candidate."""
    for d in dossiers:
        store.conn.execute(
            "INSERT INTO candidates (candidate_id, ctype, entity_id, confidence, "
            "assessment, supporting_ids, contradicting_ids, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(candidate_id) DO UPDATE SET "
            "confidence=excluded.confidence, assessment=excluded.assessment, "
            "supporting_ids=excluded.supporting_ids, "
            "contradicting_ids=excluded.contradicting_ids, updated_at=excluded.updated_at",
            (d["candidate_id"], d["role"], d["entity"]["entity_id"], d["score"],
             f"{d['confidence_level']} — {d['entity']['etype']} {d['entity']['value']} "
             f"across {len(d['markets'])} market(s)",
             json.dumps([e["observation_id"] for e in d["key_evidence"]]),
             json.dumps([c["finding_id"] for c in d["contradictions"]]), utcnow()))
    store.conn.commit()


def render_markdown(dossiers: List[dict], results: dict) -> str:
    lines = ["# CyberTrace — correlation brief", "", f"_generated {utcnow()}_", "",
             f"{len(dossiers)} candidates "
             f"(operator {len(results['operators'])}, infra {len(results['infra'])}, "
             f"ip {len(results['ips'])}) · successors {len(results['successors'])} · "
             f"clones {len(results['clones'])} · "
             f"contradictions {len(results['contradictions'])}", ""]

    if results["successors"]:
        lines += ["## Successor hypotheses", ""]
        for s in results["successors"]:
            note = f" — SUPPRESSED ({s['suppressed']})" if s["suppressed"] else ""
            lines.append(f"- `{s['source_url'] or s['source_market']}` → "
                         f"`{s['target_url'] or s['target_market']}` "
                         f"score {s['score']:.3f} · {', '.join(s['signals'])}{note}")
        lines.append("")

    if results["contradictions"]:
        lines += ["## Contradictions", ""]
        lines += [f"- [{c['severity']}] {c['detail']}" for c in results["contradictions"]]
        lines.append("")

    for d in dossiers:
        lines += [f"## {d['candidate_id']} · {d['role']} · {d['confidence_level']} "
                  f"(score {d['score']:.3f})", "",
                  f"- entity: {d['entity']['etype']} `{d['entity']['value']}`",
                  f"- markets: {', '.join(d['markets']) or '—'}",
                  f"- evidence records: {d['evidence_count']}"]
        if d["funnels"]:
            lines.append("- funnels: " + ", ".join(
                f"{f} {v['best_conf']:.2f}" for f, v in sorted(d["funnels"].items())))
        if d["contradictions"]:
            lines.append(f"- ⚠ contradicted by {len(d['contradictions'])} clone finding(s)")
        if d["aliases"]:
            lines.append("- look-alike handles: " + ", ".join(
                f"{a['a_value']}~{a['b_value']} ({a['similarity']})" for a in d["aliases"]))
        lines += ["", "### Evidence", ""]
        lines += [f"- `{e['observed_at']}` [{e['extraction_method']}] "
                  f"{(e['context'] or '')[:120]} (conf {e['confidence']}, "
                  f"snapshot `{e['sha256'][:12]}`)" for e in d["key_evidence"][:5]]
        lines += ["", "### Next steps", ""]
        lines += [f"- {a}" for a in d["recommended_actions"]]
        lines += ["", "### Limitations", ""]
        lines += [f"- {l}" for l in d["limitations"]]
        lines.append("")
    return "\n".join(lines)


# --- rendering ---------------------------------------------------------------

# colour, shape, size per entity type. Shape carries the type as well as colour
# so the graph stays readable without relying on colour discrimination, and the
# type is repeated in every tooltip.
NODE_STYLE = {
    "MARKET":           ("#e74c3c", "star", 34),
    "ONION_ADDRESS":    ("#c0392b", "triangle", 16),
    "PGP_KEY":          ("#9b59b6", "diamond", 24),
    "EMAIL":            ("#3498db", "dot", 20),
    "USERNAME":         ("#2980b9", "dot", 18),
    "BTC_ADDRESS":      ("#f39c12", "square", 20),
    "XMR_ADDRESS":      ("#e67e22", "square", 20),
    "ETH_ADDRESS":      ("#d35400", "square", 20),
    "IP":               ("#16a085", "hexagon", 22),
    "DOMAIN":           ("#1abc9c", "dot", 16),
    "HOSTING_PROVIDER": ("#27ae60", "box", 18),
    "ASN":              ("#27ae60", "box", 18),
    "ANALYTICS_ID":     ("#8e44ad", "triangleDown", 18),
    "CERTIFICATE":      ("#34495e", "box", 18),
    "NAMESERVER":       ("#34495e", "box", 18),
}
DEFAULT_STYLE = ("#7f8c8d", "dot", 14)


def render_html(store: EvidenceStore, path: str,
                results: Optional[dict] = None, height: str = "900px") -> str:
    """Write the evidence graph to a standalone interactive HTML file.

    Hypotheses are drawn differently from facts on purpose. A collected edge is
    thin and grey; a SUCCESSOR_OF edge this layer inferred is thick and orange;
    a clone contradiction is a red dashed line with no arrow, because it asserts
    no direction of control — only that the pair's shared artifacts are
    explained by copying. A reader must be able to tell at a glance which lines
    were observed and which were argued.

    occam: renders the whole store. Past a few hundred entities this is a
    hairball — add a subgraph filter (candidate + n hops) when a corpus gets
    there, rather than guessing a cutoff now.
    """
    from pyvis.network import Network                  # already a dependency

    graph = store.to_networkx()
    # in_line bundles vis-network into the file itself: one portable artifact
    # that opens with no network access, which is the point on an offline box.
    net = Network(height=height, width="100%", directed=True, bgcolor="#1e1e1e",
                  font_color="#eaeaea", cdn_resources="in_line",
                  heading=f"CyberTrace evidence graph · {graph.number_of_nodes()} entities, "
                          f"{graph.number_of_edges()} relationships")

    for node_id, attrs in graph.nodes(data=True):
        colour, shape, size = NODE_STYLE.get(attrs.get("etype"), DEFAULT_STYLE)
        value = attrs.get("value") or ""
        net.add_node(node_id, shape=shape, size=size, color=colour,
                     label=value if len(value) <= 28 else value[:26] + "…",
                     title=f"{attrs.get('etype')}\n{value}\n"
                           f"first seen {attrs.get('first_seen')}")

    for src, dst, attrs in graph.edges(data=True):
        rtype = attrs.get("rtype")
        weight = attrs.get("weight")
        inferred = rtype == "SUCCESSOR_OF"
        net.add_edge(src, dst, width=5 if inferred else 1,
                     color="#e67e22" if inferred else "#5a5a5a",
                     label="SUCCESSOR_OF" if inferred else None,
                     title=f"{rtype}\nfirst seen {attrs.get('first_seen')}"
                           + (f"\nscore {weight}" if inferred and weight else ""))

    # Contradictions are findings, not relationships, so they are overlaid from
    # the correlation results rather than read out of the graph.
    for flag in (results or {}).get("contradictions", []):
        ends = [store.find_entity("MARKET", url) for url in flag["markets"]]
        if all(ends) and len(ends) == 2:
            net.add_edge(ends[0], ends[1], color="#ff4d4d", width=3, dashes=True,
                         arrows="", label="CLONE", title=flag["detail"])

    net.write_html(path, notebook=False, open_browser=False)

    # pyvis inlines vis-network but its template still links bootstrap and
    # jquery from a CDN. Strip every remote reference: opening a dossier must
    # not announce itself to a third party, and nothing here needs them — the
    # graph draws from the inlined library alone.
    with open(path) as fh:
        page = fh.read()
    page = re.sub(r'<script[^>]+src="https?://[^"]+"[^>]*>\s*</script>', "", page)
    page = re.sub(r'<link[^>]+href="https?://[^"]+"[^>]*>', "", page)
    with open(path, "w") as fh:
        fh.write(page)
    return path


def run_correlation(store: EvidenceStore, min_conf: float = 0.35,
                    min_infra_markets: int = 2,
                    min_successor_score: float = 0.5) -> dict:
    """Full M5 pass. Clone guard first: its verdicts constrain everything after."""
    clones = detect_clones(store)
    contradictions = contradictions_from_clones(store, clones)
    clone_pairs = {frozenset(c["markets"]) for c in contradictions}
    windows = market_windows(store)
    aliases = username_aliases(store)

    results = {
        "operators": candidate_operators(store, min_conf=min_conf),
        "infra": candidate_infra(store, min_markets=min_infra_markets),
        "ips": candidate_ips(store, min_markets=min_infra_markets),
        "aliases": aliases,
        "successors": detect_successors(store, min_score=min_successor_score,
                                        clone_pairs=clone_pairs),
        "clones": clones,
        "contradictions": contradictions,
    }
    dossiers = [build_dossier(store, c, aliases, contradictions, windows)
                for c in results["operators"] + results["infra"] + results["ips"]]
    for rank, d in enumerate(dossiers, 1):
        d["rank"] = rank
    save_candidates(store, dossiers)
    results["dossiers"] = dossiers
    return results
