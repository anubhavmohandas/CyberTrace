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

import html
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set

from .evidence import _INDEX_SOURCES, EvidenceStore, detect_clones, utcnow
from .normalize import _registrable

# Which edges count as which funnel. Keyed on the relationship types `ingest()`
# actually writes — a funnel keyed on a type nothing produces scores every
# entity at zero while still looking like a working engine.
FUNNELS: Dict[str, Set[str]] = {
    "f1_contact":   {"USES_EMAIL", "USES_USERNAME", "USES_TELEGRAM", "USES_PHONE"},
    "f2_pgp_reuse": {"USES_PGP", "SIGNS_WITH", "SIGNED_BY", "CROSS_SIGNS"},
    "f3_crypto":    {"USES_BTC", "USES_XMR", "USES_ETH", "USES_TRX", "PART_OF_CLUSTER"},
    "f4_cross_plat": {"ASSOCIATED_WITH"},
    "f5_clearnet":  {"HOSTED_ON", "CANDIDATE_IP", "RESOLVES_TO", "BELONGS_TO_ASN",
                     "OWNED_BY", "USES_CERT", "USES_NS", "USES_ANALYTICS", "MENTIONS"},
}
# DISCOVERED_VIA is in no funnel on purpose: an index co-ranking two onions is
# provenance about how the address was found, never evidence about the site.
#
# HAS_FINGERPRINT is out for the same kind of reason and is not an oversight.
# ingest() writes it (evidence.py, gated by fingerprint_signature so only a
# hand-written banner becomes a node at all), and it is worth having in the
# graph and the dossier — but a build signature is shared *software*, and two
# markets running one stack are not two markets with one operator. Putting it
# in a funnel would score every self-hosted site in a family as the same party.
# tests/test_correlate.py::test_every_evidence_class_travels_exactly_as_far_as_claimed
# pins this, so wiring it becomes a deliberate edit rather than a quiet one.
#
# TRANSACTED_WITH and EXCHANGE_DEPOSIT are out for the same categorical reason
# shared_ip/shared_domain are gated (NON_ATTRIBUTIVE_SIGNALS below), just
# structural instead of runtime: being paid by an address is not control
# (evidence.enrich_bitcoin), and an EXCHANGE_DEPOSIT edge is an analyst's own
# citation (evidence.label_exchange), never the engine's finding. Neither can
# score a funnel or a successor pair without a labelled corpus this tool does
# not have — see wallet_exchange_paths, which reads both purely for
# reachability and is never folded into entity_funnel_profile.

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

SUCCESSOR_SIGNALS["shared_cluster"] = 1.0   # two wallets proven one by co-spend
SUCCESSOR_SIGNALS["shared_favicon"] = 0.4   # same icon served — see NON_ATTRIBUTIVE_SIGNALS

SHARED_ARTIFACTS = (
    ("shared_pgp_key", "PGP_KEY"), ("shared_btc", "BTC_ADDRESS"),
    ("shared_xmr", "XMR_ADDRESS"), ("shared_email", "EMAIL"),
    ("shared_ip", "IP"), ("shared_username", "USERNAME"),
    ("shared_analytics", "ANALYTICS_ID"), ("shared_domain", "DOMAIN"),
    ("shared_favicon", "FAVICON"),
)

# Signals that can rank a pair as a lead and can never assert a relationship,
# however many of them agree or how rare they measure. Not a weight — a
# category: what these have in common is that the thing being shared is not
# something either party had to control.
#
#   shared_domain   both pages cite one clearnet host. Whonix and Kicksecure —
#                   one operator, correct answer — are joined by twenty of
#                   these and nothing else, and any two wikis on one subject
#                   reproduce that.
#   shared_favicon  both sites serve one icon. Measured across this corpus:
#                   9 same-operator pairs against 10 same-platform ones (the
#                   five SecureDrop newsrooms shipping the template's logo).
#                   A signal at 0.47 precision must not be able to conclude
#                   anything on its own, and rarity cannot separate the two
#                   cases — the SecureDrop icon measures rare here.
#   shared_ip       both sites resolve to one address. An operator does not
#                   choose that address any more than it chooses a domain it
#                   cites — a hosting provider assigns it, and cheap/shared
#                   VPS and CDN ranges routinely put unrelated Tor operators
#                   behind the same host. Nothing in the corpus tests this
#                   (0 IP candidates in 97 captures — see runs/README.md), so
#                   there is no rarity/discrimination figure to bound it the
#                   way shared_favicon's 0.47 does; ungated, one HOSTED_ON leak
#                   on each of two unrelated markets alone scores 0.9 and
#                   asserts LINKED_TO — verified live, not hypothetical.
#                   ip_class already exists to flag TOR_RELAY/VPN_IP as
#                   arguing AGAINST operator hosting; nothing yet flags the
#                   ordinary case of two strangers sharing a hosting provider,
#                   so shared_ip is gated the same way domain and favicon are
#                   until a real cross-market case justifies scoring it.
#
# The gate is categorical rather than numeric for the reason the corpus notes
# record: a threshold that refuses these today is one corpus away from
# admitting them, while "a reference is not control" holds at any score.
NON_ATTRIBUTIVE_SIGNALS = frozenset({"shared_domain", "shared_favicon", "shared_ip"})

# Below this, an artifact is judged too common in the corpus to evidence shared
# control — see entity_discrimination. Calibrated to sit just under an artifact
# on 3 of 15 targets, which is where "several sites in one software family" and
# "two sites one operator built" separate in practice.
COMMON_ARTIFACT_FLOOR = 0.5

# How much each relationship implies the market CONTROLS the thing, rather than
# merely points at it. Sharing something you control is evidence; sharing
# something you link to is not — every site on earth links to twitter.com, and
# two of them doing so is not a connection between their operators.
#
# Measured, not assumed: before this existed, an Endchan mirror and a Riseup
# onion scored 0.51 as a successor pair because both donation pages linked to
# www.paypal.com and en.bitcoin.it. Commonness alone could not catch it — in a
# 17-target corpus those two domains are genuinely uncommon. The relationship
# type is what says the link means nothing.
CONTEXT_WEIGHT = {
    "MENTIONS": 0.15,          # a clearnet host the page references
    "LINKS_TO": 0.2,           # an onion the page links to
    "DISCOVERED_VIA": 0.0,     # an index co-ranking: provenance, never evidence
    "CANDIDATE_IP": 0.6,       # favicon/Shodan pivot — a lead, not a fact
}
DEFAULT_CONTEXT = 1.0          # publishing a key, address or mailbox is control

# Pairs scoring between this and min_score are reported as leads with no edge:
# visible to an analyst, invisible to anything that reads the graph as fact.
# A display floor, not a claim boundary — roughly "one moderate weak signal" —
# so lowering it shows more leads and never turns anything into an assertion.
LEAD_FLOOR = 0.10


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


def _key_created_at(store: EvidenceStore, entity_id: str) -> Optional[datetime]:
    """A PGP_KEY entity's own creation time, from the metadata evidence.ingest
    wrote off the packet bytes (see normalize.pgp_key_times) — never from
    first_seen/last_seen, which record when WE observed it, not when the key
    was made. None when unavailable, same as any other missing timestamp."""
    row = _entity(store, entity_id)
    if not row:
        return None
    meta = json.loads(row["metadata"] or "{}")
    return _parse_ts(meta.get("key_created_at"))


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


def entity_discrimination(store: EvidenceStore) -> Dict[str, float]:
    """entity_id -> how much sharing it actually distinguishes, in (0, 1].

    Inverse document frequency over targets. An artifact seen on one or two
    sites in a corpus of fifteen is close to unique and is worth its full weight;
    one seen on nine is furniture — a mail platform's own domain, a keyserver's
    key, the software family's contact address — and weighting it the same is
    exactly how "everyone in this ecosystem" becomes "one operator".

    This replaces the stoplist reflex. A blocklist has to name every piece of
    furniture in advance and goes stale; commonness is measured from the corpus
    in front of it, so a new platform's boilerplate is discounted the first time
    it shows up on enough sites. The two are complementary, not redundant:
    normalize.py still refuses page furniture that must never become an entity
    at all, while this decides what an entity's sharing is worth.

    Returns 1.0 for everything when the corpus is too small to judge (< 3
    targets): with two markets, "on both" is the signal, not a commonness
    finding, and dividing it away would silence the only evidence there is.

    An address is scored on its DOMAIN's commonness, not its own. Per-entity IDF
    cannot see the difference between `support@dnmx.cc` on the two DNMX onions
    and `support@onionmail.info` on two of the twenty-odd independently-run
    OnionMail servers: both are one string on two targets, so both score alike
    and the second becomes an operator spanning two markets. What separates them
    is not in the mailbox, it is in the domain — `onionmail.info` is attested
    across 28 targets of this corpus, `dnmx.cc` across exactly the pair that
    owns it. Measured, not listed: no platform has to be named in advance.
    """
    n_targets = (store._one("SELECT COUNT(*) AS n FROM targets WHERE url != ?",
                            (DERIVED_TARGET,)) or {"n": 0})["n"]
    rows = store._all(
        "SELECT o.entity_id, COUNT(DISTINCT s.target_id) AS df FROM observations o "
        "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        "JOIN targets t ON t.target_id = s.target_id "
        "WHERE t.url != ? AND s.status='OK' GROUP BY o.entity_id", (DERIVED_TARGET,))
    if n_targets < 3:
        return {r["entity_id"]: 1.0 for r in rows}
    scale = math.log(n_targets)

    def idf(df: int) -> float:
        return round(min(1.0, max(0.05, math.log(n_targets / max(1, df)) / scale)), 4)

    disc = {r["entity_id"]: idf(r["df"]) for r in rows}

    # Second pass for addresses only. A domain's reach is whatever bears it —
    # the DOMAIN entity a site links, or another mailbox at the same domain —
    # so both types are counted, and the widest reach wins.
    hosts = store._all(
        "SELECT e.entity_id, e.etype, e.normalized_value AS value, "
        "COUNT(DISTINCT s.target_id) AS df FROM entities e "
        "JOIN observations o ON o.entity_id = e.entity_id "
        "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        "JOIN targets t ON t.target_id = s.target_id "
        "WHERE e.etype IN ('EMAIL','DOMAIN') AND t.url != ? AND s.status='OK' "
        "GROUP BY e.entity_id", (DERIVED_TARGET,))
    reach: Dict[str, int] = {}
    for row in hosts:
        domain = _registrable(row["value"].rsplit("@", 1)[-1])
        reach[domain] = max(reach.get(domain, 0), row["df"])
    for row in hosts:
        if row["etype"] != "EMAIL":
            continue
        domain = _registrable(row["value"].rsplit("@", 1)[-1])
        disc[row["entity_id"]] = min(disc.get(row["entity_id"], 1.0),
                                     idf(reach[domain]))
    return disc


# A recorded verdict is a measured correction, not a prior, so it multiplies
# discrimination the same way commonness does rather than adding a second
# weight everywhere entity_funnel_profile is called. Biased toward damping:
# a REJECTED/BENIGN verdict cuts harder than a CONFIRMED one lifts, so a
# wrong analyst call can only ever pull a false positive down, never manufacture
# a new one by over-trusting a single confirmation.
FEEDBACK_WEIGHT = {"CONFIRMED": 1.15, "MALICIOUS": 1.15,
                   "BENIGN": 0.4, "REJECTED": 0.25, "UNKNOWN": 1.0}


def feedback_discrimination(store: EvidenceStore) -> Dict[str, float]:
    """entity_id -> multiplier from the most recent analyst_feedback outcome
    recorded against any candidate this entity has been part of.

    Empty (no key for any entity) on every store with zero recorded feedback
    -- which is every corpus run to date -- so folding this into
    run_correlation changes no existing score. See FEEDBACK_WEIGHT.

    occam: most-recent-outcome-wins is the whole rule (rows are read oldest
    first, so a later row overwrites an earlier one in the dict). Upgrade to
    a recency-weighted blend of every verdict if a corpus of reversed calls
    on the same entity ever shows losing the earlier one matters.
    """
    rows = store._all(
        "SELECT c.entity_id, af.outcome FROM analyst_feedback af "
        "JOIN candidates c ON c.candidate_id = af.candidate_id "
        "ORDER BY af.recorded_at")
    out: Dict[str, float] = {}
    for row in rows:
        out[row["entity_id"]] = FEEDBACK_WEIGHT.get(row["outcome"], 1.0)
    return out


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
    """Targets where this entity was actually observed (not merely linked).

    OK snapshots only. A DISCOVERY row means an index answered a query naming
    the target, so counting it here would let a site nobody reached still hold
    artifacts — and `min_markets`, the floor that stops one observation becoming
    an attribution, would be cleared by two search results.
    """
    rows = store._all(
        "SELECT DISTINCT s.target_id FROM observations o "
        "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        "JOIN targets t ON t.target_id = s.target_id "
        "WHERE o.entity_id=? AND t.url != ? AND s.status='OK'",
        (entity_id, DERIVED_TARGET))
    return sorted(r["target_id"] for r in rows)


def _observation_confidence(store: EvidenceStore, obs_ids: List[str]) -> Dict[str, float]:
    if not obs_ids:
        return {}
    marks = ",".join("?" * len(obs_ids))
    return {r["observation_id"]: r["confidence"] for r in store._all(
        f"SELECT observation_id, confidence FROM observations "
        f"WHERE observation_id IN ({marks})", tuple(obs_ids))}


def entity_funnel_profile(store: EvidenceStore, entity_id: str,
                          discrimination: Optional[Dict[str, float]] = None) -> dict:
    """Per-funnel best confidence plus the observations backing it.

    Strength comes from the observation, not the edge: `_link()` writes edges
    without a weight, so scoring on `relationships.weight` would compare None to
    a float on real ingested data and rank nothing.

    The whole profile is then scaled by how discriminating this entity is across
    the corpus, so a platform's shared contact address cannot out-score an
    operator's reused key merely by appearing everywhere.
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
        conf *= CONTEXT_WEIGHT.get(rtype, DEFAULT_CONTEXT)
        slot = funnels[funnel]
        slot["best_conf"] = max(slot["best_conf"], conf)
        slot["evidence_ids"] += obs_ids
        slot["rel_types"].add(rtype)

    # noisy-OR: independent funnels compound, so convergent weak signals beat a
    # lone strong claim. Capped per funnel so nothing reaches certainty.
    weight = 1.0 if discrimination is None else discrimination.get(entity_id, 1.0)
    residual = 1.0
    for name, slot in funnels.items():
        residual *= 1.0 - min(0.99, slot["best_conf"] * FUNNEL_WEIGHT[name] * weight)
        slot["rel_types"] = sorted(slot["rel_types"])   # keep the result JSON-clean
    active = {f: s for f, s in funnels.items() if s["best_conf"] > 0}
    return {
        "funnels": active,
        "markets": markets_for_entity(store, entity_id),
        "total_conf": round(1.0 - residual, 4),
        "n_funnels": len(active),
        "discrimination": round(weight, 4),
    }


def _candidate(store: EvidenceStore, role: str, row, profile: dict) -> dict:
    return {
        "role": role, "etype": row["etype"], "entity_id": row["entity_id"],
        "value": row["normalized_value"], "score": profile["total_conf"],
        "n_funnels": profile["n_funnels"], "markets": profile["markets"],
        "n_markets": len(profile["markets"]), "funnels": profile["funnels"],
        "discrimination": profile.get("discrimination", 1.0),
    }


def candidate_operators(store: EvidenceStore, min_conf: float = 0.35,
                        min_markets: int = 2,
                        discrimination: Optional[Dict[str, float]] = None) -> List[dict]:
    """Ranked OPERATOR candidates: keys, emails, handles.

    Convergence across markets is what makes an artifact an attribution claim.
    A strong key on one site is evidence about that site and nothing more — it
    stays in the graph as an entity, but promoting it to an operator candidate
    asserts a link between markets on the strength of a single observation.
    """
    rows = store._all("SELECT entity_id, etype, normalized_value FROM entities "
                      "WHERE etype IN ('PGP_KEY','EMAIL','USERNAME')")
    # The fold has to carry observations, not just score. A market that cited a
    # key only by its long id is still a market that saw that key, and counting
    # it against the alias node instead of the fingerprint would let the market
    # floor discard exactly the cross-market convergence it exists to find.
    canon = {r["entity_id"]: canonical_entity_key(store, r["entity_id"]) for r in rows}
    folded = defaultdict(list)
    for entity_id, key in canon.items():
        folded[key].append(entity_id)

    out = []
    for row in rows:
        entity_id = row["entity_id"]
        if canon[entity_id] != entity_id:
            continue                        # alias: score belongs to the fingerprint
        profile = entity_funnel_profile(store, entity_id, discrimination)
        # Markets that PUBLISHED this identity, not every capture the string
        # turned up in. An OPERATOR candidate asserts that one party is behind
        # these sites, so the market floor has to count sites that put the
        # artifact forward as their own — a certifier id embedded in someone
        # else's key block, or a quoted address, is observed on the target and
        # attributed to nobody. INFRA and IP deliberately do NOT get this
        # filter: shared references are what they are made of.
        profile["markets"] = sorted({m for eid in folded[entity_id]
                                     for m in markets_for_entity(store, eid)
                                     if _market_uses(store, _market_entity(store, m), eid)})
        if profile["total_conf"] >= min_conf and len(profile["markets"]) >= min_markets:
            out.append(_candidate(store, "OPERATOR", row, profile))
    return sorted(out, key=lambda c: (-c["score"], -c["n_funnels"]))


def candidate_infra(store: EvidenceStore, min_markets: int = 2,
                    discrimination: Optional[Dict[str, float]] = None,
                    min_conf: float = 0.35) -> List[dict]:
    """Infrastructure shared by 2+ markets — the handoff points worth a warrant.

    The score floor matters as much as the market floor. Two markets linking to
    the same payment processor satisfies "shared by 2+ markets" and is not
    infrastructure either of them runs; without the floor a dossier opens with a
    page of LOW candidates named twitter.com and t.me, and the reader learns to
    skim past the section where the real one will eventually appear.
    """
    out = []
    for row in store._all(
            "SELECT entity_id, etype, normalized_value FROM entities WHERE etype IN "
            "('CERTIFICATE','NAMESERVER','ASN','HOSTING_PROVIDER','DOMAIN','ANALYTICS_ID')"):
        profile = entity_funnel_profile(store, row["entity_id"], discrimination)
        if len(profile["markets"]) >= min_markets and profile["total_conf"] >= min_conf:
            out.append(_candidate(store, "INFRA", row, profile))
    return sorted(out, key=lambda c: (-c["score"], -c["n_markets"]))


def candidate_ips(store: EvidenceStore, min_markets: int = 2,
                  discrimination: Optional[Dict[str, float]] = None,
                  min_conf: float = 0.35) -> List[dict]:
    """IPs converging across markets. ip_class is carried through from metadata
    because a VPN egress and an origin host warrant very different next steps."""
    out = []
    for row in store._all(
            "SELECT entity_id, etype, normalized_value, metadata FROM entities "
            "WHERE etype='IP'"):
        profile = entity_funnel_profile(store, row["entity_id"], discrimination)
        if len(profile["markets"]) < min_markets or profile["total_conf"] < min_conf:
            continue
        meta = json.loads(row["metadata"] or "{}")
        out.append(_candidate(store, "IP", row, profile) |
                   {"ip_class": meta.get("ip_class", "UNKNOWN"),
                    "asn": meta.get("asn"), "org": meta.get("org")})
    return sorted(out, key=lambda c: (-c["score"], -c["n_markets"]))


# --- crypto clusters ---------------------------------------------------------

def crypto_clusters(store: EvidenceStore) -> Dict[str, str]:
    """address entity_id -> cluster label, over PART_OF_CLUSTER components.

    Co-spend edges are pairwise; ownership is transitive, so the wallet is the
    connected component. Computed at read time rather than stored as a
    CRYPTO_CLUSTER node on purpose: a cluster is a *conclusion* that grows every
    time another transaction is seen, and a persisted node would either freeze
    at whatever was known first or need merge bookkeeping nothing else here
    would use. The edges are the evidence; this is the view over them.

    Label is the smallest member's value, so a component reads as a wallet an
    analyst can look up rather than an opaque id.

    occam: union by chain, no rank/compression — components here are handfuls of
    addresses. Also no exchange filtering: a deposit address co-spent by an
    exchange's hot wallet would pull unrelated customers into one component, so
    every consumer of this must carry that caveat rather than treat a cluster as
    proof of one operator.
    """
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in store._all(
            "SELECT source_entity_id AS a, target_entity_id AS b FROM relationships "
            "WHERE rtype='PART_OF_CLUSTER' AND status='ACTIVE'"):
        ra, rb = find(r["a"]), find(r["b"])
        if ra != rb:
            parent[rb] = ra

    members: Dict[str, List[str]] = defaultdict(list)
    for node in list(parent):
        members[find(node)].append(node)

    values = {r["entity_id"]: r["normalized_value"] for r in store._all(
        "SELECT entity_id, normalized_value FROM entities")} if parent else {}
    out: Dict[str, str] = {}
    for root, group in members.items():
        if len(group) < 2:
            continue
        label = min(values.get(g, g) for g in group)
        for node in group:
            out[node] = f"cluster:{label}"
    return out


# --- wallet -> exchange reachability -----------------------------------------

EXCHANGE_HOP_DECAY = 0.75  # prior, not calibrated -- see FUNNEL_WEIGHT's own comment


def wallet_exchange_paths(store: EvidenceStore, max_hops: int = 4) -> List[dict]:
    """For every address with a path to an analyst-labeled exchange address,
    over TRANSACTED_WITH + PART_OF_CLUSTER edges (undirected), the shortest hop
    count, decayed confidence, and the evidence resolving each hop.

    Never folded into entity_funnel_profile / candidate_operators: reachability
    is not control, and a wallet must never out-rank an OPERATOR candidate
    merely because a path to a labeled exchange exists. This is a report for an
    analyst to act on (see evidence.label_exchange), not a claim the engine
    makes on its own.
    """
    # "evidence_ids" throughout this module means observation ids (what a
    # relationship's evidence row resolves to, per entity_funnel_profile) --
    # not the `evidence` table's own primary key -- so investigator._finalize
    # can resolve every id here the same way it resolves any other claim.
    adjacency: Dict[str, List[tuple]] = defaultdict(list)
    for r in store._all(
            "SELECT r.source_entity_id AS a, r.target_entity_id AS b, "
            "       ev.observation_ids FROM relationships r "
            "LEFT JOIN evidence ev ON ev.relationship_id = r.rel_id "
            "WHERE r.rtype IN ('TRANSACTED_WITH','PART_OF_CLUSTER') AND r.status='ACTIVE'"):
        obs_ids = json.loads(r["observation_ids"] or "[]")
        adjacency[r["a"]].append((r["b"], obs_ids))
        adjacency[r["b"]].append((r["a"], obs_ids))

    exchange_of: Dict[str, tuple] = {}
    for r in store._all(
            "SELECT r.source_entity_id AS addr, e.normalized_value AS exchange, "
            "       ev.observation_ids FROM relationships r "
            "JOIN entities e ON e.entity_id = r.target_entity_id "
            "LEFT JOIN evidence ev ON ev.relationship_id = r.rel_id "
            "WHERE r.rtype='EXCHANGE_DEPOSIT' AND r.status='ACTIVE'"):
        exchange_of[r["addr"]] = (r["exchange"], json.loads(r["observation_ids"] or "[]"))

    values = {r["entity_id"]: r["normalized_value"] for r in store._all(
        "SELECT entity_id, normalized_value FROM entities "
        "WHERE etype IN ('BTC_ADDRESS','ETH_ADDRESS','TRX_ADDRESS')")}

    out = []
    for start in values:
        if start in exchange_of:
            exchange, obs_ids = exchange_of[start]
            out.append({"entity_id": start, "value": values[start], "exchange": exchange,
                       "hops": 0, "confidence": 1.0, "path": [start],
                       "evidence_ids": obs_ids})
            continue

        visited = {start}
        frontier = [(start, [start], [])]
        found = None
        for hop in range(1, max_hops + 1):
            next_frontier = []
            for node, path, ev_ids in frontier:
                for peer, hop_obs in adjacency.get(node, []):
                    if peer in visited:
                        continue
                    visited.add(peer)
                    new_path = path + [peer]
                    new_ev = ev_ids + hop_obs
                    if peer in exchange_of:
                        exchange, label_obs = exchange_of[peer]
                        found = {"entity_id": start, "value": values[start], "exchange": exchange,
                                "hops": hop, "confidence": round(EXCHANGE_HOP_DECAY ** hop, 4),
                                "path": new_path,
                                "evidence_ids": new_ev + label_obs}
                        break
                    next_frontier.append((peer, new_path, new_ev))
                if found:
                    break
            if found:
                break
            frontier = next_frontier
        if found:
            out.append(found)

    return sorted(out, key=lambda w: (w["hops"], w["entity_id"]))


_TRACE_CHAIN_ETYPES = {"bitcoin": "BTC_ADDRESS", "ethereum": "ETH_ADDRESS",
                       "tron": "TRX_ADDRESS"}


def wallet_trace_report(store: EvidenceStore, address: str, max_hops: int = 4) -> Optional[dict]:
    """One traced wallet's path to the nearest analyst-labeled exchange (see
    wallet_exchange_paths), plus every piece of third-party evidence already
    on record for each address along that path -- dataset labels, abuse
    reports, GraphSense tagpack hits -- each cited to the specific address it
    came from.

    This is the investigation-report layer, built entirely by reading
    metadata evidence.enrich_bitcoin already wrote for addresses that were
    themselves searched; it computes NO new score. `flags` is a list of exact
    findings, not a risk_level or confidence composite -- inventing either
    would be exactly the kind of unearned precision this codebase refuses
    elsewhere (see EXCHANGE_HOP_DECAY's own "prior, not calibrated" note, and
    evidence.enrich_bitcoin's ellipticpp_*/chainabuse_* non-attributive
    discipline). An analyst, or the grounded Investigator, reads `flags` and
    judges risk themselves -- the engine never becomes the attribution
    decision-maker.

    Only hops that were themselves independently searched carry metadata; a
    hop discovered purely as a counterparty (never itself investigated) has
    none, and this is silent about it rather than implying absence-of-risk.

    Returns None if `address` was never searched into this store at all.
    """
    from .detector import detect_input_type
    _, chain = detect_input_type(address)
    etype = _TRACE_CHAIN_ETYPES.get(chain, "BTC_ADDRESS")
    start_id = store.find_entity(etype, address)
    if start_id is None:
        return None

    hit = next((w for w in wallet_exchange_paths(store, max_hops=max_hops)
               if w["entity_id"] == start_id), None)
    path_ids = hit["path"] if hit else [start_id]

    marks = ",".join("?" * len(path_ids))
    by_id = {r["entity_id"]: r for r in store._all(
        f"SELECT entity_id, raw_value, metadata FROM entities WHERE entity_id IN ({marks})",
        tuple(path_ids))}

    flags = []
    for eid in path_ids:
        row = by_id.get(eid)
        if row is None:
            continue
        meta = json.loads(row["metadata"] or "{}")
        addr = row["raw_value"]
        if meta.get("reported_scam"):
            cats = meta.get("chainabuse_scam_categories")
            flags.append(f"{addr}: reported for abuse"
                         + (f" ({', '.join(cats)})" if cats else ""))
        if meta.get("ellipticpp_dataset_label_name") == "illicit":
            flags.append(f"{addr}: Elliptic++ dataset label = illicit")
        packs = meta.get("exchange_tag_packs")
        if packs:
            flags.append(f"{addr}: GraphSense tagpack(s): {', '.join(packs)}")

    if hit:
        if hit["hops"] > 0:
            flags.append(f"{hit['hops']} hop(s) of layering before reaching a labeled exchange")
        flags.append(f"reached analyst-labeled exchange: {hit['exchange']} "
                     f"(reachability confidence {hit['confidence']:.2f})")

    return {
        "entity_id": start_id,
        "address": by_id[start_id]["raw_value"] if start_id in by_id else address,
        "path": [by_id[eid]["raw_value"] if eid in by_id else eid for eid in path_ids],
        "hops": hit["hops"] if hit else None,
        "exchange": hit["exchange"] if hit else None,
        "exchange_confidence": hit["confidence"] if hit else None,
        "flags": flags,
        "evidence_ids": hit["evidence_ids"] if hit else [],
    }


# --- successors --------------------------------------------------------------

def market_artifact_map(store: EvidenceStore) -> Dict[str, Dict[str, Set[str]]]:
    """target_id -> {etype: {entity_id}} over everything observed there.

    OK snapshots only, for the same reason as markets_for_entity: pairs are
    built from this map, and a target that never answered has nothing to pair
    ON. Read off DISCOVERY rows, two dark markets that happened to co-rank
    beside one link directory become a pair with shared artifacts.
    """
    out: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    for r in store._all(
            "SELECT s.target_id, o.entity_id, e.etype FROM observations o "
            "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
            "JOIN entities e ON e.entity_id = o.entity_id "
            "JOIN targets t ON t.target_id = s.target_id "
            "WHERE t.url != ? AND s.status='OK'", (DERIVED_TARGET,)):
        out[r["target_id"]][r["etype"]].add(r["entity_id"])
    return out


def market_windows(store: EvidenceStore) -> Dict[str, dict]:
    """target_id -> url plus the first/last time the site was seen LIVE.

    Index snapshots are excluded. An index answering for a dead onion dates the
    index, not the site, and these windows decide succession direction — read
    off an index, a market that has been down for a year still looks live today
    and every successor hypothesis about it inverts.
    """
    marks = ",".join("?" * len(_INDEX_SOURCES))
    rows = store._all(
        "SELECT t.target_id, t.url, MIN(s.observed_at) AS first_seen, "
        "       MAX(s.observed_at) AS last_seen "
        "FROM targets t JOIN snapshots s ON s.target_id = t.target_id "
        f"WHERE t.url != ? AND s.collector NOT IN ({marks}) AND s.status='OK' "
        "GROUP BY t.target_id", (DERIVED_TARGET, *sorted(_INDEX_SOURCES)))
    down = store.down_windows()
    return {r["target_id"]: {
        "url": r["url"],
        "first": _parse_ts(r["first_seen"]), "last": _parse_ts(r["last_seen"]),
        "down_since": down.get(r["target_id"])}
        for r in rows}


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


def _domain_groups(store: EvidenceStore, entity_ids: Set[str]) -> List[List[str]]:
    """Shared DOMAIN entities bucketed by registrable domain, longest first.

    `_registrable` is normalize's own last-two-labels rule, reused rather than
    re-derived so a host is grouped the same way it was stoplisted.
    """
    groups: Dict[str, List[str]] = defaultdict(list)
    for entity_id in entity_ids:
        row = _entity(store, entity_id)
        if row:
            groups[_registrable(row["normalized_value"])].append(entity_id)
    return sorted((sorted(g) for g in groups.values()), key=len, reverse=True)


# What an artifact is worth when NOTHING joins the market to it. It was seen in
# a capture of the site, and that is all that is known — so it is read as the
# weakest thing an edge can mean, not the strongest.
#
# The inversion this replaces was the worst false-attribution path in the
# engine. Certifier key ids are observed against the market's snapshot (they are
# inside the bytes of the key block, so the observation is true) while carrying
# no market edge, because they are a property of the KEY. Read at full control
# weight, two unrelated sites whose own distinct keys happened to be certified
# by one ordinary web-of-trust signer scored `shared_pgp_key` 1.3 AND
# `signed_by` 1.5 — a noisy-OR of ~0.9999 and a directional SUCCESSOR_OF edge
# between sites with nothing whatever to do with each other.
UNJOINED_CONTEXT = CONTEXT_WEIGHT["MENTIONS"]


def _edge_context(store: EvidenceStore, market_entity: Optional[str],
                  entity_id: str) -> float:
    """Strongest control implied by any edge joining this market to this thing.

    No edge means no demonstrated control, so it floors at UNJOINED_CONTEXT
    rather than defaulting to it: absence of evidence is not evidence.
    """
    if not market_entity:
        return UNJOINED_CONTEXT
    rows = store._all(
        "SELECT rtype FROM relationships WHERE status='ACTIVE' "
        "AND ((source_entity_id=? AND target_entity_id=?) "
        "  OR (source_entity_id=? AND target_entity_id=?))",
        (market_entity, entity_id, entity_id, market_entity))
    return max((CONTEXT_WEIGHT.get(r["rtype"], DEFAULT_CONTEXT) for r in rows),
               default=UNJOINED_CONTEXT)


def _market_uses(store: EvidenceStore, market_entity: Optional[str],
                 entity_id: str) -> bool:
    """Did this market publish this artifact as its own, rather than merely
    reproduce it? True only for an edge that asserts control."""
    return _edge_context(store, market_entity, entity_id) >= DEFAULT_CONTEXT


def _observations_of(store: EvidenceStore, target_id: str, entity_id: str) -> List[str]:
    return [r["observation_id"] for r in store._all(
        "SELECT o.observation_id FROM observations o "
        "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        "WHERE s.target_id=? AND o.entity_id=?", (target_id, entity_id))]


def _pair_signals(store: EvidenceStore, artifacts: dict, windows: dict,
                  a_id: str, b_id: str,
                  discrimination: Optional[Dict[str, float]] = None,
                  clusters: Optional[Dict[str, str]] = None) -> List[dict]:
    """Every successor signal joining two markets, with its evidence.

    Each shared artifact's weight is scaled by how discriminating that artifact
    is across the corpus (see entity_discrimination). Three mail servers in one
    software family share the family's contact address; two sites one operator
    built share something only they have. Without the scaling those two look
    identical here, which is precisely how an ecosystem becomes an "operator".
    """
    a, b = artifacts[a_id], artifacts[b_id]
    discrimination = discrimination or {}
    clusters = clusters or {}
    signals = []

    market_a, market_b = _market_entity(store, a_id), _market_entity(store, b_id)

    # The predecessor's observation window, computed once so the shared-PGP-key
    # check below and the temporal_handoff signal further down read the same
    # notion of "when did the earlier market stop being relevant". None when
    # either market has no capture window at all — no ordering, no check, same
    # as temporal_handoff's own gate.
    wa, wb = windows.get(a_id) or {}, windows.get(b_id) or {}
    predecessor_end = None
    if wa.get("first") and wb.get("first"):
        pred_window = wa if wa["first"] <= wb["first"] else wb
        predecessor_end = _parse_ts(pred_window.get("down_since")) or pred_window.get("last")

    # A key on A signing a key on B is the strongest directional evidence there
    # is: it is the outgoing operator vouching for the incoming one.
    #
    # "On A" has to mean a key A publishes as its own. Every certifier inside a
    # published key block is also observed on the target — that is honest
    # provenance, the id really is in those bytes — so without this gate the
    # signal fired whenever some third party had signed B's key and its id
    # happened to sit inside A's key too. One shared web-of-trust signature
    # between strangers then read as "the operator of A vouched for B", at the
    # heaviest weight in the table and with a direction attached.
    for key_a in a.get("PGP_KEY", set()):
        if not _market_uses(store, market_a, key_a):
            continue
        for key_b in b.get("PGP_KEY", set()):
            if not _market_uses(store, market_b, key_b):
                continue
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
        shared = a.get(etype, set()) & b.get(etype, set())
        # Nine hosts under one organisation's domain are one fact, not nine.
        # The noisy-OR below assumes independent evidence, so leaving them
        # separate compounds a single co-reference into a near-certainty — the
        # same arithmetic that would rank "both link to mail.example.com and
        # lists.example.com" above a shared PGP key.
        for entities in (_domain_groups(store, shared) if etype == "DOMAIN"
                         else [[e] for e in shared]):
            entity_id = entities[0]
            row = _entity(store, entity_id)
            rarity = min(discrimination.get(e, 1.0) for e in entities)
            # Weakest link: if either market only *references* the thing, the
            # pair's shared use of it is a reference, whatever the other side did.
            context = min(_edge_context(store, market_a, entity_id),
                          _edge_context(store, market_b, entity_id))
            if len(entities) > 1:
                # A whole namespace in common is a stronger reference than one
                # link — an operator's own hosts spread across subdomains, while
                # a third-party service gets cited once or twice.
                context = min(1.0, context * (2.0 if len(entities) > 2 else 1.5))
            if context <= 0:
                continue
            # A key created AFTER the predecessor's window closed could not
            # have been on the predecessor's page while it was live: whatever
            # this pair's shared use of it means, it is not the ordinary
            # "operator carried the key from A to B" reading, and it must not
            # earn the weight that reading gets. key_created_at comes straight
            # from the key's own packet bytes (see evidence.ingest), never from
            # when either market happened to be crawled — an unavailable
            # timestamp (no armored block, unparseable packet) leaves this
            # False and the signal scores exactly as it always has.
            key_created = None
            temporal_contradiction = False
            if etype == "PGP_KEY" and predecessor_end is not None:
                key_created = _key_created_at(store, entity_id)
                temporal_contradiction = bool(key_created and key_created > predecessor_end)
            label = row["normalized_value"][:48] + (
                f" (+{len(entities) - 1} more under the same domain)"
                if len(entities) > 1 else "")
            weight = 0.0 if temporal_contradiction else SUCCESSOR_SIGNALS[name] * rarity * context
            signals.append({
                "signal": name, "weight": weight,
                "direction": None, "discrimination": round(rarity, 3),
                "context": round(context, 3),
                # Whether this signal may support an EDGE, as opposed to a rank.
                # `context` already prices how much the pair's sharing implies
                # control; below full control weight the pair merely referenced
                # the thing, and a pile of references is the one shape that
                # reaches the assertion threshold on arithmetic no single signal
                # supports. See detect_successors. A temporal contradiction is
                # never attributive either, whatever context says: the shared
                # artifact cannot evidence control carried across this pair.
                "attributive": context >= DEFAULT_CONTEXT and not temporal_contradiction,
                "evidence": [o for e in entities
                             for o in (_observations_of(store, a_id, e)
                                       + _observations_of(store, b_id, e))],
                "detail": f"{etype} {label} on both"
                          + ("" if rarity >= COMMON_ARTIFACT_FLOOR
                             else f" (common across the corpus, weight x{rarity:.2f})")})
            if temporal_contradiction:
                # Recorded as its own zero-weight, contradicting signal — same
                # pattern as temporal_overlap below — so the objection is
                # visible in the pair's signal list and reaches a Finding via
                # contradictions_from_key_temporal, rather than only silently
                # zeroing the shared_pgp_key weight above. Nothing here deletes
                # the underlying USES_PGP/SIGNS_WITH relationship or its
                # observations; this only withholds successor-strength scoring
                # for THIS pair.
                signals.append({
                    "signal": "pgp_key_temporal_contradiction", "weight": 0.0,
                    "direction": None, "evidence": [], "contradicts": True,
                    "attributive": False,
                    "detail": (f"{label} was created {key_created.date()} — after "
                               f"the predecessor market's observation window closed "
                               f"({predecessor_end.date()}) — shared use of this key "
                               f"cannot evidence temporal reuse between these markets")})

    # Different addresses, one wallet: co-spend proves the same party signed for
    # both, which is a financial link between the markets even though neither
    # published the other's address.
    if clusters:
        for etype in ("BTC_ADDRESS", "XMR_ADDRESS", "ETH_ADDRESS"):
            shared = a.get(etype, set()) & b.get(etype, set())
            in_a = {clusters[e] for e in a.get(etype, set()) if e in clusters}
            in_b = {clusters[e] for e in b.get(etype, set()) if e in clusters}
            for label in (in_a & in_b):
                if any(clusters.get(e) == label for e in shared):
                    continue                # already scored as a shared address
                signals.append({
                    "signal": "shared_cluster", "weight": SUCCESSOR_SIGNALS["shared_cluster"],
                    "direction": None, "evidence": [],
                    "detail": f"addresses on both sides co-spend into {label}"})

    # Pairs arrive ordered by target_id, which is a hash — so which market is
    # older has to be decided here. Reading the gap in the arbitrary pair order
    # turns a clean handoff into an "overlap", which argues against succession
    # rather than for it, and costs the pair its directional hint.
    # (wa/wb computed once, above, alongside predecessor_end.)
    if wa.get("first") and wb.get("first") and wa.get("last") and wb.get("last"):
        older, newer, direction = ((wa, wb, "a_to_b") if wa["first"] <= wb["first"]
                                   else (wb, wa, "b_to_a"))
        gap = newer["first"] - older["last"]
        if gap > timedelta(0):
            # A handoff needs the predecessor to have actually gone dark. A gap
            # on its own only means we visited one site before the other, and
            # scoring that is how a corpus collected alphabetically over an
            # afternoon produces a chain of successor claims between unrelated
            # markets — measured, not hypothetical: it produced eight.
            #
            # The window runs from the TAKEDOWN, not from our last crawl of the
            # predecessor: a market last visited in January, seen dark in June
            # and replaced in August is a two-month handoff, and measuring the
            # seven months back to our own crawl would discard it.
            dark = _parse_ts(older.get("down_since"))
            since = newer["first"] - max(older["last"], dark) if dark else None
            if since is not None and timedelta(0) < since <= timedelta(days=90):
                signals.append({
                    "signal": "temporal_handoff",
                    "weight": SUCCESSOR_SIGNALS["temporal_handoff"],
                    "direction": direction, "evidence": [],
                    "detail": (f"{newer['url']} first captured {since.days}d after "
                               f"{older['url']} was observed dark on "
                               f"{older['down_since'][:10]}")})
        else:
            # Overlap argues AGAINST succession — a market does not succeed one
            # that was still live — so it carries no score. It stays in the
            # signal list because detect_successors turns it into a recorded
            # objection: dropping it here would lose the fact that the pair was
            # checked and failed the temporal test.
            signals.append({
                "signal": "temporal_overlap", "weight": 0.0,
                "direction": None, "evidence": [], "contradicts": True,
                "detail": "capture windows overlap — both live at once, so one "
                          "cannot be the other's successor"})
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
                      clone_pairs: Optional[Set[frozenset]] = None,
                      discrimination: Optional[Dict[str, float]] = None) -> List[dict]:
    """Ranked market-to-market hypotheses, each written as the edge its evidence
    actually supports:

      SUCCESSOR_OF  B replaced A — needs a directional signal: a handoff after A
                    was observed dark, or A's key certifying B's.
      LINKED_TO     the two are joined by artifacts one party controls, with
                    nothing saying which came first. Most real pairs land here,
                    including two sites one operator runs at the same time.

    A pair the clone guard called CLONE_SUSPECT gets no edge at all, however
    strongly it scores: every artifact it shares is explained by the later site
    copying the earlier one, and promoting that to a relationship attributes a
    clone's activity to its victim.
    """
    artifacts = market_artifact_map(store)
    windows = market_windows(store)
    clone_pairs = clone_pairs or set()
    clusters = crypto_clusters(store)
    results = []

    for a_id, b_id in _candidate_pairs(artifacts):
        signals = _pair_signals(store, artifacts, windows, a_id, b_id,
                                discrimination, clusters)
        # Timing corroborates a successor claim; it never makes one. Two markets
        # whose windows happen to line up share nothing that could evidence one
        # operator, so without an artifact in common there is no hypothesis here
        # to rank — only a coincidence of when we happened to look.
        if not any(s["signal"] not in ("temporal_handoff", "temporal_overlap")
                   for s in signals):
            continue
        residual = 1.0
        for s in signals:
            residual *= 1.0 - min(0.99, s["weight"])
        score = round(1.0 - residual, 4)
        # References corroborate; they never make a claim — the same rule
        # timing already gets, for the same reason. CONTEXT_WEIGHT prices one
        # shared citation at 0.06 precisely because linking to a host says
        # nothing about controlling it, but twenty of them noisy-OR to 0.69 and
        # the pair is asserted on arithmetic no single signal supports.
        #
        # Measured: Whonix and Kicksecure — one operator, correct answer — were
        # linked by twenty shared citations (unix.meta.stackexchange.com,
        # mediawiki.org, forums.openvpn.net, catb.org) and nothing else. Any two
        # wikis on one subject reproduce that, so the pair is ranked as a lead
        # and left for an analyst rather than asserted as a relationship.
        #
        # Two ways a signal fails to be attributive, and both are categorical.
        # By CLASS: a shared citation or a shared icon is not control, whatever
        # it scores. By CONTEXT: the same artifact type says different things
        # depending on the edge that joins the market to it, so an address the
        # page merely quotes and an account named by a deployment remote are
        # references too — `_pair_signals` marks those as it prices them. Keying
        # only on the class was a hole exactly the width of the next evidence
        # class: shared_username is attributive when a site publishes the handle
        # and was still attributive when the handle came off a cloned upstream
        # project's `.git/config`.
        attributive = any(s.get("attributive", True)
                          and s["signal"] not in NON_ATTRIBUTIVE_SIGNALS
                          for s in signals
                          if s["signal"] not in ("temporal_handoff", "temporal_overlap"))
        if score < min_score or not attributive:
            # Too weak to assert, too specific to throw away. A pair joined only
            # by references — both sites citing one organisation's hosts, say —
            # is a lead an analyst should see and the graph should not claim.
            # Reported without an edge, so nothing downstream can read it as a
            # relationship the tool concluded.
            if score >= LEAD_FLOOR:
                results.append({
                    "source_market": a_id, "target_market": b_id,
                    "source_url": (windows.get(a_id) or {}).get("url"),
                    "target_url": (windows.get(b_id) or {}).get("url"),
                    "score": score,
                    "suppressed": "BELOW_THRESHOLD" if score < min_score
                                  else "REFERENCES_ONLY",
                    "relation": None,
                    "signals": [s["signal"] for s in signals],
                    "signals_detail": _signal_summary(signals), "evidence_ids": []})
            continue

        urls = frozenset({(windows.get(a_id) or {}).get("url"),
                          (windows.get(b_id) or {}).get("url")})
        if urls in clone_pairs:
            results.append({"source_market": a_id, "target_market": b_id,
                            "source_url": (windows.get(a_id) or {}).get("url"),
                            "target_url": (windows.get(b_id) or {}).get("url"),
                            "score": score, "suppressed": "CLONE_SUSPECT",
                            "relation": None,
                            "signals": [s["signal"] for s in signals],
                            "signals_detail": _signal_summary(signals),
                            "evidence_ids": []})
            continue
        overlap = any(s.get("contradicts") for s in signals)

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
        # Succession is a claim about time: B replaced A. Without evidence of
        # that — a handoff after the predecessor went dark, or the old key
        # signing the new one — what the shared artifacts support is only that
        # the two are linked. Calling that SUCCESSOR_OF would put a story the
        # evidence does not tell into the graph, and a reader would carry it
        # into a warrant application.
        directional = any(s["signal"] in ("temporal_handoff", "signed_by")
                          for s in signals)
        relation = "SUCCESSOR_OF" if directional and not overlap else "LINKED_TO"
        snapshot = _derived_snapshot(store, {"pair": [src, dst], "score": score,
                                             "relation": relation,
                                             "signals": [s["detail"] for s in signals]})
        obs = store.insert_observation(
            snapshot, dst_entity, method=f"m5:{relation.lower()}", section=relation,
            context="; ".join(s["detail"] for s in signals), confidence=score)
        evidence = list(dict.fromkeys(
            [o for s in signals for o in s["evidence"]] + [obs]))
        rel = store.upsert_relationship(src_entity, dst_entity, relation,
                                        source_label="m5:correlate", weight=score)
        store.add_evidence(rel, evidence, note=f"{relation} score {score}")
        results.append({"source_market": src, "target_market": dst,
                        "source_url": (windows.get(src) or {}).get("url"),
                        "target_url": (windows.get(dst) or {}).get("url"),
                        "score": score, "suppressed": None, "rel_id": rel,
                        "relation": relation,
                        "signals": [s["signal"] for s in signals],
                        "signals_detail": _signal_summary(signals),
                        "evidence_ids": evidence})
    return sorted(results, key=lambda r: -r["score"])


def _signal_summary(signals: List[dict]) -> List[dict]:
    """Signals without their observation lists — what a reader needs to see why
    a pair scored, small enough to keep in the result JSON and in a dossier."""
    return [{"signal": s["signal"], "weight": round(s["weight"], 3),
             "discrimination": s.get("discrimination"), "detail": s["detail"]}
            for s in signals]


# --- contradictions ----------------------------------------------------------

def contradictions_from_clones(store: EvidenceStore, clones: List[dict]) -> List[dict]:
    """Clone verdicts, restated as constraints on attribution.

    A CLONE_SUSPECT pair is the standing objection to any candidate whose score
    leans on artifacts those two markets share: the reuse is copying, not shared
    control. Carried per-candidate so a dossier can never present the inference
    without the objection to it.

    This is one of four rules; see `contradictions` for the rest.
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


def contradictions_from_identity(store: EvidenceStore) -> List[dict]:
    """One identity bound to keys that never certify each other.

    A keyserver answering with two unrelated fingerprints for one address means
    one of three things — the operator rotated keys, someone else uploaded a key
    under that address, or the address is a shared role mailbox — and nothing in
    the graph separates them. Attribution built on "this key is that person"
    has to state that objection, because an uploaded key is the cheapest way to
    frame someone in this whole model.
    """
    flags = []
    rows = store._all(
        "SELECT e.entity_id, e.normalized_value, r.target_entity_id AS key_id, "
        "       k.normalized_value AS key_value "
        "FROM entities e JOIN relationships r ON r.source_entity_id = e.entity_id "
        "JOIN entities k ON k.entity_id = r.target_entity_id "
        "WHERE e.etype='EMAIL' AND r.rtype='ASSOCIATED_WITH' AND k.etype='PGP_KEY' "
        "AND r.status='ACTIVE'")
    by_email: Dict[str, List[tuple]] = defaultdict(list)
    for r in rows:
        by_email[r["normalized_value"]].append((r["key_id"], r["key_value"],
                                                r["entity_id"]))
    for email, keys in by_email.items():
        unique = {k[0]: k for k in keys}
        if len(unique) < 2:
            continue
        ids = list(unique)
        # Certified in either direction means one key vouches for the other, so
        # the pair is a rotation rather than a conflict.
        marks = ",".join("?" * len(ids))
        linked = store._all(
            f"SELECT 1 FROM relationships WHERE rtype IN ('SIGNED_BY','CROSS_SIGNS') "
            f"AND source_entity_id IN ({marks}) AND target_entity_id IN ({marks})",
            tuple(ids) * 2)
        if linked:
            continue
        markets = sorted({m for eid in ids for m in markets_for_entity(store, eid)}
                         | set(markets_for_entity(store, keys[0][2])))
        values = sorted(v for _, v, _ in unique.values())
        fid = store.add_finding(
            "IDENTITY_KEY_CONFLICT",
            f"{email} is bound to {len(values)} keys that do not certify each "
            f"other: {', '.join(v[:24] for v in values)}",
            severity="MEDIUM", confidence=0.5)
        flags.append({
            "rule": "identity_bound_to_uncertified_keys", "severity": "MEDIUM",
            "markets": markets, "finding_id": fid, "identity": email, "keys": values,
            "detail": (f"{email} answers to {len(values)} independent keys with no "
                       f"certification between them — key control is unproven, and "
                       f"a third party can publish a key under any address")})
    return flags


def contradictions_from_commonness(store: EvidenceStore,
                                   discrimination: Dict[str, float]) -> List[dict]:
    """Market pairs joined only by artifacts the whole corpus shares.

    This is the OnionMail case, and the one the engine has to get right to be
    worth anything: several servers of one mail platform legitimately share the
    platform's domain, its documentation mailbox and its software banner. Those
    are shared *ecosystem*, not shared control, and the difference is measurable
    — every joining artifact is common across the corpus.

    Stated as its own finding rather than derived from the successor list, and
    that is the point: those pairs score too low to become hypotheses, so a rule
    that only annotated proposed successors would stay silent exactly where the
    reader needs to be told "these look related and here is why they are not".
    """
    artifacts = market_artifact_map(store)
    urls = {r["target_id"]: r["url"] for r in
            store._all("SELECT target_id, url FROM targets")}
    etypes = [etype for _, etype in SHARED_ARTIFACTS]
    flags = []
    for a_id, b_id in _candidate_pairs(artifacts):
        shared = [e for etype in etypes
                  for e in artifacts[a_id].get(etype, set()) & artifacts[b_id].get(etype, set())]
        if not shared:
            continue
        if any(discrimination.get(e, 1.0) >= COMMON_ARTIFACT_FLOOR for e in shared):
            continue                       # something distinctive joins them
        pair = [urls.get(a_id, a_id), urls.get(b_id, b_id)]
        fid = store.add_finding(
            "SHARED_PLATFORM",
            f"{pair[0]} and {pair[1]} share only artifacts common across the corpus",
            severity="MEDIUM", confidence=0.5)
        flags.append({
            "rule": "shared_platform_not_shared_control", "severity": "MEDIUM",
            "markets": pair, "finding_id": fid, "shared": len(shared),
            "detail": (f"all {len(shared)} artifact(s) joining these two are common "
                       "across the corpus (software family, platform domain, role "
                       "mailbox) — consistent with running the same software, not "
                       "with one operator")})
    return flags


def contradictions_from_temporal(store: EvidenceStore, pairs: List[dict]) -> List[dict]:
    """Linked markets that were live at the same time.

    The link may well be real — one operator running two sites at once is
    ordinary. What this rules out is the *succession* reading, which is the one
    an analyst reaches for when two markets share a key, so it is recorded
    rather than left to inference.
    """
    flags = []
    for pair in pairs:
        if "temporal_overlap" not in (pair.get("signals") or []):
            continue
        urls = [pair.get("source_url"), pair.get("target_url")]
        fid = store.add_finding(
            "TEMPORAL_OVERLAP",
            f"{urls[0]} and {urls[1]} were captured live in overlapping windows",
            severity="LOW", confidence=0.4)
        flags.append({
            "rule": "overlap_contradicts_succession", "severity": "LOW",
            "markets": [u for u in urls if u], "finding_id": fid,
            "detail": ("both sites were live at once, so their shared artifacts "
                       "cannot mean one replaced the other — read this as parallel "
                       "operations or a shared supplier, recorded as LINKED_TO")})
    return flags


def contradictions_from_key_temporal(store: EvidenceStore, pairs: List[dict]) -> List[dict]:
    """Pairs where a shared PGP key was created after the predecessor market's
    observation window closed — see the temporal_contradiction check in
    _pair_signals. The key cannot have been reused from the predecessor if it
    did not exist yet while the predecessor was live, so whatever the pair's
    shared use of it means, it is not the ordinary succession story, and that
    objection is recorded here rather than left implicit in a lowered score.
    """
    flags = []
    for pair in pairs:
        if "pgp_key_temporal_contradiction" not in (pair.get("signals") or []):
            continue
        urls = [pair.get("source_url"), pair.get("target_url")]
        detail = next((s["detail"] for s in pair.get("signals_detail") or []
                      if s["signal"] == "pgp_key_temporal_contradiction"), "")
        fid = store.add_finding(
            "PGP_KEY_TEMPORAL_CONTRADICTION",
            f"{urls[0]} and {urls[1]} share a PGP key created after the "
            "predecessor's observation window closed",
            severity="MEDIUM", confidence=0.5)
        flags.append({
            "rule": "key_created_after_predecessor_window", "severity": "MEDIUM",
            "markets": [u for u in urls if u], "finding_id": fid,
            "detail": detail or ("a shared PGP key was created after the "
                                 "predecessor market's observation window closed — "
                                 "it cannot evidence reuse across this pair")})
    return flags


# The five rules are called separately by run_correlation rather than through a
# wrapper: the clone rule has to run BEFORE successors (its verdicts suppress
# them) and the commonness and temporal rules can only run after, since they
# object to pairs succession actually proposed.


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


def confidence_level(role: str, score: float, n_signal: int,
                     contradicted: bool = False) -> str:
    """Deliberately hard to reach HIGH: one funnel is never enough, whatever it
    scores, because a single artifact type is exactly what a clone can copy.

    A candidate with a standing contradiction cannot be HIGH at all. The
    objection is not a footnote to a strong conclusion — it is a competing
    explanation for the same evidence, and a reader who skims only the label
    must not be told HIGH while the body says a clone may explain it.
    """
    if role == "OPERATOR":
        level = "HIGH" if score >= 0.90 and n_signal >= 2 else (
            "MEDIUM" if score >= 0.60 else "LOW")
    else:
        level = "HIGH" if score >= 0.70 and n_signal >= 3 else (
            "MEDIUM" if score >= 0.50 and n_signal >= 2 else "LOW")
    return "MEDIUM" if contradicted and level == "HIGH" else level


def entity_timeline(store: EvidenceStore, entity_id: str, limit: int = 40) -> List[dict]:
    """When this entity was seen, where, and against which snapshot hash.

    Attribution arguments are temporal — a key that appears on B only after A
    goes quiet says something different from one live on both at once — and the
    ordering is already in the store. This is the read that puts it in front of
    the analyst instead of leaving it implicit in a score.
    """
    return [dict(r) for r in store._all(
        "SELECT o.observed_at, o.section, o.extraction_method, o.confidence, "
        "       s.sha256, t.url FROM observations o "
        "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
        "JOIN targets t ON t.target_id = s.target_id "
        "WHERE o.entity_id=? AND t.url != ? ORDER BY o.observed_at LIMIT ?",
        (entity_id, DERIVED_TARGET, limit))]


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
        if ip_class == "TOR_RELAY":
            # The one recommendation that tells the reader to stop rather than
            # to proceed. ExoneraTor places a Tor relay on this address at the
            # time it was observed, so whatever was seen there was seen on a
            # machine carrying the whole network's traffic.
            actions.insert(0, "Tor Metrics places a relay on this address at the "
                              "observed date: it is shared Tor infrastructure, so "
                              "treat this as evidence AGAINST an operator-hosting "
                              "reading unless something else ties the host to the "
                              "target")
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
        # Not necessarily a clone: four rules write contradictions, and this line
        # named only the first of them. The DNMX candidate, whose objection is
        # that both addresses were live at once, was reported to the reader as
        # contradicted by "a clone finding" that the store does not contain —
        # misdescribing the evidence in the one section a careful reader trusts.
        out.append("A contradiction stands against part of this candidate's "
                   "support — read the contradictions before relying on the score")
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
        "confidence_level": confidence_level(cand["role"], cand["score"], n_signal,
                                             bool(relevant)),
        "score": cand["score"],
        "discrimination": cand.get("discrimination", 1.0),
        "timeline": entity_timeline(store, cand["entity_id"]),
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


def split_pairs(results: dict) -> tuple:
    """(asserted, leads, refused) — the three things a pair result can be.

    Reported apart because they call for different actions: an asserted edge is
    a conclusion to check, a lead is something to look at, and a refused pair is
    a conclusion the engine talked itself out of and should not be re-proposed
    by whoever reads the brief.
    """
    asserted = [s for s in results.get("successors", []) if not s.get("suppressed")]
    leads = [s for s in results.get("successors", [])
             if s.get("suppressed") == "BELOW_THRESHOLD"]
    refused = [s for s in results.get("successors", [])
               if s.get("suppressed") and s.get("suppressed") != "BELOW_THRESHOLD"]
    return asserted, leads, refused


def render_markdown(dossiers: List[dict], results: dict) -> str:
    asserted, leads, refused = split_pairs(results)
    lines = ["# CyberTrace — correlation brief", "", f"_generated {utcnow()}_", "",
             f"{len(dossiers)} candidates "
             f"(operator {len(results['operators'])}, infra {len(results['infra'])}, "
             f"ip {len(results['ips'])}) · market links {len(asserted)} · "
             f"leads {len(leads)} · refused {len(refused)} · "
             f"clones {len(results['clones'])} · "
             f"contradictions {len(results['contradictions'])}", ""]

    if asserted or refused:
        lines += ["## Market relationships", ""]
        for s in asserted + refused:
            note = f" — REFUSED ({s['suppressed']})" if s["suppressed"] else ""
            lines.append(f"- [{s.get('relation') or 'none'}] "
                         f"`{s['source_url'] or s['source_market']}` → "
                         f"`{s['target_url'] or s['target_market']}` "
                         f"score {s['score']:.3f} · {', '.join(s['signals'])}{note}")
        lines.append("")

    if leads:
        lines += ["## Leads — ranked, not claimed", "",
                  "_Below the assertion threshold: worth an analyst's eye, not "
                  "written into the graph as a relationship._", ""]
        for s in leads:
            lines.append(f"- `{s['source_url'] or s['source_market']}` ~ "
                         f"`{s['target_url'] or s['target_market']}` "
                         f"score {s['score']:.3f} · "
                         + "; ".join(d["detail"] for d in s.get("signals_detail", [])))
        lines.append("")

    if results["contradictions"]:
        lines += ["## Contradictions", ""]
        lines += [f"- [{c['severity']}] {c['detail']}" for c in results["contradictions"]]
        lines.append("")

    if results["wallet_exchange_paths"]:
        lines += ["## Wallet → nearest exchange", "",
                  "_Reachability only — an analyst-labeled exchange address, never an engine "
                  "finding. Does not affect any candidate's score._", ""]
        for w in results["wallet_exchange_paths"]:
            lines.append(f"- `{w['value']}` → {w['hops']} hop(s) → {w['exchange']} "
                         f"(confidence {w['confidence']:.2f})")
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
            lines.append("- ⚠ contradicted by "
                         + ", ".join(sorted({c["rule"] for c in d["contradictions"]})))
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
    "FAVICON":          ("#7f8c8d", "triangleDown", 16),
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
        # Both M5 conclusions are drawn as inferred, and differently from each
        # other: an arrow for the directional claim, a plain line for the one
        # that only says "these two are joined".
        inferred = rtype in ("SUCCESSOR_OF", "LINKED_TO")
        net.add_edge(src, dst, width=5 if inferred else 1,
                     color="#e67e22" if rtype == "SUCCESSOR_OF" else
                           "#3498db" if inferred else "#5a5a5a",
                     label=rtype if inferred else None,
                     arrows="" if rtype == "LINKED_TO" else None,
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


DOSSIER_CSS = """
:root{color-scheme:dark;--bg:#15181c;--card:#1e2228;--line:#2c323a;--fg:#e6e8ea;
--dim:#9aa3ad;--hi:#e67e22;--ok:#2ecc71;--warn:#f1c40f;--bad:#ff5c5c;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:24px}
h1{font-size:20px;margin:0 0 4px} h2{font-size:15px;margin:28px 0 10px;
color:var(--hi);text-transform:uppercase;letter-spacing:.08em}
.sub{color:var(--dim);margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.stat b{display:block;font-size:22px} .stat span{color:var(--dim);font-size:12px}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;
margin:8px 0;padding:10px 14px} summary{cursor:pointer;font-weight:600}
summary::marker{color:var(--hi)}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px;display:block;
overflow-x:auto} th,td{text-align:left;padding:4px 10px 4px 0;
border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
td.wrap{white-space:normal}
.tag{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;
font-weight:700;letter-spacing:.04em}
.HIGH{background:#5c1f1f;color:#ffb3b3} .MEDIUM{background:#5c4a1f;color:#ffe08a}
.LOW{background:#25303a;color:#9fc4e0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.dim{color:var(--dim)} .bad{color:var(--bad)} .ok{color:var(--ok)}
ul{margin:6px 0 6px 18px;padding:0} li{margin:2px 0}
.note{border-left:3px solid var(--bad);padding-left:10px;margin:6px 0}
"""


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_dossier_html(results: dict, path: str, title: str = "CyberTrace case file") -> str:
    """Write the candidate dossiers to one standalone HTML case file.

    Separate from the graph on purpose. The graph answers "what connects to
    what"; this answers the question an investigator actually has to defend —
    who is claimed, on what evidence, when it was seen, and what argues against
    it. Contradictions sit above the candidates rather than inside them, because
    a reader who stops after the first screen must still have met the objections.

    occam: no JavaScript. `<details>` is a native disclosure widget, so the
    dashboard-to-detail interaction costs zero script, works offline, and keeps
    the file safe to open on an evidence machine.
    """
    d = results.get("dossiers", [])
    live_successors, leads, _refused = split_pairs(results)
    out = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
           f"<meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<title>{_esc(title)}</title><style>{DOSSIER_CSS}</style></head><body>",
           f"<h1>{_esc(title)}</h1>",
           f"<div class=sub>generated {_esc(utcnow())} · scores are ranked priors, "
           f"not calibrated probabilities</div>",
           "<div class=grid>"]
    for label, n in (("candidates", len(d)),
                     ("operator", len(results.get("operators", []))),
                     ("infra", len(results.get("infra", []))),
                     ("ip", len(results.get("ips", []))),
                     ("market links", len(live_successors)),
                     ("leads", len(leads)),
                     ("contradictions", len(results.get("contradictions", [])))):
        out.append(f"<div class=stat><b>{n}</b><span>{label}</span></div>")
    out.append("</div>")

    if results.get("contradictions"):
        out.append("<h2>Contradictions — read before the candidates</h2>")
        for c in results["contradictions"]:
            out.append(f"<div class=note><span class='tag {_esc(c['severity'])}'>"
                       f"{_esc(c['severity'])}</span> <b>{_esc(c['rule'])}</b><br>"
                       f"<span class=dim>{_esc(' ~ '.join(c['markets']))}</span><br>"
                       f"{_esc(c['detail'])}</div>")

    if live_successors:
        out.append("<h2>Market relationships</h2><table><tr><th>relation</th>"
                   "<th>from</th><th>to</th><th>score</th><th>signals</th></tr>")
        for s in live_successors:
            out.append(f"<tr><td>{_esc(s.get('relation'))}</td>"
                       f"<td class=mono>{_esc(s.get('source_url'))}</td>"
                       f"<td class=mono>{_esc(s.get('target_url'))}</td>"
                       f"<td>{s['score']:.3f}</td>"
                       f"<td class=wrap>{_esc(', '.join(s['signals']))}</td></tr>")
        out.append("</table>")

    if leads:
        out.append("<h2>Leads — ranked, not claimed</h2>"
                   "<p class=dim>Below the assertion threshold. Shown because an "
                   "analyst should see them; not written into the graph, because "
                   "the evidence does not support asserting a relationship.</p>"
                   "<table><tr><th>a</th><th>b</th><th>score</th><th>why</th></tr>")
        for s in leads:
            out.append(f"<tr><td class=mono>{_esc(s.get('source_url'))}</td>"
                       f"<td class=mono>{_esc(s.get('target_url'))}</td>"
                       f"<td>{s['score']:.3f}</td><td class=wrap>"
                       + _esc("; ".join(x["detail"] for x in s.get("signals_detail", [])))
                       + "</td></tr>")
        out.append("</table>")

    out.append("<h2>Candidates</h2>")
    if not d:
        out.append("<p class=dim>No candidate cleared the evidence floor. With this "
                   "corpus that is a result, not an empty run: nothing here converged "
                   "across enough markets to support an attribution claim.</p>")
    for c in d:
        contra = c.get("contradictions") or []
        out.append(
            f"<details><summary>{_esc(c['candidate_id'])} · {_esc(c['role'])} · "
            f"<span class='tag {_esc(c['confidence_level'])}'>{_esc(c['confidence_level'])}"
            f"</span> · score {c['score']:.3f} · "
            f"<span class=mono>{_esc(c['entity']['value'][:60])}</span>"
            + (f" · <span class=bad>{len(contra)} contradiction(s)</span>" if contra else "")
            + "</summary>")
        out.append(f"<p class=dim>{_esc(c['entity']['etype'])} · seen on "
                   f"{len(c['markets'])} market(s) · {c['evidence_count']} evidence "
                   f"record(s) · discrimination {c.get('discrimination', 1.0)}</p>")
        out.append("<ul>" + "".join(f"<li class=mono>{_esc(m)}</li>"
                                    for m in c["markets"]) + "</ul>")
        if contra:
            out.append("".join(f"<div class=note>{_esc(x['detail'])}</div>" for x in contra))
        if c.get("timeline"):
            out.append("<b>Timeline</b><table><tr><th>observed</th><th>market</th>"
                       "<th>section</th><th>snapshot</th></tr>")
            for t in c["timeline"][:20]:
                out.append(f"<tr><td class=mono>{_esc(t['observed_at'][:19])}</td>"
                           f"<td class=mono>{_esc(t['url'][:28])}</td>"
                           f"<td>{_esc(t['section'])}</td>"
                           f"<td class=mono>{_esc(t['sha256'][:12])}</td></tr>")
            out.append("</table>")
        if c.get("key_evidence"):
            out.append("<b>Evidence chain</b><table><tr><th>method</th><th>context</th>"
                       "<th>conf</th><th>snapshot</th></tr>")
            for e in c["key_evidence"][:8]:
                out.append(f"<tr><td>{_esc(e['extraction_method'])}</td>"
                           f"<td class=wrap>{_esc((e['context'] or '')[:160])}</td>"
                           f"<td>{e['confidence']}</td>"
                           f"<td class=mono>{_esc(e['sha256'][:12])}</td></tr>")
            out.append("</table>")
        for heading, key in (("Next steps", "recommended_actions"),
                             ("Limitations", "limitations")):
            if c.get(key):
                out.append(f"<b>{heading}</b><ul>"
                           + "".join(f"<li>{_esc(x)}</li>" for x in c[key]) + "</ul>")
        out.append("</details>")

    out.append("</body></html>")
    with open(path, "w") as fh:
        fh.write("\n".join(out))
    return path


def run_correlation(store: EvidenceStore, min_conf: float = 0.35,
                    min_infra_markets: int = 2,
                    min_successor_score: float = 0.5) -> dict:
    """Full M5 pass. Clone guard first: its verdicts constrain everything after."""
    clones = detect_clones(store)
    clone_flags = contradictions_from_clones(store, clones)
    clone_pairs = {frozenset(c["markets"]) for c in clone_flags}
    # Measured once per pass and threaded through everything that scores: a
    # second computation mid-pass could see different observation counts and
    # rank two candidates on two different corpora.
    discrimination = entity_discrimination(store)
    # Folded into the same slot as commonness rather than a second parameter
    # everywhere entity_funnel_profile is called. The `if feedback` guard means
    # a store with none recorded (every corpus run before this existed) skips
    # rebuilding the dict entirely -- not just a no-op multiply, no touch at all.
    feedback = feedback_discrimination(store)
    if feedback:
        discrimination = {eid: discrimination.get(eid, 1.0) * feedback.get(eid, 1.0)
                          for eid in set(discrimination) | set(feedback)}
    windows = market_windows(store)
    aliases = username_aliases(store)

    successors = detect_successors(store, min_score=min_successor_score,
                                   clone_pairs=clone_pairs,
                                   discrimination=discrimination)
    flags = (clone_flags
             + contradictions_from_identity(store)
             + contradictions_from_commonness(store, discrimination)
             + contradictions_from_temporal(store, successors)
             + contradictions_from_key_temporal(store, successors))

    results = {
        "operators": candidate_operators(store, min_conf=min_conf,
                                         discrimination=discrimination),
        "infra": candidate_infra(store, min_markets=min_infra_markets,
                                 discrimination=discrimination),
        "ips": candidate_ips(store, min_markets=min_infra_markets,
                             discrimination=discrimination),
        "aliases": aliases,
        "successors": successors,
        "clones": clones,
        "clusters": sorted(set(crypto_clusters(store).values())),
        "wallet_exchange_paths": wallet_exchange_paths(store),
        "contradictions": flags,
    }
    dossiers = [build_dossier(store, c, aliases, flags, windows)
                for c in results["operators"] + results["infra"] + results["ips"]]
    for rank, d in enumerate(dossiers, 1):
        d["rank"] = rank
    save_candidates(store, dossiers)
    results["dossiers"] = dossiers
    return results
