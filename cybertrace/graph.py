"""Evidence graph: a thin, stdlib-only view over ModuleResult artifacts.

Turns the flat per-source data a module already produces into typed nodes and
evidence-carrying edges, so an operator's reused artifacts (a PGP key, a BTC
address, a handle) line up as shared nodes across markets. Every edge records
where it was seen, when, and how much weight to give it — the graph is
investigative, not decorative.

Confidence tiers follow the project's evidence model (very_weak..very_strong):
a lone weak signal (shared username, same referenced host) never implies the
same operator on its own; corroboration by an independent source promotes it one
tier. Nothing here concludes an attribution — it ranks the links a human reads.
"""

from typing import Any, Dict, List, Optional

from .modules.base import ModuleResult

# Ordered weakest -> strongest. Rank lets a later correlation layer compare and
# aggregate link strength; the order also drives the one-tier corroboration bump.
CONFIDENCE_ORDER = ['very_weak', 'weak', 'moderate', 'strong', 'very_strong']
CONFIDENCE_RANK = {tier: i + 1 for i, tier in enumerate(CONFIDENCE_ORDER)}

# Default tier per relationship. IP edges override by provenance at build time.
REL_CONFIDENCE = {
    'HAS_ADDRESS': 'strong',       # market <-> its own onion (definitional)
    'USES_PGP': 'strong',          # a published operator key
    'USES_CRYPTO': 'moderate',     # a unique payment address in operator context
    'MENTIONS_EMAIL': 'moderate',
    'HANDLE_OF': 'weak',           # email local-part guessed as a username
    'REFERENCES_DOMAIN': 'weak',   # clearnet host named on the page
    'LINKS_TO': 'weak',            # onion links to another onion
    'CANDIDATE_IP': 'moderate',    # overridden per provenance below
    'HOSTED_BY': 'strong',         # IP -> org/provider (factual, from Shodan)
}


class EvidenceGraph:
    """Typed nodes + evidence-carrying edges. Accumulative: fold several market
    results into one graph and shared artifacts collapse onto shared nodes."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        # keyed by (from_id, rel, to_id) so a repeat observation corroborates
        # rather than duplicates.
        self._edges: Dict[tuple, Dict[str, Any]] = {}

    @staticmethod
    def node_id(ntype: str, value: str) -> str:
        return f"{ntype}:{value.strip().lower()}"

    def add_node(self, ntype: str, value: str, market: Optional[str] = None, **attrs) -> str:
        nid = self.node_id(ntype, value)
        node = self.nodes.get(nid)
        if node is None:
            node = {'id': nid, 'type': ntype, 'value': value, 'markets': []}
            self.nodes[nid] = node
        # markets touching this node: an artifact on >=2 markets is the reuse
        # signal the cross-market correlation layer keys off.
        if market and market not in node['markets']:
            node['markets'].append(market)
        # first non-empty attr value wins; never overwrite with None/empty.
        for k, v in attrs.items():
            if v and not node.get(k):
                node[k] = v
        return nid

    def add_edge(self, from_id: str, to_id: str, rel: str, source: str,
                 observed_at: str, confidence: Optional[str] = None, **meta) -> None:
        key = (from_id, rel, to_id)
        edge = self._edges.get(key)
        if edge is None:
            edge = {
                'from': from_id, 'to': to_id, 'rel': rel,
                'base_confidence': confidence or REL_CONFIDENCE.get(rel, 'weak'),
                'sources': [], 'first_seen': observed_at, **meta,
            }
            self._edges[key] = edge
        if source not in edge['sources']:
            edge['sources'].append(source)

    @classmethod
    def _bump(cls, tier: str) -> str:
        i = CONFIDENCE_ORDER.index(tier)
        return CONFIDENCE_ORDER[min(i + 1, len(CONFIDENCE_ORDER) - 1)]

    @property
    def edges(self) -> List[Dict[str, Any]]:
        """Materialise edges with a computed confidence: one tier up when two or
        more independent sources agree on the same link."""
        out = []
        for e in self._edges.values():
            conf = e['base_confidence']
            if len(e['sources']) >= 2:
                conf = self._bump(conf)
            out.append({k: v for k, v in e.items() if k != 'base_confidence'} | {'confidence': conf})
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {'nodes': list(self.nodes.values()), 'edges': self.edges}

    def summary(self) -> Dict[str, Any]:
        from collections import Counter
        edges = self.edges
        return {
            'nodes': len(self.nodes),
            'edges': len(edges),
            'node_types': dict(Counter(n['type'] for n in self.nodes.values())),
            'strong_links': [
                {'from': e['from'], 'rel': e['rel'], 'to': e['to'], 'confidence': e['confidence']}
                for e in edges if CONFIDENCE_RANK[e['confidence']] >= CONFIDENCE_RANK['strong']
            ],
        }


def build_graph(result: ModuleResult, graph: Optional[EvidenceGraph] = None) -> EvidenceGraph:
    """Fold a darkweb ModuleResult's live-onion artifacts into an EvidenceGraph.

    Pass an existing graph to accumulate several markets into one — the enabler
    for cross-market correlation: an artifact reused on two markets becomes one
    node with both markets pointing at it. Correlation/scoring over that shape is
    the next layer; this only builds the shape.
    """
    src = result.sources.get('target_onion')
    if not (src and src.success):
        return graph or EvidenceGraph()  # nothing was collected from a live onion
    ts = getattr(src.timestamp, 'isoformat', lambda: str(src.timestamp))()
    return _fold(graph or EvidenceGraph(), result.target, src.data, ts)


def build_graph_from_dict(result: Dict[str, Any], graph: Optional[EvidenceGraph] = None) -> EvidenceGraph:
    """Same as build_graph but from a saved result dict (ModuleResult.to_dict()).

    Lets `cybertrace correlate a.json b.json` accumulate previously saved market
    investigations into one graph without re-running any collection.
    """
    src = (result.get('sources') or {}).get('target_onion') or {}
    if not src.get('success'):
        return graph or EvidenceGraph()
    return _fold(graph or EvidenceGraph(), result.get('target', ''),
                 src.get('data') or {}, src.get('timestamp', ''))


# An artifact sitting in an operator-controlled block — a donate box, a contact
# panel, a published key — is more clearly the operator's own than the same
# string mentioned in passing prose, so its edge earns one tier.
PROMOTING_SECTIONS = {'wallet', 'contact', 'pgp'}


def _evidence(data: Dict[str, Any], value: str, rel: str) -> tuple:
    """Where an artifact was seen on the page, and the confidence that placement
    earns. Returns (confidence_override_or_None, edge_metadata)."""
    ev = (data.get('artifact_evidence') or {}).get(value) or {}
    meta = {k: ev[k] for k in ('section', 'context') if ev.get(k)}
    conf = (EvidenceGraph._bump(REL_CONFIDENCE.get(rel, 'weak'))
            if ev.get('section') in PROMOTING_SECTIONS else None)
    return conf, meta


def _fold(g: EvidenceGraph, mkt: str, data: Dict[str, Any], ts: str) -> EvidenceGraph:
    """Add one market's live-onion artifacts as nodes + evidence edges."""
    from .modules.darkweb_module import DarkwebModule  # lazy: reuse handle heuristic

    market = g.add_node('MARKET', mkt, title=data.get('title'))
    onion = g.add_node('ONION_ADDRESS', mkt)
    g.add_edge(market, onion, 'HAS_ADDRESS', 'target_onion', ts)

    for email in data.get('emails') or []:
        nid = g.add_node('EMAIL', email, market=mkt)
        conf, ev = _evidence(data, email, 'MENTIONS_EMAIL')
        g.add_edge(market, nid, 'MENTIONS_EMAIL', 'target_onion', ts, confidence=conf, **ev)
        for user in DarkwebModule._usernames_from_emails([email]):
            un = g.add_node('USERNAME', user, market=mkt)
            g.add_edge(nid, un, 'HANDLE_OF', 'target_onion', ts)

    for coin, key in (('BTC', 'bitcoin_addresses'),
                      ('ETH', 'ethereum_addresses'),
                      ('XMR', 'monero_addresses')):
        for addr in data.get(key) or []:
            nid = g.add_node('CRYPTO_ADDRESS', addr, market=mkt, coin=coin)
            conf, ev = _evidence(data, addr, 'USES_CRYPTO')
            g.add_edge(market, nid, 'USES_CRYPTO', 'target_onion', ts,
                       confidence=conf, coin=coin, **ev)

    for k in data.get('pgp_keys') or []:
        nid = g.add_node('PGP_KEY', k['key_id'], market=mkt)
        g.add_edge(market, nid, 'USES_PGP', 'target_onion', ts)

    for host in data.get('clearnet_hosts_referenced') or []:
        nid = g.add_node('DOMAIN', host, market=mkt)
        g.add_edge(market, nid, 'REFERENCES_DOMAIN', 'target_onion', ts)

    for link in data.get('onion_addresses_found') or []:
        nid = g.add_node('ONION_ADDRESS', link, market=mkt)
        g.add_edge(onion, nid, 'LINKS_TO', 'target_onion', ts)

    # Candidate IPs: confidence follows provenance. A real-host slip (leaked in
    # headers/body or a misconfig endpoint) is stronger than a favicon match.
    leaked = set(data.get('leaked_public_ipv4') or [])
    misconfig_ips = {
        ip for mc in (data.get('misconfigurations') or []) for ip in mc.get('leaked_ips', [])
    }
    favicon_by_ip = {
        m['ip']: m for m in ((data.get('favicon') or {}).get('shodan_matches') or [])
        if m.get('ip')
    }
    for ip in data.get('candidate_operator_ips') or []:
        nid = g.add_node('IP', ip, market=mkt)
        if ip in leaked or ip in misconfig_ips:
            conf, prov = 'strong', 'header/misconfig leak'
        elif ip in favicon_by_ip:
            conf, prov = 'moderate', 'favicon match'
        else:
            conf, prov = 'moderate', 'candidate'
        g.add_edge(market, nid, 'CANDIDATE_IP', 'target_onion', ts, confidence=conf, provenance=prov)
        m = favicon_by_ip.get(ip)
        if m and m.get('org'):
            org = g.add_node('PROVIDER', m['org'], market=mkt)
            g.add_edge(nid, org, 'HOSTED_BY', 'target_onion', ts)

    return g


# --- Cross-market correlation (evidence-model Section 5/6) -------------------

# Weight a SINGLE shared instance of each artifact type carries when the same
# value shows up on two markets. A shared PGP key is near-identity; a shared
# host or handle alone is barely a lead.
SHARED_ARTIFACT_WEIGHT = {
    'PGP_KEY': 'strong',
    'CRYPTO_ADDRESS': 'moderate',
    'EMAIL': 'moderate',
    'IP': 'moderate',
    'DOMAIN': 'weak',
    'USERNAME': 'weak',
    'PROVIDER': 'very_weak',
}


def correlate(graph: EvidenceGraph) -> Dict[str, Any]:
    """Group markets that share operator artifacts into ranked operator
    candidates. Two markets join the same candidate when they reuse any artifact
    node; the candidate's confidence is the strongest shared signal, bumped one
    tier when two independent artifact TYPES corroborate (a shared key *and* a
    shared address beats either alone).

    Weak-only clusters are surfaced but flagged — a shared username or host is a
    lead to check, never an attribution. Contradiction detection (same key,
    conflicting operator claims) needs signals not yet extracted; deferred.
    """
    # occam: union-find + max-tier scoring. No probabilistic model — the plan
    # itself disowns universal weights; tiers + a corroboration bump are enough
    # until real ground-truth exists to calibrate against.
    from collections import defaultdict

    shared = [
        n for n in graph.nodes.values()
        if n['type'] in SHARED_ARTIFACT_WEIGHT and len(n.get('markets') or []) >= 2
    ]

    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for n in shared:
        markets = n['markets']
        for other in markets[1:]:
            union(markets[0], other)

    clusters: Dict[str, set] = defaultdict(set)
    for m in list(parent):
        clusters[find(m)].add(m)

    candidates = []
    for members in clusters.values():
        if len(members) < 2:
            continue
        arts = [n for n in shared if set(n['markets']) & members]
        conf = _aggregate_confidence(arts)
        candidates.append({
            'markets': sorted(members),
            'confidence': conf,
            'note': _confidence_note(conf, arts),
            'shared_artifacts': [
                {
                    'type': a['type'], 'value': a['value'],
                    'weight': SHARED_ARTIFACT_WEIGHT[a['type']],
                    'markets': sorted(a['markets']),
                }
                for a in sorted(arts, key=lambda a: CONFIDENCE_RANK[SHARED_ARTIFACT_WEIGHT[a['type']]], reverse=True)
            ],
        })

    candidates.sort(key=lambda c: CONFIDENCE_RANK[c['confidence']], reverse=True)
    return {'operator_candidates': candidates}


def _aggregate_confidence(arts: List[Dict[str, Any]]) -> str:
    if not arts:
        return 'very_weak'
    weights = [SHARED_ARTIFACT_WEIGHT[a['type']] for a in arts]
    top = max(weights, key=lambda w: CONFIDENCE_RANK[w])
    corroborating_types = {
        a['type'] for a in arts
        if CONFIDENCE_RANK[SHARED_ARTIFACT_WEIGHT[a['type']]] >= CONFIDENCE_RANK['moderate']
    }
    return EvidenceGraph._bump(top) if len(corroborating_types) >= 2 else top


def _confidence_note(conf: str, arts: List[Dict[str, Any]]) -> str:
    if CONFIDENCE_RANK[conf] <= CONFIDENCE_RANK['weak']:
        return 'weak link — low-value signal (shared handle/host); corroborate before trusting'
    types = sorted({a['type'] for a in arts})
    return f"markets linked by shared {', '.join(types)}"
