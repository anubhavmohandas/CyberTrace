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
from .normalize import NON_ATTRIBUTIVE_SECTIONS

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


def _borrowed(data: Dict[str, Any], value: str) -> bool:
    """True when the page reproduced this artifact rather than published it.

    Cross-market attribution runs through the governed EvidenceStore engine
    (evidence.ingest, which demotes the edge to MENTIONS on the same set of
    sections) — not through this per-search graph. Marking the node borrowed
    here just keeps a quoted address or list subscriber from reading as this
    market's own artifact when darkweb_module.py attaches the graph to a
    single search's summary.
    """
    return ((data.get('artifact_evidence') or {}).get(value) or {}).get(
        'section') in NON_ATTRIBUTIVE_SECTIONS


def _fold(g: EvidenceGraph, mkt: str, data: Dict[str, Any], ts: str) -> EvidenceGraph:
    """Add one market's live-onion artifacts as nodes + evidence edges."""
    from .modules.darkweb_module import DarkwebModule  # lazy: reuse handle heuristic

    market = g.add_node('MARKET', mkt, title=data.get('title'))
    onion = g.add_node('ONION_ADDRESS', mkt)
    g.add_edge(market, onion, 'HAS_ADDRESS', 'target_onion', ts)

    # Artifacts the page reproduced rather than published stay in the graph as
    # nodes — they are real and worth seeing — but carry no market, so they can
    # never cluster two sites into one operator candidate. See _borrowed.
    for email in data.get('emails') or []:
        borrowed = _borrowed(data, email)
        nid = g.add_node('EMAIL', email, market=None if borrowed else mkt)
        conf, ev = _evidence(data, email, 'MENTIONS_EMAIL')
        g.add_edge(market, nid, 'MENTIONS_EMAIL', 'target_onion', ts, confidence=conf, **ev)
        if borrowed:
            continue        # and never seed a handle out of somebody else's address
        for user in DarkwebModule._usernames_from_emails([email]):
            un = g.add_node('USERNAME', user, market=mkt)
            g.add_edge(nid, un, 'HANDLE_OF', 'target_onion', ts)

    for coin, key in (('BTC', 'bitcoin_addresses'),
                      ('ETH', 'ethereum_addresses'),
                      ('XMR', 'monero_addresses')):
        for addr in data.get(key) or []:
            nid = g.add_node('CRYPTO_ADDRESS', addr, coin=coin,
                             market=None if _borrowed(data, addr) else mkt)
            conf, ev = _evidence(data, addr, 'USES_CRYPTO')
            g.add_edge(market, nid, 'USES_CRYPTO', 'target_onion', ts,
                       confidence=conf, coin=coin, **ev)

    for k in data.get('pgp_keys') or []:
        # A key block carries its own section, not an artifact_evidence entry.
        quoted = k.get('section') in NON_ATTRIBUTIVE_SECTIONS
        nid = g.add_node('PGP_KEY', k['key_id'], market=None if quoted else mkt)
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
        nid = g.add_node('IP', ip, market=None if _borrowed(data, ip) else mkt)
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
