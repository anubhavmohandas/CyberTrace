"""Crypto investigation graph (Loop 53): typed nodes + evidence-carrying
edges over the transaction/attribution/cross-chain evidence this codebase
already computed.

Mirrors graph.py's `EvidenceGraph` pattern (typed node/edge dicts,
`node_id()` scheme, `to_dict()`/`summary()`) rather than subclassing it --
that class is structurally tied to darkweb `ModuleResult` artifacts
(`NON_ATTRIBUTIVE_SECTIONS`, `build_graph`/`_fold`'s market-centric fold) and
has no concept of a wallet, a transaction, or a VASP. This is its own,
smaller module for a different kind of node.

**`build_from_wallet_trace` is pure construction, not a new BFS.** Every
node/edge below comes from data a caller already computed --
`correlate.wallet_trace_report`'s own `path`/`vasp_investigation` fields,
the Loop 53 `transactions` table, and cross-chain event dicts (see
`crypto_investigation.py`'s cross-chain labeling). This module issues no
query of its own beyond what it is handed.

**Semantics this graph must never blur** (see crypto_investigation.py's own
module docstring for the full policy): a `VASP_EXPOSURE` edge is a fact
about a transaction relationship, never ownership; a `BRIDGE_TRANSFER`/
`SWAP` edge is real transaction-level evidence (Loop 42/44's live sources),
never proof the two sides share a controller; a candidate-only relationship
(no confirmed hop, no live cross-chain record) still gets a node and an
edge -- with `confidence`/`provenance` saying so -- rather than being
silently omitted or promoted.

Bounded by `max_transactions`/`max_addresses`, the same limits
`crypto_investigation.investigate_wallet` threads through everywhere:
no unbounded traversal, no duplicate nodes for the same address/tx (see
`node_id`).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

WALLET = "WALLET"
TRANSACTION = "TRANSACTION"
VASP = "VASP"
EXCHANGE = "EXCHANGE"
BRIDGE = "BRIDGE"
SWAP_SERVICE = "SWAP_SERVICE"
CONTRACT = "CONTRACT"
UNKNOWN_SERVICE = "UNKNOWN_SERVICE"

SENT_TO = "SENT_TO"
RECEIVED_FROM = "RECEIVED_FROM"
PARTICIPATED_IN = "PARTICIPATED_IN"
VASP_EXPOSURE = "VASP_EXPOSURE"
BRIDGE_TRANSFER = "BRIDGE_TRANSFER"
SWAP = "SWAP"
CONTRACT_INTERACTION = "CONTRACT_INTERACTION"

DEFAULT_MAX_TRANSACTIONS = 500
DEFAULT_MAX_ADDRESSES = 250


class InvestigationGraph:
    """Typed nodes + evidence-carrying edges. Accumulative: build several
    wallets' traces into one graph and shared addresses/VASPs/services
    collapse onto shared nodes (same fold-not-duplicate discipline as
    `graph.EvidenceGraph`)."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[tuple, Dict[str, Any]] = {}

    @staticmethod
    def node_id(ntype: str, value: str) -> str:
        return f"{ntype}:{(value or '').strip().lower()}"

    def add_node(self, ntype: str, value: str, **attrs) -> str:
        nid = self.node_id(ntype, value)
        node = self.nodes.get(nid)
        if node is None:
            node = {"id": nid, "type": ntype, "value": value}
            self.nodes[nid] = node
        for k, v in attrs.items():
            if v is not None and not node.get(k):
                node[k] = v
        return nid

    def add_edge(self, from_id: str, to_id: str, rel: str, *, source: str,
                provider: Optional[str] = None, timestamp: Optional[str] = None,
                evidence: Optional[list] = None, confidence: Optional[float] = None,
                provenance: Optional[str] = None, **meta) -> None:
        """Every edge carries source/provider/timestamp/evidence/confidence/
        provenance, per Loop 53's own requirement -- absent ones stay None,
        never fabricated. A repeat call for the same (from, to, rel) merges
        sources rather than duplicating the edge."""
        key = (from_id, rel, to_id)
        edge = self._edges.get(key)
        if edge is None:
            edge = {"from": from_id, "to": to_id, "rel": rel, "sources": [],
                    "provider": provider, "timestamp": timestamp,
                    "evidence": evidence or [], "confidence": confidence,
                    "provenance": provenance, **meta}
            self._edges[key] = edge
        if source not in edge["sources"]:
            edge["sources"].append(source)

    @property
    def edges(self) -> List[Dict[str, Any]]:
        return list(self._edges.values())

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": self.edges}

    def summary(self) -> Dict[str, Any]:
        from collections import Counter
        return {
            "node_count": len(self.nodes), "edge_count": len(self._edges),
            "node_types": dict(Counter(n["type"] for n in self.nodes.values())),
            "edge_types": dict(Counter(e["rel"] for e in self._edges.values())),
        }


def _service_node_type(mechanism: Optional[str]) -> str:
    if mechanism == "BRIDGE":
        return BRIDGE
    if mechanism == "SWAP":
        return SWAP_SERVICE
    return UNKNOWN_SERVICE


def build_from_wallet_trace(wallet_trace: dict, transactions: Optional[List[dict]] = None,
                            cross_chain_events: Optional[List[dict]] = None,
                            max_transactions: int = DEFAULT_MAX_TRANSACTIONS,
                            max_addresses: int = DEFAULT_MAX_ADDRESSES) -> InvestigationGraph:
    """Build one wallet's investigation graph from data already computed by
    `correlate.wallet_trace_report` (`wallet_trace`), the Loop 53
    `transactions` table (`transactions`), and cross-chain event labeling
    (`cross_chain_events` -- see crypto_investigation.py). No new query."""
    g = InvestigationGraph()
    chain = wallet_trace.get("chain")
    suspect = g.add_node(WALLET, wallet_trace["address"], chain=chain, role="SUSPECT")

    # Fund-flow path (correlate.wallet_exchange_paths' own BFS result) --
    # consecutive hops, each a real address this case already traced.
    # Direction is the OVERALL suspect<->VASP flow (`hit['direction']`,
    # TO_VASP/FROM_VASP/UNKNOWN) -- wallet_exchange_paths does not track a
    # separate direction per intermediate hop, so this graph does not invent
    # one either; every path edge below carries the same overall direction
    # as its own `direction` attribute rather than a per-hop guess.
    path = (wallet_trace.get("path") or [])[:max_addresses]
    direction = wallet_trace.get("direction")
    rel = SENT_TO if direction == "TO_VASP" else RECEIVED_FROM if direction == "FROM_VASP" else SENT_TO
    prev = suspect
    for addr in path[1:]:
        node = g.add_node(WALLET, addr, chain=chain)
        g.add_edge(prev, node, rel, source="wallet_exchange_paths", provider="correlate",
                   confidence=wallet_trace.get("exchange_confidence"),
                   evidence=wallet_trace.get("evidence_ids") or [],
                   direction=direction, hops=wallet_trace.get("hops"))
        prev = node

    # VASP exposure -- EXPOSURE only, see module docstring. `vasp_investigation`
    # (Loop 49's canonical envelope) already states confidence/provenance;
    # this graph just cites it, never re-derives it.
    vi = wallet_trace.get("vasp_investigation") or {}
    for i, brand in enumerate([vi.get("primary_vasp"), *(vi.get("candidate_vasps") or [])]):
        if not brand:
            continue
        vasp_node = g.add_node(VASP, brand)
        g.add_edge(prev, vasp_node, VASP_EXPOSURE, source="vasp_investigation",
                  provider="correlate", confidence=vi.get("confidence") if i == 0 else None,
                  evidence=[e for e in vi.get("evidence", []) if e.get("brand") == brand],
                  provenance=",".join(vi.get("provenance") or []),
                  attribution_tier=vi.get("attribution_tier") if i == 0 else None,
                  control_status=vi.get("control_status") if i == 0 else "NOT_ESTABLISHED")

    # Real per-transaction evidence (Loop 53 `transactions` table) -- one
    # TRANSACTION node per real tx_hash, one PARTICIPATED_IN edge from the
    # suspect and (when known) the counterparty. Bounded by max_transactions.
    for tx in (transactions or [])[:max_transactions]:
        tx_node = g.add_node(TRANSACTION, tx["tx_hash"], chain=tx.get("chain"),
                             timestamp=tx.get("timestamp"))
        g.add_edge(suspect, tx_node, PARTICIPATED_IN, source="transactions",
                  provider=tx.get("provider"), timestamp=tx.get("timestamp"),
                  confidence=1.0 if tx.get("status") == "FOUND" else None,
                  value=tx.get("value"), asset=tx.get("asset"), direction=tx.get("direction"))
        peer = tx.get("counterparty")
        if peer:
            peer_node = g.add_node(WALLET, peer, chain=tx.get("chain"))
            g.add_edge(peer_node, tx_node, PARTICIPATED_IN, source="transactions",
                      provider=tx.get("provider"), timestamp=tx.get("timestamp"))

    # Cross-chain events -- BRIDGE_CONFIRMED/SWAP_CONFIRMED get a real edge
    # to a BRIDGE/SWAP_SERVICE node; CROSS_CHAIN_CANDIDATE still gets one,
    # with lower confidence and no destination-wallet-identity claim, per
    # the module docstring's "candidate still gets a node/edge" rule.
    for ev in (cross_chain_events or [])[:max_transactions]:
        svc_node = g.add_node(_service_node_type(ev.get("mechanism")),
                              ev.get("source_api") or ev.get("mechanism") or "unknown")
        rel = BRIDGE_TRANSFER if ev.get("mechanism") == "BRIDGE" else SWAP
        confidence = 1.0 if ev.get("event_type") in ("BRIDGE_CONFIRMED", "SWAP_CONFIRMED") else 0.3
        g.add_edge(suspect, svc_node, rel, source=ev.get("source_api") or "cross_chain",
                  provider=ev.get("source_api"), timestamp=ev.get("tx_timestamp"),
                  confidence=confidence, evidence=[ev.get("evidence_ref")] if ev.get("evidence_ref") else [],
                  event_type=ev.get("event_type"), dest_chain=ev.get("dest_chain"))

    return g
