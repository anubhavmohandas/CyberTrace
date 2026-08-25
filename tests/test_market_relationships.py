"""Regression for the Workspace graph's market-cardinality defect: buildGraph
(web/CyberTrace Workspace.dc.html) used to special-case `cd.markets.length
=== 2` to decide whether to draw the market<->market edge, so a 3rd market
silently dropped every inter-market relationship from the graph.

The fix has build_payload() (tools/export_case_gui.py) expose the pairs
correlate.detect_successors() already computes as `market_relationships`,
and buildGraph draws one edge per entry regardless of how many markets exist.
These tests cover the backend shape that fix depends on: 1/2/3+ markets, and
that an absent relationship is never fabricated. The frontend side is guarded
by test_graph_no_hardcoded_market_count below (static, no browser needed —
same convention as test_graph_svg_raw_parse.py).
"""
from pathlib import Path

from cybertrace.evidence import EvidenceStore, ingest

from tools.export_case_gui import build_payload

from .test_evidence import BTC_BECH32, BTC_VALID, KEY_A, ONION_A, ONION_B, _result, onion

ONION_C, ONION_D, ONION_E = onion("c"), onion("d"), onion("e")

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "web" / "CyberTrace Workspace.dc.html"

# entity_discrimination() only judges commonness once a corpus has >= 3
# targets, discounting anything shared by too large a fraction of it. Two
# filler markets with no shared artifacts keep the corpus large enough (5)
# that a PGP key or BTC address shared by exactly one real pair still scores
# as rare, not "common across the corpus" — same reasoning as the module's
# own "corpus too small to judge" comment.


def test_one_market_has_no_market_relationship():
    with EvidenceStore(":memory:") as store:
        ingest(_result(ONION_A, emails=['op@proton.me']), store)
        case = build_payload(store, "CASE-1", "one market")

    assert case["markets"] == [ONION_A]
    assert case["market_relationships"] == []


def test_two_markets_preserves_existing_linked_edge():
    with EvidenceStore(":memory:") as store:
        for m in (ONION_A, ONION_B):
            ingest(_result(m, pgp_keys=[{'armored': KEY_A}]), store)
        case = build_payload(store, "CASE-2", "two markets")

    assert set(case["markets"]) == {ONION_A, ONION_B}
    assert len(case["market_relationships"]) == 1
    rel = case["market_relationships"][0]
    assert {rel["source"], rel["target"]} == {ONION_A, ONION_B}
    assert rel["relation"] == "LINKED_TO"
    assert rel["suppressed"] is None


def test_three_markets_all_relationships_render():
    """A-B share a PGP key, B-C share a BTC address, A-C share a different BTC
    address: three markets, three real pairwise relationships. The old
    `markets.length === 2` graph logic could show at most one of these —
    every one of them must render now."""
    with EvidenceStore(":memory:") as store:
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A}],
                       bitcoin_addresses=[BTC_BECH32]), store)
        ingest(_result(ONION_B, pgp_keys=[{'armored': KEY_A}],
                       bitcoin_addresses=[BTC_VALID]), store)
        ingest(_result(ONION_C, bitcoin_addresses=[BTC_VALID, BTC_BECH32]), store)
        ingest(_result(ONION_D), store)
        ingest(_result(ONION_E), store)
        case = build_payload(store, "CASE-3", "three markets, three relationships")

    assert set(case["markets"]) == {ONION_A, ONION_B, ONION_C, ONION_D, ONION_E}
    pairs = {frozenset((r["source"], r["target"])) for r in case["market_relationships"]}
    assert pairs == {frozenset((ONION_A, ONION_B)),
                     frozenset((ONION_B, ONION_C)),
                     frozenset((ONION_A, ONION_C))}
    assert all(r["relation"] == "LINKED_TO" and r["suppressed"] is None
               for r in case["market_relationships"])


def test_three_markets_missing_relationship_not_fabricated():
    """A-B share a PGP key, B-C share a BTC address, A-C share nothing at all.
    The graph must carry exactly those two relationships — never an A-C edge
    invented merely because a third market exists, and never a dropped B-C
    edge merely because there are now more than two markets."""
    with EvidenceStore(":memory:") as store:
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, pgp_keys=[{'armored': KEY_A}],
                       bitcoin_addresses=[BTC_VALID]), store)
        ingest(_result(ONION_C, bitcoin_addresses=[BTC_VALID]), store)
        ingest(_result(ONION_D), store)
        ingest(_result(ONION_E), store)
        case = build_payload(store, "CASE-3", "three markets, one absent relationship")

    assert set(case["markets"]) == {ONION_A, ONION_B, ONION_C, ONION_D, ONION_E}
    pairs = {frozenset((r["source"], r["target"])) for r in case["market_relationships"]}
    assert pairs == {frozenset((ONION_A, ONION_B)), frozenset((ONION_B, ONION_C))}
    assert frozenset((ONION_A, ONION_C)) not in pairs

    # Each candidate's own per-market attribution also survives with 5
    # markets in play — not just the market-to-market edges.
    key_candidate = next(c for c in case["candidates"] if c["etype"] == "PGP_KEY")
    assert set(key_candidate["markets"]) == {ONION_A, ONION_B}


def test_graph_no_hardcoded_market_count():
    """Static guard: buildGraph must derive market<->market edges from
    cd.market_relationships, not from assuming exactly two markets exist."""
    js = WORKSPACE.read_text()
    start = js.index("function buildGraph(cd)")
    end = js.index("\nclass Component", start)
    fn = js[start:end]

    assert "market_relationships" in fn, (
        "buildGraph no longer reads cd.market_relationships — it must consume "
        "the backend-computed market-pair relationships directly"
    )
    assert "markets.length" not in fn, (
        "buildGraph reintroduced a markets.length cardinality check — this is "
        "exactly the defect where a 3rd market silently drops its relationships"
    )
