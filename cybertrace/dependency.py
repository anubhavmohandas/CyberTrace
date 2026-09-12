"""Upstream dependency resolution for the 4-tier VASP attribution evidence
(`correlate.py`'s ANALYST_ASSERTED/REGULATORY_ATTESTED/VASP_DISCLOSED/
TAG_ATTESTED) -- research finding: RESEARCH_LOOP48.md Parts B-D; production
gap this closes: RESEARCH_LOOP49.md.

The problem, measured on the real local corpus (RESEARCH_LOOP48.md Sec.4):
337,744 `category='exchange'` GraphSense TagPack rows trace to only 143
distinct source URLs, and one URL -- BitMEX's own 2022-11-15 proof-of-
reserves snapshot -- supplies 336,208 of them (99.5%). Two of CyberTrace's
four attribution tiers (TAG_ATTESTED and VASP_DISCLOSED) are both read from
that same tagpack archive at one commit; a hypothetical future "N tiers
agree" corroboration count would in most cases be counting one document
twice, not two observers. This module names that shared origin so a caller
CAN tell -- it does not change `correlate.py`'s existing tier ranking,
attribution algorithm, or risk scoring; see correlate.py's `_vasp_endpoints`
for the one place it is consumed (additive `dependency_groups`/
`independent_evidence_count` fields only).

`resolve_*` functions turn one attribution hit into an `upstream_source`
id -- an opaque string naming the real-world origin, not a display label.
Two hits with the same id are the same underlying fact republished, not two
independent attestors. The registry below is hand-verified against the pack
headers actually on disk (`external_data/exchange_tags/original/
graphsense-tagpacks.zip`), the same discipline exchange_tags.py's own
_VASP_DISCLOSED_SOURCES table uses -- extend it only after checking a pack's
real `source`/`creator` header, never by filename guess.
"""

from __future__ import annotations

import sqlite3
from typing import Dict, Iterable

# pack (file stem, exchange_tags.py's `pack` column) -> upstream_source id.
# Anything not listed here defaults to "tagpack:<pack>" (resolve_tag_upstream)
# -- i.e. treated as its own independent upstream, which is the honest
# default absent a checked reason to merge it with another.
#
# The two real cross-tier links this project's corpus actually has:
#  - "ofac": the GraphSense-repackaged copy of the US Treasury SDN list
#    (source: treasury.gov/ofac/downloads/sdnlist.txt, lastmod 2024-02-26) is
#    the SAME real-world fact as CyberTrace's own direct SDN Advanced XML
#    pull (integrations/ofac.py, source sanctionslistservice.ofac.treas.gov,
#    retrieved 2026-08-28) -- different endpoint, different fetch date, one
#    government list. Mapped to REGULATORY_UPSTREAM so the two can never look
#    like two agreeing sources. (Currently inert in production: this pack's
#    tags carry category='user', not 'exchange', so exchange_labels() never
#    surfaces it -- see RESEARCH_LOOP48.md Sec.4's "category-vocabulary
#    accident" note. Registered anyway so the link is caught the moment that
#    changes, not after.)
#  - "exchange-wallets-bitmex_0".."_6": seven separate pack FILES, verified
#    (unzip -p) to carry the byte-identical `source` URL -- BitMEX's one
#    2022-11-15 S3 snapshot. Same for each other brand's own
#    "exchange-wallets-<brand>" pack against exchange_tags.py's
#    _VASP_DISCLOSED_SOURCES: grouped here under the identical
#    "vasp_disclosure:<brand>" id resolve_disclosure_upstream produces, so a
#    TAG_ATTESTED hit on one of these packs (which exchange_labels() does
#    return -- these packs' tags ARE category='exchange') and the
#    VASP_DISCLOSED hit that _vasp_endpoints promotes it to are recognized as
#    one disclosure, not two.
REGULATORY_UPSTREAM = "us_ofac_sdn"

_PACK_UPSTREAM: Dict[str, str] = {
    "ofac": REGULATORY_UPSTREAM,
    "walletexplorer": "walletexplorer_heuristic_clustering",
    "etherscan-label-word-cloud": "etherscan_label_ui",
    "etherscan-wordcloud-exchange": "etherscan_label_ui",
    "etherscan-wordcloud-gambling": "etherscan_label_ui",
    "etherscan-wordcloud-market": "etherscan_label_ui",
    "etherscan-wordcloud-miner": "etherscan_label_ui",
    "etherscan-wordcloud-mixing_service": "etherscan_label_ui",
    "exchange-wallets-bitmex_0": "vasp_disclosure:BitMEX",
    "exchange-wallets-bitmex_1": "vasp_disclosure:BitMEX",
    "exchange-wallets-bitmex_2": "vasp_disclosure:BitMEX",
    "exchange-wallets-bitmex_3": "vasp_disclosure:BitMEX",
    "exchange-wallets-bitmex_4": "vasp_disclosure:BitMEX",
    "exchange-wallets-bitmex_5": "vasp_disclosure:BitMEX",
    "exchange-wallets-bitmex_6": "vasp_disclosure:BitMEX",
    "exchange-wallets-bitfinexcom": "vasp_disclosure:Bitfinex",
    "exchange-wallets-binance": "vasp_disclosure:Binance",
    "exchange-wallets-huobi": "vasp_disclosure:Huobi",
    "exchange-wallets-kucoin": "vasp_disclosure:KuCoin",
    "exchange-wallets-bybit": "vasp_disclosure:Bybit",
    "exchange-wallets-deribit": "vasp_disclosure:Deribit",
    "exchange-wallets-okx": "vasp_disclosure:OKX",
}


def resolve_tag_upstream(pack: str) -> str:
    """TAG_ATTESTED hit (GraphSense tagpack `pack` file stem) -> upstream id."""
    return _PACK_UPSTREAM.get(pack, f"tagpack:{pack}")


def resolve_disclosure_upstream(brand: str) -> str:
    """VASP_DISCLOSED hit -> upstream id, keyed by brand. Each of the 8
    `_VASP_DISCLOSED_SOURCES` URLs is a distinct real first-party publisher
    (RESEARCH_LOOP48.md Sec.3/Sec.12): two different brands are always two
    different upstreams; the same brand is always the same one."""
    return f"vasp_disclosure:{brand}"


def resolve_regulatory_upstream() -> str:
    """REGULATORY_ATTESTED (CyberTrace's own direct OFAC SDN pull) -> upstream
    id. Only one government list in this project, so this is always the same
    id -- and the same one "ofac"-pack TAG_ATTESTED hits resolve to."""
    return REGULATORY_UPSTREAM


def resolve_analyst_upstream(exchange: str) -> str:
    """ANALYST_ASSERTED hit -> upstream id. An analyst's own cited claim is
    never derived from the offline corpora above -- keyed by the exchange
    name asserted purely so two different analyst citations on the same
    address (different brands) don't collide into one id; it never merges
    with a tagpack/disclosure/regulatory id."""
    return f"analyst_citation:{exchange}"


def independent_evidence_count(upstreams: Iterable[str]) -> int:
    """How many of these attribution hits are genuinely independent, once
    shared upstream is accounted for -- the count a naive `len(hits)` would
    overstate whenever two hits share an upstream id."""
    return len(set(upstreams))


def concentration_report(category: str = "exchange") -> dict:
    """Reproduces RESEARCH_LOOP48.md Sec.4's 99.5%-concentration finding
    programmatically, against whatever local corpus is actually on disk right
    now, instead of leaving it as a one-off hand-run query.

    Two groupings, both real and checkable against each other:
      by_source    raw `source` URL column, exactly as Sec.4 queried it.
      by_upstream  `pack` column resolved through resolve_tag_upstream --
                   coarser (collapses BitMEX's 7 packs, which already share
                   one `source` URL, into the same bucket as `by_source`
                   would, but ALSO would catch a future case where the same
                   real-world fact ships under two different exact URLs, the
                   thing `by_source` alone cannot see -- e.g. the OFAC
                   direct-pull/`ofac`-pack link, if that pack's category
                   were ever added).

    Returns {} if the local tagpack index isn't built (same degrade-quietly
    contract as exchange_tags.py's own lookups) rather than raising.
    """
    from .integrations import exchange_tags

    if not (exchange_tags.available() and exchange_tags.index_available()):
        return {}

    by_source: Dict[str, int] = {}
    by_pack: Dict[str, int] = {}
    total = 0
    conn = sqlite3.connect(f"file:{exchange_tags.INDEX_PATH}?mode=ro", uri=True)
    try:
        for source, pack, n in conn.execute(
                "SELECT source, pack, COUNT(*) FROM tags "
                "WHERE lower(category)=? GROUP BY source, pack", (category,)):
            by_source[source] = by_source.get(source, 0) + n
            by_pack[pack] = by_pack.get(pack, 0) + n
            total += n
    finally:
        conn.close()

    by_upstream: Dict[str, int] = {}
    for pack, n in by_pack.items():
        upstream = resolve_tag_upstream(pack)
        by_upstream[upstream] = by_upstream.get(upstream, 0) + n

    def _top(counts: Dict[str, int]) -> dict:
        if not counts:
            return {"key": None, "rows": 0, "pct": 0.0}
        key, rows = max(counts.items(), key=lambda kv: kv[1])
        return {"key": key, "rows": rows,
                "pct": round(100.0 * rows / total, 1) if total else 0.0}

    return {
        "category": category,
        "total_rows": total,
        "distinct_sources": len(by_source),
        "distinct_upstreams": len(by_upstream),
        "top_source": _top(by_source),
        "top_upstream": _top(by_upstream),
    }
