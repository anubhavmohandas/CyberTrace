#!/usr/bin/env python3
"""RESEARCH_LOOP49.md: before/after report for upstream-dependency awareness
over the real local attribution corpus -- no synthetic data, no case, no
network. Answers two things concretely:

  1. Reproduces RESEARCH_LOOP48.md Sec.4's 99.5%-concentration finding
     programmatically (cybertrace.dependency.concentration_report), instead
     of it staying a one-off hand-run query.
  2. For every real address the local corpus attributes under MORE THAN ONE
     tier, reports the naive "how many tiers hit this" count against
     independent_evidence_count -- the concrete BEFORE/AFTER this loop's
     brief asked for.

    python tools/dependency_report.py
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybertrace import dependency
from cybertrace.integrations import exchange_tags, ofac


def _corpus_available() -> bool:
    return (exchange_tags.available() and exchange_tags.index_available()
            and ofac.available() and ofac.index_available())


def main() -> None:
    if not _corpus_available():
        print("Local OFAC/GraphSense corpora not downloaded/indexed in this "
              "checkout -- nothing to report.")
        return

    print("=== 1. Concentration (RESEARCH_LOOP48.md Sec.4, reproduced) ===")
    report = dependency.concentration_report()
    print(f"category='exchange' rows total:  {report['total_rows']:,}")
    print(f"distinct source URLs:            {report['distinct_sources']}")
    print(f"distinct upstream groups:        {report['distinct_upstreams']}")
    top = report["top_source"]
    print(f"largest single source:           {top['rows']:,} rows "
          f"({top['pct']}%) -- {top['key']}")
    topu = report["top_upstream"]
    print(f"largest upstream group:          {topu['rows']:,} rows "
          f"({topu['pct']}%) -- {topu['key']}")

    print("\n=== 2. Before/after: real addresses attributed by >1 tier ===")
    exchange_rows = exchange_tags.all_exchange_addresses()   # TAG_ATTESTED universe
    disclosed_rows = exchange_tags.all_vasp_disclosed()      # VASP_DISCLOSED universe
    ofac_rows = ofac.all_addresses()                         # REGULATORY_ATTESTED universe

    # One hit per (address, TIER) -- first row wins, same as exchange_labels()/
    # vasp_disclosed_labels()'s own "first tag wins" dict.setdefault semantics
    # (correlate._vasp_endpoints never sees more than one hit per tier either).
    # Without this, an address tagged by several packs under the SAME tier
    # (e.g. two different GraphSense packs both calling it Binance) inflates
    # the naive count as if it were several TIERS agreeing, which overstates
    # the real question this report answers: are the (at most 4) *tiers* that
    # hit this address independent, or do some of them share one upstream.
    by_key: dict = {}
    for r in exchange_rows:
        key = (r["currency"], r["address"])
        by_key.setdefault(key, {}).setdefault(
            "TAG_ATTESTED", dependency.resolve_tag_upstream(r["pack"]))
    for r in disclosed_rows:
        key = (r["currency"], r["address"])
        by_key.setdefault(key, {}).setdefault(
            "VASP_DISCLOSED", dependency.resolve_disclosure_upstream(r["brand"]))
    for r in ofac_rows:
        key = (r["currency"], r["address"])
        by_key.setdefault(key, {}).setdefault(
            "REGULATORY_ATTESTED", dependency.resolve_regulatory_upstream())
    by_key = {k: list(v.items()) for k, v in by_key.items()}

    multi = {k: v for k, v in by_key.items() if len(v) > 1}
    collapsed = 0   # naive count > independent_evidence_count
    genuinely_independent = 0
    naive_total, independent_total = 0, 0
    examples = []
    for key, hits in multi.items():
        naive = len(hits)
        indep = dependency.independent_evidence_count(u for _, u in hits)
        naive_total += naive
        independent_total += indep
        if indep < naive:
            collapsed += 1
            if len(examples) < 5:
                examples.append((key, hits, naive, indep))
        else:
            genuinely_independent += 1

    print(f"addresses hit by >1 tier:              {len(multi)}")
    print(f"  -> tiers actually independent:       {genuinely_independent}")
    print(f"  -> tiers sharing one upstream:        {collapsed}")
    print(f"naive 'sources agree' count, summed:   {naive_total}")
    print(f"independent_evidence_count, summed:    {independent_total}")
    if examples:
        print("\nExamples where dependency resolution changes the count:")
        for (currency, addr), hits, naive, indep in examples:
            tiers = ", ".join(f"{t}({u})" for t, u in hits)
            print(f"  {currency} {addr}: naive={naive} independent={indep} -- {tiers}")

    print("\n=== 3. Tier distribution of upstream groups ===")
    counts = Counter(u for hits in by_key.values() for _, u in hits)
    for upstream, n in counts.most_common(10):
        print(f"  {n:>7,}  {upstream}")


if __name__ == "__main__":
    main()
