#!/usr/bin/env python3
"""Extractor precision audit over saved `cybertrace search --save` JSON.

    python tools/audit_corpus.py runs/*.json

Ingests each saved result into its own throwaway store and reports, per entity
type: how many raw values the extractors handed to the graph, how many earned
an entity, and which ones normalization refused.

    precision = valid / extracted

`valid` here means "survived normalization", which is a machine-checkable
property, NOT "is truly an artifact of this operator". A `bc1...` that
checksums is valid and may still be a payment address the market copied from
someone else. So the accepted values are printed too: the false_positive
column of the audit is a human reading that list. The script measures what a
machine can measure and shows its work for the rest.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybertrace.evidence import EvidenceStore, ingest


def audit(paths: list[Path], show_values: bool) -> int:
    accepted: dict[str, Counter] = defaultdict(Counter)
    rejected: dict[str, Counter] = defaultdict(Counter)
    enriched: Counter = Counter()
    per_target: list[tuple] = []

    # Entities the extractors read off the site, and separately the ones only an
    # index had on file. Counting the entities table wholesale conflated the two
    # and reported eleven artifacts for a target that never answered — the exact
    # claim this audit exists to make checkable.
    OBSERVED = ("SELECT DISTINCT e.etype, e.normalized_value, e.metadata "
                "FROM entities e JOIN observations o ON o.entity_id = e.entity_id "
                "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
                "WHERE s.status=?")

    for path in paths:
        data = json.loads(path.read_text())
        # A run whose target was never fetched measures the clearnet-index
        # fallback, not the extractors. It belongs in the tally only as a known
        # blank, otherwise a corpus of dead onions reads as high precision.
        visited = any((data.get("sources") or {}).get(s, {}).get("success")
                      for s in ("target_onion", "operator_pivot"))
        if not visited:
            print(f"  ! {path.name}: target never fetched — extractors never ran",
                  file=sys.stderr)
        # Each target gets a clean store so one market's artifacts are not
        # counted again as the next one's. Cross-target dedup is correlate's
        # job; conflating the two here would silently inflate precision.
        with EvidenceStore(":memory:") as store:
            if not ingest(data, store):
                print(f"  ! {path.name}: nothing ingested "
                      f"(no target, or every source failed)", file=sys.stderr)
            rows = store.conn.execute(OBSERVED, ("OK",)).fetchall()
            discovered = store.conn.execute(OBSERVED, ("DISCOVERY",)).fetchall()
            for row in rows:
                accepted[row["etype"]][row["normalized_value"]] += 1
                if row["metadata"] and row["metadata"] not in ("{}", ""):
                    enriched[row["etype"]] += 1
            for (etype, raw), n in store.rejected.items():
                rejected[etype][raw] += n
            per_target.append((path.name, len(rows), sum(store.rejected.values()),
                               visited, len(discovered)))

    print("\n=== per target ===")
    print(f"{'target':<30}{'observed':>10}{'rejected':>10}{'precision':>11}"
          f"{'fetched':>9}{'discovery':>11}")
    for name, ok, bad, was_visited, disc in per_target:
        total = ok + bad
        p = f"{ok / total:.2f}" if total else "--"
        print(f"{name[:29]:<30}{ok:>10}{bad:>10}{p:>11}"
              f"{'yes' if was_visited else 'NO':>9}{disc:>11}")
    # A target that never answered must show a blank observed column: whatever
    # an index still had on file is discovery, and belongs in the last column.
    leaked = [n for n, ok, _b, was_visited, _d in per_target if ok and not was_visited]
    if leaked:
        print(f"\n  ! target-observed artifacts from never-fetched targets: "
              f"{', '.join(leaked)}", file=sys.stderr)

    print("\n=== per entity type (corpus, target-observed only) ===")
    print(f"{'type':<20}{'extracted':>10}{'valid':>7}{'rejct':>7}"
          f"{'precision':>11}{'enriched':>10}")
    for etype in sorted(set(accepted) | set(rejected)):
        ok = len(accepted[etype])
        # .get, not [etype]: a defaultdict lookup here inserts an empty Counter,
        # which makes the `if rejected` below fire and print an empty section.
        bad = sum(rejected.get(etype, {}).values())
        total = ok + bad
        p = f"{ok / total:.2f}" if total else "--"
        print(f"{etype:<20}{total:>10}{ok:>7}{bad:>7}{p:>11}{enriched[etype]:>10}")

    if rejected:
        print("\n=== rejected (normalizer caught these) ===")
        for etype in sorted(rejected):
            for raw, n in rejected[etype].most_common(12):
                print(f"  {etype:<18} {raw!r}" + (f"  x{n}" if n > 1 else ""))

    if show_values:
        print("\n=== accepted — read these for false positives ===")
        for etype in sorted(accepted):
            for value, n in accepted[etype].most_common(25):
                print(f"  {etype:<18} {value}" + (f"  x{n}" if n > 1 else ""))

    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", nargs="+", type=Path, help="saved --save JSON files")
    ap.add_argument("--values", action="store_true",
                    help="print accepted values for manual false-positive review")
    args = ap.parse_args()

    missing = [p for p in args.results if not p.is_file()]
    if missing:
        ap.error(f"no such file: {', '.join(str(p) for p in missing)}")
    return audit(args.results, args.values)


if __name__ == "__main__":
    raise SystemExit(main())
