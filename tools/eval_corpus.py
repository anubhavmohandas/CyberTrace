#!/usr/bin/env python3
"""Score the correlation engine against the labeled corpus.

    python tools/eval_corpus.py runs/raw/v5/*.json runs/raw/v6/*.json runs/raw/v7/*.json runs/raw/v8/*.json
    python tools/eval_corpus.py runs/raw/v5/*.json runs/raw/v6/*.json runs/raw/v7/*.json runs/raw/v8/*.json --labels corpus/labels.toml --pairs

Ingests the saved runs into one throwaway store, runs the full correlation pass,
and compares what the engine claimed about each pair of targets against
corpus/labels.toml.

The number that matters is not accuracy. Most pairs in any corpus are unrelated,
so a tool that claims nothing scores ~95% and is worthless. What is reported
instead:

    operator precision   of the pairs called SAME_OPERATOR, how many are
    operator recall      of the truly-same-operator pairs, how many were found
    ecosystem leakage    same-platform pairs wrongly called same-operator —
                         the failure this corpus exists to catch
    false attribution    unrelated pairs called same-operator

Ecosystem leakage is reported separately from ordinary false positives on
purpose. An unrelated pair scoring high is usually one noisy artifact; a
same-platform pair scoring high means the engine cannot tell a software family
from a person, which is the difference between an investigative tool and a
coincidence counter.

Exit code is 1 if any same-platform or unrelated pair was called SAME_OPERATOR,
so this can gate a change to the scoring model.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybertrace.correlate import market_artifact_map, run_correlation
from cybertrace.evidence import EvidenceStore, ingest

SAME_OPERATOR, SAME_ECOSYSTEM, UNRELATED = "SAME_OPERATOR", "SAME_ECOSYSTEM", "UNRELATED"
# Not a relation: what the engine ranked but refused to assert. Kept apart from
# UNRELATED in the report so "never saw it" and "saw it, would not claim it"
# stay distinguishable — they call for completely different follow-up.
LEAD = "LEAD"


def load_labels(path: Path) -> dict:
    """onion -> {name, operator, platform, basis}, lowercased keys."""
    data = tomllib.loads(path.read_text())
    return {t["onion"].strip().lower(): t for t in data.get("target", [])}


def evidence_class(a: dict, b: dict) -> str:
    """What a same-operator pair actually shares, per corpus/labels.toml.

    Recall over all positives mixes three different questions. Riseup's 21 pairs
    share a public-service domain and nothing else, so recovering them would
    mean promoting co-reference to shared control — the move that manufactures
    false attribution. The nowhere.moe family shares nothing recoverable at all.
    Only the `operator-specific` pairs ask the question the engine exists to
    answer, and averaging them together hides both the successes and the
    honest impossibilities.
    """
    ca, cb = a.get("evidence_class"), b.get("evidence_class")
    return ca if ca and ca == cb else "unclassified"


def truth(a: dict, b: dict) -> str | None:
    """Ground-truth relation between two labeled targets, None if unlabeled.

    'unknown' is not a platform. Two sites whose stack nobody identified share
    an absence of information, not an ecosystem, and pairing them would grade
    the engine against a label the corpus cannot support.
    """
    if not a.get("operator") or not b.get("operator"):
        return None
    if a["operator"] == b["operator"]:
        return SAME_OPERATOR
    platform = a.get("platform")
    if platform and platform not in ("unknown", "") and platform == b.get("platform"):
        return SAME_ECOSYSTEM
    return UNRELATED


def predictions(results: dict, urls: dict) -> dict:
    """frozenset({url_a, url_b}) -> (verdict, why).

    An OPERATOR candidate spanning two markets IS the engine claiming shared
    control of them — that is what the candidate means — so it is read as a
    SAME_OPERATOR prediction here rather than waiting for some separate verdict
    the engine never emits. An unsuppressed SUCCESSOR_OF edge claims the same
    thing across time.
    """
    out: dict = {}

    def claim(pair, verdict, why):
        # SAME_OPERATOR is the strongest claim: once made, a weaker signal about
        # the same pair does not soften it.
        if out.get(pair, ("", ""))[0] != SAME_OPERATOR:
            out[pair] = (verdict, why)

    for cand in results["operators"]:
        markets = sorted({urls.get(m, m) for m in cand["markets"]})
        for a, b in combinations(markets, 2):
            claim(frozenset((a, b)), SAME_OPERATOR,
                  f"operator candidate {cand['etype']} {cand['value'][:32]} "
                  f"(score {cand['score']:.2f})")

    for s in results["successors"]:
        pair = frozenset((s.get("source_url"), s.get("target_url")))
        if None in pair:
            continue
        if s.get("suppressed") in ("BELOW_THRESHOLD", "REFERENCES_ONLY"):
            # Ranked, not claimed. Scored as UNRELATED against ground truth on
            # purpose — the engine did not assert a link — but tallied so a
            # missed positive that WAS surfaced reads differently from one the
            # engine never saw at all.
            claim(pair, LEAD, f"lead only, no edge (score {s['score']:.2f})")
        elif s.get("suppressed"):
            claim(pair, SAME_ECOSYSTEM,
                  f"link refused: {s['suppressed']} (score {s['score']:.2f})")
        else:
            claim(pair, SAME_OPERATOR,
                  f"{s.get('relation')} edge (score {s['score']:.2f})")

    for flag in results["contradictions"]:
        if flag["rule"] == "shared_platform_not_shared_control" and len(flag["markets"]) == 2:
            claim(frozenset(flag["markets"]), SAME_ECOSYSTEM, "shared-platform finding")

    return out


def shared_artifacts(store) -> dict:
    """frozenset({url_a, url_b}) -> [etype …] observed on both targets.

    Read off OK snapshots only, exactly as correlation reads them, so "the pair
    had something in common to work with" means the same thing here as it does
    inside the engine. MARKET and ONION_ADDRESS are excluded: a target's own
    address and storefront node are definitional, and two markets never share
    them without one linking the other, which is not an artifact they hold.
    """
    urls = {r["target_id"]: r["url"] for r in
            store._all("SELECT target_id, url FROM targets")}
    holders: dict = {}
    for target_id, by_type in market_artifact_map(store).items():
        for etype, entity_ids in by_type.items():
            if etype in ("MARKET", "ONION_ADDRESS"):
                continue
            for entity_id in entity_ids:
                holders.setdefault(entity_id, (etype, set()))[1].add(
                    urls.get(target_id, target_id))
    out: dict = {}
    for etype, targets in holders.values():
        ordered = sorted(targets)
        for i, a in enumerate(ordered):
            for b in ordered[i + 1:]:
                out.setdefault(frozenset((a, b)), []).append(etype)
    return out


# Why a true SAME_OPERATOR pair was not recovered. Four separate layers, because
# they call for four different pieces of engineering and the aggregate recall
# number hides which one is actually binding.
#
#   discovery    a labeled sibling was never collected — no crawl reached it
#   collection   collected, but the site never answered, so nothing was extracted
#   artifact     both answered and share no artifact at all — extraction or
#                enrichment did not produce the thing the pair has in common
#   correlation  they DO share an artifact and the engine still declined
#
# Only the last is a scoring problem. Tuning weights against a pair that failed
# at `artifact` moves a threshold to compensate for evidence that was never
# collected, which is how a model gets fitted to its own corpus.
BOTTLENECKS = ("discovery", "collection", "artifact", "correlation")


def bottleneck(in_store: bool, dark: bool, shared: list) -> str:
    if not in_store:
        return "discovery"
    if dark:
        return "collection"
    return "artifact" if not shared else "correlation"


def evaluate(paths: list[Path], labels_path: Path, show_pairs: bool,
             db_path: str) -> int:
    labels = load_labels(labels_path)

    with EvidenceStore(db_path) as store:
        ingested = 0
        for path in paths:
            data = json.loads(path.read_text())
            if ingest(data, store):
                ingested += 1
            else:
                print(f"  ! {path.name}: nothing ingested", file=sys.stderr)
        results = run_correlation(store)
        urls = {r["target_id"]: r["url"] for r in
                store._all("SELECT target_id, url FROM targets")}
        in_store = {u for u in urls.values()}
        # Targets that actually answered: anything else contributed no artifacts.
        live = {r["url"] for r in store._all(
            "SELECT DISTINCT t.url FROM targets t JOIN snapshots s "
            "ON s.target_id = t.target_id WHERE s.status='OK' "
            "AND s.collector LIKE 'target_onion%'")}
        shared = shared_artifacts(store)

    predicted = predictions(results, urls)

    matrix: dict = {}
    rows, unevaluable, missed = [], [], []
    # Every labeled pair, not only the pairs both of whose sides reached the
    # store: a sibling that was never collected is a DISCOVERY failure, and
    # iterating the store instead of the labels makes exactly that failure
    # invisible — the pair simply never appears in any tally.
    for a, b in combinations(sorted(labels), 2):
        la, lb = labels[a], labels[b]
        actual = truth(la, lb)
        if actual is None:
            continue
        collected = [url for url in (a, b) if url in in_store]
        dark = [t["name"] for t, url in ((la, a), (lb, b))
                if url in in_store and url not in live]
        verdict, why = predicted.get(frozenset((a, b)), (UNRELATED, ""))
        scored = UNRELATED if verdict == LEAD else verdict
        gradable = len(collected) == 2 and not dark

        in_common = shared.get(frozenset((a, b)), [])
        if actual == SAME_OPERATOR:
            missed.append((
                "recovered" if gradable and scored == SAME_OPERATOR else
                bottleneck(len(collected) == 2, bool(dark), in_common),
                la["name"], lb["name"], evidence_class(la, lb),
                ", ".join(sorted(set(in_common))) or "—"))

        if len(collected) < 2:
            continue                      # never collected: nothing to grade
        # A target that never answered contributes no artifacts, so the engine
        # had nothing to correlate. Counting that as a miss would grade the
        # engine on Tor's weather. Reported separately and loudly instead —
        # silently dropping it would inflate precision the same way.
        if dark:
            unevaluable.append((actual, la["name"], lb["name"], ", ".join(dark),
                                evidence_class(la, lb)))
            continue
        matrix[(actual, scored)] = matrix.get((actual, scored), 0) + 1
        rows.append((actual, verdict, la["name"], lb["name"], why,
                     evidence_class(la, lb)))

    print(f"\ningested {ingested}/{len(paths)} runs · "
          f"{len(in_store)} targets · {len(rows)} labeled pairs scored"
          + (f" · {len(unevaluable)} unevaluable (target dark)" if unevaluable else ""))
    print(f"engine: {len(results['operators'])} operator, {len(results['infra'])} infra, "
          f"{len(results['ips'])} ip candidates · "
          f"{len([s for s in results['successors'] if not s['suppressed']])} successors · "
          f"{len(results['contradictions'])} contradictions")

    print("\n=== confusion (rows = truth, cols = engine) ===")
    classes = [SAME_OPERATOR, SAME_ECOSYSTEM, UNRELATED]
    print(f"{'':16}" + "".join(f"{c:>16}" for c in classes))
    for actual in classes:
        print(f"{actual:16}" + "".join(
            f"{matrix.get((actual, pred), 0):>16}" for pred in classes))

    tp = matrix.get((SAME_OPERATOR, SAME_OPERATOR), 0)
    claimed = sum(matrix.get((a, SAME_OPERATOR), 0) for a in classes)
    real = sum(matrix.get((SAME_OPERATOR, p), 0) for p in classes)
    leak = matrix.get((SAME_ECOSYSTEM, SAME_OPERATOR), 0)
    false_attr = matrix.get((UNRELATED, SAME_OPERATOR), 0)

    print("\n=== headline ===")
    print(f"  operator precision   {tp}/{claimed} = "
          f"{tp / claimed:.2f}" if claimed else "  operator precision   -- (no claims)")
    print(f"  operator recall      {tp}/{real} = "
          f"{tp / real:.2f}" if real else "  operator recall      -- (no positives)")
    leads = [r for r in rows if r[1] == LEAD]
    print(f"  ecosystem leakage    {leak}  (same-platform pairs called same-operator)")
    print(f"  leads surfaced       {len(leads)}  (ranked, not asserted; "
          f"{len([r for r in leads if r[0] == SAME_OPERATOR])} of them true positives)")
    print(f"  false attribution    {false_attr}  (unrelated pairs called same-operator)")

    # Recall by what the pair actually shares. The aggregate above is the sum of
    # three unlike questions; this is the one an acceptance gate can read.
    positives = [r for r in rows if r[0] == SAME_OPERATOR]
    dark_positives = [u for u in unevaluable if u[0] == SAME_OPERATOR]
    print("\n=== operator recall by evidence class ===")
    print(f"{'class':20}{'found':>7}{'evaluable':>11}{'dark':>7}  what a miss means")
    meaning = {
        "operator-specific": "a real miss — the artifact is there to be found",
        "namespace": "the engine declining to promote co-reference; correct",
        "none": "unrecoverable: the sites publish nothing in common",
        "unverified": "operator known from its own listing, shared evidence never observed",
        "unclassified": "family not labeled with an evidence class",
    }
    for klass in ("operator-specific", "namespace", "none", "unverified",
                  "unclassified"):
        group = [r for r in positives if r[5] == klass]
        dark_n = len([u for u in dark_positives if u[4] == klass])
        if not group and not dark_n:
            continue
        found = len([r for r in group if r[1] == SAME_OPERATOR])
        print(f"{klass:20}{found:>7}{len(group):>11}{dark_n:>7}  {meaning[klass]}")

    # Which layer lost each true pair. Recall alone cannot say whether to build
    # a crawler, an extractor or a scorer, and those are the only three answers.
    print("\n=== where the true pairs are lost ===")
    print(f"{'layer':14}{'pairs':>7}  what would have to change")
    fix = {
        "recovered": "nothing — the engine asserted this pair",
        "discovery": "collection: the sibling onion was never fetched",
        "collection": "the site never answered; retry, or accept it as dark",
        "artifact": "extraction/enrichment: the pair shares NO artifact at all",
        "correlation": "scoring: they share an artifact and the engine declined",
    }
    for layer in ("recovered", *BOTTLENECKS):
        group = [m for m in missed if m[0] == layer]
        if group:
            print(f"{layer:14}{len(group):>7}  {fix[layer]}")
    stuck = [m for m in missed if m[0] == "correlation"]
    if stuck:
        print("\n  pairs that share an artifact and were still not asserted:")
        for _layer, na, nb, klass, in_common in sorted(stuck)[:12]:
            print(f"    {na} ~ {nb}  [{klass}]  shares: {in_common}")

    if unevaluable:
        print("\n=== unevaluable — target never answered, not the engine's miss ===")
        for actual, na, nb, dark, _klass in sorted(unevaluable):
            print(f"  {actual:14} {na} ~ {nb}   (dark: {dark})")

    if show_pairs:
        print("\n=== pairs ===")
        for actual, verdict, na, nb, why, klass in sorted(rows):
            mark = "ok " if actual == verdict else "MISS"
            klass = f" [{klass}]" if actual == SAME_OPERATOR else ""
            print(f"  [{mark}] {actual:14} -> {verdict:14} {na} ~ {nb}{klass}"
                  + (f"  ({why})" if why else ""))

    return 1 if (leak or false_attr) else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", nargs="+", type=Path, help="saved --save JSON files")
    ap.add_argument("--labels", type=Path, default=Path("corpus/labels.toml"))
    ap.add_argument("--pairs", action="store_true", help="print every scored pair")
    ap.add_argument("--db", default=":memory:",
                    help="write the evidence store here instead of memory")
    args = ap.parse_args()

    missing = [p for p in args.results if not p.is_file()]
    if missing:
        ap.error(f"no such file: {', '.join(str(p) for p in missing)}")
    if not args.labels.is_file():
        ap.error(f"labels not found: {args.labels}")
    return evaluate(args.results, args.labels, args.pairs, args.db)


if __name__ == "__main__":
    raise SystemExit(main())
