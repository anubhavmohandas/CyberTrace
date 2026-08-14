#!/usr/bin/env python3
"""Score the correlation engine against the labeled corpus.

    python tools/eval_corpus.py runs/raw/v2/*.json
    python tools/eval_corpus.py runs/raw/v2/*.json --labels corpus/labels.toml --pairs

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

from cybertrace.correlate import run_correlation
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

    predicted = predictions(results, urls)

    matrix: dict = {}
    rows, unevaluable = [], []
    for a, b in combinations(sorted(in_store), 2):
        la, lb = labels.get(a.split("/")[0]), labels.get(b.split("/")[0])
        if not (la and lb):
            continue
        actual = truth(la, lb)
        if actual is None:
            continue
        # A target that never answered contributes no artifacts, so the engine
        # had nothing to correlate. Counting that as a miss would grade the
        # engine on Tor's weather. Reported separately and loudly instead —
        # silently dropping it would inflate precision the same way.
        dark = [t["name"] for t, url in ((la, a), (lb, b)) if url not in live]
        if dark:
            unevaluable.append((actual, la["name"], lb["name"], ", ".join(dark),
                                evidence_class(la, lb)))
            continue
        verdict, why = predicted.get(frozenset((a, b)), (UNRELATED, ""))
        scored = UNRELATED if verdict == LEAD else verdict
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
