#!/usr/bin/env python3
"""Score cybertrace.stylometry's n-gram author-profile similarity against
external_data/evolution's own ground truth -- the Phase 2 validation gate
before any BEHAVIORAL_SIMILARITY signal is allowed near correlate.py.

    python tools/eval_stylometry.py

Three pair buckets, never blended together:

    same_platform     network/nodes.tsv: multiple forum uids Evolution's own
                       record ties to one match_id (account changes). Same
                       genre (post vs. post) -- the fair test, and the only
                       one whose precision/recall decides the gate.
    cross_platform     forum-market/user-matching.tsv (uid<->vid): forum post
                       text vs. that vendor's listing descriptions. Different
                       genre (chat vs. product copy) -- reported separately,
                       expected noisier, never used to inflate the headline
                       number.
    different_author   random pairs across distinct match_ids. Standard
                       authorship-attribution baseline assumption: distinct
                       clusters are treated as distinct people. Evolution
                       cannot prove that, and neither can this script.

Like tools/eval_corpus.py, the number that matters is precision/recall at a
threshold, not raw accuracy -- most pairs of anyone are unrelated.
"""
from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybertrace.integrations import evolution
from cybertrace.stylometry import clean_text, profile, similarity


def _dedup_join(texts: List[str]) -> str:
    # Canned/templated posts (welcome messages, mod boilerplate) are real in
    # this corpus -- exact-repeat text is dropped before joining so it can't
    # inflate a profile's similarity to itself for a reason unrelated to
    # style.
    seen, kept = set(), []
    for t in texts:
        if t and t not in seen:
            seen.add(t)
            kept.append(t)
    return " ".join(kept)


def build_forum_profiles(min_chars: int, n: int, top_k: int) -> Dict[str, object]:
    raw: Dict[str, List[str]] = defaultdict(list)
    start = time.perf_counter()
    for i, row in enumerate(evolution.iter_forum_posts(), 1):
        uid = row.get("uid")
        text = clean_text(row.get("text") or "")
        if uid and text:
            raw[uid].append(text)
        if i % 50000 == 0:
            elapsed = time.perf_counter() - start
            print(f"  ...{i} posts read ({i / elapsed:.0f}/s, {len(raw)} distinct authors so far)",
                  flush=True)
    print(f"  {i} posts read in {time.perf_counter() - start:.0f}s -- building profiles...", flush=True)
    out = {}
    for uid, texts in raw.items():
        joined = _dedup_join(texts)
        if len(joined) >= min_chars:
            out[uid] = profile(joined, n=n, top_k=top_k)
    return out


def build_vendor_profiles(vids_needed: set, min_chars: int, n: int, top_k: int) -> Dict[str, object]:
    raw: Dict[str, List[str]] = defaultdict(list)
    start = time.perf_counter()
    for i, row in enumerate(evolution.iter_listings(), 1):
        vid = row.get("vid")
        if vid in vids_needed:
            text = clean_text(row.get("description") or "")
            if text:
                raw[vid].append(text)
        if i % 200000 == 0:
            print(f"  ...{i} listings read ({i / (time.perf_counter() - start):.0f}/s)", flush=True)
    print(f"  {i} listings read in {time.perf_counter() - start:.0f}s -- building profiles...", flush=True)
    out = {}
    for vid, texts in raw.items():
        joined = _dedup_join(texts)
        if len(joined) >= min_chars:
            out[vid] = profile(joined, n=n, top_k=top_k)
    return out


def same_platform_groups() -> List[set]:
    """One group per network/nodes.tsv row that names >=2 forum uids as one
    identity -- the row itself is the grouping unit.

    match_id is NOT a reliable cross-row clustering key, discovered by
    measuring the real table after a first pass grouped on it produced
    ~96 million "pairs" from 25 groups: match_id is blank on 26,325 of
    28,911 rows (91%), and every *non-blank* value occurs on exactly one
    row. Two separate rows never legitimately share one match_id in this
    dataset -- grouping on it collapsed all 26,325 blank rows into one fake
    26,325-member "identity". Only 38 rows actually name a second/third uid
    (secondary_uid/tertiary_uid non-empty), and that is the real ground
    truth this function returns."""
    groups = []
    for row in evolution.iter_identity_nodes():
        members = {row[col] for col in ("uid", "secondary_uid", "tertiary_uid") if row.get(col)}
        if len(members) >= 2:
            groups.append(members)
    return groups


def linked_pairs(groups: List[set]) -> set:
    """Every (uid, uid) pair known to be the same identity, from the real
    same_platform_groups() -- so negative sampling can reject a pair for a
    verifiable reason instead of trusting the unreliable match_id column."""
    out = set()
    for g in groups:
        ordered = sorted(g)
        for i, a in enumerate(ordered):
            for b in ordered[i + 1:]:
                out.add(frozenset((a, b)))
    return out


def evaluate(min_chars: int, n: int, top_k: int, max_negatives: int, seed: int) -> int:
    random.seed(seed)

    print("loading forum posts and building per-author profiles (one streaming pass)...")
    forum_profiles = build_forum_profiles(min_chars, n, top_k)
    print(f"  {len(forum_profiles)} forum accounts cleared the {min_chars}-char profile floor")

    groups = same_platform_groups()
    same_platform_pairs = [(a, b) for g in groups for i, a in enumerate(sorted(g))
                            for b in sorted(g)[i + 1:]
                            if a in forum_profiles and b in forum_profiles]
    print(f"  {len(groups)} multi-account identities in network/nodes.tsv -> "
          f"{len(same_platform_pairs)} same-platform positive pairs with both profiles present")

    user_matches = [(row["uid"], row["vid"]) for row in evolution.iter_user_matching()
                     if row.get("uid") in forum_profiles]
    vids_needed = {vid for _, vid in user_matches}
    print(f"loading vendor listings for {len(vids_needed)} candidate vendors...")
    vendor_profiles = build_vendor_profiles(vids_needed, min_chars, n, top_k)
    cross_platform_pairs = [(uid, vid) for uid, vid in user_matches if vid in vendor_profiles]
    print(f"  {len(cross_platform_pairs)} cross-platform positive pairs with both profiles present")

    known_linked = linked_pairs(groups)
    pool = list(forum_profiles)
    negative_pairs = []
    attempts = 0
    target = min(max_negatives, max(len(same_platform_pairs) * 20, 200))
    while len(negative_pairs) < target and attempts < target * 20 and len(pool) >= 2:
        a, b = random.sample(pool, 2)
        attempts += 1
        if frozenset((a, b)) not in known_linked:
            negative_pairs.append((a, b))
    print(f"  {len(negative_pairs)} different-author negative pairs sampled\n")

    same_sims = [similarity(forum_profiles[a], forum_profiles[b]) for a, b in same_platform_pairs]
    cross_sims = [similarity(forum_profiles[u], vendor_profiles[v]) for u, v in cross_platform_pairs]
    neg_sims = [similarity(forum_profiles[a], forum_profiles[b]) for a, b in negative_pairs]

    def stats(label: str, values: List[float]) -> None:
        if not values:
            print(f"{label}: no pairs")
            return
        print(f"{label}: n={len(values)} mean={statistics.mean(values):.3f} "
              f"median={statistics.median(values):.3f} "
              f"stdev={statistics.pstdev(values):.3f} "
              f"min={min(values):.3f} max={max(values):.3f}")

    print("=== similarity distributions ===")
    stats("same_platform   (positive, same genre)", same_sims)
    stats("cross_platform  (positive, different genre)", cross_sims)
    stats("different_author (negative)", neg_sims)

    print("\n=== precision/recall sweep: same_platform vs different_author ===")
    print(f"{'threshold':>9} {'precision':>10} {'recall':>8} {'f1':>6} {'tp':>5} {'fp':>5} {'fn':>5}")
    best = (0.0, -1.0)
    for i in range(1, 20):
        t = i / 20
        tp = sum(1 for s in same_sims if s >= t)
        fp = sum(1 for s in neg_sims if s >= t)
        fn = len(same_sims) - tp
        precision = tp / (tp + fp) if (tp + fp) else float("nan")
        recall = tp / (tp + fn) if (tp + fn) else float("nan")
        f1 = (2 * precision * recall / (precision + recall)
              if precision and recall and (precision + recall) else 0.0)
        if f1 > best[1]:
            best = (t, f1)
        print(f"{t:>9.2f} {precision:>10.3f} {recall:>8.3f} {f1:>6.3f} {tp:>5} {fp:>5} {fn:>5}")

    t = best[0]
    tp = sum(1 for s in same_sims if s >= t)
    fp = sum(1 for s in neg_sims if s >= t)
    fn = len(same_sims) - tp
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    print(f"\nbest-F1 threshold: {t:.2f} -> precision={precision:.3f} recall={recall:.3f}")
    if cross_sims:
        recovered = sum(1 for s in cross_sims if s >= t)
        print(f"cross_platform recovery at that same threshold: "
              f"{recovered}/{len(cross_sims)} ({recovered / len(cross_sims):.1%}) -- "
              "harder genre-mismatch set, reported for context only")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-chars", type=int, default=300,
                     help="minimum cleaned-text chars per author profile (default: 300)")
    ap.add_argument("--ngram", type=int, default=4, help="character n-gram size (default: 4)")
    ap.add_argument("--top-k", type=int, default=300,
                     help="n-grams kept per profile (default: 300)")
    ap.add_argument("--max-negatives", type=int, default=2000,
                     help="cap on sampled negative pairs (default: 2000)")
    ap.add_argument("--seed", type=int, default=0, help="random seed for negative sampling")
    args = ap.parse_args()

    if not evolution.available():
        ap.error(f"Evolution dataset not downloaded -- expected {evolution.ZIP_PATH}")

    return evaluate(args.min_chars, args.ngram, args.top_k, args.max_negatives, args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
