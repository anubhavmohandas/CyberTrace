#!/usr/bin/env python3
"""Loop 46 section-17 benchmark: does ML/similarity/graph attribution beat
Loop 45's rule-based `attribution.py` baseline for unknown-wallet VASP
attribution? Reads the cache build_ml_dataset.py (same folder) writes --
this script never touches the network, so it can be re-run freely while
iterating.

EXPERIMENTAL, not production -- see this folder's README.md and
docs/LOOP46.md for the benchmark result and why this stays out of
cybertrace/.

    python experiments/ml_attribution/build_ml_dataset.py    # once, live + offline
    python experiments/ml_attribution/eval_ml_attribution.py  # any number of times, offline

Scope, stated up front rather than implied: with a real corpus this small
(see build_ml_dataset.py's own docstring on why -- a bounded, rate-limited
live sample, never a mass crawl), per-brand x per-ablation metrics would
mostly be single-digit-N noise. This script reports AGGREGATE (macro)
metrics per ablation/model, and per-brand breakdown only for the final
top-level comparison (section 17's table): Loop 45 rules (replayed from its
own --live output, not re-derived here) vs Isolation Forest vs each
supervised classifier vs k-NN similarity vs the pure-graph model vs the
full fusion (ml_attribution.ml_vasp_candidates, every method combined).
Brands/categories with fewer than MIN_TEST_N test examples are reported
NOT TESTABLE, never a metric computed on 1-2 points and presented as if it
generalises.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))  # siblings: build_ml_dataset, ml_attribution, ml_features

import numpy as np  # noqa: E402
import build_ml_dataset as bmd  # noqa: E402
import ml_attribution as ma  # noqa: E402
from ml_features import FEATURE_SCHEMA  # noqa: E402

MIN_TEST_N = 3  # brief section 10/11: below this, NOT TESTABLE, not a noisy number

_GROUPS = {
    "txn": [c for c in FEATURE_SCHEMA if c.startswith("txn_")],
    "cp": [c for c in FEATURE_SCHEMA if c.startswith("cp_")],
    # Single source of truth for the graph-column subset: ml_attribution.py's
    # own GRAPH_COLUMNS/_GRAPH_IDX are what ml_vasp_candidates' fusion layer
    # slices a row with at inference time (see _method_votes), so the
    # graph_only ablation and the graph_classifier fed into run_combined_
    # fusion below both reuse those exact columns/order rather than
    # re-deriving a second list that could silently drift out of alignment.
    "graph": list(ma.GRAPH_COLUMNS),
    "xchain": [c for c in FEATURE_SCHEMA if c.startswith("xchain_")],
    "behav": [c for c in FEATURE_SCHEMA if c.startswith("behav_")],
}

# Brief section 12's named ablations, plus a literal graph-ONLY slice
# (section 7's actual question -- "graph proximity != ownership" needs
# graph features tested alone, not folded into a txn+graph combo).
ABLATIONS: Dict[str, List[str]] = {
    "A_txn_only": _GROUPS["txn"],
    "B_txn_behav": _GROUPS["txn"] + _GROUPS["behav"],
    "C_txn_graph": _GROUPS["txn"] + _GROUPS["graph"],
    "D_txn_counterparty_xchain": _GROUPS["txn"] + _GROUPS["cp"] + _GROUPS["xchain"],
    "graph_only": _GROUPS["graph"],
    "E_all_features": list(FEATURE_SCHEMA),
}


def _col_idx(cols: List[str]) -> np.ndarray:
    return np.array([FEATURE_SCHEMA.index(c) for c in cols])


def load_dataset(path: Path) -> List[dict]:
    if not path.exists():
        print(f"[!] no dataset cache at {path} -- run experiments/ml_attribution/build_ml_dataset.py first",
              file=sys.stderr)
        raise SystemExit(1)
    return json.loads(path.read_text())


def _vasp_false_positive_rate(y_true: List[str], y_pred: List[Optional[str]]) -> Optional[float]:
    """Brief section 11: a non-VASP wallet the model calls a real brand is
    "potentially more dangerous than simply missing a VASP" -- reported
    separately from ordinary precision, which would bury it inside one
    macro number."""
    negatives = [i for i, y in enumerate(y_true) if y == ma.NON_VASP]
    if len(negatives) < MIN_TEST_N:
        return None
    false_positives = sum(1 for i in negatives if y_pred[i] not in (None, ma.NON_VASP))
    return round(false_positives / len(negatives), 4)


def _classification_metrics(y_true: List[str], y_pred: List[Optional[str]],
                            top3_lists: Optional[List[List[str]]] = None) -> dict:
    from sklearn.metrics import precision_recall_fscore_support
    pred_filled = [p if p is not None else ma.NON_VASP for p in y_pred]
    top1 = round(sum(1 for t, p in zip(y_true, pred_filled) if t == p) / len(y_true), 4)
    precision, recall, f1, _support = precision_recall_fscore_support(
        y_true, pred_filled, average="macro", zero_division=0)
    top3_recall = (round(sum(1 for t, top3 in zip(y_true, top3_lists) if t in top3) / len(y_true), 4)
                  if top3_lists is not None else None)
    return {"n_test": len(y_true), "top1_accuracy": top1, "top3_recall": top3_recall,
            "precision_macro": round(float(precision), 4),
            "recall_macro": round(float(recall), 4), "f1_macro": round(float(f1), 4),
            "vasp_false_positive_rate": _vasp_false_positive_rate(y_true, y_pred)}


def _per_brand(y_true: List[str], y_pred: List[Optional[str]]) -> Dict[str, dict]:
    from sklearn.metrics import precision_recall_fscore_support
    brands = sorted({y for y in y_true if y != ma.NON_VASP})
    pred_filled = [p if p is not None else ma.NON_VASP for p in y_pred]
    out = {}
    for brand in brands:
        n = sum(1 for y in y_true if y == brand)
        if n < MIN_TEST_N:
            out[brand] = {"n_test": n, "status": "NOT_TESTABLE"}
            continue
        y_true_bin = [1 if y == brand else 0 for y in y_true]
        y_pred_bin = [1 if p == brand else 0 for p in pred_filled]
        precision, recall, f1, _s = precision_recall_fscore_support(
            y_true_bin, y_pred_bin, average="binary", zero_division=0)
        out[brand] = {"n_test": n, "precision": round(float(precision), 4),
                      "recall": round(float(recall), 4), "f1": round(float(f1), 4)}
    return out


def run_ablations(X_train, y_train, X_test, y_test) -> Dict[str, dict]:
    results = {}
    for name, cols in ABLATIONS.items():
        idx = _col_idx(cols)
        clf = ma.SupervisedClassifiers().fit(X_train[:, idx], y_train)
        if not clf.fitted_names:
            results[name] = {"status": "NOT_TESTABLE", "reason": "too few train rows/classes"}
            continue
        per_model = {}
        for model_name in sorted(clf.fitted_names):
            y_pred = [clf.predict_brand(model_name, row) for row in X_test[:, idx]]
            top3 = [clf.top_brands(model_name, row, n=3) for row in X_test[:, idx]]
            per_model[model_name] = _classification_metrics(y_test, y_pred, top3_lists=top3)
        results[name] = per_model
    return results


def run_similarity(X_train, y_train, addrs_train, X_test, y_test) -> dict:
    sim = ma.SimilarityEngine(k=5).fit(X_train, y_train, addrs_train)
    if not sim.fitted:
        return {"status": "NOT_TESTABLE", "reason": "fewer than 2 train rows"}
    y_pred, top3 = [], []
    for row in X_test:
        result = sim.nearest(row)
        y_pred.append(result["brand"] if result else None)
        top3.append(sim.top_brands(row, n=3))
    return _classification_metrics(y_test, y_pred, top3_lists=top3)


def run_isolation_forest(X_train, kinds_train, X_all, kinds_all) -> dict:
    """Brief section 3: never a brand, only a correlation check against the
    real category labels this corpus actually has (`kind`, from
    build_ml_dataset.py -- positive/negative_ofac/negative_ellipticpp_licit).
    Descriptive (group means), not a hypothesis test -- the corpus is too
    small for the latter to mean anything beyond noise."""
    iso = ma.AnomalyScorer().fit(X_train)
    if not iso.fitted:
        return {"status": "NOT_TESTABLE", "reason": "fewer than 8 train rows"}
    scores = iso.raw_scores(X_all)
    by_kind: Dict[str, list] = {}
    for score, kind in zip(scores, kinds_all):
        by_kind.setdefault(kind, []).append(float(score))
    return {"mean_anomaly_score_by_kind":
           {k: round(sum(v) / len(v), 4) for k, v in sorted(by_kind.items())},
           "n_by_kind": {k: len(v) for k, v in sorted(by_kind.items())}}


def run_combined_fusion(classifiers, similarity, graph_classifier, anomaly,
                        X_test, y_test) -> dict:
    """Section 8's real fusion layer, not just the "all features in one
    classifier" ablation -- every fitted method votes via
    ml_attribution.ml_vasp_candidates, preserving disagreement (AMBIGUOUS)
    rather than averaging it away."""
    y_pred, top3 = [], []
    for row in X_test:
        result = ma.ml_vasp_candidates(row, classifiers=classifiers, similarity=similarity,
                                       graph_classifier=graph_classifier, anomaly=anomaly)
        y_pred.append(result["primary_candidate"])
        # The fusion's own agreement-ranked `candidates` list doubles as its
        # top-3 -- reading it back out is the same discipline as reusing
        # ranked_brands for similarity's top3_recall above, rather than
        # re-deriving a second ranking that could disagree with what
        # ml_vasp_candidates itself actually returned. `candidates` only
        # ever lists brands a method actually voted for -- NON_VASP is
        # never a "vote" (see _method_votes), so an empty list means every
        # method abstained, i.e. the fusion's own top pick IS NON_VASP.
        # Without this fallback, a dataset that is mostly real NON_VASP
        # rows (as this one is) would score every CORRECT abstention as a
        # top-3 miss -- caught by exactly that skew on this real sample.
        ranked_brands = [c["brand"] for c in result.get("candidates", [])[:3]]
        top3.append(ranked_brands or [ma.NON_VASP])
    metrics = _classification_metrics(y_test, y_pred, top3_lists=top3)
    metrics["per_brand"] = _per_brand(y_test, y_pred)
    return metrics


def print_report(dataset: List[dict], train: List[dict], test: List[dict],
                 ablation_results: dict, similarity_result: dict, iso_result: dict,
                 combined_result: dict) -> None:
    by_kind: Dict[str, int] = {}
    for row in dataset:
        by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
    print(f"\ndataset: {len(dataset)} rows ({len(train)} train / {len(test)} test, "
          f"cluster-aware grouped split)")
    for kind, n in sorted(by_kind.items(), key=lambda kv: -kv[1]):
        print(f"  {kind:28}{n:>6}")

    print("\n=== ablation table (section 12/17; macro metrics, "
          f"NOT_TESTABLE below n_test={MIN_TEST_N} for a per-brand row) ===")
    for ablation, per_model in ablation_results.items():
        print(f"  {ablation}")
        if "status" in per_model:
            print(f"    NOT TESTABLE ({per_model['reason']})")
            continue
        for model_name, m in per_model.items():
            print(f"    {model_name:20} n={m['n_test']:<4} top1={m['top1_accuracy']:<7} "
                  f"top3={m['top3_recall']:<7} P={m['precision_macro']:<7} "
                  f"R={m['recall_macro']:<7} F1={m['f1_macro']:<7} "
                  f"VASP_FPR={m['vasp_false_positive_rate']}")

    print("\n=== isolation forest (section 3: anomaly score, never a brand) ===")
    if "status" in iso_result:
        print(f"  NOT TESTABLE ({iso_result['reason']})")
    else:
        for kind, mean in iso_result["mean_anomaly_score_by_kind"].items():
            print(f"  {kind:28} mean_anomaly={mean:<8} n={iso_result['n_by_kind'][kind]}")

    print("\n=== k-NN similarity (section 6) ===")
    if "status" in similarity_result:
        print(f"  NOT TESTABLE ({similarity_result['reason']})")
    else:
        m = similarity_result
        print(f"  n={m['n_test']} top1={m['top1_accuracy']} top3={m['top3_recall']} "
              f"P={m['precision_macro']} R={m['recall_macro']} F1={m['f1_macro']} "
              f"VASP_FPR={m['vasp_false_positive_rate']}")

    print("\n=== combined fusion (section 8: every method, disagreement preserved) ===")
    m = combined_result
    print(f"  n={m['n_test']} top1={m['top1_accuracy']} top3={m['top3_recall']} "
          f"P={m['precision_macro']} R={m['recall_macro']} F1={m['f1_macro']} "
          f"VASP_FPR={m['vasp_false_positive_rate']}")
    print("  per-brand:")
    for brand, bm in sorted(m["per_brand"].items()):
        if bm.get("status") == "NOT_TESTABLE":
            print(f"    {brand:16} NOT TESTABLE (n_test={bm['n_test']})")
        else:
            print(f"    {brand:16} n={bm['n_test']} P={bm['precision']} "
                  f"R={bm['recall']} F1={bm['f1']}")

    print("\n=== decision (section 18) ===")
    print("  Compare the numbers above against the frozen Loop 45 --live baseline "
         "(tools/eval_attribution.py --live) recorded separately -- this script "
         "does not overwrite or re-derive that baseline. See the run's own written "
         "summary for the A/B/C production decision; this table is the evidence "
         "for it, not the decision itself.")

    print("\n=== adversarial (section 16) ===")
    ofac_rows_test = [r for r in test if r["kind"] == "negative_ofac"]
    print(f"  OFAC-never-VASP: {len(ofac_rows_test)} OFAC test row(s) -- see this ablation's "
          "vasp_false_positive_rate above (computed over ALL NON_VASP test rows, OFAC and "
          "Elliptic++ licit together; a nonzero rate here is section 16's actual failure mode)")
    licit_rows_test = [r for r in test if r["kind"] == "negative_ellipticpp_licit"]
    print(f"  high-volume-personal-wallet: {len(licit_rows_test)} real high-activity licit "
          f"test row(s) (Elliptic++, ranked by real transaction volume)")
    print("  bridge/router negative: NOT TESTABLE -- no real, locally-verified bridge/router "
         "contract address exists in this codebase (same finding tools/eval_attribution.py's "
         "offline suite already reports for the rule-based baseline)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", type=Path, default=bmd.DEFAULT_CACHE)
    ap.add_argument("--test-size", type=float, default=0.3)
    ap.add_argument("--save-models", action="store_true",
                    help="persist the fitted E_all_features/similarity/graph_only/isolation "
                         "bundle to data/ml_models/ (section 19 integrity-checked storage)")
    args = ap.parse_args()

    dataset = load_dataset(args.dataset)
    if len(dataset) < 10:
        print(f"[!] only {len(dataset)} rows in the dataset cache -- too few for any real "
              "split; run experiments/ml_attribution/build_ml_dataset.py with larger --per-brand/--max-total",
              file=sys.stderr)
        return 1

    train, test = bmd.cluster_aware_split(dataset, test_size=args.test_size)
    if not test:
        print("[!] cluster-aware split left zero test rows (too few distinct groups) -- "
              "every metric below would be vacuous; not computed", file=sys.stderr)
        return 1

    X_train, y_train = ma.to_matrix(train), [r["label"] for r in train]
    X_test, y_test = ma.to_matrix(test), [r["label"] for r in test]
    addrs_train = [r["meta"]["address"] for r in train]
    X_all = ma.to_matrix(dataset)
    kinds_train = [r["kind"] for r in train]
    kinds_all = [r["kind"] for r in dataset]

    ablation_results = run_ablations(X_train, y_train, X_test, y_test)
    similarity_result = run_similarity(X_train, y_train, addrs_train, X_test, y_test)
    iso_result = run_isolation_forest(X_train, kinds_train, X_all, kinds_all)

    classifiers = ma.SupervisedClassifiers().fit(X_train, y_train)
    similarity_engine = ma.SimilarityEngine(k=5).fit(X_train, y_train, addrs_train)
    # ma._GRAPH_IDX directly -- the exact index array _method_votes uses to
    # slice a row for this classifier at inference time (see the comment on
    # _GROUPS["graph"] above).
    graph_classifier = ma.SupervisedClassifiers().fit(X_train[:, ma._GRAPH_IDX], y_train)
    isolation = ma.AnomalyScorer().fit(X_train)
    combined_result = run_combined_fusion(classifiers, similarity_engine,
                                          graph_classifier if graph_classifier.fitted_names else None,
                                          isolation, X_test, y_test)

    print_report(dataset, train, test, ablation_results, similarity_result, iso_result,
                combined_result)

    if args.save_models:
        path = ma.save_models(isolation, classifiers, similarity_engine, graph_classifier)
        print(f"\nsaved model bundle to {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
