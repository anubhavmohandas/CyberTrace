#!/usr/bin/env python3
"""Loop 46 ML dataset builder: turns real ground truth into a labelled
feature-vector cache for ml_attribution.py's benchmark (same folder), reusing
tools/eval_attribution.py's own corpus/live-ingest/masking functions rather
than duplicating them (same ground truth, same bounded/rate-limited live
sample philosophy, same cluster-aware masking Loop 45 already established).

EXPERIMENTAL, not production -- see this folder's README.md and
docs/LOOP46.md for the benchmark result and why this stays out of
cybertrace/.

    python experiments/ml_attribution/build_ml_dataset.py   # live + offline, writes the cache
    python experiments/ml_attribution/eval_ml_attribution.py  # reads the cache, no network

Two real, independent sources, kept in separate `kind` rows, never blended
at extraction time:

  positive / negative_ofac   Bounded live-ingest through the exact
                              trace-wallet path eval_attribution.py already
                              uses, with each wallet's OWN ground truth and
                              cospend cluster masked out of `exchange_of`
                              before its features are extracted (section 9/L
                              leakage guard -- see `_masked_exchange_of`).

  negative_ellipticpp_licit   Offline, from the already-indexed Elliptic++
                              dataset (cybertrace.integrations.ellipticpp).
                              No VASP-tagpack overlap exists (checked: ~0.06%
                              in a 5000-address sample) so this can only ever
                              be a negative/adversarial example, sorted by
                              real transaction volume so the sample actually
                              covers brief section 16's "high-volume personal
                              wallet" case instead of a random licit pick.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
from pathlib import Path
from typing import List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent  # experiments/ml_attribution/ -> experiments/ -> repo root
sys.path.insert(0, str(_HERE))                 # sibling: ml_features.py
sys.path.insert(0, str(_REPO_ROOT / "tools"))  # eval_attribution.py stays in tools/ (Loop 45's own)

import eval_attribution as ea  # noqa: E402  (path inserts above must run first)
import ml_features  # noqa: E402
from cybertrace import correlate  # noqa: E402  (installed package -- no path insert needed)
from cybertrace.evidence import EvidenceStore  # noqa: E402
from cybertrace.integrations import ellipticpp  # noqa: E402

# Matches ml_attribution.NON_VASP (same folder) -- duplicated as a bare
# string (not imported) so building a dataset never has to import sklearn
# through ml_attribution.py; only eval_ml_attribution.py needs the model stack.
NON_VASP = "UNKNOWN_NON_VASP"

DEFAULT_CACHE = _REPO_ROOT / "data" / "ml_models" / "loop46_dataset.json"


def _masked_exchange_of(all_exchange_of: dict, clusters: dict, entity_id: str) -> dict:
    """Same cluster-aware leakage guard as eval_attribution.py's own
    _masked_prediction (section 9/L): an address's own ground truth AND its
    whole cospend cluster are hidden before ITS features are extracted, so a
    model can't "reconstruct" a label that was never actually hidden from
    it. Reimplemented rather than imported -- _masked_prediction is wired
    specifically to call attribution.vasp_candidates, not a feature
    extractor; same "benchmark-specific plumbing, not worth a public
    correlate.py wrapper" reasoning that function's own docstring already
    gives for reaching into private state.
    """
    cluster_label = clusters.get(entity_id)
    masked = {entity_id} | ({eid for eid, c in clusters.items() if c == cluster_label}
                            if cluster_label else set())
    return {eid: hit for eid, hit in all_exchange_of.items() if eid not in masked}


async def _live_ingest_sample(store: EvidenceStore, args, semaphore: asyncio.Semaphore) -> list:
    corpus = ea.ground_truth_corpus()
    categories = ea.categorize(corpus)
    positive_sample = ea._by_brand_sample(
        categories["easy_positive"] + categories["hard_positive"],
        args.per_brand, args.max_total)

    ofac_rows = ea.ofac_negatives()
    ofac_sample = sorted(ofac_rows, key=lambda r: (r["currency"], r["address"]))[:args.max_negative]

    ingested = []
    for (currency, address), truth in positive_sample:
        ok = await ea._ingest_live(currency, address, store, semaphore, fetch_cross_chain=True)
        ingested.append(("positive", currency, address, ea.canonical_brand(truth["brand"]), ok))
    for r in ofac_sample:
        ok = await ea._ingest_live(r["currency"], r["address"], store, semaphore, fetch_cross_chain=True)
        ingested.append(("negative_ofac", r["currency"], r["address"], NON_VASP, ok))
    return ingested


def _extract_cybertrace_rows(store: EvidenceStore, ingested: list) -> List[dict]:
    wallet_rows = store._all(
        "SELECT entity_id, normalized_value, raw_value, etype FROM entities "
        "WHERE etype IN ('BTC_ADDRESS','ETH_ADDRESS','BNB_ADDRESS','POLYGON_ADDRESS','TRX_ADDRESS','SOL_ADDRESS')")
    values = {r["entity_id"]: (r["raw_value"] or r["normalized_value"]) for r in wallet_rows}
    all_exchange_of = correlate._vasp_endpoints(store, values)
    clusters = correlate.crypto_clusters(store)
    adjacency = correlate._adjacency(store)

    dataset = []
    for kind, currency, address, label, ok in ingested:
        if not ok:
            continue
        etype = ea._CURRENCY_TO_ETYPE[currency]
        entity_id = store.find_entity(etype, address)
        if entity_id is None:
            continue
        exchange_of = _masked_exchange_of(all_exchange_of, clusters, entity_id)
        row = ml_features.extract_features(store, entity_id, address, etype,
                                           adjacency, exchange_of, clusters)
        # Group = this wallet's cluster if it has one, else itself -- the
        # cluster-aware split's key (section 9). A cluster label already
        # groups a Binance omnibus wallet's own co-spend siblings together;
        # falling back to entity_id for an unclustered wallet just means it
        # is its own group of one, same as GroupShuffleSplit would treat any
        # singleton.
        dataset.append({"label": label, "group": clusters.get(entity_id, entity_id),
                        "kind": kind, **row})
    return dataset


def _sample_ellipticpp_negatives(take: int, min_total_txs: Optional[float] = None) -> List[dict]:
    """Offline, deterministic, bounded (brief section 10: real data only,
    never invented). No index exists on dataset_label or on any feature
    column (features are stored as one JSON blob per row -- see ellipticpp.
    py's own build_index docstring for why), so ranking by real activity
    means decoding every licit row's JSON blob -- measured at 0.6s for all
    251,088 of them on this machine, well inside the "one-time offline
    step" budget ellipticpp.build_index() itself already assumes (a
    LIMIT-then-sort over an address-ordered slice was tried first and
    silently missed every real high-activity wallet, since address order
    has no relationship to transaction volume). Keeps the `take`
    highest-total_txs rows: the real "high-volume personal wallet" brief
    section 16 adversarial case needs an actual high-activity sample, not
    whichever licit rows happen to sort first alphabetically.
    """
    if not ellipticpp.index_available():
        print("[!] Elliptic++ index not built -- skipping the offline negative/adversarial "
              "sample (see cybertrace.integrations.ellipticpp.build_index)", file=sys.stderr)
        return []
    conn = sqlite3.connect(f"file:{ellipticpp.INDEX_PATH}?mode=ro", uri=True)
    try:
        columns = json.loads(conn.execute(
            "SELECT value FROM meta WHERE key='feature_columns'").fetchone()[0])
        txs_idx = columns.index("total_txs")
        rows = conn.execute(
            "SELECT address, features FROM wallets WHERE dataset_label='2'").fetchall()
    finally:
        conn.close()

    decoded: List[Tuple[float, str]] = []
    for address, features_json in rows:
        arr = json.loads(features_json)
        try:
            total_txs = float(arr[txs_idx])
        except (TypeError, ValueError, IndexError):
            continue
        if min_total_txs is not None and total_txs < min_total_txs:
            continue
        decoded.append((total_txs, address))
    decoded.sort(key=lambda t: -t[0])

    out = []
    for _txs, address in decoded[:take]:
        record = ellipticpp.lookup_wallet(address)
        if record is None:
            continue
        row = ml_features.extract_features_ellipticpp(address, record)
        # Each Elliptic++ wallet is its own group -- no cospend/cluster
        # concept crosses over from that dataset's AddrAddr graph into
        # correlate.crypto_clusters, and conflating the two graphs into one
        # group id would be a fabricated relationship, not a real one.
        out.append({"label": NON_VASP, "group": f"ellipticpp:{address}",
                   "kind": "negative_ellipticpp_licit", **row})
    return out


async def build(args) -> List[dict]:
    semaphore = asyncio.Semaphore(max(1, args.concurrency))
    with EvidenceStore(":memory:") as store:
        ingested = await _live_ingest_sample(store, args, semaphore)
        cybertrace_rows = _extract_cybertrace_rows(store, ingested)

    n_missed = sum(1 for _k, _c, _a, _l, ok in ingested if not ok)
    if n_missed:
        print(f"[!] {n_missed}/{len(ingested)} sampled addresses did not ingest live "
              "(search returned nothing) -- excluded, not scored as a miss", file=sys.stderr)

    ellipticpp_rows = _sample_ellipticpp_negatives(
        args.ellipticpp_negatives, min_total_txs=args.ellipticpp_min_txs)
    return cybertrace_rows + ellipticpp_rows


def cluster_aware_split(dataset: List[dict], test_size: float = 0.3, random_state: int = 46
                        ) -> Tuple[List[dict], List[dict]]:
    """Group key = each row's own `group` (cluster label, or the entity_id/
    address itself when it has no cluster). GroupShuffleSplit guarantees
    every member of one group lands entirely in train or entirely in test,
    so a Binance cluster never has one address memorised in training and a
    cospend sibling "predicted" in test (brief section 9).
    # occam: one grouped holdout, not k-fold cross-validation -- this
    # corpus is far too small for k-fold to mean anything beyond noise, and
    # the brief asks for leakage-safe evaluation, not cross-validation.
    """
    from sklearn.model_selection import GroupShuffleSplit
    if len(dataset) < 4 or len({row["group"] for row in dataset}) < 2:
        return dataset, []  # too few distinct groups for a real split -- nothing gradable
    groups = [row["group"] for row in dataset]
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(splitter.split(range(len(dataset)), groups=groups))
    return [dataset[i] for i in train_idx], [dataset[i] for i in test_idx]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--per-brand", type=int, default=10,
                    help="max live positive addresses per VASP brand (default: 10 -- larger "
                         "than Loop45's own 3, still bounded/rate-limited, not a mass crawl)")
    ap.add_argument("--max-total", type=int, default=150,
                    help="overall cap on the live positive sample (default: 150)")
    ap.add_argument("--max-negative", type=int, default=40,
                    help="bounded live OFAC negative sample size (default: 40)")
    ap.add_argument("--concurrency", type=int, default=2)
    ap.add_argument("--ellipticpp-negatives", type=int, default=60,
                    help="offline, ranked by real transaction volume across all licit-labelled "
                         "Elliptic++ rows (~0.6s full scan) -- not a network call")
    ap.add_argument("--ellipticpp-min-txs", type=float, default=50.0,
                    help="real-transaction-count floor for the 'high-volume personal wallet' sample")
    ap.add_argument("--out", type=Path, default=DEFAULT_CACHE)
    args = ap.parse_args()

    dataset = asyncio.run(build(args))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dataset, indent=2))

    by_label: dict = {}
    for row in dataset:
        by_label[row["label"]] = by_label.get(row["label"], 0) + 1
    print(f"wrote {len(dataset)} rows to {args.out}")
    for label, n in sorted(by_label.items(), key=lambda kv: -kv[1]):
        print(f"  {label:24}{n:>6}")
    print(f"distinct cluster-aware groups: {len({row['group'] for row in dataset})}")
    return 0 if dataset else 1


if __name__ == "__main__":
    raise SystemExit(main())
