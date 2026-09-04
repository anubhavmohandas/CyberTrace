"""experiments/ml_attribution/ml_attribution.py (Loop 46): fusion-policy and
brief-section-19 security/reliability tests. EXPERIMENTAL, not production --
see this folder's README.md. Fast, synthetic, no network, no real corpus --
eval_ml_attribution.py (same folder) is the real-data benchmark; this file
only proves the MODEL/FUSION CODE itself behaves under the brief's own rules
(never a raw probability out, never a silently-broken tie, never a crash on
malformed input, never network I/O at inference time, never a tampered model
silently trusted).
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))  # siblings: ml_attribution, ml_features

from ml_attribution import (  # noqa: E402
    AMBIGUOUS, CANDIDATE, HIGH, ML_INFERENCE, NON_VASP,
    AnomalyScorer, SimilarityEngine, SupervisedClassifiers,
    load_models, ml_vasp_candidates, save_models, to_matrix,
)
from ml_features import FEATURE_SCHEMA  # noqa: E402


def _synthetic_rows(n_per_class=6, seed=0):
    """Three classes, each a distinct DIRECTION (not just a shifted origin)
    so cosine similarity -- SimilarityEngine's own metric -- separates them
    cleanly: Binance all-positive, Bybit all-negative, NON_VASP alternating
    sign. A class centered at the origin is a degenerate case for cosine
    distance (a near-zero vector's "direction" is dominated by noise, not
    signal) -- caught by this exact fixture design during Loop 46's own
    test-writing, not a hypothetical."""
    rng = np.random.default_rng(seed)
    signs = {"Binance": [1.0] * len(FEATURE_SCHEMA),
            "Bybit": [-1.0] * len(FEATURE_SCHEMA),
            NON_VASP: [(1.0 if i % 2 == 0 else -1.0) for i in range(len(FEATURE_SCHEMA))]}
    rows, labels, addrs = [], [], []
    for brand, base in signs.items():
        for i in range(n_per_class):
            vec = {k: float(b + rng.normal(0, 0.05)) for k, b in zip(FEATURE_SCHEMA, base)}
            rows.append({"features": vec})
            labels.append(brand)
            addrs.append(f"{brand}-{i}")
    return to_matrix(rows), labels, addrs


# --- to_matrix: malformed input never crashes, missing stays missing ------

def test_to_matrix_maps_none_and_inf_to_nan_never_a_manufactured_zero():
    rows = [{"features": {**{k: 0.0 for k in FEATURE_SCHEMA},
                         "txn_tx_count": None, "graph_degree": float("inf"),
                         "cp_counterparty_count": float("-inf")}}]
    X = to_matrix(rows)
    idx = {k: i for i, k in enumerate(FEATURE_SCHEMA)}
    assert np.isnan(X[0, idx["txn_tx_count"]])
    assert np.isnan(X[0, idx["graph_degree"]])
    assert np.isnan(X[0, idx["cp_counterparty_count"]])
    assert X[0, idx["txn_total_received"]] == 0.0  # a real 0 stays 0, not erased


def test_to_matrix_never_raises_on_malicious_string_value():
    rows = [{"features": {**{k: 0.0 for k in FEATURE_SCHEMA},
                         "txn_tx_count": "'; DROP TABLE wallets; --"}}]
    X = to_matrix(rows)  # must not raise -- a malformed value is "no basis", not a crash
    assert np.isnan(X[0, FEATURE_SCHEMA.index("txn_tx_count")])


# --- model policy: never a brand from the anomaly detector -----------------

def test_isolation_forest_never_returns_a_brand():
    X, _labels, _addrs = _synthetic_rows()
    iso = AnomalyScorer().fit(X)
    bucket = iso.anomaly_bucket(X[0])
    assert bucket in (None, "LOW", "MEDIUM", "HIGH")


def test_isolation_forest_stays_unfitted_on_too_few_rows():
    X = to_matrix([{"features": {k: 1.0 for k in FEATURE_SCHEMA}}])
    iso = AnomalyScorer().fit(X)
    assert iso.fitted is False
    assert iso.anomaly_bucket(X[0]) is None


# --- model policy: explicit NON_VASP class is respected ---------------------

def test_supervised_classifier_can_predict_non_vasp():
    X, labels, _addrs = _synthetic_rows()
    clf = SupervisedClassifiers().fit(X, labels)
    assert clf.fitted_names
    non_vasp_row = X[labels.index(NON_VASP)]
    predictions = {name: clf.predict_brand(name, non_vasp_row) for name in clf.fitted_names}
    # at least one fitted model must be ABLE to say "no brand" on a row drawn
    # from the NON_VASP cluster -- section 5's "must not force every wallet
    # into Binance/Bybit" is a behavioural claim, not just a label existing.
    assert None in predictions.values()


def test_similarity_engine_never_forced_into_a_brand_on_non_vasp_majority():
    X, labels, addrs = _synthetic_rows()
    sim = SimilarityEngine(k=5).fit(X, labels, addrs)
    non_vasp_row = X[labels.index(NON_VASP)]
    result = sim.nearest(non_vasp_row)
    assert result is None  # nearest neighbourhood is NON_VASP -- no candidate, not a guess


def test_similarity_engine_tie_returns_no_candidate():
    X, labels, addrs = _synthetic_rows(n_per_class=1)
    # 3 rows total (one Binance, one Bybit, one NON_VASP): with k=2 the two
    # nearest to any point are guaranteed to split across the other two
    # classes -- an exact tie, never silently resolved into one brand.
    sim = SimilarityEngine(k=2).fit(X, labels, addrs)
    result = sim.nearest(X[labels.index(NON_VASP)])
    assert result is None


# --- fusion: never a raw probability, never a silently-broken tie ----------

def test_ml_vasp_candidates_output_never_carries_a_raw_probability_field():
    X, labels, addrs = _synthetic_rows()
    clf = SupervisedClassifiers().fit(X, labels)
    sim = SimilarityEngine(k=3).fit(X, labels, addrs)
    result = ml_vasp_candidates(X[labels.index("Binance")], classifiers=clf, similarity=sim)
    assert result["tier"] == ML_INFERENCE
    blob = str(result)
    for banned in ("proba", "probability", "confidence_score"):
        assert banned not in blob.lower()


def test_ml_vasp_candidates_agreement_tie_is_ambiguous_not_a_coin_flip():
    class _Stub:
        def __init__(self, mapping):
            self._m = mapping
        @property
        def fitted_names(self):
            return set(self._m)
        def predict_brand(self, name, x_row):
            return self._m[name]

    stub = _Stub({"model_a": "Binance", "model_b": "Bybit"})
    result = ml_vasp_candidates(np.zeros(len(FEATURE_SCHEMA)), classifiers=stub)
    assert result["status"] == AMBIGUOUS
    assert result["primary_candidate"] is None
    assert {c["brand"] for c in result["candidates"]} == {"Binance", "Bybit"}


def test_ml_vasp_candidates_no_votes_returns_no_candidate_not_forced():
    """No classifiers/similarity/graph engine passed in at all -> zero
    votes -> the no-signal branch, same "no qualifying evidence, not a
    claim of zero" shape as attribution.vasp_candidates' own empty result."""
    result = ml_vasp_candidates(np.full(len(FEATURE_SCHEMA), np.nan))
    assert result["primary_candidate"] is None
    assert result["status"] is None
    assert result["supporting_signals"] == []
    assert result["also_attributed"] == []


def test_ml_vasp_candidates_never_crashes_on_inf_or_malformed_row():
    X, labels, addrs = _synthetic_rows()
    clf = SupervisedClassifiers().fit(X, labels)
    sim = SimilarityEngine(k=3).fit(X, labels, addrs)
    bad_row = np.array([np.inf, -np.inf, np.nan, 1e308] +
                       [0.0] * (len(FEATURE_SCHEMA) - 4))
    result = ml_vasp_candidates(bad_row, classifiers=clf, similarity=sim)
    assert "primary_candidate" in result  # did not raise


# --- section 19: determinism -------------------------------------------------

def test_inference_is_deterministic_across_repeated_calls():
    X, labels, addrs = _synthetic_rows()
    clf = SupervisedClassifiers().fit(X, labels)
    sim = SimilarityEngine(k=3).fit(X, labels, addrs)
    iso = AnomalyScorer().fit(X)
    row = X[labels.index("Binance")]
    first = ml_vasp_candidates(row, classifiers=clf, similarity=sim, anomaly=iso)
    second = ml_vasp_candidates(row, classifiers=clf, similarity=sim, anomaly=iso)
    assert first == second


# --- section 19: no network dependency during inference ---------------------

def test_inference_never_opens_a_socket(monkeypatch):
    import socket

    def _forbidden(*_a, **_k):
        raise AssertionError("ml_vasp_candidates must never touch the network at inference time")

    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)

    X, labels, addrs = _synthetic_rows()
    clf = SupervisedClassifiers().fit(X, labels)
    sim = SimilarityEngine(k=3).fit(X, labels, addrs)
    ml_vasp_candidates(X[0], classifiers=clf, similarity=sim)


# --- section 19: model serialization integrity ------------------------------

def test_load_models_rejects_a_tampered_model_file(tmp_path):
    X, labels, addrs = _synthetic_rows()
    iso = AnomalyScorer().fit(X)
    clf = SupervisedClassifiers().fit(X, labels)
    sim = SimilarityEngine(k=3).fit(X, labels, addrs)
    model_dir = tmp_path / "ml_models"
    path = save_models(iso, clf, sim, model_dir=model_dir)

    data = bytearray(path.read_bytes())
    data[0] ^= 0xFF  # flip one byte -- corruption/tampering, not a newer save
    path.write_bytes(bytes(data))

    with pytest.raises(RuntimeError):
        load_models(model_dir=model_dir)


def test_load_models_round_trips_a_real_bundle(tmp_path):
    X, labels, addrs = _synthetic_rows()
    iso = AnomalyScorer().fit(X)
    clf = SupervisedClassifiers().fit(X, labels)
    sim = SimilarityEngine(k=3).fit(X, labels, addrs)
    model_dir = tmp_path / "ml_models"
    save_models(iso, clf, sim, model_dir=model_dir)

    bundle = load_models(model_dir=model_dir)
    row = X[labels.index("Binance")]
    result = ml_vasp_candidates(row, classifiers=bundle["classifiers"],
                                similarity=bundle["similarity"], anomaly=bundle["isolation"])
    assert "primary_candidate" in result
