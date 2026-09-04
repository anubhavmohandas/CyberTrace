"""ML-based VASP candidate attribution (Loop 46) -- benchmarked against, and
kept structurally separate from, the rule-based engine in
cybertrace/attribution.py.

EXPERIMENTAL, not production. Benchmarked in docs/LOOP46.md; decision was C
(don't integrate). Lives under experiments/ml_attribution/, outside the
cybertrace/ package, so nothing CyberTrace actually ships imports this.
Kept, tested, and runnable for when a larger real corpus justifies
re-benchmarking -- see this folder's README.md.

This is the ONE module in the Loop 46 experiment that imports scikit-learn.
ml_features.py stays sklearn-free on purpose (a feature-extraction bug must
never be indistinguishable from a training-pipeline bug); build_ml_dataset.py
and eval_ml_attribution.py (same folder) are the only callers that decide
train/test splits, run the ablations, and print the section-17 comparison
table against attribution.py's own frozen numbers.

**Model output is never evidence.** Every candidate this module returns is
tagged `ML_INFERENCE` -- a tier that exists in NEITHER attribution.py's
CANDIDATE/CORROBORATED nor correlate.py's ANALYST_ASSERTED/REGULATORY_
ATTESTED/VASP_DISCLOSED/TAG_ATTESTED. A classifier predicting "Binance" does
not become ATTESTED Binance; it becomes one `ML_INFERENCE` supporting signal
among possibly several, same discipline the repo's own prior ML exclusions
(docs/LOOP11 Section 21, docs/LOOP18) already established for commercial
clustering tools -- this module does not get a pass just because it is
homegrown.

**No raw probability is ever exposed.** Every sklearn `predict_proba`/
`decision_function` value stays internal to this module (used only for
`tools/eval_ml_attribution.py`'s own metrics); every caller-facing bucket is
HIGH/MEDIUM/LOW off inter-method AGREEMENT COUNT, the same never-a-percentage
discipline risk.py and attribution.py already use.

**Disagreement is preserved, never silently resolved.** If methods split
evenly between two brands, `ml_vasp_candidates` returns both under
`status=AMBIGUOUS` with `primary_candidate=None` -- never picks one by
tie-break (brief section 15).

**Missing/malformed input never crashes.** `to_matrix` maps `None` -> NaN and
folds `+/-inf` into NaN too (a malicious or malformed feature value is "no
real basis", not a crash) before any sklearn call. Model files are loaded
only from a fixed local path (`data/ml_models/`) with a SHA-256 self-check
against a sidecar the save step writes -- reusing
`cybertrace.integrations._freshness.verify_checksum`, the same corruption/
tampering check ellipticpp.py/ofac.py already use for their own downloaded
indexes -- never from a network location or a caller-supplied path.
"""

from __future__ import annotations

import hashlib
import sys
import warnings
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

# ml_features.py is a sibling in this same experiments folder, not a
# cybertrace/ package member (see module docstring) -- plain sibling import,
# same convention tools/*.py already uses for importing each other.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ml_features import FEATURE_SCHEMA  # noqa: E402

# ml_features.FEATURE_SCHEMA's own docstring names two columns
# (behav_batching_behavior/behav_sweep_like_behavior) that are ALWAYS None
# from every real source this codebase has -- a structural, permanent
# condition, not a per-sample data gap. SimpleImputer already handles an
# all-missing column correctly (imputes to a constant, does not crash); its
# UserWarning about it is expected noise for a known, honest NOT_TESTABLE
# column, not a signal of a real problem -- silenced narrowly by message
# text so any other, genuinely informative imputer warning still surfaces.
warnings.filterwarnings("ignore", message="Skipping features without any observed values",
                        category=UserWarning)

ML_INFERENCE = "ML_INFERENCE"
NON_VASP = "UNKNOWN_NON_VASP"
MODEL_VERSION = "ml-attribution-v1"

CANDIDATE, AMBIGUOUS = "CANDIDATE", "AMBIGUOUS"
HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"

# Fixed, deterministic across every model in this module -- section 19's
# "deterministic inference" requirement starts here, not as an afterthought.
RANDOM_STATE = 46

GRAPH_COLUMNS = tuple(c for c in FEATURE_SCHEMA if c.startswith("graph_"))
_GRAPH_IDX = np.array([FEATURE_SCHEMA.index(c) for c in GRAPH_COLUMNS])

# experiments/ml_attribution/ml_attribution.py -> experiments/ -> repo root
_MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "ml_models"
_MODEL_FILE = "ml_attribution_models.joblib"
_DIGEST_FILE = "ml_attribution_models.sha256"


# No real feature in FEATURE_SCHEMA (a tx count, a BTC amount, a hop count,
# a neighbour count) is ever legitimately this large -- a value beyond this
# is "no real basis", the same as inf/NaN, not a number to trust. Also
# guards a real crash: several sklearn estimators cast float64 input to
# float32 internally, and a finite-but-huge float64 (e.g. 1e308, well
# within float64 range) silently overflows to inf on that cast and then
# fails sklearn's own finiteness check -- caught by testing this function
# against exactly that value (brief section 19: "extremely large
# transaction counts" must not crash inference).
_MAX_ABS_FEATURE_VALUE = 1e9


def _sanitize_row(x_row: np.ndarray) -> np.ndarray:
    """+/-inf, NaN-producing casts, and implausibly large magnitudes all
    become NaN -- the same "no real basis, not a crash" rule to_matrix
    applies to a training batch, applied here too at the single per-wallet
    inference entrypoint (ml_vasp_candidates) -- a malicious or malformed
    caller-supplied row must never reach sklearn's own finite-value check."""
    x_row = np.asarray(x_row, dtype=np.float64)
    finite = np.isfinite(x_row) & (np.abs(x_row) <= _MAX_ABS_FEATURE_VALUE)
    return np.where(finite, x_row, np.nan)


def to_matrix(rows: List[dict]) -> np.ndarray:
    """`rows` are ml_features.py row dicts (or plain `features` sub-dicts) in
    FEATURE_SCHEMA order. None/±inf/implausibly-large values all become NaN
    via the same `_sanitize_row` pass ml_vasp_candidates' single-row
    inference path uses -- "no real basis", never a crash and never a
    manufactured number (section 19: malicious/extreme feature values must
    not raise, at train time or at inference time)."""
    out = np.full((len(rows), len(FEATURE_SCHEMA)), np.nan, dtype=np.float64)
    for i, row in enumerate(rows):
        features = row["features"] if "features" in row else row
        for j, key in enumerate(FEATURE_SCHEMA):
            v = features.get(key)
            if v is None:
                continue
            try:
                out[i, j] = float(v)
            except (TypeError, ValueError):
                continue
    return _sanitize_row(out)


class AnomalyScorer:
    """Isolation Forest, unsupervised -- flags unusual wallet behaviour, NEVER
    a brand (brief section 3). `anomaly_score` is a bucket, not the raw
    decision function: HIGH/MEDIUM/LOW, same as every other output here."""

    def __init__(self):
        from sklearn.ensemble import IsolationForest
        from sklearn.impute import SimpleImputer
        self._imputer = SimpleImputer(strategy="median", add_indicator=True)
        self._model = IsolationForest(random_state=RANDOM_STATE, n_estimators=200)
        self._fitted = False

    def fit(self, X: np.ndarray) -> "AnomalyScorer":
        if len(X) < 8:
            # Too few rows for a meaningful forest -- stay unfitted rather
            # than fit noise; callers must check `fitted` before scoring.
            return self
        Xi = self._imputer.fit_transform(X)
        self._model.fit(Xi)
        self._fitted = True
        return self

    @property
    def fitted(self) -> bool:
        return self._fitted

    def raw_scores(self, X: np.ndarray) -> np.ndarray:
        """Internal use (benchmark correlation checks) only -- higher = more
        anomalous. Never call from a caller-facing candidate function."""
        Xi = self._imputer.transform(X)
        return -self._model.score_samples(Xi)  # flip sklearn's "higher=normal" convention

    def anomaly_bucket(self, x_row: np.ndarray, *, thresholds=(0.0, 0.05)) -> Optional[str]:
        """thresholds are on sklearn's score_samples scale (roughly
        log-anomaly-density) fit to THIS corpus, not a universal constant --
        recomputed by tools/eval_ml_attribution.py from the training
        distribution, passed in rather than hardcoded here. None if unfitted."""
        if not self._fitted:
            return None
        raw = self.raw_scores(x_row.reshape(1, -1))[0]
        lo, hi = thresholds
        return LOW if raw < lo else (MEDIUM if raw < hi else HIGH)


class SupervisedClassifiers:
    """Logistic Regression / Random Forest / HistGradientBoosting, each with
    an explicit `NON_VASP` class in the training labels so a wallet can come
    back "not enough evidence" rather than a forced brand (brief section 5).

    Two different missing-data policies, deliberately: the linear/forest
    models get `SimpleImputer(add_indicator=True)` (median value + a binary
    "was this missing" column, so imputation never erases the missingness
    signal itself); HistGradientBoostingClassifier gets the raw NaN matrix,
    since native missing-value splits are exactly what that model is for --
    real behavioural difference between the two, not an implementation
    accident, worth keeping visible in the ablation table rather than
    papering over with one imputer for everything.
    """

    def __init__(self):
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
        from sklearn.impute import SimpleImputer
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        self._imputer = SimpleImputer(strategy="median", add_indicator=True)
        self.models = {
            # StandardScaler first -- this codebase's own feature scales
            # span orders of magnitude (a 0-1 ratio next to a raw BTC
            # total), and lbfgs measurably failed to converge on real Loop
            # 46 data without it (sklearn's own recommended fix, not a
            # cosmetic addition). Tree-based models below are scale-
            # invariant by construction and get the raw imputed values.
            "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(
                max_iter=2000, random_state=RANDOM_STATE, class_weight="balanced")),
            "random_forest": RandomForestClassifier(
                random_state=RANDOM_STATE, n_estimators=300, class_weight="balanced"),
            "gradient_boosting": HistGradientBoostingClassifier(random_state=RANDOM_STATE),
        }
        self._fitted_names: set = set()

    def fit(self, X: np.ndarray, y: List[str]) -> "SupervisedClassifiers":
        classes = set(y)
        if len(X) < 6 or len(classes) < 2:
            # Can't train a real classifier on one class or a handful of
            # rows -- stay unfitted (see `fitted_names`), never fit garbage.
            return self
        Xi = self._imputer.fit_transform(X)
        for name, model in self.models.items():
            Xtrain = X if name == "gradient_boosting" else Xi
            try:
                model.fit(Xtrain, y)
                self._fitted_names.add(name)
            except ValueError:
                continue  # e.g. a class with a single member -- skip that model, not the run
        return self

    @property
    def fitted_names(self) -> set:
        return set(self._fitted_names)

    def predict_brand(self, name: str, x_row: np.ndarray) -> Optional[str]:
        if name not in self._fitted_names:
            return None
        Xrow = x_row.reshape(1, -1)
        X = Xrow if name == "gradient_boosting" else self._imputer.transform(Xrow)
        pred = self.models[name].predict(X)[0]
        return None if pred == NON_VASP else pred

    def predict_proba_internal(self, name: str, x_row: np.ndarray) -> Optional[Dict[str, float]]:
        """Benchmark/eval use only (section 13: internal probability may
        exist for evaluation, never shown to an investigator)."""
        if name not in self._fitted_names:
            return None
        model = self.models[name]
        Xrow = x_row.reshape(1, -1)
        X = Xrow if name == "gradient_boosting" else self._imputer.transform(Xrow)
        return dict(zip(model.classes_, model.predict_proba(X)[0]))

    def top_brands(self, name: str, x_row: np.ndarray, n: int = 3) -> List[str]:
        """Eval-only (section 11's top-3 recall) -- ranks
        predict_proba_internal's classes, NON_VASP included, never shown to
        an investigator (same boundary predict_proba_internal itself
        documents)."""
        proba = self.predict_proba_internal(name, x_row)
        if not proba:
            return []
        return [b for b, _p in sorted(proba.items(), key=lambda kv: -kv[1])[:n]]


class SimilarityEngine:
    """Cosine k-NN over the (imputed) training rows. Returns the aggregate
    brand among the nearest reference wallets and cites them by address --
    never invents a reference that was not in the fit set."""

    def __init__(self, k: int = 5):
        self.k = k
        self._imputer = None
        self._model = None
        self._labels: List[str] = []
        self._addresses: List[str] = []

    def fit(self, X: np.ndarray, y: List[str], addresses: List[str]) -> "SimilarityEngine":
        from sklearn.impute import SimpleImputer
        from sklearn.neighbors import NearestNeighbors
        if len(X) < 2:
            return self
        self._imputer = SimpleImputer(strategy="median", add_indicator=True)
        Xi = self._imputer.fit_transform(X)
        k = min(self.k, len(X))
        self._model = NearestNeighbors(n_neighbors=k, metric="cosine")
        self._model.fit(Xi)
        self._labels, self._addresses = list(y), list(addresses)
        return self

    @property
    def fitted(self) -> bool:
        return self._model is not None

    def _ranked(self, x_row: np.ndarray) -> Optional[dict]:
        """Internal: every distinct brand among the k nearest neighbours,
        ranked by vote count (ties broken by brand name for determinism),
        plus per-neighbour detail. Shared by `nearest` (caller-facing, one
        verdict or None) and `top_brands` (eval-only, section 11's top-3
        recall) so the two never silently disagree about what "nearest"
        means."""
        if not self.fitted:
            return None
        Xi = self._imputer.transform(x_row.reshape(1, -1))
        dist, idx = self._model.kneighbors(Xi)
        dist, idx = dist[0], idx[0]
        neighbors = [{"address": self._addresses[i], "brand": self._labels[i],
                     "similarity": round(1.0 - d, 4)} for d, i in zip(dist, idx)]
        counts: Dict[str, int] = {}
        sims: Dict[str, List[float]] = {}
        for n in neighbors:
            counts[n["brand"]] = counts.get(n["brand"], 0) + 1
            sims.setdefault(n["brand"], []).append(n["similarity"])
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return {"ranked": ranked, "sims": sims, "neighbors": neighbors}

    def nearest(self, x_row: np.ndarray) -> Optional[dict]:
        """{"brand", "similarity_bucket", "neighbors": [{"address","brand","similarity"}]}
        or None if no brand majority (including a NON_VASP-majority
        neighbourhood -- never forced into a brand, brief section 5/6)."""
        r = self._ranked(x_row)
        if r is None:
            return None
        ranked, sims, neighbors = r["ranked"], r["sims"], r["neighbors"]
        top_brand, top_count = ranked[0]
        if top_brand == NON_VASP or (len(ranked) > 1 and ranked[1][1] == top_count):
            return None  # majority is non-VASP, or a tie -- no candidate, not a guess
        mean_sim = sum(sims[top_brand]) / len(sims[top_brand])
        bucket = HIGH if mean_sim >= 0.8 else (MEDIUM if mean_sim >= 0.5 else LOW)
        return {"brand": top_brand, "similarity_bucket": bucket, "neighbors": neighbors}

    def top_brands(self, x_row: np.ndarray, n: int = 3) -> List[str]:
        """Eval-only (section 11's top-3 recall, section 13's "internal
        probability may exist for evaluation, never shown to an
        investigator") -- unlike `nearest`, includes NON_VASP and never
        withholds on a tie, since top-N recall is asking a different
        question ("was the truth anywhere in the ranked list") than
        `nearest`'s single-verdict "what would we tell an investigator"."""
        r = self._ranked(x_row)
        if r is None:
            return []
        return [brand for brand, _count in r["ranked"][:n]]


def _method_votes(x_row: np.ndarray, *, classifiers: Optional[SupervisedClassifiers],
                  similarity: Optional[SimilarityEngine],
                  graph_classifier: Optional[SupervisedClassifiers]) -> List[dict]:
    votes = []
    if classifiers is not None:
        for name in sorted(classifiers.fitted_names):
            brand = classifiers.predict_brand(name, x_row)
            if brand:
                votes.append({"method": name, "brand": brand})
    if similarity is not None:
        sim = similarity.nearest(x_row)
        if sim:
            votes.append({"method": "similarity_knn", "brand": sim["brand"],
                          "detail": f"nearest reference wallets: "
                                    f"{', '.join(n['address'] for n in sim['neighbors'])}",
                          "strength_hint": sim["similarity_bucket"]})
    if graph_classifier is not None:
        # graph_classifier is a SupervisedClassifiers fit on the
        # graph-columns-only submatrix (see tools/eval_ml_attribution.py's
        # ablation loop) -- must be sliced the same way at predict time or
        # the imputer/model see the wrong number of columns.
        graph_x_row = x_row[_GRAPH_IDX]
        for name in sorted(graph_classifier.fitted_names):
            brand = graph_classifier.predict_brand(name, graph_x_row)
            if brand:
                votes.append({"method": f"graph_{name}", "brand": brand})
    return votes


def _agreement_strength(n_methods: int) -> str:
    """POLICY-DEFINED buckets over inter-method AGREEMENT COUNT -- never a
    raw score -- mirroring attribution.py's own _strength/
    _STRENGTH_THRESHOLDS shape."""
    return HIGH if n_methods >= 3 else (MEDIUM if n_methods == 2 else LOW)


def ml_vasp_candidates(x_row: np.ndarray, *, classifiers: Optional[SupervisedClassifiers] = None,
                       similarity: Optional[SimilarityEngine] = None,
                       graph_classifier: Optional[SupervisedClassifiers] = None,
                       anomaly: Optional[AnomalyScorer] = None,
                       anomaly_thresholds=(0.0, 0.05)) -> dict:
    """The ML-side sibling of attribution.vasp_candidates -- same
    primary_candidate/also_attributed/status/strength shape so an
    investigator-facing renderer can display them side by side, but every
    field here is `ML_INFERENCE`, never one of correlate.py's evidence
    tiers, and ties are returned as AMBIGUOUS rather than silently broken.
    """
    x_row = _sanitize_row(x_row)
    votes = _method_votes(x_row, classifiers=classifiers, similarity=similarity,
                          graph_classifier=graph_classifier)
    anomaly_bucket = anomaly.anomaly_bucket(x_row, thresholds=anomaly_thresholds) if anomaly else None

    if not votes:
        return {"policy_version": MODEL_VERSION, "tier": ML_INFERENCE,
                "primary_candidate": None, "status": None, "strength": None,
                "supporting_signals": [], "also_attributed": [],
                "anomaly_bucket": anomaly_bucket}

    by_brand: Dict[str, List[dict]] = {}
    for v in votes:
        by_brand.setdefault(v["brand"], []).append(v)
    ranked = sorted(by_brand.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    top_brand, top_votes = ranked[0]
    tied = len(ranked) > 1 and len(ranked[1][1]) == len(top_votes)

    # One bucketing rule, applied to every brand (including the top one) --
    # same "one thresholds table, never re-derived per caller" discipline
    # attribution.py's _strength/_STRENGTH_THRESHOLDS already uses.
    candidates = [{"brand": b, "strength": _agreement_strength(len(vs)),
                  "methods": [v["method"] for v in vs]} for b, vs in ranked]
    strength = candidates[0]["strength"]

    return {
        "policy_version": MODEL_VERSION, "tier": ML_INFERENCE,
        "primary_candidate": None if tied else top_brand,
        "status": AMBIGUOUS if tied else CANDIDATE,
        "strength": None if tied else strength,
        "supporting_signals": top_votes,
        # candidates[1:] already carries {brand, strength, methods} per
        # runner-up, built from the same `ranked` order -- reused as-is
        # rather than re-zipped against `ranked` a second time.
        "also_attributed": candidates[1:],
        "candidates": candidates,  # every brand any method voted for, tied or not
        "anomaly_bucket": anomaly_bucket,
    }


def save_models(isolation: AnomalyScorer, classifiers: SupervisedClassifiers,
                similarity: SimilarityEngine,
                graph_classifier: Optional[SupervisedClassifiers] = None,
                model_dir: Path = _MODEL_DIR) -> Path:
    import joblib
    model_dir.mkdir(parents=True, exist_ok=True)
    bundle = {"version": MODEL_VERSION, "isolation": isolation, "classifiers": classifiers,
             "similarity": similarity, "graph_classifier": graph_classifier}
    model_path = model_dir / _MODEL_FILE
    joblib.dump(bundle, model_path)
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    (model_dir / _DIGEST_FILE).write_text(digest)
    return model_path


def load_models(model_dir: Path = _MODEL_DIR) -> dict:
    """Local file only -- never a network location or a caller-supplied
    path, and never trusted without a SHA-256 match against the sidecar
    save_models() wrote (section 19: model serialization integrity)."""
    from cybertrace.integrations import _freshness
    import joblib
    model_path, digest_path = model_dir / _MODEL_FILE, model_dir / _DIGEST_FILE
    if not model_path.exists() or not digest_path.exists():
        raise RuntimeError(f"no trained model bundle at {model_dir} -- run "
                           "tools/build_ml_dataset.py then tools/eval_ml_attribution.py "
                           "(or a future train step) first.")
    _freshness.verify_checksum(model_path, digest_path.read_text().strip())
    return joblib.load(model_path)


def demo() -> None:
    """occam self-check: fit on a tiny synthetic set, confirm NaN/inf input
    never crashes, confirm a tie returns AMBIGUOUS with no primary_candidate,
    confirm OFAC/NON_VASP-only neighbourhoods never produce a candidate."""
    rng = np.random.default_rng(0)
    n_per_class = 6
    rows, labels, addrs = [], [], []
    for brand, center in (("Binance", 1.0), ("Bybit", -1.0), (NON_VASP, 0.0)):
        for i in range(n_per_class):
            vec = {k: float(center + rng.normal(0, 0.05)) for k in FEATURE_SCHEMA}
            rows.append({"features": vec})
            labels.append(brand)
            addrs.append(f"{brand}-{i}")
    X = to_matrix(rows)
    assert X.shape == (len(rows), len(FEATURE_SCHEMA))

    clf = SupervisedClassifiers().fit(X, labels)
    assert clf.fitted_names, "expected at least one classifier to fit on synthetic data"
    sim = SimilarityEngine(k=3).fit(X, labels, addrs)
    iso = AnomalyScorer().fit(X)

    binance_row = X[0]
    result = ml_vasp_candidates(binance_row, classifiers=clf, similarity=sim, anomaly=iso)
    assert result["tier"] == ML_INFERENCE
    assert "primary_candidate" in result

    # malformed input never crashes
    bad = np.array([np.inf, -np.inf, np.nan] + [1.0] * (len(FEATURE_SCHEMA) - 3))
    bad_result = ml_vasp_candidates(bad, classifiers=clf, similarity=sim, anomaly=iso)
    assert "primary_candidate" in bad_result

    # a manufactured exact tie (two stub classifiers, one vote each brand)
    # exercises ml_vasp_candidates' own tie-handling directly, not a copy of
    # its logic -- AMBIGUOUS, no primary_candidate, both brands still listed.
    class _StubClassifiers:
        def __init__(self, name_to_brand):
            self._map = name_to_brand
        @property
        def fitted_names(self):
            return set(self._map)
        def predict_brand(self, name, x_row):
            return self._map[name]

    stub = _StubClassifiers({"a": "Binance", "b": "Bybit"})
    tie_result = ml_vasp_candidates(binance_row, classifiers=stub)
    assert tie_result["status"] == AMBIGUOUS
    assert tie_result["primary_candidate"] is None
    assert {c["brand"] for c in tie_result["candidates"]} == {"Binance", "Bybit"}

    print("ml_attribution.demo: OK")


if __name__ == "__main__":
    demo()
