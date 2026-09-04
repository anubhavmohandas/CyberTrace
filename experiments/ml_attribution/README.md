# experiments/ml_attribution — Loop 46 (rejected, kept for later)

ML-based VASP wallet attribution, benchmarked against the production
rule-based engine (`cybertrace/attribution.py`) and found not good enough to
ship. Full benchmark, numbers, and the decision are in
[`docs/LOOP46.md`](../../docs/LOOP46.md).

**Why this lives here and not in `cybertrace/`**: nothing in this folder is
imported by the app, the CLI, or the GUI. It's a self-contained experiment,
kept runnable so it can be re-benchmarked if the real labelled VASP corpus
this codebase can draw on ever grows past ~10 examples per exchange (the
real ceiling right now, not a sampling choice). The default `pytest`/`pip
install -e .` for the app never touch this folder or need scikit-learn.

## Files

- `ml_features.py` — wallet -> fixed-schema numeric feature vector, reusing
  `correlate.py`'s existing graph/cluster/VASP-lookup functions. No sklearn
  import.
- `ml_attribution.py` — the models (Isolation Forest, 3 classifiers, cosine
  k-NN similarity) and the fusion layer. The only file here that imports
  scikit-learn.
- `build_ml_dataset.py` — live-ingests a bounded, real, rate-limited sample
  (reusing `tools/eval_attribution.py`'s corpus/masking functions) plus an
  offline negative sample from the Elliptic++ dataset, writes
  `data/ml_models/loop46_dataset.json`.
- `eval_ml_attribution.py` — the benchmark: ablations, per-brand metrics,
  false-positive rate, the comparison table. Reads the cache above; no
  network.
- `test_ml_features.py` / `test_ml_attribution.py` — the test suite for this
  folder (19 tests). Not part of the default `pytest` run (see
  `pyproject.toml`'s `[tool.pytest.ini_options]`); run explicitly.

## Running it

```bash
pip install -e ".[ml-experiments]"   # numpy + scikit-learn, once

python experiments/ml_attribution/build_ml_dataset.py     # live + offline, ~1-2h at defaults
python experiments/ml_attribution/eval_ml_attribution.py  # offline, re-runnable freely

pytest experiments/ml_attribution/ -q                      # this folder's own tests
```

## If this ever gets promoted to production

That means the benchmark in a re-run of `eval_ml_attribution.py` shows a
real, per-brand (not just BitMEX-driven aggregate) improvement with an
acceptable false-positive rate -- see `docs/LOOP46.md` section 6 for exactly
what "acceptable" meant last time. If that happens:

1. Move `ml_features.py` and `ml_attribution.py` into `cybertrace/`, and
   switch their `cybertrace.*` imports back to relative (`from . import
   ...`) to match that package's convention.
2. Move `build_ml_dataset.py` and `eval_ml_attribution.py` into `tools/`.
3. Move `test_ml_features.py` and `test_ml_attribution.py` into `tests/`,
   and drop `testpaths = ["tests"]` back to the default (or leave it -- it
   already covers `tests/`).
4. Move `numpy`/`scikit-learn` from the `ml-experiments` extra back into
   `requirements.txt`.
5. Wire `ml_vasp_candidates` into `correlate.unattributed_wallet_candidates`
   (see `docs/LOOP46.md`'s notes on that exact call site), under a clearly
   separate `ml_vasp_candidates` key -- never merged into the rule engine's
   own result, per the brief's section 20.
