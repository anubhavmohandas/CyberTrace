# experiments/multi_hop_attribution — Loop 47 (rejected, kept for later)

Deterministic bounded multi-hop VASP attribution, benchmarked against the
production rule-based engine (`cybertrace/attribution.py`, Loop 45) and
found not to clear the bar the brief itself set. Full benchmark, numbers,
and the decision are in [`docs/LOOP47.md`](../../docs/LOOP47.md).

**Why this lives here and not in `cybertrace/`**: nothing in this folder is
imported by the app, the CLI, or the GUI. Unlike Loop 46, this needed no new
dependency (pure stdlib + reuse of `correlate.py`/`attribution.py`'s
existing graph/scoring machinery) — it's rejected on the numbers, not on
cost or risk of a new library.

## Files

- `multi_hop_attribution.py` — bounded (`max_hops`, default 3, hard ceiling
  6) BFS over `correlate._adjacency`, dead-ending at any
  `correlate._vasp_endpoints` hit (OFAC/`REGULATORY_ATTESTED` structurally
  excluded), independence-aware + hub-penalized rule-based scoring
  (`RULES`/`_score_brand`, same shape as `attribution.py`'s own), and a
  PRIMARY/AMBIGUOUS/INSUFFICIENT_EVIDENCE verdict gated by a margin rule —
  never a forced guess between close candidates.
- `eval_multi_hop_attribution.py` — the benchmark: reuses
  `tools/eval_attribution.py`'s corpus loading, masking, and live
  search+ingest wholesale; adds hop-depth ablation (1/2/3), path-quality
  ablation (raw reachability / hop-decay-only / independence / hub-only /
  full), a real-OFAC-address false-positive rate measured for both engines
  on the identical masked graph, and 5 offline adversarial cases (hub,
  competing VASPs, long path, high-activity non-VASP wallet, OFAC-walked-
  through).
- `test_multi_hop_attribution.py` — 22 tests (traversal, hop decay,
  independence dedupe, hub penalty, directionality, verdict semantics,
  safety, two real-store integration tests). Not part of the default
  `pytest` run (this folder is not under `tests/`) — run explicitly.

## Running it

```bash
python experiments/multi_hop_attribution/eval_multi_hop_attribution.py
    # offline adversarial suite only, no network
python experiments/multi_hop_attribution/eval_multi_hop_attribution.py --live --ablation
    # + live hop-depth ablation, path-quality ablation, FPR (network required)
pytest experiments/multi_hop_attribution/ -q
    # this folder's own 22 tests
```

## Why it was rejected (Decision C)

On the same held-out, masked, real-address sample `tools/eval_attribution.py
--live` uses (n=30):

| | Top-1 | Top-3 | VASP FPR (n=15 real OFAC addrs) |
|---|---|---|---|
| **Loop 45 (frozen baseline)** | **16.67%** (5/30) | **20.00%** (6/30) | 33.33% (5/15) |
| Loop 47, hop ≤ 1 | 10.00% (3/30) | 16.67% (5/30) | 33.33% (5/15) |
| Loop 47, hop ≤ 2 | 10.00% (3/30) | 20.00% (6/30) | 33.33% (5/15) |
| Loop 47, hop ≤ 3 | 10.00% (3/30) | 20.00% (6/30) | 33.33% (5/15) |

Pre-declared bar (brief section 31): ≥5pp Top-1 improvement AND ≥5pp Top-3
improvement AND no material FPR increase. Top-1 got **worse**, Top-3 stayed
flat, FPR stayed flat (identical five false positives at every depth, both
engines — a pre-existing Loop 45 exposure, not something multi-hop adds).
None of the three conditions favor integration; two fail outright.

The FPR itself (33%) is real and worth naming separately from the
integration decision: it comes from genuine 1-hop OFAC→VASP deposit
relationships already in the corpus (SUEX→BitMEX/Binance, Wu Huihui→Huobi,
MESRI Behzad→Binance) — a sanctioned entity that really did deposit into a
real exchange. No graph-evidence-only engine, multi-hop or not, can
distinguish "this wallet is that VASP's customer" from "this wallet made
one real deposit that VASP happened to receive" — see `docs/LOOP47.md`
section 11 for why this is a structural property of the evidence, not a
scoring bug.

The one substantiated technical finding worth keeping for later: in the
path-quality ablation, independence-aware deduplication (not double-counting
paths that share an intermediate node) was the one piece of the evidence
model that measurably helped — it, not hub-penalization or raw hop-decay
alone, accounts for the full engine's entire edge over naive reachability.
That edge (1/30 → 3/30) never closes the gap to Loop 45's 5/30, and the
effect size is far too small (single-digit wallet counts on n=30) to
generalize — noted for any future revisit, not acted on now.
