# experiments/vasp_control_attribution -- Loop 48

Not a new attribution algorithm. A semantic layer over evidence
`cybertrace/correlate.py` (`wallet_exchange_paths`) and `cybertrace/attribution.py`
(Loop 45's fingerprint engine) already compute, answering a question neither
states explicitly: **"this wallet interacted with VASP X" (EXPOSURE) is not
"this wallet is owned/controlled by VASP X" (CONTROL)**. Full audit, real-data
validation, and the decision are in [`docs/LOOP48.md`](../../docs/LOOP48.md).

**Why this lives here and not in `cybertrace/`**: production already keeps
the underlying evidence axes separate (`proximity` -- AT_VASP/DIRECT/INDIRECT
-- is orthogonal to the 4-tier `attribution` axis, which is orthogonal again
to `risk.py`'s scoring). This module states that separation as an explicit,
tested policy rather than adding a new production field; see LOOP48.md
section 8 for why Decision B (semantic clarity, not a new engine wired into
every surface) is the honest call here, not Decision A.

## Files

- `vasp_control_attribution.py` -- `classify(hit, candidate)`, a pure function
  over one `wallet_exchange_paths()` row and/or one `attribution.vasp_candidates()`
  result. No new query, no new graph traversal, no ML. Returns
  `exposure_candidates`/`exposure_confidence`/`exposure_evidence`,
  `control_candidates`/`control_status`/`control_confidence`/`control_evidence`,
  `regulatory_context`, `provenance`, and a plain-English `verdict` -- never a
  single collapsed score. Runnable self-check: `python vasp_control_attribution.py`.
- `test_vasp_control_attribution.py` -- 16 tests: the 6 adversarial cases
  (brief section 13) as fast policy unit tests, the 5 negative-control
  populations A-E (brief section 6) against real store fixtures, plus two
  corpus-scale checks against the FULL local OFAC BTC corpus (n=531, 0 false
  positives) and a 50/brand real VASP_DISCLOSED sample (n=97, 100% recall).
  Skips (not fails) when local OFAC/GraphSense corpora are not downloaded.
- `eval_vasp_control_attribution.py` -- the report: full-corpus FPR/recall
  numbers, the section-12 required ablation (Variant A: direct-only naive,
  B: direct+multihop naive, C: control-only, D: this module's separated
  semantics) over 5 real/real-endpoint-backed named populations, and an
  optional `--live` real-sample comparison reusing `tools/eval_attribution.py`
  wholesale (imported, not re-implemented).

## Running it

```bash
python experiments/vasp_control_attribution/vasp_control_attribution.py
    # runnable self-check, no network, no corpus needed
python experiments/vasp_control_attribution/eval_vasp_control_attribution.py
    # full report: corpus-scale FPR/recall + ablation (no network)
python experiments/vasp_control_attribution/eval_vasp_control_attribution.py --live
    # + a real sample comparison against Loop 45/47 (network required)
pytest experiments/vasp_control_attribution/ -q
    # this folder's own 16 tests
```

## Headline result

- **OFAC -> VASP-control false-positive rate: 0/531 (0.00%)**, full local
  OFAC BTC corpus -- an OFAC designation never becomes VASP ownership,
  however it is reached (Invariant 3).
- **VASP_DISCLOSED control recall: 97/97 (100%)**, a real 50-per-brand
  proof-of-reserves sample -- the one population where CONTROL should read
  ESTABLISHED does.
- **The ablation's real finding**: a naive direct/multi-hop reading of the
  exact same evidence (Variant A/B) asserts plain ownership ("VASP = X") on
  a real VASP *customer* wallet -- the exact shape of the bug this loop's
  own audit found in production (`cli.py`'s "Nearest VASP: X" headline,
  fixed in this loop). A control-only reading (Variant C) never over-claims
  but silently drops that customer's real exposure lead. Only the separated
  semantics (Variant D) report both without conflating them.

## One production change made, and documented (brief section 9)

`cybertrace/cli.py`'s `trace-wallet` headline ("Nearest VASP: {exchange}")
lost its proximity/hop-count context to the very next line -- a reader who
captured only that one line (a log excerpt, a grep) would see an unqualified
ownership-flavored claim. Fixed to carry proximity+hops on the same line,
matching the discipline `trace-wallet-batch`'s summary and every Markdown/HTML
row already had. No other production file changed.

## Why Decision B, not A or C (see LOOP48.md section 8 for the full case)

Independent control evidence genuinely exists in this corpus (`VASP_DISCLOSED`,
a VASP's own published wallet list) and the negative controls are clean at
real corpus scale. But it fires only when the suspect wallet IS literally a
VASP's own infrastructure address -- a narrow, different investigative object
from the realistic LEA target (an individual's or a suspect's wallet). For
that population, this evidence corpus can only ever support EXPOSURE, and
that is the correct, honest answer, not a gap to force-close with a scoring
formula. Semantic clarity is the win; a new production "Control" field
wired through every surface is deferred, not built, to avoid overstating
what one narrow, already-covered case is worth.
