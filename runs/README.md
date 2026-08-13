# Investigation runs

The only tracked file in this directory. Everything beside it is scraped from
live dark web sites and stays out of git — see the `runs/` block in
`.gitignore` for why, and read anything here before you consider changing that.

```
runs/
  raw/          saved `cybertrace search --save` JSON, one file per target
  raw/v2/       the labeled evaluation corpus (below)
  corpora/      .db + .html written by `correlate --db --html --dossier`
```

Both derived directories are regenerable from the raw JSON:

```bash
cybertrace correlate runs/raw/v2/*.json \
    --db runs/corpora/case.db --html runs/corpora/case-graph.html \
    --dossier runs/corpora/case.html
```

## raw/v2 — the evaluation corpus

Seventeen live captures, collected 2026-08-13 over Tor, labeled in
`corpus/labels.toml` and scored by `tools/eval_corpus.py`. It is not a sample
of the dark web; it is a set of **controls**, chosen so the engine's failure
modes are checkable rather than hypothetical:

| Control | Targets | What it tests |
|---------|---------|---------------|
| Same operator, two addresses | Riseup main + Riseup account portal; Endchan + its published mirror | Can the engine find a real link at all |
| Same platform, different operators | OnionMail servers (xyrasoru, others), independent mail providers | Does a software family read as one operator — the failure that matters most |
| Unrelated, different categories | Tor Project, Blockchair, keys.openpgp.org, Dread, DarkForest, Black Hat Chat | False attribution rate |
| Unidentified | sector-city | Kept in the corpus for its artifacts, excluded from scoring — a guessed label would make the precision figure fiction |

`raw/` (without `v2`) holds the earlier captures of overlapping targets. They
are kept: a second capture of one target is a second snapshot in the store, and
the chain between them is what the monitoring and successor logic read.

## Measured, 2026-08-13

`python tools/eval_corpus.py runs/raw/v2/*.json`, 17 targets, 91 labeled pairs
scored and 29 unevaluable because a target was dark that day:

| Metric | Result |
|--------|--------|
| False attribution (unrelated called same-operator) | **0** |
| Ecosystem leakage (same-platform called same-operator) | **0** |
| Operator claims asserted | 0 |
| Operator recall on claims | 0/1 |
| True positives surfaced as leads | 1/1 |

Read honestly, that is: on a corpus of well-run services the engine asserted
nothing and got nothing wrong, and the one evaluable same-operator pair (the
two Riseup onions) was ranked and surfaced as a **lead** rather than claimed.
Its only shared evidence is that both sites reference the same eight
`riseup.net` hosts — co-reference, not control — and that genuinely does not
support asserting shared operation. The Endchan pair, the corpus's other true
positive, was unevaluable: `enxx3…` was dark on every attempt.

Three defects were found by these runs and fixed, which is what the corpus is
for:

1. **Eight false successor edges** between unrelated markets. Collecting targets
   one after another made every pair look like a takedown-and-relaunch. A
   handoff now requires the predecessor to have been *observed dark*.
2. **A false pair at 0.51** (an Endchan mirror and a Riseup onion) because both
   donation pages linked to `www.paypal.com` and `en.bitcoin.it`. Sharing
   something you link to is now scored far below sharing something you control.
3. **Fifteen junk INFRA candidates** — `t.me`, `twitter.com`, `duckduckgo.com` —
   admitted purely on "referenced by 2+ markets".

Extractor precision over the same corpus (`tools/audit_corpus.py`) is 1.00 for
every entity type: nothing the collectors emitted was refused by normalization,
because the collectors validate before emitting.

## Reproducing a corpus run

```bash
# every target in the labels file, one at a time (a full sweep takes ~1 min each)
cybertrace search "<onion>" -t darkweb -q --save runs/raw/v2/<name>.json

python tools/eval_corpus.py runs/raw/v2/*.json --pairs      # score it
python tools/audit_corpus.py runs/raw/v2/*.json --values    # extractor precision
```

Expect targets to be dark on any given day. That is a property of the subject
matter, not a failure: the eval reports pairs involving a dark target as
**unevaluable** rather than as engine misses, and the store records the outage
as its own hashed snapshot — which is exactly the evidence a later relaunch
needs to read as a successor.
