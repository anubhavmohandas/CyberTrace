# Investigation runs

The only tracked file in this directory. Everything beside it is scraped from
live dark web sites and stays out of git — see the `runs/` block in
`.gitignore` for why, and read anything here before you consider changing that.

```
runs/
  raw/            saved `cybertrace search --save` JSON, one file per target
  raw/v5,v6,v7/   the labeled evaluation corpus (below)
  raw/superseded/ captures taken before an extractor fix, kept as the "before"
                  half of the comparison and excluded from the corpus
  corpora/        .db + .html written by `correlate --db --html --dossier`
```

Both derived directories are regenerable from the raw JSON:

```bash
cybertrace correlate runs/raw/v5/*.json runs/raw/v6/*.json runs/raw/v7/*.json \
    --db runs/corpora/v7.db --html runs/corpora/v7-graph.html \
    --dossier runs/corpora/v7-case.html
```

## The evaluation corpus

93 captures of **89 labeled targets**, collected 2026-08-13/14 over Tor, labeled
in `corpus/labels.toml` and scored by `tools/eval_corpus.py`. It is not a sample
of the dark web; it is a set of **controls**, chosen so the engine's failure
modes are checkable rather than hypothetical. Every target is classified: **74
answered, 15 were dark, none unaccounted for.**

| Control | Targets | What it tests |
|---------|---------|---------------|
| Same operator, operator-specific evidence | DNMX ×2 (`support@dnmx.cc` on both), Endchan ×2 (one donation wallet on both), Cryptostorm ×2 (`support@cryptostorm.is` on both) | The question the engine exists to answer |
| Same operator, namespace evidence only | Riseup ×7, Cock.li ×2 | Whether a co-referenced public-service domain gets promoted to shared control. It must **not** be |
| Same operator, nothing shared | Nowhere ×6 (OPSEC Bible, Git Datura, Lantern, library, radio, main) | An honest floor: one operator, six live services, no artifact in common |
| Same platform, different operators | OnionMail ×26, SecureDrop ×8 | Does a software family read as one operator — the failure that matters most |
| Unrelated, different categories | Tor Project, Blockchair, keys.openpgp.org, DarkForest, Black Hat Chat, five imageboards, two blogs | False attribution rate |
| Co-reference controls | 81chan (linked by Endchan), deep-swarm ↔ itmens (they link each other), DNM Bible, Pogachan | Being linked by a target, or co-linking what it links, must create no operator relationship |
| Dead / unreachable | 15 targets, including Mail2Tor's two published mirrors and Dread | A dark target must contribute collection evidence and no artifacts |
| Unidentified | sector-city, itmens-2, anon01–03, blockchair-401, pogachan-linked | Kept for their artifacts, never scored — a guessed label would make the precision figure fiction |

## Measured, 2026-08-14

`python tools/eval_corpus.py runs/raw/v5/*.json runs/raw/v6/*.json runs/raw/v7/*.json`
— 89 labeled targets, 2346 labeled pairs scored, 894 unevaluable because a
target was dark:

| Metric | Result |
|--------|--------|
| Operator precision | **3/3 = 1.00** |
| False attribution (unrelated called same-operator) | **0** |
| Ecosystem leakage (same-platform called same-operator) | **0** |
| Operator recall, `operator-specific` pairs | **3/3 = 1.00** |
| Operator recall, `namespace` pairs | 0/22 — declined, and correctly so |
| Operator recall, `none` pairs | 0/15 — unrecoverable by construction |
| Operator recall, aggregate | 3/40 = 0.07 |

Read the aggregate only with the class breakdown beside it. It is the sum of
three unlike questions, and `corpus/labels.toml` explains the split: promoting
the 22 namespace pairs is the same move that would manufacture the ecosystem
leakage this corpus exists to catch, and the 15 nowhere.moe pairs share nothing
any engine could key on.

Extractor precision over the same corpus (`tools/audit_corpus.py`) is 1.00 for
every artifact type except DOMAIN 0.88 and EMAIL 0.60, where the shortfall *is*
the normalizer refusing page furniture, documentation names and placeholder
mailboxes before they can become entities.

The three claims the engine asserted are the three operator-specific pairs:

- `stormways… ~ stormu36…` — OPERATOR candidate `support@cryptostorm.is`,
  MEDIUM at 0.797.
- `dnmxjait… ~ hxuzjtoc…` — OPERATOR candidate `support@dnmx.cc`, LOW at 0.592,
  carrying its own objection (both addresses were live at once, so neither
  succeeded the other).
- `endchancxfb… ~ enxx3bysp…` — LINKED_TO at 0.986 on a shared donation wallet.

### Separation, and why the scoring is frozen

Scoring every pair with the assertion floor removed (`min_score=0`) puts the
whole corpus on one scale:

| Band | Score | Pairs |
|------|-------|-------|
| operator-specific positives | 0.761 – 0.986 | 3 |
| *assertion threshold* | *0.50* | — |
| namespace positives (Riseup, Cock.li) | 0.058 – 0.124 | 9 |
| everything negative (ecosystem + unrelated) | ≤ 0.051 | rest |

The weakest true positive outranks the strongest negative by 15×, and the band
between 0.124 and 0.761 is empty — no threshold anywhere in it changes a single
verdict, so there is nothing for tuning to buy. Note also that the namespace
positives, which the engine deliberately does not assert, still rank above every
negative: they are ordered correctly and claimed anyway not at all, which is the
behaviour the corpus asks for. Weights, commonness floors and thresholds are
therefore left exactly as they were.

### Defects these runs found, and what fixed them

Each was reproduced on a live capture before anything changed, and each has a
regression test naming the site it came from:

1. **A tutorial's cast reached the keyservers.** nowhere.moe's OPSEC Bible
   prints gpg key-generation prompts and monero-wallet-cli transcripts;
   `alice@nowhere.com` and `bob@bob.com` were pivoted, and the keyserver
   answered with one real fingerprint and sixty-nine more plus a GitHub
   account. Three tutorial wallets landed in the confidence-*promoting*
   `wallet` section. Fixed by a `demo` section, non-attributive like `quoted`;
   that capture now pivots nothing.
2. **SVG path data became three leaked hosts.** Git Datura's icons yielded
   `1.5.75.75`, `1.7.75.75` and `5.142.75.75`, enriched into SoftBank, Sify and
   Rostelecom subscriber networks. Fixed by refusing coordinate attributes, and
   by requiring page text to use an address *as a host*.
3. **A catch-all site read as three exposed endpoints.** 81chan answers any
   unknown path with its front page, so `/server-status`, `/server-info` and
   `/status` all looked exposed, and the `yonga 1.0.2.1` version tag in that
   page's footer was filed as a leaked host at confidence 0.9. The probe now
   sends a control path that cannot exist. The store's only remaining IP is
   `78.17.212.207`, which that site's own text calls its clearnet address.
4. **Documentation domains became entities.** `example.com`, off zzzchan's FAQ,
   and two overlay-network addresses (`…b32.i2p`, `…loki`) each shared by two
   targets. `norm_email` already refused these; `norm_domain` did not.
5. **Every objection was labelled a clone finding.** The brief told the reader
   the DNMX candidate was contradicted by "a clone finding" the store does not
   contain — its actual objection is the temporal overlap.

## What the corpus still cannot test

Three same-operator pairs carry the `unverified` class: Mail2Tor publishes two
further addresses on its own landing page and both were unreachable, so whether
they share `admin@Mail2Tor.com` with the live address was never observed. They
are labeled and reported, never counted.

Three operator-specific positives is the floor for an evaluation, not a
comfortable sample. Finding the third took seven attempts, and the six that
failed are in the corpus as dead or artifact-free targets: Mail2Tor's two
mirrors, a Pogachan mirror, Blockchair's second onion (401, no content) and the
nowhere.moe family (six live services, nothing published in common). What is
scarce is not operators with several onions — it is operators with several
onions *live at the same moment* that each publish the same controlled artifact.

Two consequences worth stating plainly:

- All three positives rest on one artifact class each (two mailboxes, one
  wallet). Nothing here tests PGP-keyed reuse, crypto-cluster convergence or
  the successor path end to end on real data, because no live pair in reach
  exercised them. Those paths have unit coverage and no field measurement.
- The Cryptostorm pair was captured through the operator's own 403 error
  template, and the site refused all further requests afterwards. The artifact
  is real and the basis is published, but one capture each is all there is.

## Reproducing a corpus run

```bash
# every target in the labels file, one at a time (~1-2 min each over Tor)
cybertrace search "<onion>" -t darkweb -q --save runs/raw/v7/<name>.json

python tools/eval_corpus.py runs/raw/v5/*.json runs/raw/v6/*.json runs/raw/v7/*.json --pairs
python tools/audit_corpus.py runs/raw/v5/*.json runs/raw/v6/*.json runs/raw/v7/*.json --values
```

Expect targets to be dark on any given day. That is a property of the subject
matter, not a failure: the eval reports pairs involving a dark target as
**unevaluable** rather than as engine misses, and the store records the outage
as its own hashed snapshot — which is exactly the evidence a later relaunch
needs to read as a successor.
