# Investigation runs

The only tracked file in this directory. Everything beside it is scraped from
live dark web sites and stays out of git — see the `runs/` block in
`.gitignore` for why, and read anything here before you consider changing that.

```
runs/
  raw/            saved `cybertrace search --save` JSON, one file per target
  raw/v5..v8/     the labeled evaluation corpus (below)
  raw/superseded/ captures taken before an extractor fix, kept as the "before"
                  half of the comparison and excluded from the corpus
  corpora/        .db + .html written by `correlate --db --html --dossier`
```

Both derived directories are regenerable from the raw JSON:

```bash
cybertrace correlate runs/raw/v5/*.json runs/raw/v6/*.json runs/raw/v7/*.json runs/raw/v8/*.json \
    --db runs/corpora/v8.db --html runs/corpora/v8-graph.html \
    --dossier runs/corpora/v8-case.html
```

## The evaluation corpus

97 captures of **93 labeled targets**, collected 2026-08-13/15 over Tor, labeled
in `corpus/labels.toml` and scored by `tools/eval_corpus.py`. It is not a sample
of the dark web; it is a set of **controls**, chosen so the engine's failure
modes are checkable rather than hypothetical. Every target is classified: **78
answered, 16 were dark, none unaccounted for.**

| Control | Targets | What it tests |
|---------|---------|---------------|
| Same operator, operator-specific evidence | DNMX ×2 (`support@dnmx.cc` on both), Endchan ×2 (one donation wallet on both), Cryptostorm ×2 (`support@cryptostorm.is` on both), tor.taxi ×2 (one PGP fingerprint **and** `contact@tor.taxi` on both) | The question the engine exists to answer |
| Same operator, namespace evidence only | Riseup ×7, Cock.li ×2, Whonix ↔ Kicksecure | Whether a co-referenced public-service domain gets promoted to shared control. It must **not** be |
| Same operator, nothing shared | Nowhere ×6 (OPSEC Bible, Git Datura, Lantern, library, radio, main) | An honest floor: one operator, six live services, no artifact in common |
| Same platform, different operators | OnionMail ×26, SecureDrop ×8 | Does a software family read as one operator — the failure that matters most |
| Unrelated, different categories | Tor Project, Blockchair, keys.openpgp.org, DarkForest, Black Hat Chat, five imageboards, two blogs | False attribution rate |
| Co-reference controls | 81chan (linked by Endchan), deep-swarm ↔ itmens (they link each other), DNM Bible, Pogachan | Being linked by a target, or co-linking what it links, must create no operator relationship |
| Dead / unreachable | 16 targets, including Mail2Tor's two published mirrors (still dark on 2026-08-15) and Dread | A dark target must contribute collection evidence and no artifacts |
| Unidentified | sector-city, itmens-2, anon01–03, blockchair-401, pogachan-linked | Kept for their artifacts, never scored — a guessed label would make the precision figure fiction |

## Measured, 2026-08-15

`python tools/eval_corpus.py runs/raw/v5/*.json runs/raw/v6/*.json runs/raw/v7/*.json runs/raw/v8/*.json`
— 93 labeled targets, 2628 labeled pairs scored, 942 unevaluable because a
target was dark:

| Metric | Result | 2026-08-14 |
|--------|--------|-----------|
| Operator precision | **4/4 = 1.00** | 3/3 = 1.00 |
| False attribution (unrelated called same-operator) | **0** | 0 |
| Ecosystem leakage (same-platform called same-operator) | **0** | 0 |
| Operator recall, `operator-specific` pairs | **4/4 = 1.00** | 3/3 = 1.00 |
| Operator recall, `namespace` pairs | 0/23 — declined, and correctly so | 0/22 |
| Operator recall, `none` pairs | 0/15 — unrecoverable by construction | 0/15 |
| Operator recall, aggregate | 4/42 = 0.10 | 3/40 = 0.07 |

The fourth positive was added **with the scoring model untouched** — no weight,
floor or threshold moved — and was recovered on the first run. Re-scoring the
2026-08-14 corpus on today's code reproduces that day's figures exactly, so the
two columns differ by what is in the corpus and by nothing else.

Read the aggregate only with the class breakdown beside it. It is the sum of
three unlike questions, and `corpus/labels.toml` explains the split: promoting
the 23 namespace pairs is the same move that would manufacture the ecosystem
leakage this corpus exists to catch, and the 15 nowhere.moe pairs share nothing
any engine could key on.

Extractor precision over the same corpus (`tools/audit_corpus.py`) is 1.00 for
every artifact type except DOMAIN 0.90 and EMAIL 0.62, where the shortfall *is*
the normalizer refusing page furniture, documentation names and placeholder
mailboxes before they can become entities.

The four claims the engine asserted are the four operator-specific pairs:

- `tortaxiprd… ~ tortaxi2dev…` — OPERATOR candidate on PGP fingerprint
  `A5E0A839…1588778A` at 0.771, a second OPERATOR candidate on
  `contact@tor.taxi` at 0.593, and a LINKED_TO edge at 0.998.
- `stormways… ~ stormu36…` — OPERATOR candidate `support@cryptostorm.is`,
  MEDIUM at 0.798.
- `dnmxjait… ~ hxuzjtoc…` — OPERATOR candidate `support@dnmx.cc`, LOW at 0.593,
  carrying its own objection (both addresses were live at once, so neither
  succeeded the other).
- `endchancxfb… ~ enxx3bysp…` — LINKED_TO at 0.987 on a shared donation wallet.

tor.taxi is the first positive recovered from a **key** rather than a mailbox or
a wallet, and the only one two independent artifacts agree on.

### Separation, and why the scoring is frozen

Scoring every pair with the assertion floor removed (`min_score=0`) puts the
whole corpus on one scale:

| Band | Score | Pairs |
|------|-------|-------|
| operator-specific positives (asserted) | 0.762 – 0.998 | 4 |
| namespace positive, refused as references-only | 0.689 | 1 (Whonix ↔ Kicksecure) |
| *assertion threshold* | *0.50* | — |
| namespace positives (Riseup, Cock.li) | 0.058 – 0.124 | 12 |
| everything negative (ecosystem + unrelated) | **not ranked at all** | rest |

Two things changed here, and the second matters more than the first.

The empty band the previous corpus enjoyed — nothing between 0.124 and 0.761 —
is gone. Whonix ↔ Kicksecure lands at 0.689, inside it and only 0.073 below the
weakest asserted positive. That pair is a true positive, so ranking it high is
correct behaviour; what would be wrong is asserting it, because all twenty of
its signals are `shared_domain` and any two wikis on one subject reproduce them.

It is not the threshold that refuses it. The pair is suppressed
`REFERENCES_ONLY` by the signal-type gate in `detect_successors`, which holds at
**any** score: a pair joined only by references is never an edge, however many
references there are. A numeric margin would have narrowed to 1.10×; the gate
that actually decides is categorical, and that is why lowering or raising the
0.50 threshold still changes no verdict in this corpus.

The other half of the separation got stronger, not weaker: with the floor
removed entirely, **no ecosystem or unrelated pair produces a ranked hypothesis
at all** — 0 of them, not a low score. Weights, commonness floors and thresholds
are therefore still left exactly as they were.

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
6. **A directory's deliberately corrupted links became services.** tor.taxi
   alters one character in every onion address it displays — its own front page
   calls them "unclickable for your safety" — so ingesting that page minted
   well-formed addresses for sites that do not exist, among them near-twins of
   Riseup's and Cryptostorm's real addresses. `norm_onion` matched on shape
   alone. It now verifies the checksum a v3 address carries in its own bytes,
   which every reachable address passes by construction, so the phantoms are
   refused before they can become entities, inflate a commonness denominator or
   sit in the graph as a plausible sibling of a real target.

## What the corpus still cannot test

Three same-operator pairs carry the `unverified` class: Mail2Tor publishes two
further addresses on its own landing page and both were unreachable, so whether
they share `admin@Mail2Tor.com` with the live address was never observed. They
are labeled and reported, never counted.

Four operator-specific positives is still a small sample, and the cost of the
fourth says why. The existing corpus was mined first, exhaustively: every
artifact observed on more than one target was pulled from the store with its
provenance and checked by hand. It yielded **no** fourth positive. The only
cross-target key in the store, Cryptostorm's `4D87F984…`, reached both addresses
from a *keyserver pivot off the mailbox already counted* — enrichment, not
independent evidence, and counting it would have been the same positive twice.
Every other cross-target artifact was a reference: `pogachan.icu` on two
unrelated imageboards, `blog.itinerariummentis.org` on two blogs that link each
other, `datura.network` on two of nowhere.moe's own services. All correctly
inert.

Collection then cost twelve candidate operators to buy one pair. Both Mail2Tor
mirrors were still dark, re-probed on 2026-08-15. DDoSecrets, Recon,
danwin1210.de and one Monero onion did not answer. Qubes, Mullvad, Njalla,
Feather, Whonix, Kicksecure, TorBox, DarkForest and the DNM Bible each run a
single onion, or publish nothing shared across two. Amnesia serves the same
search engine on two addresses that never name each other — the `itmens-2`
situation, a vanity prefix and no operator statement, so it is not labeled.
What is scarce is not operators with several onions; it is operators with
several onions *live at the same moment* that each publish the same controlled
artifact.

Three consequences worth stating plainly:

- **PGP-keyed reuse is now field-measured**; crypto-cluster convergence and the
  successor path end to end are still not. tor.taxi is the corpus's only key
  positive, and it is a friendly one: the key sits at a fixed path on both
  addresses. Nothing here exercises a key recovered from a signature, a
  succession, or a cross-certification on real data.
- Whonix ↔ Kicksecure is the pair most able to embarrass the engine, and the
  reason its class is `namespace` and not `operator-specific`. Its two sites
  really are one operator — both Imprints name ENCRYPTED SUPPORT LLC,
  registration 966308, with the same phone — but that evidence is on a page the
  crawler does not fetch, and a phone number is not an entity type. What the
  captures share is 26 referenced hosts of 40 each, exactly one of them
  attributive. Making that pair recoverable would mean building an extractor for
  a single corpus row, which is how a tool gets fitted to its own test set. It is
  recorded as a limitation instead.
- The Cryptostorm pair was captured through the operator's own 403 error
  template, and the site refused all further requests afterwards. The artifact
  is real and the basis is published, but one capture each is all there is.

## Reproducing a corpus run

```bash
# every target in the labels file, one at a time (~1-2 min each over Tor)
cybertrace search "<onion>" -t darkweb -q --save runs/raw/v8/<name>.json

python tools/eval_corpus.py runs/raw/v5/*.json runs/raw/v6/*.json runs/raw/v7/*.json runs/raw/v8/*.json --pairs
python tools/audit_corpus.py runs/raw/v5/*.json runs/raw/v6/*.json runs/raw/v7/*.json runs/raw/v8/*.json --values
```

Expect targets to be dark on any given day. That is a property of the subject
matter, not a failure: the eval reports pairs involving a dark target as
**unevaluable** rather than as engine misses, and the store records the outage
as its own hashed snapshot — which is exactly the evidence a later relaunch
needs to read as a successor.
