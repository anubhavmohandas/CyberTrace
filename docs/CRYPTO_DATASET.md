# CyberTrace Crypto Behavioral Benchmark (Loop 52 + Loop 54 addendum)

**Loop 54 addendum (2026-09-07):** added BABD-13 (544,462 labeled Bitcoin
addresses, 13-class taxonomy) as a fourth source, kept in its own label
vocabulary and its own output files — see §3.4, §5, and §9. Also evaluated
and explicitly deferred two further candidate sources (a 43.6M-address
Kaggle wallet-classification dataset, and the DIAM graph-multigraph corpus)
— see §2's new rows for why.

## 1. Purpose

A normalized, provenance-backed, multi-source crypto transaction/wallet
dataset for future anomaly-detection and behavioral-modeling research —
separate from, and never wired into, Loop 45's deterministic VASP
attribution engine (`cybertrace/attribution.py`, `correlate.py`). Built by
`tools/build_crypto_benchmark.py`.

**This is a research benchmark, not a live investigation data source.**
Nothing in `cybertrace/` imports this pipeline; it cannot regress Loop
45/48/49/50, and its labels (below) must never be read as an OFAC-equivalent
or law-enforcement finding.

**This benchmark is Bitcoin-dominant, not evenly split across chains.**
Bitcoin (via the already-local Elliptic++ corpus) supplies 1,124,460 of the
1,127,460 total records; Ethereum is represented by a 3,000-address
stratified enrichment sample, not a comparably large or independent
Ethereum corpus. See §5 for the exact breakdown before drawing any
cross-chain conclusion from this data.

## 2. Sourcing decisions

| Source | Verdict | Reason |
|---|---|---|
| Elliptic++ (Bitcoin, tx+wallet graph) | **Used — already local** | Already on disk at `external_data/ellipticpp/original/`, checksummed and manifested (existing offline dataset, predates this loop). No new download. |
| Ethereum Fraud Detection (Kaggle, vagifa) | **Superseded** | The only HuggingFace "mirrors" found (`JoshikaV05`, `besmart-ai`) are bare zip re-uploads with no README/citation/provenance and no working plain-HTTP download path. Not trusted even if forced through. |
| `fesevu/ethereum_fraud_dataset_by_activity` (HuggingFace) | **Used — new** | Independent Ethereum source: Google BigQuery's public Ethereum chain export + Etherscan scam labels, CC-BY-4.0, documented reproducible pipeline (`github.com/fesevu/eth-fraud-dataset-pipeline`), not gated. Only the small labeled-address index is downloaded (3.9MB); the same repo's ~73GB of raw edge parquet is intentionally not fetched. |
| CryptoXChain-500K (HuggingFace) | **Deferred** | Access-gated — needs a logged-in HF account with granted access, not configured here. Searched for an ungated multi-chain (BCH/DASH/DOGE/LTC) equivalent; nothing credible found. Revisit if access is granted or an alternative surfaces — not a permanent "no multi-chain." |
| Multi-Cryptocurrency Anomaly Detection Dataset 2025 (Kaggle) | **Deferred** | Kaggle's search UI is JS-rendered; existence/contents could not be verified via an unauthenticated fetch. Per its own public description, ~88% of it is derived from Elliptic (already the authoritative local source here) with only ~10k incremental Ethereum rows — low marginal value even with access. |
| ~1.62B-row Ethereum activity dataset (unnamed, HuggingFace) | **Deferred** | Not confidently located. Per this project's own rule (never bulk-download a huge unverified source), not pursued speculatively — `fesevu` already fills the independent-Ethereum-source role for this loop. |
| **BABD-13** (Kaggle, `lemonx/babd13`) | **Used — Loop 54, manually supplied** | Real, peer-reviewed (IEEE TIFS 2024, arXiv 2204.05746): 544,462 labeled Bitcoin addresses, 148 features, 13 behavior classes. Kaggle-only distribution with no unauthenticated download path in this environment (no Kaggle API credentials) — the project owner downloaded it manually and supplied the file. Independently verified, not just trusted: every one of the paper's 13 per-class address counts matched this CSV's own label-value counts exactly (see manifest), confirming the label-index mapping rather than assuming it. See §3.4. |
| Bitcoin Wallet Classification Public Dataset, 43.6M addresses (Kaggle, `gregorywilder`) | **Deferred** | Same Kaggle-credential blocker as BABD-13, but *also* lower-trust independent of access: single-uploader dataset, no peer-reviewed paper, and its own description states most labels derive from stale WalletExplorer-era blocks with no stated verification methodology. Not worth pursuing even if access is later granted, unless independent label verification surfaces. |
| DIAM crypto-illicit-account-detection multigraphs (HuggingFace, `Tommy-DING`) | **Deferred** | Verified real and freely downloadable — real CIKM'24 paper, ungated HF repo, checked via direct HTTP HEAD requests (not assumed): 4 files, 1.73GB total, exactly matching the paper's stated feature dimensions (Ethereum 48-dim, Bitcoin-M 69-dim, Bitcoin-L 89-dim). NOT fetched: it's graph-structured (needs `torch`/`torch_geometric`, neither installed in this project), and nothing here consumes graph-ML data yet. Pulling 1.73GB with no consumer would be exactly the kind of speculative scaffolding this benchmark has avoided everywhere else. Revisit only if a graph-ML loop actually starts. |

## 3. Sources in detail

### 3.1 Elliptic++ (Bitcoin)

- **Location:** `external_data/ellipticpp/original/` (see that directory's
  own `manifest.json` for full provenance/checksums — predates this loop).
- **Citation:** Elmougy & Liu, "Demystifying Fraudulent Transactions and
  Illicit Nodes in the Bitcoin Network for Financial Forensics," KDD'23.
- **License:** `UNKNOWN` / non-redistributable per the existing manifest — no
  LICENSE file exists in the source repo or either distribution channel.
  Kept local, gitignored, never republished (already the existing policy for
  this corpus).
- **Two populations, two granularities:**
  - **Transaction nodes** (`txs_classes.csv` + `txs_features.csv` +
    `txs_edgelist.csv`): **203,769** rows, each an opaque `txId` — the
    source is intentionally anonymized at this granularity and exposes no
    raw address, only 182 aggregated numeric features (some genuinely
    missing for a subset of transactions — kept as `null`, never
    fabricated as `0`). `234,355` graph edges.
    - Label counts: **4,545 ILLICIT** (class 1), **42,019 LICIT** (class 2),
      **157,205 UNKNOWN** (class 3).
  - **Wallets** (`wallets_classes.csv` + `wallets_features_classes_combined.csv`):
    real base58 BTC addresses with 58 precomputed behavioral columns
    (num_txs_as_sender/receiver, btc_transacted stats, lifetime_in_blocks, ...).
    - `wallets_classes.csv`: **822,942 unique addresses**, verified zero
      duplicate keys. Label counts: **14,266 ILLICIT**, **251,088 LICIT**,
      **557,588 UNKNOWN**.
    - `wallets_features_classes_combined.csv`: **1,268,260 raw rows**, but
      only **822,942 unique addresses** — most addresses appear at exactly
      one `Time step`, some at more than one. Full-row deduplication drops
      this to **920,691** rows (**347,569 raw rows, 27.4%, are
      byte-identical duplicates** in the published file — a real data
      artifact, not this pipeline's error). **Do not describe 1,268,260 or
      920,691 as "unique wallets"** — only 822,942 addresses are unique.
      Post-dedup label counts: **14,720 ILLICIT**, **276,699 LICIT**,
      **629,272 UNKNOWN** (differs slightly from `wallets_classes.csv`'s
      counts because a handful of addresses in the combined file are absent
      from `wallets_classes.csv` and fall back to their own row's `class`).

### 3.2 Ethereum — fesevu labels + live Etherscan enrichment

- **Location:** `external_data/ethereum_fraud_activity/` (acquired by this
  loop's script; see that directory's `manifest.json`).
- **License:** CC-BY-4.0 — freely redistributable with attribution, unlike
  Elliptic++. Kept under `external_data/*/original/` (gitignored) anyway,
  for consistency with every other external corpus in this project, not
  because the license requires it.
- **Label index:** `addr_labels_balanced.csv` (decompressed from the
  3.9MB `.csv.zst` via the system `zstd`/`unzstd` binary — no new Python
  dependency). **114,771** labeled Ethereum addresses are available in this
  index: **60,118 non-scam**, **54,653 scam** (pre-balanced by the dataset's
  own author). **Only 3,000 of these 114,771 are actually enriched and
  included in the benchmark** (see below) — the 114,771 figure describes
  the source's own size, not this benchmark's Ethereum coverage. Also carries
  `description` (scam category, e.g. "phishing"), `activity_start_ts`/
  `activity_end_ts` (sometimes empty even for a labeled scam address — a
  real, valid record, not a parse failure), and `is_contract`.
- **Behavioral features come from a live source, not this static file.**
  `tools/build_crypto_benchmark.py` calls CyberTrace's own already-configured
  Etherscan integration (`BitcoinModule._fetch_evm_account_txs`, the same
  method `provider_health.py` health-checks) for a bounded, deterministic
  sample of these addresses (default 3,000: 1,500 scam + 1,500 non-scam,
  always the same first N in the source file's own order — see
  "Reproducibility" below). Computed per address: `transaction_count`,
  `avg/min/max_value_eth`, `active_days`, `unique_sent_to`/
  `unique_received_from`/`unique_counterparties`, `contract_calls`,
  `failed_tx_ratio`.
  - **This is a shallow sample** — the last 20 native transactions per
    address (`BitcoinModule._fetch_evm_account_txs`'s own documented
    "shallow-sample-not-full-history" design, shared with the live
    provider-health probe), not full transaction history. A real, honest
    signal for coarse behavior flags; not a substitute for a full ledger
    scan.
  - **Ground truth here is the `fesevu` dataset's own curation** (BigQuery +
    Etherscan + scam-list cross-reference) — not an OFAC/regulatory
    designation. Weaker evidentiary tier than `external_data/ofac`,
    comparable in spirit to `external_data/exchange_tags`'s community-sourced
    tags.
- **See §5 for exact sampled-address counts and fetch-status breakdown** (a
  live network step — filled in by the latest `quality_report.json`, not
  hand-typed here).

### 3.4 BABD-13 (Bitcoin, Loop 54)

- **Location:** `external_data/babd13/original/BABD-13.csv` (see that
  directory's own `manifest.json` for full provenance/checksum).
- **Citation:** Xiang et al., "BABD: A Bitcoin Address Behavior Dataset for
  Pattern Analysis," IEEE Transactions on Information Forensics and
  Security, 2024 (arXiv:2204.05746).
- **License:** `UNKNOWN` — same posture as Elliptic++: Kaggle's dataset page
  states no explicit license and is JS-rendered (unreadable via
  unauthenticated fetch, same limitation already noted for other Kaggle
  sources in §2). The dataset's *code* repository is Apache-2.0, but that
  covers the collection/preprocessing scripts, not the dataset's own
  redistribution terms. Kept local, gitignored, never republished.
- **544,462 raw rows, 542,368 unique addresses, real base58 BTC addresses.**
  148 numeric behavioral features (`PAIa...`/`S...` indicator-category
  columns — not yet decoded into this benchmark's own
  `HIGH_ACTIVITY`/`HIGH_VALUE`/`FAN_IN`/`FAN_OUT` flag vocabulary; see §9).
- **Own 13-class taxonomy, kept as its own `ground_truth_label` vocabulary**
  — never coerced into Elliptic's ILLICIT/LICIT/UNKNOWN (same precedent as
  Ethereum's FRAUD/LICIT in §3.2). Label-index mapping (`0`–`12`) was
  independently verified against the paper's own Table I per-class address
  counts — every one of the 13 counts matched this CSV's own label-value
  counts exactly, confirming the index order rather than assuming it from
  column order alone:

  | Index | Class | Count |
  |---|---|---:|
  | 0 | BLACKMAIL | 8,686 |
  | 1 | CYBER_SECURITY_SERVICE | 91,617 |
  | 2 | DARKNET_MARKET | 13,861 |
  | 3 | CENTRALIZED_EXCHANGE | 300,000 |
  | 4 | P2P_FINANCIAL_INFRASTRUCTURE | 180 |
  | 5 | P2P_FINANCIAL_SERVICE | 9,309 |
  | 6 | GAMBLING | 105,257 |
  | 7 | GOVERNMENT_CRIMINAL_BLACKLIST | 27 |
  | 8 | MONEY_LAUNDERING | 16 |
  | 9 | PONZI_SCHEME | 15 |
  | 10 | MINING_POOL | 1,580 |
  | 11 | TUMBLER | 12,412 |
  | 12 | INDIVIDUAL_WALLET | 1,502 |

  (Counts above are the raw CSV's, before dedup/conflict handling — see
  `quality_report.json`'s `babd13_wallets.label_counts` for the
  post-processing distribution, which differs slightly because
  conflict-account rows move to `LABEL_CONFLICT` and duplicates are removed.)
- **`label_confidence` comes from the source's own `SW` column** (`SA`
  =`STRONG`, `WA`=`WEAK`) — the paper's own "strong label address / weak
  label address" distinction, not invented here.
- **A real, verified data-quality defect: 1,414 accounts (0.26%) carry
  mutually conflicting labels** across duplicate rows in the published CSV
  (e.g. one real address is labeled both `BLACKMAIL` and `MONEY_LAUNDERING`
  in different rows — confirmed by direct inspection, not a parsing
  artifact). **These are never resolved by picking one label arbitrarily.**
  `tools/build_crypto_benchmark.py`'s `load_babd13_wallets` marks every row
  for such an account `ground_truth_label="LABEL_CONFLICT"`,
  `label_confidence="CONFLICT"`, and excludes them from
  `build_babd13_balanced_subset` — a training/eval subset must never be
  handed an address the source itself contradicts on. This is the single
  most important reason BABD-13 is kept in its own output files rather than
  merged into the Elliptic-derived Bitcoin rows: blending a conflicting
  label into an otherwise-clean 3-class column would be a real false-alarm
  risk for anything downstream that reads `ground_truth_label` naively.
- **2,466 addresses overlap with the Elliptic++ corpus** (§3.1) —
  cross-source label agreement/disagreement on this overlap is not
  evaluated by this loop; flagged in `quality_report.json`'s
  `babd13_x_elliptic_overlap_addresses` for a future loop to actually check,
  not silently assumed consistent.
- **Not computed:** the shared `behavior_flags` vocabulary
  (`HIGH_ACTIVITY`/`HIGH_VALUE`/`FAN_IN`/`FAN_OUT`) — BABD-13's 148 columns
  are indicator-category codes, not named tx-count/max-value/degree fields
  like Elliptic's own features, and guessing a mapping risks a wrong flag on
  a dataset this benchmark cannot independently re-derive. Left empty
  (`[]`) rather than guessed; see the `occam:` comment in
  `load_babd13_wallets` for the upgrade path.

## 4. Unified schema

Every row carries a common envelope:

```
source, chain, entity_type, entity_id, timestep (Bitcoin) / fetched_at (Ethereum),
ground_truth_label, source_label, label_confidence, label_provenance,
behavior_flags[], features{...}, split
```

Ethereum rows additionally carry `fetch_status` (`success` | `failed`),
`fetch_reason`, `is_contract`, `scam_category`.

**Address/value/timestamp fields are populated only where the source
actually has them** — real for Ethereum (via the live fetch), absent
(`entity_id` is an opaque `txId`, no `from`/`to`/`value`) for Elliptic
transaction-node rows, because the source itself is anonymized at that
granularity. This is a deliberate, documented adaptation, not an omission.

### Ground-truth labels

- Bitcoin: `ILLICIT` / `LICIT` / `UNKNOWN` (Elliptic's own 3-class
  convention — `UNKNOWN` is never treated as "normal" or coerced into
  either labeled class).
- Ethereum: `FRAUD` / `LICIT` (fesevu's binary scam/non-scam curation).

### Behavior flags (derived, independent of ground truth)

`HIGH_ACTIVITY` (tx_count ≥ 100), `HIGH_VALUE` (max value ≥ 10
BTC-or-ETH-equivalent — a documented fixed heuristic, not a fitted
percentile), `FAN_OUT`/`FAN_IN` (out/in-degree or unique-counterparty count
≥ 10). **A flag firing never changes `ground_truth_label`** — an UNKNOWN or
LICIT row can carry any of these flags without becoming ILLICIT/FRAUD
(verified by `tests/test_crypto_dataset.py::test_behavior_flags_independent_of_label`).

**Not computed:** `MIXER_EXPOSURE`, `EXCHANGE_INTERACTION`, `BRIDGE_ACTIVITY`
— no reliable signal exists inside either static source alone, and this
pipeline deliberately never touches a live case `.db` (that would couple a
static research benchmark to a specific investigation, which it must not
be). Named here as a limitation, not silently absent.

## 5. Record counts (quality report)

Generated fresh by every run of `tools/build_crypto_benchmark.py` at
`data/crypto_benchmark/quality_report.json` (gitignored, like everything
under `data/`). The exact current counts:

```json
{
  "generated_at": "2026-09-07T01:26:57.853364+00:00",
  "sources": {
    "elliptic_transactions": {
      "source": "ellipticpp_local",
      "raw_rows": 203769,
      "unique_ids": 203769,
      "label_counts": {"UNKNOWN": 157205, "LICIT": 42019, "ILLICIT": 4545}
    },
    "elliptic_wallets": {
      "source": "ellipticpp_local",
      "raw_rows": 1268260,
      "deduplicated_rows": 920691,
      "duplicate_rows_removed": 347569,
      "unique_addresses": 822942,
      "label_counts": {"LICIT": 276699, "UNKNOWN": 629272, "ILLICIT": 14720}
    },
    "ethereum_fesevu_live": {
      "source": "fesevu_ethereum_fraud_activity+live_etherscan",
      "sampled_addresses": 3000,
      "fetch_status_counts": {"success": 3000},
      "label_counts": {"FRAUD": 1500, "LICIT": 1500}
    },
    "babd13_wallets": {
      "source": "babd13_local",
      "raw_rows": 544462,
      "deduplicated_rows": 543932,
      "unique_addresses": 542368,
      "label_conflict_accounts": 1414,
      "label_counts": {"BLACKMAIL": 6765, "LABEL_CONFLICT": 2972,
        "CYBER_SECURITY_SERVICE": 91610, "DARKNET_MARKET": 13861,
        "CENTRALIZED_EXCHANGE": 299988, "P2P_FINANCIAL_INFRASTRUCTURE": 180,
        "P2P_FINANCIAL_SERVICE": 9309, "GAMBLING": 105254,
        "GOVERNMENT_CRIMINAL_BLACKLIST": 3, "MONEY_LAUNDERING": 2,
        "PONZI_SCHEME": 14, "MINING_POOL": 1580, "TUMBLER": 11338,
        "INDIVIDUAL_WALLET": 1056},
      "confidence_counts": {"STRONG": 532669, "WEAK": 8291, "CONFLICT": 2972}
    }
  },
  "cross_source_duplicate_addresses": 0,
  "babd13_x_elliptic_overlap_addresses": 2466,
  "totals": {"total_rows": 1671392}
}
```

(Regenerated by every run at `data/crypto_benchmark/quality_report.json`,
including the full `deferred_sources` reasoning already in §2 above — trimmed
here to avoid repeating it twice.)

**1,671,392 normalized records/observations**, broken down precisely:

- **203,769** Bitcoin transaction nodes
- **920,691** deduplicated Bitcoin address-timestep observations — across
  **822,942 unique Bitcoin wallet addresses** (fewer than 920,691 because a
  minority of addresses appear at more than one `Time step`; see §3.1 for
  the full raw/dedup/unique breakdown — never conflate these three numbers)
- **3,000** Ethereum wallet enrichments
- **543,932** BABD-13 Bitcoin wallet rows — across **542,368 unique
  addresses** (§3.4); 2,972 of these rows are the two-sided
  `LABEL_CONFLICT` entries for 1,414 accounts, kept visible rather than
  collapsed. 2,466 addresses overlap with the Elliptic++ population above —
  not deduplicated across sources, since the two carry different label
  taxonomies (see §6).

This comfortably clears the 50k–100k floor and reaches the 200k–500k+
strong-target band by total record count. **It is not an even split across
chains — this benchmark is Bitcoin-dominant.** Bitcoin accounts for
1,668,392 of the 1,671,392 records (99.8%); Ethereum is represented by a
3,000-address **stratified enrichment sample** (1,500 FRAUD + 1,500 LICIT),
not a comparably large or independently-balanced Ethereum corpus. Treat any
Ethereum-specific finding from this benchmark as drawn from that bounded
sample, not from full Ethereum chain coverage — raising `--max-addresses`
(see §8) grows it, but does not change this asymmetry by default.

The Ethereum live enrichment completed with **100% fetch success** on the
full 3,000-address default sample (0 failures, 0 not-yet-checked) — a real
result, not assumed; a production run against a less cooperative sample
would show a mix of `success`/`failed` here, and that would be the correct,
honest outcome too.

## 6. Deduplication

- **Within Elliptic++ wallets:** full-row exact-duplicate detection, see §3.1
  (347,569 of 1,268,260 raw rows removed).
- **Within Elliptic++ transactions / Ethereum:** no duplicates found (each
  source's own primary key — `txId` / `address` — is unique in the raw file).
- **Cross-source:** `quality_report.json`'s `cross_source_duplicate_addresses`
  checks for a BTC wallet address and an Ethereum address colliding as
  literal strings — structurally near-impossible given the two chains'
  address formats, included as a defensive check rather than assumed safe.
- **No second Elliptic-derived source was ingested this loop** (the
  HuggingFace Elliptic mirrors found during sourcing were deliberately not
  used — see §2 — specifically to avoid the double-counting problem a
  second copy of the same underlying data would create).
- **Within BABD-13:** ~527 byte-identical raw-row duplicates removed; 1,414
  accounts (3,216 raw rows) carry genuinely conflicting labels across
  duplicate rows — **not** deduplicated by picking one, marked
  `LABEL_CONFLICT` instead and excluded from the balanced subset (§3.4).
- **BABD-13 vs. Elliptic++ (cross-source, not deduplicated):** 2,466
  addresses appear in both. Left as-is rather than merged or dropped — the
  two use incompatible label taxonomies (13-class vs. ILLICIT/LICIT/UNKNOWN),
  so silently picking one source's label for an overlapping address would be
  an unverified judgment call this loop does not make. Surfaced in
  `quality_report.json` for a future loop to actually reconcile.

## 7. Splits

- **Dataset A (realistic):** `bitcoin_transactions_realistic.jsonl.gz`,
  `bitcoin_wallets_realistic.jsonl.gz`, `ethereum_wallets_realistic.jsonl.gz`
  (gzipped — a real run's row count produces multi-GB of plain JSONL, since
  JSONL repeats every key name on every line with no shared schema; measured
  ~11x smaller gzipped, 3.7GB -> 328MB total. Read with
  `gzip.open(path, "rt")` or `gzip -dc file.jsonl.gz`) — each source's
  natural label distribution, untouched (Elliptic: ~2% illicit; fesevu:
  pre-balanced by its own author, not re-balanced again here).
- **Dataset B (balanced research subset):** `balanced_subset.jsonl.gz` — Bitcoin
  wallets capped to the smallest class's size across ILLICIT/LICIT/UNKNOWN;
  Ethereum wallets (successful fetches only) capped to the smaller of
  FRAUD/LICIT. For training/experimentation, not evaluation.
- **Temporal split (Bitcoin, within-source):** uses Elliptic's native `Time
  step` (1–49) column — `train` (≤34), `val` (35–42), `test` (>42) — the
  standard convention in Elliptic literature. No random row split, so no
  temporal leakage.
- **Source-held-out split (Ethereum):** `source_held_out_train` /
  `source_held_out_test`, assigned deterministically from a SHA-256 hash of
  the address (never Python's built-in `hash()`, which is process-randomized
  and would silently reshuffle the split on every run) — stable across runs,
  ~70/30. Lets a future experiment ask "does a model trained primarily on
  Bitcoin generalize to Ethereum" as a first-class question, rather than
  mixing both chains into one shuffled pool.
- **BABD-13 (Loop 54): kept in its own files, not merged into Dataset A/B**
  — `babd13_wallets_realistic.jsonl.gz` (natural distribution, all rows
  including `LABEL_CONFLICT`) and `babd13_wallets_balanced.jsonl.gz`
  (capped to the smallest of its 13 classes, `LABEL_CONFLICT` excluded
  outright — see §3.4 for why merging taxonomies would be a false-alarm
  risk). Same SHA-256-address `source_held_out_train`/`test` split as
  Ethereum, since BABD-13's public CSV carries no per-row timestamp/time-step
  column to split on temporally.

## 8. Reproducibility

```
python tools/build_crypto_benchmark.py                    # default 3,000-address Ethereum sample
python tools/build_crypto_benchmark.py --max-addresses 500 --skip-ethereum
python tools/build_crypto_benchmark.py --refresh           # retry addresses cached as "failed"
python tools/build_crypto_benchmark.py --skip-babd13       # if BABD-13.csv isn't present locally
```

**Caution:** `--skip-ethereum` and `--skip-babd13` skip *loading* that
source for the current run, and the run still overwrites that source's own
output file with an empty one — they do not preserve a previous run's
output. The underlying Ethereum fetch cache is untouched either way (so a
follow-up plain run re-populates it for free), but a report generated with
either skip flag understates the true corpus until re-run without it. Use
skip flags only for fast local iteration on the other source(s), never to
produce the reference `quality_report.json`.

The Ethereum sample is **deterministic and stable** — `sample_ethereum_addresses`
always selects the same first N stratified addresses from the source file's
own order, regardless of what's already cached. Combined with the local
fetch cache (`external_data/ethereum_fraud_activity/etherscan_fetch_cache.json`),
this means:

- A plain re-run makes **zero new Etherscan API calls** once the sample is
  fully cached.
- Raising `--max-addresses` later fetches only the newly-added addresses.
- `--refresh` retries only addresses cached as `failed`, never re-fetches a
  `success`.
- A fetch failure is recorded as `fetch_status="failed"`, `features=null`
  and is never silently read as "zero activity" (a genuine zero-transaction
  address is recorded as `fetch_status="success"` with `transaction_count: 0`
  — a different, real fact from "the provider didn't answer").

## 9. Known limitations

- Ethereum behavioral features come from a 20-transaction shallow sample
  per address, not full history (§3.2).
- Ethereum ground truth is the `fesevu` dataset's own curation, not a
  regulatory designation (§3.2) — weaker evidentiary tier than OFAC.
- Bitcoin transaction-node rows have no raw address (source is anonymized at
  that granularity) — only the wallet-level Bitcoin rows carry real
  addresses.
- No mixer/exchange/bridge-interaction behavior flags (§4) — no reliable
  signal in either static source alone.
- CryptoXChain-500K, the 2025 Kaggle multi-crypto anomaly dataset, the
  unverified 1.62B-row Ethereum dataset, the 43.6M-address Kaggle wallet-
  classification dataset, and the DIAM graph-multigraph corpus are all
  deferred, not included — see §2 for per-source reasoning.
- BABD-13's 148 features are not mapped into this benchmark's shared
  `HIGH_ACTIVITY`/`HIGH_VALUE`/`FAN_IN`/`FAN_OUT` flag vocabulary — its
  columns are indicator-category codes, not named tx-count/degree fields
  (§3.4); `behavior_flags` is `[]` for every BABD-13 row rather than guessed.
- BABD-13's cross-source overlap with Elliptic++ (2,466 addresses, §6) has
  not been reconciled — whether the two sources agree on those addresses'
  behavior category is an open question, not silently assumed either way.
- **`babd13_wallets_balanced.jsonl.gz` is 26 rows, not a typo.**
  `build_babd13_balanced_subset` caps every class to the size of the
  smallest — the same strategy that works fine for Elliptic's 3 fairly-sized
  classes breaks down completely across BABD-13's 13, three of which have
  single-digit counts even before conflict removal (`MONEY_LAUNDERING`: 2,
  `GOVERNMENT_CRIMINAL_BLACKLIST`: 3, `PONZI_SCHEME`: 14). The result is a
  real but practically-useless-for-training balanced file (2 rows × 13
  classes). Not silently reworked into a different balancing scheme this
  loop — that's a real design decision (e.g. dropping near-empty classes,
  or per-class thresholds) that deserves its own evaluation, not a default
  guessed under this loop's own time budget. Use
  `babd13_wallets_realistic.jsonl.gz`'s natural distribution for anything
  needing more than a handful of the rarest classes.
- This benchmark's *definition* (schema, splits, provenance) is this loop's
  deliverable — no ML/anomaly model is trained against it here.

## 10. Relationship to existing CyberTrace architecture

This benchmark is fully decoupled from live investigation code:
`tools/build_crypto_benchmark.py` is a standalone script (matching
`tools/eval_attribution.py`'s convention), not imported by `cybertrace/`.
Loop 45's deterministic VASP attribution (`cybertrace/attribution.py`,
`correlate.py`), Loop 48/49's exposure-vs-control semantics, and Loop 50's
case-level VASP relationships are unmodified by this loop's dataset work.
