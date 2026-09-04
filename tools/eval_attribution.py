#!/usr/bin/env python3
"""Benchmark cybertrace.attribution's VASP candidate engine (Loop 45) against
the real local ground-truth corpora -- never a synthetic wallet or an
invented label.

    python tools/eval_attribution.py                     # offline: corpus
                                                           # stats + the
                                                           # constructed-
                                                           # scenario suite
    python tools/eval_attribution.py --live --per-brand 3 # + live reconstruction

Two entirely different things are reported, and must not be blurred:

  offline suite   Deterministic, no network. Real ground-truth addresses
                  (VASP_DISCLOSED/TAG_ATTESTED/OFAC, enumerated straight off
                  the local corpora) wired into hand-built graph scenarios --
                  same technique tests/test_risk.py and tests/test_correlate.py
                  already use to exercise real evidence sources. Proves the
                  SCORING POLICY behaves (multi-brand conflicts preserved,
                  OFAC never mistaken for a VASP, contextual-only signals
                  never name a brand alone) -- not whether the engine can
                  reconstruct an unknown label from scratch.

  --live sample   The actual section I question: hide a real address's own
                  ground truth (and its whole cluster, per section L), fetch
                  its REAL transaction history via the exact same
                  search+ingest path `trace-wallet` uses (no new API, no new
                  integration), and see whether counterparty/cross-chain
                  signals alone reconstruct the correct brand. Bounded and
                  opt-in: a handful of real addresses per brand, not a mass
                  crawl, out of respect for the same free, rate-limited APIs
                  bitcoin_module already treats carefully.

Categories with NO real local example (section J's bridge/router negative,
absent a locally-verified router contract address) are reported as exactly
that -- "no real example available" -- never filled in with a guess. See
section Q: no claimed benchmark success without a real labelled set.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybertrace import attribution, correlate
from cybertrace.evidence import EvidenceStore, ingest
from cybertrace.integrations import exchange_tags, ofac
from cybertrace.modules import get_module

VASP_DISCLOSED, TAG_ATTESTED = correlate.VASP_DISCLOSED, correlate.TAG_ATTESTED

# Real, observed raw TAG_ATTESTED label vocabulary -- queried live against
# the shipped local exchange_tags index (Loop 45; see the grouped
# label/pack/currency counts this file's own commit message cites) -- never
# guessed. Longest/most specific phrase first, same convention as
# correlate._WALLET_ROLE_FROM_DISCLOSURE_LABEL. Benchmark-only: the engine
# itself (attribution.py) never canonicalizes a brand name, so this does not
# change what `vasp_candidates` returns -- only how THIS SCRIPT groups
# results for reporting/scoring purposes.
_BRAND_FROM_LABEL = (
    ("bitmex reserve wallet", "BitMEX"),
    ("binance reserve wallets", "Binance"), ("binance.com", "Binance"),
    ("bybit reserve wallets", "Bybit"),
    ("okx reserves wallets", "OKX"), ("okx erc20 reserves", "OKX"),
    ("deribit reserves", "Deribit"),
    ("huobi reserve wallets", "Huobi"), ("huobi.com", "Huobi"),
    ("kucoin reserve wallets", "KuCoin"), ("kucoin usdt reserves", "KuCoin"),
    ("kucoin usdc reserves", "KuCoin"),
    ("swisborg reserve wallets", "SwissBorg"),  # sic -- real corpus's own typo
    ("crypto.com reserves wallets", "Crypto.com"),
    ("bitfinex", "Bitfinex"),
    ("coinbase.com", "Coinbase"),
    ("kraken.com", "Kraken"),
    ("bitstamp", "Bitstamp"),
    ("bittrex.com", "Bittrex"),
    ("zaif", "Zaif"), ("mtgox", "Mt. Gox"), ("bter.com", "Bter"),
    ("bitfloor", "Bitfloor"), ("simplecoin.cz", "SimpleCoin"),
    ("vircurex.com", "Vircurex"),
)

_CURRENCY_TO_ETYPE = {"BTC": "BTC_ADDRESS", "ETH": "ETH_ADDRESS", "BNB": "BNB_ADDRESS",
                      "TRX": "TRX_ADDRESS", "SOL": "SOL_ADDRESS"}
_CURRENCY_TO_CHAIN = {"BTC": "bitcoin", "ETH": "ethereum", "BNB": "bnb",
                      "TRX": "tron", "SOL": "solana"}


def canonical_brand(raw_label: str) -> str:
    lowered = (raw_label or "").lower()
    for phrase, brand in _BRAND_FROM_LABEL:
        if phrase in lowered:
            return brand
    return raw_label  # unrecognized -- its own bucket, never guessed into one above


def ground_truth_corpus() -> Dict[Tuple[str, str], dict]:
    """(currency, address) -> {brand, tier, raw_label, source} for every real
    VASP_DISCLOSED/TAG_ATTESTED row in the local corpora, deduplicated --
    VASP_DISCLOSED wins when an address carries both, same precedence
    correlate._vasp_endpoints already enforces. REGULATORY_ATTESTED (OFAC)
    is never in this dict -- see ofac_negatives() for how OFAC data is used
    instead (section A: OFAC is not a VASP source)."""
    out: Dict[Tuple[str, str], dict] = {}
    for row in exchange_tags.all_exchange_addresses():
        key = (row["currency"], row["address"])
        out[key] = {"brand": canonical_brand(row["label"]), "tier": TAG_ATTESTED,
                    "raw_label": row["label"], "source": row["pack"]}
    for row in exchange_tags.all_vasp_disclosed():
        key = (row["currency"], row["address"])
        out[key] = {"brand": row["brand"], "tier": VASP_DISCLOSED,
                    "raw_label": row["role"], "source": row["source"]}
    return out


def ofac_negatives() -> List[dict]:
    """Real OFAC-designated addresses -- a government designation, never a
    VASP claim (section A/M). Used only to confirm the engine never treats
    one as ground truth, not as a positive brand to reconstruct."""
    return ofac.all_addresses()


def categorize(corpus: Dict[Tuple[str, str], dict]) -> Dict[str, list]:
    """Section J's categories, populated ONLY from what the local corpora
    actually contain.

    hard_positive draws from `chaininfo`/`walletexplorer` only, both
    confirmed (manual inspection, Loop 45) to carry real per-address VASP
    wallet labels (Huobi.com, Kraken.com, LocalBitcoins.com, ...). The
    corpus's third exchange-labeled pack, `etherscan-wordcloud-exchange`
    (646 rows), was EXCLUDED after the same inspection showed its "labels"
    are ERC-20 TOKEN CONTRACT addresses named after small exchanges
    ("2GT_token (2GT)", "AC eXchange Token (ACXT)", "APROBIT") -- not a
    VASP's own wallet at all. Treating those as ground truth would silently
    poison hard_positive with the wrong entity type entirely. Kept instead
    as its own category: a real example of section M's "stale/incorrect
    third-party label" adversarial case, where the expected engine behavior
    is exactly what it already does (no fabricated candidate), not
    reconstruction of a "true" brand that was never actually there.

    bridge/router carries no real, locally-verified example (no known-
    router-contract registry exists in this codebase -- the bridge modules
    take an arbitrary address as INPUT, they don't ship a list of the
    bridges' own contract addresses) -- reported as such, not guessed.
    """
    easy = [(k, v) for k, v in corpus.items() if v["tier"] == VASP_DISCLOSED]
    hard = [(k, v) for k, v in corpus.items() if v["tier"] == TAG_ATTESTED
            and v["source"] in ("chaininfo", "walletexplorer")]
    mislabeled = [(k, v) for k, v in corpus.items() if v["tier"] == TAG_ATTESTED
                 and v["source"] == "etherscan-wordcloud-exchange"]
    return {
        "easy_positive": easy, "hard_positive": hard,
        "unreliable_third_party_label": mislabeled,
        "negative_ofac": ofac_negatives(),
        "bridge_router_negative": [],  # see docstring above
    }


def _by_brand_sample(rows: List[Tuple[Tuple[str, str], dict]], per_brand: int,
                     max_total: int) -> List[Tuple[Tuple[str, str], dict]]:
    """Up to `per_brand` addresses per real brand, BTC-currency preferred
    (blockchain.com's rawaddr response is the richest real counterparty/flow
    source this codebase reads -- see bitcoin_module._check_blockchain_com),
    capped at `max_total` overall so a --live run stays a bounded sample, not
    a crawl of a 337k-row corpus. Deterministic (sorted), not random, so two
    runs against the same corpus snapshot pick the same addresses."""
    by_brand: Dict[str, list] = {}
    for key, v in sorted(rows, key=lambda kv: (kv[1]["brand"], kv[0][0] != "BTC", kv[0])):
        by_brand.setdefault(v["brand"], [])
        if len(by_brand[v["brand"]]) < per_brand:
            by_brand[v["brand"]].append((key, v))
    out = [item for items in by_brand.values() for item in items]
    return out[:max_total]


async def _ingest_live(currency: str, address: str, store: EvidenceStore,
                       semaphore: asyncio.Semaphore, fetch_cross_chain: bool) -> bool:
    """Exactly the trace-wallet search+ingest path, for ONE address, plus
    (optionally) the same live cross-chain lookup `trace-cross-chain` runs --
    no new module, no new call shape, only reused here for a benchmark
    sample instead of one CLI invocation."""
    chain = _CURRENCY_TO_CHAIN.get(currency)
    if chain is None:
        return False
    module = get_module(chain)
    if module is None:
        return False
    async with semaphore:
        try:
            async with module:
                result = await module.search(address, target_type=chain)
        except Exception:
            return False
    try:
        ingested = bool(ingest(result, store))
    except Exception:
        return False

    if fetch_cross_chain:
        from cybertrace.modules.cross_chain_module import (
            AcrossModule, LifiModule, ThorchainModule, WormholeModule)
        for module_cls in (WormholeModule, ThorchainModule, AcrossModule, LifiModule):
            async with semaphore:
                try:
                    async with module_cls() as m:
                        links = (await m.search(address)).summary.get(
                            "transaction_cross_chain_links", [])
                except Exception:
                    links = []
            for link in links:
                store.record_cross_chain_tx_link(link)
    return ingested


def _masked_prediction(store: EvidenceStore, entity_id: str, address: str, etype: str) -> Optional[dict]:
    """attribution.vasp_candidates for `entity_id`, with its OWN ground truth
    AND its entire cospend cluster masked out of `exchange_of` first --
    section L's cluster-aware leakage guard, using correlate.crypto_clusters
    (real PART_OF_CLUSTER data from the live ingest above) rather than a
    synthetic split. Reaches into correlate's private _vasp_endpoints/
    _adjacency on purpose: this masking need is specific to benchmarking held
    -out labels and has no other caller -- adding a public wrapper for one
    script would be exactly the unrequested-abstraction Occam warns against.
    """
    wallet_rows = store._all(
        "SELECT entity_id, normalized_value, raw_value, etype FROM entities "
        "WHERE etype IN ('BTC_ADDRESS','ETH_ADDRESS','BNB_ADDRESS','POLYGON_ADDRESS','TRX_ADDRESS','SOL_ADDRESS')")
    values = {r["entity_id"]: (r["raw_value"] or r["normalized_value"]) for r in wallet_rows}
    if entity_id not in values:
        return None

    exchange_of = correlate._vasp_endpoints(store, values)
    clusters = correlate.crypto_clusters(store)
    cluster_label = clusters.get(entity_id)
    masked = {entity_id} | ({eid for eid, c in clusters.items() if c == cluster_label}
                            if cluster_label else set())
    exchange_of = {eid: hit for eid, hit in exchange_of.items() if eid not in masked}

    adjacency = correlate._adjacency(store)
    return attribution.vasp_candidates(
        store, entity_id, address, etype,
        peers=adjacency.get(entity_id, {}), exchange_of=exchange_of, values=values)


async def run_live_sample(sample: List[Tuple[Tuple[str, str], dict]], concurrency: int) -> List[dict]:
    semaphore = asyncio.Semaphore(max(1, concurrency))
    rows = []
    with EvidenceStore(":memory:") as store:
        for (currency, address), truth in sample:
            ok = await _ingest_live(currency, address, store, semaphore, fetch_cross_chain=True)
            etype = _CURRENCY_TO_ETYPE[currency]
            entity_id = store.find_entity(etype, address)
            if not ok or entity_id is None:
                rows.append({"address": address, "true_brand": truth["brand"],
                            "tier": truth["tier"], "status": "not_ingested"})
                continue
            result = _masked_prediction(store, entity_id, address, etype)
            predicted = result["primary_candidate"] if result else None
            top_brands = ({canonical_brand(predicted)} if predicted else set()) | (
                {canonical_brand(c["brand"]) for c in (result or {}).get("also_attributed", [])})
            rows.append({
                "address": address, "true_brand": truth["brand"], "tier": truth["tier"],
                "status": "ok", "predicted": canonical_brand(predicted) if predicted else None,
                "correct": predicted is not None and canonical_brand(predicted) == truth["brand"],
                "top3_hit": truth["brand"] in top_brands,
                "strength": (result or {}).get("strength"),
            })
    return rows


# --- offline, deterministic scenario suite ----------------------------------
# Real ground-truth addresses (fetched from the local corpora, never
# invented), wired into hand-built graph edges -- same technique
# tests/test_risk.py/tests/test_correlate.py already use for real-source
# scenarios. No network. Proves the POLICY, not reconstruction from scratch
# (that is what --live is for).

def _pick(corpus: Dict[Tuple[str, str], dict], brand: str, currency: str = "BTC") -> Optional[Tuple[str, str]]:
    for (cur, addr), v in corpus.items():
        if cur == currency and v["brand"] == brand:
            return (cur, addr)
    return None


def offline_suite(corpus: Dict[Tuple[str, str], dict]) -> List[dict]:
    results = []

    # M1: multi-brand conflict must be PRESERVED, never "first brand wins".
    binance = _pick(corpus, "Binance")
    bybit = _pick(corpus, "Bybit")
    if binance and bybit:
        with EvidenceStore(":memory:") as store:
            target_id = store.upsert_target("http://eval.local")
            snap_id = store.insert_snapshot(target_id, {}, "eval_attribution", status="OK")
            unknown_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # real, valid-format BTC address never in either corpus
            unknown = store.upsert_entity("BTC_ADDRESS", unknown_addr)
            for _cur, addr in (binance, bybit):
                peer = store.upsert_entity("BTC_ADDRESS", addr)
                obs = store.insert_observation(snap_id, peer, method="eval:counterparty")
                rel = store.upsert_relationship(unknown, peer, "TRANSACTED_WITH", source_label="eval")
                store.add_evidence(rel, [obs])
            result = _masked_prediction(store, unknown, unknown_addr, "BTC_ADDRESS")
            # canonical_brand here, not a raw comparison: attribution.py itself
            # never canonicalizes (see _BRAND_FROM_LABEL's own docstring), so
            # the engine's real output is whatever raw TAG_ATTESTED label this
            # specific address carries (e.g. "binance.com") -- this benchmark
            # script's OWN brand bucketing has to be applied to compare it
            # against the "Binance"/"Bybit" buckets _pick() selected by.
            brands = {canonical_brand(result["primary_candidate"])} | \
                {canonical_brand(c["brand"]) for c in result["also_attributed"]}
            ok = "Binance" in brands and "Bybit" in brands
            results.append({"case": "multi_brand_conflict_preserved", "pass": ok,
                            "detail": f"candidates: {sorted(brands)}"})
    else:
        results.append({"case": "multi_brand_conflict_preserved", "pass": None,
                        "detail": "no real Binance+Bybit BTC ground truth available locally"})

    # M2: an OFAC designation must never surface as a VASP candidate.
    ofac_rows = ofac_negatives()
    ofac_row = next((r for r in ofac_rows if r["currency"] == "BTC"), None)
    if ofac_row:
        with EvidenceStore(":memory:") as store:
            target_id = store.upsert_target("http://eval.local")
            snap_id = store.insert_snapshot(target_id, {}, "eval_attribution", status="OK")
            unknown_addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"  # real, valid-format, never in either corpus
            unknown = store.upsert_entity("BTC_ADDRESS", unknown_addr)
            peer = store.upsert_entity("BTC_ADDRESS", ofac_row["address"])
            obs = store.insert_observation(snap_id, peer, method="eval:counterparty")
            rel = store.upsert_relationship(unknown, peer, "TRANSACTED_WITH", source_label="eval")
            store.add_evidence(rel, [obs])
            result = _masked_prediction(store, unknown, unknown_addr, "BTC_ADDRESS")
            ok = result["primary_candidate"] is None
            results.append({"case": "ofac_never_a_vasp_candidate", "pass": ok,
                            "detail": f"OFAC entity {ofac_row['entity_name']!r} as sole counterparty "
                                      f"-> primary_candidate={result['primary_candidate']!r}"})
    else:
        results.append({"case": "ofac_never_a_vasp_candidate", "pass": None,
                        "detail": "no real OFAC BTC address available locally"})

    # M3: bridge/router negative -- named as untestable, not faked.
    results.append({"case": "bridge_router_never_a_vasp_candidate", "pass": None,
                    "detail": "no locally-verified bridge/router CONTRACT address available "
                              "(the live bridge modules take an arbitrary address as input; "
                              "this codebase carries no registry of the bridges' own contract "
                              "addresses to test against) -- see --live for real corroboration "
                              "evidence instead"})

    return results


def print_report(corpus: Dict[Tuple[str, str], dict], categories: dict,
                 offline_results: List[dict], live_rows: Optional[List[dict]]) -> int:
    by_brand: Dict[str, int] = {}
    for v in corpus.values():
        by_brand[v["brand"]] = by_brand.get(v["brand"], 0) + 1
    print(f"\nground truth corpus: {len(corpus)} addresses across {len(by_brand)} brand(s) "
          f"(VASP_DISCLOSED + TAG_ATTESTED; OFAC/REGULATORY_ATTESTED excluded -- section A)")
    for brand, n in sorted(by_brand.items(), key=lambda kv: -kv[1])[:15]:
        print(f"  {brand:16}{n:>8}")

    print("\n=== categories (section J) ===")
    print(f"  easy_positive             {len(categories['easy_positive'])}  (VASP_DISCLOSED)")
    print(f"  hard_positive             {len(categories['hard_positive'])}  "
          "(chaininfo/walletexplorer -- confirmed real wallet labels)")
    print(f"  unreliable_third_party_label {len(categories['unreliable_third_party_label'])}  "
          "(etherscan-wordcloud-exchange -- confirmed TOKEN CONTRACTS mislabeled "
          "'exchange', not VASP wallets; section M adversarial case)")
    print(f"  negative_ofac             {len(categories['negative_ofac'])}  "
          "(real OFAC designations, never a VASP)")
    print(f"  bridge_router_negative    {len(categories['bridge_router_negative'])}  "
          "(no real local example -- see offline suite below)")

    print("\n=== offline scenario suite (no network, real addresses + constructed edges) ===")
    exit_code = 0
    for r in offline_results:
        mark = "SKIP" if r["pass"] is None else ("PASS" if r["pass"] else "FAIL")
        if r["pass"] is False:
            exit_code = 1
        print(f"  [{mark}] {r['case']}: {r['detail']}")

    if live_rows is not None:
        print(f"\n=== --live sample ({len(live_rows)} real address(es)) ===")
        gradable = [r for r in live_rows if r["status"] == "ok"]
        ungradable = [r for r in live_rows if r["status"] != "ok"]
        if ungradable:
            print(f"  {len(ungradable)} not ingested (search returned nothing live) -- excluded, not scored as a miss")
        top1 = sum(1 for r in gradable if r["correct"])
        top3 = sum(1 for r in gradable if r["top3_hit"])
        print(f"  gradable: {len(gradable)}")
        if gradable:
            print(f"  top-1 accuracy: {top1}/{len(gradable)} = {top1/len(gradable):.2f}")
            print(f"  top-3 candidate recall: {top3}/{len(gradable)} = {top3/len(gradable):.2f}")
        for r in gradable:
            mark = "ok " if r["correct"] else "MISS"
            print(f"    [{mark}] {r['address']} true={r['true_brand']} "
                  f"predicted={r['predicted']} strength={r['strength']}")
    else:
        print("\n(--live not passed: no real-address reconstruction sample was run)")

    return exit_code


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true",
                    help="also live-fetch a bounded real-address sample and test "
                         "held-out reconstruction (network required)")
    ap.add_argument("--per-brand", type=int, default=3,
                    help="max real addresses sampled per brand for --live (default: 3)")
    ap.add_argument("--max-total", type=int, default=30,
                    help="overall cap on --live sample size (default: 30)")
    ap.add_argument("--concurrency", type=int, default=2,
                    help="concurrent live fetches (default: 2 -- these are free, "
                         "rate-limited public APIs)")
    args = ap.parse_args()

    corpus = ground_truth_corpus()
    categories = categorize(corpus)
    offline_results = offline_suite(corpus)

    live_rows = None
    if args.live:
        sample = _by_brand_sample(categories["easy_positive"] + categories["hard_positive"],
                                  args.per_brand, args.max_total)
        if not sample:
            print("[!] --live requested but no real ground-truth addresses are available "
                  "locally (is external_data/exchange_tags downloaded?)", file=sys.stderr)
            return 1
        live_rows = asyncio.run(run_live_sample(sample, args.concurrency))

    return print_report(corpus, categories, offline_results, live_rows)


if __name__ == "__main__":
    raise SystemExit(main())
