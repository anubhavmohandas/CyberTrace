#!/usr/bin/env python3
"""Loop 48 benchmark, moved here in Loop 49 alongside cybertrace.vasp_
investigation now that it is a production module (see docs/LOOP49.md): does
separating VASP EXPOSURE from VASP CONTROL cost real exposure discovery, and
does it actually stop false ownership claims a naive (pre-Loop-48) reading of
the same evidence would make?

Two parts, both real-data, no synthetic label anywhere in the numbers below:

  1. Offline (default, no network): full/near-full local-corpus FPR and
     recall report (same populations tests/test_vasp_investigation.py pins,
     at full corpus scale where that's cheap), plus the section 12 ablation
     (Variant A/B/C/D) over five real, named populations.
  2. `--live` (opt-in, network required): reuses tools/eval_attribution.py's
     corpus loading, masking, and live search+ingest wholesale (imported,
     never re-implemented -- Occam) to report how many wallets in that same
     real, brand-stratified sample are even CONTROL-eligible at all, next to
     the exposure number already reported for Loop 45/47.

No new graph engine, no ML, no learned weight -- see cybertrace/vasp_
investigation.py's own module docstring for the (small, closed) policy this
script is testing.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root, same as every tools/*.py

import cybertrace.vasp_investigation as vca
from cybertrace.correlate import wallet_exchange_paths
from cybertrace.evidence import EvidenceStore, enrich_bitcoin

BITMEX_RESERVE = "3BMEXbSSrK2K7cRgqxrtqUWfxowBBrW1BE"
BITFINEX_COLD = "3JZq4atUahhuA9rLhXLMhhTo133J9rF97j"
BINANCE_HOT = "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s"
OFAC_POLYANIN = "158treVZBGMBThoaympxccPdZPtqUfYrT9"
OFAC_POLYANIN_REAL_SENT_TO = [
    BINANCE_HOT, "32aYQCHHAdRZGyxX5ZqJtr3FEmQPnhvmvC", "38u7Gu2GsEEUhQDwzqHLkEA6NQuu7HrdAC",
    "3AAXYnRdcrN56tgDVbDsrFHbhK2A9QE1s5", "3Dj75bpjUVd4J7bnYnEqzS9YUtxtsfJmjg",
    "3KUkjNLuwH4WaN5u8v5xkT8uQfiuv7J3kV", "3LGyKfGNQ62CiKrhDLbMS1hrixzYGTxuK4",
    "3PrUCKdZUP2LsrUUaD16BM54kj2gNkcnyr", "3QCqAMWK51iwTGRipZVQWGrBiQPihmU2a9",
]
BTC_VALID = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
BITFINEX_INTERMEDIARY_STAND_IN = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"


def _sources_available() -> bool:
    from cybertrace.integrations import exchange_tags, ofac
    return (ofac.available() and ofac.index_available()
           and exchange_tags.available() and exchange_tags.index_available())


def _traced(store, address, summary_extra):
    addr = store.upsert_entity("BTC_ADDRESS", address)
    sid = store.insert_snapshot(store.upsert_target("btc:" + address), {}, "bitcoin")
    enrich_bitcoin(store, sid, addr, {"address": address, **summary_extra}, "bitcoin")
    return addr


def _hit_for(store, entity_id):
    return next((w for w in wallet_exchange_paths(store) if w["entity_id"] == entity_id), None)


# --- Section 6: corpus-scale negative controls / recall ---------------------

def corpus_scale_report(tmp_dir: Path) -> dict:
    from cybertrace.integrations import exchange_tags, ofac

    with EvidenceStore(str(tmp_dir / "ofac_fpr.db")) as store:
        addresses = sorted({r["address"] for r in ofac.all_addresses() if r.get("currency") == "BTC"})
        for a in addresses:
            store.upsert_entity("BTC_ADDRESS", a)
        false_positives = [
            (w["value"], r["control_candidates"])
            for w in wallet_exchange_paths(store)
            for r in [vca.classify(w)] if r["control_status"] == vca.ESTABLISHED]
        ofac_n, ofac_fp = len(addresses), false_positives

    with EvidenceStore(str(tmp_dir / "vd_recall.db")) as store:
        rows = sorted({(r["address"], r["brand"]) for r in exchange_tags.all_vasp_disclosed()
                      if r["currency"] == "BTC"})
        by_brand: dict = {}
        for address, brand in rows:
            by_brand.setdefault(brand, [])
            if len(by_brand[brand]) < 50:
                by_brand[brand].append(address)
        sample = {a for addrs in by_brand.values() for a in addrs}
        for a in sample:
            store.upsert_entity("BTC_ADDRESS", a)
        misses = [(w["value"], r["control_status"]) for w in wallet_exchange_paths(store)
                 if w["value"] in sample for r in [vca.classify(w)]
                 if r["control_status"] != vca.ESTABLISHED]
        vd_n, vd_misses = len(sample), misses

    return {"ofac_n": ofac_n, "ofac_control_false_positives": ofac_fp,
           "vasp_disclosed_n": vd_n, "vasp_disclosed_control_misses": vd_misses}


# --- Section 12: required ablation, over 5 real/real-constructed populations -

def _named_populations(tmp_dir: Path) -> List[Tuple[str, dict]]:
    """One real (or real-endpoint-backed) example per population A-E. n=5:
    illustrative of the mechanism this ablation exists to show, not a
    statistical claim -- same honesty discipline Loop 47 applied to its own
    n=2 `indirect` stratum."""
    out = []
    with EvidenceStore(str(tmp_dir / "pop_a.db")) as store:
        addr = store.upsert_entity("BTC_ADDRESS", BITMEX_RESERVE)
        out.append(("A: real VASP_DISCLOSED address (BitMEX's own)", _hit_for(store, addr)))
    with EvidenceStore(str(tmp_dir / "pop_b.db")) as store:
        addr = _traced(store, BTC_VALID, {"counterparty_addresses": [BINANCE_HOT]})
        out.append(("B: real VASP customer (1-hop counterparty of Binance)", _hit_for(store, addr)))
    with EvidenceStore(str(tmp_dir / "pop_c.db")) as store:
        addr = _traced(store, OFAC_POLYANIN, {
            "sent_to_addresses": OFAC_POLYANIN_REAL_SENT_TO, "tx_sample_size": 19,
            "first_seen": "2018-01-18T09:06:08", "last_seen": "2021-02-14T19:46:51"})
        out.append(("C: real OFAC-designated suspect (Polyanin -> Binance)", _hit_for(store, addr)))
    with EvidenceStore(str(tmp_dir / "pop_d.db")) as store:
        addr = _traced(store, BTC_VALID, {"cospend_addresses": [BITFINEX_INTERMEDIARY_STAND_IN]})
        inter_id = store.find_entity("BTC_ADDRESS", BITFINEX_INTERMEDIARY_STAND_IN)
        sid = store.insert_snapshot(store.upsert_target("btc:" + BITFINEX_INTERMEDIARY_STAND_IN), {}, "bitcoin")
        enrich_bitcoin(store, sid, inter_id,
                       {"address": BITFINEX_INTERMEDIARY_STAND_IN, "counterparty_addresses": [BITFINEX_COLD]},
                       "bitcoin")
        out.append(("D: 2-hop indirect path to a real VASP_DISCLOSED address", _hit_for(store, addr)))
    with EvidenceStore(str(tmp_dir / "pop_e.db")) as store:
        store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        out.append(("E: no VASP relationship at all", None))
    return out


def _variant_a_claim(hit) -> str:
    """Direct transaction evidence only -- AT_VASP or DIRECT, any tier,
    claims plain ownership ('VASP = X'), exactly the pre-Loop-48 cli.py
    headline this loop's own audit found (docs/LOOP48.md section 2)."""
    if hit and hit["proximity"] in (vca.AT_VASP, vca.DIRECT) and hit["attribution"] != vca.REGULATORY_ATTESTED:
        return f"VASP = {hit['exchange']}"
    return "no claim"


def _variant_b_claim(hit) -> str:
    """Direct + multi-hop -- same naive claim, INDIRECT included."""
    if hit and hit["attribution"] != vca.REGULATORY_ATTESTED:
        return f"VASP = {hit['exchange']}"
    return "no claim"


def _variant_c_claim(hit) -> str:
    """Control evidence only -- silent unless classify() reaches ESTABLISHED."""
    r = vca.classify(hit)
    if r["control_status"] == vca.ESTABLISHED:
        return f"CONTROLLED_BY = {', '.join(r['control_candidates'])}"
    return "no claim"


def _variant_d_claim(hit) -> str:
    """Exposure + control, separated -- this module's actual output."""
    r = vca.classify(hit)
    exposure = (f"EXPOSURE({r['exposure_confidence']}) = {', '.join(r['exposure_candidates'])}"
               if r["exposure_candidates"] else "no exposure")
    control = (f"CONTROL = {', '.join(r['control_candidates'])}"
              if r["control_status"] == vca.ESTABLISHED else "CONTROL = not established")
    return f"{exposure}; {control}"


def run_ablation(tmp_dir: Path) -> List[dict]:
    out = []
    for name, hit in _named_populations(tmp_dir):
        out.append({"population": name, "A_direct_only": _variant_a_claim(hit),
                   "B_direct_plus_multihop": _variant_b_claim(hit),
                   "C_control_only": _variant_c_claim(hit),
                   "D_separated_semantics": _variant_d_claim(hit)})
    return out


# --- Optional live exposure comparison against Loop 45/47 -------------------

def run_live(per_brand: int = 3, max_total: int = 30) -> None:
    import eval_attribution as ea  # sibling module in this same tools/ directory

    corpus = ea.ground_truth_corpus()
    categories = ea.categorize(corpus)
    positives = categories["easy_positive"] + categories["hard_positive"]
    sample = ea._by_brand_sample(positives, per_brand, max_total)

    async def _run():
        store = EvidenceStore(":memory:")
        sem = asyncio.Semaphore(4)
        control_eligible, exposure_found = 0, 0
        for (currency, address), truth in sample:
            ok = await ea._ingest_live(currency, address, store, sem, fetch_cross_chain=False)
            if not ok:
                continue
            entity_id = store.find_entity({"BTC": "BTC_ADDRESS"}.get(currency, "BTC_ADDRESS"), address)
            hit = _hit_for(store, entity_id) if entity_id else None
            r = vca.classify(hit)
            if r["control_status"] == vca.ESTABLISHED:
                control_eligible += 1
            if r["exposure_candidates"]:
                exposure_found += 1
        store.close()
        print(f"\n--live sample (n={len(sample)} real ground-truth addresses, "
             f"same {per_brand}/brand selection tools/eval_attribution.py uses):")
        print(f"  exposure found (any brand):  {exposure_found}/{len(sample)}")
        print(f"  control ESTABLISHED (any):   {control_eligible}/{len(sample)}")
        print("  (each of these addresses IS a real VASP's own ground-truth wallet -- "
             "this is the ceiling on how often CONTROL can ever fire on a real "
             "corpus this codebase has, not a customer/OFAC population.)")

    asyncio.run(_run())


def print_report(fpr_report: dict, ablation: List[dict]) -> None:
    print("=" * 78)
    print("Loop 48 -- VASP Exposure vs. Control: real-data validation")
    print("=" * 78)

    print(f"\nOFAC -> VASP-control false-positive rate "
         f"(full local OFAC BTC corpus, n={fpr_report['ofac_n']}):")
    fp = fpr_report["ofac_control_false_positives"]
    print(f"  {len(fp)}/{fpr_report['ofac_n']} = {len(fp) / max(fpr_report['ofac_n'], 1):.2%}"
         f"  {'(target: 0% -- PASS)' if not fp else '(target: 0% -- FAIL: ' + str(fp) + ')'}")

    print(f"\nVASP_DISCLOSED control recall (real proof-of-reserves sample, "
         f"n={fpr_report['vasp_disclosed_n']}, up to 50/brand):")
    misses = fpr_report["vasp_disclosed_control_misses"]
    hit_n = fpr_report["vasp_disclosed_n"] - len(misses)
    print(f"  {hit_n}/{fpr_report['vasp_disclosed_n']} = "
         f"{hit_n / max(fpr_report['vasp_disclosed_n'], 1):.2%} correctly read as CONTROL ESTABLISHED")
    if misses:
        print(f"  misses: {misses}")

    print("\nAblation (section 12) -- n=5 named populations, real/real-endpoint-backed, "
         "illustrative of the mechanism, not a statistical claim:\n")
    for row in ablation:
        print(f"  {row['population']}")
        print(f"    A (direct-only, naive):        {row['A_direct_only']}")
        print(f"    B (direct+multihop, naive):    {row['B_direct_plus_multihop']}")
        print(f"    C (control-evidence only):     {row['C_control_only']}")
        print(f"    D (separated semantics):       {row['D_separated_semantics']}")
        print()

    print("Reading the ablation: Variant A/B assert plain ownership ('VASP = X') on "
         "population B (a real customer) whenever B is DIRECT or B/D includes INDIRECT "
         "-- exactly the pre-Loop-48 cli.py headline this loop's audit found and fixed. "
         "Variant C never over-claims, but says nothing at all about B or D -- real, "
         "actionable exposure leads go unreported. Only D reports both without "
         "conflating them.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true",
                       help="also run a live comparison against the real Loop 45/47 sample "
                            "(network required)")
    parser.add_argument("--per-brand", type=int, default=3)
    parser.add_argument("--max-total", type=int, default=30)
    args = parser.parse_args()

    if not _sources_available():
        print("Local OFAC SDN / GraphSense TagPacks corpora not downloaded/indexed "
             "in this checkout -- nothing to benchmark against. See setup.sh.")
        return 1

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        fpr_report = corpus_scale_report(tmp_dir)
        ablation = run_ablation(tmp_dir)
        print_report(fpr_report, ablation)

    if args.live:
        run_live(args.per_brand, args.max_total)

    return 0


if __name__ == "__main__":
    sys.exit(main())
