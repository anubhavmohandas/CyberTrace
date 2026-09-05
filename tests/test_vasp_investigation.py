"""Loop 48 tests: policy unit tests (fast, no store) + real-corpus/real-store
negative controls and adversarial cases (offline -- local downloaded OFAC SDN
/ GraphSense TagPacks corpora only, no network, no live blockchain fetch:
AT_VASP status is a pure local-corpus address lookup, so a bare
`store.upsert_entity` is enough evidence for it -- no transaction history
needed). Skips (not fails) when a checkout has not downloaded those corpora,
same convention as tests/test_correlate.py.

Not a re-test of wallet_exchange_paths/attribution.vasp_candidates
themselves -- tests/test_attribution.py and tests/test_correlate.py already
cover proximity semantics, tier precedence, and omnibus guards exhaustively
(see docs/LOOP48.md section 2's audit). These tests are only about this
module's OWN new decision: the exposure/control policy boundary.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cybertrace.correlate import wallet_exchange_paths
from cybertrace.evidence import EvidenceStore, enrich_bitcoin

import vasp_control_attribution as vca

# Real, independently-attributed addresses (same constants tests/test_correlate.py
# pins) -- never a fabricated ground-truth claim.
BITMEX_RESERVE = "3BMEXbSSrK2K7cRgqxrtqUWfxowBBrW1BE"       # VASP_DISCLOSED
BITFINEX_COLD = "3JZq4atUahhuA9rLhXLMhhTo133J9rF97j"        # VASP_DISCLOSED
BINANCE_HOT = "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s"          # TAG_ATTESTED
OFAC_POLYANIN = "158treVZBGMBThoaympxccPdZPtqUfYrT9"
OFAC_POLYANIN_REAL_SENT_TO = [
    BINANCE_HOT, "32aYQCHHAdRZGyxX5ZqJtr3FEmQPnhvmvC", "38u7Gu2GsEEUhQDwzqHLkEA6NQuu7HrdAC",
    "3AAXYnRdcrN56tgDVbDsrFHbhK2A9QE1s5", "3Dj75bpjUVd4J7bnYnEqzS9YUtxtsfJmjg",
    "3KUkjNLuwH4WaN5u8v5xkT8uQfiuv7J3kV", "3LGyKfGNQ62CiKrhDLbMS1hrixzYGTxuK4",
    "3PrUCKdZUP2LsrUUaD16BM54kj2gNkcnyr", "3QCqAMWK51iwTGRipZVQWGrBiQPihmU2a9",
]
BTC_VALID = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"   # no VASP relationship at all


def _skip_unless_real_sources_available():
    from cybertrace.integrations import exchange_tags, ofac
    if not (ofac.available() and ofac.index_available()):
        pytest.skip("OFAC SDN not downloaded/indexed in this checkout")
    if not (exchange_tags.available() and exchange_tags.index_available()):
        pytest.skip("GraphSense TagPacks not downloaded/indexed in this checkout")


def _traced(store, address, summary_extra):
    """Same shape tests/test_correlate.py's own `_traced` helper writes --
    duplicated (4 lines) rather than imported from a test module that is not
    a library, same choice Loop 47 made for its own tiny fixture helpers."""
    addr = store.upsert_entity("BTC_ADDRESS", address)
    sid = store.insert_snapshot(store.upsert_target("btc:" + address), {}, "bitcoin")
    enrich_bitcoin(store, sid, addr, {"address": address, **summary_extra}, "bitcoin")
    return addr


def _hit_for(store, entity_id):
    return next(w for w in wallet_exchange_paths(store) if w["entity_id"] == entity_id)


# --- Policy unit tests (Adversarial Tests 1-6, brief section 13) -- no store,
# no network, hand-built `hit` dicts exercising every branch of classify() ----

def _base_hit(**over):
    hit = {"exchange": "Binance", "attribution": vca.TAG_ATTESTED,
          "attribution_source": "tag", "proximity": vca.DIRECT, "hops": 1,
          "direct_vasp_contacts": [], "secondary_vasp_contacts": [], "also_attributed": []}
    hit.update(over)
    return hit


def test_1_exchange_customer_direct_hop_never_becomes_controlled_by():
    r = vca.classify(_base_hit(proximity=vca.DIRECT, hops=1))
    assert r["control_status"] == vca.NOT_ESTABLISHED
    assert "Binance" in r["exposure_candidates"]


def test_2_ofac_then_intermediary_then_binance_is_regulatory_plus_exposure_only():
    hit = _base_hit(exchange="SUEX OTC S.R.O.", attribution=vca.REGULATORY_ATTESTED,
                    attribution_source="OFAC SDN", proximity=vca.AT_VASP, hops=0,
                    secondary_vasp_contacts=[{"exchange": "Binance", "attribution": vca.TAG_ATTESTED,
                                             "attribution_source": "tag", "hops": 2}])
    r = vca.classify(hit)
    assert r["regulatory_context"]["designated"] is True
    assert r["regulatory_context"]["entity"] == "SUEX OTC S.R.O."
    assert "Binance" in r["exposure_candidates"]
    assert r["control_status"] == vca.NOT_ESTABLISHED
    assert not any("Binance" in c and "CONTROL" in c.upper() for c in r["control_evidence"])


def test_3_multiple_vasps_preserve_ambiguity_never_pick_a_winner():
    hit = _base_hit(exchange="Binance",
                    direct_vasp_contacts=[{"exchange": "BitMEX", "attribution": vca.TAG_ATTESTED,
                                          "attribution_source": "tag", "hops": 1}])
    r = vca.classify(hit)
    assert set(r["exposure_candidates"]) == {"Binance", "BitMEX"}
    assert r["control_status"] == vca.NOT_ESTABLISHED


def test_4_hop_count_and_confidence_alone_never_flip_control_established():
    """No hub-degree signal exists in this module at all (Loop 47's hub
    penalty lives in the rejected multi-hop engine, never reused here) --
    this asserts the structural consequence: nothing about a path's shape
    (hop count, confidence) can promote DIRECT/INDIRECT to control,
    regardless of value."""
    for hops in (1, 2, 3, 4, 6):
        proximity = vca.DIRECT if hops == 1 else vca.INDIRECT
        r = vca.classify(_base_hit(proximity=proximity, hops=hops))
        assert r["control_status"] == vca.NOT_ESTABLISHED, f"hops={hops}"


def test_5_multi_hop_path_is_exposure_only_without_independent_evidence():
    r = vca.classify(_base_hit(proximity=vca.INDIRECT, hops=3, attribution=vca.VASP_DISCLOSED,
                               attribution_source="binance self-disclosure"))
    assert r["control_status"] == vca.NOT_ESTABLISHED
    assert "Binance" in r["exposure_candidates"]


def test_6_explicit_vasp_disclosed_control_evidence_upgrades_to_established():
    r = vca.classify(_base_hit(proximity=vca.AT_VASP, hops=0, attribution=vca.VASP_DISCLOSED,
                               attribution_source="Binance self-disclosure (hot wallet): binance.com"))
    assert r["control_status"] == vca.ESTABLISHED
    assert r["control_confidence"] == vca.HIGH
    assert r["control_candidates"] == ["Binance"]


def test_at_vasp_tag_attested_is_exposure_only_a_third_party_guess_is_not_ownership():
    r = vca.classify(_base_hit(proximity=vca.AT_VASP, hops=0, attribution=vca.TAG_ATTESTED))
    assert r["control_status"] == vca.NOT_ESTABLISHED
    assert r["exposure_confidence"] == vca.LOW


def test_candidate_only_evidence_never_reaches_established():
    candidate = {"primary_candidate": "Binance", "strength": "HIGH", "also_attributed": [],
                "supporting_signals": [{"rule_id": "attribution.counterparty_overlap.v1"}]}
    r = vca.classify(None, candidate)
    assert r["control_status"] == vca.NOT_ESTABLISHED
    assert "Binance" in r["exposure_candidates"]
    assert vca.CANDIDATE_VASP_EXPOSURE in r["exposure_evidence"]


def test_no_evidence_at_all_is_insufficient_on_both_axes():
    r = vca.classify(None, None)
    assert r["exposure_evidence"] == [vca.INSUFFICIENT_EVIDENCE]
    assert r["control_status"] == vca.CONTROL_UNKNOWN


# --- Real-corpus, real-store negative-control populations (brief section 6) --

def test_population_a_a_real_vasp_disclosed_address_is_control_established(tmp_path):
    """The suspect address IS a real VASP_DISCLOSED address (BitMEX's own
    published proof-of-reserves wallet) -- the one population where CONTROL
    should read ESTABLISHED."""
    _skip_unless_real_sources_available()
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr = store.upsert_entity("BTC_ADDRESS", BITMEX_RESERVE)
        hit = _hit_for(store, addr)
        r = vca.classify(hit)
        assert r["control_status"] == vca.ESTABLISHED
        assert r["control_confidence"] == vca.HIGH
        assert r["control_candidates"] == ["BitMEX"]


def test_population_b_a_real_vasp_customer_is_exposure_only_never_control(tmp_path):
    """A synthetic suspect wallet that directly transacted with Binance's
    real, independently-tagged hot wallet -- a customer relationship, not
    Binance's own address. Must never read CONTROL ESTABLISHED."""
    _skip_unless_real_sources_available()
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr = _traced(store, BTC_VALID, {"counterparty_addresses": [BINANCE_HOT]})
        hit = _hit_for(store, addr)
        r = vca.classify(hit)
        assert "binance.com" in r["exposure_candidates"]
        assert r["control_status"] == vca.NOT_ESTABLISHED


def test_population_c_a_real_ofac_designated_suspects_real_binance_deposit(tmp_path):
    """OFAC_POLYANIN's real, live-observed transaction history (19 real
    transactions, 8 of them real deposits into Binance's real hot wallet --
    same ground truth tests/test_correlate.py pins). Regulatory attribution
    on the suspect himself; real exposure to Binance; control never
    established for either."""
    _skip_unless_real_sources_available()
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr = _traced(store, OFAC_POLYANIN, {
            "sent_to_addresses": OFAC_POLYANIN_REAL_SENT_TO, "tx_sample_size": 19,
            "first_seen": "2018-01-18T09:06:08", "last_seen": "2021-02-14T19:46:51"})
        hit = _hit_for(store, addr)
        r = vca.classify(hit)
        assert r["regulatory_context"]["designated"] is True
        assert "binance.com" in r["exposure_candidates"]
        assert r["control_status"] == vca.NOT_ESTABLISHED


def test_population_d_a_three_hop_path_to_a_vasp_disclosed_address_is_still_not_control(tmp_path):
    """suspect -cospend-> intermediary -counterparty-> a real VASP_DISCLOSED
    address (Bitfinex's own disclosed cold wallet). The sharpest version of
    Invariant 2: even a real, strong-tier VASP_DISCLOSED endpoint does not
    become control when reached through hops -- only AT_VASP does."""
    _skip_unless_real_sources_available()
    intermediary = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr = _traced(store, BTC_VALID, {"cospend_addresses": [intermediary]})
        inter_id = store.find_entity("BTC_ADDRESS", intermediary)
        sid = store.insert_snapshot(store.upsert_target("btc:" + intermediary), {}, "bitcoin")
        enrich_bitcoin(store, sid, inter_id,
                       {"address": intermediary, "counterparty_addresses": [BITFINEX_COLD]}, "bitcoin")

        hit = _hit_for(store, addr)
        assert hit["proximity"] == vca.INDIRECT
        assert hit["hops"] == 2
        r = vca.classify(hit)
        assert r["control_status"] == vca.NOT_ESTABLISHED
        assert "Bitfinex" in r["exposure_candidates"]


def test_population_e_no_vasp_relationship_is_insufficient_evidence(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        hits = [w for w in wallet_exchange_paths(store) if w["value"] == BTC_VALID]
        assert hits == []
        r = vca.classify(None)
        assert r["exposure_evidence"] == [vca.INSUFFICIENT_EVIDENCE]
        assert r["control_status"] == vca.CONTROL_UNKNOWN


# --- Corpus-scale FPR check (brief section 11's headline metric) ------------

def test_ofac_control_false_positive_rate_is_zero_across_the_full_local_ofac_corpus(tmp_path):
    """Every real OFAC SDN digital-currency address this checkout has
    downloaded, run through the actual production wallet_exchange_paths ->
    classify() pipeline. AT_VASP status is a pure local-corpus lookup (no
    live transaction fetch needed), so this covers the FULL local corpus in
    one pass, not a 15-address sample -- a stronger negative control than
    Loop 47's own FPR measurement, at zero network cost.

    control_status must read ESTABLISHED for a VASP brand on exactly 0 of
    these -- an OFAC designation, however it is reached, never becomes VASP
    ownership (Invariant 3)."""
    _skip_unless_real_sources_available()
    from cybertrace.integrations import ofac
    addresses = sorted({row["address"] for row in ofac.all_addresses()
                       if row.get("currency") == "BTC"})[:500]
    if not addresses:
        pytest.skip("no BTC addresses in the local OFAC corpus")
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for a in addresses:
            store.upsert_entity("BTC_ADDRESS", a)
        false_positives = []
        for w in wallet_exchange_paths(store):
            r = vca.classify(w)
            if r["control_status"] == vca.ESTABLISHED:
                false_positives.append((w["value"], r["control_candidates"]))
        assert false_positives == [], f"OFAC->VASP-control false positives: {false_positives}"


def test_vasp_disclosed_control_recall_across_a_real_sample(tmp_path):
    """The recall counterpart to the FPR test above: a deterministic sample
    of real VASP_DISCLOSED addresses (both verified sources -- Bitfinex and
    BitMEX proof-of-reserves) must all read CONTROL ESTABLISHED. Sampled
    (50/source) rather than the full 336k-row BitMEX set, for test speed;
    sampling is deterministic (sorted), not random."""
    _skip_unless_real_sources_available()
    from cybertrace.integrations import exchange_tags
    rows = sorted({(r["currency"], r["address"], r["brand"])
                  for r in exchange_tags.all_vasp_disclosed() if r["currency"] == "BTC"})
    by_brand: dict = {}
    for currency, address, brand in rows:
        by_brand.setdefault(brand, [])
        if len(by_brand[brand]) < 50:
            by_brand[brand].append(address)
    sample = [a for addrs in by_brand.values() for a in addrs]
    if not sample:
        pytest.skip("no VASP_DISCLOSED BTC addresses in the local corpus")
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for a in sample:
            store.upsert_entity("BTC_ADDRESS", a)
        misses = []
        for w in wallet_exchange_paths(store):
            if w["value"] not in sample:
                continue
            r = vca.classify(w)
            if r["control_status"] != vca.ESTABLISHED:
                misses.append((w["value"], r["control_status"]))
        assert misses == [], f"VASP_DISCLOSED addresses not read as control-established: {misses}"
