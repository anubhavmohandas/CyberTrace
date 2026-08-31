"""Risk scoring (risk-v1): explainability and policy tests.

Two layers, matching risk.py's own split:

- Unit tests drive score_wallet_risk directly with hand-built `hit`/
  `service_tags`/metadata, isolating the scoring policy from
  wallet_exchange_paths' BFS -- fast, deterministic, no external data
  required.
- Real-data tests run the actual pipeline (enrich_bitcoin -> ingest's own
  path -> wallet_trace_report) against real OFAC/GraphSense ground truth
  already used elsewhere in this suite (test_correlate.py's Polyanin and
  Blender.io fixtures), skip-guarded the same way those tests are.
"""

from __future__ import annotations

import pytest

from cybertrace.correlate import (
    AT_VASP, DIRECT, DIRECTION_UNKNOWN, REGULATORY_ATTESTED, TAG_ATTESTED,
    TO_VASP, wallet_trace_report,
)
from cybertrace.evidence import EvidenceStore, enrich_bitcoin
from cybertrace.risk import (
    CRITICAL, INSUFFICIENT_EVIDENCE, LOW, MODERATE, RISK_POLICY_VERSION,
    reconstruct_score, score_wallet_risk,
)

from .test_evidence import BTC_VALID


def _wallet(store, address=BTC_VALID, metadata=None):
    eid = store.upsert_entity("BTC_ADDRESS", address)
    if metadata:
        store.set_metadata(eid, **metadata)
    return eid


def _at_vasp_self_designation(entity_id, address, exchange="Test Sanctioned Entity",
                              profile="99999"):
    """A hand-built AT_VASP (hop 0) row shaped exactly like a
    wallet_exchange_paths() self-attribution row -- see correlate.py:1100."""
    return {"entity_id": entity_id, "value": address, "exchange": exchange,
            "hops": 0, "confidence": 1.0, "path": [entity_id], "evidence_ids": [],
            "attribution": REGULATORY_ATTESTED,
            "attribution_source": f"OFAC SDN: profile {profile}",
            "proximity": AT_VASP, "direction": DIRECTION_UNKNOWN,
            "direct_vasp_contacts": [], "secondary_vasp_contacts": []}


# --- zero evidence -----------------------------------------------------------

def test_zero_evidence_is_insufficient_not_low(tmp_path):
    """No qualifying signal at all must never read as a numeric LOW score --
    global invariant 8, "absence of evidence != low risk"."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        eid = _wallet(store)
        risk = score_wallet_risk(store, eid, BTC_VALID, hit=None, service_tags=[])

    assert risk["risk_score"] is None
    assert risk["risk_level"] == INSUFFICIENT_EVIDENCE
    assert risk["risk_categories"] == []
    assert risk["risk_contributions"] == []
    assert risk["risk_policy_version"] == RISK_POLICY_VERSION
    assert reconstruct_score(risk) is None


# --- self-designation alone reaches CRITICAL ---------------------------------

def test_self_designation_alone_reaches_critical(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        eid = _wallet(store)
        hit = _at_vasp_self_designation(eid, BTC_VALID)
        risk = score_wallet_risk(store, eid, BTC_VALID, hit=hit, service_tags=[])

    assert risk["risk_score"] == 80
    assert risk["risk_level"] == CRITICAL
    assert risk["risk_categories"] == ["SANCTIONS"]
    assert len(risk["risk_contributions"]) == 1
    assert risk["risk_contributions"][0]["rule_id"] == "sanctions.self_designation.v1"
    assert reconstruct_score(risk) == 80


# --- remove-one-signal: the mixing tag's own delta ---------------------------

def test_remove_one_signal_mixing_delta_matches_its_own_rule(tmp_path):
    """score(with mixing tag) - score(without) must equal exactly
    service.mixing.v1's base contribution -- proves the explanation is not
    decorative (Loop 36's mandatory 'remove one signal' test)."""
    mixing_tag = [{"entity_id": "ent_mixer", "value": "mixeraddr", "hop": 1,
                   "category": "mixing_service", "label": "Test Mixer",
                   "attribution": TAG_ATTESTED,
                   "attribution_source": "GraphSense tagpack: test",
                   "evidence_ids": []}]
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        eid = _wallet(store)
        hit = _at_vasp_self_designation(eid, BTC_VALID)
        with_mixing = score_wallet_risk(store, eid, BTC_VALID, hit=hit,
                                        service_tags=mixing_tag)
        without_mixing = score_wallet_risk(store, eid, BTC_VALID, hit=hit,
                                           service_tags=[])

    delta = with_mixing["risk_score"] - without_mixing["risk_score"]
    assert delta == 12  # service.mixing.v1's base, confidence 1.0, well under its cap
    assert with_mixing["risk_categories"] == ["MIXING", "SANCTIONS"]


# --- source-strength difference ----------------------------------------------

def test_source_strength_difference_is_policy_visible_not_just_different_numbers(tmp_path):
    """A regulatory (OFAC) finding and a third-party (Elliptic++) finding must
    differ in BOTH their numeric weight and their declared source_strength --
    the policy documenting *why* they differ, not merely producing different
    numbers by accident."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        reg_eid = _wallet(store, address=BTC_VALID)
        reg_hit = _at_vasp_self_designation(reg_eid, BTC_VALID)
        regulatory = score_wallet_risk(store, reg_eid, BTC_VALID, hit=reg_hit,
                                       service_tags=[])

        other_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        third_eid = _wallet(store, address=other_addr,
                            metadata={"ellipticpp_dataset_label_name": "illicit"})
        third_party = score_wallet_risk(store, third_eid, other_addr, hit=None,
                                        service_tags=[])

    reg_c = regulatory["risk_contributions"][0]
    tp_c = third_party["risk_contributions"][0]
    assert reg_c["source_strength"] == "REGULATORY_AUTHORITATIVE"
    assert tp_c["source_strength"] == "THIRD_PARTY_ATTRIBUTION"
    assert regulatory["risk_score"] > third_party["risk_score"]
    assert regulatory["risk_score"] == 80
    assert third_party["risk_score"] == 8


# --- repetition / deduplication ----------------------------------------------

def test_repeated_tagpack_hits_on_the_same_address_do_not_double_count(tmp_path):
    """Two different GraphSense packs both tagging the SAME address the SAME
    category are one underlying fact ('this address is a tagged mixer'), not
    two independent risk signals -- global invariant 12."""
    duplicate_hits = [
        {"entity_id": "ent_mixer", "value": "mixeraddr", "hop": 1,
         "category": "mixing_service", "label": "Samourai",
         "attribution": TAG_ATTESTED,
         "attribution_source": "GraphSense tagpack: pack_a", "evidence_ids": []},
        {"entity_id": "ent_mixer", "value": "mixeraddr", "hop": 1,
         "category": "mixing_service", "label": "Wasabi",
         "attribution": TAG_ATTESTED,
         "attribution_source": "GraphSense tagpack: pack_b", "evidence_ids": []},
    ]
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        eid = _wallet(store)
        risk = score_wallet_risk(store, eid, BTC_VALID, hit=None,
                                 service_tags=duplicate_hits)

    assert risk["risk_score"] == 12          # one occurrence, not 24
    assert len(risk["risk_contributions"]) == 1


def test_distinct_addresses_each_still_count_up_to_the_category_cap(tmp_path):
    """Unlike same-address repetition, two DIFFERENT mixer addresses on one
    path are genuinely independent facts -- both count, capped by
    CATEGORY_CAP[MIXING], not by an artificial single-fact limit."""
    two_distinct = [
        {"entity_id": "ent_mixer_a", "value": "addrA", "hop": 1,
         "category": "mixing_service", "label": "Mixer A", "attribution": TAG_ATTESTED,
         "attribution_source": "GraphSense tagpack: pack_a", "evidence_ids": []},
        {"entity_id": "ent_mixer_b", "value": "addrB", "hop": 2,
         "category": "mixing_service", "label": "Mixer B", "attribution": TAG_ATTESTED,
         "attribution_source": "GraphSense tagpack: pack_b", "evidence_ids": []},
    ]
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        eid = _wallet(store)
        risk = score_wallet_risk(store, eid, BTC_VALID, hit=None,
                                 service_tags=two_distinct)

    assert risk["risk_score"] == 20          # 12 + 12 = 24, capped at MIXING's ceiling (20)
    assert len(risk["risk_contributions"]) == 2
    assert risk["risk_contributions"][0]["applied_amount"] + \
           risk["risk_contributions"][1]["applied_amount"] == 20


# --- overall is not the naive sum of wallet + flow ---------------------------

def test_overall_is_not_the_naive_sum_of_wallet_and_flow(tmp_path):
    """A self-designated wallet (WALLET-dimension SANCTIONS, 80) that ALSO
    directly transacts with a second, independently OFAC-designated entity
    (FLOW-dimension SANCTIONS, 40 * 0.75 hop-decay = 30): wallet_risk=80,
    flow_risk=30, naive sum=110 -- but overall_risk applies ONE SANCTIONS
    ceiling (90) across the union, giving 90, not 110. See risk.py's module
    docstring for why this is deliberate, not a bug."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        eid = _wallet(store)
        hit = _at_vasp_self_designation(eid, BTC_VALID)
        hit["direct_vasp_contacts"] = [{
            "peer_entity_id": "ent_other_designated", "exchange": "Other Sanctioned Entity",
            "attribution": REGULATORY_ATTESTED,
            "attribution_source": "OFAC SDN: profile 11111",
            "direction": TO_VASP, "evidence_ids": [],
        }]
        risk = score_wallet_risk(store, eid, BTC_VALID, hit=hit, service_tags=[])

    assert risk["wallet_risk"]["score"] == 80
    assert risk["flow_risk"]["score"] == 30
    assert risk["wallet_risk"]["score"] + risk["flow_risk"]["score"] == 110
    assert risk["risk_score"] == 90                     # capped, not 110
    assert risk["risk_score"] != risk["wallet_risk"]["score"] + risk["flow_risk"]["score"]
    assert reconstruct_score(risk) == 90


# --- "why" reconstruction ------------------------------------------------

def test_reasons_are_generated_from_contributions_not_hardcoded(tmp_path):
    """Every risk_reasons line must trace to a risk_contributions entry --
    the mandatory 'why' test: an investigator can recompute the total from
    risk_reasons/risk_contributions alone, with no access to risk.py."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        eid = _wallet(store)
        hit = _at_vasp_self_designation(eid, BTC_VALID)
        risk = score_wallet_risk(store, eid, BTC_VALID, hit=hit, service_tags=[])

    assert any("sanctions.self_designation.v1" in reason for reason in risk["risk_reasons"])
    assert any(str(risk["risk_score"]) in reason for reason in risk["risk_reasons"])
    assert reconstruct_score(risk) == risk["risk_score"]


# --- real-data verification --------------------------------------------------

def _skip_unless_real_sources_available():
    from cybertrace.integrations import exchange_tags, ofac
    if not (ofac.available() and ofac.index_available()):
        pytest.skip("OFAC SDN not downloaded/indexed in this checkout")
    if not (exchange_tags.available() and exchange_tags.index_available()):
        pytest.skip("GraphSense TagPacks not downloaded/indexed in this checkout")


# Real OFAC SDN ground truth, profile 33858: Yevgeniy Igorevich Polyanin,
# sanctioned 2021-11-08 (E.O. 13694, Sodinokibi/REvil ransomware-as-a-service).
# Same address/history used by test_correlate.py's own real-data fixtures.
OFAC_POLYANIN = "158treVZBGMBThoaympxccPdZPtqUfYrT9"
OFAC_POLYANIN_REAL_SENT_TO = [
    "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s",  # Binance hot wallet (GraphSense-tagged)
    "32aYQCHHAdRZGyxX5ZqJtr3FEmQPnhvmvC", "38u7Gu2GsEEUhQDwzqHLkEA6NQuu7HrdAC",
    "3AAXYnRdcrN56tgDVbDsrFHbhK2A9QE1s5", "3Dj75bpjUVd4J7bnYnEqzS9YUtxtsfJmjg",
    "3KUkjNLuwH4WaN5u8v5xkT8uQfiuv7J3kV", "3LGyKfGNQ62CiKrhDLbMS1hrixzYGTxuK4",
    "3PrUCKdZUP2LsrUUaD16BM54kj2gNkcnyr", "3QCqAMWK51iwTGRipZVQWGrBiQPihmU2a9",
]


def test_real_data_case_a_regulatory_sanctions_signal_alone(tmp_path):
    """Case A (Loop 36 real-data verification): a real OFAC-designated
    ransomware operator's own wallet, self-attributed -- must score CRITICAL
    from the designation alone, and the score must audit exactly."""
    _skip_unless_real_sources_available()
    with EvidenceStore(str(tmp_path / "polyanin.db")) as store:
        eid = store.upsert_entity("BTC_ADDRESS", OFAC_POLYANIN)
        sid = store.insert_snapshot(store.upsert_target("btc:" + OFAC_POLYANIN), {}, "bitcoin")
        enrich_bitcoin(store, sid, eid, {
            "address": OFAC_POLYANIN, "sent_to_addresses": OFAC_POLYANIN_REAL_SENT_TO,
            "tx_sample_size": 19,
        }, "bitcoin")

        report = wallet_trace_report(store, OFAC_POLYANIN)

    risk = report["risk"]
    assert risk["risk_score"] == 80
    assert risk["risk_level"] == CRITICAL
    assert risk["risk_categories"] == ["SANCTIONS"]
    assert reconstruct_score(risk) == 80
    # The real Binance deposits are TAG_ATTESTED, not REGULATORY_ATTESTED --
    # must not silently add a second SANCTIONS contribution.
    assert len(risk["risk_contributions"]) == 1


def test_real_data_case_b_graphsense_service_signal_alone(tmp_path):
    """Case B: a wallet with no VASP/OFAC path at all, only a real
    GraphSense-tagged CoinJoin hop on its way to an (unrelated,
    TAG_ATTESTED-only) exchange -- must stay LOW, never INSUFFICIENT_EVIDENCE
    (a real signal exists) and never HIGH (contextual alone)."""
    _skip_unless_real_sources_available()
    coinjoin_addr = "bc1qnfu52l5vgg0gf2hw98epfvupveepnq7tg5l75h"  # samourai: coinjoin
    binance = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"                 # category=exchange
    with EvidenceStore(str(tmp_path / "coinjoin.db")) as store:
        suspect = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        sid1 = store.insert_snapshot(store.upsert_target("btc:" + BTC_VALID), {}, "bitcoin")
        enrich_bitcoin(store, sid1, suspect,
                       {"address": BTC_VALID, "sent_to_addresses": [coinjoin_addr]}, "bitcoin")
        coinjoin_id = store.find_entity("BTC_ADDRESS", coinjoin_addr)
        sid2 = store.insert_snapshot(store.upsert_target("btc:" + coinjoin_addr), {}, "bitcoin")
        enrich_bitcoin(store, sid2, coinjoin_id,
                       {"address": coinjoin_addr, "sent_to_addresses": [binance]}, "bitcoin")

        report = wallet_trace_report(store, BTC_VALID)

    risk = report["risk"]
    assert risk["risk_score"] == 8
    assert risk["risk_level"] == LOW
    assert risk["risk_categories"] == ["COINJOIN"]
    assert reconstruct_score(risk) == 8


def test_real_data_case_c_combined_regulatory_and_service_signals(tmp_path):
    """Case C: Blender.io is real ground truth for BOTH datasets on the SAME
    address at once (OFAC SDN + GraphSense mixing_service) -- proves the two
    signals combine without either corrupting the other, and the combined
    score audits exactly by hand: sanctions.flow_reach.v1 (40 * 0.75 hop
    decay = 30) + service.mixing.v1 (12) = 42, MODERATE."""
    _skip_unless_real_sources_available()
    blender = "3NDzzVxiLBUs1WPvVGRfCYDTAD2Ua2PvW4"  # OFAC: Blender.io; GraphSense: mixing_service
    with EvidenceStore(str(tmp_path / "blender.db")) as store:
        suspect = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        sid = store.insert_snapshot(store.upsert_target("btc:" + BTC_VALID), {}, "bitcoin")
        enrich_bitcoin(store, sid, suspect,
                       {"address": BTC_VALID, "sent_to_addresses": [blender]}, "bitcoin")

        report = wallet_trace_report(store, BTC_VALID)

    # Pre-existing VASP/proximity behavior, byte-for-byte unchanged by this loop.
    assert report["exchange"] == "Blender.io"
    assert report["attribution"] == REGULATORY_ATTESTED
    assert report["proximity"] == DIRECT

    risk = report["risk"]
    assert risk["risk_categories"] == ["MIXING", "SANCTIONS"]
    by_rule = {c["rule_id"]: c["applied_amount"] for c in risk["risk_contributions"]}
    assert by_rule["sanctions.flow_reach.v1"] == 30
    assert by_rule["service.mixing.v1"] == 12
    assert risk["risk_score"] == 42
    assert risk["risk_level"] == MODERATE
    assert reconstruct_score(risk) == 42
