"""Loop 50 tests: case-level VASP relationship aggregation
(cybertrace.vasp_investigation.aggregate_vasp_relationships).

Not another attribution engine and not a re-test of Loop 45/48/49's own
policy (see test_attribution.py / test_vasp_investigation.py for that) --
this module tests exactly one thing: that grouping already-computed
per-wallet `investigate()` results by VASP brand name never turns "these
wallets both touched the same VASP" into "these wallets share an owner",
never drops the exposure/control distinction, and never inflates evidence.

Two layers, same split test_vasp_investigation.py uses: fast synthetic-`vi`
unit tests (no store) for every adversarial invariant from docs/LOOP50.md
section 21/24, plus one real-store integration test mirroring
test_run_correlation_attaches_vasp_investigation_to_every_wallet_row that
proves run_correlation()/render_markdown()/render_dossier_html() all consume
the same canonical `results["vasp_relationships"]`.
"""

from __future__ import annotations

import cybertrace.vasp_investigation as vca
from cybertrace.correlate import render_dossier_html, render_markdown, run_correlation
from cybertrace.evidence import EvidenceStore, enrich_bitcoin, label_exchange

from .test_correlate import BTC_OTHER
from .test_evidence import BTC_VALID


def _hit(exchange, attribution, proximity, hops=0, contacts=None, also_attributed=None):
    contacts = contacts or {}
    return {
        "exchange": exchange, "attribution": attribution, "attribution_source": "test",
        "proximity": proximity, "hops": hops,
        "direct_vasp_contacts": contacts.get("direct", []),
        "secondary_vasp_contacts": contacts.get("secondary", []),
        "also_attributed": also_attributed or [],
    }


def _row(wallet_id, vi, chain="BTC_ADDRESS"):
    return {"value": wallet_id, "chain": chain, "entity_id": wallet_id, "vasp_investigation": vi}


def _all_wallets(relationships):
    return [w for rel in relationships for w in rel["wallets"]]


# --- Test 1: two wallets share a VASP -- never wallet-to-wallet attribution -

def test_1_two_wallets_sharing_a_vasp_are_never_read_as_the_same_actor():
    vi_a = vca.investigate(None, "A", "BTC_ADDRESS",
                          hit=_hit("Binance", vca.TAG_ATTESTED, vca.DIRECT, hops=1))
    vi_b = vca.investigate(None, "B", "BTC_ADDRESS",
                          hit=_hit("Binance", vca.TAG_ATTESTED, vca.DIRECT, hops=1))
    rels = vca.aggregate_vasp_relationships([_row("A", vi_a), _row("B", vi_b)], [])

    assert len(rels) == 1
    assert rels[0]["vasp"] == "Binance"
    wallet_ids = {w["entity_id"] for w in rels[0]["wallets"]}
    assert wallet_ids == {"A", "B"}, "shared VASP exposure must list distinct wallets"

    dumped = str(rels)
    for forbidden in ("same_actor", "same_owner", "common_owner", "related_wallets", "same_entity"):
        assert forbidden not in dumped


# --- Test 2: direct + indirect stay distinguishable, never collapsed -------

def test_2_direct_and_indirect_exposure_are_never_collapsed_into_one_label():
    vi_a = vca.investigate(None, "A", "BTC_ADDRESS",
                          hit=_hit("Binance", vca.TAG_ATTESTED, vca.DIRECT, hops=1))
    vi_b = vca.investigate(None, "B", "BTC_ADDRESS",
                          hit=_hit("Binance", vca.TAG_ATTESTED, vca.INDIRECT, hops=2))
    rels = vca.aggregate_vasp_relationships([_row("A", vi_a), _row("B", vi_b)], [])

    assert len(rels) == 1
    by_wallet = {w["entity_id"]: w for w in rels[0]["wallets"]}
    assert by_wallet["A"]["relationship_type"] == vca.DIRECT_EXPOSURE
    assert by_wallet["B"]["relationship_type"] == vca.INDIRECT_EXPOSURE
    assert rels[0]["direct_exposure_count"] == 1
    assert rels[0]["indirect_exposure_count"] == 1


# --- Test 3: a customer address vs. the VASP's own disclosed address -------

def test_3_a_customer_and_a_vasp_disclosed_address_keep_distinct_control_status():
    vi_customer = vca.investigate(None, "CUSTOMER", "BTC_ADDRESS",
                                 hit=_hit("Binance", vca.TAG_ATTESTED, vca.DIRECT, hops=1))
    vi_vasp_owned = vca.investigate(None, "VASP_OWNED", "BTC_ADDRESS",
                                   hit=_hit("Binance", vca.VASP_DISCLOSED, vca.AT_VASP, hops=0))
    rels = vca.aggregate_vasp_relationships(
        [_row("CUSTOMER", vi_customer), _row("VASP_OWNED", vi_vasp_owned)], [])

    assert len(rels) == 1
    by_wallet = {w["entity_id"]: w for w in rels[0]["wallets"]}
    assert by_wallet["CUSTOMER"]["control_status"] == vca.NOT_ESTABLISHED
    assert by_wallet["VASP_OWNED"]["control_status"] == vca.ESTABLISHED
    assert rels[0]["control_established_count"] == 1
    assert rels[0]["wallet_count"] == 2


# --- Test 4: OFAC designation + VASP exposure stay separate claims ---------

def test_4_ofac_designated_wallet_reaching_a_vasp_keeps_regulatory_and_exposure_separate():
    hit = _hit("SUEX OTC S.R.O.", vca.REGULATORY_ATTESTED, vca.AT_VASP, hops=0,
              contacts={"direct": [{"exchange": "Binance", "attribution": vca.TAG_ATTESTED,
                                    "attribution_source": "tag", "hops": 1}]})
    vi = vca.investigate(None, "OFAC_WALLET", "BTC_ADDRESS", hit=hit)
    rels = vca.aggregate_vasp_relationships([_row("OFAC_WALLET", vi)], [])

    assert len(rels) == 1 and rels[0]["vasp"] == "Binance"
    w = rels[0]["wallets"][0]
    assert w["regulatory_context"]["designated"] is True
    assert w["regulatory_context"]["entity"] == "SUEX OTC S.R.O."
    assert w["control_status"] == vca.NOT_ESTABLISHED


# --- Test 5: one wallet, multiple VASPs -- not automatic ambiguity ---------

def test_5_one_wallet_touching_multiple_vasps_produces_two_relationships_not_ambiguity():
    hit = _hit("Binance", vca.TAG_ATTESTED, vca.DIRECT, hops=1,
              contacts={"direct": [{"exchange": "BitMEX", "attribution": vca.TAG_ATTESTED,
                                    "attribution_source": "tag", "hops": 1}]})
    vi = vca.investigate(None, "A", "BTC_ADDRESS", hit=hit)
    rels = vca.aggregate_vasp_relationships([_row("A", vi)], [])

    names = {rel["vasp"] for rel in rels}
    assert names == {"Binance", "BitMEX"}
    for rel in rels:
        assert rel["wallet_count"] == 1
        assert rel["wallets"][0]["entity_id"] == "A"


# --- Test 6: evidence is never inflated by aggregation ---------------------

def test_6_case_level_aggregation_never_inflates_evidence_beyond_the_wallet_level_result():
    """The case-level VASP entry must never carry a flattened, summed
    evidence pool -- only per-wallet counts (wallet_count/direct/indirect/
    candidate/control_established), with each wallet's own evidence kept
    exactly as investigate() produced it, never re-resolved or merged with
    another wallet's."""
    vi_a = vca.investigate(None, "A", "BTC_ADDRESS",
                          hit=_hit("Binance", vca.TAG_ATTESTED, vca.DIRECT, hops=1))
    vi_b = vca.investigate(None, "B", "BTC_ADDRESS",
                          hit=_hit("Binance", vca.TAG_ATTESTED, vca.DIRECT, hops=1))
    rels = vca.aggregate_vasp_relationships([_row("A", vi_a), _row("B", vi_b)], [])

    rel = rels[0]
    assert set(rel.keys()) == {
        "policy_version", "vasp", "wallet_count", "direct_exposure_count",
        "indirect_exposure_count", "candidate_exposure_count",
        "control_established_count", "wallets",
    }
    by_wallet = {w["entity_id"]: w for w in rel["wallets"]}
    assert by_wallet["A"]["evidence"] == vi_a["evidence"]
    assert by_wallet["B"]["evidence"] == vi_b["evidence"]


# --- Test 7: cross-chain evidence stays with its own wallet/VASP -----------

def test_7_cross_chain_evidence_stays_associated_with_its_own_wallet_never_double_counted():
    candidate = {
        "policy_version": "attribution-v1", "primary_candidate": "Binance",
        "status": "CANDIDATE", "strength": vca.MEDIUM, "also_attributed": [],
        "contradicting_signals": [], "behavioral_note": None, "fingerprint": {},
        "supporting_signals": [
            {"rule_id": "attribution.cross_chain_corroboration.v1", "brand": "Binance",
             "attribution": vca.TAG_ATTESTED, "attribution_source": "tag",
             "peer_chain": "ETH_ADDRESS", "peer_address": "0xabc",
             "evidence_ref": "bridge-1", "detail": "cross-chain corroboration",
             "evidence_ids": []},
        ],
    }
    vi = vca.investigate(None, "A", "BTC_ADDRESS", candidate=candidate)
    rels = vca.aggregate_vasp_relationships([], [_row("A", vi)])

    assert len(rels) == 1 and rels[0]["wallet_count"] == 1
    w = rels[0]["wallets"][0]
    assert w["entity_id"] == "A"
    assert w["relationship_type"] == vca.CANDIDATE_EXPOSURE
    assert len(w["evidence"]) == 1  # one signal, one evidence item -- not duplicated


# --- Test 8: no VASP relationships at all -----------------------------------

def test_8_no_vasp_evidence_anywhere_produces_no_fabricated_relationship():
    vi = vca.investigate(None, "A", "BTC_ADDRESS")
    assert vca.aggregate_vasp_relationships([_row("A", vi)], []) == []
    assert vca.aggregate_vasp_relationships([], []) == []


# --- Test 9: independent wallet correlation stays a separate fact ----------

def test_9_shared_vasp_exposure_never_merges_with_an_independent_wallet_correlation():
    """Even when two wallets are independently known to be related (a
    cospend cluster, a successor edge -- any fact this codebase's other
    engines already establish), the VASP-relationship aggregator must not
    read their shared VASP exposure as further proof of that relationship,
    or invent a combined identity for them. It only ever groups by VASP
    brand name, so two distinct wallet ids remain two distinct entries no
    matter what else is true about them elsewhere in the case."""
    vi_a = vca.investigate(None, "A", "BTC_ADDRESS",
                          hit=_hit("Binance", vca.TAG_ATTESTED, vca.DIRECT, hops=1))
    vi_b = vca.investigate(None, "B", "BTC_ADDRESS",
                          hit=_hit("Binance", vca.TAG_ATTESTED, vca.DIRECT, hops=1))
    # Simulate "A and B are already independently correlated" (e.g. a real
    # cospend/successor fact) purely as a fact ABOUT the two wallet ids the
    # aggregator receives -- it takes no such input at all, so it cannot act
    # on it even here.
    rels = vca.aggregate_vasp_relationships([_row("A", vi_a), _row("B", vi_b)], [])
    assert {w["entity_id"] for w in rels[0]["wallets"]} == {"A", "B"}
    assert not any("correlated" in w or "cluster" in w for w in rels[0]["wallets"])


# --- Regression: production wiring --------------------------------------

def test_run_correlation_attaches_vasp_relationships_and_renderers_agree(tmp_path):
    """Real-store sibling of test_run_correlation_attaches_vasp_investigation_
    to_every_wallet_row: one wallet directly reaching a labeled exchange
    (exposure only) and the labeled exchange address itself (control
    established) must both surface in results['vasp_relationships'], and
    Markdown/HTML must render the same counts run_correlation computed --
    never a second, independently reconstructed case-level view."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        target = store.upsert_target("btc:" + BTC_VALID)
        sid = store.insert_snapshot(target, {}, "bitcoin")
        enrich_bitcoin(store, sid, addr,
                       {"address": BTC_VALID, "counterparty_addresses": [BTC_OTHER]}, "bitcoin")
        assert label_exchange(store, BTC_OTHER, "Test Exchange") is not None

        results = run_correlation(store)
        rels = results["vasp_relationships"]
        assert rels, "expected at least one case-level VASP relationship"
        rel = next(r for r in rels if r["vasp"] == "test exchange")
        assert rel["wallet_count"] == 2
        assert rel["control_established_count"] == 1
        by_wallet = {w["wallet"]: w for w in rel["wallets"]}
        assert by_wallet[BTC_VALID]["control_status"] == "NOT_ESTABLISHED"
        assert by_wallet[BTC_OTHER]["control_status"] == "ESTABLISHED"

        md = render_markdown(results["dossiers"], results)
        assert "## VASP Relationships" in md
        assert "test exchange" in md

        out = tmp_path / "case.html"
        render_dossier_html(results, str(out))
        html = out.read_text()
        assert "VASP Relationships" in html
        assert "test exchange" in html
