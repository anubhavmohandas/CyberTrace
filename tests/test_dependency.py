"""Loop 49 (RESEARCH_LOOP49.md): upstream-dependency resolution over the
4-tier VASP attribution evidence.

Two layers, both real:

  unit          resolve_*/independent_evidence_count are pure functions --
                no store, no corpus, always run.

  real-corpus   the actual case RESEARCH_LOOP48.md Sec.3 found: the Bitfinex
                and BitMEX cold/reserve wallets are tagged BOTH TAG_ATTESTED
                (a GraphSense exchange-wallets-* pack, category='exchange')
                AND VASP_DISCLOSED (the same address matches
                exchange_tags._VASP_DISCLOSED_SOURCES) -- the exact "two
                tiers, one document" collision this module exists to name.
                Skips (not fails) when the local corpus isn't downloaded,
                same convention as tests/test_correlate.py.
"""

from __future__ import annotations

import pytest

from cybertrace import dependency
from cybertrace.correlate import REGULATORY_ATTESTED, TAG_ATTESTED, VASP_DISCLOSED, wallet_exchange_paths
from cybertrace.evidence import EvidenceStore, enrich_bitcoin

from .test_evidence import BTC_VALID

# Same real ground-truth addresses tests/test_correlate.py already pins.
BITFINEX_COLD = "3JZq4atUahhuA9rLhXLMhhTo133J9rF97j"
BITMEX_RESERVE = "3BMEXbSSrK2K7cRgqxrtqUWfxowBBrW1BE"
BINANCE_HOT = "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s"
OFAC_POLYANIN = "158treVZBGMBThoaympxccPdZPtqUfYrT9"


# --- unit: pure functions, no corpus needed ---------------------------------

def test_bitmex_packs_collapse_to_one_upstream():
    groups = {dependency.resolve_tag_upstream(f"exchange-wallets-bitmex_{i}") for i in range(7)}
    assert groups == {"vasp_disclosure:BitMEX"}


def test_tag_and_disclosure_tiers_agree_on_the_same_brand():
    assert (dependency.resolve_tag_upstream("exchange-wallets-bitfinexcom")
            == dependency.resolve_disclosure_upstream("Bitfinex"))


def test_ofac_pack_and_direct_pull_share_one_upstream():
    assert dependency.resolve_tag_upstream("ofac") == dependency.resolve_regulatory_upstream()


def test_unknown_pack_defaults_to_its_own_independent_upstream():
    assert dependency.resolve_tag_upstream("some-future-pack") == "tagpack:some-future-pack"
    assert dependency.resolve_tag_upstream("some-future-pack") != dependency.resolve_tag_upstream("ofac")


def test_different_brands_are_different_upstreams():
    assert (dependency.resolve_disclosure_upstream("Bitfinex")
            != dependency.resolve_disclosure_upstream("BitMEX"))


def test_independent_evidence_count_dedupes_shared_upstream():
    assert dependency.independent_evidence_count(["a", "a", "b"]) == 2
    assert dependency.independent_evidence_count(["a", "a"]) == 1
    assert dependency.independent_evidence_count([]) == 0


# --- real corpus -------------------------------------------------------------

def _require_corpus():
    from cybertrace.integrations import exchange_tags, ofac
    if not (exchange_tags.available() and exchange_tags.index_available()):
        pytest.skip("GraphSense TagPacks not downloaded/indexed in this checkout")
    if not (ofac.available() and ofac.index_available()):
        pytest.skip("OFAC SDN not downloaded/indexed in this checkout")


def _one_hit(tmp_path, target_addr):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        sid = store.insert_snapshot(store.upsert_target("btc:" + BTC_VALID), {}, "bitcoin")
        enrich_bitcoin(store, sid, addr,
                       {"address": BTC_VALID, "sent_to_addresses": [target_addr]}, "bitcoin")
        return next(w for w in wallet_exchange_paths(store) if w["entity_id"] == addr)


def test_bitfinex_cold_wallet_is_one_independent_source_not_two(tmp_path):
    """RESEARCH_LOOP48.md Sec.3's real collision: this address is TAG_ATTESTED
    (exchange-wallets-bitfinexcom) AND VASP_DISCLOSED (github.com/bitfinexcom)
    -- one first-party disclosure, republished under two tiers. Before this
    module, nothing recorded that; naive corroboration counting would have
    read this as 2 agreeing sources."""
    _require_corpus()
    from cybertrace.integrations import exchange_tags
    if not exchange_tags.exchange_labels({"BTC": [BITFINEX_COLD]}):
        pytest.skip("fixture address no longer TAG_ATTESTED in this corpus")
    hit = _one_hit(tmp_path, BITFINEX_COLD)
    assert hit["attribution"] == VASP_DISCLOSED
    assert hit["dependency_groups"] == ["vasp_disclosure:Bitfinex"]
    assert hit["independent_evidence_count"] == 1


def test_bitmex_reserve_wallet_is_one_independent_source_not_two(tmp_path):
    """Same collision, the 336,208-row population (RESEARCH_LOOP48.md Sec.4)."""
    _require_corpus()
    hit = _one_hit(tmp_path, BITMEX_RESERVE)
    assert hit["attribution"] == VASP_DISCLOSED
    assert hit["dependency_groups"] == ["vasp_disclosure:BitMEX"]
    assert hit["independent_evidence_count"] == 1


def test_tag_attested_only_address_is_one_independent_source(tmp_path):
    _require_corpus()
    hit = _one_hit(tmp_path, BINANCE_HOT)
    assert hit["attribution"] == TAG_ATTESTED
    assert hit["independent_evidence_count"] == 1
    assert len(hit["dependency_groups"]) == 1


def test_ofac_only_address_is_one_independent_source(tmp_path):
    _require_corpus()
    hit = _one_hit(tmp_path, OFAC_POLYANIN)
    assert hit["attribution"] == REGULATORY_ATTESTED
    assert hit["dependency_groups"] == ["us_ofac_sdn"]
    assert hit["independent_evidence_count"] == 1


def test_concentration_report_reproduces_the_measured_finding():
    """RESEARCH_LOOP48.md Sec.4, programmatically: >=99% of the local
    category='exchange' corpus traces to one upstream. Thresholded rather
    than pinned to the exact 99.5%, since a corpus refresh can shift the
    decimal without changing the finding."""
    _require_corpus()
    report = dependency.concentration_report()
    assert report["total_rows"] > 0
    assert report["top_source"]["pct"] >= 99.0
    assert report["top_upstream"]["pct"] >= 99.0
