"""Unknown-wallet VASP attribution (Loop 45): explainability and policy tests.

Same two-layer split as test_risk.py:

- Unit tests drive attribution.vasp_candidates/wallet_fingerprint directly
  with hand-built peers/exchange_of/values, isolating the scoring policy
  from correlate's BFS/adjacency machinery -- fast, deterministic, no
  external data required.
- Real-data tests run the actual pipeline against real GraphSense/OFAC
  ground truth already used elsewhere in this suite (test_correlate.py's
  OFAC_POLYANIN/BINANCE_HOT fixtures), skip-guarded the same way those
  tests are.
"""

from __future__ import annotations

from cybertrace.attribution import (
    ATTRIBUTION_POLICY_VERSION, CANDIDATE, CORROBORATED, vasp_candidates,
    wallet_fingerprint,
)
from cybertrace.correlate import (
    REGULATORY_ATTESTED, TAG_ATTESTED, VASP_DISCLOSED,
    unattributed_wallet_candidates, wallet_exchange_paths, wallet_trace_report,
)
from cybertrace.evidence import EvidenceStore

from .test_correlate import (
    BINANCE_HOT, OFAC_POLYANIN, OFAC_POLYANIN_REAL_SENT_TO,
    _skip_unless_real_sources_available, _synth_btc, _traced,
)

BINANCE_ADDR = _synth_btc("attribution-binance")
BYBIT_ADDR = _synth_btc("attribution-bybit")
UNKNOWN_ADDR = _synth_btc("attribution-unknown")


def _wallet(store, address, etype="BTC_ADDRESS"):
    return store.upsert_entity(etype, address)


def _hit(brand, attribution=TAG_ATTESTED, source="test"):
    return {"exchange": brand, "attribution": attribution,
            "attribution_source": source, "evidence_ids": []}


# --- no signal -----------------------------------------------------------

def test_no_signal_returns_no_candidate(tmp_path):
    """Zero peers, zero cross-chain evidence: never a forced answer (section
    M) -- matches risk.py's own INSUFFICIENT_EVIDENCE discipline."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        result = vasp_candidates(store, unknown, UNKNOWN_ADDR, "BTC_ADDRESS",
                                 peers={}, exchange_of={}, values={})

    assert result["primary_candidate"] is None
    assert result["also_attributed"] == []
    assert result["status"] is None
    assert result["strength"] is None
    assert result["policy_version"] == ATTRIBUTION_POLICY_VERSION


# --- single signal -> CANDIDATE ---------------------------------------------

def test_single_counterparty_overlap_is_candidate_not_corroborated(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        peer = _wallet(store, BINANCE_ADDR)
        exchange_of = {peer: _hit("Binance")}
        values = {unknown: UNKNOWN_ADDR, peer: BINANCE_ADDR}
        result = vasp_candidates(store, unknown, UNKNOWN_ADDR, "BTC_ADDRESS",
                                 peers={peer: ([], {None})}, exchange_of=exchange_of,
                                 values=values)

    assert result["primary_candidate"] == "Binance"
    assert result["status"] == CANDIDATE
    assert result["strength"] == "LOW"
    assert result["also_attributed"] == []
    assert len(result["supporting_signals"]) == 1
    assert result["supporting_signals"][0]["rule_id"] == "attribution.counterparty_overlap.v1"


# --- multi-brand conflict preserved (section G) -----------------------------

def test_multi_brand_conflict_preserved_never_first_wins(tmp_path):
    """Two real, distinct brand signals on one wallet must BOTH surface --
    never silently collapsed to whichever peer's entity_id happens to sort
    first (the exact gap this module closes; see attribution.py's own module
    docstring)."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        binance_peer = _wallet(store, BINANCE_ADDR)
        bybit_peer = _wallet(store, BYBIT_ADDR)
        exchange_of = {binance_peer: _hit("Binance"), bybit_peer: _hit("Bybit")}
        values = {unknown: UNKNOWN_ADDR, binance_peer: BINANCE_ADDR, bybit_peer: BYBIT_ADDR}
        peers = {binance_peer: ([], {None}), bybit_peer: ([], {None})}
        result = vasp_candidates(store, unknown, UNKNOWN_ADDR, "BTC_ADDRESS",
                                 peers=peers, exchange_of=exchange_of, values=values)

    brands = {result["primary_candidate"]} | {c["brand"] for c in result["also_attributed"]}
    assert brands == {"Binance", "Bybit"}
    assert len(result["also_attributed"]) == 1
    assert result["contradicting_signals"][0]["brand"] != result["primary_candidate"]


# --- OFAC is never VASP evidence (section A) --------------------------------

def test_regulatory_attested_peer_never_becomes_a_candidate(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        peer = _wallet(store, BINANCE_ADDR)
        exchange_of = {peer: _hit("Some Sanctioned Entity", attribution=REGULATORY_ATTESTED,
                                  source="OFAC SDN: profile 1")}
        values = {unknown: UNKNOWN_ADDR, peer: BINANCE_ADDR}
        result = vasp_candidates(store, unknown, UNKNOWN_ADDR, "BTC_ADDRESS",
                                 peers={peer: ([], {None})}, exchange_of=exchange_of,
                                 values=values)

    assert result["primary_candidate"] is None


# --- CORROBORATED requires two INDEPENDENT signal types ---------------------

def test_two_independent_signal_types_is_corroborated(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        peer = _wallet(store, BINANCE_ADDR)
        other_chain_peer = _wallet(store, "0x00000000000000000000000000000000000000aa",
                                   etype="ETH_ADDRESS")
        exchange_of = {peer: _hit("Binance"),
                      other_chain_peer: _hit("Binance", attribution=VASP_DISCLOSED,
                                             source="Binance self-disclosure")}
        values = {unknown: UNKNOWN_ADDR, peer: BINANCE_ADDR,
                 other_chain_peer: "0x00000000000000000000000000000000000000aa"}
        store.record_cross_chain_tx_link({
            "source_chain": "BTC_ADDRESS", "source_address": UNKNOWN_ADDR,
            "dest_chain": "ETH_ADDRESS",
            "dest_address": "0x00000000000000000000000000000000000000aa",
            "mechanism": "BRIDGE", "evidence_ref": "test-ref-1",
            "source_api": "wormholescan", "tx_timestamp": None, "status": "completed"})
        result = vasp_candidates(store, unknown, UNKNOWN_ADDR, "BTC_ADDRESS",
                                 peers={peer: ([], {None})}, exchange_of=exchange_of,
                                 values=values)

    assert result["primary_candidate"] == "Binance"
    assert result["status"] == CORROBORATED
    rule_ids = {s["rule_id"] for s in result["supporting_signals"]}
    assert rule_ids == {"attribution.counterparty_overlap.v1",
                        "attribution.cross_chain_corroboration.v1"}


def test_two_peers_same_signal_type_is_still_only_candidate(tmp_path):
    """Two counterparties of the SAME brand is more of the SAME kind of
    evidence, not two independent kinds -- CORROBORATED requires two
    DIFFERENT signal_types (section D/N), never just more volume of one."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        peer1 = _wallet(store, BINANCE_ADDR)
        peer2 = _wallet(store, _synth_btc("attribution-binance-2"))
        exchange_of = {peer1: _hit("Binance"), peer2: _hit("Binance")}
        values = {unknown: UNKNOWN_ADDR, peer1: BINANCE_ADDR,
                 peer2: _synth_btc("attribution-binance-2")}
        peers = {peer1: ([], {None}), peer2: ([], {None})}
        result = vasp_candidates(store, unknown, UNKNOWN_ADDR, "BTC_ADDRESS",
                                 peers=peers, exchange_of=exchange_of, values=values)

    assert result["status"] == CANDIDATE
    assert result["primary_candidate"] == "Binance"


# --- tier multiplier: TAG_ATTESTED discounted vs VASP_DISCLOSED -------------

def test_tag_attested_signal_scores_lower_than_vasp_disclosed(tmp_path):
    def _run(attribution_tier):
        with EvidenceStore(str(tmp_path / f"e_{attribution_tier}.db")) as store:
            unknown = _wallet(store, UNKNOWN_ADDR)
            peer = _wallet(store, BINANCE_ADDR)
            exchange_of = {peer: _hit("Binance", attribution=attribution_tier)}
            values = {unknown: UNKNOWN_ADDR, peer: BINANCE_ADDR}
            return vasp_candidates(store, unknown, UNKNOWN_ADDR, "BTC_ADDRESS",
                                   peers={peer: ([], {None})}, exchange_of=exchange_of,
                                   values=values)

    tag = _run(TAG_ATTESTED)
    disclosed = _run(VASP_DISCLOSED)
    tag_amount = tag["supporting_signals"][0]["applied_amount"]
    disclosed_amount = disclosed["supporting_signals"][0]["applied_amount"]
    assert tag_amount < disclosed_amount


# --- behavioral context is contextual-only (section C.5/M) ------------------

def test_behavioral_note_never_creates_a_candidate_alone(tmp_path):
    """Consolidation-like flow with ZERO corroborating source must stay
    INSUFFICIENT_EVIDENCE (no candidate at all) -- the exact adversarial
    case section M names: 'high-volume personal wallet' must not be forced
    into a VASP answer just because it looks operationally busy."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        store.set_metadata(unknown, total_received=10.0, total_sent=1.0, tx_count=50)
        peers = {_wallet(store, _synth_btc(f"noise-{i}")): ([], {None}) for i in range(6)}
        result = vasp_candidates(store, unknown, UNKNOWN_ADDR, "BTC_ADDRESS",
                                 peers=peers, exchange_of={}, values={})

    assert result["behavioral_note"] is not None  # the pattern IS detected...
    assert result["primary_candidate"] is None    # ...but never promoted to a candidate


def test_behavioral_note_only_annotates_an_existing_real_candidate(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        store.set_metadata(unknown, total_received=10.0, total_sent=1.0, tx_count=50)
        binance_peer = _wallet(store, BINANCE_ADDR)
        noise_peers = {_wallet(store, _synth_btc(f"noise2-{i}")): ([], {None}) for i in range(5)}
        peers = {binance_peer: ([], {None}), **noise_peers}
        exchange_of = {binance_peer: _hit("Binance")}
        values = {unknown: UNKNOWN_ADDR, binance_peer: BINANCE_ADDR}
        result = vasp_candidates(store, unknown, UNKNOWN_ADDR, "BTC_ADDRESS",
                                 peers=peers, exchange_of=exchange_of, values=values)

    assert result["primary_candidate"] == "Binance"
    rule_ids = [s["rule_id"] for s in result["supporting_signals"]]
    assert "attribution.behavioral_context.v1" in rule_ids


# --- wallet_fingerprint ------------------------------------------------------

def test_fingerprint_is_unknown_not_zero_with_no_metadata(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        fp = wallet_fingerprint(store, unknown, counterparty_count=0)

    assert fp["tx_count"] is None
    assert fp["total_received"] is None
    assert fp["net_flow_ratio"] is None
    assert fp["avg_tx_value"] is None
    assert fp["counterparty_count"] == 0


def test_fingerprint_computes_net_flow_ratio_and_avg_tx_value(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        store.set_metadata(unknown, total_received=8.0, total_sent=2.0, tx_count=10)
        fp = wallet_fingerprint(store, unknown, counterparty_count=4)

    assert fp["net_flow_ratio"] == 0.8
    assert fp["avg_tx_value"] == 1.0
    assert fp["counterparty_count"] == 4


def test_fingerprint_counterparty_count_computed_when_not_provided(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        unknown = _wallet(store, UNKNOWN_ADDR)
        peer = _wallet(store, BINANCE_ADDR)
        obs = store.insert_observation(
            store.insert_snapshot(store.upsert_target("http://t"), {}, "test"),
            peer, method="test")
        rel = store.upsert_relationship(unknown, peer, "TRANSACTED_WITH", source_label="test")
        store.add_evidence(rel, [obs])
        fp = wallet_fingerprint(store, unknown)

    assert fp["counterparty_count"] == 1


# --- correlate.unattributed_wallet_candidates -------------------------------

def test_unattributed_wallet_candidates_skips_already_reachable_wallets(tmp_path):
    """A wallet WITH a wallet_exchange_paths hit must never also appear in
    unattributed_wallet_candidates -- the two lists are mutually exclusive
    by construction (see correlate.unattributed_wallet_candidates' own
    docstring)."""
    _skip_unless_real_sources_available()
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        suspect = _traced(store, OFAC_POLYANIN, {
            "sent_to_addresses": OFAC_POLYANIN_REAL_SENT_TO,
            "tx_sample_size": len(OFAC_POLYANIN_REAL_SENT_TO) + 1})
        reachable_ids = {w["entity_id"] for w in wallet_exchange_paths(store)}
        candidate_ids = {w["entity_id"] for w in unattributed_wallet_candidates(store)}

    assert suspect in reachable_ids       # OFAC_POLYANIN is AT_VASP on himself
    assert suspect not in candidate_ids   # so never also a fingerprint candidate
    assert reachable_ids.isdisjoint(candidate_ids)


def test_wallet_trace_report_vasp_candidates_is_none_when_there_is_a_hit(tmp_path):
    _skip_unless_real_sources_available()
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _traced(store, OFAC_POLYANIN, {
            "sent_to_addresses": OFAC_POLYANIN_REAL_SENT_TO,
            "tx_sample_size": len(OFAC_POLYANIN_REAL_SENT_TO) + 1})
        report = wallet_trace_report(store, OFAC_POLYANIN, chain="bitcoin")

    assert report["exchange"] is not None
    assert report["vasp_candidates"] is None


def test_wallet_trace_report_surfaces_candidates_for_a_wallet_with_no_hit(tmp_path):
    """A wallet with a real cross-chain bridge/swap link to BINANCE_HOT (real,
    independently GraphSense-tagged) on a DIFFERENT chain, and no same-chain
    counterparty at all -- wallet_exchange_paths' BFS never consults
    cross_chain_tx_links (it only walks same-chain TRANSACTED_WITH/
    SENT_FUNDS_TO/PART_OF_CLUSTER edges), so it finds nothing for this
    wallet; attribution.vasp_candidates, run through the real
    unattributed_wallet_candidates path, does."""
    _skip_unless_real_sources_available()
    eth_addr = "0x000000000000000000000000000000000000bbbb"
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        store.upsert_entity("ETH_ADDRESS", eth_addr)
        store.record_cross_chain_tx_link({
            "source_chain": "ETH_ADDRESS", "source_address": eth_addr,
            "dest_chain": "BTC_ADDRESS", "dest_address": BINANCE_HOT,
            "mechanism": "BRIDGE", "evidence_ref": "test-ref-real-binance-link",
            "source_api": "wormholescan", "tx_timestamp": None, "status": "completed"})
        # BINANCE_HOT itself only needs to EXIST as an entity for
        # _vasp_endpoints' GraphSense-tag lookup to find it -- no enrichment
        # needed for that half of the check.
        store.upsert_entity("BTC_ADDRESS", BINANCE_HOT)

        report = wallet_trace_report(store, eth_addr, chain="ethereum")

    assert report["exchange"] is None            # no same-chain reachability at all
    assert report["vasp_candidates"] is not None
    assert report["vasp_candidates"]["primary_candidate"] == "binance.com"
    assert report["vasp_candidates"]["supporting_signals"][0]["rule_id"] == \
        "attribution.cross_chain_corroboration.v1"
