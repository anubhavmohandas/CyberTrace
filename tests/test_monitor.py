"""cybertrace.monitor: watch_narrative wiring, wallet re-check plumbing, and
the pure wallet_targets/wallet_deltas helpers. recheck()/run_watch()'s live
Tor-fetch path (the onion side) is still untested offline, same as before
this addition -- the wallet side is exercised through a fake chain module
(get_module is monkeypatched) instead, since a wallet re-check is one plain
async function call with no live-Tor equivalent to substitute."""
import json
from pathlib import Path

import pytest

from cybertrace.correlate import (
    _attach_wallet_risk, _attach_wallet_service_intelligence, wallet_exchange_paths,
)
from cybertrace.evidence import EvidenceStore, _ingest_enrichment, ingest, label_exchange
from cybertrace.modules.base import ModuleResult
from cybertrace.monitor import (
    run_watch, wallet_deltas, wallet_targets, watch_narrative,
)

from .test_correlate import BINANCE_HOT, BTC_OTHER, _synth_btc, _traced
from .test_evidence import BTC_VALID

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = [ROOT / "runs" / "raw" / "v8" / "tortaxi-prd.json",
            ROOT / "runs" / "raw" / "v8" / "tortaxi-2dev.json"]


@pytest.fixture
def store():
    with EvidenceStore(":memory:") as s:
        for p in CAPTURES:
            ingest(json.loads(p.read_text()), s)
        yield s


def test_watch_narrative_none_when_no_deltas(store):
    assert watch_narrative(store, "tortaxi", []) is None


def test_watch_narrative_grounded_answer_when_deltas_present(store, monkeypatch):
    monkeypatch.delenv("CT_LLM_PROVIDER", raising=False)
    fake_delta = [{"change": "NEW", "candidate_id": "OP-fake0000",
                   "confidence": 0.9, "assessment": "test delta"}]
    result = watch_narrative(store, "tortaxi", fake_delta)
    assert result is not None
    assert result["case_id"] == "tortaxi"
    assert result["mode"] == "deterministic"
    assert result["answer"]
    assert "claims" in result and "evidence" in result


# --- case-state enforcement + watch-history persistence (Loop 42) -----------
#
# A fresh, empty ":memory:" store on purpose here: it has no onion or wallet
# targets, so run_watch's re-check loops are both empty and no live Tor/chain
# fetch is attempted -- these pin the guard and the persistence write, not
# the live re-check path (still exercised elsewhere in this file via a fake
# chain module).

def test_run_watch_refused_once_case_is_closed():
    with EvidenceStore(":memory:") as s:
        s.update_case(status="CLOSED")
        with pytest.raises(ValueError, match="case is CLOSED"):
            run_watch(s, correlate=False)


def test_run_watch_persists_a_watch_run():
    with EvidenceStore(":memory:") as s:
        report = run_watch(s)
        history = s.watch_history()
        assert len(history) == 1
        assert history[0]["checked_at"] == report["checked_at"]
        assert history[0]["status"] == "OK"


def test_reopening_a_case_shows_prior_watch_history():
    """The exact LEA workflow gap named in Loop 42: a second analyst
    reopening the same --db must see what an earlier watch cycle found, not
    only what the run that found it printed."""
    with EvidenceStore(":memory:") as s:
        run_watch(s, correlate=False)
        run_watch(s, correlate=False)
        assert len(s.watch_history()) == 2


def _wallet_search_result(address: str, **summary_fields) -> ModuleResult:
    """Shaped exactly like a BitcoinModule.search() return: a ModuleResult, so
    it can stand in for what module.search() itself returns (_visit_wallet
    calls .to_dict() on it, same as production) as well as feed ingest()
    directly via .to_dict()."""
    return ModuleResult(target=address, target_type="bitcoin", module="bitcoin",
                        summary={"address": address, **summary_fields})


class TestWalletTargets:
    """wallet_targets() must find exactly the addresses this case actually
    searched, and nothing an address merely appeared next to."""

    def test_finds_a_directly_searched_wallet(self):
        with EvidenceStore(":memory:") as s:
            ingest(_wallet_search_result(BTC_VALID, sent_to_addresses=[BTC_OTHER]).to_dict(), s)
            found = {w["address"]: w for w in wallet_targets(s)}
            assert BTC_VALID in found
            assert found[BTC_VALID]["etype"] == "BTC_ADDRESS"

    def test_excludes_an_address_only_ever_observed_as_someone_elses_mention(self):
        """The boundary wallet_targets exists to hold: a BTC address seen on a
        market page (section != enrichment) belongs to the market's own
        target, never becomes a re-search candidate on its own."""
        with EvidenceStore(":memory:") as s:
            tid = s.upsert_target("market.example.onion")
            sid = s.insert_snapshot(tid, {"page": "contact"}, collector="darkweb")
            addr_id = s.upsert_entity("BTC_ADDRESS", BTC_OTHER)
            s.insert_observation(sid, addr_id, method="darkweb:crypto",
                                 section="crypto", context=BTC_OTHER, confidence=0.7)
            assert wallet_targets(s) == []

    def test_a_pivot_discovered_wallet_resolves_its_own_canonical_target(self):
        """Real shape found live against cases/tortaxi.db (adversarial
        validation against a real case database, not a synthetic guess): a market crawl's own
        operator_pivot enrichment of an address found on the page is filed
        under the MARKET's target row (evidence.py:1290-1294), yet its
        observation's method still ends in ':enrichment'. wallet_targets must
        not hand that market target_id back as the address's own -- a later
        re-check would then diff against the market's unrelated snapshot
        chain instead of the wallet's, always reading as a first capture."""
        with EvidenceStore(":memory:") as s:
            market_tid = s.upsert_target("pivot-market.example.onion")
            s.insert_snapshot(market_tid, {"page": "contact"}, collector="darkweb")
            _ingest_enrichment(s, BTC_VALID, "bitcoin",
                               {"address": BTC_VALID, "sent_to_addresses": [BTC_OTHER]},
                               "operator_pivot:pivot", "2026-08-24T00:00:00+00:00",
                               market_tid)

            found = wallet_targets(s)
            assert len(found) == 1
            assert found[0]["address"] == BTC_VALID
            assert found[0]["target_id"] == s.upsert_target(BTC_VALID)
            assert found[0]["target_id"] != market_tid

    def test_excludes_onion_targets(self):
        with EvidenceStore(":memory:") as s:
            for p in CAPTURES:
                ingest(json.loads(p.read_text()), s)
            ingest(_wallet_search_result(BTC_VALID, sent_to_addresses=[BTC_OTHER]).to_dict(), s)
            found = wallet_targets(s)
            addresses = {w["address"] for w in found}
            assert BTC_VALID in addresses
            # every row is a wallet entity, never an onion market target
            assert all(w["etype"] in ("BTC_ADDRESS", "ETH_ADDRESS", "TRX_ADDRESS")
                      for w in found)


class TestWalletDeltas:
    """Pure function: compared by entity_id against the same fields
    wallet_exchange_paths reports, never against a wallet this run did not
    touch (that is `before`'s whole job -- see wallet_deltas' own docstring)."""

    ROW = {"value": BTC_VALID, "proximity": "DIRECT", "hops": 1,
          "exchange": "Binance", "attribution": "TAG_ATTESTED", "direction": "TO_VASP",
          "risk": {"risk_level": "LOW", "risk_score": 0}}

    def test_new_when_a_wallet_only_has_a_path_after(self):
        out = wallet_deltas({}, [{"entity_id": "e1", **self.ROW}])
        assert len(out) == 1 and out[0]["change"] == "NEW"
        assert out[0]["entity_id"] == "e1" and out[0]["value"] == BTC_VALID

    def test_moved_when_a_tracked_field_changes(self):
        before = {"e1": {**self.ROW, "proximity": "INDIRECT", "hops": 2}}
        out = wallet_deltas(before, [{"entity_id": "e1", **self.ROW}])
        assert len(out) == 1 and out[0]["change"] == "MOVED"
        assert out[0]["before"]["hops"] == 2 and out[0]["after"]["hops"] == 1

    def test_identical_path_produces_no_delta(self):
        before = {"e1": dict(self.ROW)}
        assert wallet_deltas(before, [{"entity_id": "e1", **self.ROW}]) == []

    def test_moved_when_only_risk_changes(self):
        """A wallet whose risk crosses a level with no path/attribution change
        (a fresh Chainabuse report, a newly tagged mixing hop) must still
        surface as MOVED -- not only ever show up in risk_alerts."""
        before = {"e1": dict(self.ROW)}
        after_row = {**self.ROW, "risk": {"risk_level": "HIGH", "risk_score": 80}}
        out = wallet_deltas(before, [{"entity_id": "e1", **after_row}])
        assert len(out) == 1 and out[0]["change"] == "MOVED"
        assert out[0]["before"]["risk"]["risk_level"] == "LOW"
        assert out[0]["after"]["risk"]["risk_level"] == "HIGH"

    def test_no_gone_case_when_a_tracked_wallet_is_absent_from_after(self):
        """The evidence store is append-only -- a path already found cannot be
        un-found by a re-check that simply did not run this session."""
        before = {"e1": dict(self.ROW)}
        assert wallet_deltas(before, []) == []


def _direct_contact(exchange, attribution="TAG_ATTESTED", direction="TO_VASP"):
    """Shaped like a wallet_exchange_paths direct_vasp_contacts entry: hop 1
    is implied by the field itself, so real entries never carry a "hops"
    key (see correlate.py's `secondary` list)."""
    return {"peer_entity_id": f"peer-{exchange}", "exchange": exchange,
            "attribution": attribution, "attribution_source": "test",
            "direction": direction, "evidence_ids": [1]}


def _secondary_contact(exchange, hops=2, attribution="TAG_ATTESTED", direction="TO_VASP"):
    """Shaped like a wallet_exchange_paths secondary_vasp_contacts entry:
    always carries an explicit "hops" (see correlate.py's
    _secondary_vasp_reach)."""
    return {"peer_entity_id": f"peer-{exchange}", "exchange": exchange,
            "attribution": attribution, "attribution_source": "test",
            "hops": hops, "path": ["e1", "mid", f"peer-{exchange}"],
            "direction": direction, "evidence_ids": [1]}


class TestVaspContactDeltas:
    """Loop 31: direct_vasp_contacts/secondary_vasp_contacts (Loop 28/30,
    AT_VASP-only) now participate in wallet_deltas' MOVED/NEW comparison the
    same way proximity/hops/exchange/attribution/direction already did --
    see _vasp_contacts in monitor.py. DIRECT/INDIRECT rows, which never
    carry either key, must remain exactly as safe as TestWalletDeltas above
    already pins."""

    ROW = {"value": BTC_VALID, "proximity": "AT_VASP", "hops": 0,
          "exchange": "VASP A", "attribution": "ANALYST_ASSERTED",
          "direction": "UNKNOWN", "direct_vasp_contacts": [],
          "secondary_vasp_contacts": [], "risk": {"risk_level": "LOW", "risk_score": 0}}

    def test_a_new_direct_vasp_contact_is_a_moved_delta(self):
        before = {"e1": dict(self.ROW)}
        after = [{"entity_id": "e1", **self.ROW,
                  "direct_vasp_contacts": [_direct_contact("VASP B")]}]
        out = wallet_deltas(before, after)
        assert len(out) == 1 and out[0]["change"] == "MOVED"
        assert out[0]["before"]["vasp_contacts"] == []
        assert [c["exchange"] for c in out[0]["after"]["vasp_contacts"]] == ["VASP B"]

    def test_a_new_secondary_vasp_contact_is_a_moved_delta(self):
        before = {"e1": dict(self.ROW)}
        after = [{"entity_id": "e1", **self.ROW,
                  "secondary_vasp_contacts": [_secondary_contact("VASP B")]}]
        out = wallet_deltas(before, after)
        assert len(out) == 1 and out[0]["change"] == "MOVED"
        assert [c["exchange"] for c in out[0]["after"]["vasp_contacts"]] == ["VASP B"]

    def test_an_unchanged_vasp_contact_across_cycles_produces_no_delta(self):
        row = {**self.ROW, "direct_vasp_contacts": [_direct_contact("VASP B")]}
        before = {"e1": dict(row)}
        assert wallet_deltas(before, [{"entity_id": "e1", **row}]) == []

    def test_direct_and_indirect_rows_without_contact_fields_are_unaffected(self):
        """A watched wallet that never reaches AT_VASP carries neither key at
        all -- must not KeyError, and the missing-field default (empty
        contact set) must not manufacture a false delta."""
        row = {"value": BTC_VALID, "proximity": "DIRECT", "hops": 1,
              "exchange": "Binance", "attribution": "TAG_ATTESTED", "direction": "TO_VASP",
              "risk": {"risk_level": "LOW", "risk_score": 0}}
        before = {"e1": dict(row)}
        assert wallet_deltas(before, [{"entity_id": "e1", **row}]) == []
        out = wallet_deltas({}, [{"entity_id": "e1", **row}])
        assert len(out) == 1 and out[0]["vasp_contacts"] == []

    def test_only_the_newly_added_contact_changes_the_reported_set(self):
        before = {"e1": {**self.ROW, "direct_vasp_contacts": [_direct_contact("VASP B")]}}
        after = [{"entity_id": "e1", **self.ROW,
                  "direct_vasp_contacts": [_direct_contact("VASP B"), _direct_contact("VASP C")]}]
        out = wallet_deltas(before, after)
        assert len(out) == 1
        assert {c["exchange"] for c in out[0]["before"]["vasp_contacts"]} == {"VASP B"}
        assert {c["exchange"] for c in out[0]["after"]["vasp_contacts"]} == {"VASP B", "VASP C"}

    def test_a_contact_disappearing_is_reported_moved_not_a_new_gone_type(self):
        """No enforced removal-prevention for contacts, unlike the primary
        relationship's append-only guarantee (see wallet_deltas' own
        docstring) -- a brand present before and absent after is compared by
        plain inequality like any other tracked field, and surfaces as
        MOVED, never a new delta type invented for this loop."""
        before = {"e1": {**self.ROW, "direct_vasp_contacts": [_direct_contact("VASP B")]}}
        after = [{"entity_id": "e1", **self.ROW}]
        out = wallet_deltas(before, after)
        assert len(out) == 1 and out[0]["change"] == "MOVED"
        assert out[0]["after"]["vasp_contacts"] == []

    def test_an_evidence_only_change_produces_no_delta(self):
        """path/evidence_ids are excluded from the comparison, matching
        FIELDS' own omission of both for the primary relationship."""
        contact_v1 = {"peer_entity_id": "p1", "exchange": "VASP B",
                     "attribution": "TAG_ATTESTED", "attribution_source": "test",
                     "direction": "TO_VASP", "evidence_ids": [1]}
        contact_v2 = {**contact_v1, "evidence_ids": [1, 2, 3]}
        before = {"e1": {**self.ROW, "direct_vasp_contacts": [contact_v1]}}
        after = [{"entity_id": "e1", **self.ROW, "direct_vasp_contacts": [contact_v2]}]
        assert wallet_deltas(before, after) == []

    def test_a_direct_brand_and_a_different_secondary_brand_both_surface_without_duplication(self):
        """wallet_exchange_paths itself guarantees a brand lands in only one
        of the two fields (its own direct_brands guard) -- confirm the
        delta layer reports each exactly once when they're already split
        across the two fields, never twice."""
        row = {**self.ROW, "direct_vasp_contacts": [_direct_contact("VASP B")],
              "secondary_vasp_contacts": [_secondary_contact("VASP C")]}
        out = wallet_deltas({}, [{"entity_id": "e1", **row}])
        assert len(out) == 1
        assert [c["exchange"] for c in out[0]["vasp_contacts"]] == ["VASP B", "VASP C"]


class TestVaspContactWatchCycle:
    """Phase 6: a real, two-cycle wallet_exchange_paths() diff -- the exact
    shape recheck() feeds wallet_deltas cycle to cycle (see recheck's
    wallets_before/wallets_after in monitor.py) -- proving a newly
    discovered VASP relationship is now visible to monitoring, and that a
    pre-existing one is never re-reported as newly discovered."""

    def test_a_secondary_vasp_discovered_between_cycles_produces_a_delta(self):
        suspect_addr = BTC_VALID
        w1, w2 = _synth_btc("m31-w1"), _synth_btc("m31-w2")
        vasp_b = _synth_btc("m31-vaspb")
        with EvidenceStore(":memory:") as s:
            assert label_exchange(s, suspect_addr, "VASP A") is not None
            suspect = _traced(s, suspect_addr, {})

            # Cycle 1: no secondary VASP.
            cycle1 = [p for p in wallet_exchange_paths(s) if p["entity_id"] == suspect]
            assert cycle1[0]["proximity"] == "AT_VASP"
            assert cycle1[0]["secondary_vasp_contacts"] == []
            _attach_wallet_service_intelligence(s, cycle1)
            _attach_wallet_risk(s, cycle1)
            before = {p["entity_id"]: p for p in cycle1}

            # Cycle 2: suspect -> w1 -> w2 -> VASP B appears.
            _traced(s, suspect_addr, {"counterparty_addresses": [w1]})
            _traced(s, w1, {"counterparty_addresses": [w2]})
            _traced(s, w2, {"sent_to_addresses": [vasp_b]})
            assert label_exchange(s, vasp_b, "VASP B") is not None

            after = [p for p in wallet_exchange_paths(s) if p["entity_id"] == suspect]
            _attach_wallet_service_intelligence(s, after)
            _attach_wallet_risk(s, after)
            deltas = wallet_deltas(before, after)

        assert len(after[0]["secondary_vasp_contacts"]) == 1
        assert after[0]["secondary_vasp_contacts"][0]["exchange"] == "vasp b"

        assert len(deltas) == 1 and deltas[0]["change"] == "MOVED"
        assert deltas[0]["before"]["vasp_contacts"] == []
        assert [c["exchange"] for c in deltas[0]["after"]["vasp_contacts"]] == ["vasp b"]

    def test_a_preexisting_direct_vasp_is_not_rereported_when_a_secondary_vasp_appears(self):
        suspect_addr, vasp_b = BTC_VALID, BTC_OTHER
        w1, vasp_c = _synth_btc("m31b-w1"), _synth_btc("m31b-vaspc")
        with EvidenceStore(":memory:") as s:
            assert label_exchange(s, suspect_addr, "VASP A") is not None
            suspect = _traced(s, suspect_addr,
                              {"counterparty_addresses": [vasp_b], "sent_to_addresses": [vasp_b]})
            assert label_exchange(s, vasp_b, "VASP B") is not None

            # Cycle 1: the suspect already directly reaches VASP B.
            cycle1 = [p for p in wallet_exchange_paths(s) if p["entity_id"] == suspect]
            assert [c["exchange"] for c in cycle1[0]["direct_vasp_contacts"]] == ["vasp b"]
            _attach_wallet_service_intelligence(s, cycle1)
            _attach_wallet_risk(s, cycle1)
            before = {p["entity_id"]: p for p in cycle1}

            # Cycle 2: a NEW secondary VASP C appears one hop further out.
            # counterparty_addresses is cumulative (a real re-search reports
            # a wallet's full on-chain history, not just what's new -- see
            # test_a_wallet_that_newly_reaches_a_labeled_exchange_is_reported
            # above), so vasp_b is repeated here alongside the new w1 hop.
            _traced(s, suspect_addr, {"counterparty_addresses": [vasp_b, w1],
                                      "sent_to_addresses": [vasp_b]})
            _traced(s, w1, {"sent_to_addresses": [vasp_c]})
            assert label_exchange(s, vasp_c, "VASP C") is not None

            after = [p for p in wallet_exchange_paths(s) if p["entity_id"] == suspect]
            _attach_wallet_service_intelligence(s, after)
            _attach_wallet_risk(s, after)
            deltas = wallet_deltas(before, after)

        assert [c["exchange"] for c in after[0]["direct_vasp_contacts"]] == ["vasp b"]
        assert [c["exchange"] for c in after[0]["secondary_vasp_contacts"]] == ["vasp c"]

        assert len(deltas) == 1 and deltas[0]["change"] == "MOVED"
        before_brands = {c["exchange"] for c in deltas[0]["before"]["vasp_contacts"]}
        after_brands = {c["exchange"] for c in deltas[0]["after"]["vasp_contacts"]}
        assert before_brands == {"vasp b"}
        assert after_brands == {"vasp b", "vasp c"}


class _FakeChainModule:
    """Stands in for BitcoinModule/TronModule in recheck()'s wallet loop --
    same async context-manager + search(target, **options) shape, no network."""

    def __init__(self, result: dict):
        self._result = result
        self.show_progress = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def search(self, target: str, **options) -> ModuleResult:
        return self._result


class TestWalletRecheck:
    """run_watch()'s wallet pass end to end: query -> re-search -> ingest ->
    diff, over a fake chain module standing in for the live one."""

    def test_a_wallet_that_newly_reaches_a_labeled_exchange_is_reported(self, monkeypatch):
        import cybertrace.modules as modules_pkg

        with EvidenceStore(":memory:") as s:
            ingest(_wallet_search_result(BTC_VALID, sent_to_addresses=[BTC_OTHER]).to_dict(), s)
            label_exchange(s, BINANCE_HOT, "Binance", analyst="jdoe")

            recheck_payload = _wallet_search_result(
                BTC_VALID, sent_to_addresses=[BTC_OTHER, BINANCE_HOT])
            monkeypatch.setattr(modules_pkg, "get_module",
                                lambda module_type: _FakeChainModule(recheck_payload))

            report = run_watch(s, correlate=False)

        assert report["wallets_checked"] == [
            {"address": BTC_VALID, "chain": "BTC_ADDRESS", "status": "CHANGED"}]
        assert len(report["wallet_deltas"]) == 1
        delta = report["wallet_deltas"][0]
        assert delta["change"] == "NEW"
        assert delta["value"] == BTC_VALID
        assert delta["proximity"] == "DIRECT" and delta["hops"] == 1
        assert delta["attribution"] == "ANALYST_ASSERTED"

    def test_an_unchanged_wallet_reports_unchanged_and_no_delta(self, monkeypatch):
        import cybertrace.modules as modules_pkg

        with EvidenceStore(":memory:") as s:
            payload = _wallet_search_result(BTC_VALID, sent_to_addresses=[BTC_OTHER])
            ingest(payload.to_dict(), s)
            monkeypatch.setattr(modules_pkg, "get_module",
                                lambda module_type: _FakeChainModule(payload))

            report = run_watch(s, correlate=False)

        assert report["wallets_checked"] == [
            {"address": BTC_VALID, "chain": "BTC_ADDRESS", "status": "UNCHANGED"}]
        assert report["wallet_deltas"] == []

    def test_a_wallet_recheck_that_returns_no_data_is_reported_as_check_failed(self, monkeypatch):
        import cybertrace.modules as modules_pkg

        with EvidenceStore(":memory:") as s:
            ingest(_wallet_search_result(BTC_VALID, sent_to_addresses=[BTC_OTHER]).to_dict(), s)
            empty = ModuleResult(target=BTC_VALID, target_type="bitcoin",
                                 module="bitcoin", summary={})
            monkeypatch.setattr(modules_pkg, "get_module",
                                lambda module_type: _FakeChainModule(empty))

            report = run_watch(s, correlate=False)

        assert report["wallets_checked"] == [
            {"address": BTC_VALID, "chain": "BTC_ADDRESS", "status": "CHECK_FAILED"}]
        assert report["wallet_deltas"] == []

    def test_a_pivot_discovered_wallets_first_recheck_lands_on_its_own_chain(
            self, monkeypatch):
        """End-to-end version of the wallet_targets fix above, using the exact
        real shape found live against cases/tortaxi.db.

        insert_snapshot chains per (target_id, collector) -- correct for page
        captures (a per-target-only chain would compare unrelated pages) but
        it means a pivot's capture (collector="operator_pivot:pivot") and a
        direct re-check's capture (collector="bitcoin") are, by that same
        rule, two different chains even once they share a target_id. So the
        FIRST watch re-check of a pivot-discovered wallet still reads CHANGED
        here -- correctly read as "first capture under this collector", not a
        false claim -- and this is the known, named remainder of the fix:
        every re-check AFTER this one correctly diffs against ITS OWN prior
        "bitcoin"-collector capture, because both now share the right
        target_id. What this test actually pins is the fix that removed the
        WORSE failure: without it, the new capture landed on the market's
        target_id and this address was never diffed against its own history
        at all, on any re-check, ever.
        """
        import cybertrace.modules as modules_pkg

        with EvidenceStore(":memory:") as s:
            market_tid = s.upsert_target("pivot-market.example.onion")
            summary = {"address": BTC_VALID, "sent_to_addresses": [BTC_OTHER]}
            _ingest_enrichment(s, BTC_VALID, "bitcoin", summary, "operator_pivot:pivot",
                               "2026-08-24T00:00:00+00:00", market_tid)

            same_again = ModuleResult(target=BTC_VALID, target_type="bitcoin",
                                      module="bitcoin", summary=summary)
            monkeypatch.setattr(modules_pkg, "get_module",
                                lambda module_type: _FakeChainModule(same_again))

            report = run_watch(s, correlate=False)
            canonical_tid = s.upsert_target(BTC_VALID)
            second_snapshot = s._one(
                "SELECT target_id FROM snapshots WHERE target_id=? AND collector='bitcoin'",
                (canonical_tid,))

        # The recheck's own capture landed on the address's own canonical
        # target, not the market's -- the failure mode a real run
        # against cases/tortaxi.db actually found and this fix closes.
        assert second_snapshot is not None
        assert report["wallets_checked"] == [
            {"address": BTC_VALID, "chain": "BTC_ADDRESS", "status": "CHANGED"}]


def test_run_watch_surfaces_a_critical_wallet_as_a_risk_alert(monkeypatch):
    """Loop 37: high-risk wallet alerts reach the watch/case surface too, not
    just a one-off `correlate` run -- reusing the same real Polyanin
    self-designation (CRITICAL, score 80) test_correlate.py's own risk-alert
    test pins. run_watch's re-check re-confirms the same real deposits (the
    fake chain module returns the identical payload), then re-correlates;
    risk_alerts must come through unmodified from that re-correlation, the
    same way successors/contradictions already do."""
    import cybertrace.modules as modules_pkg

    from .test_correlate import (
        OFAC_POLYANIN, OFAC_POLYANIN_REAL_SENT_TO, _skip_unless_real_sources_available,
    )

    _skip_unless_real_sources_available()
    with EvidenceStore(":memory:") as s:
        payload = _wallet_search_result(
            OFAC_POLYANIN, sent_to_addresses=OFAC_POLYANIN_REAL_SENT_TO, tx_sample_size=19)
        ingest(payload.to_dict(), s)

        monkeypatch.setattr(modules_pkg, "get_module",
                            lambda module_type: _FakeChainModule(payload))

        report = run_watch(s, correlate=True)

    assert len(report["risk_alerts"]) == 1
    alert = report["risk_alerts"][0]
    assert alert["value"] == OFAC_POLYANIN
    assert alert["risk"]["risk_level"] == "CRITICAL"
    assert alert["risk"]["risk_score"] == 80
