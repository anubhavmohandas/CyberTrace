"""cybertrace.monitor: watch_narrative wiring, wallet re-check plumbing, and
the pure wallet_targets/wallet_deltas helpers. recheck()/run_watch()'s live
Tor-fetch path (the onion side) is still untested offline, same as before
this addition -- the wallet side is exercised through a fake chain module
(get_module is monkeypatched) instead, since a wallet re-check is one plain
async function call with no live-Tor equivalent to substitute."""
import json
from pathlib import Path

import pytest

from cybertrace.evidence import EvidenceStore, _ingest_enrichment, ingest, label_exchange
from cybertrace.modules.base import ModuleResult
from cybertrace.monitor import (
    run_watch, wallet_deltas, wallet_targets, watch_narrative,
)

from .test_correlate import BINANCE_HOT, BTC_OTHER
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
        """Real shape found live against cases/tortaxi.db (this loop's own
        adversarial validation, not a synthetic guess): a market crawl's own
        operator_pivot enrichment of an address found on the page is filed
        under the MARKET's target row (evidence.py:1290-1294), yet its
        observation's method still ends in ':enrichment'. wallet_targets must
        not hand that market target_id back as the address's own -- a later
        re-check would then diff against the market's unrelated snapshot
        chain instead of the wallet's, always reading as a first capture."""
        with EvidenceStore(":memory:") as s:
            market_tid = s.upsert_target("pivot-market.example.onion")
            market_sid = s.insert_snapshot(market_tid, {"page": "contact"},
                                           collector="darkweb")
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
          "exchange": "Binance", "attribution": "TAG_ATTESTED", "direction": "TO_VASP"}

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

    def test_no_gone_case_when_a_tracked_wallet_is_absent_from_after(self):
        """The evidence store is append-only -- a path already found cannot be
        un-found by a re-check that simply did not run this session."""
        before = {"e1": dict(self.ROW)}
        assert wallet_deltas(before, []) == []


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
        real shape found live against cases/tortaxi.db this loop.

        insert_snapshot chains per (target_id, collector) -- correct for page
        captures (docs/LOOP-era comment beside it: a per-target-only chain
        would compare unrelated pages) but it means a pivot's capture
        (collector="operator_pivot:pivot") and a direct re-check's capture
        (collector="bitcoin") are, by that same rule, two different chains
        even once they share a target_id. So the FIRST watch re-check of a
        pivot-discovered wallet still reads CHANGED here -- correctly read as
        "first capture under this collector", not a false claim -- and this
        is the known, named remainder of the fix (see docs/LOOP24.md): every
        re-check AFTER this one correctly diffs against ITS OWN prior
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
        # target, not the market's -- the failure mode this loop's live run
        # against cases/tortaxi.db actually found and this fix closes.
        assert second_snapshot is not None
        assert report["wallets_checked"] == [
            {"address": BTC_VALID, "chain": "BTC_ADDRESS", "status": "CHANGED"}]
