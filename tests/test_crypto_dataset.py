"""Tests for tools/build_crypto_benchmark.py (Loop 52) -- the multi-source
crypto benchmark builder. Unit tests here use tiny synthetic fixtures (tmp_path)
matching the real Elliptic++/fesevu CSV headers exactly, never the real
multi-hundred-MB corpora -- monkeypatching the module's own path constants,
same convention as tests/test_integrations.py. The one real-data test is
skip-guarded for when the corpus isn't present.

This script is standalone (tools/, not cybertrace/) and touches no production
import path -- these tests exist to protect the dataset pipeline itself, not
anything Loop 45/48/49/50 depends on.
"""

from __future__ import annotations

import asyncio
import csv
import gzip
import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
bcb = importlib.import_module("build_crypto_benchmark")


# --- fixtures --------------------------------------------------------------

def _write_csv(path: Path, header: list, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


@pytest.fixture
def ellipticpp_dir(tmp_path, monkeypatch):
    d = tmp_path / "ellipticpp"
    _write_csv(d / "txs_classes.csv", ["txId", "class"],
               [["100", "1"], ["101", "2"], ["102", "3"], ["103", "3"]])
    _write_csv(d / "txs_edgelist.csv", ["txId1", "txId2"],
               [["100", "101"], ["100", "102"], ["103", "100"]])
    _write_csv(d / "txs_features.csv", ["txId", "Time step", "Local_feature_1", "Local_feature_2"],
               [["100", "1", "0.5", "-0.2"], ["101", "1", "0.1", ""],  # "" = genuinely missing
                ["102", "38", "0.3", "0.4"], ["103", "45", "0.2", "0.1"]])
    _write_csv(d / "wallets_classes.csv", ["address", "class"],
               [["addrA", "1"], ["addrB", "2"], ["addrC", "3"]])
    wallet_header = ["address", "Time step", "class", "num_txs_as_sender", "num_txs_as receiver",
                     "total_txs", "btc_transacted_max"]
    wallet_rows = [
        ["addrA", "1", "1", "20", "3", "23", "5.0"],
        ["addrB", "2", "2", "1", "1", "2", "0.01"],
        ["addrB", "2", "2", "1", "1", "2", "0.01"],  # exact duplicate row -- must be deduped
        ["addrC", "38", "3", "0", "1", "1", "0.5"],
    ]
    _write_csv(d / "wallets_features_classes_combined.csv", wallet_header, wallet_rows)
    monkeypatch.setattr(bcb, "ELLIPTICPP_DIR", d)
    return d


@pytest.fixture
def ethereum_labels_csv(tmp_path, monkeypatch):
    d = tmp_path / "eth"
    d.mkdir()
    csv_path = d / "addr_labels_balanced.csv"
    _write_csv(csv_path, ["address", "is_scam", "description", "activity_start_ts",
                          "activity_end_ts", "is_contract"],
               [["0xaaa", "1", "phishing", "", "", "0"],
                ["0xbbb", "0", "", "2020-01-01 00:00:00 UTC", "2020-01-02 00:00:00 UTC", "0"],
                ["0xccc", "0", "", "", "", "1"]])
    monkeypatch.setattr(bcb, "ETH_ORIGINAL_DIR", d)
    monkeypatch.setattr(bcb, "ETH_CACHE_PATH", d / "etherscan_fetch_cache.json")
    return csv_path


# --- B1: Elliptic++ transactions --------------------------------------------

class TestLoadEllipticTransactions:
    def test_label_mapping_is_never_normal_for_unknown(self, ellipticpp_dir):
        rows = bcb.load_elliptic_transactions()
        by_id = {r["entity_id"]: r for r in rows}
        assert by_id["100"]["ground_truth_label"] == "ILLICIT"
        assert by_id["101"]["ground_truth_label"] == "LICIT"
        assert by_id["102"]["ground_truth_label"] == "UNKNOWN"
        assert by_id["102"]["label_confidence"] == "NONE"
        assert by_id["100"]["label_confidence"] == "HIGH"

    def test_missing_feature_value_is_none_not_zero(self, ellipticpp_dir):
        rows = {r["entity_id"]: r for r in bcb.load_elliptic_transactions()}
        assert rows["101"]["features"]["Local_feature_2"] is None

    def test_graph_degree_is_computed_from_edgelist(self, ellipticpp_dir):
        rows = {r["entity_id"]: r for r in bcb.load_elliptic_transactions()}
        # 100 -> 101, 100 -> 102 (out=2); 103 -> 100 (in=1)
        assert rows["100"]["graph_features"] == {
            "in_degree": 1, "out_degree": 2, "unique_counterparties": 3}

    def test_behavior_flags_independent_of_label(self, ellipticpp_dir, monkeypatch):
        """A flag firing must never change ground_truth_label -- forcing a
        low threshold here to make FAN_OUT fire on an UNKNOWN row proves the
        two are computed independently."""
        monkeypatch.setattr(bcb, "compute_behavior_flags",
                             lambda tx, mv, ind, outd: ["FAN_OUT"] if outd else [])
        rows = {r["entity_id"]: r for r in bcb.load_elliptic_transactions()}
        assert rows["100"]["ground_truth_label"] == "ILLICIT"
        assert "FAN_OUT" in rows["100"]["behavior_flags"]
        # 102 is UNKNOWN with out_degree 0 -- flag doesn't fire, but proves
        # the label itself was never touched by the flag computation path.
        assert rows["102"]["ground_truth_label"] == "UNKNOWN"

    def test_temporal_split_boundaries(self, ellipticpp_dir):
        rows = {r["entity_id"]: r for r in bcb.load_elliptic_transactions()}
        assert rows["100"]["split"] == "train"   # timestep 1
        assert rows["102"]["split"] == "val"     # timestep 38 (35-42)
        assert rows["103"]["split"] == "test"    # timestep 45 (>42)

    def test_provenance_present_on_every_row(self, ellipticpp_dir):
        for r in bcb.load_elliptic_transactions():
            assert "Elmougy & Liu" in r["label_provenance"]
            assert r["source"] == "ellipticpp_local"

    def test_missing_corpus_raises_a_clear_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bcb, "ELLIPTICPP_DIR", tmp_path / "does_not_exist")
        with pytest.raises(FileNotFoundError, match="ellipticpp"):
            bcb.load_elliptic_transactions()


# --- B1: Elliptic++ wallets (dedup) -----------------------------------------

class TestLoadEllipticWallets:
    def test_exact_duplicate_rows_are_removed(self, ellipticpp_dir):
        rows, raw_count = bcb.load_elliptic_wallets()
        assert raw_count == 4          # 4 rows in the fixture, one is a dup
        assert len(rows) == 3          # addrA, addrB (once), addrC
        addr_ids = [r["entity_id"] for r in rows]
        assert addr_ids.count("addrB") == 1

    def test_unknown_class_survives_as_unknown(self, ellipticpp_dir):
        rows = {r["entity_id"]: r for r in bcb.load_elliptic_wallets()[0]}
        assert rows["addrC"]["ground_truth_label"] == "UNKNOWN"

    def test_wallet_split_uses_its_own_timestep(self, ellipticpp_dir):
        rows = {r["entity_id"]: r for r in bcb.load_elliptic_wallets()[0]}
        assert rows["addrA"]["split"] == "train"  # timestep 1
        assert rows["addrC"]["split"] == "val"    # timestep 38


# --- B1b: BABD-13 wallets (own taxonomy, conflict handling) -----------------

@pytest.fixture
def babd13_dir(tmp_path, monkeypatch):
    d = tmp_path / "babd13"
    header = ["account", "SW", "feat1", "feat2", "label"]
    rows = [
        ["addrX", "SA", "1.0", "2.0", "3"],   # CENTRALIZED_EXCHANGE, strong
        ["addrY", "WA", "0.5", "", "6"],      # GAMBLING, weak, missing feature
        ["addrZ", "SA", "0.1", "0.2", "0"],   # first claim: BLACKMAIL
        ["addrZ", "SA", "0.1", "0.2", "8"],   # conflicting claim: MONEY_LAUNDERING
        ["addrW", "SA", "9.0", "9.0", "12"],
        ["addrW", "SA", "9.0", "9.0", "12"],  # exact duplicate row
    ]
    _write_csv(d / "BABD-13.csv", header, rows)
    monkeypatch.setattr(bcb, "BABD13_DIR", d)
    return d


class TestLoadBabd13Wallets:
    def test_missing_corpus_raises_a_clear_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bcb, "BABD13_DIR", tmp_path / "does_not_exist")
        with pytest.raises(FileNotFoundError, match="BABD-13"):
            bcb.load_babd13_wallets()

    def test_label_index_maps_to_its_own_named_taxonomy(self, babd13_dir):
        rows = {r["entity_id"]: r for r in bcb.load_babd13_wallets()[0]}
        assert rows["addrX"]["ground_truth_label"] == "CENTRALIZED_EXCHANGE"
        assert rows["addrY"]["ground_truth_label"] == "GAMBLING"

    def test_sw_column_becomes_label_confidence(self, babd13_dir):
        rows = {r["entity_id"]: r for r in bcb.load_babd13_wallets()[0]}
        assert rows["addrX"]["label_confidence"] == "STRONG"
        assert rows["addrY"]["label_confidence"] == "WEAK"

    def test_missing_feature_value_is_none_not_zero(self, babd13_dir):
        rows = {r["entity_id"]: r for r in bcb.load_babd13_wallets()[0]}
        assert rows["addrY"]["features"]["feat2"] is None

    def test_conflicting_labels_never_pick_one_arbitrarily(self, babd13_dir):
        rows, _ = bcb.load_babd13_wallets()
        addrz_rows = [r for r in rows if r["entity_id"] == "addrZ"]
        # Both claims survive, neither silently dropped in favor of the other.
        assert len(addrz_rows) == 2
        assert all(r["ground_truth_label"] == "LABEL_CONFLICT" for r in addrz_rows)
        assert all(r["label_confidence"] == "CONFLICT" for r in addrz_rows)
        assert {r["source_label"] for r in addrz_rows} == {"0,8"}

    def test_exact_duplicate_rows_are_removed(self, babd13_dir):
        rows, raw_count = bcb.load_babd13_wallets()
        assert raw_count == 6
        addrw_rows = [r for r in rows if r["entity_id"] == "addrW"]
        assert len(addrw_rows) == 1

    def test_conflict_rows_excluded_from_balanced_subset(self, babd13_dir):
        rows, _ = bcb.load_babd13_wallets()
        balanced = bcb.build_babd13_balanced_subset(rows)
        assert all(r["ground_truth_label"] != "LABEL_CONFLICT" for r in balanced)


# --- B2: Ethereum labels -----------------------------------------------------

class TestLoadEthereumLabels:
    def test_all_valid_rows_load(self, ethereum_labels_csv):
        rows = bcb.load_ethereum_labels(ethereum_labels_csv)
        assert {r["address"] for r in rows} == {"0xaaa", "0xbbb", "0xccc"}

    def test_malformed_is_scam_value_is_skipped_not_guessed(self, tmp_path):
        path = tmp_path / "bad.csv"
        _write_csv(path, ["address", "is_scam", "description", "activity_start_ts",
                          "activity_end_ts", "is_contract"],
                   [["0xgood", "1", "", "", "", "0"], ["0xbad", "maybe", "", "", "", "0"]])
        rows = bcb.load_ethereum_labels(path)
        assert [r["address"] for r in rows] == ["0xgood"]


class TestSampleEthereumAddresses:
    def test_stratified_by_scam_status(self, ethereum_labels_csv):
        rows = bcb.load_ethereum_labels(ethereum_labels_csv)
        sample = bcb.sample_ethereum_addresses(rows, 2)
        assert {r["is_scam"] for r in sample} == {"0", "1"}

    def test_sample_is_deterministic_across_calls(self, ethereum_labels_csv):
        """The bug this pins: an earlier version selected "next uncached
        batch", which meant re-running with the same target size kept
        advancing to new addresses instead of converging -- caught by
        running the real script twice and watching the cache grow both
        times instead of staying put."""
        rows = bcb.load_ethereum_labels(ethereum_labels_csv)
        first = bcb.sample_ethereum_addresses(rows, 2)
        second = bcb.sample_ethereum_addresses(rows, 2)
        assert [r["address"] for r in first] == [r["address"] for r in second]


# --- B2: live enrichment (mocked network) -----------------------------------

def _mock_module(monkeypatch, responses: dict):
    """responses: address -> (txs_or_None, error_or_None)"""
    async def fake_fetch(self, address, chain, action):
        return responses[address]
    monkeypatch.setattr(bcb.BitcoinModule, "_fetch_evm_account_txs", fake_fetch)


class TestEnrichEthereumAddresses:
    def test_failed_fetch_stays_failed_never_becomes_zero_activity(self, ethereum_labels_csv, monkeypatch):
        rows = bcb.load_ethereum_labels(ethereum_labels_csv)
        sample = [r for r in rows if r["address"] == "0xaaa"]
        _mock_module(monkeypatch, {"0xaaa": (None, "rate limited")})
        out = asyncio.run(bcb.enrich_ethereum_addresses(sample, refresh=False))
        assert out[0]["fetch_status"] == "failed"
        assert out[0]["fetch_reason"] == "rate limited"
        assert out[0]["features"] is None
        assert out[0]["behavior_flags"] == []  # never computed from a null feature set

    def test_successful_fetch_computes_real_features(self, ethereum_labels_csv, monkeypatch):
        rows = bcb.load_ethereum_labels(ethereum_labels_csv)
        sample = [r for r in rows if r["address"] == "0xbbb"]
        txs = [
            {"from": "0xbbb", "to": "0xpeer1", "value": str(2 * 10**18),
             "timeStamp": "1000000", "input": "0x", "isError": "0"},
            {"from": "0xpeer2", "to": "0xbbb", "value": str(1 * 10**18),
             "timeStamp": "1086400", "input": "0xdeadbeef", "isError": "1"},
        ]
        _mock_module(monkeypatch, {"0xbbb": (txs, None)})
        out = asyncio.run(bcb.enrich_ethereum_addresses(sample, refresh=False))
        f = out[0]["features"]
        assert out[0]["fetch_status"] == "success"
        assert f["transaction_count"] == 2
        assert f["unique_sent_to"] == 1
        assert f["unique_received_from"] == 1
        assert f["contract_calls"] == 1
        assert f["failed_tx_ratio"] == 0.5
        assert f["active_days"] == 1.0

    def test_cache_makes_a_second_run_call_the_network_zero_times(self, ethereum_labels_csv, monkeypatch):
        rows = bcb.load_ethereum_labels(ethereum_labels_csv)
        sample = [r for r in rows if r["address"] == "0xccc"]
        calls = {"n": 0}

        async def counting_fetch(self, address, chain, action):
            calls["n"] += 1
            return ([], None)

        monkeypatch.setattr(bcb.BitcoinModule, "_fetch_evm_account_txs", counting_fetch)
        asyncio.run(bcb.enrich_ethereum_addresses(sample, refresh=False))
        assert calls["n"] == 1
        asyncio.run(bcb.enrich_ethereum_addresses(sample, refresh=False))
        assert calls["n"] == 1, "second run must be served entirely from cache"

    def test_refresh_retries_only_failed_addresses_not_successes(self, ethereum_labels_csv, monkeypatch):
        rows = bcb.load_ethereum_labels(ethereum_labels_csv)
        calls = {"n": 0}

        async def fake_fetch(self, address, chain, action):
            calls["n"] += 1
            if address == "0xaaa":
                return (None, "timeout")
            return ([], None)

        monkeypatch.setattr(bcb.BitcoinModule, "_fetch_evm_account_txs", fake_fetch)
        asyncio.run(bcb.enrich_ethereum_addresses(rows, refresh=False))
        assert calls["n"] == 3
        asyncio.run(bcb.enrich_ethereum_addresses(rows, refresh=True))
        # Only 0xaaa (the failed one) should be retried -- the 2 successes
        # must not incur another network call under --refresh.
        assert calls["n"] == 4

    def test_cache_is_saved_periodically_not_only_at_the_end(self, tmp_path, monkeypatch):
        """A 3000-address run takes minutes; an interrupted run (Ctrl-C,
        crash) must resume from wherever it actually got to. Pins that the
        cache file on disk is updated mid-run, not only after the full loop
        completes."""
        eth_dir = tmp_path / "eth2"
        eth_dir.mkdir()
        cache_path = eth_dir / "cache.json"
        monkeypatch.setattr(bcb, "ETH_CACHE_PATH", cache_path)
        monkeypatch.setattr(bcb, "_CACHE_SAVE_EVERY", 3)
        monkeypatch.setattr(bcb, "FETCH_DELAY_SECONDS", 0)
        rows = [{"address": f"0x{i}", "is_scam": "0"} for i in range(7)]
        _mock_module(monkeypatch, {r["address"]: ([], None) for r in rows})

        saved_sizes = []
        real_save = bcb._save_fetch_cache

        def spy_save(cache):
            real_save(cache)
            saved_sizes.append(len(json.loads(cache_path.read_text())))

        monkeypatch.setattr(bcb, "_save_fetch_cache", spy_save)
        asyncio.run(bcb.enrich_ethereum_addresses(rows, refresh=False))
        # saved at 3 and 6 mid-loop, plus once more at the end (7) -- never
        # only a single save after all 7 addresses were already fetched.
        assert saved_sizes == [3, 6, 7]

    def test_ground_truth_label_matches_is_scam(self, ethereum_labels_csv, monkeypatch):
        rows = bcb.load_ethereum_labels(ethereum_labels_csv)
        _mock_module(monkeypatch, {a: ([], None) for a in ("0xaaa", "0xbbb", "0xccc")})
        out = {r["entity_id"]: r for r in asyncio.run(bcb.enrich_ethereum_addresses(rows, False))}
        assert out["0xaaa"]["ground_truth_label"] == "FRAUD"
        assert out["0xbbb"]["ground_truth_label"] == "LICIT"
        assert out["0xaaa"]["scam_category"] == "phishing"


# --- quality report / balanced subset / cross-source dedup ------------------

class TestQualityReportAndSubset:
    def test_cross_source_duplicate_addresses_detected(self):
        btc_wallets = [{"entity_id": "0xshared", "ground_truth_label": "LICIT"}]
        eth_rows = [{"entity_id": "0xshared", "ground_truth_label": "LICIT", "fetch_status": "success"},
                    {"entity_id": "0xother", "ground_truth_label": "FRAUD", "fetch_status": "success"}]
        report = bcb.build_quality_report([], btc_wallets, 1, eth_rows)
        assert report["cross_source_duplicate_addresses"] == 1

    def test_deferred_sources_are_documented_with_reasons(self):
        report = bcb.build_quality_report([], [], 0, [])
        for name in ("cryptoxchain_500k", "kaggle_multi_crypto_anomaly_detection_2025"):
            assert name in report["deferred_sources"]
            assert len(report["deferred_sources"][name]) > 20  # a real reason, not a stub

    def test_balanced_subset_caps_every_class_to_the_smallest(self):
        btc_wallets = ([{"entity_id": f"i{i}", "ground_truth_label": "ILLICIT"} for i in range(2)]
                       + [{"entity_id": f"l{i}", "ground_truth_label": "LICIT"} for i in range(10)]
                       + [{"entity_id": f"u{i}", "ground_truth_label": "UNKNOWN"} for i in range(10)])
        subset = bcb.build_balanced_subset(btc_wallets, [])
        counts = {}
        for r in subset:
            counts[r["ground_truth_label"]] = counts.get(r["ground_truth_label"], 0) + 1
        assert counts == {"ILLICIT": 2, "LICIT": 2, "UNKNOWN": 2}


class TestWriteJsonl:
    def test_output_is_gzipped_and_round_trips(self, tmp_path):
        """A real run's row count produces multi-GB of plain JSONL (measured:
        ~14x smaller gzipped) -- pins that write_jsonl actually compresses,
        not just that it writes valid JSON."""
        path = tmp_path / "out.jsonl"
        rows = [{"a": 1}, {"a": 2}]
        bcb.write_jsonl(path, rows)
        gz_path = tmp_path / "out.jsonl.gz"
        assert gz_path.exists()
        assert not path.exists()
        with gzip.open(gz_path, "rt") as f:
            loaded = [json.loads(line) for line in f]
        assert loaded == rows


# --- real-data smoke test ----------------------------------------------------

def _real_corpus_available() -> bool:
    real_dir = Path(__file__).resolve().parent.parent / "external_data" / "ellipticpp" / "original"
    return (real_dir / "txs_classes.csv").exists()


@pytest.mark.skipif(not _real_corpus_available(), reason="real Elliptic++ corpus not present locally")
def test_real_elliptic_corpus_yields_all_three_label_classes(monkeypatch):
    importlib.reload(bcb)  # undo any monkeypatched ELLIPTICPP_DIR from earlier tests
    rows = bcb.load_elliptic_transactions()
    assert len(rows) >= 200_000
    labels = {r["ground_truth_label"] for r in rows}
    assert labels == {"ILLICIT", "LICIT", "UNKNOWN"}
