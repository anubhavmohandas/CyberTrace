"""Tests for cybertrace/provider_health.py -- the centralized live-provider
health registry (Loop 51). No test here makes a real network call: every
probe is monkeypatched, matching the rest of this suite's convention of
setting fake coroutines directly rather than mocking aiohttp.
"""

import asyncio

import pytest

from cybertrace import provider_health as ph
from cybertrace.config import config
from cybertrace.modules.base import SourceResult
from cybertrace.modules.bitcoin_module import BitcoinModule
from cybertrace.detector import btc_address_family


@pytest.fixture(autouse=True)
def _clear_cache():
    """Every test starts from an empty health cache -- otherwise test order
    could leak a cached LIVE/DOWN result from one test into another."""
    ph._cache.clear()
    ph._cache_ts.clear()
    yield
    ph._cache.clear()
    ph._cache_ts.clear()


class TestClassify:
    def test_fast_success_is_live(self):
        assert ph._classify(True, 100.0, None) == (ph.LIVE, None)

    def test_slow_success_is_degraded_with_latency_in_the_reason(self):
        status, reason = ph._classify(True, 5000.0, None)
        assert status == ph.DEGRADED
        assert "5000" in reason

    def test_failure_is_down_with_the_source_error_as_reason(self):
        assert ph._classify(False, 50.0, "bad gateway") == (ph.DOWN, "bad gateway")

    def test_failure_with_no_error_text_still_gets_a_reason(self):
        status, reason = ph._classify(False, 50.0, None)
        assert status == ph.DOWN
        assert reason


class TestProviderSpecs:
    def test_every_provider_id_is_unique(self):
        specs = ph._live_provider_specs()
        ids = [s.id for s in specs]
        assert len(ids) == len(set(ids))

    def test_keyed_providers_match_the_real_api_key_registry(self):
        """chainabuse/etherscan/nodereal are the only crypto providers that
        require a key (see api_key_registry.py) -- pins that against drift."""
        keyed = {s.id: s.config_key for s in ph._live_provider_specs() if s.config_key}
        assert keyed == {
            "chainabuse": "chainabuse",
            "etherscan_ethereum": "etherscan",
            "etherscan_polygon": "etherscan",
            "nodereal_bnb": "nodereal",
        }


class TestCheckOneNotConfigured:
    def test_missing_key_short_circuits_without_calling_the_probe(self, monkeypatch):
        monkeypatch.setattr(config.api_keys, "chainabuse", None)
        called = []

        async def _boom():
            called.append(True)
            raise AssertionError("probe must not run when the provider isn't configured")

        spec = ph._ProviderSpec("chainabuse", "BTC/ETH abuse reports", "chainabuse", _boom)
        health = asyncio.run(ph._check_one(spec))
        assert health.status == ph.NOT_CONFIGURED
        assert health.configured is False
        assert "CHAINABUSE_API_KEY" in health.reason
        assert not called

    def test_configured_key_lets_the_probe_run(self, monkeypatch):
        monkeypatch.setattr(config.api_keys, "chainabuse", "a-real-key")

        async def _ok():
            return SourceResult(source="chainabuse", success=True, data={})

        spec = ph._ProviderSpec("chainabuse", "BTC/ETH abuse reports", "chainabuse", _ok)
        health = asyncio.run(ph._check_one(spec))
        assert health.status == ph.LIVE
        assert health.configured is True


class TestCheckOneClassification:
    def test_successful_probe_is_live(self):
        async def _ok():
            return SourceResult(source="x", success=True, data={})
        spec = ph._ProviderSpec("x", "cap", None, _ok)
        health = asyncio.run(ph._check_one(spec))
        assert health.status == ph.LIVE
        assert health.fallback is None  # no provider here has a real fallback

    def test_failed_probe_is_down_with_the_sourceresult_error(self):
        async def _fail():
            return SourceResult(source="x", success=False, error="no data returned")
        spec = ph._ProviderSpec("x", "cap", None, _fail)
        health = asyncio.run(ph._check_one(spec))
        assert health.status == ph.DOWN
        assert health.reason == "no data returned"

    def test_an_exception_in_the_probe_is_down_not_a_crash(self):
        async def _raises():
            raise RuntimeError("connection refused")
        spec = ph._ProviderSpec("x", "cap", None, _raises)
        health = asyncio.run(ph._check_one(spec))
        assert health.status == ph.DOWN
        assert "connection refused" in health.reason

    def test_a_hung_probe_times_out_as_down(self, monkeypatch):
        monkeypatch.setattr(ph, "_PROBE_TIMEOUT_SECONDS", 0.05)

        async def _hangs():
            await asyncio.sleep(10)
            return SourceResult(source="x", success=True, data={})
        spec = ph._ProviderSpec("x", "cap", None, _hangs)
        health = asyncio.run(ph._check_one(spec))
        assert health.status == ph.DOWN
        assert "0s" in health.reason or "no response" in health.reason


class TestOfflineDatasetEntries:
    def test_fresh_stale_unavailable_map_to_live_degraded_not_configured(self, monkeypatch):
        monkeypatch.setattr(
            "cybertrace.correlate.data_source_status",
            lambda: {"ofac": "FRESH", "exchange_tags": "STALE", "ellipticpp": "UNAVAILABLE"},
        )
        entries = {e.provider: e for e in ph._offline_dataset_entries()}
        assert entries["ofac"].status == ph.LIVE
        assert entries["exchange_tags"].status == ph.DEGRADED
        assert entries["ellipticpp"].status == ph.NOT_CONFIGURED
        assert entries["ellipticpp"].configured is False
        assert entries["exchange_tags"].reason


class TestCheckAllCaching:
    def test_a_provider_within_ttl_is_not_re_probed(self, monkeypatch):
        calls = {"n": 0}

        async def _ok():
            calls["n"] += 1
            return SourceResult(source="x", success=True, data={})

        monkeypatch.setattr(ph, "_live_provider_specs",
                             lambda: [ph._ProviderSpec("x", "cap", None, _ok)])
        monkeypatch.setattr(ph, "_offline_dataset_entries", lambda: [])

        asyncio.run(ph.check_all())
        asyncio.run(ph.check_all())
        assert calls["n"] == 1

    def test_force_bypasses_the_cache(self, monkeypatch):
        calls = {"n": 0}

        async def _ok():
            calls["n"] += 1
            return SourceResult(source="x", success=True, data={})

        monkeypatch.setattr(ph, "_live_provider_specs",
                             lambda: [ph._ProviderSpec("x", "cap", None, _ok)])
        monkeypatch.setattr(ph, "_offline_dataset_entries", lambda: [])

        asyncio.run(ph.check_all())
        asyncio.run(ph.check_all(force=True))
        assert calls["n"] == 2

    def test_an_expired_entry_is_re_probed(self, monkeypatch):
        calls = {"n": 0}

        async def _ok():
            calls["n"] += 1
            return SourceResult(source="x", success=True, data={})

        monkeypatch.setattr(ph, "_live_provider_specs",
                             lambda: [ph._ProviderSpec("x", "cap", None, _ok)])
        monkeypatch.setattr(ph, "_offline_dataset_entries", lambda: [])
        monkeypatch.setattr(ph, "_CACHE_TTL_SECONDS", 0.01)

        asyncio.run(ph.check_all())
        import time
        time.sleep(0.02)
        asyncio.run(ph.check_all())
        assert calls["n"] == 2


class TestProbeAddressesAreWellFormed:
    """A hand-typed probe address with a dropped hex digit doesn't fail
    loudly -- it just reports a real, working provider as DOWN (caught live:
    the original _BNB_PROBE_ADDR was 39 hex chars, not 40)."""

    def test_evm_probe_addresses_are_40_hex_chars(self):
        import re
        evm_addr = re.compile(r'^0x[a-fA-F0-9]{40}$')
        for addr in (ph._ETH_PROBE_ADDR, ph._BNB_PROBE_ADDR, ph._POLYGON_PROBE_ADDR):
            assert evm_addr.match(addr), f"malformed EVM probe address: {addr!r}"

    def test_the_module_self_check_runs_clean(self):
        ph.demo()  # raises AssertionError on any regression above


class TestProbeEvmNetworks:
    """BitcoinModule.probe_evm_networks -- the live "which EVM chain is this
    0x address actually active on" check (format ≠ network identity)."""

    ADDR = "0x742d35Cc6634C0532925a3b844Bc9e7595f12345"

    def test_reports_active_only_where_transactions_exist(self, monkeypatch):
        module = BitcoinModule()

        async def eth_txs(addr):
            return SourceResult(source="etherscan_transactions", success=True,
                                 data={"tx_count": 3})

        async def evm_txs(addr, chain):
            if chain == "bnb":
                return SourceResult(source="bnb_transactions", success=True, data={"tx_count": 0})
            return SourceResult(source="polygon_transactions", success=False,
                                 error="no Etherscan API key configured")

        monkeypatch.setattr(module, "_check_etherscan_transactions", eth_txs)
        monkeypatch.setattr(module, "_check_evm_transactions", evm_txs)

        result = asyncio.run(module.probe_evm_networks(self.ADDR))
        assert result["ethereum"] == {"checked": True, "active": True, "error": None}
        assert result["bnb"] == {"checked": True, "active": False, "error": None}
        assert result["polygon"]["checked"] is False
        assert result["polygon"]["active"] is False
        assert "Etherscan" in result["polygon"]["error"]


class TestBtcAddressFamily:
    def test_legacy(self):
        assert "Legacy" in btc_address_family("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

    def test_p2sh(self):
        assert "P2SH" in btc_address_family("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")

    def test_native_segwit(self):
        assert "SegWit" in btc_address_family("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")

    def test_taproot(self):
        assert "Taproot" in btc_address_family("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
