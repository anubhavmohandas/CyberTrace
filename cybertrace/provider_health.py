"""Centralized live-provider health registry.

CyberTrace calls ~15 external crypto/VASP data providers (see
api_key_registry.py + each modules/*.py file) plus 3 offline attribution
datasets, but nothing before this checked whether any of them were actually
reachable -- "a key exists in .env" and "the request just succeeded" are
different facts (cli.py's `config --check` only ever checked the former).
This is the one place that checks the latter.

Audited fact this design leans on hard: there is NO ordered primary/fallback
chain anywhere in this codebase today. Bitcoin and Ethereum run several
providers concurrently and MERGE whatever succeeds (BitcoinModule.search's
run_sources fires every source at once, unions the results); BNB, Polygon,
TRON and Solana each have exactly one live provider. So `fallback` below is
always None -- an honest "no fallback configured" beats inventing one that
doesn't exist.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable, Dict, List, Optional

from .config import config

LIVE, DEGRADED, DOWN, NOT_CONFIGURED = "LIVE", "DEGRADED", "DOWN", "NOT_CONFIGURED"

# capability_summary()'s output vocabulary -- deliberately distinct from the
# per-provider LIVE/DOWN/NOT_CONFIGURED states above (PROVIDER HEALTH is not
# CAPABILITY AVAILABILITY: one provider being DOWN does not mean the chain it
# serves is unreachable if another provider covers it). DEGRADED is shared
# with the per-provider vocabulary on purpose -- "usable but degraded" means
# the same thing at both levels.
AVAILABLE, UNAVAILABLE = "AVAILABLE", "UNAVAILABLE"

# Above this, a successful response still isn't "fine" to an investigator
# waiting on it.
_DEGRADED_LATENCY_MS = 3000.0
# Hard ceiling per probe, independent of the provider's own retry/backoff
# (Config.request_timeout, default 30s, can itself be spent retrying) -- a
# health check that can hang as long as a real investigation defeats the point.
_PROBE_TIMEOUT_SECONDS = 12.0
# How long a result is trusted before being re-checked, so health-checking
# itself doesn't spend meaningful quota against a rate-limited free-tier key.
_CACHE_TTL_SECONDS = 300.0

# Well-known, permanently-active, publicly-documented protocol/exchange
# addresses -- NOT investigation targets. Chosen so every probe queries an
# address guaranteed to carry real on-chain history.
_BTC_PROBE_ADDR = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"          # Binance BTC cold wallet
_ETH_PROBE_ADDR = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"  # WETH9 contract
_BNB_PROBE_ADDR = "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56"  # Binance-Peg BUSD contract
_POLYGON_PROBE_ADDR = "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"  # WMATIC contract
_TRON_PROBE_ADDR = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"         # USDT-TRC20 contract
_SOL_PROBE_ADDR = "So11111111111111111111111111111111111111112"  # Wrapped SOL mint


@dataclass
class ProviderHealth:
    provider: str
    capability: str
    configured: bool
    status: str
    latency_ms: Optional[float]
    reason: Optional[str]
    checked_at: str
    # Always None today -- see module docstring. Kept explicit (not omitted)
    # so a real fallback pair, if one is ever added, has somewhere obvious to
    # report itself instead of silently switching providers.
    fallback: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "capability": self.capability,
            "configured": self.configured, "status": self.status,
            "latency_ms": self.latency_ms, "reason": self.reason,
            "checked_at": self.checked_at, "fallback": self.fallback,
        }


@dataclass
class _ProviderSpec:
    id: str
    capability: str
    config_key: Optional[str]           # api_keys field required, or None if keyless
    probe: Callable[[], Awaitable]      # zero-arg async -> SourceResult


def _classify(success: bool, latency_ms: float, error: Optional[str]) -> tuple:
    if not success:
        return DOWN, error or "request failed"
    if latency_ms >= _DEGRADED_LATENCY_MS:
        return DEGRADED, f"slow response ({latency_ms:.0f}ms)"
    return LIVE, None


async def _probe_bitcoin_module(method: str, *args):
    from .modules.bitcoin_module import BitcoinModule
    async with BitcoinModule() as m:
        return await getattr(m, method)(*args)


async def _probe_trongrid():
    from .modules.tron_module import TronModule
    async with TronModule() as m:
        return await m._check_trongrid(_TRON_PROBE_ADDR)


async def _probe_solana_rpc():
    from .modules.solana_module import SolanaModule
    async with SolanaModule() as m:
        return await m._check_solana_rpc(_SOL_PROBE_ADDR)


def _live_provider_specs() -> List[_ProviderSpec]:
    return [
        _ProviderSpec("blockchain_info", "Bitcoin balance & transactions", None,
                      lambda: _probe_bitcoin_module("_check_blockchain_com", _BTC_PROBE_ADDR)),
        _ProviderSpec("blockchair_bitcoin", "Bitcoin balance & tx stats", None,
                      lambda: _probe_bitcoin_module("_check_blockchair", _BTC_PROBE_ADDR, "bitcoin")),
        _ProviderSpec("blockchair_ethereum", "Ethereum balance & tx stats", None,
                      lambda: _probe_bitcoin_module("_check_blockchair", _ETH_PROBE_ADDR, "ethereum")),
        _ProviderSpec("blockstream", "Bitcoin balance & tx stats", None,
                      lambda: _probe_bitcoin_module("_check_blockstream", _BTC_PROBE_ADDR)),
        _ProviderSpec("cryptoscamdb", "Bitcoin scam/abuse reports", None,
                      lambda: _probe_bitcoin_module("_check_bitcoin_abuse", _BTC_PROBE_ADDR)),
        _ProviderSpec("chainabuse", "BTC/ETH abuse reports", "chainabuse",
                      lambda: _probe_bitcoin_module("_check_chainabuse", _BTC_PROBE_ADDR, "BTC")),
        _ProviderSpec("ethplorer", "Ethereum balance & ERC-20 holdings", None,
                      lambda: _probe_bitcoin_module("_check_ethplorer", _ETH_PROBE_ADDR)),
        _ProviderSpec("etherscan_ethereum", "Ethereum transaction history", "etherscan",
                      lambda: _probe_bitcoin_module("_check_etherscan_transactions", _ETH_PROBE_ADDR)),
        _ProviderSpec("etherscan_polygon", "Polygon transaction history", "etherscan",
                      lambda: _probe_bitcoin_module("_check_evm_transactions", _POLYGON_PROBE_ADDR, "polygon")),
        _ProviderSpec("nodereal_bnb", "BNB Chain transaction history", "nodereal",
                      lambda: _probe_bitcoin_module("_check_evm_transactions", _BNB_PROBE_ADDR, "bnb")),
        _ProviderSpec("trongrid", "TRON balance & activity", None, _probe_trongrid),
        _ProviderSpec("solana_rpc", "Solana balance & activity", None, _probe_solana_rpc),
    ]


# Which chain(s) each live provider's capability actually serves -- used only
# by capability_summary() below, kept separate from _live_provider_specs()
# because it's a read of that list, not a property of any one probe.
# chainabuse covers both chains its capability string names ("BTC/ETH abuse
# reports"); every other provider serves exactly one chain.
_CHAIN_PROVIDERS: Dict[str, tuple] = {
    "bitcoin": ("blockchain_info", "blockchair_bitcoin", "blockstream", "cryptoscamdb", "chainabuse"),
    "ethereum": ("blockchair_ethereum", "chainabuse", "ethplorer", "etherscan_ethereum"),
    "bnb": ("nodereal_bnb",),
    "polygon": ("etherscan_polygon",),
    "tron": ("trongrid",),
    "solana": ("solana_rpc",),
}
# VASP attribution is cross-chain by definition -- it comes from the 3
# offline datasets (see _OFFLINE_LABELS below), never from a chain's live
# probes, so it is never folded into one of the chain buckets above.
_VASP_ATTRIBUTION_PROVIDERS = ("ofac", "exchange_tags", "ellipticpp")


def capability_summary(entries: List[ProviderHealth]) -> Dict[str, str]:
    """Reduces per-provider health into per-CAPABILITY availability (spec
    section 4): AVAILABLE if at least one provider for that capability is
    LIVE (e.g. Etherscan DOWN + Alchemy LIVE => Ethereum tx intelligence is
    still AVAILABLE, not DOWN), DEGRADED if none are LIVE but at least one is
    DEGRADED, else UNAVAILABLE. Returns one entry per chain in
    _CHAIN_PROVIDERS plus a separate "vasp_attribution" entry -- VASP
    attribution is cross-chain and must never be read off a single chain's
    bucket.
    """
    by_id = {e.provider: e.status for e in entries}

    def reduce_for(provider_ids) -> str:
        statuses = [by_id[i] for i in provider_ids if i in by_id]
        if any(s == LIVE for s in statuses):
            return AVAILABLE
        if any(s == DEGRADED for s in statuses):
            return DEGRADED
        return UNAVAILABLE

    summary = {chain: reduce_for(ids) for chain, ids in _CHAIN_PROVIDERS.items()}
    summary["vasp_attribution"] = reduce_for(_VASP_ATTRIBUTION_PROVIDERS)
    return summary


_OFFLINE_LABELS = {
    "ofac": "OFAC sanctions screening (offline dataset)",
    "exchange_tags": "VASP attribution labels — GraphSense TagPacks (offline dataset)",
    "ellipticpp": "Fraud/wallet-graph labels — Elliptic++ (offline dataset)",
}
_OFFLINE_STATUS_MAP = {"FRESH": LIVE, "STALE": DEGRADED, "UNAVAILABLE": NOT_CONFIGURED}
_OFFLINE_REASON = {
    LIVE: None,
    DEGRADED: "local dataset is stale against its source file",
    NOT_CONFIGURED: "dataset not downloaded or not indexed",
}


def _offline_dataset_entries() -> List[ProviderHealth]:
    from .correlate import data_source_status
    now = datetime.now(timezone.utc).isoformat()
    out = []
    for name, raw in data_source_status().items():
        status = _OFFLINE_STATUS_MAP[raw]
        out.append(ProviderHealth(
            provider=name, capability=_OFFLINE_LABELS[name], configured=status != NOT_CONFIGURED,
            status=status, latency_ms=None, reason=_OFFLINE_REASON[status], checked_at=now))
    return out


_cache_lock = threading.Lock()
_cache: Dict[str, ProviderHealth] = {}
_cache_ts: Dict[str, float] = {}


async def _check_one(spec: _ProviderSpec) -> ProviderHealth:
    now_iso = datetime.now(timezone.utc).isoformat()
    if spec.config_key and not config.api_keys.has(spec.config_key):
        return ProviderHealth(
            provider=spec.id, capability=spec.capability, configured=False,
            status=NOT_CONFIGURED, latency_ms=None,
            reason=f"no {spec.config_key.upper()}_API_KEY configured", checked_at=now_iso)
    start = time.monotonic()
    try:
        result = await asyncio.wait_for(spec.probe(), timeout=_PROBE_TIMEOUT_SECONDS)
        latency_ms = (time.monotonic() - start) * 1000
        status, reason = _classify(result.success, latency_ms, result.error)
    except asyncio.TimeoutError:
        latency_ms = (time.monotonic() - start) * 1000
        status, reason = DOWN, f"no response within {_PROBE_TIMEOUT_SECONDS:.0f}s"
    except Exception as e:  # a single bad probe must never take the whole check down
        latency_ms = (time.monotonic() - start) * 1000
        status, reason = DOWN, str(e) or type(e).__name__
    return ProviderHealth(
        provider=spec.id, capability=spec.capability, configured=True, status=status,
        latency_ms=round(latency_ms, 1), reason=reason, checked_at=now_iso)


async def check_all(force: bool = False) -> List[ProviderHealth]:
    """Health for every live provider CyberTrace's crypto modules call, plus
    the 3 offline attribution datasets. Cached per-provider for
    _CACHE_TTL_SECONDS.

    occam: two concurrent check_all() calls can both see the same stale
    entries and probe them twice -- a per-provider asyncio.Lock would close
    that, add it if duplicate concurrent health-check load actually matters.
    """
    specs = _live_provider_specs()
    now = time.monotonic()
    with _cache_lock:
        stale = [s for s in specs
                 if force or s.id not in _cache_ts or now - _cache_ts[s.id] >= _CACHE_TTL_SECONDS]
    if stale:
        results = await asyncio.gather(*(_check_one(s) for s in stale))
        with _cache_lock:
            for spec, health in zip(stale, results):
                _cache[spec.id] = health
                _cache_ts[spec.id] = now
    with _cache_lock:
        live = [_cache[s.id] for s in specs if s.id in _cache]
    return live + _offline_dataset_entries()


def demo() -> None:
    """occam self-check: classification + offline-status mapping, no network,
    plus a guard the live run above just proved is worth having -- a
    hand-typed probe address with a dropped hex digit doesn't fail loudly,
    it just reports a real provider as DOWN. Run with
    `python -m cybertrace.provider_health`."""
    import re

    assert _classify(True, 100.0, None) == (LIVE, None)
    status, reason = _classify(True, 5000.0, None)
    assert status == DEGRADED and "5000" in reason
    assert _classify(False, 50.0, "boom") == (DOWN, "boom")
    assert _OFFLINE_STATUS_MAP["FRESH"] == LIVE
    assert _OFFLINE_STATUS_MAP["UNAVAILABLE"] == NOT_CONFIGURED
    specs = _live_provider_specs()
    assert len({s.id for s in specs}) == len(specs), "duplicate provider id"
    evm_addr = re.compile(r'^0x[a-fA-F0-9]{40}$')
    for addr in (_ETH_PROBE_ADDR, _BNB_PROBE_ADDR, _POLYGON_PROBE_ADDR):
        assert evm_addr.match(addr), f"malformed EVM probe address: {addr!r}"

    # capability_summary: every id it reduces over must be a real spec/offline
    # id (a typo here would silently reduce an empty list to UNAVAILABLE).
    spec_ids = {s.id for s in specs}
    for chain, ids in _CHAIN_PROVIDERS.items():
        assert set(ids) <= spec_ids, f"{chain}: unknown provider id in {ids}"
    assert set(_VASP_ATTRIBUTION_PROVIDERS) == set(_OFFLINE_LABELS)

    def _health(provider, status):
        return ProviderHealth(provider=provider, capability="x", configured=True,
                               status=status, latency_ms=1.0, reason=None, checked_at="t")

    # spec section 4's exact example: one provider DOWN does not make the
    # capability DOWN if another provider for the same chain is LIVE.
    mixed = [_health("etherscan_ethereum", DOWN), _health("blockchair_ethereum", LIVE)]
    assert capability_summary(mixed)["ethereum"] == AVAILABLE
    degraded_only = [_health("trongrid", DEGRADED)]
    assert capability_summary(degraded_only)["tron"] == DEGRADED
    all_down = [_health("solana_rpc", DOWN)]
    assert capability_summary(all_down)["solana"] == UNAVAILABLE
    # vasp_attribution must reduce from the offline datasets, never a chain.
    vasp_live = [_health("ofac", LIVE), _health("exchange_tags", DOWN), _health("ellipticpp", DOWN)]
    assert capability_summary(vasp_live)["vasp_attribution"] == AVAILABLE
    assert capability_summary([])["vasp_attribution"] == UNAVAILABLE

    print("provider_health self-check OK")


if __name__ == "__main__":
    demo()
