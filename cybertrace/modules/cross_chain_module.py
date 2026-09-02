"""Transaction-level cross-chain intelligence (Loop 42): real bridge/swap
records from live third-party sources, structurally and semantically
separate from correlate.cross_chain_links' same-entity groupings (which
read only the local OFAC/VASP-disclosure/GraphSense corpora and never a
live transaction).

Wormholescan (bridge transfers) and THORChain Midgard (cross-chain swaps)
are the two real, free, address-queryable sources this loop's audit
verified live. A source-supplied record is NEVER read as proof the two
addresses it names share a controller: a bridge/swap moves VALUE across
chains, and neither source asserts common ownership of both sides. No
confidence number is invented -- neither source publishes one.

WBTC mint/burn is explicitly NOT covered here: the only real, public
linkage evidence is the WBTC DAO's own on-chain Merchant Guide, which
covers roughly forty DAO-approved custodian addresses, not general
suspect tracing -- building it would misrepresent its coverage. Stays
MISSING/BLOCKED.

Neither module is registered for the general `cybertrace search` dispatch
(supported_types is empty): both are invoked directly, one address
CyberTrace is already tracing at a time, by `cybertrace trace-cross-chain`.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseModule, ModuleResult, SourceResult

BRIDGE, SWAP = "BRIDGE", "SWAP"

# Wormhole's own numeric chain ids, for the chains CyberTrace itself traces
# and Wormhole actually supports. Bitcoin and TRON are not Wormhole-
# supported chains at all -- absent here on purpose, not a mapping gap, so
# this source can never manufacture a BTC-/TRX-side link.
_WORMHOLE_CHAIN = {1: "SOL_ADDRESS", 2: "ETH_ADDRESS", 4: "BNB_ADDRESS", 5: "POLYGON_ADDRESS"}


class WormholeModule(BaseModule):
    """Bridge-transfer lookup by address, via api.wormholescan.io -- free,
    no API key, verified live (Loop 42 audit)."""

    name = "wormhole"
    description = "Wormhole bridge transfer lookup (cross-chain, Loop 42)"
    supported_types: set = set()

    async def search(self, target: str, **options) -> ModuleResult:
        result = ModuleResult(target=target, target_type="cross_chain_bridge", module=self.name)
        data = await self.fetch_json(
            f"https://api.wormholescan.io/api/v1/operations?address={target}&pageSize=50")
        if not isinstance(data, dict):
            # None on a failed/exhausted-retry fetch; a non-dict (list,
            # string...) on a malformed or unexpected-shape response --
            # both mean "nothing usable came back", never a crash.
            result.sources["wormholescan"] = SourceResult(
                source="wormholescan", success=False, error="request failed or no data")
            return result
        links = self._parse(data, target)
        result.sources["wormholescan"] = SourceResult(
            source="wormholescan", success=True,
            data={"operation_count": len(data.get("operations") or [])})
        result.summary["transaction_cross_chain_links"] = links
        return result

    @staticmethod
    def _parse(data: dict, queried_address: str) -> List[dict]:
        out = []
        for op in data.get("operations") or []:
            if not isinstance(op, dict):
                continue
            src = op.get("sourceChain") or {}
            if not isinstance(src, dict):
                continue
            content = op.get("content") if isinstance(op.get("content"), dict) else {}
            props = content.get("standarizedProperties") or {}
            if not isinstance(props, dict):
                props = {}
            src_chain = _WORMHOLE_CHAIN.get(src.get("chainId"))
            if src_chain is None:
                continue  # a chain this codebase doesn't trace -- nothing to link to
            transaction = src.get("transaction")
            tx = transaction.get("txHash") if isinstance(transaction, dict) else None
            op_id = op.get("id") or tx
            if not op_id:
                continue  # no stable reference to cite -- refuse rather than invent one
            out.append({
                "source_chain": src_chain,
                "source_address": src.get("from") or queried_address,
                "source_tx": tx,
                "dest_chain": _WORMHOLE_CHAIN.get(props.get("toChain")),
                "dest_address": props.get("toAddress"),
                # Wormholescan's own operations-list response does not
                # reliably carry the destination-leg tx hash (Loop 42
                # audit, live-checked) -- left None rather than guessed.
                "dest_tx": None,
                "mechanism": BRIDGE,
                # The operation's own id (falling back to the source tx hash)
                # -- not a constructed webpage URL, since this module cannot
                # verify Wormholescan's own frontend routing format is stable.
                "evidence_ref": str(op_id),
                "tx_timestamp": src.get("timestamp"),
                "source_api": "wormholescan",
                "status": src.get("status"),
            })
        return out


# THORChain's own L1 gas-asset chain prefixes for the chains CyberTrace
# traces. Ethereum's L1 gas asset is ETH.ETH, but ERC-20s (including
# ETH.WBTC-...) still key on the ETH prefix -- ERC-20 tokens are correctly
# read as an Ethereum-side swap leg, not a separate chain.
_MIDGARD_CHAIN = {"BTC": "BTC_ADDRESS", "ETH": "ETH_ADDRESS", "BNB": "BNB_ADDRESS",
                  "TRX": "TRX_ADDRESS", "SOL": "SOL_ADDRESS"}


class ThorchainModule(BaseModule):
    """Cross-chain swap lookup by address, via THORChain's own Midgard API
    -- free, no key. The documented midgard.ninerealms.com host no longer
    resolves (Loop 42 audit, verified live); gateway.liquify.com's public
    mirror is the real, currently-working endpoint."""

    name = "thorchain"
    description = "THORChain Midgard swap lookup (cross-chain, Loop 42)"
    supported_types: set = set()

    _MIDGARD_URL = "https://gateway.liquify.com/chain/thorchain_midgard/v2/actions"

    async def search(self, target: str, **options) -> ModuleResult:
        result = ModuleResult(target=target, target_type="cross_chain_swap", module=self.name)
        data = await self.fetch_json(f"{self._MIDGARD_URL}?address={target}")
        if not isinstance(data, dict):
            result.sources["thorchain_midgard"] = SourceResult(
                source="thorchain_midgard", success=False, error="request failed or no data")
            return result
        links = self._parse(data)
        result.sources["thorchain_midgard"] = SourceResult(
            source="thorchain_midgard", success=True,
            data={"action_count": len(data.get("actions") or [])})
        result.summary["transaction_cross_chain_links"] = links
        return result

    @staticmethod
    def _l1_leg(leg: dict) -> Optional[Dict[str, Any]]:
        """One in[]/out[] leg, or None if it carries no genuine L1 address.
        A THORChain Trade Account asset (ticker after the '.' contains '~')
        reports a thor1... bech32 account instead of the depositor's real
        L1 address (Loop 42 audit, live-checked) -- must not be reported as
        that chain's address."""
        if not isinstance(leg, dict):
            return None
        coins = leg.get("coins") or []
        if not coins or not isinstance(coins[0], dict):
            return None
        asset = coins[0].get("asset") or ""
        if not isinstance(asset, str) or "." not in asset:
            return None
        prefix, _, rest = asset.partition(".")
        if "~" in rest:
            return None
        chain = _MIDGARD_CHAIN.get(prefix)
        if chain is None:
            return None
        return {"chain": chain, "address": leg.get("address"), "tx": leg.get("txID")}

    @classmethod
    def _parse(cls, data: dict) -> List[dict]:
        out = []
        for action in data.get("actions") or []:
            if not isinstance(action, dict) or action.get("type") != "swap":
                continue
            ins, outs = action.get("in") or [], action.get("out") or []
            src = cls._l1_leg(ins[0]) if isinstance(ins, list) and ins else None
            dest = cls._l1_leg(outs[0]) if isinstance(outs, list) and outs else None
            if src is None or not src.get("address"):
                continue  # no genuine L1 source address/chain to cite
            evidence_ref = src.get("tx") or (dest or {}).get("tx")
            if not evidence_ref:
                continue  # no stable reference to cite -- refuse rather than invent one
            ts = action.get("date")
            try:
                tx_timestamp = (datetime.fromtimestamp(int(ts) / 1e9, tz=timezone.utc).isoformat()
                                if ts else None)
            except (ValueError, TypeError, OverflowError):
                # A malformed `date` (non-numeric, or an out-of-range value)
                # must not crash the whole parse -- the transaction is still
                # real evidence even if its timestamp cannot be interpreted.
                tx_timestamp = None
            out.append({
                "source_chain": src["chain"], "source_address": src["address"],
                "source_tx": src.get("tx"),
                "dest_chain": dest["chain"] if dest else None,
                "dest_address": dest.get("address") if dest else None,
                "dest_tx": dest.get("tx") if dest else None,
                "mechanism": SWAP,
                # The in-leg's own tx id (falling back to the out-leg's) --
                # not a constructed webpage URL, since this module cannot
                # verify a THORChain explorer's routing format is stable.
                "evidence_ref": str(evidence_ref),
                # Midgard's own `date` is nanoseconds since the Unix epoch,
                # as a decimal string.
                "tx_timestamp": tx_timestamp,
                "source_api": "thorchain_midgard",
                "status": action.get("status"),
            })
        return out
