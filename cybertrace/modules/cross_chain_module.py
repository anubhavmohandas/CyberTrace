"""Transaction-level cross-chain intelligence (Loop 42): real bridge/swap
records from live third-party sources, structurally and semantically
separate from correlate.cross_chain_links' same-entity groupings (which
read only the local OFAC/VASP-disclosure/GraphSense corpora and never a
live transaction).

Wormholescan (bridge transfers), THORChain Midgard (cross-chain swaps),
Across Protocol (bridge transfers) and LI.FI (cross-chain aggregator) are
the four real, free, address-queryable sources verified live across Loops
42 and 44. A source-supplied record is NEVER read as proof the two
addresses it names share a controller: a bridge/swap moves VALUE across
chains, and no source here asserts common ownership of both sides. No
confidence number is invented -- none of the four publish one.

WBTC mint/burn is explicitly NOT covered here: the only real, public
linkage evidence is the WBTC DAO's own on-chain Merchant Guide, which
covers roughly forty DAO-approved custodian addresses, not general
suspect tracing -- building it would misrepresent its coverage. Stays
MISSING/BLOCKED.

Loop 44's DeFi bridge audit (native bridge / DeFi bridge / cross-chain
messaging / DEX-swap / aggregator are genuinely different evidence
classes -- collapsing them was the LayerZero mistake Loop 43 caught)
tested every protocol named in that loop's brief against its real,
current API and rejected the rest:

  Hop Protocol    -- explorer-api.hop.exchange is dead (Cloudflare
                     "origin DNS error", confirmed on two independent
                     fetch paths). No live source, nothing to build on.
  Synapse         -- api.synapseprotocol.com's own published OpenAPI spec
                     (/openapi.json) has no address-history endpoint at
                     all: every route either builds a new quote or needs
                     a txHash/synapseTxId the investigator would already
                     have to know. Can't discover a suspect's transfers
                     from their wallet address alone.
  Celer cBridge   -- cbridge-prod2.celer.app is alive, but its address-
                     history RPC (transferHistoryByAddr, every path
                     variant tried) now answers "Not Implemented"; only
                     lookup-by-transfer-id still works, which has the
                     same can't-start-from-a-wallet problem as Synapse.
  Multichain      -- unreachable (connection failure, not an HTTP error)
                     -- consistent with its confirmed shutdown after the
                     July 2023 exploit. Long defunct.
  Connext         -- rebranded to Everclear, which itself sunset as a
                     protocol in 2026. Dead.
  Stargate        -- built on LayerZero's own message layer; re-checking
                     scan.layerzero-api.com found the identical address/
                     executor ambiguity Loop 43 already rejected for
                     LayerZero itself, and no Stargate-specific address-
                     clean source exists. Same rejection, same reason.
  Socket, Rango   -- Socket's v2 API is deprecated (v3 needs a paid key);
                     Rango's public demo key is rejected (403). Neither
                     could be verified live against a real response in
                     this audit -- BLOCKED on external access, not
                     rejected on evidence grounds. Revisit if a key is
                     ever provisioned.

LI.FI qualifies, but is explicitly an AGGREGATOR, not a bridge: its own
`/v1/analytics/transfers?wallet=` (no key required, live-verified) only
ever reports a transaction that was routed through LI.FI's own contracts,
and its `sending`/`receiving` legs can land on the SAME chain (a plain
swap, not a cross-chain move at all) -- LifiModule filters those out.
What makes it usable evidence despite being an aggregator: LI.FI's own
record names `fromAddress`/`toAddress` as the actual counterparties (not
a diamond-proxy or executor address) and cites a real source-chain-native
block-explorer link (etherscan.io, arbiscan.io, basescan.org...) for each
leg's tx hash -- a third party's own citation, not one this codebase
constructs. It complements rather than substitutes for Across: a suspect
who bridged directly via Across's own UI/contracts never touches LI.FI's
contracts and won't appear there.

Neither module is registered for the general `cybertrace search` dispatch
(supported_types is empty): all four are invoked directly, one address
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


# Standard EIP-155 chain ids, for the CyberTrace-traced chains that are
# actually EVM chains. Both Across and LI.FI report chain identity this way
# (unlike Wormhole/THORChain's own custom numbering above) -- not a
# coincidence, EIP-155 ids are a public standard, so one shared map is
# correct rather than two copies that could silently drift apart. BTC,
# TRX and SOL have no EIP-155 id and are absent on purpose: neither source
# supports them (live-checked, Loop 44), so this map can never manufacture
# a link to a chain CyberTrace didn't ask for.
_EVM_CHAIN = {1: "ETH_ADDRESS", 56: "BNB_ADDRESS", 137: "POLYGON_ADDRESS"}


class AcrossModule(BaseModule):
    """Bridge-deposit lookup by address, via app.across.to/api/deposits --
    free, no API key, verified live (Loop 44 audit). This is the JSON
    backend Across's own explorer frontend calls; a separate, documented
    partner API (docs.across.to) exists behind an API key/integratorId,
    but is not needed here since this endpoint already returns real,
    complete deposit records without one -- the same evidentiary posture
    already accepted for Wormholescan and THORChain Midgard in Loop 42.
    """

    name = "across"
    description = "Across Protocol bridge deposit lookup (cross-chain, Loop 44)"
    supported_types: set = set()

    _URL = "https://app.across.to/api/deposits"

    async def search(self, target: str, **options) -> ModuleResult:
        result = ModuleResult(target=target, target_type="cross_chain_bridge", module=self.name)
        # `address` matches either side (live-checked) -- one call covers a
        # suspect who deposited OR one who received, same convenience
        # Wormholescan's own `address` param already gives that module.
        data = await self.fetch_json(f"{self._URL}?address={target}&limit=50")
        if not isinstance(data, list):
            # The real API returns a bare JSON array (unlike Wormhole/
            # THORChain's wrapping object) -- None on a failed/exhausted
            # fetch, any non-list on a malformed/unexpected shape.
            result.sources["across"] = SourceResult(
                source="across", success=False, error="request failed or no data")
            return result
        links = self._parse(data)
        result.sources["across"] = SourceResult(
            source="across", success=True, data={"deposit_count": len(data)})
        result.summary["transaction_cross_chain_links"] = links
        return result

    @staticmethod
    def _parse(data: list) -> List[dict]:
        out = []
        for dep in data:
            if not isinstance(dep, dict):
                continue
            src_chain = _EVM_CHAIN.get(dep.get("originChainId"))
            if src_chain is None:
                continue  # a chain this codebase doesn't trace
            depositor = dep.get("depositor")
            dep_tx = dep.get("depositTxHash")
            if not depositor or not dep_tx:
                continue  # no source address or no stable tx to cite
            out.append({
                "source_chain": src_chain,
                "source_address": depositor,
                "source_tx": dep_tx,
                "dest_chain": _EVM_CHAIN.get(dep.get("destinationChainId")),
                "dest_address": dep.get("recipient"),
                # Only present once Across's relayer has actually filled the
                # deposit on the destination chain (status == "filled");
                # None on an unfilled/expired/refunded deposit, left as such
                # rather than guessed.
                "dest_tx": dep.get("fillTx"),
                "mechanism": BRIDGE,
                # Across's own deposit tx hash -- stable, and the same
                # reference an investigator would use to look this deposit
                # up on Across's own explorer.
                "evidence_ref": dep_tx,
                "tx_timestamp": dep.get("depositBlockTimestamp"),
                "source_api": "across",
                "status": dep.get("status"),
            })
        return out


class LifiModule(BaseModule):
    """Cross-chain transfer lookup by address, via li.quest/v1/analytics/
    transfers -- free, no API key, verified live (Loop 44 audit). LI.FI is
    an AGGREGATOR: this only surfaces a transfer that went through LI.FI's
    own contracts (never a bridge used directly), and LI.FI itself mixes
    same-chain swaps into this endpoint -- `_parse` drops every record
    whose two legs land on the same chain, since those are not cross-chain
    evidence at all. See the module docstring above for why LI.FI's own
    fromAddress/toAddress are trusted the same way Across's depositor/
    recipient and Wormhole's `from` already are."""

    name = "lifi"
    description = "LI.FI cross-chain aggregator transfer lookup (Loop 44)"
    supported_types: set = set()

    _URL = "https://li.quest/v1/analytics/transfers"

    async def search(self, target: str, **options) -> ModuleResult:
        result = ModuleResult(target=target, target_type="cross_chain_bridge", module=self.name)
        data = await self.fetch_json(f"{self._URL}?wallet={target}&limit=50")
        if not isinstance(data, dict):
            result.sources["lifi"] = SourceResult(
                source="lifi", success=False, error="request failed or no data")
            return result
        transfers = data.get("transfers")
        if not isinstance(transfers, list):
            # A 400 (e.g. a malformed address) lands here too: LI.FI
            # returns {"message": ..., "code": ...} on HTTP 200-incompatible
            # input, which .get("transfers") correctly yields None for.
            result.sources["lifi"] = SourceResult(
                source="lifi", success=False, error="request failed or no data")
            return result
        links = self._parse(transfers)
        result.sources["lifi"] = SourceResult(
            source="lifi", success=True, data={"transfer_count": len(transfers)})
        result.summary["transaction_cross_chain_links"] = links
        return result

    @staticmethod
    def _parse(transfers: list) -> List[dict]:
        out = []
        for t in transfers:
            if not isinstance(t, dict):
                continue
            sending = t.get("sending") if isinstance(t.get("sending"), dict) else {}
            receiving = t.get("receiving") if isinstance(t.get("receiving"), dict) else {}
            src_chain = _EVM_CHAIN.get(sending.get("chainId"))
            dest_chain = _EVM_CHAIN.get(receiving.get("chainId"))
            if src_chain is None:
                continue  # a chain this codebase doesn't trace
            if src_chain == dest_chain and sending.get("chainId") == receiving.get("chainId"):
                continue  # same-chain swap, not cross-chain evidence
            from_addr = t.get("fromAddress")
            src_tx = sending.get("txHash")
            ref = t.get("transactionId")
            if not from_addr or not src_tx or not ref:
                continue  # no source address, no source tx, or no stable reference to cite
            ts = sending.get("timestamp")
            try:
                tx_timestamp = (datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
                                if ts else None)
            except (ValueError, TypeError, OverflowError, OSError):
                tx_timestamp = None
            out.append({
                "source_chain": src_chain,
                "source_address": from_addr,
                "source_tx": src_tx,
                "dest_chain": dest_chain,
                "dest_address": t.get("toAddress"),
                "dest_tx": receiving.get("txHash"),
                "mechanism": BRIDGE,
                # LI.FI's own transactionId -- the same reference LI.FI's
                # explorer link (sending/receiving txLink, both real
                # third-party block-explorer URLs LI.FI supplies, never
                # constructed here) resolves against.
                "evidence_ref": str(ref),
                "tx_timestamp": tx_timestamp,
                "source_api": "lifi",
                "status": t.get("status"),
            })
        return out
