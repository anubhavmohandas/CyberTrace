"""Solana (SOL) OSINT module (Loop 38 Section 8)."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..integrations import exchange_tags
from .base import BaseModule, ModuleResult, SourceResult

# Solana's public RPC (used when no private endpoint is configured -- see
# api_key_registry.SOLANA_RPC_URL) is free but rate-limited and explicitly
# not meant for production traffic. These bounds keep one search() call
# small regardless: _SHALLOW_LIMIT signatures for the investigation
# default, _DEEP_LIMIT for --deep. Each signature costs a SECOND RPC call
# (getTransaction) to learn its counterparty/direction --
# getSignaturesForAddress alone carries no account information -- so this
# is N+1 calls, not N; kept small on purpose, same "bounded acquisition"
# reasoning as bitcoin_module's _TX_SHALLOW_PAGES/_TX_DEEP_PAGES.
_SHALLOW_LIMIT = 10
_DEEP_LIMIT = 30
_LAMPORTS_PER_SOL = 1_000_000_000

# Distinguishes "fetch_json itself failed" (rate limit exhausted, network
# error, JSON-RPC `error`) from a legitimate JSON `null` result, which
# getTransaction returns often in practice: the public RPC does not retain
# full history, so an older signature commonly comes back null without
# anything having gone wrong. Conflating the two would report a normal
# history-retention gap as a retrieval failure -- see _check_solana_rpc.
_RPC_FAILED = object()


class SolanaModule(BaseModule):
    """
    Solana address investigation via JSON-RPC (public endpoint by default,
    or a private one set via SOLANA_RPC_URL -- see api_key_registry.py).

    Same architecture as bitcoin_module/tron_module: no auth required for
    the public default, one bounded transaction-history sample for
    counterparty/direction evidence, offline GraphSense TagPacks lookup
    alongside it (real SOL coverage exists there -- see _check_exchange_tags).
    Solana is account-based like TRON/Ethereum -- no UTXO/co-spend signal,
    only TRANSACTED_WITH reachability -- but unlike either, a transaction's
    `accountKeys` lists every account an instruction merely TOUCHED, not a
    simple payer/payee pair, so direction here comes from lamport BALANCE
    CHANGE (this address's own preBalance vs postBalance), not account
    position; see _extract_peer.
    """

    name = "solana"
    description = "Solana (SOL) address analysis"
    supported_types = {'solana'}

    def _rpc_url(self) -> str:
        return self.config.api_keys.get('solana_rpc') or "https://api.mainnet-beta.solana.com"

    @staticmethod
    def _retryable(body: Any) -> bool:
        """Same in-band-rate-limit shape as NodeReal/TronGrid (see
        bitcoin_module._is_rate_limit_body/tron_module._trongrid_retryable):
        a Solana RPC node returns HTTP 200 with a JSON-RPC `error` even when
        the real cause is exceeding that node's own rate limit."""
        error = body.get('error') if isinstance(body, dict) else None
        if not isinstance(error, dict):
            return False
        message = str(error.get('message', '')).lower()
        return any(kw in message for kw in ('rate limit', 'too many requests', '429'))

    async def _rpc(self, method: str, params: list) -> Tuple[Any, Optional[str]]:
        """One JSON-RPC 2.0 call. Returns (result, error): result is
        _RPC_FAILED only when the call itself failed (network/rate-limit/
        JSON-RPC error) -- a legitimate JSON `null` result (getTransaction
        on a signature this node no longer retains) comes back as plain
        None, which callers must NOT treat as a failure."""
        data = await self.fetch_json(
            self._rpc_url(), method='POST',
            json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params},
            retryable_body=self._retryable,
        )
        if not data:
            return _RPC_FAILED, 'No data returned'
        if 'error' in data:
            return _RPC_FAILED, str(data['error'].get('message') or data['error'])
        return data.get('result'), None

    async def search(self, target: str, **options) -> ModuleResult:
        deep = bool(options.get('deep'))
        result = ModuleResult(target=target, target_type='solana', module=self.name)
        sources = [
            ('solana_rpc', self._check_solana_rpc(target, deep=deep)),
            ('exchange_tags', self._check_exchange_tags(target)),
        ]
        await self.run_sources(sources, result)
        result.summary = self._build_summary(result)
        result.end_time = datetime.now(timezone.utc)
        return result

    async def _check_solana_rpc(self, address: str, deep: bool = False) -> SourceResult:
        """Balance + a bounded transaction sample. getSignaturesForAddress
        alone has no account/value information -- see the module docstring
        -- so each signature costs a follow-up getTransaction call."""
        balance, err = await self._rpc('getBalance', [address])
        if balance is _RPC_FAILED:
            return SourceResult(source='solana_rpc', success=False, error=err)
        balance_lamports = (balance or {}).get('value', 0) if isinstance(balance, dict) else 0

        limit = _DEEP_LIMIT if deep else _SHALLOW_LIMIT
        signatures, sig_err = await self._rpc(
            'getSignaturesForAddress', [address, {'limit': limit}])
        if signatures is _RPC_FAILED:
            return SourceResult(source='solana_rpc', success=False, error=sig_err)
        signatures = signatures or []  # a wallet with zero history is a real, valid result

        counterparties: set = set()
        sent_to: set = set()
        received_from: set = set()
        first_seen = last_seen = None
        fetch_failed = False
        # Loop 53: real per-tx rows, same N+1 fetch _extract_peer already
        # reads -- no new RPC call. Value comes from the SAME lamport
        # balance-change this module already uses for direction (see
        # _lamport_delta), never a second, unrelated field.
        raw_transactions: List[dict] = []
        for sig_info in signatures:
            sig = sig_info.get('signature')
            if not sig:
                continue
            ts = sig_info.get('blockTime')
            iso = None
            if ts:
                iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                first_seen = iso if first_seen is None else min(first_seen, iso)
                last_seen = iso if last_seen is None else max(last_seen, iso)
            tx, tx_err = await self._rpc(
                'getTransaction', [sig, {'encoding': 'json', 'maxSupportedTransactionVersion': 0}])
            if tx is _RPC_FAILED:
                # A single signature's detail genuinely failing to fetch
                # (rate limit exhausted, network error) must not silently
                # look like "this signature has no counterparty" -- same
                # principle as bitcoin_module's pagination_failed, applied
                # to Solana's own N+1 fetch shape.
                fetch_failed = True
                continue
            if tx is None:
                continue  # legitimately not retained by this RPC node -- not a failure
            peer, direction = self._extract_peer(tx, address)
            if peer:
                counterparties.add(peer)
                if direction == 'sent':
                    sent_to.add(peer)
                elif direction == 'received':
                    received_from.add(peer)
                delta = self._lamport_delta(tx, address)
                fee = ((tx.get('meta') or {}).get('fee') or 0) / _LAMPORTS_PER_SOL
                raw_transactions.append({
                    'tx_hash': sig, 'direction': 'OUT' if direction == 'sent' else 'IN',
                    'counterparty': peer, 'asset': 'SOL',
                    'value': abs(delta) / _LAMPORTS_PER_SOL if delta is not None else None,
                    'timestamp': iso, 'block': tx.get('slot'), 'fee': fee,
                    'provider': 'solana_rpc', 'status': 'FOUND',
                })

        parsed: Dict[str, Any] = {
            'balance_sol': balance_lamports / _LAMPORTS_PER_SOL,
            'tx_count': len(signatures),
            'first_seen': first_seen,
            'last_seen': last_seen,
            'counterparty_addresses': sorted(counterparties)[:20],
            'sent_to_addresses': sorted(sent_to)[:20],
            'received_from_addresses': sorted(received_from)[:20],
            'connected_addresses': sorted(counterparties)[:20],
            'raw_transactions': raw_transactions,
        }
        if fetch_failed:
            parsed['pagination_incomplete'] = True
        return SourceResult(source='solana_rpc', success=True, data=parsed)

    @staticmethod
    def _lamport_delta(tx: dict, address: str) -> Optional[int]:
        """This address's own lamport balance change in `tx` -- the same
        pre/postBalances _extract_peer already reads, factored out rather
        than changing that function's tested (peer, direction) return shape.
        """
        try:
            keys = tx['transaction']['message']['accountKeys']
            pre = tx['meta']['preBalances']
            post = tx['meta']['postBalances']
        except (KeyError, TypeError):
            return None
        addrs = [k if isinstance(k, str) else (k or {}).get('pubkey') for k in keys]
        if address not in addrs:
            return None
        idx = addrs.index(address)
        if idx >= len(pre) or idx >= len(post):
            return None
        return post[idx] - pre[idx]

    @staticmethod
    def _extract_peer(tx: dict, address: str) -> Tuple[Optional[str], Optional[str]]:
        """The one counterparty and direction this transaction says about
        `address`, from lamport balance change -- NOT accountKeys order,
        which includes every account the instruction touched (a program id,
        a rent-exempt PDA, ...) regardless of whether value moved.

        occam: only the single largest-magnitude opposing balance change is
        reported (the dominant real transfer), not every account that moved
        by any amount -- a token-account rent payment alongside the real
        transfer would otherwise report a false second peer for no
        investigative value. Known ceiling: a transfer smaller than the
        network fee could misattribute the fee-payer as the peer; upgrade
        by reading the fee-payer index (accountKeys[0]) out of the
        comparison if that ever shows up on a real case.
        """
        try:
            keys = tx['transaction']['message']['accountKeys']
            pre = tx['meta']['preBalances']
            post = tx['meta']['postBalances']
        except (KeyError, TypeError):
            return None, None
        # accountKeys entries are plain strings or {"pubkey": ...} dicts
        # depending on encoding/version -- normalize both.
        addrs = [k if isinstance(k, str) else (k or {}).get('pubkey') for k in keys]
        if address not in addrs:
            return None, None
        me_idx = addrs.index(address)
        if me_idx >= len(pre) or me_idx >= len(post):
            return None, None
        my_delta = post[me_idx] - pre[me_idx]
        if my_delta == 0:
            return None, None
        direction = 'sent' if my_delta < 0 else 'received'
        best_peer, best_delta = None, 0
        for i, addr in enumerate(addrs):
            if i == me_idx or addr is None or i >= len(pre) or i >= len(post):
                continue
            delta = post[i] - pre[i]
            # The real counterparty moves opposite to `address`: if we lost
            # lamports, the account that GAINED the most is the recipient
            # (the fee payer's own tiny gain/loss is normally dwarfed by a
            # genuine transfer amount).
            if (my_delta < 0 and delta > best_delta) or (my_delta > 0 and delta < best_delta):
                best_peer, best_delta = addr, delta
        return best_peer, direction

    async def _check_exchange_tags(self, address: str) -> SourceResult:
        """Offline lookup against the local GraphSense TagPacks corpus --
        same EXTERNAL_DATASET_MATCH class as bitcoin_module/tron_module's
        own copies. Real SOL coverage exists (Loop 38 Section 8): 5 tags,
        including two ("bitfinex Solana hot wallet"/"...cold wallet") from
        exchange-wallets-bitfinexcom.yaml -- the exact source already in
        exchange_tags._VASP_DISCLOSED_SOURCES, so these resolve to
        VASP_DISCLOSED with a real wallet_role, not merely TAG_ATTESTED.
        """
        if not exchange_tags.available():
            return SourceResult(source='exchange_tags', success=False,
                                error='GraphSense TagPacks dataset not downloaded locally')
        if not exchange_tags.index_available():
            return SourceResult(source='exchange_tags', success=False,
                                error='GraphSense TagPacks downloaded but not indexed '
                                      '(run exchange_tags.build_index() once, offline)')
        if exchange_tags.is_stale():
            return SourceResult(source='exchange_tags', success=False,
                                error='GraphSense TagPacks index is stale -- the local '
                                      'archive changed since this index was built (run '
                                      'exchange_tags.build_index(force=True) to refresh)')
        tags = exchange_tags.lookup_address(address, 'SOL')
        if not tags:
            return SourceResult(source='exchange_tags', success=True, data={'tagged': False})
        return SourceResult(source='exchange_tags', success=True, data={
            'tagged': True,
            'categories': sorted({t['category'] for t in tags if t.get('category')}),
            'labels': sorted({t['label'] for t in tags if t.get('label')})[:10],
            'packs': sorted({t['pack'] for t in tags if t.get('pack')}),
            'is_exchange_tagged': any((t.get('category') or '').lower() == 'exchange'
                                      for t in tags),
        })

    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        """Same field shape as tron_module._build_summary -- this is what
        lets evidence._ENRICHERS route Solana through the existing,
        chain-agnostic enrich_bitcoin rather than a Solana-specific
        enrichment function."""
        summary: Dict[str, Any] = {
            'address': result.target,
            'type': 'solana',
            'balance': None,
            'tx_count': None,
            'first_seen': None,
            'last_seen': None,
            'counterparty_addresses': [],
            'sent_to_addresses': [],
            'received_from_addresses': [],
            'connected_addresses': [],
            # True only when a getTransaction detail call genuinely failed
            # partway through the sample (see _check_solana_rpc) -- must not
            # be confused with a wallet simply having fewer signatures than
            # the requested limit.
            'pagination_incomplete': False,
            'raw_transactions': [],
        }

        for source, res in result.sources.items():
            if not res.success:
                continue
            data = res.data

            if summary['balance'] is None and 'balance_sol' in data:
                summary['balance'] = f"{data['balance_sol']:.9f} SOL"
            if summary['tx_count'] is None and 'tx_count' in data:
                summary['tx_count'] = data['tx_count']
            if summary['first_seen'] is None and data.get('first_seen'):
                summary['first_seen'] = data['first_seen']
            if summary['last_seen'] is None and data.get('last_seen'):
                summary['last_seen'] = data['last_seen']

            if data.get('counterparty_addresses'):
                summary['counterparty_addresses'] = data['counterparty_addresses']
                summary['connected_addresses'] = data['counterparty_addresses']
                result.related.extend(data['counterparty_addresses'][:5])
            if data.get('sent_to_addresses'):
                summary['sent_to_addresses'] = data['sent_to_addresses']
            if data.get('received_from_addresses'):
                summary['received_from_addresses'] = data['received_from_addresses']
            if source == 'solana_rpc' and data.get('pagination_incomplete'):
                summary['pagination_incomplete'] = True
            if data.get('raw_transactions'):
                summary['raw_transactions'].extend(data['raw_transactions'])

            if source == 'exchange_tags' and data.get('tagged'):
                summary['exchange_tag_categories'] = data.get('categories')
                summary['exchange_tag_labels'] = data.get('labels')
                summary['exchange_tag_packs'] = data.get('packs')
                summary['exchange_tag_is_exchange'] = data.get('is_exchange_tagged')

        return summary
