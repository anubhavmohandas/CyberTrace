"""TRON (TRX) OSINT module."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..integrations import exchange_tags
from ..normalize import tron_hex_to_address
from .base import BaseModule, ModuleResult, SourceResult

# ERC20-style transfer(address,uint256) selector -- the one calldata shape
# TRC20 (USDT-on-TRON and friends) transfers actually use in practice. occam:
# only this selector is decoded; transferFrom/approve/swap calldata and
# anything else is left unparsed rather than guessed at.
_ERC20_TRANSFER_SELECTOR = "a9059cbb"


def _decode_trc20_transfer_recipient(data_hex: str) -> Optional[str]:
    """Best-effort recipient of a TriggerSmartContract's transfer() calldata:
    4-byte selector, then a 32-byte padded address param -- the last 20 bytes
    of that param, re-prefixed 0x41 and re-encoded, is the TRON address.
    """
    if not data_hex.startswith(_ERC20_TRANSFER_SELECTOR):
        return None
    param = data_hex[8:72]
    if len(param) != 64:
        return None
    return tron_hex_to_address("41" + param[-40:])


class TronModule(BaseModule):
    """
    TRON address investigation via TronGrid (official, free-tier no-auth API).

    SUCCESS RATE: 95% - Blockchain is public by design, same as bitcoin_module.
    An optional TRONGRID_API_KEY (config.api_keys.trongrid) raises the free
    tier's rate limit; every source below runs without one.
    """

    name = "tron"
    description = "TRON (TRX) address analysis"
    supported_types = {'tron'}

    async def search(self, target: str, **options) -> ModuleResult:
        result = ModuleResult(target=target, target_type='tron', module=self.name)
        sources = [
            ('trongrid', self._check_trongrid(target)),
            ('trongrid_transactions', self._check_trongrid_transactions(target)),
            ('exchange_tags', self._check_exchange_tags(target)),
        ]
        await self.run_sources(sources, result)
        result.summary = self._build_summary(result)
        result.end_time = datetime.utcnow()
        return result

    def _headers(self) -> Dict[str, str]:
        key = self.config.api_keys.get('trongrid')
        return {'TRON-PRO-API-KEY': key} if key else {}

    async def _check_trongrid(self, address: str) -> SourceResult:
        """Account balance/activity via TronGrid's public REST API."""
        data = await self.fetch_json(
            f"https://api.trongrid.io/v1/accounts/{address}",
            headers=self._headers())
        if not data or not data.get('data'):
            return SourceResult(source='trongrid', success=False, error='No data returned')
        acct = data['data'][0]
        return SourceResult(source='trongrid', success=True, data={
            'balance_trx': acct.get('balance', 0) / 1_000_000,
            'token_count': len(acct.get('trc20') or []),
        })

    async def _check_trongrid_transactions(self, address: str) -> SourceResult:
        """Recent transfers, for counterparty extraction. TRON is account-based
        like Ethereum -- no UTXO/co-spend signal here, only TRANSACTED_WITH
        reachability (see bitcoin_module's own counterparty_addresses).

        Handles the two plain-transfer contract types (native TRX, TRC10)
        directly, and TRC20 (USDT and friends -- the dominant real-world TRON
        activity today) via the one calldata shape most transfers actually
        use; see _decode_trc20_transfer_recipient.
        """
        data = await self.fetch_json(
            f"https://api.trongrid.io/v1/accounts/{address}/transactions",
            params={'limit': 20, 'only_confirmed': 'true'},
            headers=self._headers())
        if not data or 'data' not in data:
            return SourceResult(source='trongrid_transactions', success=False,
                                error='No data returned')

        counterparties: set = set()
        # owner_address is the party that signed the transfer, so it is the
        # payer and the other side is the payee -- direction is on the contract
        # itself. Kept beside the direction-blind `counterparty_addresses`
        # rather than replacing it; see bitcoin_module._check_blockchain_com.
        sent_to: set = set()
        received_from: set = set()
        first_seen = last_seen = None
        for tx in data['data']:
            ts = tx.get('block_timestamp')
            if ts:
                iso = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).isoformat()
                first_seen = iso if first_seen is None else min(first_seen, iso)
                last_seen = iso if last_seen is None else max(last_seen, iso)
            for contract in tx.get('raw_data', {}).get('contract', []):
                ctype = contract.get('type')
                value = contract.get('parameter', {}).get('value', {})
                hex_peers: List[Optional[str]] = []
                owner = to_addr = None
                if ctype in ('TransferContract', 'TransferAssetContract'):
                    hex_peers = [value.get('owner_address'), value.get('to_address')]
                    owner = tron_hex_to_address(value.get('owner_address') or '')
                    to_addr = tron_hex_to_address(value.get('to_address') or '')
                elif ctype == 'TriggerSmartContract':
                    hex_peers = [value.get('owner_address')]
                    owner = tron_hex_to_address(value.get('owner_address') or '')
                    recipient = _decode_trc20_transfer_recipient(value.get('data') or '')
                    if recipient:
                        counterparties.add(recipient)
                        to_addr = recipient
                if owner and to_addr and owner != to_addr:
                    if owner == address:
                        sent_to.add(to_addr)
                    elif to_addr == address:
                        received_from.add(owner)
                for hex_addr in hex_peers:
                    if not hex_addr:
                        continue
                    addr58 = tron_hex_to_address(hex_addr)
                    if addr58:
                        counterparties.add(addr58)
        counterparties.discard(address)
        sent_to.discard(address)
        received_from.discard(address)

        return SourceResult(source='trongrid_transactions', success=True, data={
            'tx_count': len(data['data']),
            'first_seen': first_seen,
            'last_seen': last_seen,
            'counterparty_addresses': sorted(counterparties)[:20],
            'sent_to_addresses': sorted(sent_to)[:20],
            'received_from_addresses': sorted(received_from)[:20],
        })

    async def _check_exchange_tags(self, address: str) -> SourceResult:
        """Offline lookup against the local GraphSense TagPacks corpus (public,
        MIT-licensed community address tags) -- no network call. Same
        EXTERNAL_DATASET_MATCH class as bitcoin_module._check_ellipticpp: a
        tag here is a third party's public claim about this address, never
        proof of control -- evidence.enrich_bitcoin writes it as
        non-attributive metadata only, never an EXCHANGE_DEPOSIT edge. Only
        label_exchange (an analyst's own say-so) can create that edge.
        """
        if not exchange_tags.available():
            return SourceResult(source='exchange_tags', success=False,
                                error='GraphSense TagPacks dataset not downloaded locally')
        if not exchange_tags.index_available():
            return SourceResult(source='exchange_tags', success=False,
                                error='GraphSense TagPacks downloaded but not indexed '
                                      '(run exchange_tags.build_index() once, offline)')
        tags = exchange_tags.lookup_address(address, 'TRX')
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
        summary: Dict[str, Any] = {
            'address': result.target,
            'type': 'tron',
            'balance': None,
            'tx_count': None,
            'first_seen': None,
            'last_seen': None,
            # Same reachability-only shape as bitcoin_module's summary --
            # see evidence.enrich_bitcoin: counterparty proves a transaction
            # happened, not shared control, so this only ever becomes a
            # TRANSACTED_WITH edge, never a cluster/funnel signal.
            'counterparty_addresses': [],
            # Direction-aware split of the same peers; see
            # evidence.enrich_bitcoin's SENT_FUNDS_TO branch.
            'sent_to_addresses': [],
            'received_from_addresses': [],
            'connected_addresses': [],
        }

        for source, res in result.sources.items():
            if not res.success:
                continue
            data = res.data

            if summary['balance'] is None and 'balance_trx' in data:
                summary['balance'] = f"{data['balance_trx']:.6f} TRX"
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

            if source == 'exchange_tags' and data.get('tagged'):
                summary['exchange_tag_categories'] = data.get('categories')
                summary['exchange_tag_labels'] = data.get('labels')
                summary['exchange_tag_packs'] = data.get('packs')
                summary['exchange_tag_is_exchange'] = data.get('is_exchange_tagged')

        return summary
