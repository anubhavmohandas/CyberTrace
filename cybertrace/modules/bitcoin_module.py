"""Bitcoin and cryptocurrency OSINT module."""

import re
from datetime import datetime
from typing import Any, Dict, Optional

import aiohttp

from ..integrations import ellipticpp
from .base import BaseModule, ModuleResult, SourceResult


class BitcoinModule(BaseModule):
    """
    Cryptocurrency address investigation.
    
    SUCCESS RATE: 95% - Blockchain is public by design.
    
    Supports:
    - Bitcoin (legacy and bech32)
    - Ethereum
    """
    
    name = "bitcoin"
    description = "Cryptocurrency address analysis"
    supported_types = {'bitcoin', 'ethereum'}
    
    async def search(self, target: str, **options) -> ModuleResult:
        """Search cryptocurrency address across blockchain explorers."""
        
        result = ModuleResult(
            target=target,
            target_type=self._detect_crypto_type(target),
            module=self.name,
        )
        
        if result.target_type == 'bitcoin':
            sources = [
                ('blockchain.com', self._check_blockchain_com(target)),
                ('blockchair', self._check_blockchair(target, 'bitcoin')),
                ('blockstream', self._check_blockstream(target)),
                ('bitcoinabuse', self._check_bitcoin_abuse(target)),
                ('chainabuse', self._check_chainabuse(target, 'BTC')),
                ('ellipticpp', self._check_ellipticpp(target)),
            ]
        elif result.target_type == 'ethereum':
            sources = [
                ('blockchair_eth', self._check_blockchair(target, 'ethereum')),
                ('ethplorer', self._check_ethplorer(target)),
                ('chainabuse', self._check_chainabuse(target, 'ETH')),
            ]
        else:
            sources = []
        
        await self.run_sources(sources, result)
        
        # Build summary
        result.summary = self._build_summary(result)
        result.end_time = datetime.utcnow()
        
        return result
    
    def _detect_crypto_type(self, address: str) -> str:
        """Detect cryptocurrency type from address format."""
        if address.startswith('0x') and len(address) == 42:
            return 'ethereum'
        if address.startswith('bc1'):
            return 'bitcoin'
        if address[0] in '13':
            return 'bitcoin'
        return 'unknown'
    
    async def _check_blockchain_com(self, address: str) -> SourceResult:
        """Query blockchain.com API (no auth needed)."""
        url = f"https://blockchain.info/rawaddr/{address}"
        
        data = await self.fetch_json(url)
        
        if not data:
            return SourceResult(
                source='blockchain.com',
                success=False,
                error='No data returned',
            )
        
        # Parse response
        parsed = {
            'address': data.get('address'),
            'balance_satoshi': data.get('final_balance', 0),
            'balance_btc': data.get('final_balance', 0) / 100_000_000,
            'total_received_satoshi': data.get('total_received', 0),
            'total_received_btc': data.get('total_received', 0) / 100_000_000,
            'total_sent_satoshi': data.get('total_sent', 0),
            'total_sent_btc': data.get('total_sent', 0) / 100_000_000,
            'tx_count': data.get('n_tx', 0),
        }
        
        # Get first and last transaction
        txs = data.get('txs', [])
        if txs:
            parsed['first_seen'] = datetime.fromtimestamp(txs[-1].get('time', 0)).isoformat()
            parsed['last_seen'] = datetime.fromtimestamp(txs[0].get('time', 0)).isoformat()
            
            # Two different relations, deliberately kept apart.
            #
            # co-spend: addresses signed into the SAME transaction's inputs as
            # this one. Spending them together needs both private keys, so under
            # the common-input-ownership heuristic they are one wallet — this is
            # the only relation here that evidences shared control, and it is
            # what evidence.enrich_bitcoin turns into cluster edges.
            #
            # counterparty: everything else the transactions touched. Paying an
            # address says nothing about who owns it, so merging the two (as one
            # 'connected' bag) would cluster every customer of a market into the
            # operator's wallet. `connected_addresses` stays for callers that
            # only want "addresses seen nearby", now flagged as the weak set.
            cospend, counterparty = set(), set()
            for tx in txs[:10]:
                inputs = {inp.get('prev_out', {}).get('addr') for inp in tx.get('inputs', [])}
                inputs.discard(None)
                if address in inputs and len(inputs) > 1:
                    cospend |= inputs - {address}
                else:
                    counterparty |= inputs - {address}
                counterparty |= {o.get('addr') for o in tx.get('out', [])
                                 if o.get('addr') and o.get('addr') != address}
            parsed['cospend_addresses'] = sorted(cospend)[:20]
            parsed['counterparty_addresses'] = sorted(counterparty - cospend)[:20]
            parsed['connected_addresses'] = sorted(cospend | counterparty)[:20]
        
        return SourceResult(
            source='blockchain.com',
            success=True,
            data=parsed,
        )
    
    async def _check_blockchair(self, address: str, chain: str) -> SourceResult:
        """Query Blockchair API (no auth, rate limited)."""
        url = f"https://api.blockchair.com/{chain}/dashboards/address/{address}"
        
        data = await self.fetch_json(url)
        
        if not data or 'data' not in data:
            return SourceResult(
                source=f'blockchair_{chain}',
                success=False,
                error='No data returned',
            )
        
        addr_data = data['data'].get(address, {})
        addr_info = addr_data.get('address', {})
        
        if chain == 'bitcoin':
            parsed = {
                'balance_btc': addr_info.get('balance', 0) / 100_000_000,
                'balance_usd': addr_info.get('balance_usd'),
                'tx_count': addr_info.get('transaction_count', 0),
                'received_btc': addr_info.get('received', 0) / 100_000_000,
                'spent_btc': addr_info.get('spent', 0) / 100_000_000,
                'first_seen': addr_info.get('first_seen_receiving'),
                'last_seen': addr_info.get('last_seen_receiving'),
                'type': addr_info.get('type'),  # pubkey, scripthash, witness_v0_keyhash, etc.
            }
        else:  # ethereum
            parsed = {
                'balance_eth': addr_info.get('balance', 0) / 1e18,
                'balance_usd': addr_info.get('balance_usd'),
                'tx_count': addr_info.get('transaction_count', 0),
                'is_contract': addr_info.get('type') == 'contract',
            }
        
        return SourceResult(
            source=f'blockchair_{chain}',
            success=True,
            data=parsed,
        )
    
    async def _check_blockstream(self, address: str) -> SourceResult:
        """Query Blockstream.info API (no auth)."""
        url = f"https://blockstream.info/api/address/{address}"
        
        data = await self.fetch_json(url)
        
        if not data:
            return SourceResult(
                source='blockstream',
                success=False,
                error='No data returned',
            )
        
        chain_stats = data.get('chain_stats', {})
        mempool_stats = data.get('mempool_stats', {})
        
        parsed = {
            'funded_txo_count': chain_stats.get('funded_txo_count', 0),
            'funded_txo_sum': chain_stats.get('funded_txo_sum', 0) / 100_000_000,
            'spent_txo_count': chain_stats.get('spent_txo_count', 0),
            'spent_txo_sum': chain_stats.get('spent_txo_sum', 0) / 100_000_000,
            'mempool_tx_count': mempool_stats.get('tx_count', 0),
        }
        
        # Calculate current balance
        funded = chain_stats.get('funded_txo_sum', 0)
        spent = chain_stats.get('spent_txo_sum', 0)
        parsed['balance_btc'] = (funded - spent) / 100_000_000
        
        return SourceResult(
            source='blockstream',
            success=True,
            data=parsed,
        )
    
    async def _check_bitcoin_abuse(self, address: str) -> SourceResult:
        """
        Check Cryptoscamdb for scam/abuse reports on this address.

        Cryptoscamdb is a free, community-maintained database of crypto scam
        addresses and domains. The API requires no key for basic lookups.
        Endpoint: https://api.cryptoscamdb.org/v1/check/{address}

        Response shape (success):
          {"success": true, "result": "blocked"|"neutral", "entries": [...]}
        Each entry may contain a "type" field (e.g. "scam", "phishing").
        """
        url = f"https://api.cryptoscamdb.org/v1/check/{address}"

        data = await self.fetch_json(url)

        if data is None:
            return SourceResult(
                source='bitcoinabuse',
                success=False,
                error='No response from Cryptoscamdb',
            )

        if not data.get('success'):
            # API returned success=false — address unknown to the database
            return SourceResult(
                source='bitcoinabuse',
                success=True,
                data={
                    'reported': False,
                    'report_count': 0,
                    'scam_type': None,
                },
            )

        entries = data.get('entries') or []
        result_flag = data.get('result', 'neutral')
        is_flagged = result_flag == 'blocked' or len(entries) > 0

        # Derive scam_type from the first matching entry if available
        scam_type = None
        if entries and isinstance(entries[0], dict):
            scam_type = (
                entries[0].get('type')
                or entries[0].get('category')
                or None
            )

        parsed = {
            'reported': is_flagged,
            'report_count': len(entries) if entries else (1 if is_flagged else 0),
            'scam_type': scam_type,
        }

        return SourceResult(
            source='bitcoinabuse',
            success=True,
            data=parsed,
        )

    async def _check_chainabuse(self, address: str, chain: str) -> SourceResult:
        """
        Check Chainabuse (https://chainabuse.com) for community-submitted
        abuse reports on this address.

        Requires an organization API key — HTTP Basic auth, the same key in
        both the username and password fields (Chainabuse's own convention,
        not this codebase's). CHAINABUSE_API_KEY is unset by default; without
        it this degrades the same way an unset Shodan key does in
        darkweb_module._favicon_pivot.

        A report here is exactly that — a REPORT — never proof of control.
        It rides into `reported_scam`/`scam_report_count` in _build_summary,
        the same non-attributive metadata slot bitcoinabuse already fills, so
        it lands on the address as metadata (evidence.enrich_bitcoin) and
        never becomes an operator-funnel signal.
        """
        key = self.config.api_keys.get('chainabuse')
        if not key:
            return SourceResult(
                source='chainabuse',
                success=False,
                error='no Chainabuse API key configured (set CHAINABUSE_API_KEY)',
            )

        data = await self.fetch_json(
            'https://api.chainabuse.com/v0/reports',
            params={'address': address, 'chain': chain, 'perPage': 20},
            headers={'Authorization': aiohttp.encode_basic_auth(key, key)},
        )
        if data is None:
            return SourceResult(
                source='chainabuse',
                success=False,
                error='No response from Chainabuse',
            )

        reports = data.get('reports') or []
        categories = sorted({
            r['scamCategory'] for r in reports if r.get('scamCategory')
        })
        # createdAt is when the report was FILED, not when the address did
        # anything -- external temporal context about a third party's paperwork,
        # never a sighting of the address itself. See evidence.enrich_bitcoin's
        # chainabuse_* docstring for why this stays a timestamp to display and
        # is never read by the successor/temporal engine.
        report_dates = sorted({
            r['createdAt'] for r in reports if r.get('createdAt')
        })

        return SourceResult(
            source='chainabuse',
            success=True,
            data={
                'reported': bool(reports),
                'report_count': data.get('count', len(reports)),
                'scam_categories': categories,
                'trusted_report_count': sum(1 for r in reports if r.get('trusted')),
                'report_dates': report_dates,
            },
        )

    async def _check_ellipticpp(self, address: str) -> SourceResult:
        """Offline lookup against the local Elliptic++ dataset index (KDD'23
        Bitcoin transaction/wallet graph) -- no network call, just a local
        SQLite read, so it runs beside the live blockchain-explorer sources
        above rather than instead of them.

        A dataset_label here is the *dataset authors'* classification of this
        address in isolation, built for a fraud-detection paper -- it is
        external dataset context, never CyberTrace evidence of who controls
        the address. evidence.enrich_bitcoin writes it as address metadata
        only; see that function's docstring for why no relationship is ever
        created from it. See cybertrace/integrations/ellipticpp.py and
        external_data/ellipticpp/manifest.json for the full safety boundary.

        Degrades the same way chainabuse does without a key: dataset not
        downloaded, or downloaded but not indexed yet (build_index() is a
        deliberate offline step -- see that function's docstring), both
        report success=False with an explanatory error rather than raising.
        """
        if not ellipticpp.available():
            return SourceResult(
                source='ellipticpp', success=False,
                error='Elliptic++ dataset not downloaded locally',
            )
        if not ellipticpp.index_available():
            return SourceResult(
                source='ellipticpp', success=False,
                error='Elliptic++ dataset downloaded but not indexed '
                      '(run ellipticpp.build_index() once, offline)',
            )
        row = ellipticpp.lookup_wallet(address)
        if row is None:
            return SourceResult(
                source='ellipticpp', success=True,
                data={'seen_in_dataset': False},
            )
        return SourceResult(
            source='ellipticpp', success=True,
            data={
                'seen_in_dataset': True,
                'dataset_label': row['dataset_label'],
                'dataset_label_name': row['dataset_label_name'],
                'time_steps': row['time_steps'],
                'record_count': row['record_count'],
                'feature_count': len(row['features']),
            },
        )

    async def _check_ethplorer(self, address: str) -> SourceResult:
        """Query Ethplorer API (no auth for basic)."""
        url = f"https://api.ethplorer.io/getAddressInfo/{address}?apiKey=freekey"
        
        data = await self.fetch_json(url)
        
        if not data or 'error' in data:
            return SourceResult(
                source='ethplorer',
                success=False,
                error=data.get('error', {}).get('message', 'Unknown error') if data else 'No response',
            )
        
        eth_data = data.get('ETH', {})
        parsed = {
            'balance_eth': eth_data.get('balance', 0),
            'tx_count': data.get('countTxs', 0),
            'token_count': len(data.get('tokens', [])),
        }
        
        # List tokens held
        tokens = data.get('tokens', [])
        if tokens:
            parsed['tokens'] = [
                {
                    'symbol': t.get('tokenInfo', {}).get('symbol'),
                    'name': t.get('tokenInfo', {}).get('name'),
                    'balance': t.get('balance', 0),
                }
                for t in tokens[:10]  # Top 10 tokens
            ]
        
        return SourceResult(
            source='ethplorer',
            success=True,
            data=parsed,
        )
    
    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        """Build summary from all source results."""
        summary = {
            'address': result.target,
            'type': result.target_type,
            'balance': None,
            'tx_count': None,
            'first_seen': None,
            'last_seen': None,
            'reported_scam': False,
            'connected_addresses': [],
            # Same-wallet under common-input-ownership; see _check_blockchain_com.
            # Carried in the summary because that is all the darkweb pivot hands
            # back, and it is the half of `connected_addresses` that evidences
            # shared control rather than a payment.
            'cospend_addresses': [],
        }
        
        # Aggregate from sources
        for source, res in result.sources.items():
            if not res.success:
                continue
            
            data = res.data
            
            # Balance (prefer blockchain.com or blockchair)
            if summary['balance'] is None:
                if 'balance_btc' in data:
                    summary['balance'] = f"{data['balance_btc']:.8f} BTC"
                elif 'balance_eth' in data:
                    summary['balance'] = f"{data['balance_eth']:.6f} ETH"
            
            # Transaction count
            if summary['tx_count'] is None and 'tx_count' in data:
                summary['tx_count'] = data['tx_count']
            
            # Timestamps
            if summary['first_seen'] is None and 'first_seen' in data:
                summary['first_seen'] = data['first_seen']
            if summary['last_seen'] is None and 'last_seen' in data:
                summary['last_seen'] = data['last_seen']
            
            # Scam reports
            if data.get('reported'):
                summary['reported_scam'] = True
                summary['scam_report_count'] = data.get('report_count', 0)

            # Chainabuse-specific detail -- category/trusted-count/report_dates
            # exist only in this source's response, so unlike report_count
            # above (which bitcoinabuse also sets) these need their own gate.
            # report_dates is when each report was FILED, external metadata
            # about the report, not a sighting of the address; see
            # evidence.enrich_bitcoin's chainabuse_* docstring.
            if source == 'chainabuse' and data.get('reported'):
                summary['chainabuse_scam_categories'] = data.get('scam_categories')
                summary['chainabuse_trusted_report_count'] = data.get('trusted_report_count')
                summary['chainabuse_report_dates'] = data.get('report_dates')

            # Elliptic++ dataset context -- distilled, non-attributive; see
            # _check_ellipticpp and evidence.enrich_bitcoin. Only set when the
            # source actually ran (source == 'ellipticpp'): 'seen_in_dataset'
            # alone is not enough to key off, since a live source could in
            # principle emit an unrelated field by that name.
            if source == 'ellipticpp' and data.get('seen_in_dataset'):
                summary['ellipticpp_dataset_label'] = data.get('dataset_label')
                summary['ellipticpp_dataset_label_name'] = data.get('dataset_label_name')
                summary['ellipticpp_time_steps'] = data.get('time_steps')
                summary['ellipticpp_record_count'] = data.get('record_count')

            # Connected addresses
            if 'connected_addresses' in data:
                summary['connected_addresses'] = data['connected_addresses']
                # Add to related for further investigation
                result.related.extend(data['connected_addresses'][:5])
            if data.get('cospend_addresses'):
                summary['cospend_addresses'] = data['cospend_addresses']
        
        return summary
