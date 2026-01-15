"""Bitcoin and cryptocurrency OSINT module."""

import re
from datetime import datetime
from typing import Any, Dict, Optional

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
            ]
        elif result.target_type == 'ethereum':
            sources = [
                ('blockchair_eth', self._check_blockchair(target, 'ethereum')),
                ('ethplorer', self._check_ethplorer(target)),
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
            
            # Extract connected addresses (first 10 transactions)
            connected = set()
            for tx in txs[:10]:
                for inp in tx.get('inputs', []):
                    prev = inp.get('prev_out', {})
                    addr = prev.get('addr')
                    if addr and addr != address:
                        connected.add(addr)
                for out in tx.get('out', []):
                    addr = out.get('addr')
                    if addr and addr != address:
                        connected.add(addr)
            parsed['connected_addresses'] = list(connected)[:20]
        
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
        """Check BitcoinAbuse for scam reports."""
        url = f"https://www.bitcoinabuse.com/api/reports/check?address={address}"
        
        data = await self.fetch_json(url)
        
        if data is None:
            return SourceResult(
                source='bitcoinabuse',
                success=False,
                error='API error or address not found',
            )
        
        parsed = {
            'reported': data.get('count', 0) > 0,
            'report_count': data.get('count', 0),
        }
        
        return SourceResult(
            source='bitcoinabuse',
            success=True,
            data=parsed,
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
            
            # Connected addresses
            if 'connected_addresses' in data:
                summary['connected_addresses'] = data['connected_addresses']
                # Add to related for further investigation
                result.related.extend(data['connected_addresses'][:5])
        
        return summary
