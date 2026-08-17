from cybertrace.modules.base import ModuleResult
from cybertrace.output import format_table


def test_bitcoin_pivot_shows_temporal_fields_and_summary_stays_compact():
    """operator_pivots is a short list of dicts: the SUMMARY section must not
    join it into a raw repr, and the ARTIFACT PIVOTS section must reach past
    tx_count to show first_seen/last_seen without spotlighting the
    connected/cospend address lists (see evidence.py's cospend-only rule)."""
    pivot = {
        'target': '1B7E2o6ALyCtANbJt4KQNdM4BGzYCvyeLR',
        'type': 'bitcoin',
        'sources_ok': '2/4',
        'summary': {
            'address': '1B7E2o6ALyCtANbJt4KQNdM4BGzYCvyeLR',
            'type': 'bitcoin',
            'balance': '0.00000000 BTC',
            'tx_count': 27,
            'first_seen': '2016-01-24T23:45:01',
            'last_seen': '2022-12-11T15:15:38',
            'reported_scam': False,
            'connected_addresses': ['a'] * 20,
            'cospend_addresses': ['b'],
        },
    }
    result = ModuleResult(
        target='hades2....onion', target_type='onion', module='darkweb',
        summary={'operator_pivots': [pivot]},
    )

    table = format_table(result)

    assert 'first_seen: 2016-01-24T23:45:01' in table
    assert 'last_seen: 2022-12-11T15:15:38' in table
    assert "operator_pivots: 1 items" in table
    assert "'connected_addresses': ['a', 'a'" not in table  # no raw dict dump
