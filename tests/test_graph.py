"""Evidence-graph tests: build shape, confidence-by-provenance, cross-market reuse."""

from cybertrace.graph import (
    EvidenceGraph, build_graph, build_graph_from_dict, correlate, CONFIDENCE_RANK,
)
from cybertrace.modules.base import ModuleResult, SourceResult


def _result(target, **onion_data):
    r = ModuleResult(target=target, target_type='darkweb', module='darkweb')
    r.sources['target_onion'] = SourceResult(
        source='target_onion', success=True, data={'online': True, **onion_data}
    )
    return r


def test_build_graph_shape_and_confidence():
    r = _result(
        'abc.onion',
        title='Shop',
        emails=['darkoperator@proton.me'],
        bitcoin_addresses=['1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'],
        pgp_keys=[{'key_id': 'deadbeefdeadbeef'}],
        leaked_public_ipv4=['8.8.8.8'],
        candidate_operator_ips=['8.8.8.8', '1.1.1.1'],
        favicon={'shodan_matches': [{'ip': '1.1.1.1', 'org': 'ExampleHost'}]},
    )
    g = build_graph(r)
    d = g.to_dict()
    types = {n['type'] for n in d['nodes']}
    assert {'MARKET', 'ONION_ADDRESS', 'EMAIL', 'USERNAME', 'CRYPTO_ADDRESS',
            'PGP_KEY', 'IP', 'PROVIDER'} <= types

    rels = {(e['rel'], e['to'].split(':', 1)[0]) for e in d['edges']}
    assert ('MENTIONS_EMAIL', 'EMAIL') in rels
    assert ('HANDLE_OF', 'USERNAME') in rels  # local-part -> handle
    assert ('USES_PGP', 'PGP_KEY') in rels
    assert ('HOSTED_BY', 'PROVIDER') in rels

    conf = {e['to']: e['confidence'] for e in d['edges'] if e['rel'] == 'CANDIDATE_IP'}
    # leaked IP is a real-host slip -> strong; favicon-only match -> moderate
    assert conf['IP:8.8.8.8'] == 'strong'
    assert conf['IP:1.1.1.1'] == 'moderate'


def test_build_graph_empty_when_no_live_onion():
    r = ModuleResult(target='x.onion', target_type='darkweb', module='darkweb')
    r.sources['target_onion'] = SourceResult('target_onion', success=False, error='down')
    assert build_graph(r).to_dict() == {'nodes': [], 'edges': []}


def test_cross_market_reuse_collapses_to_one_node():
    shared = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
    g = build_graph(_result('market_a.onion', bitcoin_addresses=[shared]))
    g = build_graph(_result('market_b.onion', bitcoin_addresses=[shared]), graph=g)

    btc = [n for n in g.nodes.values() if n['type'] == 'CRYPTO_ADDRESS']
    assert len(btc) == 1                       # one node, not two
    assert len(btc[0]['markets']) == 2         # reused across both markets


def test_corroboration_bumps_confidence_one_tier():
    g = EvidenceGraph()
    a, b = g.add_node('EMAIL', 'x@y.com'), g.add_node('USERNAME', 'x')
    g.add_edge(a, b, 'HANDLE_OF', 'source_one', 't0')      # weak
    g.add_edge(a, b, 'HANDLE_OF', 'source_two', 't1')      # +independent source
    edge = g.edges[0]
    assert len(edge['sources']) == 2
    assert CONFIDENCE_RANK[edge['confidence']] == CONFIDENCE_RANK['moderate']  # weak -> moderate


def test_correlate_ranks_and_scores_operator_candidates():
    key = {'key_id': 'deadbeefdeadbeef'}
    shared_btc = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
    # A + B share a PGP key AND a BTC address -> two corroborating types -> bumped
    g = build_graph(_result('a.onion', pgp_keys=[key], bitcoin_addresses=[shared_btc]))
    g = build_graph(_result('b.onion', pgp_keys=[key], bitcoin_addresses=[shared_btc]), graph=g)
    # C + D share only a username (via email local-part) -> weak, flagged
    g = build_graph(_result('c.onion', emails=['darkoperator@proton.me']), graph=g)
    g = build_graph(_result('d.onion', emails=['darkoperator@tuta.io']), graph=g)

    cands = correlate(g)['operator_candidates']
    assert len(cands) == 2
    # strongest cluster ranked first: shared strong PGP + moderate BTC -> very_strong
    assert set(cands[0]['markets']) == {'a.onion', 'b.onion'}
    assert cands[0]['confidence'] == 'very_strong'
    # weak-only cluster is surfaced but flagged
    weak = cands[1]
    assert set(weak['markets']) == {'c.onion', 'd.onion'}
    assert weak['confidence'] == 'weak' and 'corroborate' in weak['note']


def test_page_section_carries_evidence_and_promotes_confidence():
    addr = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
    g = build_graph(_result(
        'a.onion',
        bitcoin_addresses=[addr],
        emails=['ops@shop.example'],
        artifact_evidence={
            addr: {'section': 'wallet', 'context': 'Donate BTC: 1BvB…'},
            'ops@shop.example': {'section': 'body', 'context': 'as noted by ops@…'},
        },
    ))
    edges = {e['rel']: e for e in g.to_dict()['edges']}

    # in a donate block: the operator's own address -> moderate bumped to strong
    btc = edges['USES_CRYPTO']
    assert btc['confidence'] == 'strong'
    assert btc['section'] == 'wallet'
    assert 'Donate BTC' in btc['context']

    # mentioned in passing prose: no promotion, keeps its default tier
    assert edges['MENTIONS_EMAIL']['confidence'] == 'moderate'


def test_missing_evidence_leaves_confidence_unchanged():
    # Results saved before artifact_evidence existed must still fold cleanly.
    g = build_graph(_result('a.onion', bitcoin_addresses=['1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2']))
    edge = [e for e in g.to_dict()['edges'] if e['rel'] == 'USES_CRYPTO'][0]
    assert edge['confidence'] == 'moderate'
    assert 'section' not in edge


def test_correlate_empty_without_shared_artifacts():
    g = build_graph(_result('solo.onion', emails=['unique@x.com']))
    assert correlate(g)['operator_candidates'] == []


def test_build_graph_from_dict_matches_object_path():
    r = _result('a.onion', bitcoin_addresses=['1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'])
    from_obj = build_graph(r).to_dict()
    from_dict = build_graph_from_dict(r.to_dict()).to_dict()
    assert {n['id'] for n in from_obj['nodes']} == {n['id'] for n in from_dict['nodes']}
