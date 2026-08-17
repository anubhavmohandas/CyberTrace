"""Evidence-graph tests: build shape, confidence-by-provenance, cross-market reuse."""

from cybertrace.graph import (
    EvidenceGraph, build_graph, build_graph_from_dict, CONFIDENCE_RANK,
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


def test_build_graph_from_dict_matches_object_path():
    r = _result('a.onion', bitcoin_addresses=['1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'])
    from_obj = build_graph(r).to_dict()
    from_dict = build_graph_from_dict(r.to_dict()).to_dict()
    assert {n['id'] for n in from_obj['nodes']} == {n['id'] for n in from_dict['nodes']}


def test_quoted_artifacts_never_cluster_two_markets():
    """A quoted third-party address must never read as the market's own artifact.
    Cross-market attribution runs through the governed EvidenceStore engine
    (cybertrace/correlate.py), not this module — but EvidenceGraph is still
    built per-search (see darkweb_module.py's evidence_graph summary field),
    so its node/edge construction must not credit a quoted email to the
    market that merely quoted it, or seed a username node from it.
    """
    a, b = 'a' * 56 + '.onion', 'b' * 56 + '.onion'
    graph = EvidenceGraph()
    for onion in (a, b):
        build_graph_from_dict({
            'target': onion,
            'sources': {'target_onion': {'success': True, 'timestamp': '2026-08-14',
                'data': {'online': True,
                         'emails': ['amrounix@gmail.com', f'admin@{onion[:6]}.cc'],
                         'artifact_evidence': {
                             'amrounix@gmail.com': {'section': 'quoted'},
                             f'admin@{onion[:6]}.cc': {'section': 'contact'}}}}},
        }, graph)

    quoted = graph.nodes[EvidenceGraph.node_id('EMAIL', 'amrounix@gmail.com')]
    assert quoted['markets'] == [], "quoted address belongs to whoever was quoted"
    # …and it must not have seeded a handle for the pivot chain either.
    assert EvidenceGraph.node_id('USERNAME', 'amrounix') not in graph.nodes
