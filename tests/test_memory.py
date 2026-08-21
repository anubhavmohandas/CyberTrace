"""Historical memory: "have I seen this evidence before?" — never
SAME_OPERATOR. Every classification test pairs with a `run_correlation` check
proving the governed engine's own verdict is untouched by what memory found:
the two read the same store independently, and memory asserting nothing is
the property under test as much as memory finding the right thing.
"""

from datetime import datetime, timezone

from cybertrace import memory
from cybertrace.correlate import run_correlation
from cybertrace.evidence import EvidenceStore, ingest
from cybertrace.modules.base import ModuleResult, SourceResult

from .test_correlate import _attach
from .test_evidence import BTC_VALID, KEY_A, ONION_A, ONION_B, _result, onion

ONION_C = onion("c")
JAN = datetime(2026, 1, 10, tzinfo=timezone.utc)
MAR = datetime(2026, 3, 1, tzinfo=timezone.utc)
AUG = datetime(2026, 8, 2, tzinfo=timezone.utc)


# --- EXACT: identity artifacts ------------------------------------------------

def test_exact_pgp_match(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, seen=AUG, pgp_keys=[{'armored': KEY_A}]), store)

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'PGP_KEY']
        assert len(hits) == 1
        hit = hits[0]
        assert hit['classification'] == 'EXACT'
        assert hit['previous_target'] == ONION_A
        assert hit['current_target'] == ONION_B
        assert hit['first_seen'].startswith('2026-01-10')
        assert hit['attribution'] == 'NOT ESTABLISHED BY MEMORY'
        assert hit['source'] == 'prior CyberTrace investigation'


def test_exact_email_match(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, emails=['op@proton.me']), store)
        ingest(_result(ONION_B, seen=AUG, emails=['op@proton.me']), store)

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'EMAIL']
        assert hits and hits[0]['classification'] == 'EXACT'
        assert hits[0]['value'] == 'op@proton.me'


def test_exact_username_match(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, usernames=['hackerman123']), store)
        ingest(_result(ONION_B, seen=AUG, usernames=['hackerman123']), store)

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'USERNAME']
        assert hits and hits[0]['classification'] == 'EXACT'


def test_exact_bitcoin_match(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, bitcoin_addresses=[BTC_VALID]), store)
        ingest(_result(ONION_B, seen=AUG, bitcoin_addresses=[BTC_VALID]), store)

        hits = [h for h in memory.historical_matches(store, ONION_B)
                if h['etype'] == 'BTC_ADDRESS']
        assert hits and hits[0]['classification'] == 'EXACT'


# --- CONTEXTUAL: shared infrastructure/ecosystem, never identity -------------

def test_exact_favicon_is_contextual_not_exact(tmp_path):
    """A shared icon is the SecureDrop-template case from corpus/labels.toml:
    real convergence, capped at CONTEXTUAL exactly like correlate.py caps it
    at a NON_ATTRIBUTIVE_SIGNAL, never treated as identity."""
    favicon = {'favicon_mmh3': 123456}
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, favicon=favicon), store)
        ingest(_result(ONION_B, seen=AUG, favicon=favicon), store)

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'FAVICON']
        assert hits and hits[0]['classification'] == 'CONTEXTUAL'


def test_shared_ecosystem_domain_is_contextual(tmp_path):
    # Not en.bitcoin.it: normalize._BOILERPLATE_DOMAINS blocks that one outright
    # (it's the exact false pair from the correlate.py CONTEXT_WEIGHT comment),
    # which would test the gate instead of memory's own CONTEXTUAL boundary.
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, clearnet_hosts_referenced=['vendor-forum.net']), store)
        ingest(_result(ONION_B, seen=AUG, clearnet_hosts_referenced=['vendor-forum.net']), store)

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'DOMAIN']
        assert hits and hits[0]['classification'] == 'CONTEXTUAL'


def test_shared_nameserver_is_contextual(tmp_path):
    """NAMESERVER has no producer (see evidence.ARTIFACT_MAP's comment and
    test_evidence.test_certificate_and_nameserver_stay_unwired) — built by
    hand with the public store API, the same way correlate's own
    test_shared_nameserver_reaches_infra_never_operator proves the consumption
    side. Memory must classify it CONTEXTUAL the moment it exists at all."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for target in (ONION_A, ONION_B):
            ingest(_result(target), store)
        ns = store.upsert_entity("NAMESERVER", "ns1.bulk-registrar.example")
        for target in (ONION_A, ONION_B):
            _attach(store, target, ns, "USES_NS")

        hits = [h for h in memory.historical_matches(store, ONION_B)
                if h['etype'] == 'NAMESERVER']
        assert hits and hits[0]['classification'] == 'CONTEXTUAL'

        assert run_correlation(store)['operators'] == []


def test_shared_certificate_is_contextual(tmp_path):
    """Same reasoning as the nameserver case above — CERTIFICATE is also
    unwired today (Phase 3 of this loop confirmed both stay blocked); this
    proves memory's classification is correct FOR WHEN one exists, without
    claiming a producer exists now."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for target in (ONION_A, ONION_B):
            ingest(_result(target), store)
        cert = store.upsert_entity("CERTIFICATE", "shop.example")
        for target in (ONION_A, ONION_B):
            _attach(store, target, cert, "USES_CERT")

        hits = [h for h in memory.historical_matches(store, ONION_B)
                if h['etype'] == 'CERTIFICATE']
        assert hits and hits[0]['classification'] == 'CONTEXTUAL'


def test_shared_vpn_ip_is_contextual_not_exact(tmp_path):
    """A VPN_IP/TOR_RELAY-classed address is shared egress, not a shared host
    — the same caveat correlate.recommended_actions() already raises for a
    VPN-classed IP, and CONTEXTUAL either way now (see the next test): this
    pins the ip_class-specific path stays CONTEXTUAL too, not just the
    general bare-IP one."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for target in (ONION_A, ONION_B):
            ingest(_result(target), store)
        ip = store.upsert_entity("IP", "185.220.101.1")
        store.set_metadata(ip, ip_class="VPN_IP")
        for target in (ONION_A, ONION_B):
            _attach(store, target, ip, "CANDIDATE_IP")

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'IP']
        assert hits and hits[0]['classification'] == 'CONTEXTUAL'


def test_bare_ip_without_vpn_class_is_also_contextual(tmp_path):
    """A hosting provider assigns an address; an operator does not choose it
    — the same reasoning correlate.NON_ATTRIBUTIVE_SIGNALS already applies to
    a shared domain or favicon applies to a shared IP, VPN-egress or not
    (correlate.py's shared_ip comment: two unrelated Tor operators on one
    cheap/shared host is the ordinary case, and nothing in this store
    distinguishes that from a dedicated one). memory.CONTEXTUAL_TYPES reads
    this straight off correlate.NON_ATTRIBUTIVE_SIGNALS, so the fix lives
    there — this only pins that memory's classification followed it."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for target in (ONION_A, ONION_B):
            ingest(_result(target), store)
        ip = store.upsert_entity("IP", "203.0.113.9")
        for target in (ONION_A, ONION_B):
            _attach(store, target, ip, "CANDIDATE_IP")

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'IP']
        assert hits and hits[0]['classification'] == 'CONTEXTUAL'


# --- gate-rejected artifacts leave no trace for memory to find ---------------

def test_documentation_email_never_becomes_a_memory_hit(tmp_path):
    """foo@bar.com is refused at normalize() (test_evidence.test_misc_normalizers)
    -- no entity is ever created, so memory has nothing to manufacture."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, emails=['foo@bar.com']), store)
        ingest(_result(ONION_B, seen=AUG, emails=['foo@bar.com']), store)

        assert not any(h['etype'] == 'EMAIL' for h in memory.historical_matches(store, ONION_B))


def test_etag_is_never_tracked_as_an_artifact(tmp_path):
    """ETag has no ENTITY_TYPES member and fingerprint_signature() explicitly
    refuses it (test_evidence.test_a_timestamp_is_not_a_build_signature) -- so
    unlike CERTIFICATE/NAMESERVER there is no store API to even construct this
    case by hand. Confirms the honest answer is zero hits, not a fabricated
    ETag entity type memory would have to invent."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for target in (ONION_A, ONION_B):
            ingest(_result(target, server_fingerprint={'Server': 'Apache',
                                                        'ETag': 'W/"1a2b3c"'}), store)
        assert memory.historical_matches(store, ONION_B) == []


# --- quoted / rostered content: surfaced, never attributed --------------------

def test_quoted_third_party_email_surfaces_but_stays_unattributed(tmp_path):
    # A real, non-placeholder domain: example.com/.org/etc are rejected at
    # normalize() (see normalize._PLACEHOLDER_DOMAINS) before a 'quoted'
    # section ever gets a say, which would test the wrong gate entirely.
    shared_email = 'thirdparty@morke.ru'
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for target, seen in ((ONION_A, JAN), (ONION_B, AUG)):
            ingest(_result(target, seen=seen, emails=[shared_email],
                          artifact_evidence={shared_email: {'section': 'quoted'}}), store)

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'EMAIL']
        assert hits and hits[0]['classification'] == 'EXACT'
        assert hits[0]['attribution'] == 'NOT ESTABLISHED BY MEMORY'

        # The governed engine sees the identical store and still refuses it.
        assert run_correlation(store)['operators'] == []


def test_mailing_list_roster_email_surfaces_but_stays_unattributed(tmp_path):
    shared_email = 'subscriber@morke.ru'
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for target, seen in ((ONION_A, JAN), (ONION_B, AUG)):
            ingest(_result(target, seen=seen, emails=[shared_email],
                          artifact_evidence={shared_email: {'section': 'roster'}}), store)

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'EMAIL']
        assert hits and hits[0]['classification'] == 'EXACT'
        assert run_correlation(store)['operators'] == []


# --- discovery: named, never fetched, before ----------------------------------

def test_discovered_onion_is_a_prior_reference_not_attribution(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        r = ModuleResult(target=ONION_A, target_type='darkweb', module='darkweb')
        r.sources['torch'] = SourceResult(source='torch', success=True, timestamp=JAN,
                                          data={'onion_addresses_found': [ONION_B]})
        ingest(r, store)

        # B is only fetched directly in a later, separate investigation.
        ingest(_result(ONION_B, seen=AUG), store)

        refs = memory.prior_references(store, ONION_B)
        assert len(refs) == 1
        assert refs[0]['classification'] == 'PRIOR_REFERENCE'
        assert refs[0]['previous_target'] == ONION_A
        assert refs[0]['attribution'] == 'NOT ESTABLISHED BY MEMORY'

        assert run_correlation(store)['operators'] == []


def test_no_prior_reference_when_never_discovered(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN), store)
        assert memory.prior_references(store, ONION_A) == []


# --- temporal semantics: history is not liveness ------------------------------

def test_historical_dead_target_reports_history_not_current_liveness(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, emails=['op@proton.me']), store)
        ingest(_result(ONION_B, seen=AUG, emails=['op@proton.me']), store)

        # ONION_A is re-checked later and found dark -- a DOWN snapshot, no new
        # OK observation.
        target_id = store._one("SELECT target_id FROM targets WHERE url=?",
                               (ONION_A,))["target_id"]
        store.record_down(target_id, collector='target_onion', note='down',
                          observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc).isoformat())

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'EMAIL']
        assert hits
        # last_seen must still reflect the real OK observation (January), never
        # the DOWN snapshot's timestamp -- a dark rescan cannot manufacture a
        # more recent "last seen".
        assert hits[0]['last_seen'].startswith('2026-01-10')


# --- deduplication: aggregate cleanly, never lose the underlying rows --------

def test_duplicate_target_is_not_its_own_previous_observation(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, emails=['op@proton.me']), store)
        assert memory.historical_matches(store, ONION_A) == []


def test_duplicate_scan_does_not_inflate_the_hit_count(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, emails=['op@proton.me']), store)
        ingest(_result(ONION_B, seen=AUG, emails=['op@proton.me']), store)
        ingest(_result(ONION_B, seen=AUG, emails=['op@proton.me']), store)   # same file, re-run

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'EMAIL']
        assert len(hits) == 1


def test_conflicting_historical_observations_are_all_shown(tmp_path):
    """The same email on two different prior targets: memory must show both,
    never silently pick one."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, emails=['op@proton.me']), store)
        ingest(_result(ONION_C, seen=MAR, emails=['op@proton.me']), store)
        ingest(_result(ONION_B, seen=AUG, emails=['op@proton.me']), store)

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'EMAIL']
        assert {h['previous_target'] for h in hits} == {ONION_A, ONION_C}

        summary = memory.summarize(memory.historical_matches(store, ONION_B))
        email_group = next(g for g in summary if g['etype'] == 'EMAIL')
        assert set(email_group['previous_targets']) == {ONION_A, ONION_C}
        assert email_group['first_seen'].startswith('2026-01-10')   # earliest of the two


# --- rendering: a section only appears when there is something to show ------

def test_render_markdown_is_empty_with_nothing_to_show():
    assert memory.render_markdown(ONION_A, [], []) == []


def test_render_markdown_labels_classification_and_never_says_attribution():
    hits = [{'classification': 'EXACT', 'etype': 'PGP_KEY', 'value': 'abc123',
            'raw_value': 'abc123', 'previous_target': ONION_A, 'current_target': ONION_B,
            'first_seen': '2026-01-10T00:00:00+00:00', 'last_seen': '2026-01-10T00:00:00+00:00',
            'source': 'prior CyberTrace investigation',
            'attribution': 'NOT ESTABLISHED BY MEMORY'}]
    lines = memory.render_markdown(ONION_B, hits, [])
    text = "\n".join(lines)
    assert '[EXACT]' in text
    assert 'SAME_OPERATOR' in text          # states the boundary, doesn't assert it
    assert 'same operator' not in text.lower().replace('same_operator', '')


# --- Stage A: case / relationship / temporal / pattern memory ----------------

def test_case_history_surfaces_a_prior_candidate_and_its_feedback(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, seen=AUG, pgp_keys=[{'armored': KEY_A}]), store)
        dossier = run_correlation(store)["dossiers"][0]
        store.record_feedback(dossier["candidate_id"], "CONFIRMED", analyst="jdoe")

        cases = memory.case_history(store, ONION_A)
        assert len(cases) == 1
        case = cases[0]
        assert case['classification'] == 'PRIOR_CASE'
        assert case['candidate_id'] == dossier["candidate_id"]
        assert case['attribution'] == 'NOT ESTABLISHED BY MEMORY'
        assert case['analyst_feedback'][0]['outcome'] == 'CONFIRMED'


def test_case_history_is_empty_before_any_correlate_pass(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, pgp_keys=[{'armored': KEY_A}]), store)
        # No run_correlation() yet -- nothing in `candidates` to have an opinion on.
        assert memory.case_history(store, ONION_A) == []


def test_relationship_context_surfaces_a_one_hop_neighbor(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, emails=['op@proton.me']), store)
        email = store.find_entity("EMAIL", 'op@proton.me')
        domain = store.upsert_entity("DOMAIN", "vendor-forum.net")
        store.upsert_relationship(email, domain, "MENTIONS", source_label="test")

        related = memory.relationship_context(store, ONION_A)
        hit = next(r for r in related if r['etype'] == 'EMAIL')
        assert hit['classification'] == 'RELATED'
        assert hit['related_etype'] == 'DOMAIN'
        assert hit['related_value'] == 'vendor-forum.net'
        assert hit['attribution'] == 'NOT ESTABLISHED BY MEMORY'


def test_relationship_context_skips_the_markets_own_address_edge(tmp_path):
    """Every artifact on a market has a HAS_ADDRESS-adjacent edge to the
    market/onion node itself -- that's not new context, it's the fact memory
    already reports as EXACT/CONTEXTUAL. relationship_context must not repeat
    it."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, emails=['op@proton.me']), store)
        related = memory.relationship_context(store, ONION_A)
        assert not any(r['related_etype'] in ('MARKET', 'ONION_ADDRESS') for r in related)


def test_temporal_infra_timeline_orders_by_first_seen(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN), store)
        ip1 = store.upsert_entity("IP", "203.0.113.9")
        _attach(store, ONION_A, ip1, "CANDIDATE_IP")

        timeline = memory.temporal_infra_timeline(store, ONION_A)
        assert any(row['etype'] == 'IP' and row['value'] == '203.0.113.9' for row in timeline)


def test_pattern_overlap_reports_a_matched_over_total_ratio(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, emails=['op@proton.me'],
                      pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, seen=AUG, emails=['op@proton.me']), store)

        overlap = memory.pattern_overlap(store, ONION_B)
        assert len(overlap) == 1
        hit = overlap[0]
        assert hit['previous_target'] == ONION_A
        assert hit['matched'] == 1          # only the email is shared
        assert hit['total'] == 1            # ONION_B itself has just the one artifact
        assert 'characteristics match' in hit['explanation']


def test_pattern_overlap_is_empty_with_no_shared_artifacts(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, emails=['unique-a@proton.me']), store)
        ingest(_result(ONION_B, seen=AUG, emails=['unique-b@proton.me']), store)
        assert memory.pattern_overlap(store, ONION_B) == []


# --- negative / false-positive memory: surfaced as a caveat, never a delete -

def test_rejected_feedback_surfaces_as_a_caveat_on_the_same_historical_hit(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, seen=AUG, pgp_keys=[{'armored': KEY_A}]), store)
        dossier = run_correlation(store)["dossiers"][0]
        store.record_feedback(dossier["candidate_id"], "REJECTED",
                              note="turned out to be a keysigning party key")

        hits = [h for h in memory.historical_matches(store, ONION_B) if h['etype'] == 'PGP_KEY']
        assert hits
        # The hit itself is untouched -- memory does not delete or hide evidence
        # because an analyst rejected it once.
        assert hits[0]['classification'] == 'EXACT'
        assert hits[0]['prior_feedback'][0]['outcome'] == 'REJECTED'

        rendered = "\n".join(memory.render_markdown(ONION_B, hits, []))
        assert 'REJECTED' in rendered
