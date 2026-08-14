"""M5 correlation: funnel convergence, successor direction, clone suppression.

Offline throughout — every scenario is seeded through `ingest()`, so what is
under test is the same path a real crawl takes.
"""

from datetime import datetime, timezone

from cybertrace.correlate import (
    COMMON_ARTIFACT_FLOOR, canonical_entity_key, candidate_infra, candidate_operators,
    confidence_level, contradictions_from_identity, crypto_clusters, detect_successors,
    entity_discrimination, entity_funnel_profile, markets_for_entity,
    render_dossier_html, render_html, render_markdown, run_correlation,
    username_aliases,
)
from cybertrace.evidence import EvidenceStore, enrich_email, ingest
from cybertrace.modules.base import ModuleResult, SourceResult
from cybertrace.modules.darkweb_module import DarkwebModule
from cybertrace.monitor import candidate_deltas

from .test_evidence import BTC_VALID, KEY_A, KEY_B, ONION_A, ONION_B, _result, onion

JAN = datetime(2026, 1, 10, tzinfo=timezone.utc)
AUG = datetime(2026, 8, 2, tzinfo=timezone.utc)


def _two_markets(store, *, clone: bool):
    """Two markets sharing a key. `clone` decides whether the later site is a
    copy of the earlier one or an unrelated-looking rebuild.

    The first market is recorded dark before the second appears, which is what
    makes this a succession scenario rather than merely two linked sites: a gap
    between captures is collection order, and only an observed takedown turns it
    into a handoff.
    """
    ingest(_result(ONION_A, seen=JAN, title='OldShop', emails=['op@proton.me'],
                   bitcoin_addresses=[BTC_VALID], pgp_keys=[{'armored': KEY_A}]), store)
    store.record_down(store._one("SELECT target_id FROM targets WHERE url=?",
                                 (ONION_A,))["target_id"],
                      collector='target_onion', note='Onion unreachable via Tor',
                      observed_at=datetime(2026, 6, 1, tzinfo=timezone.utc).isoformat())
    later = (dict(title='OldShop', emails=['op@proton.me'], bitcoin_addresses=[BTC_VALID])
             if clone else dict(title='NewPlace', analytics_ids=['UA-1234-1']))
    ingest(_result(ONION_B, seen=AUG, pgp_keys=[{'armored': KEY_A}], **later), store)


# --- convergence -------------------------------------------------------------

def test_funnel_profile_scores_from_observation_confidence(tmp_path):
    """Edges written by ingest carry no weight, so strength has to come from the
    observations. Scoring on relationships.weight would rank nothing at all."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, emails=['op@proton.me'], bitcoin_addresses=[BTC_VALID],
                       pgp_keys=[{'armored': KEY_A}]), store)
        assert store._one("SELECT weight FROM relationships LIMIT 1")["weight"] is None

        key = store.find_entity("PGP_KEY", KEY_A)
        profile = entity_funnel_profile(store, key)
        assert profile["funnels"]["f2_pgp_reuse"]["best_conf"] > 0
        assert profile["total_conf"] > 0
        assert profile["markets"]


def test_a_second_funnel_compounds_the_score(tmp_path):
    """Noisy-OR: an independent second funnel must raise an entity's score above
    what either funnel reaches alone. Priors still separate funnel classes — a
    reused key outranks a contact address — so this compares an entity to
    itself, which is the only comparison the model actually claims."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, emails=['op@proton.me']), store)
        email = store.find_entity("EMAIL", 'op@proton.me')
        before = entity_funnel_profile(store, email)

        domain = store.upsert_entity("DOMAIN", "shop.dnmx.cc")
        store.upsert_relationship(email, domain, "MENTIONS", source_label="test", weight=0.7)
        after = entity_funnel_profile(store, email)

        assert before["n_funnels"] == 1 and after["n_funnels"] == 2
        assert after["total_conf"] > before["total_conf"]
        assert after["total_conf"] > max(
            f["best_conf"] for f in after["funnels"].values())


def test_funnel_priors_rank_a_reused_key_over_a_contact_address(tmp_path):
    """Weights encode a domain prior, not calibration: a published key is closer
    to identity than an address scraped off the same page."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, emails=['op@proton.me'], pgp_keys=[{'armored': KEY_A}]), store)
        key = entity_funnel_profile(store, store.find_entity("PGP_KEY", KEY_A))
        email = entity_funnel_profile(store, store.find_entity("EMAIL", 'op@proton.me'))
        assert key["n_funnels"] == email["n_funnels"] == 1
        assert key["total_conf"] > email["total_conf"]


def test_operator_candidates_ranked_and_filtered(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _two_markets(store, clone=False)
        cands = candidate_operators(store, min_conf=0.35)
        assert cands and cands[0]["role"] == "OPERATOR"
        assert [c["score"] for c in cands] == sorted((c["score"] for c in cands), reverse=True)
        key = next(c for c in cands if c["etype"] == "PGP_KEY")
        assert len(key["markets"]) == 2          # the reused key spans both markets
        assert candidate_operators(store, min_conf=0.999) == []


def test_single_market_artifact_is_evidence_but_not_an_operator(tmp_path):
    """The structural rule: convergence is what makes an artifact an attribution
    claim. A strong key on one site stays a first-class entity with its
    observations intact — it just isn't a candidate operator, because there is
    no second market for it to be the link to."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, emails=['op@proton.me'],
                       pgp_keys=[{'armored': KEY_A}]), store)
        key = store.find_entity("PGP_KEY", KEY_A)

        assert key is not None                                # entity: yes
        assert entity_funnel_profile(store, key)["total_conf"] > 0.35   # scores well
        assert candidate_operators(store) == []               # candidate: no

        ingest(_result(ONION_B, pgp_keys=[{'armored': KEY_A}]), store)
        assert key in {c["entity_id"] for c in candidate_operators(store)}


def test_market_floor_counts_a_key_cited_by_id_on_the_second_market(tmp_path):
    """The alias fold has to carry observations, not just score. Market A
    publishes the key, market B cites only its long id — that is exactly the
    cross-market convergence the floor exists to catch, so folding the alias
    away without its market would turn the fix into a false negative."""
    from cybertrace.normalize import norm_pgp

    with EvidenceStore(str(tmp_path / "e.db")) as store:
        fpr = norm_pgp(KEY_A).removeprefix("PGP:")
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, pgp_keys=[{'key_id': fpr[-16:]}]), store)

        real = store.find_entity("PGP_KEY", KEY_A)
        cand = next((c for c in candidate_operators(store) if c["entity_id"] == real), None)
        assert cand is not None and cand["n_markets"] == 2


def test_infra_requires_two_markets_and_more_than_a_reference(tmp_path):
    """Both floors, and why the second one exists: a host two markets merely
    link to satisfies the market floor while being nobody's infrastructure. It
    becomes a candidate only when an edge implies control — here, resolution."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, clearnet_hosts_referenced=['shared.dnmx.cc',
                                                           'only-a.dnmx.cc']), store)
        ingest(_result(ONION_B, clearnet_hosts_referenced=['shared.dnmx.cc']), store)
        assert candidate_infra(store, min_markets=2) == []       # referenced only

        host = store.find_entity("DOMAIN", 'shared.dnmx.cc')
        for onion in (ONION_A, ONION_B):
            store.upsert_relationship(store.find_entity("MARKET", onion), host,
                                      "RESOLVES_TO", source_label="test", weight=0.8)
        values = {c["value"] for c in candidate_infra(store, min_markets=2)}
        assert values == {'shared.dnmx.cc'}


# --- resolution --------------------------------------------------------------

def test_key_id_resolves_to_the_fingerprint_that_owns_it(tmp_path):
    """The one merge M5 may make: a fingerprint's low 64 bits ARE the long key
    id, so the fingerprint is itself the proof the two are one key. An unmatched
    key id stays its own node."""
    from cybertrace.normalize import norm_pgp

    with EvidenceStore(str(tmp_path / "e.db")) as store:
        fpr = norm_pgp(KEY_A).removeprefix("PGP:")
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A},
                                          {'key_id': fpr[-16:]},
                                          {'key_id': 'deadbeefdeadbeef'}]), store)
        real = store.find_entity("PGP_KEY", KEY_A)
        alias = store.find_entity("PGP_KEY", fpr[-16:])
        orphan = store.find_entity("PGP_KEY", 'deadbeefdeadbeef')

        assert alias != real                                  # stored separately
        assert canonical_entity_key(store, alias) == real     # but resolves onto it
        assert canonical_entity_key(store, orphan) == orphan  # nothing proves a merge
        # The alias must not also be ranked as an operator in its own right.
        assert alias not in {c["entity_id"] for c in candidate_operators(store)}


def test_username_aliases_are_reported_not_merged(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, usernames=['dread_operator']), store)
        ingest(_result(ONION_B, usernames=['dread_0perator', 'totally_unrelated']), store)
        pairs = username_aliases(store)
        assert len(pairs) == 1 and pairs[0]["similarity"] >= 0.82
        assert {pairs[0]["a_value"], pairs[0]["b_value"]} == {'dread_operator', 'dread_0perator'}
        # Reported only: both survive as distinct entities.
        assert len(store._all("SELECT 1 FROM entities WHERE etype='USERNAME'")) == 3


# --- successors --------------------------------------------------------------

def test_successor_edge_points_from_older_to_newer(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _two_markets(store, clone=False)
        found = detect_successors(store, min_score=0.5)
        assert len(found) == 1
        pair = found[0]
        assert pair["suppressed"] is None and pair["score"] >= 0.9
        assert 'shared_pgp_key' in pair["signals"]

        older = store._one("SELECT target_id FROM targets WHERE url=?", (ONION_A,))["target_id"]
        assert pair["source_market"] == older          # older market is the predecessor

        rel = store._one("SELECT rel_id, source_entity_id FROM relationships "
                         "WHERE rtype='SUCCESSOR_OF'")
        assert rel and rel["source_entity_id"] == store.find_entity("MARKET", ONION_A)
        # The derived edge is walkable back to hashed snapshots like any other.
        chain = store.provenance(rel["rel_id"])
        assert chain and all(c["sha256"] for c in chain)


def test_handoff_is_read_in_time_order_not_pair_order(tmp_path):
    """Pairs arrive ordered by target_id — a hash — so whichever market sorts
    first is arbitrary. Reading the gap in that order turns a handoff into an
    'overlap', which argues against succession instead of for it.

    Both orderings are exercised by swapping which onion is captured first, so
    the test cannot pass by accident on one hash ordering.

    The predecessor is recorded dark before the successor appears, because a
    handoff now requires that: a gap alone only says we visited one site before
    the other.
    """
    for first_seen, second_seen in ((ONION_A, ONION_B), (ONION_B, ONION_A)):
        with EvidenceStore(str(tmp_path / f"{first_seen[:4]}.db")) as store:
            ingest(_result(first_seen, seen=JAN, title='OldShop',
                           pgp_keys=[{'armored': KEY_A}]), store)
            store.record_down(
                store._one("SELECT target_id FROM targets WHERE url=?",
                           (first_seen,))["target_id"],
                collector='target_onion', note='Onion unreachable via Tor',
                observed_at=datetime(2026, 3, 1, tzinfo=timezone.utc).isoformat())
            ingest(_result(second_seen, seen=datetime(2026, 3, 20, tzinfo=timezone.utc),
                           title='NewPlace', pgp_keys=[{'armored': KEY_A}]), store)

            pair = detect_successors(store, min_score=0.5)[0]
            assert 'temporal_handoff' in pair["signals"]
            assert 'temporal_overlap' not in pair["signals"]
            older = store._one("SELECT target_id FROM targets WHERE url=?",
                               (first_seen,))["target_id"]
            assert pair["source_market"] == older


def test_clone_verdict_suppresses_the_successor_edge(tmp_path):
    """A copied site shares every artifact. Promoting that to succession would
    attribute the clone's activity to its victim, so the edge is refused."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _two_markets(store, clone=True)
        results = run_correlation(store)

        assert [c["ftype"] for c in results["clones"]] == ["CLONE_SUSPECT"]
        assert results["successors"] and results["successors"][0]["suppressed"] == "CLONE_SUSPECT"
        assert store._all("SELECT 1 FROM relationships WHERE rtype='SUCCESSOR_OF'") == []

        flag = results["contradictions"][0]
        assert flag["severity"] == "HIGH" and set(flag["markets"]) == {ONION_A, ONION_B}
        # Every candidate resting on those markets carries the objection.
        contested = [d for d in results["dossiers"] if d["contradictions"]]
        assert contested and any("contradiction stands against" in l
                                 for l in contested[0]["limitations"])
        # …and the brief names the rule that objected, so "a clone copied this"
        # stays distinguishable from the other three objections.
        assert "shared_artifacts_explained_by_cloning" in render_markdown(
            results["dossiers"], results)


# --- dossiers ----------------------------------------------------------------

def test_confidence_level_needs_more_than_one_funnel():
    assert confidence_level("OPERATOR", 0.99, 1) == "MEDIUM"   # loud, but single-source
    assert confidence_level("OPERATOR", 0.95, 2) == "HIGH"
    assert confidence_level("INFRA", 0.99, 2) == "MEDIUM"
    assert confidence_level("IP", 0.4, 5) == "LOW"


def test_run_correlation_persists_dossiers_and_is_idempotent(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _two_markets(store, clone=False)
        first = run_correlation(store)
        assert first["dossiers"] and all(d["rank"] for d in first["dossiers"])

        rows = store._all("SELECT candidate_id, contradicting_ids FROM candidates")
        assert len(rows) == len(first["dossiers"])

        second = run_correlation(store)
        assert len(store._all("SELECT 1 FROM candidates")) == len(rows)
        assert len(store._all("SELECT 1 FROM relationships WHERE rtype='SUCCESSOR_OF'")) == 1
        # A second pass must not invent market pairs out of its own derived rows.
        assert len(second["successors"]) == len(first["successors"])


def test_markdown_brief_carries_evidence_and_limits(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _two_markets(store, clone=False)
        results = run_correlation(store)
        text = render_markdown(results["dossiers"], results)
        assert "# CyberTrace — correlation brief" in text
        assert "Market relationships" in text and "Limitations" in text
        assert "probabilistic" in text                  # the caveat is never optional


def test_html_graph_is_self_contained_and_marks_hypotheses(tmp_path):
    """The rendered file must open on an offline box, and must distinguish what
    was observed from what was inferred."""
    out = tmp_path / "graph.html"
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _two_markets(store, clone=False)
        results = run_correlation(store)
        render_html(store, str(out), results)

    page = out.read_text()
    assert "SUCCESSOR_OF" in page                  # the inferred edge is labelled
    assert "vis-network" in page                   # library inlined, not fetched
    assert "http://cdn" not in page and "https://cdn" not in page
    assert not (tmp_path / "lib").exists()         # single portable artifact


def test_html_graph_draws_clone_contradictions(tmp_path):
    out = tmp_path / "clone.html"
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _two_markets(store, clone=True)
        results = run_correlation(store)
        render_html(store, str(out), results)

    page = out.read_text()
    assert "CLONE" in page and "dashes" in page
    # A suppressed successor must not be drawn as an edge at all.
    assert "SUCCESSOR_OF" not in page


def test_empty_store_yields_nothing(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        results = run_correlation(store)
        assert all(results[k] == [] for k in
                   ("operators", "infra", "ips", "successors", "clones",
                    "contradictions", "dossiers"))


# --- commonness: the ecosystem-vs-operator separation ------------------------

def _onion(n: int) -> str:
    return onion(chr(ord('c') + n))


def test_platform_furniture_is_discounted_and_a_rare_artifact_is_not(tmp_path):
    """The OnionMail case in miniature. Six sites of one family share the
    family's contact address; two of them also share something only they have.
    The shared address must not score like the shared secret."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for i in range(6):
            ingest(_result(_onion(i), emails=['support@platformmail.org']), store)
        for i in (0, 1):
            ingest(_result(_onion(i), emails=['support@platformmail.org',
                                              'private@rarehost.net']), store)

        weights = entity_discrimination(store)
        common = weights[store.find_entity("EMAIL", 'support@platformmail.org')]
        rare = weights[store.find_entity("EMAIL", 'private@rarehost.net')]
        assert common < COMMON_ARTIFACT_FLOOR < rare

        # The address six sites publish is on two of them together as well, so
        # the market floor alone would let it through as an operator candidate.
        # Commonness is what keeps it out while the rare one still qualifies.
        values = {c["value"] for c in candidate_operators(store, discrimination=weights)}
        assert values == {'private@rarehost.net'}
        assert 'support@platformmail.org' in {
            c["value"] for c in candidate_operators(store)}      # unweighted: it passes


def _key_certified_by(fpr: str, certifier: str) -> dict:
    return {'key_id': f'PGP:{fpr}', 'fingerprint': fpr, 'role': 'contact',
            'section': 'contact', 'certifiers': [certifier]}


def test_a_site_that_came_back_was_never_taken_down(tmp_path):
    """`temporal_handoff` reads "B appeared within 90 days of A being taken
    down", so a predecessor that is alive right now makes every site collected
    afterwards look like its successor.

    Measured: Endchan was unreachable in one sweep and answered a few hours
    later in the next. The stale DOWN row produced three SUCCESSOR_OF edges at
    0.52 out of Endchan — to cock.li's mail service and a personal blog among
    them, sharing nothing but a co-referenced host. Tor reachability flaps
    routinely (7 of 41 targets failed one sweep here; 2 answered an hour later),
    so this is the ordinary case.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, emails=['op@shop.li']), store)
        target = store._one("SELECT target_id FROM targets WHERE url=?", (ONION_A,))["target_id"]
        store.record_down(target, collector='target_onion', note='unreachable',
                          observed_at=datetime(2026, 3, 1, tzinfo=timezone.utc).isoformat())
        assert store.down_windows(), "while it is dark, the outage stands"

        # …and then it answers again.
        ingest(_result(ONION_A, seen=datetime(2026, 4, 1, tzinfo=timezone.utc),
                       emails=['op@shop.li']), store)
        assert store.down_windows() == {}, "a site that came back is not taken down"
        assert store._one("SELECT active FROM targets WHERE url=?", (ONION_A,))["active"] == 1

        # An unrelated site captured afterwards must not inherit a handoff.
        ingest(_result(ONION_B, seen=AUG, emails=['someone@else.li'],
                       clearnet_hosts_referenced=['shared-reference.li']), store)
        ingest(_result(ONION_A, seen=AUG, emails=['op@shop.li'],
                       clearnet_hosts_referenced=['shared-reference.li']), store)
        signals = {s for p in detect_successors(store) for s in p["signals"]}
        assert "temporal_handoff" not in signals


def test_a_keyserver_answer_is_not_the_markets_key(tmp_path):
    """Anyone can upload a key under anyone's address, so a keyserver hit is
    evidence about the ADDRESS, never about the sites that printed it.

    Two markets naming one mailbox is already scored as a shared email. If the
    fingerprint the keyserver returned were also read as theirs, one upload by a
    third party would add a second, heavier funnel to that pair — and the key,
    which no market ever published, would rank as the operator behind both.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion, emails=['op@proton.me']), store)
        email = store.find_entity("EMAIL", 'op@proton.me')
        snapshot = store._one("SELECT snapshot_id FROM snapshots LIMIT 1")["snapshot_id"]
        enrich_email(store, snapshot, email, {'pgp_fingerprints': [KEY_A]},
                     collector='email:pivot')
        key = store.find_entity("PGP_KEY", KEY_A)
        assert key and store._one(
            "SELECT 1 FROM relationships WHERE source_entity_id=? AND target_entity_id=? "
            "AND rtype='ASSOCIATED_WITH'", (email, key))

        operators = candidate_operators(store, min_conf=0.0)
        by_id = {c["entity_id"]: c for c in operators}
        # The mailbox both sites published is the claim the evidence supports.
        assert by_id[email]["n_markets"] == 2
        # The uploaded key is not, however strongly the keyserver asserted it.
        assert key not in by_id, by_id.get(key)


def test_a_platform_mailbox_is_not_an_operator_however_few_sites_show_it(tmp_path):
    """Two servers of one mail platform, both printing the platform's support
    address. Same string, same count, same page section as a real operator's
    mailbox on its own two onions — and the opposite conclusion.

    Per-entity commonness cannot tell them apart: `support@platform.info` on two
    of a platform's servers is one address on two targets, exactly like
    `support@dnmx.cc` on the two DNMX onions. What differs is the domain's reach
    — the platform's domain is all over the corpus, an operator's is on the pair
    that owns it — so the address is scored on that instead. Left per-entity,
    every ecosystem in the corpus mints an operator as soon as one of its
    servers prints a support address.
    """
    platform, operator = 'support@platform.info', 'support@ownbrand.cc'
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        # The rest of the platform: enough servers to make the domain furniture,
        # each naming it the way a real one does — a link, not a mailbox.
        for i in range(6):
            ingest(_result(f"{'q' * 54}{i:02d}.onion", seen=JAN,
                           clearnet_hosts_referenced=['docs.platform.info']), store)
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion, seen=JAN, emails=[platform, operator]), store)

        by_value = {c["value"]: c for c in candidate_operators(
            store, discrimination=entity_discrimination(store))}
        # Same two markets, same section, same confidence — only the domain's
        # reach differs, and that is the whole verdict.
        assert by_value[operator]["n_markets"] == 2
        assert platform not in by_value, by_value.get(platform)


def test_a_pile_of_shared_citations_is_a_lead_and_not_an_edge(tmp_path):
    """Two wikis on one subject cite the same twenty sources. That is a topic,
    not an operator.

    CONTEXT_WEIGHT already prices a single shared citation near nothing, because
    linking to a host says nothing about controlling it. What it cannot price is
    volume: the pair score is a noisy-OR, so twenty independent near-nothings
    compound past the assertion threshold and the edge is asserted on arithmetic
    that no individual signal supports. Whonix and Kicksecure — genuinely one
    operator — scored 0.69 this way, on stackexchange, mediawiki.org and the
    OpenVPN forums. Right answer, and a reason that links any two privacy wikis
    on the web.

    The pair still ranks: an analyst should see it. It just is not a claim.
    """
    # Twenty distinct registrable domains: subdomains of one host collapse into
    # a single signal, which is not the case being tested.
    cited = [f"docs.cited-source{i:02d}.net" for i in range(20)]
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion, seen=JAN, clearnet_hosts_referenced=cited), store)
        pairs = detect_successors(store)
        assert pairs, "the pair must still be ranked — suppressed, not discarded"
        assert pairs[0]["score"] >= 0.5, "and it must be the score, not a low one, that is refused"
        assert pairs[0]["suppressed"] == "REFERENCES_ONLY"
        assert pairs[0]["relation"] is None

        # One artifact the sites actually control, and the same pile of
        # citations becomes what it should have been all along: corroboration.
        ingest(_result(ONION_A, seen=AUG, emails=['op@ownbrand.cc'],
                       clearnet_hosts_referenced=cited), store)
        ingest(_result(ONION_B, seen=AUG, emails=['op@ownbrand.cc'],
                       clearnet_hosts_referenced=cited), store)
        asserted = [p for p in detect_successors(store) if not p["suppressed"]]
        assert len(asserted) == 1 and asserted[0]["relation"] == "LINKED_TO"


def test_a_shared_certifier_is_not_a_shared_operator(tmp_path):
    """The worst false-attribution path the engine had.

    Every certifier inside a published key block is observed on the target —
    honestly, the id really is in those bytes — while carrying no edge from the
    market, because it is a property of the KEY. Read at full control weight,
    two unrelated sites whose own distinct keys were both certified by one
    ordinary web-of-trust signer scored `shared_pgp_key` (1.3) AND `signed_by`
    (1.5): a noisy-OR near 0.9999 and a DIRECTIONAL successor edge between
    strangers, on the strength of one signature neither of them made.

    Absence of a market edge now floors at MENTIONS instead of defaulting to
    full control, and `signed_by` requires both keys to be published by their
    own side.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pgp_keys=[_key_certified_by('A' * 40, 'C' * 40)]), store)
        ingest(_result(ONION_B, pgp_keys=[_key_certified_by('B' * 40, 'C' * 40)]), store)

        assert candidate_operators(store) == [], "a certifier attributes nobody"
        pairs = detect_successors(store)
        assert not [p for p in pairs if not p.get("suppressed")], "no asserted edge"
        assert "signed_by" not in {s for p in pairs for s in p["signals"]}


def test_one_key_published_by_both_still_correlates(tmp_path):
    """The other half of the pair above: the guard must not cost the real
    signal. Two sites that each publish the SAME key as their own remain an
    operator candidate and a linked pair."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion, pgp_keys=[_key_certified_by('A' * 40, 'C' * 40)]), store)

        operators = candidate_operators(store)
        assert [c["value"] for c in operators] == ['pgp:' + 'a' * 40]
        assert operators[0]["n_markets"] == 2
        assert [p["relation"] for p in detect_successors(store)] == ["LINKED_TO"]


def test_a_two_market_corpus_keeps_its_only_signal(tmp_path):
    """With two markets, 'on both' IS the evidence. Dividing it away as common
    would silence the only thing a small case has to go on."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion, emails=['op@proton.me']), store)
        assert set(entity_discrimination(store).values()) == {1.0}


def test_shared_platform_is_recorded_as_an_objection(tmp_path):
    """Same software family, different operators: the pair must be reported as
    ecosystem, not quietly rescored into an operator claim."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for i in range(5):
            ingest(_result(_onion(i), emails=['support@platformmail.org'],
                           analytics_ids=['UA-9-9']), store)
        results = run_correlation(store)

        rules = {c["rule"] for c in results["contradictions"]}
        assert "shared_platform_not_shared_control" in rules
        assert not [s for s in results["successors"] if not s["suppressed"]]


# --- crypto clustering -------------------------------------------------------

BTC_OTHER = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"


def test_cospend_addresses_form_one_wallet(tmp_path):
    """Co-spending proves one party held both keys, and ownership is transitive,
    so A~B and B~C must resolve to a single cluster."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        a = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        b = store.upsert_entity("BTC_ADDRESS", BTC_OTHER)
        c = store.upsert_entity("BTC_ADDRESS", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        store.upsert_relationship(a, b, "PART_OF_CLUSTER")
        store.upsert_relationship(b, c, "PART_OF_CLUSTER")

        clusters = crypto_clusters(store)
        assert len({clusters[x] for x in (a, b, c)}) == 1

        lone = store.upsert_entity("BTC_ADDRESS", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
        assert lone not in clusters      # a component of one is not a wallet claim


# --- broadened contradictions ------------------------------------------------

def test_two_uncertified_keys_for_one_identity_contradict_each_other(tmp_path):
    """Anyone can upload a key under someone else's address. Two keys answering
    for one mailbox with no certification between them is an objection, not a
    richer profile."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, emails=['op@proton.me']), store)
        email = store.find_entity("EMAIL", 'op@proton.me')
        for key in (KEY_A, KEY_B):
            key_id = store.upsert_entity("PGP_KEY", key)
            store.upsert_relationship(email, key_id, "ASSOCIATED_WITH")

        flags = contradictions_from_identity(store)
        assert [f["rule"] for f in flags] == ["identity_bound_to_uncertified_keys"]

        # Certify one with the other and the conflict resolves to a rotation.
        store.upsert_relationship(store.find_entity("PGP_KEY", KEY_A),
                                  store.find_entity("PGP_KEY", KEY_B), "SIGNED_BY")
        assert contradictions_from_identity(store) == []


def test_overlapping_lifetimes_downgrade_succession_to_a_link(tmp_path):
    """Both live at once means neither replaced the other, however much they
    share. The link survives — one operator running two sites is ordinary — but
    the directional claim does not, and the objection is recorded."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion, seen=JAN, pgp_keys=[{'armored': KEY_A}]), store)
            ingest(_result(onion, seen=AUG, pgp_keys=[{'armored': KEY_A}]), store)
        results = run_correlation(store)

        assert [s["relation"] for s in results["successors"]] == ["LINKED_TO"]
        assert store._all("SELECT 1 FROM relationships WHERE rtype='SUCCESSOR_OF'") == []
        assert store._all("SELECT 1 FROM relationships WHERE rtype='LINKED_TO'")
        assert "overlap_contradicts_succession" in {c["rule"] for c in
                                                    results["contradictions"]}


def test_timing_alone_never_makes_a_successor(tmp_path):
    """Two markets that share nothing but happen to have been visited in order
    are not a hypothesis — this is the corpus-collection artefact that produced
    eight false successor edges before the rule existed."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, emails=['a@onehost.net']), store)
        store.record_down(store._one("SELECT target_id FROM targets WHERE url=?",
                                     (ONION_A,))["target_id"],
                          collector='target_onion', note='Onion unreachable via Tor')
        ingest(_result(ONION_B, seen=AUG, emails=['b@twohost.net']), store)
        assert detect_successors(store, min_score=0.1) == []


def test_an_objection_is_reported_as_the_rule_that_made_it(tmp_path):
    """Four rules write contradictions; the brief called every one of them a
    clone finding. On the corpus that misdescribed the real DNMX candidate — its
    only objection is that both addresses were live at once — as contradicted by
    a clone finding the store does not contain, in the one section a careful
    reader goes to precisely because they distrust the score."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion, seen=JAN, emails=['op@proton.me']), store)
            ingest(_result(onion, seen=AUG, emails=['op@proton.me']), store)
        results = run_correlation(store, min_conf=0.0)
        assert not results["clones"]
        brief = render_markdown(results["dossiers"], results)
        assert "overlap_contradicts_succession" in brief
        assert "clone finding" not in brief
        assert "A clone finding contradicts" not in brief


def test_a_contradicted_candidate_cannot_be_reported_high():
    """The objection is a competing explanation, not a footnote — a reader who
    only sees the label must not be told HIGH while the body says 'clone'."""
    assert confidence_level("OPERATOR", 0.95, 3) == "HIGH"
    assert confidence_level("OPERATOR", 0.95, 3, contradicted=True) == "MEDIUM"


# --- case file ---------------------------------------------------------------

def test_dossier_html_is_self_contained_and_leads_with_objections(tmp_path):
    out = tmp_path / "case.html"
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _two_markets(store, clone=True)
        results = run_correlation(store)
        render_dossier_html(results, str(out))

    page = out.read_text()
    assert "<script" not in page                    # native <details>, no JS
    assert "http://" not in page.split("<body>")[0]  # nothing fetched remotely
    # Contradictions are rendered above the candidate list, not inside it.
    assert page.index("Contradictions") < page.index("<h2>Candidates</h2>")
    assert "not calibrated probabilities" in page


# --- monitoring --------------------------------------------------------------

def test_candidate_deltas_report_only_movement():
    before = [{"candidate_id": "OP-1", "confidence": 0.5, "assessment": "x"},
              {"candidate_id": "OP-2", "confidence": 0.7, "assessment": "y"}]
    after = [{"candidate_id": "OP-1", "confidence": 0.5, "assessment": "x"},
             {"candidate_id": "OP-2", "confidence": 0.9, "assessment": "y"},
             {"candidate_id": "OP-3", "confidence": 0.6, "assessment": "z"}]
    changes = {d["candidate_id"]: d["change"] for d in candidate_deltas(before, after)}
    assert changes == {"OP-2": "MOVED", "OP-3": "NEW"}   # OP-1 unchanged: not news
    # A candidate that stopped clearing the bar is news too, in the other direction.
    reverse = {d["candidate_id"]: d["change"] for d in candidate_deltas(after, before)}
    assert reverse == {"OP-2": "MOVED", "OP-3": "GONE"}


# --- index discovery ---------------------------------------------------------

def _index_only(target, seen, **index_data):
    """A target nobody reached: the direct Tor visit failed, an index answered.

    The shape of the adversarial case this file exists to keep closed — the
    target is dark, so every artifact and every neighbouring onion in the run
    came off Torch and off nothing else.
    """
    r = ModuleResult(target=target, target_type='darkweb', module='darkweb')
    r.sources['target_onion'] = SourceResult(
        source='target_onion', success=False, timestamp=seen,
        error='Onion unreachable via Tor (127.0.0.1:9050 is up) — the site is down')
    r.sources['torch'] = SourceResult(
        source='torch', success=True, timestamp=seen, data=index_data)
    return r


def test_torch_discovered_onions_never_become_an_operator_link(tmp_path):
    """Two dark onions that co-ranked on Torch must correlate to nothing.

    This is the whole leak in one scenario: Torch returns A and B beside each
    other and repeats the same result-snippet contact details under both. Read
    as observations, that is a shared email, a shared key and a shared wallet
    across two markets — the exact convergence the engine promotes to an
    operator — and every part of it is a property of the search index.
    """
    shared = dict(emails=['op@morke.ru'], bitcoin_addresses=[BTC_VALID],
                  pgp_keys=[{'armored': KEY_A}])
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_index_only(ONION_A, JAN, onion_addresses_found=[ONION_B], **shared), store)

        # Discovery does not mint a target, so nothing downstream will ever
        # crawl B or enrich it: `recheck` and correlation both enumerate targets.
        assert [r["url"] for r in store._all("SELECT url FROM targets")] == [ONION_A]
        # A -> B is provenance about how B was found. LINKS_TO would assert the
        # market published the link, which no one ever asked the market.
        assert [r["rtype"] for r in store._all(
            "SELECT r.rtype FROM relationships r JOIN entities e "
            "ON e.entity_id = r.target_entity_id WHERE e.normalized_value=?",
            (ONION_B,))] == ["DISCOVERED_VIA"]

        ingest(_index_only(ONION_B, AUG, onion_addresses_found=[ONION_A], **shared), store)
        results = run_correlation(store)

        assert results["operators"] == []
        assert results["successors"] == []       # not even a lead: no pair exists
        assert results["infra"] == [] and results["ips"] == []
        # The leads themselves survive as entities — a dark market's index entry
        # is still where an analyst starts — attributed to no market.
        for etype, value in (("EMAIL", 'op@morke.ru'), ("BTC_ADDRESS", BTC_VALID),
                             ("ONION_ADDRESS", ONION_B)):
            entity = store.find_entity(etype, value)
            assert entity is not None, f"{etype} {value} was dropped, not demoted"
            assert markets_for_entity(store, entity) == []


def test_an_index_payload_seeds_no_enrichment_pivot():
    """The module-side half of the same guarantee. Phase 7 only ever sees the
    live page's data, and enrichment is what turns a string into a named person
    (keyserver, Gravatar, chain lookup) — so an index snippet must not reach it
    even if it is handed over directly."""
    index_payload = {'emails': ['op@morke.ru'], 'bitcoin_addresses': [BTC_VALID],
                     'onion_addresses_found': [ONION_B]}
    assert DarkwebModule._pivot_targets(index_payload)      # not inert by accident
    # An onion is never a pivot target regardless of where it came from: there
    # is no module that "enriches" an onion except by visiting it.
    assert not any(ONION_B in target
                   for _, target in DarkwebModule._pivot_targets(index_payload))
