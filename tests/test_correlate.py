"""M5 correlation: funnel convergence, successor direction, clone suppression.

Offline throughout — every scenario is seeded through `ingest()`, so what is
under test is the same path a real crawl takes.
"""

from datetime import datetime, timezone

from cybertrace.correlate import (
    canonical_entity_key, candidate_infra, candidate_operators, confidence_level,
    detect_successors, entity_funnel_profile, render_html, render_markdown,
    run_correlation,
    username_aliases,
)
from cybertrace.evidence import EvidenceStore, ingest

from .test_evidence import BTC_VALID, KEY_A, ONION_A, ONION_B, _result

JAN = datetime(2026, 1, 10, tzinfo=timezone.utc)
AUG = datetime(2026, 8, 2, tzinfo=timezone.utc)


def _two_markets(store, *, clone: bool):
    """Two markets sharing a key. `clone` decides whether the later site is a
    copy of the earlier one or an unrelated-looking rebuild."""
    ingest(_result(ONION_A, seen=JAN, title='OldShop', emails=['op@proton.me'],
                   bitcoin_addresses=[BTC_VALID], pgp_keys=[{'armored': KEY_A}]), store)
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

        domain = store.upsert_entity("DOMAIN", "shop.example.com")
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


def test_infra_requires_two_markets(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, clearnet_hosts_referenced=['shared.example.com',
                                                           'only-a.example.com']), store)
        ingest(_result(ONION_B, clearnet_hosts_referenced=['shared.example.com']), store)
        values = {c["value"] for c in candidate_infra(store, min_markets=2)}
        assert values == {'shared.example.com'}


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
    """
    for first_seen, second_seen in ((ONION_A, ONION_B), (ONION_B, ONION_A)):
        with EvidenceStore(str(tmp_path / f"{first_seen[:4]}.db")) as store:
            ingest(_result(first_seen, seen=JAN, title='OldShop',
                           pgp_keys=[{'armored': KEY_A}]), store)
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
        assert contested and any("clone finding contradicts" in l
                                 for l in contested[0]["limitations"])


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
        assert "Successor hypotheses" in text and "Limitations" in text
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
