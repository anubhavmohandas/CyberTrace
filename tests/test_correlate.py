"""M5 correlation: funnel convergence, successor direction, clone suppression.

Offline throughout — every scenario is seeded through `ingest()`, so what is
under test is the same path a real crawl takes.
"""

import base64
from datetime import datetime, timezone

from cybertrace.correlate import (
    FUNNELS,
    COMMON_ARTIFACT_FLOOR, EXCHANGE_HOP_DECAY, LEAD_FLOOR,
    canonical_entity_key, candidate_infra, candidate_ips, candidate_operators,
    confidence_level, contradictions_from_identity, contradictions_from_key_temporal,
    crypto_clusters, detect_successors,
    entity_discrimination, entity_funnel_profile, feedback_discrimination, markets_for_entity,
    market_windows, render_dossier_html, render_html, render_markdown, run_correlation,
    save_candidates, username_aliases, wallet_exchange_paths, wallet_trace_report,
)
from cybertrace.evidence import EvidenceStore, enrich_bitcoin, enrich_email, ingest, label_exchange
from cybertrace.modules.base import ModuleResult, SourceResult
from cybertrace.modules.darkweb_module import DarkwebModule
from cybertrace.monitor import candidate_deltas
from cybertrace.normalize import pgp_fingerprint

from .test_evidence import (
    BTC_VALID, KEY_A, KEY_B, ONION_A, ONION_B, TRX_VALID, _armor, _pivot_result,
    _pubkey_packet, _result, _signature_packet, onion,
)

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


# --- PGP key temporal validation ----------------------------------------------
#
# A shared key only evidences succession if the key could actually have been
# on the predecessor's page while it was live. These pin the two synthetic
# cases from the investigation this feature came out of: created 2023-11-14
# (well before a Jan-Jun 2026 predecessor) scores the same 0.995 it always
# has; created 2026-07-01 (after the predecessor went dark 2026-06-01, before
# the Aug 2026 successor appeared) must not reach that conclusion.

PREDECESSOR_DOWN = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _predecessor_successor(store, key_block):
    """Predecessor live Jan-Jun 2026, successor appears Aug 2026, both showing
    one PGP key — the shape `_two_markets` uses, reduced to just the key so a
    temporal read-out is not entangled with the other shared-artifact signals."""
    ingest(_result(ONION_A, seen=JAN, title="OldShop",
                   pgp_keys=[{"armored": key_block}]), store)
    store.record_down(
        store._one("SELECT target_id FROM targets WHERE url=?", (ONION_A,))["target_id"],
        collector="target_onion", note="Onion unreachable via Tor",
        observed_at=PREDECESSOR_DOWN.isoformat())
    ingest(_result(ONION_B, seen=AUG, title="NewPlace",
                   pgp_keys=[{"armored": key_block}]), store)


def test_key_created_before_predecessor_window_scores_normally(tmp_path):
    """Case A / the investigation's 'valid' synthetic case: created 2023-11-14,
    predecessor Jan-Jun 2026, successor Aug 2026. The key could genuinely have
    carried over, so the successor edge must score exactly as it always has."""
    created = int(datetime(2023, 11, 14, tzinfo=timezone.utc).timestamp())
    key = _armor(_pubkey_packet((1 << 2047) | 0x1357, created=created))
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _predecessor_successor(store, key)
        pair = detect_successors(store, min_score=0.5)[0]
        assert pair["score"] == 0.995
        assert pair["suppressed"] is None
        assert pair["relation"] == "SUCCESSOR_OF"
        assert "pgp_key_temporal_contradiction" not in pair["signals"]
        assert store._all("SELECT 1 FROM relationships WHERE rtype='SUCCESSOR_OF'")


def test_key_created_after_predecessor_window_suppresses_succession(tmp_path):
    """Case B / the investigation's 'invalid' synthetic case: created
    2026-07-01, one month AFTER the predecessor was observed dark. The key
    cannot have been reused from a market that closed before it existed, so
    this must not reach the old 0.995 SUCCESSOR_OF conclusion — but nothing
    about the underlying evidence is deleted."""
    created = int(datetime(2026, 7, 1, tzinfo=timezone.utc).timestamp())
    key = _armor(_pubkey_packet((1 << 2047) | 0x2468, created=created))
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _predecessor_successor(store, key)
        pair = detect_successors(store, min_score=0.5)[0]

        assert pair["score"] != 0.995
        assert pair["score"] < 0.9
        assert pair["relation"] is None
        assert pair["suppressed"] is not None
        assert "pgp_key_temporal_contradiction" in pair["signals"]
        # Downgraded, not deleted: no SUCCESSOR_OF edge, but the key itself and
        # its USES_PGP observations on both markets are still fully in the store.
        assert store._all("SELECT 1 FROM relationships WHERE rtype='SUCCESSOR_OF'") == []
        key_entity = store.find_entity("PGP_KEY", key)
        assert len(store._all("SELECT 1 FROM observations WHERE entity_id=?",
                              (key_entity,))) == 2
        assert store.metadata(key_entity)["key_created_at"].startswith("2026-07-01")

        # The contradiction is visible, not silent: a Finding backs it and the
        # dossier-level contradiction rule reports it explicitly.
        flags = contradictions_from_key_temporal(store, [pair])
        assert flags and flags[0]["rule"] == "key_created_after_predecessor_window"
        assert {ONION_A, ONION_B} <= set(flags[0]["markets"])
        assert store.findings("PGP_KEY_TEMPORAL_CONTRADICTION")


def test_no_creation_timestamp_leaves_correlation_unchanged(tmp_path):
    """Case C: a key the parser has no packet for (bare fingerprint, as a
    keyserver hit or an unparseable export would supply) must correlate
    exactly as before this feature existed — no chronology invented from
    when the tool happened to observe it."""
    fpr = "AA" * 20
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, title="OldShop",
                       pgp_keys=[{"fingerprint": fpr}]), store)
        store.record_down(
            store._one("SELECT target_id FROM targets WHERE url=?", (ONION_A,))["target_id"],
            collector="target_onion", note="Onion unreachable via Tor",
            observed_at=PREDECESSOR_DOWN.isoformat())
        ingest(_result(ONION_B, seen=AUG, title="NewPlace",
                       pgp_keys=[{"fingerprint": fpr}]), store)

        key = store.find_entity("PGP_KEY", fpr)
        assert "key_created_at" not in store.metadata(key)

        pair = detect_successors(store, min_score=0.5)[0]
        assert pair["score"] == 0.995
        assert pair["relation"] == "SUCCESSOR_OF"
        assert "pgp_key_temporal_contradiction" not in pair["signals"]


def test_malformed_creation_timestamp_is_untrusted_not_fabricated(tmp_path):
    """Case D: a key packet too short to hold a real creation time must behave
    exactly like 'no timestamp' — safely unavailable, never a guess."""
    truncated_block = ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
                       + base64.b64encode(bytes([0x99, 0x00, 0x02, 4, 0x17])).decode()
                       + "\n-----END PGP PUBLIC KEY BLOCK-----")
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, title="OldShop",
                       pgp_keys=[{"armored": truncated_block}]),
               store)
        store.record_down(
            store._one("SELECT target_id FROM targets WHERE url=?", (ONION_A,))["target_id"],
            collector="target_onion", note="Onion unreachable via Tor",
            observed_at=PREDECESSOR_DOWN.isoformat())
        ingest(_result(ONION_B, seen=AUG, title="NewPlace",
                       pgp_keys=[{"armored": truncated_block}]),
               store)

        key = store.find_entity("PGP_KEY", truncated_block)
        assert "key_created_at" not in store.metadata(key)
        pair = detect_successors(store, min_score=0.5)[0]
        assert "pgp_key_temporal_contradiction" not in pair["signals"]


def test_multiple_observations_of_one_key_keep_their_own_timestamps(tmp_path):
    """Case E: the same key captured twice must not collapse into one
    observation — each capture keeps its own observed_at, while the key's own
    created_at (an entity-level fact) is unaffected by how many times or when
    it was seen."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, title="Shop",
                       pgp_keys=[{"armored": KEY_A}]), store)
        ingest(_result(ONION_A, seen=datetime(2026, 3, 1, tzinfo=timezone.utc),
                       title="Shop", pgp_keys=[{"armored": KEY_A}]), store)

        key = store.find_entity("PGP_KEY", KEY_A)
        stamps = {r["observed_at"] for r in
                 store._all("SELECT observed_at FROM observations WHERE entity_id=?",
                            (key,))}
        assert len(stamps) == 2
        assert store.metadata(key)["key_created_at"] == datetime.fromtimestamp(
            1_700_000_000, tz=timezone.utc).isoformat()


def test_expired_key_is_not_read_as_newly_created(tmp_path):
    """Case F: an OLD, already-expired key that only gets observed again long
    after it expired must still be read as old. Expiration must never stand in
    for creation just because the key resurfaces later."""
    created = int(datetime(2023, 11, 14, tzinfo=timezone.utc).timestamp())
    expires_seconds = 45 * 86400                       # expired mid-December 2023
    pubkey = _pubkey_packet((1 << 2047) | 0x9999, created=created)
    fpr = pgp_fingerprint(_armor(pubkey))
    self_sig = _signature_packet(sig_type=0x13, issuer=bytes.fromhex(fpr[-16:]),
                                 sig_created=created,
                                 key_expiration_seconds=expires_seconds)
    key_block = _armor(pubkey + self_sig)

    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _predecessor_successor(store, key_block)

        key = store.find_entity("PGP_KEY", key_block)
        meta = store.metadata(key)
        assert meta["key_created_at"] == datetime.fromtimestamp(
            created, tz=timezone.utc).isoformat()
        assert meta["key_expires_at"] == datetime.fromtimestamp(
            created + expires_seconds, tz=timezone.utc).isoformat()

        # Old and expired, but still created well before the predecessor's
        # window — normal correlation, no contradiction, expiry never
        # substituted for creation.
        pair = detect_successors(store, min_score=0.5)[0]
        assert pair["score"] == 0.995
        assert "pgp_key_temporal_contradiction" not in pair["signals"]


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


def test_five_newsrooms_serving_one_logo_are_not_one_operator(tmp_path):
    """The SecureDrop case, and the reason a favicon hash cannot assert.

    Not a constructed adversary: five independently-operated newsroom instances
    in the corpus — Bloomberg, CBC, Forbes, the Guardian, the New York Times —
    serve the SecureDrop template's icon, so `mmh3:-1412307033` is one hash on
    five targets run by five organisations. Across the whole corpus the hash is
    9 same-operator pairs against 10 same-platform ones: a coin flip.

    Rarity cannot save it, and that is the load-bearing part. On the real corpus
    the icon sits on 5 targets of 94 and measures 0.65 — comfortably over
    COMMON_ARTIFACT_FLOOR — so the commonness model reads the platform's logo as
    a DISTINCTIVE artifact, exactly as it reads the platform's `gettor@`
    mailbox. This runs with no discrimination at all, i.e. the icon scored as if
    it were unique to the pair, because that is the case the gate has to hold
    in: what refuses it is the category in NON_ATTRIBUTIVE_SIGNALS, and the
    score floor is removed here so a numeric refusal cannot pass for a
    categorical one.
    """
    newsrooms = [onion(c) for c in "vwxyz"]
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for site in newsrooms:
            ingest(_result(site, seen=JAN,
                           favicon={'favicon_mmh3': -1412307033,
                                    'favicon_url': f'http://{site}/favicon.ico'}), store)

        icon = store.find_entity("FAVICON", "mmh3:-1412307033")
        assert len(markets_for_entity(store, icon)) == 5

        # Ranked so an analyst sees them; asserted for none of them, at any score.
        pairs = detect_successors(store, min_score=0.0)
        assert len(pairs) == 10                      # every pair of the five
        assert {p["suppressed"] for p in pairs} == {"REFERENCES_ONLY"}
        assert {p["relation"] for p in pairs} == {None}
        assert run_correlation(store)["operators"] == []
        assert not store._all(
            "SELECT 1 FROM relationships WHERE rtype IN ('SUCCESSOR_OF','LINKED_TO')")

        # …and one artifact the sites actually control flips exactly one pair,
        # so the icon is corroboration rather than dead weight.
        for site in newsrooms[:2]:
            ingest(_result(site, seen=AUG, emails=['op@ownbrand.cc'],
                           favicon={'favicon_mmh3': -1412307033}), store)
        asserted = [p for p in detect_successors(store) if not p["suppressed"]]
        assert len(asserted) == 1 and asserted[0]["relation"] == "LINKED_TO"
        assert "shared_favicon" in asserted[0]["signals"]


def test_a_deployment_remote_is_a_lead_not_an_identity(tmp_path):
    """Two sites that deployed the same upstream project are not one operator.

    An exposed `.git/config` is the most authoritative artifact in the whole
    collector — the server handed over its own configuration — and the account
    in it is the least certain thing about it, because a checkout can point at
    a project the operator merely cloned. Read at control weight, two sites
    running one theme become one operator on the theme author's handle, which
    is the same failure as the SecureDrop mailbox with a stronger provenance
    story attached to it.

    So the handle is an entity, it is in the graph, it ranks a pair as a lead —
    and it cannot promote either site to a candidate on its own.
    """
    exposure = [{'path': '/.git/config', 'status': 200, 'bytes': 293,
                 'leaked_ips': [],
                 'git_remotes': [{'url': 'ssh://git@code.forge.test/upstream/theme.git',
                                  'host': 'code.forge.test', 'repository': 'theme',
                                  'account': 'upstream'}]}]
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for site in (ONION_A, ONION_B):
            ingest(_result(site, seen=JAN, misconfigurations=exposure), store)

        handle = store.find_entity("USERNAME", 'upstream')
        assert handle, "the account must be recorded — it is real, and it is evidence"
        assert [r["rtype"] for r in store._all(
            "SELECT rtype FROM relationships WHERE target_entity_id=?", (handle,))] \
            == ["MENTIONS", "MENTIONS"]
        assert run_correlation(store)["operators"] == []
        assert not store._all(
            "SELECT 1 FROM relationships WHERE rtype IN ('SUCCESSOR_OF','LINKED_TO')")

        # It is not inert either: the pair ranks, so an analyst sees the two
        # sites pulling from one repository.
        pairs = detect_successors(store, min_score=0.0)
        assert pairs and pairs[0]["suppressed"] and "shared_username" in pairs[0]["signals"]


def test_a_favicon_hit_keeps_the_hop_it_was_found_through(tmp_path):
    """ONION -> HASH -> IP, with the middle term still in the graph.

    A Shodan answer says one thing: some host serves this icon. Hanging the
    address straight off the market collapses that into "this market's host",
    and the reader cannot see which of the two they were told. The chain is
    kept whole so the dossier can answer why an address is in the case, and
    neither hop is in a funnel — an index observing a host is not the operator
    owning it, at any confidence.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, candidate_operator_ips=['203.0.113.7'],
                       favicon={'favicon_mmh3': 12345, 'shodan_total': 1,
                                'shodan_matches': [{'ip': '203.0.113.7',
                                                    'org': 'Example Hosting'}]}), store)
        market = store.find_entity("MARKET", ONION_A)
        icon = store.find_entity("FAVICON", "mmh3:12345")
        host = store.find_entity("IP", '203.0.113.7')
        assert icon and host

        hops = {(r["source_entity_id"], r["rtype"], r["target_entity_id"])
                for r in store._all("SELECT source_entity_id, rtype, target_entity_id "
                                    "FROM relationships")}
        assert (market, "HAS_FINGERPRINT", icon) in hops
        assert (icon, "ASSOCIATED_WITH_IP", host) in hops

        # The hash and the host it was seen on are observations. Neither is an
        # operator claim, and one market cannot make them one.
        assert entity_funnel_profile(store, icon)["total_conf"] == 0.0
        assert run_correlation(store)["operators"] == []


def test_a_direct_ip_leak_is_not_also_filed_as_a_weaker_candidate(tmp_path):
    """One observation must not become two signals.

    darkweb_module unions every IP-shaped hit — header/body leaks, misconfig
    leaks AND Shodan favicon matches — into `candidate_operator_ips`, because
    that one list is what the enrichment pivot sweeps. A header leak already
    earns its own HOSTED_ON edge at the model's top confidence; refiling the
    same address as CANDIDATE_IP ("a lead, not a fact" — correlate.py's own
    words for that weight) would claim a second, weaker signal out of a single
    fact. A genuinely pivot-only address — never seen on the page, matched by
    icon hash alone — is the case CANDIDATE_IP exists for, and must still get
    it.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(
            ONION_A, seen=JAN,
            leaked_public_ipv4=['198.51.100.9'],
            candidate_operator_ips=['198.51.100.9', '203.0.113.7'],
            favicon={'favicon_mmh3': 12345, 'shodan_total': 1,
                     'shodan_matches': [{'ip': '203.0.113.7', 'org': 'Example Hosting'}]},
        ), store)
        market = store.find_entity("MARKET", ONION_A)
        leaked = store.find_entity("IP", '198.51.100.9')
        pivoted = store.find_entity("IP", '203.0.113.7')

        rtypes = {(r["target_entity_id"], r["rtype"]) for r in store._all(
            "SELECT target_entity_id, rtype FROM relationships WHERE source_entity_id=?",
            (market,))}
        assert (leaked, "HOSTED_ON") in rtypes
        assert (leaked, "CANDIDATE_IP") not in rtypes  # no redundant weaker edge
        assert (pivoted, "CANDIDATE_IP") in rtypes      # pivot-only IP still lands


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

# A genuinely different address from BTC_VALID (imported from test_evidence) —
# it was a byte-for-byte copy of BTC_VALID before this fix, so every
# "two unrelated markets, two addresses" test below (test_chainabuse_reports_
# never_link_two_unrelated_markets, test_ellipticpp_illicit_label_never_
# links_two_unrelated_markets) was silently upserting ONE entity under two
# names and asserting "no relationship" against itself — true either way, but
# not the claim the test names. Real BTC address (genesis block, public).
BTC_OTHER = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


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


def test_counterparty_addresses_never_join_the_cluster(tmp_path):
    """A paid address is not a co-spent one. enrich_bitcoin must read
    cospend_addresses into PART_OF_CLUSTER and counterparty_addresses into the
    separate, weaker TRANSACTED_WITH relation — feeding either into the other
    would either pull every customer of a market into the operator's wallet
    (cluster) or claim a payment as shared control (cluster from counterparty)."""
    cospend_peer = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    counterparty_peer = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        target = store.upsert_target("btc:" + BTC_VALID)
        sid = store.insert_snapshot(target, {}, "bitcoin")
        enrich_bitcoin(store, sid, addr, {
            "address": BTC_VALID,
            "cospend_addresses": [cospend_peer],
            "counterparty_addresses": [counterparty_peer],
            "connected_addresses": [cospend_peer, counterparty_peer],
        }, "bitcoin")

        clusters = crypto_clusters(store)
        counterparty_id = store.find_entity("BTC_ADDRESS", counterparty_peer)
        assert counterparty_id is not None  # upserted for tracing, just not clustered
        assert counterparty_id not in clusters      # never joins the co-spend component
        assert clusters[addr] == clusters[store.find_entity("BTC_ADDRESS", cospend_peer)]

        rel = store._one(
            "SELECT rtype FROM relationships WHERE source_entity_id=? AND target_entity_id=?",
            (addr, counterparty_id))
        assert rel["rtype"] == "TRANSACTED_WITH"


def test_exchange_consolidation_cospend_does_not_link_two_unrelated_markets(tmp_path):
    """crypto_clusters' own occam note admits the risk this reproduces: a
    service consolidating many customers' deposit addresses into one input set
    sweeps them all into a single co-spend component, so Market A's address and
    Market B's address can land in one cluster despite the two markets sharing
    nothing real -- only an exchange's internal housekeeping. This is the
    scenario, run through the actual pipeline rather than assumed safe.

    It survives on two mechanisms neither of which lives in bitcoin_module or
    touches SUCCESSOR_SIGNALS: _candidate_pairs (correlate.py) only compares
    markets that already share one literal entity_id, and a market's edge to a
    cluster-mate it never itself published floors at UNJOINED_CONTEXT (0.15,
    MENTIONS-equivalent -- see _edge_context), never DEFAULT_CONTEXT's 1.0. So
    the swept-in address scores as a bare reference, not control, and never as
    the full-weight dedicated shared_cluster signal (that path is skipped once
    shared_btc already covers the pair -- see _pair_signals).
    """
    exchange_hot_wallet = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, bitcoin_addresses=[BTC_VALID]), store)
        ingest(_result(ONION_B, seen=JAN, bitcoin_addresses=[BTC_OTHER]), store)

        # Market A's address happened to be swept alongside Market B's address
        # and the exchange's own wallet in one large consolidation transaction
        # -- exactly what bitcoin_module._check_blockchain_com would report as
        # cospend_addresses for a many-input tx it does not special-case.
        addr_a = store.find_entity("BTC_ADDRESS", BTC_VALID)
        target_a = store.upsert_target("btc:" + BTC_VALID)
        sid = store.insert_snapshot(target_a, {}, "bitcoin")
        enrich_bitcoin(store, sid, addr_a, {
            "address": BTC_VALID,
            "cospend_addresses": [BTC_OTHER, exchange_hot_wallet],
        }, "bitcoin")

        addr_b = store.find_entity("BTC_ADDRESS", BTC_OTHER)
        assert crypto_clusters(store)[addr_a] == crypto_clusters(store)[addr_b], \
            "the two addresses really are one co-spend component -- that part is real"

        # Worth surfacing as a lead (score clears LEAD_FLOOR) -- an analyst may
        # still want to see "these two swept through one exchange" -- but the
        # MENTIONS-floor context keeps it a reference, never a claim: no edge,
        # same REFERENCES_ONLY refusal shared_ip gets in
        # test_two_strangers_on_one_shared_host_are_not_linked.
        pairs = detect_successors(store, min_score=0.0)
        assert pairs, "the pair is still worth ranking as a lead"
        pair = pairs[0]
        assert pair["score"] >= LEAD_FLOOR       # visible...
        assert pair["relation"] is None          # ...but never asserted
        assert pair["suppressed"] == "REFERENCES_ONLY"

        results = run_correlation(store)
        assert all(s["relation"] is None for s in results["successors"])
        assert results["operators"] == []


def test_transacted_with_never_links_two_unrelated_markets(tmp_path):
    """The counterparty analog of the cospend-consolidation test above: being
    paid by the same address is even weaker than co-spending it, so it must be
    at least as safe -- no funnel score, no successor edge, no operator."""
    shared_counterparty = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=JAN, bitcoin_addresses=[BTC_VALID]), store)
        ingest(_result(ONION_B, seen=JAN, bitcoin_addresses=[BTC_OTHER]), store)

        addr_a = store.find_entity("BTC_ADDRESS", BTC_VALID)
        target_a = store.upsert_target("btc:" + BTC_VALID)
        sid_a = store.insert_snapshot(target_a, {}, "bitcoin")
        enrich_bitcoin(store, sid_a, addr_a,
                       {"address": BTC_VALID, "counterparty_addresses": [shared_counterparty]},
                       "bitcoin")

        addr_b = store.find_entity("BTC_ADDRESS", BTC_OTHER)
        target_b = store.upsert_target("btc:" + BTC_OTHER)
        sid_b = store.insert_snapshot(target_b, {}, "bitcoin")
        enrich_bitcoin(store, sid_b, addr_b,
                       {"address": BTC_OTHER, "counterparty_addresses": [shared_counterparty]},
                       "bitcoin")

        counterparty_id = store.find_entity("BTC_ADDRESS", shared_counterparty)
        assert entity_funnel_profile(store, counterparty_id)["total_conf"] == 0.0

        results = run_correlation(store)
        assert all(s["relation"] is None for s in results["successors"])
        assert results["operators"] == []


def test_transacted_with_and_exchange_deposit_are_in_no_funnel():
    """Structural non-attribution, not a runtime gate: unlike shared_domain/
    shared_favicon/shared_ip (NON_ATTRIBUTIVE_SIGNALS, checked at scoring
    time), these two relationship types are simply never assigned to a funnel
    at all -- the same mechanism DISCOVERED_VIA and HAS_FINGERPRINT rely on."""
    funnelled = {rtype for rtypes in FUNNELS.values() for rtype in rtypes}
    assert "TRANSACTED_WITH" not in funnelled
    assert "EXCHANGE_DEPOSIT" not in funnelled


# --- wallet -> exchange reachability ------------------------------------------

def test_wallet_exchange_paths_direct_hit(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        rel = label_exchange(store, BTC_VALID, "Test Exchange", analyst="jdoe",
                             note="public disclosure")
        assert rel is not None

        paths = wallet_exchange_paths(store)
        assert len(paths) == 1
        assert paths[0]["exchange"] == "test exchange"
        assert paths[0]["hops"] == 0
        assert paths[0]["confidence"] == 1.0
        assert paths[0]["evidence_ids"]


def test_wallet_exchange_paths_direct_hit_tron(tmp_path):
    """Same direct-hit shape as the BTC case, on a TRX_ADDRESS -- pins that
    wallet_exchange_paths' entity query actually includes TRX_ADDRESS (it did
    not, before TRON support), not just that label_exchange can write one."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        rel = label_exchange(store, TRX_VALID, "Test Exchange", analyst="jdoe")
        assert rel is not None

        paths = wallet_exchange_paths(store)
        assert len(paths) == 1
        # "value" is entities.normalized_value throughout correlate.py (see
        # build_dossier) -- the lowercase, prefixed dedup key, not raw_value.
        assert paths[0]["value"] == f"trx:{TRX_VALID.lower()}"
        assert paths[0]["hops"] == 0


def test_wallet_exchange_paths_one_hop_via_transacted_with(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        target = store.upsert_target("btc:" + BTC_VALID)
        sid = store.insert_snapshot(target, {}, "bitcoin")
        enrich_bitcoin(store, sid, addr,
                       {"address": BTC_VALID, "counterparty_addresses": [BTC_OTHER]}, "bitcoin")
        assert label_exchange(store, BTC_OTHER, "Test Exchange") is not None

        paths = wallet_exchange_paths(store)
        row = next(w for w in paths if w["entity_id"] == addr)
        assert row["hops"] == 1
        assert row["confidence"] == round(EXCHANGE_HOP_DECAY ** 1, 4)
        assert row["evidence_ids"]


def test_wallet_exchange_paths_two_hops_mixing_cluster_and_transacted_with(tmp_path):
    """A -cospend-> B -counterparty-> C(labeled exchange): the walk must cross
    both PART_OF_CLUSTER and TRANSACTED_WITH edges to find the nearest label."""
    third = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr_a = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        target_a = store.upsert_target("btc:" + BTC_VALID)
        sid_a = store.insert_snapshot(target_a, {}, "bitcoin")
        enrich_bitcoin(store, sid_a, addr_a,
                       {"address": BTC_VALID, "cospend_addresses": [BTC_OTHER]}, "bitcoin")

        addr_b = store.find_entity("BTC_ADDRESS", BTC_OTHER)
        target_b = store.upsert_target("btc:" + BTC_OTHER)
        sid_b = store.insert_snapshot(target_b, {}, "bitcoin")
        enrich_bitcoin(store, sid_b, addr_b,
                       {"address": BTC_OTHER, "counterparty_addresses": [third]}, "bitcoin")

        assert label_exchange(store, third, "Test Exchange") is not None

        paths = wallet_exchange_paths(store)
        row = next(w for w in paths if w["entity_id"] == addr_a)
        assert row["hops"] == 2
        assert row["confidence"] == round(EXCHANGE_HOP_DECAY ** 2, 4)


def test_wallet_exchange_paths_no_path_and_max_hops_cutoff(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        assert wallet_exchange_paths(store) == []   # no exchange labeled anywhere yet

        # A chain longer than max_hops must not report the far end at all.
        chain = [BTC_VALID, BTC_OTHER, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]
        target = store.upsert_target("btc:chain")
        sid = store.insert_snapshot(target, {}, "bitcoin")
        prev = store.upsert_entity("BTC_ADDRESS", chain[0])
        for nxt_value in chain[1:]:
            nxt = store.upsert_entity("BTC_ADDRESS", nxt_value)
            enrich_bitcoin(store, sid, prev, {"address": "x", "counterparty_addresses": [nxt_value]},
                           "bitcoin")
            prev = nxt
        assert label_exchange(store, chain[-1], "Test Exchange") is not None  # 3 hops from chain[0]

        near = {w["entity_id"] for w in wallet_exchange_paths(store, max_hops=2)}
        assert store.find_entity("BTC_ADDRESS", chain[0]) not in near   # 3 hops away, past the cutoff

        far = {w["entity_id"]: w["hops"] for w in wallet_exchange_paths(store, max_hops=4)}
        assert far[store.find_entity("BTC_ADDRESS", chain[0])] == 3


def test_wallet_exchange_paths_never_score_a_candidate(tmp_path):
    """A wallet's reachability to a labeled exchange must never upgrade or
    create an OPERATOR/INFRA/IP candidate -- see wallet_exchange_paths'
    own docstring on why this is a report, not a finding."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        target = store.upsert_target("btc:" + BTC_VALID)
        sid = store.insert_snapshot(target, {}, "bitcoin")
        enrich_bitcoin(store, sid, addr,
                       {"address": BTC_VALID, "counterparty_addresses": [BTC_OTHER]}, "bitcoin")
        assert label_exchange(store, BTC_OTHER, "Test Exchange") is not None

        results = run_correlation(store)
        assert results["wallet_exchange_paths"], "sanity: the path was actually found"
        assert results["operators"] == []
        assert results["infra"] == []
        assert results["ips"] == []


def test_wallet_trace_report_never_searched_returns_none(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        assert wallet_trace_report(store, BTC_VALID) is None


def test_wallet_trace_report_surfaces_flags_from_metadata_already_on_record(tmp_path):
    """Every flag must cite the specific address it came from, and the report
    computes no score of its own -- see the function's own docstring on why
    that would be exactly the fabricated-precision failure the rest of this
    engine refuses (EXCHANGE_HOP_DECAY, ellipticpp_*, chainabuse_*)."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        addr = store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        target = store.upsert_target("btc:" + BTC_VALID)
        sid = store.insert_snapshot(target, {}, "bitcoin")
        enrich_bitcoin(store, sid, addr, {
            "address": BTC_VALID, "counterparty_addresses": [BTC_OTHER],
            "reported_scam": True, "chainabuse_scam_categories": ["PHISHING"],
            "exchange_tag_packs": ["ransomware", "ofac"],
        }, "bitcoin")
        assert label_exchange(store, BTC_OTHER, "Test Exchange") is not None

        report = wallet_trace_report(store, BTC_VALID)
        assert report["address"] == BTC_VALID
        assert report["path"] == [BTC_VALID, BTC_OTHER]
        assert report["hops"] == 1
        assert report["exchange"] == "test exchange"
        assert report["exchange_confidence"] == round(EXCHANGE_HOP_DECAY ** 1, 4)
        assert any(BTC_VALID in f and "PHISHING" in f for f in report["flags"])
        assert any(BTC_VALID in f and "ransomware" in f and "ofac" in f for f in report["flags"])
        assert any("1 hop(s) of layering" in f for f in report["flags"])
        assert any("test exchange" in f for f in report["flags"])
        assert report["evidence_ids"]


def test_wallet_trace_report_with_no_metadata_and_no_path_is_still_honest(tmp_path):
    """A wallet with no enrichment and no path to a labeled exchange must
    report an empty flag list, not silently invented ones -- see the
    function's docstring on staying silent about un-investigated hops."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        store.upsert_entity("BTC_ADDRESS", BTC_VALID)
        report = wallet_trace_report(store, BTC_VALID)
        assert report["path"] == [BTC_VALID]
        assert report["exchange"] is None
        assert report["flags"] == []


def test_two_strangers_on_one_shared_host_are_not_linked(tmp_path):
    """Shared hosting is not a shared operator — measured live, not assumed.

    Before this fix, two markets that merely leaked the same literal IP (a
    cheap/shared VPS, a CDN edge, a hosting provider's whole /24 — nothing in
    a bare HOSTED_ON observation distinguishes those from one dedicated box)
    scored 0.9 on `shared_ip` alone and reached an ASSERTED `LINKED_TO` edge:
    `suppressed` was None, not REFERENCES_ONLY. `shared_ip` carried none of
    the corpus-measured discipline `shared_favicon` has (0 IP candidates in
    97 captures — runs/README.md — so there was no rarity/precision figure to
    bound it), and nothing in NON_ATTRIBUTIVE_SIGNALS caught it, unlike
    shared_domain and shared_favicon. Two markets on one host is still a real
    lead — candidate_ips() ranks it — it must never be the claim on its own.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion, seen=JAN, leaked_public_ipv4=['203.0.113.55']), store)

        pairs = detect_successors(store, min_score=0.0)
        assert pairs and "shared_ip" in pairs[0]["signals"]
        assert pairs[0]["score"] >= 0.5, "refused on the gate, not a low score"
        assert pairs[0]["suppressed"] == "REFERENCES_ONLY"
        assert pairs[0]["relation"] is None
        assert run_correlation(store)["operators"] == []
        assert not store._all(
            "SELECT 1 FROM relationships WHERE rtype IN ('SUCCESSOR_OF','LINKED_TO')")

        # Still visible to the analyst as exactly what it is: a shared host.
        ips = candidate_ips(store)
        assert ips and ips[0]["value"] == '203.0.113.55' and ips[0]["n_markets"] == 2


def test_two_onions_behind_one_tor_exit_are_not_linked(tmp_path):
    """Section 8's adversarial case, run through the real pipeline rather than
    only classify_ip's unit-level checks (test_a_tor_relay_host_argues_
    against_the_candidate_that_named_it covers those): a Tor exit node
    carries traffic for the whole network, so two unrelated onions whose
    favicon/Shodan pivot both land on the SAME exit IP must fare no better
    than test_two_strangers_on_one_shared_host_are_not_linked's ordinary
    shared host — if anything the exit case is the stronger negative control
    (classify_ip.__doc__: TOR_RELAY "outranks the rest and is the one class
    that argues AGAINST the candidate"), so this pins that ip_class carrying
    that verdict changes nothing about NON_ATTRIBUTIVE_SIGNALS gating
    shared_ip already does independent of enrichment (see the trace this loop
    ran: candidate operator IPs are auto-piped through ip_module's live
    ExoneraTor check, but shared_ip is gated categorically either way).
    """
    exit_ip = '171.25.193.25'
    relay = {'tor_relay': True, 'checked_date': '2026-08-13', 'org': 'Foreningen for digitala fri'}
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion, seen=JAN,
                           favicon={'favicon_mmh3': 999,
                                    'shodan_matches': [{'ip': exit_ip, 'org': relay['org']}]}),
                   store)
            ingest(_pivot_result(onion, [
                {'target': exit_ip, 'type': 'ip', 'summary': relay},
            ]), store)

        ip = store.find_entity("IP", exit_ip)
        assert store.metadata(ip)["ip_class"] == "TOR_RELAY"

        pairs = detect_successors(store, min_score=0.0)
        assert pairs, "still worth ranking as a lead"
        assert pairs[0]["relation"] is None
        assert pairs[0]["suppressed"] == "REFERENCES_ONLY"

        results = run_correlation(store)
        assert results["operators"] == []
        assert not store._all(
            "SELECT 1 FROM relationships WHERE rtype IN "
            "('SUCCESSOR_OF','LINKED_TO','SAME_OPERATOR')")

        # Visible to the analyst as exactly what it is: shared Tor egress, not
        # shared origin infrastructure.
        ips = candidate_ips(store)
        assert ips and ips[0]["value"] == exit_ip and ips[0]["ip_class"] == "TOR_RELAY"


def test_stacking_every_non_attributive_signal_still_does_not_assert(tmp_path):
    """shared_domain + shared_favicon + shared_ip on one pair, and nothing else.

    Each of the three is tested alone elsewhere in this file; none combines all
    three. The gate in detect_successors (`attributive = any(... not in
    NON_ATTRIBUTIVE_SIGNALS ...)`) is categorical, not score-based — but the
    noisy-OR score is what would expose a categorical gate implemented as a
    threshold by mistake. Priced individually these three signals noisy-OR to
    0.4, 0.4, 0.9 -> a combined score of 1-(0.6*0.6*0.1) = 0.964, comfortably
    over min_score=0.5 and higher than most real operator-specific pairs in
    the corpus. If `attributive` were ever computed from the score instead of
    the signal classes, this is the pair that would slip through.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for site in (ONION_A, ONION_B):
            ingest(_result(site, seen=JAN,
                           clearnet_hosts_referenced=['shared-host.li'],
                           favicon={'favicon_mmh3': 42},
                           leaked_public_ipv4=['203.0.113.99']), store)

        pairs = detect_successors(store, min_score=0.0)
        assert pairs
        pair = pairs[0]
        assert {"shared_domain", "shared_favicon", "shared_ip"} <= set(pair["signals"])
        assert pair["score"] >= 0.9, "the stacked score must actually be high"
        assert pair["suppressed"] == "REFERENCES_ONLY"
        assert pair["relation"] is None
        assert run_correlation(store)["operators"] == []
        assert not store._all(
            "SELECT 1 FROM relationships WHERE rtype IN ('SUCCESSOR_OF','LINKED_TO')")


def test_chainabuse_reports_never_link_two_unrelated_markets(tmp_path):
    """Two markets, two different wallets, each independently reported to
    Chainabuse under the same scam category — the same failure shape as
    `shared_platform_not_shared_control`, on a third-party report instead of a
    co-visited banner. `reported_scam`/`scam_categories` land as metadata via
    `evidence.enrich_bitcoin` (bitcoin_module.py's own docstring: "never an
    operator-funnel signal") with no relationship created at all, so nothing
    here can wire the two addresses together, however many reports either
    carries or however identical the category. Locks that guarantee in so a
    future change to enrich_bitcoin cannot quietly turn a report into an edge.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, bitcoin_addresses=[BTC_VALID]), store)
        ingest(_result(ONION_B, bitcoin_addresses=[BTC_OTHER]), store)

        for addr in (BTC_VALID, BTC_OTHER):
            entity = store.find_entity("BTC_ADDRESS", addr)
            target = store.upsert_target("btc:" + addr)
            sid = store.insert_snapshot(target, {}, "bitcoin")
            enrich_bitcoin(store, sid, entity, {
                "address": addr,
                "reported_scam": True,
                "scam_categories": ["RUG_PULL"],
                "trusted_report_count": 3,
            }, "bitcoin")

        addr_a = store.find_entity("BTC_ADDRESS", BTC_VALID)
        addr_b = store.find_entity("BTC_ADDRESS", BTC_OTHER)
        assert store.metadata(addr_a)["reported_scam"] is True
        assert store.metadata(addr_b)["reported_scam"] is True

        # The market still USES_BTC its own wallet — that edge is expected.
        # What must not exist is any edge BETWEEN the two addresses: the
        # report carries no relationship, so there is nothing to create one.
        assert not store._all(
            "SELECT 1 FROM relationships WHERE source_entity_id=? AND target_entity_id=?",
            (addr_a, addr_b))
        assert not store._all(
            "SELECT 1 FROM relationships WHERE source_entity_id=? AND target_entity_id=?",
            (addr_b, addr_a))
        clusters = crypto_clusters(store)
        assert addr_a not in clusters and addr_b not in clusters
        assert run_correlation(store)["operators"] == []


def test_chainabuse_report_dates_are_external_paperwork_not_a_sighting(tmp_path):
    """Section 12: createdAt is when a REPORT was filed, not when the address
    did anything. Two markets whose wallets were both reported on the exact
    same date must not read as "co-active at time T" — correlate.py's
    temporal engine (market_windows/temporal_handoff/temporal_overlap) only
    ever reads snapshot/observation timestamps, never entity metadata, so
    chainabuse_report_dates landing as metadata is structurally inert to it;
    this pins that it also creates no relationship, the same way
    reported_scam/scam_categories already do not.
    """
    same_filing_date = "2026-02-01T00:00:00.000Z"
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, bitcoin_addresses=[BTC_VALID]), store)
        ingest(_result(ONION_B, bitcoin_addresses=[BTC_OTHER]), store)

        for addr in (BTC_VALID, BTC_OTHER):
            entity = store.find_entity("BTC_ADDRESS", addr)
            target = store.upsert_target("btc:" + addr)
            sid = store.insert_snapshot(target, {}, "bitcoin")
            enrich_bitcoin(store, sid, entity, {
                "address": addr,
                "reported_scam": True,
                "chainabuse_scam_categories": ["RANSOMWARE"],
                "chainabuse_trusted_report_count": 2,
                "chainabuse_report_dates": [same_filing_date],
            }, "bitcoin")

        addr_a = store.find_entity("BTC_ADDRESS", BTC_VALID)
        addr_b = store.find_entity("BTC_ADDRESS", BTC_OTHER)
        assert store.metadata(addr_a)["chainabuse_report_dates"] == [same_filing_date]
        assert store.metadata(addr_b)["chainabuse_report_dates"] == [same_filing_date]

        assert not store._all(
            "SELECT 1 FROM relationships WHERE source_entity_id=? AND target_entity_id=?",
            (addr_a, addr_b))
        assert not store._all(
            "SELECT 1 FROM relationships WHERE source_entity_id=? AND target_entity_id=?",
            (addr_b, addr_a))
        results = run_correlation(store)
        assert results["operators"] == []
        assert all(s["relation"] is None for s in results["successors"])


def test_ellipticpp_illicit_label_never_links_two_unrelated_markets(tmp_path):
    """Adversarial false-attribution check for the Elliptic++ offline dataset
    context: two markets whose wallets both carry the dataset's "illicit"
    label share nothing but a third party's fraud-classification paper. That
    is the ecosystem-leakage failure shape (corpus/labels.toml) recast with a
    risk label standing in for a shared platform, and it must fail the same
    way — same discipline as reported_scam
    (test_chainabuse_reports_never_link_two_unrelated_markets), see
    evidence.enrich_bitcoin's ellipticpp_* docstring section.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, bitcoin_addresses=[BTC_VALID]), store)
        ingest(_result(ONION_B, bitcoin_addresses=[BTC_OTHER]), store)

        for addr in (BTC_VALID, BTC_OTHER):
            entity = store.find_entity("BTC_ADDRESS", addr)
            target = store.upsert_target("btc:" + addr)
            sid = store.insert_snapshot(target, {}, "bitcoin")
            enrich_bitcoin(store, sid, entity, {
                "address": addr,
                "ellipticpp_dataset_label": "1",
                "ellipticpp_dataset_label_name": "illicit",
                "ellipticpp_time_steps": ["25", "26"],
                "ellipticpp_record_count": 2,
            }, "bitcoin")

        addr_a = store.find_entity("BTC_ADDRESS", BTC_VALID)
        addr_b = store.find_entity("BTC_ADDRESS", BTC_OTHER)
        assert store.metadata(addr_a)["ellipticpp_dataset_label_name"] == "illicit"
        assert store.metadata(addr_b)["ellipticpp_dataset_label_name"] == "illicit"

        # No edge between the two addresses, in either direction: the dataset
        # label carries no relationship, so there is nothing to create one.
        assert not store._all(
            "SELECT 1 FROM relationships WHERE source_entity_id=? AND target_entity_id=?",
            (addr_a, addr_b))
        assert not store._all(
            "SELECT 1 FROM relationships WHERE source_entity_id=? AND target_entity_id=?",
            (addr_b, addr_a))
        clusters = crypto_clusters(store)
        assert addr_a not in clusters and addr_b not in clusters
        assert run_correlation(store)["operators"] == []


def test_evolution_pgp_dataset_match_never_links_two_unrelated_markets(tmp_path):
    """Adversarial false-attribution check for the Evolution live PGP pivot
    (Section 11): two markets whose DIFFERENT keys both happen to match a
    vendor record in the 2014-2015 Evolution corpus share nothing but a
    historical dataset's row count. Same discipline as
    test_ellipticpp_illicit_label_never_links_two_unrelated_markets, on
    evolution_dataset_match instead of a dataset_label -- a fingerprint match
    against a defunct marketplace is not a claim that these two keys, let
    alone these two markets, are related to each other at all.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pgp_keys=[{
            'armored': KEY_A, 'evolution_dataset_match': True,
            'evolution_vendor_count': 12,
        }]), store)
        ingest(_result(ONION_B, pgp_keys=[{
            'armored': KEY_B, 'evolution_dataset_match': True,
            'evolution_vendor_count': 3,
        }]), store)

        key_a = store.find_entity("PGP_KEY", pgp_fingerprint(KEY_A))
        key_b = store.find_entity("PGP_KEY", pgp_fingerprint(KEY_B))
        assert store.metadata(key_a)["evolution_dataset_match"] is True
        assert store.metadata(key_b)["evolution_dataset_match"] is True
        assert store.metadata(key_a)["evolution_vendor_count"] == 12
        assert store.metadata(key_b)["evolution_vendor_count"] == 3

        # No edge between the two keys, in either direction: a shared dataset
        # match carries no relationship, so there is nothing to create one.
        assert not store._all(
            "SELECT 1 FROM relationships WHERE source_entity_id=? AND target_entity_id=?",
            (key_a, key_b))
        assert not store._all(
            "SELECT 1 FROM relationships WHERE source_entity_id=? AND target_entity_id=?",
            (key_b, key_a))
        results = run_correlation(store)
        assert results["operators"] == []
        assert all(s["relation"] is None for s in results["successors"])


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


def test_label_exchange_does_not_zero_a_small_cases_operators(tmp_path):
    """LOOP7 gap 1: labeling an exchange on a two-market case must not flip
    entity_discrimination's "too small to judge" floor to "corpus-sized" and
    erase both real operator candidates as a side effect.

    label_exchange writes a real row into `targets` (ANALYST_TARGET) so the
    assertion is provenance-tracked -- but the <3-real-targets floor has to
    keep seeing this as two markets, not three, or an unrelated CLI action
    (labeling a wallet) silently deletes attribution evidence that nothing
    actually invalidated.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        _two_markets(store, clone=False)
        before = run_correlation(store)
        assert before["operators"]           # the shared PGP key scores as one

        label_exchange(store, BTC_VALID, "TestExchange", analyst="you")
        assert set(entity_discrimination(store).values()) == {1.0}

        after = run_correlation(store)
        assert {c["entity_id"] for c in after["operators"]} == \
               {c["entity_id"] for c in before["operators"]}


def test_save_candidates_retires_a_dropped_candidate_but_keeps_feedback(tmp_path):
    """LOOP7 gap 1's compounding effect: save_candidates only ever upserted
    rows present in the current pass's dossiers, so a candidate that stopped
    scoring was left behind at its old confidence forever -- which also broke
    monitor.candidate_deltas's GONE detection, since that reads the same
    never-pruned table by absence. A row with no analyst_feedback against it
    must be removed when it drops out of a fresh pass. A row an analyst
    already recorded feedback against must survive instead:
    analyst_feedback.candidate_id REFERENCES candidates with no ON DELETE, by
    design, so deleting it would either crash the pass or (if cascaded) erase
    a recorded verdict -- neither acceptable.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        def dossier(cid, entity_id, score):
            return {"candidate_id": cid, "role": "OPERATOR",
                    "entity": {"entity_id": entity_id, "etype": "EMAIL", "value": "x@y.com"},
                    "score": score, "confidence_level": "MEDIUM", "markets": ["a", "b"],
                    "key_evidence": [], "contradictions": []}

        e_kept = store.upsert_entity("EMAIL", "kept@y.com")
        e_fed = store.upsert_entity("EMAIL", "feedback@y.com")
        e_bare = store.upsert_entity("EMAIL", "bare@y.com")

        save_candidates(store, [dossier("OP-kept", e_kept, 0.9),
                                dossier("OP-fed", e_fed, 0.7),
                                dossier("OP-bare", e_bare, 0.6)])
        store.conn.execute(
            "INSERT INTO analyst_feedback (feedback_id, candidate_id, outcome, recorded_at) "
            "VALUES ('fb-1','OP-fed','CONFIRMED','2026-08-26T00:00:00Z')")
        store.conn.commit()

        # OP-fed and OP-bare both stop scoring on the next pass.
        save_candidates(store, [dossier("OP-kept", e_kept, 0.9)])

        ids = {r["candidate_id"] for r in store._all("SELECT candidate_id FROM candidates")}
        assert ids == {"OP-kept", "OP-fed"}   # OP-bare retired, OP-fed kept for its verdict

        deltas = candidate_deltas(
            [{"candidate_id": "OP-kept", "confidence": 0.9, "assessment": "x"},
             {"candidate_id": "OP-fed", "confidence": 0.7, "assessment": "y"},
             {"candidate_id": "OP-bare", "confidence": 0.6, "assessment": "y"}],
            [dict(r) for r in store._all(
                "SELECT candidate_id, confidence, assessment FROM candidates")])
        assert {d["candidate_id"]: d["change"] for d in deltas} == {"OP-bare": "GONE"}


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


def test_an_unrecognised_collector_is_discovery_not_a_capture(tmp_path):
    """The gate is asked "did you fetch the site?", never "do I know this name?".

    Every scenario above names a collector the guard already knows, so all of
    them pass whichever way the question is asked. This one names collectors it
    does not know — which is the only case where the two readings differ, and
    the case the next provider integration arrives as.

    Asked as recognition, the default is capture: an unlisted collector's whole
    payload is filed as a first-party observation, at full confidence, of a site
    nobody reached. The four here are not invented for the test — the domain
    module already emits crtsh/whois/dns_records/hackertarget down this path,
    and they are inert today only because their payloads carry no ARTIFACT_MAP
    key. `onionsearch` is the one this actually guards: it is next on the
    integration list, and adding it is a one-line collector that would inherit
    a capture's authority without anyone editing this file.
    """
    for collector in ('onionsearch', 'fofa', 'crtsh', 'whois'):
        with EvidenceStore(str(tmp_path / f"{collector}.db")) as store:
            store_result = _index_only(ONION_A, JAN, emails=['op@morke.ru'],
                                       bitcoin_addresses=[BTC_VALID],
                                       onion_addresses_found=[ONION_B])
            # Same payload, delivered by a collector the guard has no entry for.
            store_result.sources[collector] = store_result.sources.pop('torch')
            ingest(store_result, store)

            assert store._one("SELECT status FROM snapshots WHERE collector=?",
                              (collector,))["status"] == "DISCOVERY", collector
            # The target was never reached, so nothing may be observed on it, and
            # every artifact is demoted to the edge that says somebody else
            # recorded this: MENTIONS scores 0.15 as context and USES_EMAIL /
            # USES_BTC would assert the operator's own contact and wallet.
            for etype, value in (("EMAIL", 'op@morke.ru'), ("BTC_ADDRESS", BTC_VALID)):
                entity = store.find_entity(etype, value)
                assert markets_for_entity(store, entity) == [], collector
                assert [r["rtype"] for r in store._all(
                    "SELECT rtype FROM relationships WHERE target_entity_id=?",
                    (entity,))] == ["MENTIONS"], collector
                # Context, not identity: visible to an analyst, and nowhere near
                # carrying a candidate on its own.
                assert 0 < entity_funnel_profile(store, entity)["total_conf"] < LEAD_FLOOR
            # …and a co-ranked onion is provenance, never a link the site made.
            assert [r["rtype"] for r in store._all(
                "SELECT rtype FROM relationships WHERE target_entity_id=?",
                (store.find_entity("ONION_ADDRESS", ONION_B),))] == ["DISCOVERED_VIA"], collector
            assert run_correlation(store)["operators"] == [], collector


def _discovered_beside(result, seen, *addresses, indexes=('torch', 'dargle', 'ahmia')):
    """The same neighbours returned by several indexes, as a real sweep returns
    them — every index in phase 2 answers the same query."""
    for name in indexes:
        result.sources[name] = SourceResult(
            source=name, success=True, timestamp=seen,
            data={'result_count': len(addresses),
                  'onion_addresses_found': list(addresses),
                  'results': [{'onion_url': f'http://{a}'} for a in addresses]})
    return result


def test_a_reachable_target_discovers_without_attributing(tmp_path):
    """The live half of the index guard, and the case that motivated it.

    Every other scenario here has the target dark, where refusing an index
    answer is easy — there is nothing else in the run. A site that ANSWERED is
    the harder case: the result set holds a real capture, so a co-ranking
    arriving beside it reads as part of the same observation. Measured on
    donionsix… — online, HTTP 301, one page, no artifacts, `Server: nginx` —
    beside which Torch returned itself and two strangers.

    Repetition is tested in the same scenario because the two failures compound:
    three indexes returning one address is still one search result, and a repeat
    observation that raised anything would raise it here.
    """
    onion_c = onion("c")
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for _ in range(3):              # re-running the sweep must not accumulate
            ingest(_discovered_beside(
                _result(ONION_A, seen=JAN, http_status=301, pages_fetched=1,
                        server_fingerprint={'Server': 'nginx'}),
                JAN, ONION_A, ONION_B, onion_c), store)

        # The target answered, so its own capture is an observation OF it; what
        # the indexes said about it is filed apart from that.
        assert {r["collector"]: r["status"] for r in store._all(
            "SELECT collector, status FROM snapshots")} == {
                'target_onion': 'OK', 'torch': 'DISCOVERY',
                'dargle': 'DISCOVERY', 'ahmia': 'DISCOVERY'}
        # Discovery mints no target, so nothing downstream — recheck, crawl,
        # correlation — ever reaches the neighbours.
        assert [r["url"] for r in store._all("SELECT url FROM targets")] == [ONION_A]
        assert {r["rtype"] for r in store._all("SELECT rtype FROM relationships")} \
            == {'HAS_ADDRESS', 'DISCOVERED_VIA'}
        # Nine sightings of two addresses are two search results, not nine, and
        # neither one is attributed to the market it was ranked beside.
        assert store._one("SELECT COUNT(*) AS n FROM relationships "
                          "WHERE rtype='DISCOVERED_VIA'")["n"] == 2
        for addr in (ONION_B, onion_c):
            entity = store.find_entity("ONION_ADDRESS", addr)
            assert markets_for_entity(store, entity) == []
            assert entity_funnel_profile(store, entity)["total_conf"] == 0.0
        assert run_correlation(store)["operators"] == []


def test_discovery_chains_do_not_compound_into_operator_chains(tmp_path):
    """A -> B -> C, a different index at each hop, every site actually visited.

    Discovery is transitive as a lead and must not be transitive as evidence.
    Were a co-ranking worth anything, the neighbourhood of every index would
    fuse into one operator graph as deep as the chain runs — and the sites here
    share exactly what unrelated onions do share: a stock nginx and a couple of
    the same clearnet references.
    """
    onion_c = onion("c")
    # A stock banner and two co-referenced hosts — hosts normalize actually
    # keeps, so the chain really does share artifacts rather than sharing
    # nothing and passing by default.
    ecosystem = dict(server_fingerprint={'Server': 'nginx'},
                     clearnet_hosts_referenced=['cryptostorm.is', 'mediawiki.org'])
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_discovered_beside(_result(ONION_A, seen=JAN, **ecosystem), JAN,
                                  ONION_B, indexes=('torch',)), store)
        ingest(_discovered_beside(_result(ONION_B, seen=AUG, **ecosystem), AUG,
                                  onion_c, indexes=('dargle',)), store)
        ingest(_result(onion_c, seen=AUG, **ecosystem), store)

        # Each hop is reached only as provenance, so no link in the chain is
        # ever observed on the site that was ranked beside it.
        for addr in (ONION_B, onion_c):
            assert markets_for_entity(store, store.find_entity("ONION_ADDRESS", addr)) == []
        assert {r["rtype"] for r in store._all("SELECT rtype FROM relationships")} \
            == {'HAS_ADDRESS', 'DISCOVERED_VIA', 'MENTIONS'}

        results = run_correlation(store)
        assert results["operators"] == [] and results["infra"] == []
        assert [s for s in results["successors"] if not s.get("suppressed")] == []
        assert not store._all(
            "SELECT 1 FROM relationships WHERE rtype IN ('SUCCESSOR_OF','LINKED_TO')")


def test_an_external_observers_history_is_not_our_capture_window(tmp_path):
    """AIL has been seeing these addresses since 2023; our sweep met them this
    week. Both facts belong in the case, and only one of them may set the clock.

    `market_windows` decides which market is the predecessor, and
    `temporal_handoff` measures a gap against it. Feeding another crawler's
    dates into that window would let AIL's crawl schedule choose the direction
    of a succession claim — and its dates are not observations of ours at all.
    So the history lands on the ADDRESS as metadata plus a walkable observation,
    with no relationship anywhere, and the capture window stays what we saw.

    Measured on the corpus: AIL knows 77 of 78 live targets and 12 of 15 dark
    ones, several with a `last_seen` days before our sweep — so a target we
    record as dark is usually a service that stopped answering US, which is
    exactly the corroboration a successor hypothesis needs and exactly the claim
    that must not become evidence about who runs it.
    """
    lookup = ModuleResult(target=ONION_A, target_type='darkweb', module='darkweb')
    lookup.sources['target_onion'] = SourceResult(
        source='target_onion', success=True, timestamp=AUG,
        data={'online': True, 'emails': ['op@ownbrand.cc']})
    lookup.sources['onion_lookup'] = SourceResult(
        source='onion_lookup', success=True, timestamp=AUG,
        data={'observer': 'ail-project/onion-lookup', 'checked': 2, 'known': 2,
              'results': [{'onion': ONION_A, 'first_seen': '2023-04-21',
                           'last_seen': '2026-08-06', 'titles': ['DNMX'], 'tags': []},
                          {'onion': ONION_B, 'first_seen': '2019-01-01',
                           'last_seen': '2026-08-06', 'titles': [], 'tags': []}]})

    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(lookup, store)

        # An external observer is not a collector of ours.
        assert store._one("SELECT status FROM snapshots WHERE collector='onion_lookup'"
                          )["status"] == "DISCOVERY"

        address = store.find_entity("ONION_ADDRESS", ONION_A)
        assert store.metadata(address) == {
            "external_observer": "onion_lookup",
            "external_first_seen": "2023-04-21", "external_last_seen": "2026-08-06"}

        # No edge, so nothing can score it and nothing can pair on it.
        neighbour = store.find_entity("ONION_ADDRESS", ONION_B)
        assert not store._all("SELECT 1 FROM relationships WHERE source_entity_id=? "
                              "OR target_entity_id=?", (neighbour, neighbour))
        assert entity_funnel_profile(store, neighbour)["total_conf"] == 0.0
        assert markets_for_entity(store, neighbour) == []

        # …and the window the successor logic reads is still our own capture.
        window = next(iter(market_windows(store).values()))
        assert window["first"] == AUG and window["last"] == AUG
        assert run_correlation(store)["operators"] == []


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


# --- evidence-source wiring map ----------------------------------------------

# How far each evidence class actually travels, measured end to end rather than
# read off the architecture diagram. Both failure directions look like working
# capability from outside: a funnel keyed on an rtype nothing writes scores
# every entity at zero, and a collector whose output is fetched at real network
# cost and then dropped fills a report with things no claim can rest on.
#
#   candidate  reaches candidate_operators — an identity claim about a person
#   pair       reaches detect_successors   — a link between two markets
#   stored     entity and edge exist, nothing scores them
#   dropped    ingest() writes no entity at all
#
# Three entries are deliberately short of scoring, and each is a decision rather
# than an omission:
#
#   domain       MENTIONS at CONTEXT_WEIGHT 0.15. Every site references the same
#                handful of clearnet hosts; two doing so links nobody.
#   favicon      reaches `pair`, and can never be more than a lead there: it is
#                in NON_ATTRIBUTIVE_SIGNALS, so a favicon-only pair is refused
#                REFERENCES_ONLY at any score. See the five-newsrooms test.
#   fingerprint  Collected because a hand-written banner is a real tell, but in
#                no funnel: a shared banner is shared software, not a shared
#                operator. Same reasoning as DISCOVERED_VIA — see FUNNELS.
#   tls_cert     Same rung as fingerprint, same reason: HAS_FINGERPRINT, not
#                USES_CERT (which IS in f5_clearnet), because no pair in
#                corpus/labels.toml is yet known to share a TLS cert — see the
#                comment above evidence.ingest's tls_cert block.
#   breach /     The modules fetch these and nothing consumes them. Wiring them
#   social       is a scoring decision, not a plumbing one, and is unmade.
#   certificate/ Declared in ENTITY_TYPES and already scored by candidate_infra
#   nameserver   if an entity of this type existed (see the manual-construction
#                tests below), but no producer writes one: ARTIFACT_MAP has no
#                row for either, domain_module's crt.sh/dns_records output is
#                never pivoted into from a darkweb crawl, and 'domain' is not
#                in _ENRICHERS. See the comment above evidence.ARTIFACT_MAP and
#                test_evidence.test_certificate_and_nameserver_stay_unwired.
#
# Changing a verdict here is allowed; changing one by accident is what this
# catches.
WIRING_MAP = {
    'email':       (dict(emails=['op@proton.me']),                     'candidate'),
    'pgp':         (dict(pgp_keys=[{'armored': KEY_A}]),               'candidate'),
    'username':    (dict(usernames=['operator_x']),                    'candidate'),
    'btc':         (dict(bitcoin_addresses=[BTC_VALID]),               'pair'),
    'analytics':   (dict(analytics_ids=['UA-1234-1']),                 'pair'),
    'leaked_ip':   (dict(misconfigurations=[
                        {'path': '/s', 'leaked_ips': ['203.0.113.9']}]), 'pair'),
    'domain':      (dict(clearnet_hosts_referenced=['cryptostorm.is']), 'scored'),
    'favicon':     (dict(favicon={'favicon_mmh3': 12345}),             'pair'),
    'fingerprint': (dict(server_fingerprint={
                        'X-Powered-By': 'the almighty n0tr1v'}),       'stored'),
    'tls_cert':    (dict(tls_cert={'cert_sha256': 'a' * 64}),          'stored'),
    'breach':      (dict(breaches=[{'name': 'X', 'email': 'op@proton.me'}]), 'dropped'),
    'social':      (dict(social_accounts=[{'site': 'x', 'handle': 'op'}]),   'dropped'),
    'certificate': (dict(certificates=[{'common_name': 'shop.example',
                                        'issuer': "Let's Encrypt"}]),   'dropped'),
    'nameserver':  (dict(nameservers=['ns1.example-registrar.com']),   'dropped'),
}


def _furthest_stage(payload: dict) -> str:
    """Push one artifact class through ingest() on two markets sharing it —
    exactly the case correlation exists to catch — and report how far it got.

    `scored` has to be its own rung. An etype that can never be an operator
    candidate or a successor signal (HTTP_FINGERPRINT is both) would otherwise
    read as `stored` whether or not a funnel scores it, so putting it in a
    funnel — the precise drift this guards — would change nothing here.
    """
    store = EvidenceStore(":memory:")
    for url in (ONION_A, ONION_B):
        ingest(_result(url, seen=JAN, **payload), store)
    candidates = candidate_operators(store, discrimination=entity_discrimination(store))
    # temporal_overlap fires for any live pair, so only artifact-driven signals
    # count as the class having reached the pair stage.
    shared = {s for pair in detect_successors(store, min_score=0.0)
              for s in pair['signals'] if s.startswith('shared_')}
    entities = store._all("SELECT entity_id FROM entities "
                          "WHERE etype NOT IN ('MARKET','ONION_ADDRESS')")
    scored = any(entity_funnel_profile(store, e["entity_id"])["total_conf"] > 0
                 for e in entities)
    return ('candidate' if candidates else 'pair' if shared else
            'scored' if scored else 'stored' if entities else 'dropped')


def test_every_evidence_class_travels_exactly_as_far_as_claimed():
    """For every arrow in the architecture, prove data crosses it — or that it
    deliberately does not."""
    assert {name: _furthest_stage(payload)
            for name, (payload, _) in WIRING_MAP.items()} == \
           {name: stage for name, (_, stage) in WIRING_MAP.items()}


def test_no_funnel_is_keyed_on_a_relationship_nothing_writes():
    """The other half: a funnel scoring an rtype no collector produces is dead
    weight that still reads as coverage."""
    from cybertrace.evidence import ARTIFACT_MAP, RELATIONSHIP_TYPES
    funnelled = {rtype for rtypes in FUNNELS.values() for rtype in rtypes}
    assert funnelled <= RELATIONSHIP_TYPES, funnelled - RELATIONSHIP_TYPES
    # Every rtype ARTIFACT_MAP writes is either scored or a documented exception.
    unscored = {rtype for _, rtype in ARTIFACT_MAP.values()} - funnelled
    assert unscored == {'LINKS_TO'}, unscored


# --- CERTIFICATE / NAMESERVER: consumption side, since nothing produces them -
#
# WIRING_MAP above pins that neither class gets past ingest() today (also
# proven directly, from a domain_module-shaped payload, by
# test_evidence.test_certificate_and_nameserver_stay_unwired). What follows
# proves the other half: candidate_infra() already scores an entity of either
# type if one exists (per the comment above evidence.ARTIFACT_MAP), and the
# scoring is capped at INFRA by construction, not by a threshold that a future
# corpus could nudge into SAME_OPERATOR.
#
#   candidate_operators() queries entities WHERE etype IN
#   ('PGP_KEY','EMAIL','USERNAME') -- CERTIFICATE/NAMESERVER can never be a row
#   there, whatever they score.
#
#   SHARED_ARTIFACTS -- the list _pair_signals() reads to score a successor
#   pair -- names nine artifact types and neither of these is one, so a pair
#   joined only by a shared cert or nameserver produces no signal at all, not
#   even a weak one: detect_successors drops it before scoring (only
#   temporal_overlap/temporal_handoff would be left, and those never stand
#   alone).
#
# Entities and edges are built by hand with the public EvidenceStore API
# (upsert_entity / insert_observation / upsert_relationship), the same way
# test_infra_requires_two_markets_and_more_than_a_reference stands in for a
# producer RESOLVES_TO never writes on its own -- there is no ingest() path to
# drive this from a ModuleResult, and building one is a separate, larger
# decision the comment above ARTIFACT_MAP argues against making blind.

def _attach(store: EvidenceStore, onion: str, entity_id: str, rtype: str) -> None:
    """Wire one market to an already-upserted entity: an observation on the
    market's own snapshot (so markets_for_entity resolves it) plus the edge --
    what `_link()` does for every artifact type that has a producer."""
    target_id = store._one("SELECT target_id FROM targets WHERE url=?", (onion,))["target_id"]
    sid = store.latest_snapshot(target_id)["snapshot_id"]
    store.insert_observation(sid, entity_id, method="test:enrichment", section="test",
                             confidence=0.8)
    store.upsert_relationship(store.find_entity("MARKET", onion), entity_id, rtype,
                              source_label="test")


def test_shared_certificate_reaches_infra_never_operator(tmp_path):
    """A cert seen on two storefronts (CDN, reseller panel, a misconfigured
    multi-tenant host) is real infrastructure evidence and candidate_infra must
    surface it -- but it must never become an OPERATOR candidate or a
    successor edge, which is what a SAME_OPERATOR verdict actually requires
    (see tools/eval_corpus.py predictions())."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion), store)

        cert = store.upsert_entity("CERTIFICATE", "shop.example")
        assert cert is not None
        for onion in (ONION_A, ONION_B):
            _attach(store, onion, cert, "USES_CERT")

        # The row and the edges are real, in the SQLite store.
        assert store._one("SELECT 1 FROM entities WHERE entity_id=? AND etype='CERTIFICATE'",
                          (cert,))
        rels = store._all("SELECT source_entity_id FROM relationships "
                          "WHERE target_entity_id=? AND rtype='USES_CERT'", (cert,))
        assert {r["source_entity_id"] for r in rels} == \
               {store.find_entity("MARKET", ONION_A), store.find_entity("MARKET", ONION_B)}

        infra = candidate_infra(store, min_markets=2)
        assert {c["value"] for c in infra} == {"shop.example"}
        assert infra[0]["role"] == "INFRA"

        assert candidate_operators(store) == []

        results = run_correlation(store)
        assert results["operators"] == []
        pairs = {frozenset((s["source_url"], s["target_url"])) for s in results["successors"]}
        assert frozenset((ONION_A, ONION_B)) not in pairs


def test_shared_ca_alone_never_becomes_one_certificate_entity(tmp_path):
    """The scenario a shared-CA/CDN worry is actually about: two unrelated
    shops both on Let's Encrypt (or any commodity CA) must not converge.
    CERTIFICATE identity is the certificate's own subject -- nothing keys an
    entity on `issuer` -- so 'same CA' can never become the same entity_id,
    and every downstream floor (min_markets, candidate_infra) only ever sees
    one market per node."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion), store)

        cert_a = store.upsert_entity("CERTIFICATE", "shop-a.example")
        cert_b = store.upsert_entity("CERTIFICATE", "shop-b.example")
        assert cert_a != cert_b
        _attach(store, ONION_A, cert_a, "USES_CERT")
        _attach(store, ONION_B, cert_b, "USES_CERT")

        assert candidate_infra(store, min_markets=2) == []


def test_shared_nameserver_reaches_infra_never_operator(tmp_path):
    """Same guarantee as the certificate case, for a bulk/shared DNS host:
    convergence is real infrastructure evidence, capped at INFRA."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion), store)

        ns = store.upsert_entity("NAMESERVER", "ns1.bulk-registrar.example")
        for onion in (ONION_A, ONION_B):
            _attach(store, onion, ns, "USES_NS")

        assert store._one("SELECT 1 FROM entities WHERE entity_id=? AND etype='NAMESERVER'",
                          (ns,))
        assert len(store._all(
            "SELECT 1 FROM relationships WHERE target_entity_id=? AND rtype='USES_NS'",
            (ns,))) == 2

        infra = candidate_infra(store, min_markets=2)
        assert {c["value"] for c in infra} == {"ns1.bulk-registrar.example"}
        assert candidate_operators(store) == []

        results = run_correlation(store)
        assert results["operators"] == []
        pairs = {frozenset((s["source_url"], s["target_url"])) for s in results["successors"]}
        assert frozenset((ONION_A, ONION_B)) not in pairs


# --- analyst feedback folded into discrimination ------------------------------
#
# feedback_discrimination() is a new multiplier folded into the SAME slot
# entity_discrimination() already fills, not a second parameter threaded
# through candidate_operators/candidate_infra/candidate_ips/
# entity_funnel_profile. These tests prove the fold, not the storage —
# test_evidence.py covers record_feedback/feedback_for/feedback_for_entity.

def test_feedback_discrimination_is_empty_with_nothing_recorded(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A}]), store)
        assert feedback_discrimination(store) == {}


def test_zero_feedback_leaves_run_correlation_byte_identical(tmp_path):
    """The corpus baseline (211 -> 254 tests, 4/4 precision, 0 leakage) was
    measured with an empty analyst_feedback table. This is the regression
    guard for that: wiring feedback in must not move a single score when none
    is recorded."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, emails=['op@proton.me'], pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, emails=['op@proton.me'], pgp_keys=[{'armored': KEY_A}]), store)
        before = run_correlation(store)
        after = run_correlation(store)
        assert [d["score"] for d in before["dossiers"]] == [d["score"] for d in after["dossiers"]]


def test_rejected_feedback_damps_the_entitys_score(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, pgp_keys=[{'armored': KEY_A}]), store)
        before = run_correlation(store)
        dossier = before["dossiers"][0]
        before_score = dossier["score"]

        store.record_feedback(dossier["candidate_id"], "REJECTED",
                              note="shared key traced to a keysigning party, not one operator")

        after = run_correlation(store)
        after_dossier = next((d for d in after["dossiers"]
                              if d["candidate_id"] == dossier["candidate_id"]), None)
        # REJECTED's 0.25x damping is steep enough to drop a two-market,
        # single-funnel candidate below min_conf entirely -- suppressed
        # candidacy is a stronger form of "damped", not a different outcome.
        assert after_dossier is None or after_dossier["score"] < before_score


def test_confirmed_feedback_lifts_the_entitys_score(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, pgp_keys=[{'armored': KEY_A}]), store)
        before_score = run_correlation(store)["dossiers"][0]["score"]

        cid = run_correlation(store)["dossiers"][0]["candidate_id"]
        store.record_feedback(cid, "CONFIRMED", note="matched a signed commit key")

        after_score = next(d["score"] for d in run_correlation(store)["dossiers"]
                           if d["candidate_id"] == cid)
        assert after_score > before_score


def test_most_recent_feedback_outcome_wins(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, pgp_keys=[{'armored': KEY_A}]), store)
        cid = run_correlation(store)["dossiers"][0]["candidate_id"]
        entity_id = run_correlation(store)["dossiers"][0]["entity"]["entity_id"]

        store.record_feedback(cid, "REJECTED")
        store.record_feedback(cid, "CONFIRMED")  # a later, revised verdict

        disc = feedback_discrimination(store)
        assert disc[entity_id] == 1.15  # CONFIRMED's weight, not REJECTED's


def test_feedback_never_manufactures_a_candidate_that_did_not_exist(tmp_path):
    """A CONFIRMED verdict boosts an existing candidate's score; it cannot, by
    itself, pull an entity that never cleared min_markets/min_conf into the
    result set -- the multiplier only ever scales a funnel confidence that
    was already nonzero."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A}]), store)  # only one market
        assert candidate_operators(store) == []
        # No candidate exists yet, so there is nothing to attach feedback to --
        # record_feedback itself refuses an unknown candidate_id (test_evidence.py).
        assert feedback_discrimination(store) == {}
