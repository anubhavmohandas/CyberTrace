"""AI Investigator: context grounding, deterministic fallback, and the
provider-output validator (fabricated ids stripped, real contradictions
force-appended). Same real-capture fixture as test_case_api.py's
_make_case_db — no live network, no live LLM; FakeProvider stands in.
"""
import json
from pathlib import Path

import pytest

from cybertrace import investigator, llm_provider
from cybertrace.evidence import EvidenceStore, ingest
from cybertrace.llm_provider import FakeProvider, ProviderError

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = [ROOT / "runs" / "raw" / "v8" / "tortaxi-prd.json",
            ROOT / "runs" / "raw" / "v8" / "tortaxi-2dev.json"]


@pytest.fixture
def store():
    with EvidenceStore(":memory:") as s:
        for p in CAPTURES:
            ingest(json.loads(p.read_text()), s)
        s.update_case(name="tor.taxi mirror pair")
        yield s


@pytest.fixture(autouse=True)
def _clear_llm_env(monkeypatch):
    monkeypatch.delenv("CT_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("CT_LLM_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def test_context_known_ids_cover_dossier_evidence(store):
    assert CAPTURES[0].is_file(), "runs/raw/v8 tortaxi captures are missing"
    ctx = investigator.build_context(store)
    assert ctx["candidates"], "expected at least one candidate from the real tortaxi captures"
    for cand in ctx["candidates"]:
        assert cand["candidate_id"] in ctx["known_ids"]["candidate_ids"]
        for ev in cand["key_evidence"]:
            assert ev["observation_id"] in ctx["known_ids"]["evidence_ids"]
            assert ev["observation_id"] in ctx["_evidence_by_id"]


def test_deterministic_mode_connected_is_grounded(store):
    result = investigator.answer(store, "tortaxi", "why are these markets connected?")
    assert result["mode"] == "deterministic"
    assert result["case_id"] == "tortaxi"
    assert result["claims"], "expected at least one grounded claim"
    known_evidence = {e["id"] for e in result["evidence"]}
    for claim in result["claims"]:
        for eid in claim["evidence_ids"]:
            assert eid in known_evidence


def test_deterministic_mode_suppressed(store):
    result = investigator.answer(store, "tortaxi", "what did the engine reject?")
    assert result["mode"] == "deterministic"
    assert result["claims"], "tortaxi case is expected to carry a suppressed clone finding"
    assert all(c["kind"] == "SUPPRESSED" for c in result["claims"])


def test_deterministic_mode_insufficient_evidence(store):
    result = investigator.answer(store, "tortaxi", "what should I have for lunch today")
    assert result["mode"] == "deterministic"
    assert result["claims"] == []
    assert "does not have enough observed evidence" in result["answer"]


def test_live_mode_grounded_claim_passes_through(store, monkeypatch):
    ctx = investigator.build_context(store)
    cand = ctx["candidates"][0]
    real_evidence = cand["key_evidence"][0]["observation_id"]
    fake = FakeProvider({"grounded question": {
        "answer": "They share a real artifact.",
        "claims": [{"text": "grounded claim", "kind": "OBSERVED",
                    "evidence_ids": [real_evidence], "candidate_ids": [cand["candidate_id"]],
                    "finding_ids": []}],
        "limitations": [],
    }})
    monkeypatch.setattr(llm_provider, "get_provider", lambda: fake)
    result = investigator.answer(store, "tortaxi", "grounded question")
    assert result["mode"] == "live"
    assert result["claims"][0]["evidence_ids"] == [real_evidence]
    assert any(e["id"] == real_evidence for e in result["evidence"])


def test_live_mode_strips_fabricated_evidence_id(store, monkeypatch):
    ctx = investigator.build_context(store)
    cand = ctx["candidates"][0]
    fake = FakeProvider({"adversarial question": {
        "answer": "Confirmed same operator.",
        "claims": [{"text": "fabricated claim", "kind": "OBSERVED",
                    "evidence_ids": ["OBS-DOES-NOT-EXIST"],
                    "candidate_ids": [cand["candidate_id"]], "finding_ids": ["FIND-DOES-NOT-EXIST"]}],
        "limitations": [],
    }})
    monkeypatch.setattr(llm_provider, "get_provider", lambda: fake)
    result = investigator.answer(store, "tortaxi", "adversarial question")
    assert result["mode"] == "live"
    fabricated_claim = next(c for c in result["claims"] if c["text"] == "fabricated claim")
    assert fabricated_claim["evidence_ids"] == []
    assert fabricated_claim["finding_ids"] == []
    # the engine's real contradictions for the referenced candidate must still
    # surface, verbatim, regardless of what the model claimed
    real_contradiction_texts = {c["detail"] for c in cand["contradictions"]}
    if real_contradiction_texts:
        surfaced = {c["text"] for c in result["claims"]}
        assert real_contradiction_texts & surfaced


def test_live_mode_unknown_claim_kind_is_coerced(store, monkeypatch):
    ctx = investigator.build_context(store)
    cand = ctx["candidates"][0]
    fake = FakeProvider({"kind question": {
        "answer": "answer text",
        "claims": [{"text": "claim", "kind": "SAME_OPERATOR_CONFIRMED",
                    "evidence_ids": [], "candidate_ids": [cand["candidate_id"]], "finding_ids": []}],
        "limitations": [],
    }})
    monkeypatch.setattr(llm_provider, "get_provider", lambda: fake)
    result = investigator.answer(store, "tortaxi", "kind question")
    assert result["claims"][0]["kind"] == "INFERRED"


def test_provider_misconfigured_returns_error_mode_not_exception(store, monkeypatch):
    monkeypatch.setenv("CT_LLM_PROVIDER", "anthropic")
    result = investigator.answer(store, "tortaxi", "why are these connected")
    assert result["mode"] == "error"
    assert "misconfigured" in result["answer"].lower()


def test_provider_call_failure_returns_error_mode(store, monkeypatch):
    class BrokenProvider:
        def ask(self, question, context):
            raise ProviderError("simulated network failure")
    monkeypatch.setattr(llm_provider, "get_provider", lambda: BrokenProvider())
    result = investigator.answer(store, "tortaxi", "why are these connected")
    assert result["mode"] == "error"
    assert "unavailable" in result["answer"].lower()


def test_candidate_id_filters_context(store):
    full = investigator.build_context(store)
    one = full["candidates"][0]["candidate_id"]
    filtered = investigator.build_context(store, candidate_id=one)
    assert {c["candidate_id"] for c in filtered["candidates"]} == {one}


def _label_a_traced_wallet(store):
    """Wire a wallet -> exchange path into the tortaxi store, the same way an
    analyst would via `cybertrace label-exchange`."""
    from cybertrace.evidence import enrich_bitcoin, label_exchange
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    counterparty = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    addr = store.upsert_entity("BTC_ADDRESS", btc)
    target = store.upsert_target("btc:" + btc)
    sid = store.insert_snapshot(target, {}, "bitcoin")
    enrich_bitcoin(store, sid, addr, {"address": btc, "counterparty_addresses": [counterparty]},
                   "bitcoin")
    assert label_exchange(store, counterparty, "Test Exchange") is not None


def test_wallet_exchange_paths_are_citable_in_context(store):
    _label_a_traced_wallet(store)
    ctx = investigator.build_context(store)
    assert ctx["wallet_exchange_paths"], "expected the labeled path to appear in context"
    for w in ctx["wallet_exchange_paths"]:
        for eid in w["evidence_ids"]:
            assert eid in ctx["known_ids"]["evidence_ids"]
            assert eid in ctx["_evidence_by_id"]


def test_deterministic_mode_answers_nearest_exchange(store):
    _label_a_traced_wallet(store)
    result = investigator.answer(store, "tortaxi", "which vasp is closest to this wallet")
    assert result["mode"] == "deterministic"
    assert result["claims"], "expected at least one wallet-exchange claim"
    assert any("test exchange" in c["text"].lower() for c in result["claims"])
    known_evidence = {e["id"] for e in result["evidence"]}
    for claim in result["claims"]:
        for eid in claim["evidence_ids"]:
            assert eid in known_evidence
    # Loop 37: risk was previously invisible to this natural-language answer
    # even though run_correlation already attached it to the same rows every
    # other surface reads. ANALYST_ASSERTED carries no risk rule, so this
    # must read INSUFFICIENT_EVIDENCE -- never a silently implied LOW.
    assert any("INSUFFICIENT_EVIDENCE" in c["text"] for c in result["claims"])
    assert any("not a finding of low risk" in c["text"] for c in result["claims"])


def test_deterministic_mode_answers_nearest_exchange_with_a_real_disclosed_wallet_role(store):
    """Real Bitfinex cold-wallet ground truth (test_correlate.py's own
    BITFINEX_COLD, independently verified via Bitfinex's own GitHub
    proof-of-reserves repo) must surface its disclosed role through the same
    natural-language answer, not just the CLI/report renderers."""
    from cybertrace.evidence import enrich_bitcoin
    from cybertrace.integrations import exchange_tags

    from .test_correlate import BITFINEX_COLD

    if not (exchange_tags.available() and exchange_tags.index_available()):
        pytest.skip("GraphSense TagPacks not downloaded/indexed in this checkout")

    btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    addr = store.upsert_entity("BTC_ADDRESS", btc)
    sid = store.insert_snapshot(store.upsert_target("btc:" + btc), {}, "bitcoin")
    enrich_bitcoin(store, sid, addr, {"address": btc, "sent_to_addresses": [BITFINEX_COLD]},
                   "bitcoin")

    result = investigator.answer(store, "tortaxi", "which vasp is closest to this wallet")
    assert result["mode"] == "deterministic"
    assert any("disclosed as a cold wallet" in c["text"] for c in result["claims"])


def test_deterministic_mode_wallet_answer_surfaces_chain_and_direct_vasp_contacts(store):
    """chain (an EVM address is otherwise an indistinguishable bare "0x...")
    and direct_vasp_contacts (a self-attributed suspect's own additional VASP
    relationship, AT_VASP rows only) were previously invisible to every
    natural-language question -- only trace-wallet's own CLI `flags` prose
    had them. Same AT_VASP construction test_monitor.py's watch-cycle tests
    already use."""
    from cybertrace.evidence import enrich_bitcoin, label_exchange
    suspect = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    other_vasp_wallet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert label_exchange(store, suspect, "VASP A") is not None
    assert label_exchange(store, other_vasp_wallet, "VASP B") is not None
    addr = store.upsert_entity("BTC_ADDRESS", suspect)
    sid = store.insert_snapshot(store.upsert_target("btc:" + suspect), {}, "bitcoin")
    enrich_bitcoin(store, sid, addr,
                   {"address": suspect, "counterparty_addresses": [other_vasp_wallet]},
                   "bitcoin")

    result = investigator.answer(store, "tortaxi", "which vasp is closest to this wallet")
    assert result["mode"] == "deterministic"
    assert "chains involved: BTC_ADDRESS" in result["answer"]
    assert any("(BTC_ADDRESS)" in c["text"] for c in result["claims"])
    assert any("Also directly reaches: vasp b" in c["text"] for c in result["claims"])


@pytest.mark.parametrize("question", [
    "are there any high-risk wallet alerts?",
    "tell me about this wallet",
    "which chains are involved in this case?",
])
def test_deterministic_router_reaches_wallet_exchange_for_risk_chain_and_wallet_questions(
        store, question):
    """_wallet_exchange was previously only reachable via "vasp"/"exchange"/
    "deposit" -- a literal risk/wallet/chain question fell through to the
    generic _insufficient fallback even though a working, grounded handler
    already existed for it."""
    _label_a_traced_wallet(store)
    result = investigator.answer(store, "tortaxi", question)
    assert result["mode"] == "deterministic"
    assert result["claims"], f"expected a grounded wallet claim for: {question!r}"


def test_wallet_exchange_answer_cites_risk_alerts(store):
    """risk_alerts (the case's own HIGH/CRITICAL-filtered, ranked list) was
    computed by run_correlation but never reached build_context at all --
    every other surface (CLI/Markdown/HTML/GUI) already had a dedicated
    section for it (Loop 41 audit). Real data: Polyanin's own OFAC
    self-designation, CRITICAL/80 (see test_correlate.py's identical
    fixture)."""
    from .test_correlate import _real_polyanin_case, _skip_unless_real_sources_available

    _skip_unless_real_sources_available()
    _real_polyanin_case(store)

    ctx = investigator.build_context(store)
    assert len(ctx["risk_alerts"]) == 1
    assert ctx["risk_alerts"][0]["risk"]["risk_level"] == "CRITICAL"

    result = investigator.answer(store, "tortaxi", "are there any high-risk wallet alerts?")
    assert result["mode"] == "deterministic"
    assert any("1 wallet(s) reached HIGH or CRITICAL" in c["text"] for c in result["claims"])


def test_wallet_exchange_answer_surfaces_a_recorded_wallet_verdict(store):
    """Loop 41: a wallet-level analyst verdict (new in this loop, kept apart
    from analyst_feedback/candidates) must reach the Investigator as its own
    ANALYST_VERDICT claim, the same claim kind _boundary already uses for a
    candidate verdict -- never folded into the INFERRED wallet-reachability
    claim beside it."""
    _label_a_traced_wallet(store)
    addr = store.find_entity("BTC_ADDRESS", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    store.record_wallet_feedback(addr, "MALICIOUS", note="matched a prior case",
                                 analyst="jdoe")

    result = investigator.answer(store, "tortaxi", "which vasp is closest to this wallet")
    assert result["mode"] == "deterministic"
    verdict_claims = [c for c in result["claims"] if c["kind"] == "ANALYST_VERDICT"]
    assert verdict_claims, "expected an ANALYST_VERDICT claim for the wallet"
    assert "MALICIOUS" in verdict_claims[0]["text"]
    assert "matched a prior case" in verdict_claims[0]["text"]


def test_wallet_exchange_answer_cites_a_real_cross_chain_link(store):
    """Loop 41: cross_chain_links (real OFAC-sourced multi-chain profiles)
    must reach the Investigator's context and be citable in an answer, the
    same way risk_alerts now is."""
    from .test_correlate import SIM_HYON_SOP_ETH, SIM_HYON_SOP_TRX
    from cybertrace.integrations import ofac
    if not (ofac.available() and ofac.index_available()):
        pytest.skip("OFAC SDN not downloaded/indexed in this checkout")

    store.upsert_entity("ETH_ADDRESS", SIM_HYON_SOP_ETH)
    store.upsert_entity("TRX_ADDRESS", SIM_HYON_SOP_TRX)

    ctx = investigator.build_context(store)
    assert len(ctx["cross_chain_links"]) == 1
    assert ctx["cross_chain_links"][0]["entity_name"] == "Sim Hyon Sop"

    result = investigator.answer(store, "tortaxi", "any cross-chain links in this case?")
    assert result["mode"] == "deterministic"
    assert any("Cross-chain: Sim Hyon Sop" in c["text"] for c in result["claims"])


def test_boundary_answer_surfaces_a_recorded_analyst_verdict(store):
    """analyst_feedback (candidates.verdict in build_context) was computed
    into context but no answer path ever read it -- "has this candidate
    already been reviewed?" got no verdict-aware answer even deterministically.
    Also exercises ANALYST_VERDICT, a claim kind CLAIM_KINDS/llm_provider's
    own prompt already defined but no answer path had ever emitted."""
    from cybertrace.correlate import run_correlation

    before = run_correlation(store)
    cid = before["dossiers"][0]["candidate_id"]
    # CONFIRMED, not REJECTED -- REJECTED damps score (see
    # test_rejected_feedback_damps_the_entitys_score) and can push a
    # candidate below min_conf, dropping it from dossiers entirely before
    # this test gets to check whether its verdict is answerable at all.
    store.record_feedback(cid, "CONFIRMED", note="matched a signed commit key", analyst="jdoe")

    result = investigator.answer(store, "tortaxi", "does this prove the same operator?")
    assert result["mode"] == "deterministic"
    verdict_claims = [c for c in result["claims"] if c["kind"] == "ANALYST_VERDICT"]
    assert verdict_claims, "expected an ANALYST_VERDICT claim"
    assert "CONFIRMED" in verdict_claims[0]["text"]
    assert "matched a signed commit key" in verdict_claims[0]["text"]
    assert verdict_claims[0]["candidate_ids"] == [cid]


def test_live_mode_strips_fabricated_wallet_evidence_id(store, monkeypatch):
    _label_a_traced_wallet(store)
    fake = FakeProvider({"nearest exchange question": {
        "answer": "Reaches an exchange in one hop.",
        "claims": [{"text": "fabricated wallet claim", "kind": "INFERRED",
                    "evidence_ids": ["OBS-WALLET-DOES-NOT-EXIST"],
                    "candidate_ids": [], "finding_ids": []}],
        "limitations": [],
    }})
    monkeypatch.setattr(llm_provider, "get_provider", lambda: fake)
    result = investigator.answer(store, "tortaxi", "nearest exchange question")
    assert result["claims"][0]["evidence_ids"] == []


def test_does_this_prove_the_same_operator_refuses_while_citing_evidence(store):
    """The one question that decides whether a case becomes a warrant.

    It used to fall through every intent to "CyberTrace does not have enough
    observed evidence to establish that" — misleading in a case holding a 0.91
    candidate, and an analyst could read it as an empty case. The bounded
    answer has to do three things at once: refuse the attribution, cite the
    evidence that does exist, and say the judgement is a human's.
    """
    result = investigator.answer(store, "tortaxi", "does this prove the same operator?")
    assert result["mode"] == "deterministic"
    assert "does not have enough observed evidence" not in result["answer"]
    assert result["answer"].startswith("No.")
    assert "not proof of common control" in result["answer"]
    assert "human judgement" in result["answer"]

    # Refusing is not hand-waving: the support it declines to promote is cited,
    # and every cited id resolves to evidence the caller is handed.
    observed = [c for c in result["claims"] if c["kind"] == "OBSERVED"]
    assert observed and all(c["evidence_ids"] for c in observed)
    known = {e["id"] for e in result["evidence"]}
    for claim in result["claims"]:
        for eid in claim["evidence_ids"]:
            assert eid in known
    assert any("never a proven identity" in l for l in result["limitations"])


def test_a_question_that_is_not_yes_or_no_is_not_answered_no(store):
    """"What remains uncertain?" is not a yes/no question, and was being
    answered "No.".

    The boundary handler assembles exactly what a limitations question wants —
    band, standing objections, limitations — so routing "uncertain" into it was
    right. Its opening was not: the sentence is hardcoded for "does this prove
    …?", and "certain" is a substring of "uncertain", so the boundary keywords
    swallowed the phrasing either way. An analyst asking what is still open got
    a flat refusal to a question nobody asked.
    """
    for question in ("what remains uncertain?", "why is this candidate weak?"):
        result = investigator.answer(store, "tortaxi", question)
        assert "does not have enough observed evidence" not in result["answer"], question
        assert not result["answer"].startswith("No."), question
        # Same bounded content as the yes/no form — cited, not merely narrated.
        assert "not proof of common control" in result["answer"], question
        assert result["limitations"], question
        known = {e["id"] for e in result["evidence"]}
        for claim in result["claims"]:
            for eid in claim["evidence_ids"]:
                assert eid in known, question


def test_a_standing_objection_is_as_walkable_as_the_support_it_argues_against(store):
    """Supporting ids resolved to observations while contradicting ids resolved
    to a finding whose own evidence list was empty — so 'what supports this'
    was checkable and 'what contradicts this' was not. For a tool whose safety
    property is that contradictions constrain attribution, that asymmetry ran
    the wrong way."""
    ctx = investigator.build_context(store)
    contradictions = [c for c in ctx["contradictions"] if c.get("evidence_ids")]
    assert contradictions, "expected at least one evidence-backed contradiction"
    for c in contradictions:
        for eid in c["evidence_ids"]:
            assert eid in ctx["known_ids"]["evidence_ids"]
            assert eid in ctx["_evidence_by_id"]
            assert ctx["_evidence_by_id"][eid]["sha256"]

    result = investigator.answer(store, "tortaxi", "what contradicts the attribution?")
    suppressed = [c for c in result["claims"] if c["kind"] == "SUPPRESSED"]
    assert suppressed and any(c["evidence_ids"] for c in suppressed)
