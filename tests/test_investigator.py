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
