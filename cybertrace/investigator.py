"""AI Investigator: an explanation/reasoning interface over CyberTrace's own
evidence, NOT a second attribution engine.

Two moving parts:

    build_context()   bounded, serializable slice of what run_correlation()
                       and memory.py already computed for a case — the ONLY
                       facts an answer is allowed to draw on. Nothing here is
                       recomputed; every field is read off correlate.py's own
                       dossiers/contradictions/successors and memory.py's own
                       retrieval functions.

    answer()           no llm_provider configured -> a deterministic answer
                       built directly from the context (same intents the old
                       scripted frontend matched, now grounded in the real
                       store instead of client-side fixture state). Provider
                       configured -> the provider's untrusted JSON reply is
                       validated against context["known_ids"] before a single
                       evidence/candidate/finding id from it is trusted: any
                       id the model didn't get from context is stripped, never
                       forwarded. Every candidate a validated answer references
                       also gets its real contradictions/limitations appended
                       verbatim, so a reader is never shown the model's framing
                       without CyberTrace's own record beside it — see the
                       module-level CLAIM_KINDS distinction below.

Attribution boundary: this module must never manufacture a candidate, a
relationship, a score, or an attribution conclusion. It only narrates what
correlate.py and memory.py already decided.
"""

from __future__ import annotations

from typing import List, Optional

from .correlate import evidence_chain, run_correlation, market_windows
from .memory import case_history, historical_matches, prior_references, summarize
from .evidence import EvidenceStore
from . import llm_provider

CLAIM_KINDS = frozenset({"OBSERVED", "INFERRED", "SUPPRESSED", "ANALYST_VERDICT", "MEMORY"})


def _short(v: str, n: int = 40) -> str:
    return v if not v or len(v) <= n else v[: n - 1] + "…"


def _assessment(cand: dict) -> str:
    ent = cand["entity"]
    return (f"Shared {ent['etype'].replace('_', ' ').title()} across "
            f"{len(cand['markets'])} onion(s): " + ", ".join(_short(m, 30) for m in cand["markets"]) + ".")


def build_context(store: EvidenceStore, candidate_id: Optional[str] = None) -> dict:
    """Bounded, serializable case context. Deliberately not a raw store dump —
    only fields an answer is allowed to cite end up here."""
    results = run_correlation(store)
    windows = market_windows(store)

    dossiers = results["dossiers"]
    if candidate_id:
        dossiers = [d for d in dossiers if d["candidate_id"] == candidate_id]

    candidates, evidence_by_id, candidate_ids = [], {}, set()
    for d in dossiers:
        verdict = None
        feedback = store.feedback_for_entity(d["entity"]["entity_id"])
        if feedback:
            latest = feedback[0]
            verdict = {"outcome": latest["outcome"], "note": latest["note"] or "",
                       "analyst": latest["analyst"] or "", "recorded_at": latest["recorded_at"]}
        for ke in d["key_evidence"]:
            evidence_by_id[ke["observation_id"]] = {
                "id": ke["observation_id"], "extraction_method": ke["extraction_method"],
                "url": ke["url"], "sha256": ke["sha256"], "observed_at": ke["observed_at"],
                "confidence": ke["confidence"],
            }
        candidate_ids.add(d["candidate_id"])
        candidates.append({
            "candidate_id": d["candidate_id"], "role": d["role"],
            "confidence_level": d["confidence_level"], "score": d["score"],
            "entity": d["entity"], "markets": d["markets"],
            "assessment": _assessment(d),
            "key_evidence": d["key_evidence"], "contradictions": d["contradictions"],
            "recommended_actions": d["recommended_actions"], "limitations": d["limitations"],
            "timeline": d["timeline"], "verdict": verdict,
        })

    suppressed_relationships = [{
        "source_url": s["source_url"], "target_url": s["target_url"],
        "relation": s["relation"], "suppressed": s["suppressed"], "score": s["score"],
        "why": s["signals_detail"][0]["detail"] if s["signals_detail"] else "",
        "evidence_ids": s.get("evidence_ids") or [],
    } for s in results["successors"] if s["suppressed"]]

    markets = sorted({r["url"] for r in store._all("SELECT url FROM targets")})
    memory_ctx = {}
    for url in markets:
        matches = historical_matches(store, url)
        memory_ctx[url] = {
            "historical_matches": summarize(matches),
            "case_history": case_history(store, url),
            "prior_references": prior_references(store, url),
        }

    finding_ids = {c["finding_id"] for c in results["contradictions"] if c.get("finding_id")}

    # A contradiction's own observations, registered like any other evidence so
    # an objection can be cited and walked back instead of read on faith.
    for c in list(results["contradictions"]) + suppressed_relationships:
        for e in evidence_chain(store, c.get("evidence_ids") or []):
            evidence_by_id[e["observation_id"]] = {
                "id": e["observation_id"], "extraction_method": e["extraction_method"],
                "url": e["url"], "sha256": e["sha256"], "observed_at": e["observed_at"],
                "confidence": e["confidence"],
            }

    # Wallet reachability is its own report, not a candidate (see
    # correlate.wallet_exchange_paths) -- pulled in here only so an answer can
    # cite its evidence the same validated way as everything else.
    wallet_exchange_paths = results["wallet_exchange_paths"]
    for w in wallet_exchange_paths:
        for e in evidence_chain(store, w["evidence_ids"]):
            evidence_by_id[e["observation_id"]] = {
                "id": e["observation_id"], "extraction_method": e["extraction_method"],
                "url": e["url"], "sha256": e["sha256"], "observed_at": e["observed_at"],
                "confidence": e["confidence"],
            }

    return {
        "case": store.case_info(),
        "markets": markets,
        "candidates": candidates,
        "suppressed_relationships": suppressed_relationships,
        "contradictions": results["contradictions"],
        "wallet_exchange_paths": wallet_exchange_paths,
        "memory": memory_ctx,
        "known_ids": {
            "evidence_ids": set(evidence_by_id),
            "candidate_ids": candidate_ids,
            "finding_ids": finding_ids,
        },
        "_evidence_by_id": evidence_by_id,
    }


# ---------------------------------------------------------------- deterministic

def _insufficient(note: str = "") -> dict:
    text = "CyberTrace does not have enough observed evidence to establish that."
    return {"answer": f"{text} {note}".strip(), "claims": [], "limitations": []}


def _connected(ctx: dict) -> dict:
    claims = [{
        "text": f"{c['entity']['etype'].replace('_', ' ')} `{_short(c['entity']['value'], 32)}` "
                f"observed directly on {', '.join(_short(m, 24) for m in c['markets'])} — "
                f"score {c['score']:.2f}, band {c['confidence_level']}.",
        "kind": "OBSERVED", "evidence_ids": [e["observation_id"] for e in c["key_evidence"]],
        "candidate_ids": [c["candidate_id"]], "finding_ids": [],
    } for c in ctx["candidates"]]
    if not claims:
        return _insufficient("No candidate relationships are recorded for this case yet.")
    return {"answer": "Direct evidence collected on both markets, not inferred:",
            "claims": claims, "limitations": []}


def _suppressed(ctx: dict) -> dict:
    claims = [{
        "text": f"{(s['suppressed'] or s['relation'] or 'relationship').replace('_', ' ')} between "
                f"{_short(s['source_url'], 28)} and {_short(s['target_url'], 28)}: {s['why']}",
        "kind": "SUPPRESSED",
        "evidence_ids": [i for i in (s.get("evidence_ids") or [])
                         if i in ctx["known_ids"]["evidence_ids"]],
        "candidate_ids": [], "finding_ids": [],
    } for s in ctx["suppressed_relationships"]]
    claims += [{
        "text": c["detail"], "kind": "SUPPRESSED",
        "evidence_ids": [i for i in (c.get("evidence_ids") or [])
                         if i in ctx["known_ids"]["evidence_ids"]],
        "candidate_ids": [],
        "finding_ids": [c["finding_id"]] if c.get("finding_id") else [],
    } for c in ctx["contradictions"]]
    if not claims:
        return {"answer": "Nothing was suppressed or contradicted in this case.",
                "claims": [], "limitations": []}
    return {"answer": "Standing objections recorded and left unresolved rather than silently discounted:",
            "claims": claims, "limitations": []}


def _strongest(ctx: dict) -> dict:
    if not ctx["candidates"]:
        return _insufficient("No candidates are recorded for this case yet.")
    best = max(ctx["candidates"], key=lambda c: c["score"])
    return {"answer": f"{best['entity']['etype'].replace('_', ' ')} "
                       f"`{_short(best['entity']['value'], 32)}`, score {best['score']:.2f}, "
                       f"band {best['confidence_level']}. {best['assessment']}",
            "claims": [{
                "text": best["assessment"], "kind": "OBSERVED",
                "evidence_ids": [e["observation_id"] for e in best["key_evidence"]],
                "candidate_ids": [best["candidate_id"]], "finding_ids": [],
            }], "limitations": []}


def _why_here(ctx: dict) -> dict:
    if not ctx["candidates"]:
        return _insufficient("No candidates are recorded for this case yet.")
    claims = [{
        "text": f"{c['assessment']} Every observation resolves to a snapshot hash.",
        "kind": "OBSERVED", "evidence_ids": [e["observation_id"] for e in c["key_evidence"]],
        "candidate_ids": [c["candidate_id"]], "finding_ids": [],
    } for c in ctx["candidates"]]
    return {"answer": "Every candidate here entered through a direct capture, not through inference:",
            "claims": claims, "limitations": []}


def _changed(ctx: dict) -> dict:
    claims = []
    for url, mem in ctx["memory"].items():
        for prior in mem["case_history"]:
            note = (f" [analyst: {prior['analyst_feedback'][0]['outcome']}]"
                    if prior["analyst_feedback"] else "")
            claims.append({
                "text": f"Prior correlation pass scored {prior['etype']} `{_short(prior['value'], 28)}` "
                        f"on {_short(url, 24)} at confidence {prior['confidence']:.2f} "
                        f"as of {prior['last_scored']}{note}",
                "kind": "MEMORY", "evidence_ids": [], "candidate_ids": [], "finding_ids": [],
            })
    if not claims:
        return {"answer": "No prior correlation run is on record for this case to compare against — "
                           "this is what the current pass found.",
                "claims": [], "limitations": []}
    return {"answer": "Prior-investigation record for the artifacts on these markets:",
            "claims": claims, "limitations": []}


def _next_steps(ctx: dict) -> dict:
    if not ctx["candidates"]:
        return _insufficient("No candidates are recorded to base next steps on.")
    claims = []
    for c in ctx["candidates"]:
        for action in c["recommended_actions"]:
            claims.append({"text": action, "kind": "INFERRED", "evidence_ids": [],
                            "candidate_ids": [c["candidate_id"]], "finding_ids": []})
    limitations = sorted({lim for c in ctx["candidates"] for lim in c["limitations"]})
    return {"answer": "Recommended next steps, grounded in the current candidates:",
            "claims": claims, "limitations": limitations}


def _wallet_exchange(ctx: dict) -> dict:
    paths = ctx["wallet_exchange_paths"]
    if not paths:
        return _insufficient("No wallet in this case has a recorded path to an "
                             "analyst-labeled exchange address.")
    claims = [{
        "text": f"`{_short(w['value'], 32)}` — {w['proximity']} to {w['exchange']} "
                f"({w['hops']} hop(s), flow {w['direction']}, "
                f"{w['attribution']}: {w['attribution_source']}, "
                f"reachability {w['confidence']:.2f}).",
        "kind": "INFERRED", "evidence_ids": w["evidence_ids"],
        "candidate_ids": [], "finding_ids": [],
    } for w in paths]
    return {"answer": "Nearest VASP-attributed address for each traced wallet:",
            "claims": claims,
            "limitations": [
                "ANALYST_ASSERTED endpoints are a human's cited claim; TAG_ATTESTED "
                "endpoints are a third party's public tagpack entry. Neither is "
                "CyberTrace's own finding, and neither is written as an edge.",
                "Hop distance is reachability, not proof of an intentional transfer.",
                "Direction UNKNOWN means the capture never recorded which way value "
                "moved — it is not evidence of a deposit."]}


def _boundary(ctx: dict, lead: str = "No. ") -> dict:
    """"Does this prove the same operator?" — the one question the attribution
    boundary exists to answer, and the one an analyst carries into a warrant.

    Answered from what the engine already decided: the band it assigned, the
    objections standing against it, and its own limitations. Nothing is
    recomputed and no verdict is offered, because there isn't one to offer --
    the honest answer is what the evidence reaches and where it stops.
    """
    if not ctx["candidates"]:
        return _insufficient("No candidates are recorded for this case yet.")
    best = max(ctx["candidates"], key=lambda c: c["score"])
    contradicted = [c for c in ctx["candidates"] if c["contradictions"]]
    claims = [{
        "text": f"{c['assessment']} Scored {c['score']:.2f}, band {c['confidence_level']} — "
                f"a rank against others in this case, not a probability.",
        "kind": "OBSERVED", "evidence_ids": [e["observation_id"] for e in c["key_evidence"]],
        "candidate_ids": [c["candidate_id"]], "finding_ids": [],
    } for c in ctx["candidates"]]
    claims += [{
        "text": contra["detail"], "kind": "SUPPRESSED",
        "evidence_ids": [i for i in (contra.get("evidence_ids") or [])
                         if i in ctx["known_ids"]["evidence_ids"]],
        "candidate_ids": [c["candidate_id"]],
        "finding_ids": [contra["finding_id"]] if contra.get("finding_id") else [],
    } for c in contradicted for contra in c["contradictions"]]
    answer = (f"{lead}The strongest candidate is {best['entity']['etype'].replace('_', ' ').lower()} "
              f"`{_short(best['entity']['value'], 32)}` at {best['score']:.2f} ({best['confidence_level']}), "
              f"which is shared-artifact evidence, not proof of common control.")
    if contradicted:
        answer += (f" {len(contradicted)} candidate(s) additionally have a standing objection "
                   f"that has not been resolved.")
    answer += " Attribution is a human judgement on the evidence below."
    return {"answer": answer, "claims": claims,
            "limitations": sorted({lim for c in ctx["candidates"] for lim in c["limitations"]})}


def _limits(ctx: dict) -> dict:
    """Same bounded evidence as _boundary, for a question that is not yes/no.

    "What remains uncertain?" and "why is this candidate weak?" want exactly
    what the boundary answer already assembles -- band, standing objections,
    limitations -- but answering either of them "No." replies to a question the
    analyst did not ask.
    """
    return _boundary(ctx, lead="")


_INTENTS = [
    # Ordered: the boundary question is matched before the looser keyword sets
    # below, so "does this prove they are connected?" gets the bounded answer
    # rather than the connection list it also mentions.
    #
    # _limits comes first because "certain" is a substring of "uncertain" --
    # the boundary set would otherwise swallow the limitation phrasings and
    # answer them "No."
    (("uncertain", "limitation", "how sure", "confident", "weak"), _limits),
    (("prove", "proof", "certain", "same operator", "same person",
      "who controls"), _boundary),
    (("connect", "related", "linked", "support", "evidence for"), _connected),
    (("reject", "suppress", "why not", "didn't", "contradict", "objection",
      "against"), _suppressed),
    (("strongest",), _strongest),
    (("why is this here", "why here", "why is it here"), _why_here),
    (("changed", "different", "update", "since"), _changed),
    (("next step", "investigate next", "recommended action"), _next_steps),
    (("vasp", "exchange", "deposit"), _wallet_exchange),
]


def _deterministic_answer(question: str, ctx: dict) -> dict:
    q = question.lower()
    for keywords, handler in _INTENTS:
        if any(k in q for k in keywords):
            return handler(ctx)
    return _insufficient("Try asking about connections, suppressed relationships, "
                          "the strongest candidate, what changed, or next steps.")


# ------------------------------------------------------------------------ live

def _validate(raw: dict, ctx: dict) -> dict:
    """Untrusted provider JSON in, grounded dict out. Every evidence/candidate/
    finding id is checked against ctx['known_ids'] — anything the model didn't
    get from the context is dropped, never forwarded to the UI."""
    known = ctx["known_ids"]
    claims = []
    for c in raw.get("claims") or []:
        if not isinstance(c, dict) or not c.get("text"):
            continue
        kind = c.get("kind") if c.get("kind") in CLAIM_KINDS else "INFERRED"
        claims.append({
            "text": str(c["text"]), "kind": kind,
            "evidence_ids": [i for i in (c.get("evidence_ids") or []) if i in known["evidence_ids"]],
            "candidate_ids": [i for i in (c.get("candidate_ids") or []) if i in known["candidate_ids"]],
            "finding_ids": [i for i in (c.get("finding_ids") or []) if i in known["finding_ids"]],
        })

    answer_text = str(raw.get("answer") or "").strip() or "The model returned no answer text."
    limitations = [str(x) for x in (raw.get("limitations") or []) if isinstance(x, str)]

    # The engine's own record for any candidate referenced is force-appended,
    # verbatim, regardless of what the model wrote — a fabricated attribution
    # framing can never be shown without the real contradictions/limitations
    # sitting right next to it (see module docstring's attribution boundary).
    referenced = {cid for c in claims for cid in c["candidate_ids"]}
    for cand in ctx["candidates"]:
        if cand["candidate_id"] not in referenced:
            continue
        for contra in cand["contradictions"]:
            claims.append({
                "text": contra["detail"], "kind": "SUPPRESSED",
                "evidence_ids": [i for i in (contra.get("evidence_ids") or [])
                                 if i in known["evidence_ids"]],
                "candidate_ids": [cand["candidate_id"]],
                "finding_ids": [contra["finding_id"]] if contra.get("finding_id") in known["finding_ids"] else [],
            })
        limitations.extend(cand["limitations"])

    seen, deduped_limitations = set(), []
    for lim in limitations:
        if lim not in seen:
            seen.add(lim)
            deduped_limitations.append(lim)

    return {"answer": answer_text, "claims": claims, "limitations": deduped_limitations}


def _finalize(raw: dict, ctx: dict, case_id: str, mode: str) -> dict:
    evidence_ids: List[str] = []
    seen = set()
    for c in raw["claims"]:
        for eid in c["evidence_ids"]:
            if eid not in seen:
                seen.add(eid)
                evidence_ids.append(eid)
    return {
        "answer": raw["answer"], "claims": raw["claims"],
        "evidence": [ctx["_evidence_by_id"][eid] for eid in evidence_ids],
        "limitations": raw["limitations"], "mode": mode, "case_id": case_id,
    }


def answer(store: EvidenceStore, case_id: str, question: str,
          candidate_id: Optional[str] = None) -> dict:
    ctx = build_context(store, candidate_id)
    try:
        provider = llm_provider.get_provider()
    except llm_provider.ProviderError as e:
        return _finalize(_insufficient(f"Investigator backend misconfigured: {e}"), ctx, case_id, "error")

    if provider is None:
        return _finalize(_deterministic_answer(question, ctx), ctx, case_id, "deterministic")

    try:
        raw = provider.ask(question, ctx)
    except llm_provider.ProviderError as e:
        return _finalize(_insufficient(f"Investigator backend unavailable: {e}"), ctx, case_id, "error")

    return _finalize(_validate(raw, ctx), ctx, case_id, "live")


def demo() -> None:
    """occam: exercises the deterministic/validation branches without a real
    EvidenceStore fixture — the store-backed paths (build_context,
    integration through answer()) are covered by tests/test_investigator.py,
    which needs the real tortaxi captures pytest already fixtures with."""
    ctx = {
        "candidates": [{
            "candidate_id": "OP-abc12345", "role": "OPERATOR", "confidence_level": "MEDIUM",
            "score": 0.71, "entity": {"etype": "PGP_KEY", "value": "ABCD1234", "entity_id": "e1"},
            "markets": ["a.onion", "b.onion"], "assessment": "Shared PGP Key across 2 onion(s): a.onion, b.onion.",
            "key_evidence": [{"observation_id": "OBS-1", "extraction_method": "pgp_key", "url": "a.onion",
                              "sha256": "deadbeef", "observed_at": "2026-01-01T00:00:00", "confidence": 0.9}],
            "contradictions": [{"detail": "clone-consistent overlap", "finding_id": "FIND-1"}],
            "recommended_actions": ["watch for reuse"], "limitations": ["probabilistic"],
            "timeline": [], "verdict": None,
        }],
        "suppressed_relationships": [], "contradictions": [],
        "wallet_exchange_paths": [{"entity_id": "e2", "value": "bc1qabc", "exchange": "Test Exchange",
                                   "hops": 1, "confidence": 0.75, "path": ["e2", "e3"],
                                   "evidence_ids": ["OBS-2"]}],
        "known_ids": {"evidence_ids": {"OBS-1", "OBS-2"}, "candidate_ids": {"OP-abc12345"},
                     "finding_ids": {"FIND-1"}},
        "_evidence_by_id": {"OBS-1": {"id": "OBS-1"}, "OBS-2": {"id": "OBS-2"}},
    }

    det = _deterministic_answer("why are they connected", ctx)
    assert det["claims"][0]["evidence_ids"] == ["OBS-1"]

    wallet_det = _deterministic_answer("which vasp is closest to this wallet", ctx)
    assert wallet_det["claims"][0]["evidence_ids"] == ["OBS-2"]

    fabricated = _validate({"answer": "same operator confirmed", "claims": [
        {"text": "fabricated", "kind": "OBSERVED", "evidence_ids": ["OBS-FAKE"],
         "candidate_ids": ["OP-abc12345"], "finding_ids": ["FIND-FAKE"]}]}, ctx)
    assert fabricated["claims"][0]["evidence_ids"] == [], "fabricated evidence id must be stripped"
    # the real contradiction must still be force-appended next to the model's claim
    assert any(c["text"] == "clone-consistent overlap" for c in fabricated["claims"])

    fabricated_wallet = _validate({"answer": "closest exchange", "claims": [
        {"text": "fabricated wallet hop", "kind": "INFERRED", "evidence_ids": ["OBS-WALLET-FAKE"],
         "candidate_ids": [], "finding_ids": []}]}, ctx)
    assert fabricated_wallet["claims"][0]["evidence_ids"] == [], \
        "fabricated wallet-path evidence id must be stripped"

    print("investigator.demo() OK")


if __name__ == "__main__":
    demo()
