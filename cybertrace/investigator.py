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

from .correlate import evidence_chain, run_correlation
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

    dossiers = results["dossiers"]
    if candidate_id:
        dossiers = [d for d in dossiers if d["candidate_id"] == candidate_id]

    candidates, evidence_by_id, candidate_ids = [], {}, set()
    for d in dossiers:
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
            # build_dossier already computed this (canonical, Loop 40) -- no
            # second feedback_for_entity query here.
            "timeline": d["timeline"], "verdict": d["verdict"],
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
    # cite its evidence the same validated way as everything else. Includes
    # direct_vasp_contacts/secondary_vasp_contacts' own evidence_ids (AT_VASP
    # rows only), not just the primary path's -- _wallet_exchange cites both.
    wallet_exchange_paths = results["wallet_exchange_paths"]
    for w in wallet_exchange_paths:
        contacts = (w.get("direct_vasp_contacts") or []) + (w.get("secondary_vasp_contacts") or [])
        ids = w["evidence_ids"] + [i for c in contacts for i in c.get("evidence_ids", [])]
        for e in evidence_chain(store, ids):
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
        # The case's own HIGH/CRITICAL-filtered, ranked list -- every other
        # surface (CLI, Markdown, HTML, GUI) has a dedicated section for this;
        # without it, "what are the alerts on this case" could only be
        # answered by scanning every wallet_exchange_paths row by hand
        # (Loop 41 audit). Reads the same `risk` field each row already
        # carries -- no second scoring pass.
        "risk_alerts": results.get("risk_alerts", []),
        # Real, government/VASP-sourced cross-chain groupings (Loop 41) --
        # see correlate.cross_chain_links' own docstring for exactly which
        # evidence this reads and why it invents no confidence number.
        "cross_chain_links": results.get("cross_chain_links", []),
        # Real, live-fetched bridge/swap records (Loop 42) -- see
        # correlate.run_correlation's own read (canonical, no second query).
        "transaction_cross_chain_links": results.get("transaction_cross_chain_links", []),
        "data_source_status": results.get("data_source_status", {}),
        # Persisted `watch` cycles (Loop 42) -- run_correlation's own read
        # (canonical, no second query), capped here so a long-running case
        # doesn't inflate every answer's context with its entire monitoring
        # history. _changed cites the latest row.
        "watch_history": (results.get("watch_history") or [])[:10],
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
    # The most recent persisted `watch` cycle (Loop 42) -- the one other
    # source of "what changed" this case has, distinct from the per-artifact
    # case_history above: a watch run diffs the whole case against its own
    # last check, not one candidate against a prior correlation pass.
    runs = ctx.get("watch_history") or []
    if runs:
        latest = runs[0]
        claims.append({
            "text": f"Last watch run at {latest['checked_at']}: "
                    f"{len(latest['wallet_deltas'])} wallet delta(s), "
                    f"{len(latest['candidate_deltas'])} candidate delta(s), "
                    f"{len(latest['risk_alerts'])} risk alert(s)"
                    + (f" — {latest['narrative']}" if latest.get('narrative') else ""),
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
    # Loop 43 audit: this guard previously fired on `paths` alone, so a case
    # with real transaction_cross_chain_links (Loop 42) but no VASP-path
    # wallet got a blanket "insufficient evidence" for every wallet/chain/
    # bridge/swap question -- the live bridge/swap evidence was already in
    # context and simply never reached, the same "computed but unreachable"
    # gap the deposit_candidate fix above addresses for a different field.
    if not paths and not ctx.get("transaction_cross_chain_links"):
        return _insufficient("No wallet in this case has a recorded path to an "
                             "analyst-labeled exchange address, and no live "
                             "bridge/swap record is on file.")
    # risk/wallet_role are read off the SAME wallet_exchange_paths rows
    # run_correlation already attached them to (_attach_wallet_risk) -- no
    # second score_wallet_risk call, so this answer can never disagree with
    # the CLI/Markdown/HTML/GUI surfaces reading the identical field (Loop 37
    # cross-surface consistency: risk was previously invisible to every
    # natural-language question, even though the data was already here).
    claims = []
    alerts = ctx.get("risk_alerts") or []
    if alerts:
        # The case's own HIGH/CRITICAL-filtered list, cited by name rather
        # than left for a reader to re-derive by scanning every wallet claim
        # below -- every other surface (CLI/Markdown/HTML/GUI) has this exact
        # list as its own section (Loop 41 audit: this was previously the
        # one field the Investigator's context did not carry at all).
        names = ", ".join(f"`{_short(a['value'], 24)}` ({a['risk']['risk_level']})"
                          for a in alerts)
        claims.append({
            "text": f"{len(alerts)} wallet(s) reached HIGH or CRITICAL risk-v1: {names}.",
            "kind": "INFERRED",
            "evidence_ids": [i for a in alerts for i in a.get("evidence_ids", [])],
            "candidate_ids": [], "finding_ids": [],
        })
    for w in paths:
        role = f", disclosed as a {w['wallet_role'].lower()} wallet" if w.get("wallet_role") else ""
        r = w.get("risk") or {}
        risk_phrase = (f" Risk: {r['risk_level']} (score {r['risk_score']}, {r['risk_policy_version']})."
                       if r.get("risk_score") is not None
                       else " Risk: INSUFFICIENT_EVIDENCE -- not a finding of low risk.")
        # Computed by wallet_exchange_paths (1-hop, one-way TO_VASP only --
        # see correlate._is_deposit_candidate) but previously never read past
        # the JSON report (Loop 43 audit): silently dropped from every prose
        # surface including this one. Framed as reachability, not identity --
        # the same caveat _is_deposit_candidate's own docstring gives for why
        # AT_VASP/INDIRECT/BOTH_WAYS are excluded.
        deposit_phrase = (" Possible 1-hop deposit endpoint (reachability only, not proof "
                          "of a customer relationship)." if w.get("deposit_candidate") else "")
        # direct/secondary_vasp_contacts (AT_VASP rows only) are structured
        # fields wallet_exchange_paths already computed -- this was
        # previously narrated only in trace-wallet's own `flags` prose, so a
        # suspect's own additional VASP relationships (e.g. Polyanin's direct
        # Binance deposits alongside his primary designation) were invisible
        # to every question this module answers.
        contacts = (w.get("direct_vasp_contacts") or []) + (w.get("secondary_vasp_contacts") or [])
        contacts_phrase = ""
        if w.get("direct_vasp_contacts"):
            names = ", ".join(sorted({c["exchange"] for c in w["direct_vasp_contacts"]}))
            contacts_phrase += f" Also directly reaches: {names}."
        if w.get("secondary_vasp_contacts"):
            names = ", ".join(sorted({c["exchange"] for c in w["secondary_vasp_contacts"]}))
            contacts_phrase += f" Reaches further out: {names}."
        # A genuine same-address, same-or-higher-tier SECOND attribution
        # (Loop 42) -- e.g. two OFAC profiles or two analyst citations
        # naming this SAME address. Distinct from direct/secondary contacts
        # above, which are OTHER addresses; this is a conflict on THIS one,
        # surfaced rather than silently merged into a single "winner".
        also = w.get("also_attributed") or []
        if also:
            names = ", ".join(sorted({c["exchange"] for c in also}))
            contacts_phrase += (f" ALSO attributed to (conflicting evidence on this "
                               f"same address, not merged): {names}.")
        contact_evidence = [i for c in contacts + also for i in c.get("evidence_ids", [])]
        claims.append({
            "text": f"`{_short(w['value'], 32)}` ({w['chain']}) — {w['proximity']} to {w['exchange']} "
                    f"({w['hops']} hop(s), flow {w['direction']}, "
                    f"{w['attribution']}: {w['attribution_source']}{role}, "
                    f"reachability {w['confidence']:.2f}).{deposit_phrase}{risk_phrase}{contacts_phrase}",
            "kind": "INFERRED", "evidence_ids": w["evidence_ids"] + contact_evidence,
            "candidate_ids": [], "finding_ids": [],
        })
        # A recorded human decision on this SAME wallet -- kept as its own
        # ANALYST_VERDICT claim (the claim kind _boundary already uses for a
        # candidate verdict) rather than folded into the INFERRED claim
        # above, so an automated finding and a human's conclusion about it
        # stay visibly distinguishable here too.
        if w.get("verdict"):
            v = w["verdict"]
            claims.append({
                "text": f"Analyst verdict on {_short(w['value'], 32)}: {v['outcome']}" +
                        (f" — {v['note']}" if v["note"] else "") +
                        f" (recorded by {v['analyst'] or 'unknown'} at {v['recorded_at']}).",
                "kind": "ANALYST_VERDICT", "evidence_ids": [],
                "candidate_ids": [], "finding_ids": [],
            })
    # Same entity named on more than one chain by one evidence record (Loop
    # 41) -- never inferred from address similarity, timing, or amount; see
    # correlate.cross_chain_links' own docstring for exactly what evidence
    # this reads and why it carries no invented confidence number.
    for link in ctx.get("cross_chain_links") or []:
        addrs = ", ".join(f"{_short(m['value'], 24)} ({m['chain']})" for m in link["members"])
        claims.append({
            "text": f"Cross-chain: {link['entity_name']} ({link['attribution']}) is named "
                    f"on more than one chain by the same evidence record: {addrs}.",
            "kind": "INFERRED", "evidence_ids": [],
            "candidate_ids": [], "finding_ids": [],
        })
    # Real, live-fetched bridge/swap records (Loop 42) -- distinct from the
    # cross-chain claim above, which reads the local OFAC/VASP-disclosure/
    # GraphSense corpora for a SHARED designation. A record here is a live
    # third party's own transaction; never read as proof of shared control.
    for tx in ctx.get("transaction_cross_chain_links") or []:
        dest = (f"{_short(tx['dest_address'], 24)} ({tx['dest_chain']})"
               if tx.get("dest_address") else "an unsupplied destination")
        claims.append({
            "text": f"Transaction cross-chain: a {tx['mechanism'].lower()} moved value from "
                    f"{_short(tx['source_address'], 24)} ({tx['source_chain']}) to {dest}, "
                    f"per {tx['source_api']} (ref: {tx['evidence_ref']})"
                    + (f" ({tx['status']})" if tx.get("status") else "") + ".",
            # A live third party's own transaction record, not a graph-derived
            # relationship -- OBSERVED, not INFERRED, matching the kind this
            # module uses everywhere else for a first-hand fact (Loop 43 --
            # this claim was previously mislabeled INFERRED alongside genuine
            # graph-proximity inferences, undermining the observed/inferred
            # split the GUI's own Evidence tab advertises). No evidence_ids:
            # cross_chain_tx_links is its own table, not the observations
            # store `evidence_ids` resolves against -- the citation above is
            # the real reference (evidence_ref), not a fabricated one.
            "kind": "OBSERVED", "evidence_ids": [],
            "candidate_ids": [], "finding_ids": [],
        })
    not_fresh = [name for name, state in ctx.get("data_source_status", {}).items()
                if state != "FRESH"]
    chains = ", ".join(sorted({w["chain"] for w in paths}))
    answer = (f"Nearest VASP-attributed address for each traced wallet "
             f"(chains involved: {chains}):") if paths \
        else "No traced wallet has a recorded path to a VASP; live bridge/swap records only:"
    return {"answer": answer,
            "claims": claims,
            "limitations": ([
                f"Data source(s) not fresh: {', '.join(not_fresh)} -- a 'no match' from "
                f"these does not mean 'checked, clean', it may mean the local corpus is "
                f"stale or was never downloaded."] if not_fresh else []) + [
                "ANALYST_ASSERTED endpoints are a human's cited claim; REGULATORY_ATTESTED "
                "endpoints are an OFAC SDN designation of that address (not always a VASP -- "
                "some designated parties are a market or a mixer); VASP_DISCLOSED endpoints "
                "are on the VASP's own verified published wallet list; TAG_ATTESTED endpoints "
                "are a third party's public tagpack entry. None is CyberTrace's own finding, "
                "and none is written as an edge.",
                "Hop distance is reachability, not proof of an intentional transfer.",
                "Direction UNKNOWN means the capture never recorded which way value "
                "moved — it is not evidence of a deposit.",
                "Wallet role (hot/cold/reserve) is only ever the VASP's own disclosure, "
                "never an inference from balance or transaction volume.",
                "Risk is a policy-scored priority signal (risk-v1), not a probability and "
                "not proof of criminality -- kept separate from VASP attribution above."]}


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
    # ctx["candidates"][i]["verdict"] (build_context) was computed but never
    # read by any answer path -- an analyst's own recorded conclusion, kept
    # distinguishable from the engine's score/band via the already-defined
    # but previously unused ANALYST_VERDICT claim kind (see CLAIM_KINDS /
    # llm_provider's own prompt, which already told the live model this kind
    # exists).
    claims += [{
        "text": f"Analyst verdict on {c['entity']['etype'].replace('_', ' ').lower()} "
                f"`{_short(c['entity']['value'], 32)}`: {c['verdict']['outcome']}" +
                (f" — {c['verdict']['note']}" if c['verdict']['note'] else "") +
                f" (recorded by {c['verdict']['analyst'] or 'unknown'} "
                f"at {c['verdict']['recorded_at']}).",
        "kind": "ANALYST_VERDICT", "evidence_ids": [],
        "candidate_ids": [c["candidate_id"]], "finding_ids": [],
    } for c in ctx["candidates"] if c.get("verdict")]
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
    (("vasp", "exchange", "deposit", "wallet", "risk", "alert", "chain", "bridge", "swap"),
     _wallet_exchange),
]


def _deterministic_answer(question: str, ctx: dict) -> dict:
    q = question.lower()
    for keywords, handler in _INTENTS:
        if any(k in q for k in keywords):
            return handler(ctx)
    return _insufficient("Try asking about connections, suppressed relationships, "
                          "the strongest candidate, what changed, wallet/VASP "
                          "reachability and risk, or next steps.")


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
