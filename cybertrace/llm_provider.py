"""LLM provider boundary for the AI Investigator (investigator.py).

Kept deliberately thin and swappable: investigator.py never imports `requests`
or knows an HTTP shape, only `Provider.ask(question, context) -> dict`. That
return value is untrusted model output — investigator.py validates every
evidence/candidate/finding id it references before any of it reaches a UI.

Configuration is env-only (CT_LLM_PROVIDER / CT_LLM_API_KEY / CT_LLM_MODEL),
never hardcoded, matching case_api.py's own CT_API_KEY convention. Unset
CT_LLM_PROVIDER is not an error — get_provider() returns None and
investigator.py falls back to a deterministic, clearly-labeled evidence-only
answer instead of pretending to be AI-generated.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional, Protocol

import requests

ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-opus-5"

SYSTEM_PROMPT = """You are the evidence-grounding layer of CyberTrace, a dark-web OSINT \
investigation tool. You are given a JSON "context" containing everything the \
correlation engine has already found for one case: candidate dossiers, \
suppressed/successor relationships, contradictions, recommended actions, \
limitations, and prior-investigation memory. You answer the analyst's \
question using ONLY facts present in that context.

Rules, no exceptions:
- Never state or imply a SAME_OPERATOR / same-person conclusion beyond what a \
candidate's own "role" and "confidence_level" in the context already say.
- Never treat a suppressed relationship as confirmed, and never omit a \
standing contradiction for a candidate you discuss.
- Never invent an evidence id, candidate id, or finding id. Only reference \
ids that literally appear in the context.
- If the context does not contain enough to answer, say so plainly instead \
of guessing.
- Distinguish OBSERVED (a raw observation), INFERRED (engine-derived from \
observations), SUPPRESSED (rejected/contradicted), ANALYST_VERDICT (human \
feedback), and MEMORY (prior-investigation context) — never collapse these.

Respond with ONLY a single JSON object (no markdown fences, no prose outside \
it), matching exactly this shape:
{
  "answer": "<natural-language answer, 1-4 sentences>",
  "claims": [
    {"text": "<one grounded claim>", "kind": "OBSERVED|INFERRED|SUPPRESSED|ANALYST_VERDICT|MEMORY",
     "evidence_ids": ["<ids from context.known_ids.evidence_ids>"],
     "candidate_ids": ["<ids from context.known_ids.candidate_ids>"],
     "finding_ids": ["<ids from context.known_ids.finding_ids>"]}
  ],
  "limitations": ["<any caveat worth surfacing beyond what's already in the candidate's own limitations>"]
}"""


class ProviderError(Exception):
    """The provider could not produce an answer (misconfigured, unreachable,
    malformed reply) — caught by investigator.answer() and turned into an
    explicit mode="error" response, never a crash."""


class Provider(Protocol):
    def ask(self, question: str, context: dict) -> dict: ...


class AnthropicProvider:
    """Raw HTTP via `requests` (already a project dependency) — no SDK added,
    matching case_api.py's own no-new-dependency stance."""

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, timeout: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def ask(self, question: str, context: dict) -> dict:
        body = {
            "model": self.model,
            "max_tokens": 2048,
            "system": SYSTEM_PROMPT,
            "messages": [{
                "role": "user",
                "content": f"context = {json.dumps(context, ensure_ascii=False)}\n\nquestion = {question!r}",
            }],
        }
        try:
            resp = requests.post(
                ANTHROPIC_MESSAGES_URL,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.api_key,
                    "anthropic-version": ANTHROPIC_VERSION,
                },
                json=body, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            raise ProviderError(f"could not reach Anthropic API: {e}") from e

        if resp.status_code != 200:
            raise ProviderError(f"Anthropic API returned HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            text = resp.json()["content"][0]["text"]
        except (KeyError, IndexError, ValueError) as e:
            raise ProviderError(f"unexpected Anthropic response shape: {e}") from e

        return _parse_json_object(text)


def _parse_json_object(text: str) -> dict:
    """Model is instructed to emit only JSON, but strip stray markdown fences
    if it doesn't comply — never regex out fields, always full json.loads()
    so a malformed reply fails loudly as ProviderError rather than silently
    parsing partial/wrong data."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z]*\n?|```$", "", stripped).strip()
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as e:
        raise ProviderError(f"model reply was not valid JSON: {e}") from e
    if not isinstance(parsed, dict):
        raise ProviderError("model reply JSON was not an object")
    return parsed


class FakeProvider:
    """Test-only: deterministic canned dict-in/dict-out, no network. `script`
    maps a question substring (lowercased) to the raw dict AnthropicProvider
    would have returned — including adversarial fixtures that try to smuggle
    fabricated ids, so tests can exercise investigator.py's validator."""

    def __init__(self, script: dict[str, dict]):
        self.script = script

    def ask(self, question: str, context: dict) -> dict:
        q = question.lower()
        for key, reply in self.script.items():
            if key in q:
                return reply
        return {"answer": "No scripted fake reply configured for this question.",
                "claims": [], "limitations": []}


def get_provider() -> Optional[Provider]:
    name = os.environ.get("CT_LLM_PROVIDER", "").strip().lower()
    if name in ("", "none"):
        return None
    if name == "anthropic":
        key = os.environ.get("CT_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ProviderError(
                "CT_LLM_PROVIDER=anthropic but no key set (CT_LLM_API_KEY or ANTHROPIC_API_KEY)")
        model = os.environ.get("CT_LLM_MODEL", "").strip() or DEFAULT_MODEL
        return AnthropicProvider(key, model)
    raise ProviderError(f"unknown CT_LLM_PROVIDER: {name!r}")


def demo() -> None:
    """occam: smallest runnable check for the JSON-parsing/validation-adjacent
    logic in this module that isn't already covered by pytest fixtures needing
    a real EvidenceStore (that half lives in tests/test_investigator.py)."""
    assert _parse_json_object('{"answer": "ok", "claims": []}') == {"answer": "ok", "claims": []}
    assert _parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    try:
        _parse_json_object("not json")
        raise AssertionError("expected ProviderError")
    except ProviderError:
        pass

    fake = FakeProvider({"connected": {"answer": "they share a key", "claims": []}})
    assert fake.ask("Why are these connected?", {})["answer"] == "they share a key"
    assert "No scripted" in fake.ask("unrelated", {})["answer"]

    os.environ.pop("CT_LLM_PROVIDER", None)
    assert get_provider() is None
    os.environ["CT_LLM_PROVIDER"] = "anthropic"
    os.environ.pop("CT_LLM_API_KEY", None)
    os.environ.pop("ANTHROPIC_API_KEY", None)
    try:
        get_provider()
        raise AssertionError("expected ProviderError for missing key")
    except ProviderError:
        pass
    finally:
        os.environ.pop("CT_LLM_PROVIDER", None)
    print("llm_provider.demo() OK")


if __name__ == "__main__":
    demo()
