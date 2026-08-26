"""cybertrace.monitor: watch_narrative wiring only — recheck()/run_watch()'s
live Tor-fetch path is untested offline, same as before this addition."""
import json
from pathlib import Path

import pytest

from cybertrace.evidence import EvidenceStore, ingest
from cybertrace.monitor import watch_narrative

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = [ROOT / "runs" / "raw" / "v8" / "tortaxi-prd.json",
            ROOT / "runs" / "raw" / "v8" / "tortaxi-2dev.json"]


@pytest.fixture
def store():
    with EvidenceStore(":memory:") as s:
        for p in CAPTURES:
            ingest(json.loads(p.read_text()), s)
        yield s


def test_watch_narrative_none_when_no_deltas(store):
    assert watch_narrative(store, "tortaxi", []) is None


def test_watch_narrative_grounded_answer_when_deltas_present(store, monkeypatch):
    monkeypatch.delenv("CT_LLM_PROVIDER", raising=False)
    fake_delta = [{"change": "NEW", "candidate_id": "OP-fake0000",
                   "confidence": 0.9, "assessment": "test delta"}]
    result = watch_narrative(store, "tortaxi", fake_delta)
    assert result is not None
    assert result["case_id"] == "tortaxi"
    assert result["mode"] == "deterministic"
    assert result["answer"]
    assert "claims" in result and "evidence" in result
