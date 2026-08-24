"""Locks the real-corpus result, not a synthetic fixture.

Every other correlation test seeds scenarios through ingest() by hand. This one
runs the actual saved captures in runs/raw/v5..v8 through tools/eval_corpus.py
exactly as a human running it from the CLI would, so a change that breaks a
real positive pair or lets a real negative through fails a test instead of
only showing up the next time someone happens to run the tool by hand.

See memory: corpus-positive-ceiling — recall here is bounded by how many
operator-specific families the corpus contains (currently 4: cryptostorm,
dnmx, endchan, tor.taxi), not by scoring, so this pins the count rather than
demanding it grow.
"""

import json
from pathlib import Path

from cybertrace.correlate import run_correlation
from cybertrace.evidence import EvidenceStore, ingest
from tools.eval_corpus import evaluate

ROOT = Path(__file__).resolve().parent.parent
RUNS = sorted(
    p for v in ("v5", "v6", "v7", "v8")
    for p in (ROOT / "runs" / "raw" / v).glob("*.json")
)
EXPANDED_RUNS = sorted(
    p for v in ("v5", "v6", "v7", "v8", "v10")
    for p in (ROOT / "runs" / "raw" / v).glob("*.json")
)
V14_RUNS = sorted(
    p for v in ("v5", "v6", "v7", "v8", "v10", "v14")
    for p in (ROOT / "runs" / "raw" / v).glob("*.json")
)
# v12: 66 real ransomware leak-site onions (LockBit, ALPHV, Conti-successor
# brands, etc.) captured 2026-08-22 as an infrastructure/false-attribution
# stress batch — different operators by construction, never labeled because
# grading needs no ground truth here, only that none of them get merged.
# v13: 4 more unrelated live darkweb captures from the same sweep (a market,
# an exploit forum, a recapture, a dead drug-marketplace attempt).
# Neither directory is in corpus/labels.toml — see runs/README.md.
UNLABELED_RUNS = sorted(
    p for v in ("v12", "v13")
    for p in (ROOT / "runs" / "raw" / v).glob("*.json")
)


def test_real_corpus_recovers_known_operators_with_no_false_attribution(capsys):
    assert RUNS, "runs/raw/v5..v8 captures are missing"
    exit_code = evaluate(RUNS, ROOT / "corpus" / "labels.toml",
                         show_pairs=False, db_path=":memory:")
    out = capsys.readouterr().out

    assert exit_code == 0, out  # no ecosystem leakage, no false attribution
    assert "false attribution    0" in out
    assert "ecosystem leakage    0" in out
    assert "operator precision   4/4 = 1.00" in out
    assert "operator recall      4/42 = 0.10" in out


def test_expanded_corpus_new_families_stay_precise(capsys):
    """v10 adds four new real operator families (Tor Project satellite sites,
    Freedom of the Press Foundation's three onion projects, Disroot, Systemli)
    captured live on 2026-08-22 — see corpus/labels.toml for provenance. Every
    one is evidence_class 'none': a real single operator across independently
    keyed onions, searched by hand for a shared EMAIL/PGP_KEY/wallet the same
    way the original 4-of-4 was found, and none turned one up.

    The point of this test is not recall — none of the ten new pairs are
    recoverable by construction — it is that adding them moves the recall
    denominator (42 -> 52) without moving precision, leakage or false
    attribution. A future change that starts asserting one of these pairs on
    the strength of a shared DOMAIN reference (freedom.press's own onion links
    to its own securedrop.org and pressfreedomtracker.us) would be exactly the
    ecosystem-leakage failure mode this corpus exists to catch.
    """
    assert EXPANDED_RUNS, "runs/raw/v5..v8,v10 captures are missing"
    exit_code = evaluate(EXPANDED_RUNS, ROOT / "corpus" / "labels.toml",
                         show_pairs=False, db_path=":memory:")
    out = capsys.readouterr().out

    assert exit_code == 0, out
    assert "false attribution    0" in out
    assert "ecosystem leakage    0" in out
    assert "operator precision   4/4 = 1.00" in out
    assert "operator recall      4/52 = 0.08" in out


def test_v14_blind_rediscovery_family_stays_precise(capsys):
    """v14 (2026-08-23) paired fresh captures of EFF's own three onions and
    four newsroom main-site onions against their already-labeled SecureDrop
    rows, without telling the engine they were related — see runs/README.md.
    Verified by hand there at 4/4 precision, 4/56 recall, 0 leakage/false
    attribution; this test is what was missing to keep that finding from
    regressing silently the way v5-v10 already can't.
    """
    assert V14_RUNS, "runs/raw/v5..v8,v10,v14 captures are missing"
    exit_code = evaluate(V14_RUNS, ROOT / "corpus" / "labels.toml",
                         show_pairs=False, db_path=":memory:")
    out = capsys.readouterr().out

    assert exit_code == 0, out
    assert "false attribution    0" in out
    assert "ecosystem leakage    0" in out
    assert "operator precision   4/4 = 1.00" in out
    assert "operator recall      4/56 = 0.07" in out


def test_fresh_unrelated_infrastructure_produces_no_candidates():
    """66 real ransomware leak sites plus 4 more live darkweb captures
    (runs/raw/v12, v13) run through the real pipeline alongside the full
    labeled corpus. They are different operators by construction — no shared
    ground truth needed to grade them, only that the engine never merges them.

    Unlike the synthetic non-attributive-signal stacking test in
    test_correlate.py, this is real infrastructure: real hosting, real HTTP
    fingerprints, real (mostly dead) Tor circuits. It is the blind
    false-attribution check the labeled corpus can't run, because every one
    of its targets already has a label.
    """
    assert UNLABELED_RUNS, "runs/raw/v12/v13 captures are missing"
    unrelated_urls = {
        json.loads(p.read_text()).get("target", "").lower()
        for p in UNLABELED_RUNS
    }

    with EvidenceStore(":memory:") as store:
        for path in V14_RUNS + UNLABELED_RUNS:
            ingest(json.loads(path.read_text()), store)
        results = run_correlation(store)

    def touches_unrelated(pair) -> bool:
        return any(u.lower() in unrelated_urls for u in (pair.get("urls") or ()))

    asserted = [r for r in results["successors"] if r.get("relation")]
    leads = [r for r in results["successors"]
             if not r.get("relation") and (r.get("score") or 0) >= 0.10]

    assert not any(touches_unrelated(r) for r in asserted), (
        "a ransomware/discovery target was asserted as SUCCESSOR_OF/LINKED_TO "
        f"to something else: {[r for r in asserted if touches_unrelated(r)]}")
    assert not any(touches_unrelated(r) for r in leads), (
        "a ransomware/discovery target was even ranked as a lead against "
        f"something else: {[r for r in leads if touches_unrelated(r)]}")

    # The pre-existing labeled positives must be exactly unchanged: adding 70
    # unrelated targets to the store must not shift scoring for anyone else.
    assert len(asserted) == 3
    assert [c["value"] for c in results["operators"]] == [
        "support@cryptostorm.is", "pgp:a5e0a8393961186aa291379fbd89c41a1588778a",
        "support@dnmx.cc", "contact@tor.taxi",
    ]
