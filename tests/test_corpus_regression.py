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

from pathlib import Path

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
