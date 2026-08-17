"""CLI-level check that `cybertrace correlate` surfaces historical memory as
its own section — next to the governed dossiers, never merged into them —
and that `cybertrace feedback` lets an analyst record a verdict that a later
`correlate` pass actually reads back.
"""

import json

from click.testing import CliRunner

from cybertrace.cli import cli

from .test_cli_correlate import ONION_X, ONION_Y, _write_result
from .test_evidence import KEY_A


def test_correlate_markdown_shows_a_historical_memory_section(tmp_path):
    a = _write_result(tmp_path / 'a.json', ONION_X, pgp_keys=[{'armored': KEY_A}])
    b = _write_result(tmp_path / 'b.json', ONION_Y, pgp_keys=[{'armored': KEY_A}])
    result = CliRunner().invoke(cli, ['correlate', a, b])
    assert result.exit_code == 0, result.output
    assert 'Historical memory' in result.output
    assert '[EXACT] PGP_KEY' in result.output
    assert 'NOT ESTABLISHED BY MEMORY' not in result.output  # that's a data field, not printed verbatim
    assert 'never establishes SAME_OPERATOR' in result.output


def test_correlate_json_includes_a_memory_key_without_breaking_dossiers(tmp_path):
    a = _write_result(tmp_path / 'a.json', ONION_X, pgp_keys=[{'armored': KEY_A}])
    b = _write_result(tmp_path / 'b.json', ONION_Y, pgp_keys=[{'armored': KEY_A}])
    result = CliRunner().invoke(cli, ['correlate', a, b, '--output', 'json'])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert 'dossiers' in data                      # governed engine's own output, untouched
    assert ONION_Y in data['memory']
    hit = next(h for h in data['memory'][ONION_Y]['matches'] if h['etype'] == 'PGP_KEY')
    assert hit['classification'] == 'EXACT'
    assert hit['attribution'] == 'NOT ESTABLISHED BY MEMORY'
    # Stage-A keys are present even when empty, never silently dropped.
    for key in ('cases', 'related', 'patterns'):
        assert key in data['memory'][ONION_Y]


def test_correlate_with_no_shared_history_shows_no_memory_section(tmp_path):
    a = _write_result(tmp_path / 'a.json', ONION_X, emails=['unique-a@proton.me'])
    result = CliRunner().invoke(cli, ['correlate', a])
    assert result.exit_code == 0, result.output
    assert 'Historical memory' not in result.output


def test_feedback_command_requires_a_real_candidate(tmp_path):
    db = str(tmp_path / 'case.db')
    a = _write_result(tmp_path / 'a.json', ONION_X, pgp_keys=[{'armored': KEY_A}])
    CliRunner().invoke(cli, ['correlate', a, '--db', db])  # initializes the schema

    result = CliRunner().invoke(cli, ['feedback', 'OP-doesnotexist', '--db', db,
                                      '--outcome', 'confirmed'])
    assert result.exit_code == 1
    assert 'no such candidate' in result.output.lower()


def test_feedback_recorded_via_cli_changes_the_next_correlate_score(tmp_path):
    db = str(tmp_path / 'case.db')
    a = _write_result(tmp_path / 'a.json', ONION_X, pgp_keys=[{'armored': KEY_A}])
    b = _write_result(tmp_path / 'b.json', ONION_Y, pgp_keys=[{'armored': KEY_A}])

    before = CliRunner().invoke(cli, ['correlate', a, b, '--db', db, '--output', 'json'])
    assert before.exit_code == 0, before.output
    dossier = json.loads(before.output)['dossiers'][0]

    fb = CliRunner().invoke(cli, ['feedback', dossier['candidate_id'], '--db', db,
                                  '--outcome', 'confirmed', '--analyst', 'jdoe'])
    assert fb.exit_code == 0, fb.output
    assert 'Recorded CONFIRMED' in fb.output

    after = CliRunner().invoke(cli, ['correlate', a, b, '--db', db, '--output', 'json'])
    after_dossier = next(d for d in json.loads(after.output)['dossiers']
                         if d['candidate_id'] == dossier['candidate_id'])
    assert after_dossier['score'] > dossier['score']

    # And the case-history side: a later `correlate` on this store surfaces
    # the confirmed verdict as prior-case memory, not as a re-derived opinion.
    cases = json.loads(after.output)['memory'][ONION_X]['cases']
    assert any(c['analyst_feedback'] and c['analyst_feedback'][0]['outcome'] == 'CONFIRMED'
              for c in cases)
