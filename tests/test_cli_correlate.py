"""CLI-level regression for `cybertrace correlate`: both invocation forms
(with and without --db) must reach the same governed engine
(cybertrace.correlate.run_correlation via the EvidenceStore), never a
separate ad-hoc attribution path.
"""

import json
import sqlite3

from click.testing import CliRunner

from cybertrace.cli import cli

from .test_evidence import KEY_A, onion

ONION_X = onion("x")
ONION_Y = onion("y")


def _write_result(path, target, **onion_data):
    """A saved `cybertrace search --save` file: ModuleResult.to_dict() as JSON."""
    payload = {
        'target': target, 'target_type': 'darkweb', 'module': 'darkweb',
        'sources': {
            'target_onion': {
                'source': 'target_onion', 'success': True, 'error': None,
                'timestamp': '2026-01-10T00:00:00',
                'data': {'online': True, **onion_data},
            }
        },
        'summary': {}, 'related': [],
        'stats': {'success': 1, 'total': 1, 'duration_sec': 0.1},
    }
    path.write_text(json.dumps(payload))
    return str(path)


def _shared_key_pair(tmp_path):
    """Two markets that genuinely share a published PGP key -> real positive."""
    a = _write_result(tmp_path / 'a.json', ONION_X, pgp_keys=[{'armored': KEY_A}])
    b = _write_result(tmp_path / 'b.json', ONION_Y, pgp_keys=[{'armored': KEY_A}])
    return a, b


def _quoted_third_party_pair(tmp_path):
    """Two markets that both merely QUOTE a third party's email in a 'quoted'
    section. A naive union-find over shared-artifact nodes (graph.py's now-
    removed clustering path) would cluster these two markets as one operator
    purely because the node has two markets attached. The governed engine must not:
    quoted mentions are marked non-attributive at ingest and must never
    surface as a SAME_OPERATOR dossier.
    """
    shared_email = 'thirdparty@example.com'
    a = _write_result(
        tmp_path / 'qa.json', ONION_X, emails=[shared_email],
        artifact_evidence={shared_email: {'section': 'quoted'}},
    )
    b = _write_result(
        tmp_path / 'qb.json', ONION_Y, emails=[shared_email],
        artifact_evidence={shared_email: {'section': 'quoted'}},
    )
    return a, b


# --- both CLI paths reach the same governed engine ---------------------------

def test_correlate_without_db_finds_the_real_shared_key(tmp_path):
    a, b = _shared_key_pair(tmp_path)
    result = CliRunner().invoke(cli, ['correlate', a, b, '--output', 'json'])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert any(set(d.get('markets', [])) >= {ONION_X, ONION_Y}
               for d in data['dossiers'])


def test_correlate_with_db_finds_the_same_shared_key(tmp_path):
    a, b = _shared_key_pair(tmp_path)
    db = str(tmp_path / 'case.db')
    result = CliRunner().invoke(cli, ['correlate', a, b, '--db', db, '--output', 'json'])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert any(set(d.get('markets', [])) >= {ONION_X, ONION_Y}
               for d in data['dossiers'])


def test_quoted_artifact_never_attributes_without_db(tmp_path):
    a, b = _quoted_third_party_pair(tmp_path)
    result = CliRunner().invoke(cli, ['correlate', a, b, '--output', 'json'])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert not any(set(d.get('markets', [])) >= {ONION_X, ONION_Y}
                   for d in data['dossiers'])


def test_quoted_artifact_never_attributes_with_db(tmp_path):
    a, b = _quoted_third_party_pair(tmp_path)
    db = str(tmp_path / 'case.db')
    result = CliRunner().invoke(cli, ['correlate', a, b, '--db', db, '--output', 'json'])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert not any(set(d.get('markets', [])) >= {ONION_X, ONION_Y}
                   for d in data['dossiers'])


def test_correlate_db_only_rerenders_without_result_files(tmp_path):
    """An analyst who only wants to re-render the
    current case state must not be forced to pass dummy JSON files or
    re-crawl live via `watch`. A prior `correlate ... --db` pass already
    ingested a.json/b.json into the store; a later `correlate --db` call
    with no positional args re-runs the engine over what is already there.
    """
    a, b = _shared_key_pair(tmp_path)
    db = str(tmp_path / 'case.db')
    first = CliRunner().invoke(cli, ['correlate', a, b, '--db', db, '--output', 'json'])
    assert first.exit_code == 0, first.output

    result = CliRunner().invoke(cli, ['correlate', '--db', db, '--output', 'json'])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert any(set(d.get('markets', [])) >= {ONION_X, ONION_Y}
               for d in data['dossiers'])


def test_correlate_with_neither_files_nor_db_errors(tmp_path):
    result = CliRunner().invoke(cli, ['correlate'])
    assert result.exit_code != 0
    assert 'RESULT_FILES' in result.output or '--db' in result.output


# --- label-exchange -----------------------------------------------------------

def test_label_exchange_then_correlate_reports_the_wallet_path(tmp_path):
    """cybertrace label-exchange is the only way an EXCHANGE_DEPOSIT edge gets
    written; a later `correlate --db` pass over the same store must report the
    resulting wallet_exchange_paths without needing anything re-ingested."""
    from cybertrace.evidence import EvidenceStore, enrich_bitcoin

    db = str(tmp_path / 'case.db')
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    counterparty = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    with EvidenceStore(db) as store:
        addr = store.upsert_entity("BTC_ADDRESS", btc)
        target = store.upsert_target("btc:" + btc)
        sid = store.insert_snapshot(target, {}, "bitcoin")
        enrich_bitcoin(store, sid, addr,
                       {"address": btc, "counterparty_addresses": [counterparty]}, "bitcoin")

    result = CliRunner().invoke(
        cli, ['label-exchange', counterparty, '--exchange', 'Test Exchange', '--db', db,
             '--analyst', 'jdoe'])
    assert result.exit_code == 0, result.output
    assert 'Recorded' in result.output

    dummy = _write_result(tmp_path / 'dummy.json', ONION_X)
    result = CliRunner().invoke(cli, ['correlate', dummy, '--db', db, '--output', 'json'])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert any(w['exchange'] == 'test exchange' and w['hops'] == 1
              for w in data['wallet_exchange_paths'])


def test_label_exchange_rejects_an_invalid_address(tmp_path):
    from cybertrace.evidence import EvidenceStore
    db = str(tmp_path / 'case.db')
    with EvidenceStore(db):
        pass
    result = CliRunner().invoke(
        cli, ['label-exchange', 'not-a-btc-address', '--exchange', 'Test Exchange', '--db', db])
    assert result.exit_code != 0
    assert 'not a valid' in result.output.lower()


# --- trace-wallet ---------------------------------------------------------------

def test_trace_wallet_reports_path_and_flags(tmp_path):
    """The full loop: an enriched wallet with a scam report and a GraphSense
    tagpack hit, one hop from a labeled exchange -- trace-wallet must surface
    both flags plus the path, reading nothing but metadata already on record.
    """
    from cybertrace.evidence import EvidenceStore, enrich_bitcoin

    db = str(tmp_path / 'case.db')
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    counterparty = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    with EvidenceStore(db) as store:
        addr = store.upsert_entity("BTC_ADDRESS", btc)
        target = store.upsert_target("btc:" + btc)
        sid = store.insert_snapshot(target, {}, "bitcoin")
        enrich_bitcoin(store, sid, addr, {
            "address": btc, "counterparty_addresses": [counterparty],
            "reported_scam": True, "chainabuse_scam_categories": ["PHISHING"],
            "exchange_tag_packs": ["ransomware"],
        }, "bitcoin")

    CliRunner().invoke(
        cli, ['label-exchange', counterparty, '--exchange', 'Test Exchange', '--db', db])

    result = CliRunner().invoke(cli, ['trace-wallet', btc, '--db', db, '--output', 'json'])
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report['address'] == btc
    assert report['exchange'] == 'test exchange'
    assert report['hops'] == 1
    assert any('reported for abuse' in f and 'PHISHING' in f for f in report['flags'])
    assert any('ransomware' in f for f in report['flags'])
    # See test_correlate.test_wallet_trace_report_surfaces_flags_from_metadata_
    # already_on_record: "layering" named a typology the engine cannot detect.
    # What the CLI has to carry instead is proximity, who attributed the VASP,
    # and whether value actually moved toward it.
    assert report['proximity'] == 'DIRECT'
    assert report['attribution'] == 'ANALYST_ASSERTED'
    assert report['direction'] == 'UNKNOWN'


def test_wallet_verdict_command_requires_a_traced_wallet(tmp_path):
    """Loop 41: wallet-level analyst verdicts. Mirrors
    test_feedback_command_requires_a_real_candidate -- verdict on a wallet
    never searched into this case is a typo, not a new fact."""
    from cybertrace.evidence import EvidenceStore
    db = str(tmp_path / 'case.db')
    with EvidenceStore(db):
        pass
    result = CliRunner().invoke(
        cli, ['wallet-verdict', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', '--db', db,
              '--outcome', 'confirmed'])
    assert result.exit_code == 1
    assert 'never searched' in result.output.lower()


def test_wallet_verdict_recorded_via_cli_is_read_back_by_trace_wallet(tmp_path):
    """The full loop: record a wallet verdict via the CLI, then confirm
    trace-wallet's own JSON report reads it back as `verdict` -- kept
    apart from, and never overwriting, the automated attribution/wallet_role/
    risk fields sitting beside it."""
    from cybertrace.evidence import EvidenceStore

    db = str(tmp_path / 'case.db')
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    with EvidenceStore(db):
        pass  # initializes the schema -- label-exchange's --db requires an existing file
    result = CliRunner().invoke(
        cli, ['label-exchange', btc, '--exchange', 'Test Exchange', '--db', db])
    assert result.exit_code == 0, result.output

    before = CliRunner().invoke(cli, ['trace-wallet', btc, '--db', db, '--output', 'json'])
    assert json.loads(before.output)['verdict'] is None

    fb = CliRunner().invoke(
        cli, ['wallet-verdict', btc, '--db', db, '--outcome', 'benign',
              '--note', 'known merchant deposit address', '--analyst', 'jdoe'])
    assert fb.exit_code == 0, fb.output
    assert 'Recorded BENIGN' in fb.output

    after = CliRunner().invoke(cli, ['trace-wallet', btc, '--db', db, '--output', 'json'])
    report = json.loads(after.output)
    assert report['verdict']['outcome'] == 'BENIGN'
    assert report['verdict']['analyst'] == 'jdoe'
    # Automated fields are untouched by the verdict.
    assert report['attribution'] == 'ANALYST_ASSERTED'
    assert report['exchange'] == 'test exchange'


def test_trace_wallet_unsearched_address_fails_loudly(tmp_path):
    from cybertrace.evidence import EvidenceStore
    db = str(tmp_path / 'case.db')
    with EvidenceStore(db):
        pass
    result = CliRunner().invoke(
        cli, ['trace-wallet', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', '--db', db])
    assert result.exit_code != 0
    assert 'never searched' in result.output.lower()


# --- --db input validation ----------------------------------------------------

def test_missing_db_value_is_a_usage_error(tmp_path):
    a, b = _shared_key_pair(tmp_path)
    result = CliRunner().invoke(cli, ['correlate', a, b, '--db'])
    assert result.exit_code == 2
    assert 'requires an argument' in result.output.lower()


def test_db_path_that_is_a_directory_is_rejected(tmp_path):
    a, b = _shared_key_pair(tmp_path)
    a_dir = tmp_path / 'not_a_file'
    a_dir.mkdir()
    result = CliRunner().invoke(cli, ['correlate', a, b, '--db', str(a_dir)])
    assert result.exit_code != 0
    # Click's own Path(dir_okay=False) check, not the correlation engine.
    assert 'directory' in result.output.lower()


def test_db_parent_directory_missing_fails_loudly_not_silently(tmp_path):
    a, b = _shared_key_pair(tmp_path)
    bad_db = str(tmp_path / 'no_such_dir' / 'case.db')
    result = CliRunner().invoke(cli, ['correlate', a, b, '--db', bad_db])
    assert result.exit_code != 0
    assert not (tmp_path / 'no_such_dir').exists()


def test_db_file_that_is_not_a_sqlite_database_fails_loudly(tmp_path):
    a, b = _shared_key_pair(tmp_path)
    garbage_db = tmp_path / 'garbage.db'
    garbage_db.write_bytes(b'not a sqlite file at all, just bytes\x00\x01\x02')
    result = CliRunner().invoke(cli, ['correlate', a, b, '--db', str(garbage_db)])
    assert result.exit_code != 0
    # Must not have silently produced a candidate from a corrupt store.
    assert 'dossiers' not in result.output


def test_db_with_incompatible_existing_schema_fails_loudly(tmp_path):
    """A pre-existing sqlite file with a same-named but foreign `targets` table
    (CREATE TABLE IF NOT EXISTS is a no-op here) must fail at first write
    rather than silently ingesting into the wrong shape."""
    incompatible_db = tmp_path / 'incompatible.db'
    conn = sqlite3.connect(str(incompatible_db))
    conn.execute("CREATE TABLE targets (nothing_like_our_schema TEXT)")
    conn.commit()
    conn.close()

    a, b = _shared_key_pair(tmp_path)
    result = CliRunner().invoke(cli, ['correlate', a, b, '--db', str(incompatible_db)])
    assert result.exit_code != 0
    assert 'dossiers' not in result.output


def test_empty_db_file_self_initializes_its_schema(tmp_path):
    """An empty file is a valid, schema-less SQLite database -- CREATE TABLE IF
    NOT EXISTS must initialize it cleanly rather than erroring."""
    empty_db = tmp_path / 'empty.db'
    empty_db.write_bytes(b'')

    a, b = _shared_key_pair(tmp_path)
    result = CliRunner().invoke(cli, ['correlate', a, b, '--db', str(empty_db)])
    assert result.exit_code == 0, result.output
