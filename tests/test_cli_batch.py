"""`cybertrace trace-wallet-batch` -- Loop 35 Module C: search + ingest + trace
many wallets in one run against one shared evidence store.

Every module network call is mocked (BitcoinModule.search / TronModule.search)
so these are CLI/orchestration tests, not live-network tests: what is under
test is the batch loop's dispatch, concurrency bound, duplicate handling,
failure isolation, and output schema -- never a second tracing engine, since
_trace_one_wallet calls the same evidence.ingest/correlate.wallet_trace_report
path `search` + `correlate --db` + `trace-wallet` already exercise one wallet
at a time.
"""

import csv
import json

from click.testing import CliRunner

from cybertrace.cli import cli
from cybertrace.evidence import EvidenceStore
from cybertrace.modules.base import ModuleResult, SourceResult
from cybertrace.modules.bitcoin_module import BitcoinModule
from cybertrace.modules.tron_module import TronModule

BTC_A = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
BTC_B = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
ETH_A = "0x" + "3" * 39 + "c"
TRX_A = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def _write_csv(path, rows):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["address", "chain"])
        for row in rows:
            w.writerow(row)
    return str(path)


def _mock_modules(monkeypatch, *, fail_for=(), sent_to=None):
    """Replace BitcoinModule.search / TronModule.search with an offline fake
    that records every (module, target, target_type) call, raises for any
    address in `fail_for` (simulating an API failure), and otherwise returns
    a minimal but real ModuleResult -- same shape evidence.ingest expects."""
    calls = []
    sent_to = sent_to or {}

    async def fake_search(self, target, **options):
        calls.append((self.name, target, options.get("target_type")))
        if target in fail_for:
            raise RuntimeError(f"simulated API failure for {target}")
        tt = options.get("target_type") or self.name
        result = ModuleResult(target=target, target_type=tt, module=self.name)
        payload = {"address": target, "sent_to_addresses": sent_to.get(target, [])}
        source = "trongrid" if self.name == "tron" else "blockchain.com"
        result.sources[source] = SourceResult(source=source, success=True, data=payload)
        result.summary = payload
        return result

    monkeypatch.setattr(BitcoinModule, "search", fake_search)
    monkeypatch.setattr(TronModule, "search", fake_search)
    return calls


def _invoke_batch(csv_path, db_path, *extra_args):
    return CliRunner().invoke(
        cli, ["trace-wallet-batch", csv_path, "--db", db_path, "-o", "json", *extra_args])


# --- 1. single wallet ---------------------------------------------------------

def test_batch_traces_a_single_wallet(tmp_path, monkeypatch):
    _mock_modules(monkeypatch)
    csv_path = _write_csv(tmp_path / "w.csv", [(BTC_A, "")])
    result = _invoke_batch(csv_path, str(tmp_path / "case.db"))
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["total"] == data["successful"] == 1
    assert data["failed"] == 0
    assert data["wallets"][0]["status"] == "ok"
    assert data["wallets"][0]["result"]["address"] == BTC_A


# --- 2. multiple wallets -------------------------------------------------------

def test_batch_traces_multiple_wallets(tmp_path, monkeypatch):
    _mock_modules(monkeypatch)
    csv_path = _write_csv(tmp_path / "w.csv", [(BTC_A, ""), (BTC_B, ""), (ETH_A, "ethereum")])
    result = _invoke_batch(csv_path, str(tmp_path / "case.db"))
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["total"] == 3
    assert data["successful"] == 3
    assert {w["wallet"] for w in data["wallets"]} == {BTC_A, BTC_B, ETH_A}


# --- 3. mixed-chain batch -------------------------------------------------------

def test_batch_mixed_chain_dispatches_the_right_module_and_target_type(tmp_path, monkeypatch):
    calls = _mock_modules(monkeypatch)
    csv_path = _write_csv(tmp_path / "w.csv",
                          [(BTC_A, ""), (ETH_A, "ethereum"), (TRX_A, "tron")])
    result = _invoke_batch(csv_path, str(tmp_path / "case.db"))
    assert result.exit_code == 0, result.output
    assert ("bitcoin", BTC_A, "bitcoin") in calls
    assert ("bitcoin", ETH_A, "ethereum") in calls
    assert ("tron", TRX_A, "tron") in calls


# --- 4. one failure does not abort others --------------------------------------

def test_one_wallet_api_failure_does_not_abort_the_batch(tmp_path, monkeypatch):
    _mock_modules(monkeypatch, fail_for={ETH_A})
    csv_path = _write_csv(tmp_path / "w.csv", [(BTC_A, ""), (ETH_A, "ethereum"), (BTC_B, "")])
    result = _invoke_batch(csv_path, str(tmp_path / "case.db"))
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["total"] == 3
    assert data["successful"] == 2
    assert data["failed"] == 1
    by_wallet = {w["wallet"]: w for w in data["wallets"]}
    assert by_wallet[ETH_A]["status"] == "error"
    assert "simulated API failure" in by_wallet[ETH_A]["error"]
    assert by_wallet[BTC_A]["status"] == "ok"
    assert by_wallet[BTC_B]["status"] == "ok"


# --- 5. malformed input ---------------------------------------------------------

def test_malformed_input_missing_address_column_is_a_usage_error(tmp_path, monkeypatch):
    _mock_modules(monkeypatch)
    bad = tmp_path / "w.csv"
    bad.write_text("wallet,network\nsomething,bitcoin\n")
    result = _invoke_batch(str(bad), str(tmp_path / "case.db"))
    assert result.exit_code != 0
    assert "address" in result.output.lower()


def test_empty_input_file_is_refused(tmp_path, monkeypatch):
    _mock_modules(monkeypatch)
    empty = tmp_path / "w.csv"
    empty.write_text("address,chain\n")
    result = _invoke_batch(str(empty), str(tmp_path / "case.db"))
    assert result.exit_code != 0
    assert "no addresses" in result.output.lower()


def test_unsupported_chain_value_is_reported_not_crashed(tmp_path, monkeypatch):
    _mock_modules(monkeypatch)
    csv_path = _write_csv(tmp_path / "w.csv", [(BTC_A, "dogecoin")])
    result = _invoke_batch(csv_path, str(tmp_path / "case.db"))
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["wallets"][0]["status"] == "unsupported_chain"
    assert data["wallets"][0]["result"] is None


def test_invalid_wallet_shape_is_reported_not_crashed(tmp_path, monkeypatch):
    _mock_modules(monkeypatch)
    csv_path = _write_csv(tmp_path / "w.csv", [("not-a-real-wallet", "")])
    result = _invoke_batch(csv_path, str(tmp_path / "case.db"))
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["wallets"][0]["status"] == "invalid_address"
    assert data["wallets"][0]["result"] is None
    assert data["failed"] == 1


# --- 6. duplicate handling -------------------------------------------------------

def test_duplicate_wallet_is_searched_once_and_flagged_not_dropped(tmp_path, monkeypatch):
    calls = _mock_modules(monkeypatch)
    csv_path = _write_csv(tmp_path / "w.csv", [(BTC_A, ""), (BTC_A, ""), (BTC_A, "bitcoin")])
    result = _invoke_batch(csv_path, str(tmp_path / "case.db"))
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    # (BTC_A, None) and (BTC_A, 'bitcoin') are different keys as given in the
    # file -- both auto-detect to the same chain, so both really do search --
    # only the *second occurrence of the identical row* is a true duplicate.
    assert len(calls) == 2
    statuses = [w["status"] for w in data["wallets"]]
    assert statuses == ["ok", "duplicate", "ok"]
    assert data["wallets"][1]["result"] == data["wallets"][0]["result"]
    assert data["total"] == 3
    assert data["successful"] == 3


# --- 7. output schema -------------------------------------------------------------

def test_batch_output_schema_matches_the_documented_shape(tmp_path, monkeypatch):
    _mock_modules(monkeypatch)
    csv_path = _write_csv(tmp_path / "w.csv", [(BTC_A, "")])
    result = _invoke_batch(csv_path, str(tmp_path / "case.db"))
    data = json.loads(result.output)
    assert set(data.keys()) == {"total", "successful", "failed", "wallets"}
    entry = data["wallets"][0]
    assert set(entry.keys()) == {"wallet", "chain", "status", "result", "error"}
    # `result`, when present, is exactly a wallet_trace_report() dict -- not a
    # second, batch-only schema.
    assert set(entry["result"].keys()) == {
        "entity_id", "address", "chain", "path", "hops", "exchange", "exchange_confidence",
        "attribution", "attribution_rank", "attribution_source", "wallet_role", "proximity",
        "direction", "deposit_candidate", "direct_vasp_contacts", "secondary_vasp_contacts",
        "verdict", "flags", "evidence_ids", "service_tags", "risk", "data_source_status",
    }


# --- 8. evidence preserved ---------------------------------------------------------

def test_batch_persists_evidence_into_the_shared_store(tmp_path, monkeypatch):
    """The whole point of batch over N separate `search` calls: everything
    lands in one on-disk case, re-traceable afterward with no mock needed."""
    _mock_modules(monkeypatch, sent_to={BTC_A: [BTC_B]})
    db_path = str(tmp_path / "case.db")
    csv_path = _write_csv(tmp_path / "w.csv", [(BTC_A, "")])
    result = _invoke_batch(csv_path, db_path)
    assert result.exit_code == 0, result.output

    with EvidenceStore(db_path) as store:
        assert store.find_entity("BTC_ADDRESS", BTC_A) is not None
        assert store.find_entity("BTC_ADDRESS", BTC_B) is not None

    # An analyst labels the counterparty batch discovered as a VASP, then
    # re-traces with no module mocked at all -- reads only what batch wrote.
    label = CliRunner().invoke(
        cli, ["label-exchange", BTC_B, "--exchange", "Test Exchange", "--db", db_path])
    assert label.exit_code == 0, label.output
    trace = CliRunner().invoke(cli, ["trace-wallet", BTC_A, "--db", db_path, "-o", "json"])
    assert trace.exit_code == 0, trace.output
    report = json.loads(trace.output)
    assert report["address"] == BTC_A
    assert report["hops"] == 1
    assert BTC_B in report["path"]


# --- 9. chain selection preserved ---------------------------------------------------

def test_batch_keeps_identical_address_strings_on_separate_chains(tmp_path, monkeypatch):
    """Loop 34's own regression, at batch scope: the same 0x string declared
    bnb on one row and polygon on another must land as two distinct entities,
    never merged by address value alone."""
    _mock_modules(monkeypatch)
    db_path = str(tmp_path / "case.db")
    csv_path = _write_csv(tmp_path / "w.csv", [(ETH_A, "bnb"), (ETH_A, "polygon")])
    result = _invoke_batch(csv_path, db_path)
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["total"] == 2
    assert data["successful"] == 2
    assert data["wallets"][0]["status"] == "ok"
    assert data["wallets"][1]["status"] == "ok"  # different key -- not a duplicate

    with EvidenceStore(db_path) as store:
        bnb_id = store.find_entity("BNB_ADDRESS", ETH_A)
        polygon_id = store.find_entity("POLYGON_ADDRESS", ETH_A)
        assert bnb_id is not None
        assert polygon_id is not None
        assert bnb_id != polygon_id


# --- concurrency bound sanity --------------------------------------------------

def test_batch_respects_an_explicit_concurrency_override(tmp_path, monkeypatch):
    """Not a timing test (flaky by nature) -- just proves --concurrency is
    plumbed through and a bound of 1 still processes every wallet correctly."""
    _mock_modules(monkeypatch)
    csv_path = _write_csv(tmp_path / "w.csv", [(BTC_A, ""), (BTC_B, "")])
    result = _invoke_batch(csv_path, str(tmp_path / "case.db"), "--concurrency", "1")
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["total"] == 2 and data["successful"] == 2
