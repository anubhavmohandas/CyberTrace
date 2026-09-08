"""Smoke test for tools/case_api.py: a real case .db, served over HTTP, must
come back in the exact shape web/CyberTrace Workspace.dc.html expects — same
invariant as test_export_case_gui.py, just through the live bridge instead of
a batch export.
"""
import functools
import json
import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

from cybertrace.evidence import EvidenceStore, ingest
from tools import case_api

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = [ROOT / "runs" / "raw" / "v8" / "tortaxi-prd.json",
            ROOT / "runs" / "raw" / "v8" / "tortaxi-2dev.json"]


def _make_case_db(path: Path) -> None:
    with EvidenceStore(str(path)) as store:
        for p in CAPTURES:
            ingest(json.loads(p.read_text()), store)
        store.update_case(name="tor.taxi mirror pair")


def _get(url: str) -> tuple[int, object]:
    try:
        with urlopen(url) as r:
            return r.status, json.loads(r.read())
    except Exception as e:  # urllib raises HTTPError (subclass of Exception) on 404
        return e.code, json.loads(e.read())


def _post(url: str, body: dict) -> tuple[int, object]:
    req = Request(url, data=json.dumps(body).encode("utf-8"),
                  headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req) as r:
            return r.status, json.loads(r.read())
    except Exception as e:  # urllib raises HTTPError (subclass of Exception) on 4xx
        return e.code, json.loads(e.read())


def _delete(url: str) -> tuple[int, object]:
    req = Request(url, method="DELETE")
    try:
        with urlopen(req) as r:
            return r.status, json.loads(r.read())
    except Exception as e:  # urllib raises HTTPError (subclass of Exception) on 4xx
        return e.code, json.loads(e.read())


@contextmanager
def _running_server(cases_dir: Path):
    handler = functools.partial(case_api.make_handler(cases_dir), directory=str(case_api.WEB_DIR))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join()


def test_cases_and_case_endpoints(tmp_path):
    assert all(p.is_file() for p in CAPTURES), "runs/raw/v8 tortaxi captures are missing"
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_case_db(cases_dir / "tortaxi.db")

    with _running_server(cases_dir) as base:
        status, cases = _get(f"{base}/api/cases")
        assert status == 200
        assert cases == [{"id": "tortaxi", "title": "tor.taxi mirror pair", "status": "OPEN"}]

        status, case = _get(f"{base}/api/case/tortaxi")
        assert status == 200
        assert case["title"] == "tor.taxi mirror pair"
        assert len(case["candidates"]) == 2
        assert case["suppressed"], "expected the page-similarity contradiction to survive the live path too"
        assert case["status"] == "OPEN"
        assert case["updated_at"]
        assert "correlation brief" in case["report_markdown"].lower()

        status, body = _get(f"{base}/api/case/does-not-exist")
        assert status == 404
        assert "error" in body


def test_create_case_endpoint_persists_and_lists(tmp_path):
    """Loop 55: the Workspace's "+ New case" button had no backend endpoint
    to call at all -- this is the whole create-case round trip a click must
    now complete: POST creates a real, empty EvidenceStore on disk (not a
    frontend-only fake), and it shows up in a subsequent GET /api/cases."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, created = _post(f"{base}/api/case", {"title": "Loop 55 Regression Case"})
        assert status == 201
        assert created == {"id": "loop-55-regression-case", "title": "Loop 55 Regression Case",
                           "status": "OPEN"}
        assert (cases_dir / "loop-55-regression-case.db").is_file()

        status, cases = _get(f"{base}/api/cases")
        assert status == 200
        assert cases == [{"id": "loop-55-regression-case", "title": "Loop 55 Regression Case",
                          "status": "OPEN"}]

        status, case = _get(f"{base}/api/case/loop-55-regression-case")
        assert status == 200
        assert case["title"] == "Loop 55 Regression Case"
        assert case["status"] == "OPEN"
        assert case["candidates"] == []


def test_create_case_endpoint_requires_title(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case", {"title": ""})
        assert status == 400
        assert "error" in resp

        status, resp = _post(f"{base}/api/case", {"title": "   "})
        assert status == 400
        assert "error" in resp

        status, resp = _post(f"{base}/api/case", {})
        assert status == 400
        assert "error" in resp

    assert list(cases_dir.glob("*.db")) == []


def test_create_case_endpoint_dedupes_identical_titles(tmp_path):
    """Two cases with the same title must never collide on disk -- the second
    create has to fall back to a suffixed id rather than silently overwriting
    (or 500ing on) the first case's .db file."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, first = _post(f"{base}/api/case", {"title": "Duplicate Title"})
        assert status == 201
        assert first["id"] == "duplicate-title"

        status, second = _post(f"{base}/api/case", {"title": "Duplicate Title"})
        assert status == 201
        assert second["id"] == "duplicate-title-2"
        assert second["id"] != first["id"]

        status, cases = _get(f"{base}/api/cases")
        assert status == 200
        assert {c["id"] for c in cases} == {"duplicate-title", "duplicate-title-2"}


def test_create_case_endpoint_slugifies_and_falls_back(tmp_path):
    """A title with no ASCII alphanumerics (all punctuation/unicode) must
    still produce a valid, non-empty case_id instead of a blank filename."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case", {"title": "  Tor.Taxi Mirror PAIR!! "})
        assert status == 201
        assert resp["id"] == "tor-taxi-mirror-pair"

        status, resp = _post(f"{base}/api/case", {"title": "★★★"})
        assert status == 201
        assert resp["id"] == "case"


def test_verdict_persists_across_reload(tmp_path):
    """The saveVerdict write path (section 6 of the workspace-integration pass):
    a POST'd verdict must survive a fresh GET of the case, the way reopening
    the case in the Workspace does."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_case_db(cases_dir / "tortaxi.db")

    with _running_server(cases_dir) as base:
        status, case = _get(f"{base}/api/case/tortaxi")
        assert status == 200
        candidate = case["candidates"][0]
        assert candidate["verdict"] is None

        status, resp = _post(f"{base}/api/case/tortaxi/verdict", {
            "candidate_id": candidate["candidate_id"], "outcome": "CONFIRMED",
            "note": "regression test verdict", "analyst": "pytest",
        })
        assert status == 200
        assert "feedback_id" in resp

        status, reloaded = _get(f"{base}/api/case/tortaxi")
        assert status == 200
        reloaded_candidate = next(c for c in reloaded["candidates"]
                                  if c["candidate_id"] == candidate["candidate_id"])
        assert reloaded_candidate["verdict"] == {
            "outcome": "CONFIRMED", "note": "regression test verdict",
            "analyst": "pytest", "recorded_at": reloaded_candidate["verdict"]["recorded_at"],
        }

        # the verdict is a second, independent fact about the same entity — it
        # does not rewrite what the engine found about it (its identity and
        # supporting assessment stay put; the score is allowed to move on a
        # later re-correlation, since feedback_discrimination() feeding CONFIRMED
        # verdicts back into scoring is the engine's own documented behavior,
        # not something the verdict endpoint does directly)
        assert reloaded_candidate["assessment"] == candidate["assessment"]
        assert reloaded_candidate["etype"] == candidate["etype"]
        assert reloaded_candidate["key"] == candidate["key"]


def test_verdict_rejects_bad_outcome(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_case_db(cases_dir / "tortaxi.db")

    with _running_server(cases_dir) as base:
        _, case = _get(f"{base}/api/case/tortaxi")
        candidate_id = case["candidates"][0]["candidate_id"]

        status, resp = _post(f"{base}/api/case/tortaxi/verdict",
                             {"candidate_id": candidate_id, "outcome": "NOT_A_REAL_OUTCOME"})
        assert status == 400
        assert "error" in resp


def test_verdict_rejects_unknown_candidate(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_case_db(cases_dir / "tortaxi.db")

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/tortaxi/verdict",
                             {"candidate_id": "OP-doesnotexist", "outcome": "CONFIRMED"})
        assert status == 400
        assert "error" in resp


def test_verdict_refused_once_case_is_closed(tmp_path):
    """Case-state enforcement (Loop 42) reaches the GUI's own verdict route
    through the identical guard the CLI uses -- no case_api-specific check,
    since record_feedback already refuses before this endpoint's try/except
    ValueError -> 400 even sees the write attempted. A closed case must stay
    readable through the same GET route."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    db_path = cases_dir / "tortaxi.db"
    _make_case_db(db_path)
    with EvidenceStore(str(db_path)) as store:
        store.update_case(status="CLOSED")

    with _running_server(cases_dir) as base:
        status, case = _get(f"{base}/api/case/tortaxi")
        assert status == 200
        assert case["status"] == "CLOSED"
        candidate_id = case["candidates"][0]["candidate_id"]

        status, resp = _post(f"{base}/api/case/tortaxi/verdict",
                             {"candidate_id": candidate_id, "outcome": "CONFIRMED"})
        assert status == 400
        assert "CLOSED" in resp["error"]


def test_verdict_no_such_case_404(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/does-not-exist/verdict",
                             {"candidate_id": "OP-x", "outcome": "CONFIRMED"})
        assert status == 404
        assert "error" in resp


def _add_wallet(db_path: Path) -> None:
    from cybertrace.evidence import label_exchange
    with EvidenceStore(str(db_path)) as store:
        label_exchange(store, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "Test Exchange")


def test_wallet_verdict_persists_across_reload(tmp_path):
    """Loop 41: the wallet-level sibling of test_verdict_persists_across_reload
    -- a POST'd wallet verdict must survive a fresh GET of the case, and must
    never touch the automated attribution/exchange fields beside it."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    db_path = cases_dir / "tortaxi.db"
    _make_case_db(db_path)
    _add_wallet(db_path)

    with _running_server(cases_dir) as base:
        status, case = _get(f"{base}/api/case/tortaxi")
        assert status == 200
        wallet = case["wallet_exchange_paths"][0]
        assert wallet["verdict"] is None

        status, resp = _post(f"{base}/api/case/tortaxi/wallet-verdict", {
            "entity_id": wallet["entity_id"], "outcome": "BENIGN",
            "note": "regression test wallet verdict", "analyst": "pytest",
        })
        assert status == 200
        assert "feedback_id" in resp

        status, reloaded = _get(f"{base}/api/case/tortaxi")
        assert status == 200
        reloaded_wallet = next(w for w in reloaded["wallet_exchange_paths"]
                               if w["entity_id"] == wallet["entity_id"])
        assert reloaded_wallet["verdict"] == {
            "outcome": "BENIGN", "note": "regression test wallet verdict",
            "analyst": "pytest", "recorded_at": reloaded_wallet["verdict"]["recorded_at"],
        }
        assert reloaded_wallet["attribution"] == wallet["attribution"]
        assert reloaded_wallet["exchange"] == wallet["exchange"]


def test_wallet_verdict_rejects_bad_outcome(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    db_path = cases_dir / "tortaxi.db"
    _make_case_db(db_path)
    _add_wallet(db_path)

    with _running_server(cases_dir) as base:
        _, case = _get(f"{base}/api/case/tortaxi")
        entity_id = case["wallet_exchange_paths"][0]["entity_id"]

        status, resp = _post(f"{base}/api/case/tortaxi/wallet-verdict",
                             {"entity_id": entity_id, "outcome": "NOT_A_REAL_OUTCOME"})
        assert status == 400
        assert "error" in resp


def test_wallet_verdict_rejects_unknown_entity(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_case_db(cases_dir / "tortaxi.db")

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/tortaxi/wallet-verdict",
                             {"entity_id": "ent_doesnotexist", "outcome": "CONFIRMED"})
        assert status == 400
        assert "error" in resp


def test_wallet_verdict_no_such_case_404(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/does-not-exist/wallet-verdict",
                             {"entity_id": "ent_x", "outcome": "CONFIRMED"})
        assert status == 404
        assert "error" in resp


def test_investigator_endpoint_deterministic(tmp_path):
    """No CT_LLM_PROVIDER set in this test process -> the real live path
    (tools/case_api.py -> cybertrace.investigator.answer) falls back to a
    deterministic, evidence-grounded answer over the real tortaxi case."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_case_db(cases_dir / "tortaxi.db")

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/tortaxi/investigator",
                             {"question": "why are these markets connected?"})
        assert status == 200
        assert resp["mode"] == "deterministic"
        assert resp["case_id"] == "tortaxi"
        assert resp["claims"], "expected grounded claims for a real correlated case"


def test_investigator_endpoint_missing_question(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_case_db(cases_dir / "tortaxi.db")

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/tortaxi/investigator", {})
        assert status == 400
        assert "error" in resp


def test_investigator_endpoint_no_such_case(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/does-not-exist/investigator",
                             {"question": "why are these connected?"})
        assert status == 404
        assert "error" in resp


class _FakeModule:
    """Stands in for a real OSINT module so /api/search tests don't hit the
    network — mirrors the `async with module:` / `await module.search()`
    protocol case_api.run_search() actually drives."""
    name = "fake"
    supported_types: tuple = ()

    def __init__(self, result):
        self._result = result

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def search(self, target, **options):
        return self._result


def test_search_endpoint_returns_module_result(tmp_path, monkeypatch):
    from cybertrace.modules.base import ModuleResult

    fake_result = ModuleResult(target="13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94",
                                target_type="bitcoin", module="bitcoin")
    monkeypatch.setattr(
        case_api, "resolve_module_for_target",
        lambda target, input_type="auto": (_FakeModule(fake_result), target, "bitcoin", "bitcoin"))

    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, body = _get(f"{base}/api/search?q=13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94")
        assert status == 200
        assert body["target_type"] == "bitcoin"
        assert body["module"] == "bitcoin"


def test_search_endpoint_requires_q(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, body = _get(f"{base}/api/search")
        assert status == 400
        assert "error" in body


def test_search_endpoint_refuses_blocked_query(tmp_path, monkeypatch):
    monkeypatch.setattr(case_api, "is_blocked_query", lambda target: True)
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, body = _get(f"{base}/api/search?q=whatever")
        assert status == 400
        assert "error" in body


def test_search_endpoint_no_module_for_type(tmp_path, monkeypatch):
    monkeypatch.setattr(
        case_api, "resolve_module_for_target",
        lambda target, input_type="auto": (None, target, "mystery", "mystery"))
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, body = _get(f"{base}/api/search?q=whatever")
        assert status == 400
        assert "error" in body


def test_search_endpoint_rejects_checksum_invalid_btc_without_any_mock(tmp_path):
    """Loop 58, end to end through the real (unmocked) resolve_module_for_target:
    a Base58-shaped, wrong-checksum BTC address must never reach BitcoinModule
    (no live network call from a test) and must never fall through to a
    generic 'no module' message -- the browser needs to see it is specifically
    an invalid address, not an unsupported chain or a username."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, body = _get(
            f"{base}/api/search?q=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
        assert status == 400
        assert "Not a valid Bitcoin address" in body["error"]
        assert "checksum" in body["error"]


def test_search_endpoint_rejects_dataset_shape_only_string_without_any_mock(tmp_path):
    """The exact Kaggle-corpus string that motivated this loop -- must not
    silently become a username/social-search target."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, body = _get(f"{base}/api/search?q=19e6aqs6ru2ei5r3cuzcfmcklq78uksmry")
        assert status == 400
        assert "Not a valid Bitcoin address" in body["error"]


def test_detect_endpoint_flags_checksum_invalid_btc_address(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, body = _get(
            f"{base}/api/detect?address=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
        assert status == 200
        assert body["valid_address"] is False
        assert "fails checksum" in body["caveat"]


def test_detect_endpoint_flags_shape_only_dataset_string(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, body = _get(
            f"{base}/api/detect?address=19e6aqs6ru2ei5r3cuzcfmcklq78uksmry")
        assert status == 200
        assert body["module_type"] == "invalid_address"
        assert body["valid_address"] is False
        assert "Not a valid Bitcoin address" in body["caveat"]


def test_detect_endpoint_real_btc_address_is_valid(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, body = _get(
            f"{base}/api/detect?address=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert status == 200
        assert body["valid_address"] is True
        assert body["caveat"] == ""


def test_case_db_path_rejects_traversal_and_absolute_segments():
    """Unit-level pin on the guard itself (Loop 38 defect hunt): case_id
    reaches cases_dir / f"{case_id}.db" with nothing else validating it --
    a bare filename-stem allowlist is the fix, not a ".." blacklist (which
    an absolute right-hand path -- Path.__truediv__ discards the left side
    entirely for one -- or an encoded separator can bypass)."""
    cases_dir = Path("/some/cases/dir")
    assert case_api._case_db_path(cases_dir, "tortaxi") == cases_dir / "tortaxi.db"
    for hostile in ("../outside/secret", "..", "/etc/passwd", "a/b",
                    "a/../../b", "", ".", "..%2fsecret"):
        assert case_api._case_db_path(cases_dir, hostile) is None


def test_case_endpoint_rejects_a_live_path_traversal_attempt(tmp_path):
    """Reproduces the exact live exploit shape a defect hunt confirmed
    against the pre-fix handler: a %2f-encoded ".." segment survives
    unquote() as a real path separator and used to reach a *.db file
    entirely outside --cases-dir. Must now 404 like any other bad case_id,
    not read the file."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    with EvidenceStore(str(outside / "secret.db")) as store:
        store.update_case(name="should never be reachable over the API")

    with _running_server(cases_dir) as base:
        status, body = _get(f"{base}/api/case/..%2foutside%2fsecret")
        assert status == 404
        assert "error" in body

        status, body = _get(f"{base}/api/case/..%2foutside%2fsecret/snapshot/x")
        assert status == 404
        assert "error" in body

        status, resp = _post(f"{base}/api/case/..%2foutside%2fsecret/verdict",
                             {"candidate_id": "OP-x", "outcome": "CONFIRMED"})
        assert status == 404
        assert "error" in resp

        status, resp = _post(f"{base}/api/case/..%2foutside%2fsecret/wallet-verdict",
                             {"entity_id": "ent_x", "outcome": "CONFIRMED"})
        assert status == 404
        assert "error" in resp


def test_snapshot_endpoint_returns_real_payload(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_case_db(cases_dir / "tortaxi.db")

    with _running_server(cases_dir) as base:
        _, case = _get(f"{base}/api/case/tortaxi")
        snapshot_id = case["captures"][0]["snapshot_id"]

        status, payload = _get(f"{base}/api/case/tortaxi/snapshot/{snapshot_id}")
        assert status == 200
        assert payload, "expected the real captured payload, not an empty placeholder"

        status, resp = _get(f"{base}/api/case/does-not-exist/snapshot/{snapshot_id}")
        assert status == 404
        assert "error" in resp


# --- Loop 53: crypto/investigate --------------------------------------------

_BTC_VALID = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
_BTC_OTHER = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"


def _make_crypto_case_db(path: Path) -> None:
    with EvidenceStore(str(path)) as store:
        eid = store.upsert_entity("BTC_ADDRESS", _BTC_VALID)
        store.set_metadata(eid, tx_count=1)
        store.record_transactions(eid, _BTC_VALID, "BTC_ADDRESS", "bitcoin", [
            {"tx_hash": "h1", "direction": "OUT", "counterparty": _BTC_OTHER,
             "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T00:00:00+00:00"},
        ])
        store.update_case(name="crypto smoke case")


def test_crypto_investigate_endpoint_returns_composed_result(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_crypto_case_db(cases_dir / "cryptocase.db")

    with _running_server(cases_dir) as base:
        status, resp = _get(f"{base}/api/case/cryptocase/crypto/investigate?address={_BTC_VALID}")
        assert status == 200
        for key in ("wallet_trace", "transactions", "graph", "graph_summary",
                   "typology_signals", "cross_chain_events", "timeline",
                   "recommended_actions", "risk", "vasp_investigation"):
            assert key in resp
        assert resp["address"] == _BTC_VALID
        assert len(resp["transactions"]) == 1


def test_crypto_investigate_endpoint_requires_address(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_crypto_case_db(cases_dir / "cryptocase.db")

    with _running_server(cases_dir) as base:
        status, resp = _get(f"{base}/api/case/cryptocase/crypto/investigate")
        assert status == 400
        assert "error" in resp


def test_crypto_investigate_endpoint_no_such_case(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, resp = _get(
            f"{base}/api/case/does-not-exist/crypto/investigate?address={_BTC_VALID}")
        assert status == 404
        assert "error" in resp


def test_crypto_investigate_endpoint_wallet_never_searched(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_crypto_case_db(cases_dir / "cryptocase.db")

    with _running_server(cases_dir) as base:
        status, resp = _get(
            f"{base}/api/case/cryptocase/crypto/investigate?address={_BTC_OTHER}")
        assert status == 404
        assert "never searched" in resp["error"]


# --- Loop 56: /api/search runs the canonical crypto investigation too ------
#
# The landing-page Trace button hits /api/search, never a case-scoped route
# (there is no case yet at that point) -- so before this loop,
# investigate_wallet() was simply never reached from the browser at all.
# crypto_investigate_adhoc() closes that gap by ingesting this one search's
# own result into a scratch in-memory store, then calling the exact same
# investigate_wallet() the case-scoped route and CLI use. These tests pin
# that wiring at the API layer, same _FakeModule harness as the plain
# /api/search tests above -- no live network call.

_ADHOC_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
_ADHOC_COUNTERPARTY = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"


def _fake_bitcoin_result(target: str, raw_transactions: list) -> "ModuleResult":
    from cybertrace.modules.base import ModuleResult
    return ModuleResult(
        target=target, target_type="bitcoin", module="bitcoin",
        summary={"address": target, "raw_transactions": raw_transactions})


def test_search_endpoint_attaches_crypto_investigation_for_wallet_with_vasp_hit(tmp_path, monkeypatch):
    fake_result = _fake_bitcoin_result(_ADHOC_BTC, [
        {"tx_hash": "h1", "direction": "OUT", "counterparty": _ADHOC_COUNTERPARTY,
         "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T00:00:00+00:00"},
    ])
    monkeypatch.setattr(
        case_api, "resolve_module_for_target",
        lambda target, input_type="auto": (_FakeModule(fake_result), target, "bitcoin", "bitcoin"))

    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, body = _get(f"{base}/api/search?q={_ADHOC_BTC}")
        assert status == 200
        ci = body["crypto_investigation"]
        assert ci is not None, "investigate_wallet() must run for a wallet target"
        assert ci["address"] == _ADHOC_BTC
        assert ci["transaction_status"] == "FOUND"
        assert len(ci["transactions"]) == 1
        for key in ("wallet_trace", "graph", "graph_summary", "typology_signals",
                   "cross_chain_events", "timeline", "recommended_actions", "risk",
                   "vasp_investigation"):
            assert key in ci


def test_search_endpoint_non_vasp_wallet_still_returns_full_investigation(tmp_path, monkeypatch):
    """PS §13: a wallet with real transactions but no VASP reachability must
    still surface transactions/graph/behavioral data -- never render as if
    nothing happened just because there is no VASP hit."""
    fake_result = _fake_bitcoin_result(_ADHOC_BTC, [
        {"tx_hash": "h1", "direction": "IN", "counterparty": _ADHOC_COUNTERPARTY,
         "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T00:00:00+00:00"},
    ])
    monkeypatch.setattr(
        case_api, "resolve_module_for_target",
        lambda target, input_type="auto": (_FakeModule(fake_result), target, "bitcoin", "bitcoin"))

    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, body = _get(f"{base}/api/search?q={_ADHOC_BTC}")
        assert status == 200
        ci = body["crypto_investigation"]
        assert ci is not None
        assert ci["vasp_investigation"] is None or ci["vasp_investigation"].get("primary_vasp") is None
        assert ci["wallet_trace"]["exchange"] is None
        # Still real, not fabricated: the one transaction/graph/timeline entry
        # this wallet actually has must survive regardless of the VASP miss.
        assert len(ci["transactions"]) == 1
        assert ci["graph_summary"]["node_count"] > 0
        assert isinstance(ci["typology_signals"], list)
        assert isinstance(ci["recommended_actions"], list)


def test_search_endpoint_non_crypto_target_has_no_investigation_key(tmp_path, monkeypatch):
    """A username/domain/etc. search must never pay for or surface a crypto
    investigation it has nothing to do with."""
    from cybertrace.modules.base import ModuleResult
    fake_result = ModuleResult(target="someuser", target_type="username", module="username")
    monkeypatch.setattr(
        case_api, "resolve_module_for_target",
        lambda target, input_type="auto": (_FakeModule(fake_result), target, "username", "username"))

    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, body = _get(f"{base}/api/search?q=someuser")
        assert status == 200
        assert "crypto_investigation" not in body


def test_search_endpoint_crypto_target_no_raw_transactions_is_not_found_not_fabricated(tmp_path, monkeypatch):
    """PS §16: when every source failed (no raw_transactions at all), the
    composed investigation must say transaction_status NOT_FOUND -- not
    silently claim a clean wallet, and never fabricate a FOUND/PARTIAL status
    or a VASP hit for data that was never actually retrieved."""
    fake_result = _fake_bitcoin_result(_ADHOC_BTC, [])  # every source failed: no raw transactions
    monkeypatch.setattr(
        case_api, "resolve_module_for_target",
        lambda target, input_type="auto": (_FakeModule(fake_result), target, "bitcoin", "bitcoin"))

    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    with _running_server(cases_dir) as base:
        status, body = _get(f"{base}/api/search?q={_ADHOC_BTC}")
        assert status == 200
        ci = body["crypto_investigation"]
        assert ci is not None, "the wallet was still searched -- an entity exists to report on"
        assert ci["transaction_status"] == "NOT_FOUND"
        assert ci["transactions"] == []
        assert ci["wallet_trace"]["exchange"] is None


def test_crypto_investigate_adhoc_reuses_canonical_investigate_wallet(tmp_path):
    """Unit-level pin, independent of the HTTP layer: crypto_investigate_adhoc
    must call the exact same investigate_wallet() the case-scoped route and
    CLI use -- monkeypatching it here must change the ad-hoc result too, or a
    second implementation has crept in."""
    import cybertrace.crypto_investigation as ci_module

    calls = []
    real = ci_module.investigate_wallet

    def spy(store, address, **kwargs):
        calls.append(address)
        return real(store, address, **kwargs)

    ci_module.investigate_wallet = spy
    try:
        payload = _fake_bitcoin_result(_ADHOC_BTC, [
            {"tx_hash": "h1", "direction": "OUT", "counterparty": _ADHOC_COUNTERPARTY,
             "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T00:00:00+00:00"},
        ]).to_dict()
        result = case_api.crypto_investigate_adhoc(payload, "bitcoin")
    finally:
        ci_module.investigate_wallet = real

    assert calls == [_ADHOC_BTC]
    assert result is not None
    assert result["address"] == _ADHOC_BTC


# --- Loop 57: /api/case/<id>/target -- the case workspace's missing "Add
# target" round trip. Before this, the only way to get a target into a case
# was the CLI (`cybertrace search --save x.json && cybertrace correlate
# x.json --db case.db`) -- there was no browser path from "empty case" to
# "case with an investigation in it" at all. ---------------------------------

_TARGET_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
_TARGET_COUNTERPARTY = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"


def test_add_target_endpoint_persists_into_the_real_case_store(tmp_path, monkeypatch):
    """The defining behavior: unlike run_search's scratch :memory: store
    (crypto_investigate_adhoc) or add_target's own module search, ingesting
    here must land in the case's actual .db -- durable, and visible to a
    later plain GET /api/case/<id> with no special handling."""
    fake_result = _fake_bitcoin_result(_TARGET_BTC, [
        {"tx_hash": "h1", "direction": "OUT", "counterparty": _TARGET_COUNTERPARTY,
         "asset": "BTC", "value": 0.1, "timestamp": "2026-01-01T00:00:00+00:00"},
    ])
    monkeypatch.setattr(
        case_api, "resolve_module_for_target",
        lambda target, input_type="auto": (_FakeModule(fake_result), target, "bitcoin", "bitcoin"))

    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with EvidenceStore(str(cases_dir / "empty.db")) as store:
        store.update_case(name="fresh case")

    with _running_server(cases_dir) as base:
        status, before = _get(f"{base}/api/case/empty")
        assert before["target_count"] == 0, "a brand-new case must start with zero targets"

        status, resp = _post(f"{base}/api/case/empty/target", {"target": _TARGET_BTC})
        assert status == 201
        assert resp["crypto_investigation"] is not None
        assert resp["crypto_investigation"]["address"] == _TARGET_BTC

        status, after = _get(f"{base}/api/case/empty")
        assert status == 200
        assert after["target_count"] == 1, "the searched wallet must now be a real, persisted target"
        assert after["case_has_crypto"] is True


def test_add_target_endpoint_no_such_case(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/does-not-exist/target", {"target": _TARGET_BTC})
        assert status == 404
        assert "error" in resp


def test_add_target_endpoint_requires_target(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with EvidenceStore(str(cases_dir / "empty.db")) as store:
        store.update_case(name="fresh case")
    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/empty/target", {})
        assert status == 400
        assert "error" in resp


def test_add_target_endpoint_refuses_on_closed_case(tmp_path, monkeypatch):
    """PS §7/§29: a closed/archived case must not silently accrue new
    evidence -- EvidenceStore._require_open (via ingest) is what actually
    enforces this; this pins that the HTTP layer surfaces it as a clear 400,
    not a 500 or a silent no-op."""
    fake_result = _fake_bitcoin_result(_TARGET_BTC, [])
    monkeypatch.setattr(
        case_api, "resolve_module_for_target",
        lambda target, input_type="auto": (_FakeModule(fake_result), target, "bitcoin", "bitcoin"))

    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with EvidenceStore(str(cases_dir / "shut.db")) as store:
        store.update_case(name="closed case", status="CLOSED")

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/shut/target", {"target": _TARGET_BTC})
        assert status == 400
        assert "closed" in resp["error"].lower()


def test_add_target_endpoint_rejects_traversal_case_id(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/..%2foutside%2fsecret/target",
                             {"target": _TARGET_BTC})
        assert status == 404
        assert "error" in resp


# --- Loop 57: case lifecycle -- /api/case/<id>/status (archive/close/reopen)
# and DELETE /api/case/<id> (real deletion, not a frontend-only removal). ----

def test_set_status_endpoint_updates_and_persists(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with EvidenceStore(str(cases_dir / "life.db")) as store:
        store.update_case(name="lifecycle case")

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/life/status", {"status": "archived"})
        assert status == 200
        assert resp["status"] == "ARCHIVED"

        status, case = _get(f"{base}/api/case/life")
        assert case["status"] == "ARCHIVED"

        status, cases = _get(f"{base}/api/cases")
        assert next(c for c in cases if c["id"] == "life")["status"] == "ARCHIVED"


def test_set_status_endpoint_rejects_unknown_status(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with EvidenceStore(str(cases_dir / "life.db")) as store:
        store.update_case(name="lifecycle case")

    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/life/status", {"status": "deleted"})
        assert status == 400
        assert "error" in resp


def test_set_status_endpoint_no_such_case(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, resp = _post(f"{base}/api/case/does-not-exist/status", {"status": "closed"})
        assert status == 404
        assert "error" in resp


def test_delete_case_endpoint_removes_the_db_and_is_idempotent_404(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    db_path = cases_dir / "gone.db"
    with EvidenceStore(str(db_path)) as store:
        store.update_case(name="to be deleted")

    with _running_server(cases_dir) as base:
        status, cases = _get(f"{base}/api/cases")
        assert any(c["id"] == "gone" for c in cases)

        status, resp = _delete(f"{base}/api/case/gone")
        assert status == 200
        assert resp["deleted"] == "gone"
        assert not db_path.exists(), "delete must remove the real .db file, not just hide it in the UI"

        status, cases = _get(f"{base}/api/cases")
        assert not any(c["id"] == "gone" for c in cases), "count/list must update after delete"

        status, resp = _get(f"{base}/api/case/gone")
        assert status == 404, "a direct URL to the deleted case must not resurrect it"

        # Deleting again (double-click, stale tab) must 404, not 500.
        status, resp = _delete(f"{base}/api/case/gone")
        assert status == 404


def test_delete_case_endpoint_no_such_case(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    with _running_server(cases_dir) as base:
        status, resp = _delete(f"{base}/api/case/never-existed")
        assert status == 404
        assert "error" in resp


def test_delete_case_endpoint_rejects_traversal_case_id(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    with EvidenceStore(str(outside / "secret.db")) as store:
        store.update_case(name="must never be deletable over the API")

    with _running_server(cases_dir) as base:
        status, resp = _delete(f"{base}/api/case/..%2foutside%2fsecret")
        assert status == 404
        assert (outside / "secret.db").exists(), "traversal guard must block DELETE too, not only GET"
