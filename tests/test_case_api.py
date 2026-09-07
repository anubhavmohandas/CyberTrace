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
