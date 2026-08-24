"""Smoke test for tools/case_api.py: a real case .db, served over HTTP, must
come back in the exact shape web/CyberTrace Workspace.dc.html expects — same
invariant as test_export_case_gui.py, just through the live bridge instead of
a batch export.
"""
import functools
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

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


def test_cases_and_case_endpoints(tmp_path):
    assert all(p.is_file() for p in CAPTURES), "runs/raw/v8 tortaxi captures are missing"
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    _make_case_db(cases_dir / "tortaxi.db")

    handler = functools.partial(case_api.make_handler(cases_dir), directory=str(case_api.WEB_DIR))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, cases = _get(f"http://127.0.0.1:{port}/api/cases")
        assert status == 200
        assert cases == [{"id": "tortaxi", "title": "tor.taxi mirror pair", "status": "OPEN"}]

        status, case = _get(f"http://127.0.0.1:{port}/api/case/tortaxi")
        assert status == 200
        assert case["title"] == "tor.taxi mirror pair"
        assert len(case["candidates"]) == 2
        assert case["suppressed"], "expected the page-similarity contradiction to survive the live path too"

        status, body = _get(f"http://127.0.0.1:{port}/api/case/does-not-exist")
        assert status == 404
        assert "error" in body
    finally:
        server.shutdown()
        thread.join()
