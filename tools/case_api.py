#!/usr/bin/env python3
"""Thin read-only bridge: serves web/CyberTrace Workspace.dc.html plus a small
JSON API that reads real case .db files instead of the one static
case-tortaxi.json export.

A "case" is just a *.db file under --cases-dir, built the same way the CLI
already builds one:

    cybertrace correlate a.json b.json --db cases/tortaxi.db
    cybertrace case --db cases/tortaxi.db --name "tor.taxi mirror pair"

    python tools/case_api.py                       # serves ./cases, ./web on :8765

occam: stdlib http.server, one process, no new dependency, no registry file —
the CLI's existing `case --name` command already stores the display title
inside each db, and build_payload() (tools/export_case_gui.py) already knows
how to shape a store into what the GUI expects.
"""
from __future__ import annotations

import argparse
import functools
import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybertrace.evidence import EvidenceStore
from tools.export_case_gui import build_payload

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"


def case_summary(db_path: Path) -> dict:
    with EvidenceStore(str(db_path)) as store:
        info = store.case_info()
    return {"id": db_path.stem, "title": info.get("name") or db_path.stem,
            "status": info.get("status", "OPEN")}


def case_payload(cases_dir: Path, case_id: str) -> dict | None:
    db_path = cases_dir / f"{case_id}.db"
    if not db_path.is_file():
        return None
    with EvidenceStore(str(db_path)) as store:
        title = store.case_info().get("name") or case_id
        return build_payload(store, case_id, title)


def make_handler(cases_dir: Path):
    class Handler(SimpleHTTPRequestHandler):
        def do_GET(self):
            path = unquote(urlsplit(self.path).path)
            if path == "/api/cases":
                cases = [case_summary(p) for p in sorted(cases_dir.glob("*.db"))]
                return self._json(cases)
            if path.startswith("/api/case/"):
                payload = case_payload(cases_dir, path[len("/api/case/"):])
                if payload is None:
                    return self._json({"error": "no such case"}, status=404)
                return self._json(payload)
            return super().do_GET()

        def _json(self, obj, status: int = 200) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases-dir", type=Path, default=ROOT / "cases")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()

    args.cases_dir.mkdir(exist_ok=True)
    handler = functools.partial(make_handler(args.cases_dir), directory=str(WEB_DIR))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    print(f"serving {WEB_DIR} + /api on http://127.0.0.1:{args.port}/CyberTrace%20Workspace.dc.html "
          f"(cases dir: {args.cases_dir})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
