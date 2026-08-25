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
import hmac
import json
import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybertrace.evidence import EvidenceStore
from tools.export_case_gui import build_payload

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"

# Unset (local dev, same-origin) => open, exactly today's behavior.
# Set (any public deploy) => every /api/* request needs X-CT-Api-Key: <value>,
# since this process otherwise has zero authentication and a public URL
# would let anyone read case evidence or write fake analyst verdicts.
API_KEY = os.environ.get("CT_API_KEY", "")
# Netlify (or wherever the frontend is hosted) is a different origin than
# this API once they're split across two hosts — needs its own CORS grant.
ALLOWED_ORIGIN = os.environ.get("CT_ALLOWED_ORIGIN", "*")


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


def snapshot_body(cases_dir: Path, case_id: str, snapshot_id: str) -> dict | None:
    db_path = cases_dir / f"{case_id}.db"
    if not db_path.is_file():
        return None
    with EvidenceStore(str(db_path)) as store:
        return store.snapshot_payload(snapshot_id)


def make_handler(cases_dir: Path):
    class Handler(SimpleHTTPRequestHandler):
        def _authorized(self) -> bool:
            if not API_KEY:
                return True
            return hmac.compare_digest(self.headers.get("X-CT-Api-Key", ""), API_KEY)

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors_headers()
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CT-Api-Key")
            self.end_headers()

        def do_GET(self):
            path = unquote(urlsplit(self.path).path)
            if path.startswith("/api/") and not self._authorized():
                return self._json({"error": "unauthorized"}, status=401)
            if path == "/api/cases":
                cases = [case_summary(p) for p in sorted(cases_dir.glob("*.db"))]
                return self._json(cases)
            if path.startswith("/api/case/"):
                rest = path[len("/api/case/"):]
                if "/snapshot/" in rest:
                    case_id, snapshot_id = rest.split("/snapshot/", 1)
                    payload = snapshot_body(cases_dir, case_id, snapshot_id)
                    if payload is None:
                        return self._json({"error": "no such case"}, status=404)
                    return self._json(payload)
                payload = case_payload(cases_dir, rest)
                if payload is None:
                    return self._json({"error": "no such case"}, status=404)
                return self._json(payload)
            return super().do_GET()

        def do_POST(self):
            path = unquote(urlsplit(self.path).path)
            if path.startswith("/api/") and not self._authorized():
                return self._json({"error": "unauthorized"}, status=401)
            if path.startswith("/api/case/") and path.endswith("/verdict"):
                case_id = path[len("/api/case/"):-len("/verdict")]
                return self._save_verdict(case_id)
            return self._json({"error": "not found"}, status=404)

        def _save_verdict(self, case_id: str) -> None:
            db_path = cases_dir / f"{case_id}.db"
            if not db_path.is_file():
                return self._json({"error": "no such case"}, status=404)
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._json({"error": "invalid JSON body"}, status=400)
            candidate_id = body.get("candidate_id")
            outcome = body.get("outcome")
            if not candidate_id or not outcome:
                return self._json({"error": "candidate_id and outcome are required"}, status=400)
            with EvidenceStore(str(db_path)) as store:
                try:
                    feedback_id = store.record_feedback(
                        candidate_id, outcome, note=body.get("note"), analyst=body.get("analyst"))
                except ValueError as e:
                    return self._json({"error": str(e)}, status=400)
            return self._json({"feedback_id": feedback_id}, status=200)

        def _cors_headers(self) -> None:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            if ALLOWED_ORIGIN != "*":
                self.send_header("Vary", "Origin")

        def _json(self, obj, status: int = 200) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._cors_headers()
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases-dir", type=Path, default=ROOT / "cases")
    # $PORT: most PaaS hosts (Render, Railway, Fly...) assign the port and
    # expect the process to read it from the environment.
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8765)))
    # 127.0.0.1 only accepts connections from the same machine — fine for
    # local dev, unreachable if this process is meant to serve a public host.
    ap.add_argument("--host", default=os.environ.get("CT_API_HOST", "127.0.0.1"))
    args = ap.parse_args()

    args.cases_dir.mkdir(exist_ok=True)
    handler = functools.partial(make_handler(args.cases_dir), directory=str(WEB_DIR))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    if not API_KEY and args.host != "127.0.0.1":
        print("WARNING: serving on a non-local host with CT_API_KEY unset — "
              "every /api/* route is open to anyone who can reach this host.",
              file=sys.stderr)
    print(f"serving {WEB_DIR} + /api on http://{args.host}:{args.port}/CyberTrace%20Workspace.dc.html "
          f"(cases dir: {args.cases_dir})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
