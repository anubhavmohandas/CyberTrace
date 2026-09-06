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
import asyncio
import functools
import hmac
import json
import os
import re
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybertrace import investigator
from cybertrace.evidence import EvidenceStore
from cybertrace.modules import resolve_module_for_target
from cybertrace.safety import is_blocked_query
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


# case_id/`rest` below reach every one of these call sites straight off the
# URL path (do_GET/do_POST) with nothing else validating them. A bare
# filename-stem allowlist is the root-cause fix, applied once here rather
# than patched into each of the four `cases_dir / f"{case_id}.db"` sites
# individually: a blacklist against ".." is easy to bypass (an absolute
# path -- Path.__truediv__ with an absolute right operand discards the left
# side entirely, e.g. Path("cases") / "/etc/passwd" == Path("/etc/passwd")
# -- or an encoded separator), while this only ever accepts what the CLI
# itself already produces as a case_id (a `--db cases/<name>.db` stem).
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _case_db_path(cases_dir: Path, case_id: str) -> Optional[Path]:
    """The on-disk *.db path for `case_id`, or None if it isn't a bare
    filename stem -- treated identically to "no such case" by every caller,
    so a traversal attempt gets the same 404 a typo would, not a distinct
    error that would confirm the guard exists."""
    if not _CASE_ID_RE.match(case_id):
        return None
    return cases_dir / f"{case_id}.db"


def case_summary(db_path: Path) -> dict:
    with EvidenceStore(str(db_path)) as store:
        info = store.case_info()
    return {"id": db_path.stem, "title": info.get("name") or db_path.stem,
            "status": info.get("status", "OPEN")}


def case_payload(cases_dir: Path, case_id: str) -> dict | None:
    db_path = _case_db_path(cases_dir, case_id)
    if db_path is None or not db_path.is_file():
        return None
    with EvidenceStore(str(db_path)) as store:
        title = store.case_info().get("name") or case_id
        return build_payload(store, case_id, title)


def run_search(target: str) -> dict:
    """Run the same single-target search `cybertrace search` does and return
    its ModuleResult as a dict. Raises ValueError on a refused/unsupported
    target so the caller can turn it into a 400.

    occam: runs inline on the request thread rather than as a background
    job — fine for bitcoin/domain (~5s), but username/email modules shell
    out to maigret/holehe and can block a thread for minutes (tool_timeout).
    ThreadingHTTPServer gives each request its own thread so this doesn't
    stall other requests; move to a job+polling model if the UI needs to
    stay responsive during a slow module.
    """
    if is_blocked_query(target):
        raise ValueError("target refused: names prohibited content")
    module, normalized, specific_type, module_type = resolve_module_for_target(target)
    if module is None:
        raise ValueError(f"no module available for type: {module_type}")

    async def _go():
        async with module:
            return await module.search(normalized, target_type=specific_type)

    result = asyncio.run(_go())
    return result.to_dict()


def provider_health() -> dict:
    """Live provider health, cached a few minutes -- see provider_health.py
    for why "a key is set" and "the API actually answered" are kept as two
    different facts. capability_summary() reduces the per-provider rows to
    per-chain + cross-chain vasp_attribution availability (Loop 52 §4): one
    provider being DOWN does not mean the chain it serves is unreachable if
    another provider covers it."""
    from cybertrace.provider_health import capability_summary, check_all
    entries = asyncio.run(check_all())
    return {"providers": [e.to_dict() for e in entries],
            "capabilities": capability_summary(entries)}


def detect_address(address: str) -> dict:
    """Format detection plus, for an ambiguous EVM address, a live probe of
    which networks it actually has activity on -- mirrors `cybertrace detect`."""
    from cybertrace.detector import btc_address_family, chain_caveat, detect_input_type
    from cybertrace.modules.bitcoin_module import BitcoinModule

    specific, module_type = detect_input_type(address)
    out = {'address': address, 'format': specific, 'module_type': module_type,
           'caveat': chain_caveat(specific), 'btc_family': None, 'networks': None}
    if specific in ('btc_legacy', 'btc_bech32'):
        out['btc_family'] = btc_address_family(address)
    elif specific == 'ethereum':
        async def _go():
            async with BitcoinModule() as m:
                return await m.probe_evm_networks(address)
        out['networks'] = asyncio.run(_go())
    return out


def snapshot_body(cases_dir: Path, case_id: str, snapshot_id: str) -> dict | None:
    db_path = _case_db_path(cases_dir, case_id)
    if db_path is None or not db_path.is_file():
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
            if path == "/api/providers/health":
                try:
                    return self._json(provider_health())
                except Exception as e:
                    return self._json({"error": f"health check failed: {e}"}, status=502)
            if path == "/api/detect":
                address = (parse_qs(urlsplit(self.path).query).get("address") or [""])[0].strip()
                if not address:
                    return self._json({"error": "address is required"}, status=400)
                try:
                    return self._json(detect_address(address))
                except Exception as e:
                    return self._json({"error": f"detect failed: {e}"}, status=502)
            if path == "/api/search":
                target = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0].strip()
                if not target:
                    return self._json({"error": "q is required"}, status=400)
                try:
                    return self._json(run_search(target))
                except ValueError as e:
                    return self._json({"error": str(e)}, status=400)
                except Exception as e:
                    return self._json({"error": f"search failed: {e}"}, status=502)
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
            if path.startswith("/api/case/") and path.endswith("/wallet-verdict"):
                case_id = path[len("/api/case/"):-len("/wallet-verdict")]
                return self._save_wallet_verdict(case_id)
            if path.startswith("/api/case/") and path.endswith("/verdict"):
                case_id = path[len("/api/case/"):-len("/verdict")]
                return self._save_verdict(case_id)
            if path.startswith("/api/case/") and path.endswith("/investigator"):
                case_id = path[len("/api/case/"):-len("/investigator")]
                return self._investigator_answer(case_id)
            return self._json({"error": "not found"}, status=404)

        def _investigator_answer(self, case_id: str) -> None:
            db_path = _case_db_path(cases_dir, case_id)
            if db_path is None or not db_path.is_file():
                return self._json({"error": "no such case"}, status=404)
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._json({"error": "invalid JSON body"}, status=400)
            question = (body.get("question") or "").strip()
            if not question:
                return self._json({"error": "question is required"}, status=400)
            with EvidenceStore(str(db_path)) as store:
                result = investigator.answer(store, case_id, question,
                                              candidate_id=body.get("candidate_id"))
            return self._json(result, status=200)

        def _save_verdict(self, case_id: str) -> None:
            db_path = _case_db_path(cases_dir, case_id)
            if db_path is None or not db_path.is_file():
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

        def _save_wallet_verdict(self, case_id: str) -> None:
            """Same shape as _save_verdict, for a wallet entity_id rather than
            a candidate_id -- see evidence.wallet_feedback's schema comment
            for why a traced wallet needs its own table/endpoint instead of
            reusing the candidate one."""
            db_path = _case_db_path(cases_dir, case_id)
            if db_path is None or not db_path.is_file():
                return self._json({"error": "no such case"}, status=404)
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._json({"error": "invalid JSON body"}, status=400)
            entity_id = body.get("entity_id")
            outcome = body.get("outcome")
            if not entity_id or not outcome:
                return self._json({"error": "entity_id and outcome are required"}, status=400)
            with EvidenceStore(str(db_path)) as store:
                try:
                    feedback_id = store.record_wallet_feedback(
                        entity_id, outcome, note=body.get("note"), analyst=body.get("analyst"))
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
