#!/usr/bin/env python3
"""Benchmark: adaptive (full Origami) vs blind (wordlist-only) — the §8 north star.

A fake target hides four "treasure" files that are NOT in the builtin wordlist
and are reachable ONLY through the adaptive folds:
  * /api/internal/secret-config , /api/internal/users-export — referenced from JS;
  * /api/v2/admin-tokens — declared in an OpenAPI spec;
  * /backup-2024/dump.sql — under a dir disclosed by robots.txt + the backups fold.
A couple of files that ARE in the wordlist (admin, login) exist too, so the blind
run finds *something*. We run both configs against the same server and report
hits, requests and hits/request — the proof that evidence-guided > brute.

Run:  PYTHONPATH=. .venv/bin/python tests/benchmark/bench_adaptive.py
"""

from __future__ import annotations

import asyncio
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from origami.core.httpclient import Engine, EngineConfig
from origami.core.scanner import ScanOptions, scan

# A tiny wordlist keeps the benchmark fast — the treasures are found via the
# FOLDS, not the wordlist; the list only needs the two easy names so the blind
# run has a baseline to find.
_WORDS = ["admin", "login", "index", "api", "backup", "static", "robots", "users"]

# Each treasure is reachable ONLY via one adaptive fold, and none is in the
# wordlist. Distinct bodies (path-derived) so the same-length collapse can't
# merge them.
TREASURE = {
    "/api/internal/secret-config",   # JS reference
    "/api/internal/users-export",    # JS reference
    "/api/v2/admin-tokens",          # OpenAPI spec
    "/secret-backup.sql",            # robots.txt Disallow
}
WORDLIST_HITS = {"/admin", "/login"}            # exist AND are in the wordlist

_APP_JS = (b'const a="/api/internal/secret-config";'
           b'fetch("/api/internal/users-export");')
_OPENAPI = (b'{"openapi":"3.0.0","paths":{"/api/v2/admin-tokens":{"get":{}}}}')
_ROBOTS = b"User-agent: *\nDisallow: /secret-backup.sql\n"
_ROOT = b'<html><body><script src="/static/app.js"></script></body></html>'


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): ...

    def _send(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Server", "nginx")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        routes = {
            "/": _ROOT, "/static/app.js": _APP_JS, "/openapi.json": _OPENAPI,
            "/robots.txt": _ROBOTS,
        }
        if p in routes:
            ct = ("application/javascript" if p.endswith(".js")
                  else "application/json" if p.endswith(".json")
                  else "text/plain" if p.endswith(".txt") else "text/html")
            return self._send(200, routes[p], ct)
        if p in TREASURE or p in WORDLIST_HITS:
            # path-derived body → unique length, so the collapse can't merge hits
            return self._send(200, f'{{"path":"{p}","ok":true}}'.encode(), "application/json")
        self._send(404, b"<h1>404 Not Found</h1>")
    do_HEAD = do_GET


async def _run(base, opts):
    cfg = EngineConfig(concurrency=20, timeout=5.0)
    async with Engine(cfg) as e:
        r = await scan(e, base, opts, memory=None)
    found = {f.url.split(base.rstrip("/"), 1)[-1] for f in r.findings}
    return r.requests_made, found


async def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/"

    wl = Path(tempfile.mkdtemp()) / "wl.txt"
    wl.write_text("\n".join(_WORDS))
    common = dict(max_requests=20000, shortscan="off", wordlist_path=str(wl))
    blind = ScanOptions(js=False, apidocs=False, backups=False, max_folds=0, **common)
    adaptive = ScanOptions(**common)

    b_req, b_found = await _run(base, blind)
    a_req, a_found = await _run(base, adaptive)
    srv.shutdown()

    def report(name, req, found):
        treasure = len(TREASURE & found)
        hits = len(found)
        print(f"  {name:<10} requests={req:<6} hits={hits:<4} "
              f"treasure={treasure}/{len(TREASURE)}  hits/req={hits/max(req,1):.3f}")

    print("Origami — adaptive vs blind (§8 north star)\n")
    report("blind", b_req, b_found)
    report("adaptive", a_req, a_found)
    gain = (len(TREASURE & a_found)) - (len(TREASURE & b_found))
    print(f"\n  adaptive found {gain} more treasure files than blind "
          f"(reachable only via JS / OpenAPI / robots folds).")


if __name__ == "__main__":
    asyncio.run(main())
