#!/usr/bin/env python3
"""Benchmark: vocabulary-fold budget (--max-folds) vs cost and yield.

Scenario models the real value of folding: a JS bundle references many names
(5 high-frequency "valuable" ones + 95 low-frequency noise). Hidden files live
at /app/<name>.ashx for the 5 valuable names only — and those names are NOT in
the base wordlist, so they're findable *only* by folding the learned vocabulary
into the /app/ recursion.

We sweep --max-folds and report requests made vs hidden files found, to pick a
sane default (capture the high-value tail, don't pay for the noise).

Run:  PYTHONPATH=. .venv/bin/python tests/benchmark/bench_folds.py
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from origami.core.httpclient import Engine, EngineConfig
from origami.core.scanner import ScanOptions, scan

# 5 valuable names (high freq in JS), none in the builtin base wordlist.
VALUABLE = ["invoices", "getorders", "billing", "claims", "statements"]
NOISE = [f"noise{i}" for i in range(95)]

# Valuable names appear in 3 DISTINCT reference paths each (freq 3, rank high);
# noise appears once (freq 1). js_paths is a set, so distinct paths = frequency.
_JS = "".join(f'fetch("/api/v1/{n}.ashx");fetch("/api/v2/{n}.ashx");fetch("/m/{n}.ashx");'
              for n in VALUABLE)
_JS += "".join(f'fetch("/svc/{n}.ashx");' for n in NOISE)
_JS = _JS.encode()

# robots.txt makes /app/ discoverable so recursion can reach the hidden files.
_ROBOTS = b"User-agent: *\nDisallow: /app/\n"

HIDDEN = {f"/app/{n}.ashx" for n in VALUABLE}   # findable only via folded vocab


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): ...

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            return self._send(200, b"<html><script src='/bundle.js'></script></html>")
        if p == "/bundle.js":
            return self._send(200, _JS, "application/javascript")
        if p == "/robots.txt":
            return self._send(200, _ROBOTS, "text/plain")
        if p in HIDDEN:
            return self._send(200, b'{"ok":true,"secret":1}', "application/json")
        if p == "/app" or p == "/app/":
            return self._send(403, b"<h1>403 Forbidden</h1>")
        return self._send(404, b"<h1>404 Not Found</h1>")

    do_HEAD = do_GET

    def _send(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


async def run_once(base_url, max_folds):
    cfg = EngineConfig(concurrency=30)
    opts = ScanOptions(max_depth=1, max_folds=max_folds, backups=False)
    async with Engine(cfg) as engine:
        res = await scan(engine, base_url, opts)   # NullObserver, no memory
    found = sum(1 for f in res.findings if f.url.endswith(".ashx") and "/app/" in f.url)
    return res.requests_made, found


def main():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}/"

    print(f"scenario: 5 valuable + 95 noise names in JS; {len(HIDDEN)} hidden /app/*.ashx files")
    print(f"{'max_folds':>10} {'requests':>10} {'hidden_found':>13} {'req/find':>10}")
    for mf in (0, 5, 10, 20, 40, 80, 150):
        reqs, found = asyncio.run(run_once(base, mf))
        ratio = f"{reqs/found:.0f}" if found else "-"
        print(f"{mf:>10} {reqs:>10} {found:>3}/{len(HIDDEN):<9} {ratio:>10}")
    httpd.shutdown()


if __name__ == "__main__":
    main()
