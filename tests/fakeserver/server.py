#!/usr/bin/env python3
"""Origami test target — a configurable fake server.

Lets us develop baseline/fingerprint/classifier deterministically, without
hammering a real host. Emulates the cases that break naive scanners:

  * proper 404s vs **soft-404** (misses answer 200 with a "not found" page);
  * **wildcard** catch-all routing;
  * a custom 404 body carrying a **dynamic nonce** every request — so a
    length/word filter would flap but a structural simhash won't;
  * IIS-flavoured headers + ASP.NET cookie (fingerprint signal);
  * optional **rate-limit** (429 past a per-second budget).

Run:
    python tests/fakeserver/server.py --port 8000 --profile iis-soft404
"""

from __future__ import annotations

import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Paths that actually exist, with (content-type, body). Everything else is a
# miss, handled per --profile.
EXISTING = {
    "/": ("text/html",
          b"<html><body><h1>Welcome</h1><a href='/default.aspx'>home</a>"
          b"<script src='/js/app.js'></script></body></html>"),
    "/default.aspx": ("text/html", b"<html><body><h1>Default</h1><form>login</form></body></html>"),
    "/admin/login.aspx": ("text/html", b"<html><body><h1>Admin Login</h1><form>user/pass</form></body></html>"),
    "/robots.txt": ("text/plain",
                    b"User-agent: *\nDisallow: /admin/\n"
                    b"Disallow: /private/dashboard.aspx\n"
                    b"Disallow: /admin-secret\n"
                    b"Sitemap: /sitemap.xml\n"),
    # /admin-secret is 403 (in PROTECTED) but /admin-secret/ slips through →
    # exercises the 403-bypass fold (trailing-slash bypass).
    "/admin-secret/": ("application/json",
                       b'{"secret":"real admin content reached via trailing-slash bypass"}'),
    "/sitemap.xml": ("application/xml",
                     b"<?xml version='1.0'?><urlset>"
                     b"<url><loc>/reports/q3.pdf</loc></url>"
                     b"<url><loc>/legacy/portal.asp</loc></url></urlset>"),
    # only reachable via robots/sitemap, never in the wordlist:
    "/private/dashboard.aspx": ("text/html", b"<html><body><h1>Private Dashboard</h1></body></html>"),
    "/reports/q3.pdf": ("application/pdf", b"%PDF-1.4 fake report"),
    "/legacy/portal.asp": ("text/html", b"<html><body><h1>Legacy Portal</h1></body></html>"),
    "/favicon.ico": ("image/x-icon", b"\x00\x00\x01\x00" + b"FAKEICON" * 16),
    # JS with embedded endpoints — exercises the js_parser fold.
    "/js/app.js": ("application/javascript",
                   b'const base="/api/v1/";fetch("/api/v1/users");'
                   b'axios.get("/secret/panel.aspx");var x="/reports/export.ashx";'
                   b'var chunk="/js/chunk.2f3a.js";\n//# sourceMappingURL=/js/app.js.map'),
    # JS referenced from JS (webpack chunk) → exercises JS→JS following
    "/js/chunk.2f3a.js": ("application/javascript", b'fetch("/api/v2/admin/secret");'),
    "/api/v1/users": ("application/json", b'{"users":[]}'),
    "/api/v2/admin/secret": ("application/json", b'{"secret":true}'),
    "/secret/panel.aspx": ("text/html", b"<html><body><h1>Secret Panel</h1></body></html>"),
    "/reports/export.ashx": ("text/html", b"<html><body>export</body></html>"),
    # backup/source disclosure — exercises the backups fold.
    "/default.aspx.bak": ("text/plain", b"<%-- backup of default.aspx with secrets --%>"),
    "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
    "/.env": ("text/plain", b"APP_ENV=production\nAWS_ACCESS_KEY_ID=AKIAZ7QF3X9PLMNB2WQT\n"
                            b"DATABASE_URL=postgres://app:s3cr3tP4ssw0rd@db.internal:5432/prod\n"
                            b"JWT_SECRET=9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c\n"),
    # OpenAPI spec → exercises the apidocs fold. Declares endpoints reachable
    # nowhere else (not in the wordlist, JS, or robots).
    "/swagger.json": ("application/json",
                      b'{"openapi":"3.0.1","servers":[{"url":"/api/v3"}],"paths":{'
                      b'"/billing/invoices":{"get":{}},"/billing/{id}":{"get":{}},'
                      b'"/internal/metrics":{"get":{}}}}'),
    "/api/v3/billing/invoices": ("application/json", b'{"invoices":[]}'),
    "/api/v3/internal/metrics": ("application/json", b'{"uptime":1234}'),
    # OIDC index → exercises the .well-known fold (auth endpoints folded as seeds)
    "/.well-known/openid-configuration": ("application/json",
        b'{"issuer":"http://127.0.0.1","authorization_endpoint":"/oauth2/authorize",'
        b'"token_endpoint":"/oauth2/token","jwks_uri":"/oauth2/jwks.json"}'),
    "/oauth2/authorize": ("text/html", b"<html><body>OAuth Authorize</body></html>"),
    "/oauth2/jwks.json": ("application/json", b'{"keys":[]}'),
    # PWA: manifest + service worker → exercise the clientapp recon fold.
    "/manifest.json": ("application/json",
                       b'{"name":"App","start_url":"/app/home",'
                       b'"icons":[{"src":"/icons/app.png"}],'
                       b'"shortcuts":[{"url":"/pwa/orders"}]}'),
    "/sw.js": ("application/javascript",
               b'self.__precacheManifest=[{"url":"/pwa/offline-secret","revision":"1"}];'),
    "/app/home": ("text/html", b"<html><body>PWA home</body></html>"),
    "/pwa/orders": ("application/json", b'{"orders":[]}'),
    "/pwa/offline-secret": ("application/json", b'{"secret":"precached route"}'),
    # JSON:API index (Drupal-style) → exercises the apidocs JSON:API fold.
    "/jsonapi": ("application/vnd.api+json",
                 b'{"jsonapi":{"version":"1.0"},"data":[],"links":{'
                 b'"self":{"href":"/jsonapi"},'
                 b'"node--secretdoc":{"href":"/jsonapi/node/secretdoc"},'
                 b'"user--user":{"href":"/jsonapi/user/user"}}}'),
    "/jsonapi/node/secretdoc": ("application/vnd.api+json", b'{"data":[{"id":"leak"}]}'),
}
PROTECTED = {"/web.config", "/bin/", "/admin/", "/admin-secret"}  # answer 403


def _nonce() -> bytes:
    # Changes every request: a length-based filter would treat each miss as
    # "different". Structural simhash ignores it.
    return f"<!-- req {time.time_ns()} csrf={time.time_ns():x} -->".encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "Microsoft-IIS/10.0"
    profile = "iis"
    rate_limit = 0
    case_insensitive = False
    _bucket: list[float] = []

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, ctype: str, body: bytes, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Server", self.server_version)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "ASP.NET_SessionId=abc123; path=/; HttpOnly")
        self.send_header("X-Powered-By", "ASP.NET")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _rate_limited(self) -> bool:
        if not self.rate_limit:
            return False
        now = time.time()
        Handler._bucket = [t for t in Handler._bucket if now - t < 1.0]
        if len(Handler._bucket) >= self.rate_limit:
            return True
        Handler._bucket.append(now)
        return False

    def _lookup(self, path: str):
        if self.case_insensitive:
            low = path.lower()
            for k, v in EXISTING.items():
                if k.lower() == low:
                    return v
            return None
        return EXISTING.get(path)

    def do_GET(self):
        if self._rate_limited():
            self._send(429, "text/html", b"<h1>429 Too Many Requests</h1>",
                       {"Retry-After": "1"})
            return

        path = self.path.split("?")[0]

        # Explicitly-existing resources win, even under a protected prefix
        # (real IIS serves /admin/login.aspx but 403s the /admin/ listing).
        hit = self._lookup(path)
        if hit is not None:
            ctype, body = hit
            self._send(200, ctype, body)
            return

        if path in PROTECTED or any(path.startswith(p) for p in PROTECTED if p.endswith("/")):
            self._send(403, "text/html", b"<html><body><h1>403 Forbidden</h1></body></html>")
            return

        self._miss(path)

    do_HEAD = do_GET

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        if self.path.split("?")[0] == "/graphql":   # introspection enabled
            self._send(200, "application/json",
                       b'{"data":{"__schema":{"queryType":{"name":"Query"},'
                       b'"mutationType":null,"types":['
                       b'{"name":"Query","fields":[{"name":"secretUser"},{"name":"allInvoices"}]},'
                       b'{"name":"__Type","fields":[{"name":"name"}]}]}}}')
            return
        self._send(404, "text/html", b"<h1>404 Not Found</h1>")

    def do_OPTIONS(self):
        # advertise a dangerous method set so the methods fold has something to flag
        self._send(200, "text/plain", b"", {"Allow": "GET, POST, PUT, DELETE, OPTIONS"})

    def _miss(self, path: str):
        body = b"<html><body><h1>Not Found</h1><p>The resource was not found.</p>" + _nonce() + b"</body></html>"
        if self.profile == "wildcard":
            # Catch-all: everything 200 with the same shell.
            self._send(200, "text/html",
                       b"<html><body><h1>App</h1><div id=root></div>" + _nonce() + b"</body></html>")
        elif self.profile == "iis-soft404":
            self._send(200, "text/html", body)              # soft-404: 200 on a miss
        else:  # "iis": honest 404
            self._send(404, "text/html", body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--profile", default="iis",
                    choices=["iis", "iis-soft404", "wildcard"])
    ap.add_argument("--rate-limit", type=int, default=0,
                    help="max requests/second before 429 (0 = off)")
    ap.add_argument("--case-insensitive", action="store_true")
    args = ap.parse_args()

    Handler.profile = args.profile
    Handler.rate_limit = args.rate_limit
    Handler.case_insensitive = args.case_insensitive

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[fakeserver] http://{args.host}:{args.port}  profile={args.profile} "
          f"rate_limit={args.rate_limit} case_insensitive={args.case_insensitive}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
