"""HTTP method discovery (work.md: OPTIONS/TRACE/PUT).

One OPTIONS request reveals the server's `Allow` set. Dangerous methods enabled
in production are a real, actionable misconfig: PUT/DELETE (write/remove),
TRACE/TRACK (Cross-Site Tracing), PATCH, and the WebDAV verbs (PROPFIND, MKCOL,
MOVE, COPY — often a writable share). We only surface a finding when something
dangerous is allowed; an ordinary GET/POST/HEAD set is just logged.
"""

from __future__ import annotations

# Methods worth flagging when a server advertises them.
_DANGEROUS = {
    "PUT", "DELETE", "TRACE", "TRACK", "PATCH", "CONNECT",
    "PROPFIND", "PROPPATCH", "MKCOL", "MOVE", "COPY", "LOCK", "UNLOCK",
}


def parse_allow(allow: str) -> tuple[list[str], list[str]]:
    """An `Allow` header value → (sorted methods, sorted dangerous subset)."""
    methods = sorted({m.strip().upper() for m in (allow or "").split(",") if m.strip()})
    return methods, sorted(set(methods) & _DANGEROUS)


async def probe(engine, base_url: str) -> tuple[int, list[str], list[str]]:
    """OPTIONS the base URL → (status, allowed_methods, dangerous_methods)."""
    p = await engine.fetch(base_url, method="OPTIONS")
    if not p.ok:
        return 0, [], []
    allow = p.headers.get("allow") or p.headers.get("access-control-allow-methods") or ""
    methods, dangerous = parse_allow(allow)
    return p.status, methods, dangerous
