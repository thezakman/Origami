"""OPTIONS metadata: advertised methods are leads, not proof of writable access.

Neither Allow nor a CORS policy establishes successful execution, authorization
or a misconfiguration. No write method is exercised by this module.
"""

from __future__ import annotations

from shlex import quote

from origami.core.response_classifier import Finding

# Methods worth flagging when a server advertises them.
_DANGEROUS = {
    "PUT", "DELETE", "TRACE", "TRACK", "PATCH", "CONNECT",
    "PROPFIND", "PROPPATCH", "MKCOL", "MOVE", "COPY", "LOCK", "UNLOCK",
}


def parse_allow(allow: str) -> tuple[list[str], list[str]]:
    """An `Allow` header value → (sorted methods, sorted dangerous subset)."""
    methods = sorted({m.strip().upper() for m in (allow or "").split(",") if m.strip()})
    return methods, sorted(set(methods) & _DANGEROUS)


async def probe(engine, base_url: str) -> Finding | None:
    """Return an observation using the actual OPTIONS response metadata."""
    p = await engine.fetch(base_url, method="OPTIONS")
    if not p.ok:
        return None
    source = "Allow" if p.headers.get("allow") else "Access-Control-Allow-Methods"
    _, interesting = parse_allow(p.headers.get(source.lower(), ""))
    if not interesting:
        return None
    return Finding(
        p.url, p.status, p.length, p.content_type, 0.5, "methods",
        note=(f"advertised via {source}: {', '.join(interesting)}; "
              "execution and authorization not tested"),
        tags=["methods"], simhash=p.body_simhash, words=p.words, lines=p.lines,
        repro=f"curl -X OPTIONS -- {quote(p.url)}",
        body_digest=p.body_digest, redirect_digest=p.redirect_digest,
        location=p.location, truncated=p.truncated, header_digest=p.header_digest,
    )
