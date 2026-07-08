"""Scope rules — two distinct scopes, deliberately.

  * PARSE scope (same registrable domain): which hosts' JS/HTML we fetch and
    read. Includes the org's own CDN (cdn.example.com for app.example.com),
    because that's where the endpoint references live.
  * SCAN scope (the exact target host): which paths we actually brute-force.
    Relative references resolve against the target, so reading CDN JS still
    only ever fires requests at the target host.

Reading the CDN but scanning only the target is the fix for "lost all the good
findings": we lose them if we refuse to *read* the CDN, and we explode the
scope if we *scan* it.
"""

from __future__ import annotations

# Multi-label public suffixes: the registrable domain is ONE label above these.
# Two families, both needed for correct scope:
#   * ccTLD second-levels (com.br, co.uk) — a normal org domain hangs off them;
#   * shared-hosting / PaaS suffixes (github.io, herokuapp.com, *.amazonaws.com)
#     from the PSL's PRIVATE section — each subdomain is a DIFFERENT tenant, so
#     treating them as one site would pull a co-tenant host into `--scope site`.
# Not a full PSL, but it closes the co-tenant scope hole the heuristic had.
_PUBLIC_SUFFIX = frozenset({
    # ccTLD second-level
    "com.br", "net.br", "org.br", "gov.br", "com.au", "net.au", "org.au",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.kr", "co.in", "co.za",
    "co.nz", "com.mx", "com.ar", "com.tr", "com.cn", "com.sg", "com.hk", "com.tw",
    # shared-hosting / PaaS (co-tenant boundaries)
    "github.io", "gitlab.io", "herokuapp.com", "web.app", "firebaseapp.com",
    "pages.dev", "workers.dev", "vercel.app", "netlify.app", "azurewebsites.net",
    "cloudfront.net", "s3.amazonaws.com", "amazonaws.com", "appspot.com", "run.app",
    "pythonanywhere.com", "onrender.com", "blogspot.com", "wordpress.com",
    "myshopify.com", "readthedocs.io", "translate.goog",
})


def reg_domain(host: str) -> str:
    """Best-effort registrable domain (apex). Honors multi-label public suffixes
    so co-tenant hosts on shared platforms (foo.github.io vs bar.github.io) are
    NOT treated as the same site."""
    host = host.split("@")[-1].split(":")[0].lower().strip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    for cut in (3, 2):                      # longest public-suffix match first
        if len(parts) > cut and ".".join(parts[-cut:]) in _PUBLIC_SUFFIX:
            return ".".join(parts[-(cut + 1):])
    return ".".join(parts[-2:])


def same_site(a: str, b: str) -> bool:
    """Same registrable domain (treats www/cdn/api subdomains as one site)."""
    return reg_domain(a) == reg_domain(b)


def same_host(a: str, b: str) -> bool:
    """Exact host match, ignoring port and a leading www."""
    a, b = a.split(":")[0].lower(), b.split(":")[0].lower()
    a = a[4:] if a.startswith("www.") else a
    b = b[4:] if b.startswith("www.") else b
    return a == b
