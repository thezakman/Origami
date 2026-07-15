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


# Hosts where the TENANT is a PATH segment, not the host: one shared host serves
# every customer (Google Cloud REST APIs — Firestore/Storage/BigQuery/…, where
# the tenant is `/v1/projects/<id>/…`, `/<bucket>/…`, etc.). Host scope alone is
# not a tenant boundary here: history harvested by DOMAIN (gau/wayback) and memory
# primed by HOST both return co-tenants' paths, and `same_host` waves them through
# — so a scan of one project probes (and reports) other people's live data. On
# these hosts we additionally confine seeds to the target's own path chain.
_PATH_TENANT_SUFFIXES = frozenset({
    "googleapis.com",
})


def path_tenant_host(host: str) -> bool:
    """True for shared hosts whose tenant is identified by the URL path, so host
    scope must be tightened to the target's path chain (see same_tenant_path)."""
    h = host.split("@")[-1].split(":")[0].lower().strip(".")
    return any(h == s or h.endswith("." + s) for s in _PATH_TENANT_SUFFIXES)


def _segs(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def same_tenant_path(target_path: str, cand_path: str) -> bool:
    """For a shared path-multitenant host: is cand_path on the SAME tenant chain
    as target_path? True iff one path is a prefix of the other — an ancestor (so
    path-climb up toward root still works) or a descendant (discovery under the
    target). Diverging in ANY leading segment means a DIFFERENT tenant → False.

    A target with no path (bare host) names no tenant, so nothing is confined."""
    t, c = _segs(target_path), _segs(cand_path)
    n = min(len(t), len(c))
    return t[:n] == c[:n]
