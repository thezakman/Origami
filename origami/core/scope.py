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

from urllib.parse import urlparse

# second-level labels that act as public suffixes (com.br, co.uk, gov.au, ...)
_2LD = {"com", "co", "org", "net", "gov", "edu", "ac", "gob", "mil", "or", "ne", "go"}


def reg_domain(host: str) -> str:
    """Best-effort registrable domain without a full public-suffix list."""
    host = host.split("@")[-1].split(":")[0].lower().strip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    if parts[-2] in _2LD:
        return ".".join(parts[-3:])
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


def host_of(url: str) -> str:
    return urlparse(url).netloc
