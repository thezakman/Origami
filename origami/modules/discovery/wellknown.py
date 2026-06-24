"""`.well-known/` discovery (RFC 8615) — passive, high-signal recon.

Standardised URIs that routinely expose real endpoints unauthenticated:
  * `openid-configuration` / `oauth-authorization-server` — an OIDC/OAuth index
    listing every auth endpoint (authorization, token, jwks, userinfo, logout,
    registration). One request maps the whole auth surface.
  * `security.txt` — discloses contact/policy URLs (sometimes internal paths).
  * `change-password`, `assetlinks.json`, `apple-app-site-association`,
    `host-meta` — cheap to check, occasionally useful.

Each discovered file is a finding; endpoints parsed from the OIDC/OAuth indexes
are folded as seeds (origin "wellknown") with provenance edges for the graph.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse

from origami.core.scope import same_host

WELL_KNOWN = (
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/change-password",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/host-meta",
)

# OIDC/OAuth metadata keys whose values are endpoint URLs worth folding.
_ENDPOINT_KEYS_SUFFIX = ("_endpoint", "_uri")


def _same_host_path(url: str, host: str) -> str | None:
    if not isinstance(url, str):
        return None
    if url.startswith(("http://", "https://", "//")):   # absolute OR protocol-relative
        u = urlparse(url)                                # urlparse("//evil/x") → netloc=evil
        if u.netloc and not same_host(u.netloc, host):
            return None                                  # off-host (incl. //evil.com) → drop
        url = u.path
    if not url.startswith("/") or url.startswith("//"):
        return None
    return url.split("?")[0].split("#")[0] or None


def extract_oidc_endpoints(doc: dict, host: str) -> set[str]:
    """OIDC/OAuth metadata → same-host endpoint paths."""
    out: set[str] = set()
    for key, val in doc.items():
        if not isinstance(key, str) or not key.endswith(_ENDPOINT_KEYS_SUFFIX):
            continue
        if isinstance(val, str):
            p = _same_host_path(val, host)
            if p and p != "/":
                out.add(p)
    return out


async def harvest(engine, base_url: str,
                  on_progress=None) -> tuple[set[str], list[tuple[str, str]]]:
    """Probe the well-known URIs; return (paths, edges).

    `paths` includes each found file (so it's reported) + parsed OIDC endpoints.
    """
    host = urlparse(base_url).netloc
    paths: set[str] = set()
    edges: list[tuple[str, str]] = []
    for i, cand in enumerate(WELL_KNOWN, 1):
        if on_progress is not None:
            on_progress(i, len(WELL_KNOWN))
        probe = await engine.fetch(urljoin(base_url, cand.lstrip("/")), keep_body=True)
        if not (probe.ok and probe.status == 200 and probe.body):
            continue
        paths.add(cand)
        if cand.endswith(("openid-configuration", "oauth-authorization-server")):
            try:
                doc = json.loads(probe.body)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(doc, dict):
                eps = extract_oidc_endpoints(doc, host)
                paths |= eps
                edges += [(cand, e) for e in sorted(eps)]
    return paths, edges
