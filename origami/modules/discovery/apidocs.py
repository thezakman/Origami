"""OpenAPI / Swagger discovery (§3.7 folding, API surface).

Modern apps describe their whole API in a machine-readable spec, and it's almost
always reachable unauthenticated at a well-known path. One `swagger.json` can
list hundreds of endpoints a wordlist would never guess — so we probe the common
spec locations, and when one parses, fold its declared paths in as high-value
seeds (origin "apidocs"). The spec file itself is a finding worth reporting.

Templated paths (`/users/{id}`) can't be fetched literally, so we seed the
static prefix (`/users/`) as a directory; fully-static paths are seeded whole.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse

# Common unauthenticated spec locations, ordered by prevalence across stacks
# (Swagger UI defaults, springfox/springdoc, .NET Swashbuckle, NestJS, etc.).
SPEC_PATHS = (
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/openapi.yaml",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
    "/api/openapi.json", "/api/v1/swagger.json", "/api/v2/api-docs",
    "/swagger-resources", "/.well-known/openapi.json", "/swagger/docs/v1",
)


def _load(body: bytes) -> dict | None:
    """Parse a spec body as JSON, then YAML; None if neither yields a dict."""
    try:
        d = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        try:
            import yaml
            d = yaml.safe_load(body)
        except Exception:
            return None
    return d if isinstance(d, dict) else None


def _is_spec(d: dict) -> bool:
    return ("swagger" in d or "openapi" in d) and isinstance(d.get("paths"), dict)


def _base_prefix(spec: dict) -> str:
    """The path prefix every operation hangs off — Swagger 2 `basePath` or the
    path of OpenAPI 3's first server URL."""
    bp = spec.get("basePath")
    if isinstance(bp, str) and bp.startswith("/"):
        return bp.rstrip("/")
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url", "")
        path = urlparse(url).path if "://" in url else url
        if isinstance(path, str) and path.startswith("/"):
            return path.rstrip("/")
    return ""


def extract_endpoints(spec: dict) -> set[str]:
    """Declared paths → root-absolute scan seeds (static prefix for templated)."""
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return set()
    prefix = _base_prefix(spec)
    out: set[str] = set()
    for raw in paths:
        if not isinstance(raw, str) or not raw.startswith("/"):
            continue
        full = (prefix + raw) if prefix else raw
        if "{" in full:                          # /users/{id} → seed the static dir
            static = full.split("{", 1)[0]
            out.add(static if static.endswith("/") else static.rsplit("/", 1)[0] + "/")
        else:
            out.add(full)
    return {p for p in out if p and p != "/"}


async def harvest(engine, base_url: str) -> tuple[str | None, set[str]]:
    """Probe spec locations; on the first that parses, return (spec_url, paths).

    `paths` includes the spec's own path, so the disclosure is reported too.
    """
    for cand in SPEC_PATHS:
        url = urljoin(base_url, cand.lstrip("/"))
        probe = await engine.fetch(url, keep_body=True)
        if not (probe.ok and probe.status == 200 and probe.body):
            continue
        spec = _load(probe.body)
        if spec is None or not _is_spec(spec):
            continue
        endpoints = extract_endpoints(spec)
        endpoints.add("/" + cand.lstrip("/"))    # the spec file itself
        return url, endpoints
    return None, set()
