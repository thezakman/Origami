"""API-surface discovery: OpenAPI / Swagger / JSON:API (§3.7 folding).

Modern apps describe their whole API in a machine-readable document, almost
always reachable unauthenticated at a well-known path. One file can list hundreds
of endpoints a wordlist would never guess — so we probe the common locations,
and when one parses, fold its declared paths in as high-value seeds (origin
"apidocs"). The document itself is a finding worth reporting.

Two shapes are understood:
  * OpenAPI / Swagger — `paths` object (templated `/users/{id}` → seed the static
    dir `/users/`; fully-static paths seeded whole), with `basePath`/`servers`;
  * JSON:API — the Drupal-style `/jsonapi` index, whose `links` object lists
    every resource collection URL.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

# Common unauthenticated locations, ordered by prevalence (Swagger UI defaults,
# springfox/springdoc, .NET Swashbuckle, NestJS, then the JSON:API index).
SPEC_PATHS = (
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/openapi.yaml",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
    "/api/openapi.json", "/api/v1/swagger.json", "/api/v2/api-docs",
    "/swagger-resources", "/.well-known/openapi.json", "/swagger/docs/v1",
    "/jsonapi", "/jsonapi/index",          # JSON:API index (Drupal, etc.)
)

MAX_API_PATHS = 300                        # cap folded endpoints — a big API can be huge

# Swagger/Redoc UI pages that DECLARE the real spec locations. Crucial for the
# multi-document .NET Swashbuckle pattern: one UI at /swagger/index.html whose
# config lists several specs (`urls:[{url,name},…]`) at non-default, per-area
# paths a brute list would never guess (/swagger/internal/swagger.json, …).
UI_PATHS = (
    "/swagger/index.html", "/swagger", "/swagger/", "/swagger-ui/index.html",
    "/swagger-ui/", "/api-docs/index.html", "/redoc",
)
MAX_SPECS = 12                             # cap distinct specs folded from one UI

# `"url":"…swagger.json"` entries in the UI config (the multi-doc `urls:[…]` array
# or a single `url:`), and a `configUrl` that points at a JSON carrying them.
_UI_SPEC_URL = re.compile(rb"""["']url["']\s*:\s*["']([^"']+?\.(?:json|ya?ml))["']""", re.I)
_UI_CONFIG_URL = re.compile(rb"""["']?configUrl["']?\s*:\s*["']([^"']+)["']""", re.I)


def extract_ui_spec_urls(html: bytes, page_url: str) -> list[str]:
    """A Swagger-UI page (or its configUrl JSON) → the spec URLs it declares,
    each resolved against the page location. Handles the multi-document
    `urls:[{url,name},…]` array with relative (`internal/swagger.json`) or
    absolute entries; order-preserving and de-duplicated."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _UI_SPEC_URL.finditer(html[:200_000]):
        full = urljoin(page_url, m.group(1).decode("utf-8", "replace"))
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out[:MAX_SPECS]


def _load(body: bytes) -> dict | None:
    """Parse a body as JSON, then YAML; None if neither yields a dict."""
    try:
        d = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        try:
            import yaml
            d = yaml.safe_load(body)
        except Exception:
            return None
    return d if isinstance(d, dict) else None


# ---- OpenAPI / Swagger --------------------------------------------------------

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
        path = urlparse(url).path if url.startswith(("http://", "https://")) else url
        if isinstance(path, str) and path.startswith("/"):
            return path.rstrip("/")
    return ""


def extract_endpoints(spec: dict) -> set[str]:
    """OpenAPI declared paths → root-absolute scan seeds (static prefix for
    templated)."""
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


# ---- JSON:API -----------------------------------------------------------------

def _is_jsonapi(d: dict, ctype: str = "") -> bool:
    if "vnd.api+json" in (ctype or ""):
        return True
    return isinstance(d.get("jsonapi"), dict) and isinstance(d.get("links"), dict)


def extract_jsonapi_links(d: dict) -> set[str]:
    """JSON:API index `links` → root-absolute resource paths.

    Each link value is either a URL string or a `{"href": url, ...}` object.
    """
    links = d.get("links")
    if not isinstance(links, dict):
        return set()
    out: set[str] = set()
    for v in links.values():
        href = v.get("href") if isinstance(v, dict) else (v if isinstance(v, str) else None)
        if not isinstance(href, str):
            continue
        path = urlparse(href).path if href.startswith(("http://", "https://")) else href
        if isinstance(path, str) and path.startswith("/") and path != "/":
            out.add(path.split("?")[0].split("#")[0])
    return out


# ---- driver -------------------------------------------------------------------

def _endpoints_from_doc(doc: dict, ctype: str = "") -> set[str]:
    """OpenAPI/Swagger or JSON:API doc → declared endpoint paths (empty if neither)."""
    if _is_spec(doc):
        return extract_endpoints(doc)
    if _is_jsonapi(doc, ctype):
        return extract_jsonapi_links(doc)
    return set()


async def ingest_source(engine, source: str) -> tuple[str | None, set[str]]:
    """Load an *explicitly-provided* OpenAPI/Swagger or JSON:API document from a
    URL or local file (`--openapi`) and return (label, declared paths).

    Lets the user feed a spec the scanner can't reach on its own — an off-host
    docs server, or a file handed over by the client — to seed the scan with the
    full declared API surface. The returned paths are root-absolute, applied to
    the target being scanned (a spec's `/users/` is probed on the target host).
    `label` is the URL/path, for the log line; on any failure returns (None, set()).
    """
    body: bytes | None = None
    ctype = ""
    if source.startswith(("http://", "https://")):
        probe = await engine.fetch(source, keep_body=True)
        if probe.ok and probe.body:
            body, ctype = probe.body, probe.content_type
    else:
        try:
            body = Path(source).expanduser().read_bytes()
        except OSError:
            return None, set()
    if not body:
        return None, set()
    doc = _load(body)
    if doc is None:
        return None, set()
    endpoints = set(sorted(_endpoints_from_doc(doc, ctype))[:MAX_API_PATHS])
    return (source, endpoints) if endpoints else (None, set())


async def _discover_ui_specs(engine, base_url: str) -> list[str]:
    """Probe the Swagger-UI pages; return the spec URLs the first one declares
    (following a `configUrl` one hop if the page defers to one). Empty if no UI
    or config is found."""
    for cand in UI_PATHS:
        url = urljoin(base_url, cand.lstrip("/"))
        try:
            probe = await engine.fetch(url, keep_body=True)
        except Exception:
            continue
        if not (probe.ok and probe.status == 200 and probe.body):
            continue
        specs = extract_ui_spec_urls(probe.body, url)
        if specs:
            return specs
        m = _UI_CONFIG_URL.search(probe.body[:200_000])   # UI defers to a config JSON
        if m:
            cfg_url = urljoin(url, m.group(1).decode("utf-8", "replace"))
            try:
                cp = await engine.fetch(cfg_url, keep_body=True)
            except Exception:
                cp = None
            if cp is not None and cp.ok and cp.body:
                specs = extract_ui_spec_urls(cp.body, cfg_url)
                if specs:
                    return specs
    return []


async def harvest(engine, base_url: str, on_progress=None) -> tuple[list[str], set[str]]:
    """Discover API documents and fold their union of declared endpoints.

    First reads the Swagger-UI's declared spec list — multi-document aware, so a
    .NET app that serves several specs under one UI (`/swagger/internal/…`,
    `/swagger/siscomexEvents/…`) gets ALL of them, not just the first — then falls
    back to the common default locations when the UI reveals nothing. Every spec
    that parses is folded, and each spec's own path is included so the disclosure
    is reported. Returns (spec_urls, paths)."""
    ui_specs = await _discover_ui_specs(engine, base_url)
    candidates = ui_specs or [urljoin(base_url, c.lstrip("/")) for c in SPEC_PATHS]
    endpoints: set[str] = set()
    found: list[str] = []
    for i, url in enumerate(candidates, 1):
        if on_progress is not None:
            on_progress(i, len(candidates))
        try:
            probe = await engine.fetch(url, keep_body=True)
        except Exception:
            continue
        if not (probe.ok and probe.status == 200 and probe.body):
            continue
        doc = _load(probe.body)
        if doc is None:
            continue
        eps = _endpoints_from_doc(doc, probe.content_type)
        if not eps:
            continue
        endpoints |= eps
        endpoints.add(urlparse(url).path)        # the document itself
        found.append(url)
        if not ui_specs:                         # default-path brute: first hit is enough
            break
    endpoints = set(sorted(endpoints)[:MAX_API_PATHS])
    return found, endpoints
