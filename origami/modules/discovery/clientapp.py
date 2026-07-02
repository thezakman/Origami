"""Client-app recon — service worker + web app manifest (§3.7 recon).

Two more of the app's own declarations, both high-yield for paths:
  * the **service worker** (`/sw.js`, `/service-worker.js`…) usually embeds a
    Workbox/precache manifest listing EVERY asset and route the app caches — a
    goldmine the wordlist would never guess;
  * the **web app manifest** (`/manifest.json`, `*.webmanifest`) declares
    `start_url`, `scope`, icon/shortcut/screenshot paths.

Both feed the dynamic wordlist as seeds (origin "js"). The SW is JavaScript, so
we reuse js_parser.extract_paths on it.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse

from origami.modules.discovery.js_parser import extract_paths

SW_PATHS = (
    "/service-worker.js", "/sw.js", "/serviceworker.js",
    "/firebase-messaging-sw.js", "/ngsw-worker.js", "/workbox-sw.js",
)
MANIFEST_PATHS = (
    "/manifest.json", "/manifest.webmanifest", "/site.webmanifest",
    "/app.webmanifest", "/manifest",
)

# (array key, field holding a URL) inside a web app manifest.
_MANIFEST_ARRAYS = (("icons", "src"), ("shortcuts", "url"),
                    ("screenshots", "src"), ("related_applications", "url"))


def _same_host_path(url: str, host: str) -> str | None:
    if not isinstance(url, str):
        return None
    if url.startswith(("http://", "https://", "//")):   # absolute OR protocol-relative
        u = urlparse(url)                                # urlparse("//evil/x") → netloc=evil
        if u.netloc and u.netloc != host:
            return None                                  # off-host (incl. //evil.com) → drop
        url = u.path
    url = url.split("?")[0].split("#")[0]
    return url if url.startswith("/") and not url.startswith("//") and url != "/" else None


def manifest_paths(doc: dict, base_url: str) -> set[str]:
    """Web app manifest → same-host paths (start_url, scope, icons, shortcuts…)."""
    host = urlparse(base_url).netloc
    out: set[str] = set()
    for key in ("start_url", "scope"):
        p = _same_host_path(doc.get(key, ""), host)
        if p:
            out.add(p)
    for arr_key, field in _MANIFEST_ARRAYS:
        for item in doc.get(arr_key) or []:
            if isinstance(item, dict):
                p = _same_host_path(item.get(field, ""), host)
                if p:
                    out.add(p)
    return out


async def harvest(engine, base_url: str) -> tuple[set[str], list[tuple[str, str]]]:
    """Probe service workers + manifests; return (paths, provenance edges)."""
    paths: set[str] = set()
    edges: list[tuple[str, str]] = []

    for cand in MANIFEST_PATHS:
        p = await engine.fetch(urljoin(base_url, cand.lstrip("/")), keep_body=True)
        if not (p.ok and p.status == 200 and p.body):
            continue
        try:
            doc = json.loads(p.body)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(doc, dict):
            mp = manifest_paths(doc, base_url)
            paths.add(cand)
            paths |= mp
            edges += [(cand, x) for x in sorted(mp)]
            break                                   # one manifest is enough

    for cand in SW_PATHS:
        p = await engine.fetch(urljoin(base_url, cand.lstrip("/")), keep_body=True)
        if not (p.ok and p.status == 200 and p.body):
            continue
        ct = p.content_type
        if ct:
            if "javascript" not in ct and "ecmascript" not in ct:
                continue                            # ct set but not JS → not a real SW
        elif p.body[:64].lstrip()[:1] == b"<":      # no ct + HTML-shaped → catch-all, skip
            continue                                # (a real SW without a ct is still parsed)
        sw = extract_paths(p.body, base_url)
        paths.add(cand)
        paths |= sw
        edges += [(cand, x) for x in sorted(sw)]
    return paths, edges
