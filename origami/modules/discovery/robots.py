"""Passive discovery from robots.txt and sitemap.xml (§3.7).

Free, zero-bruteforce intel: Disallow/Allow rules and sitemap <loc> entries
routinely point straight at the paths worth looking at. We harvest them as
high-priority seeds (origin "robots"). Wildcards are dropped — they're rules,
not resources.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from origami.core.scope import same_host

_RULE = re.compile(r"(?:dis)?allow\s*:\s*(\S+)", re.I)
_SITEMAP_REF = re.compile(r"sitemap\s*:\s*(\S+)", re.I)
_LOC = re.compile(rb"<loc>\s*([^<]+?)\s*</loc>", re.I)

MAX_SITEMAPS = 12        # cap fetched sitemaps (sitemapindex fan-out)
MAX_PATHS = 2000         # cap content paths harvested from sitemaps


def _same_host_path(raw: str, host: str) -> str | None:
    u = urlparse(raw)
    if u.netloc and u.netloc != host:
        return None
    path = (u.path or raw).split("?")[0].split("#")[0]
    bare = path.lstrip("/")
    if not bare or "*" in bare or "$" in bare or len(bare) > 120:
        return None
    return "/" + bare              # root-absolute (robots/sitemap are from root)


def parse_robots(body: bytes, base_url: str) -> set[str]:
    host = urlparse(base_url).netloc
    out: set[str] = set()
    for line in body.decode("latin-1").splitlines():
        line = line.strip()
        m = _RULE.match(line)
        if m:
            p = _same_host_path(m.group(1), host)
            if p:
                out.add(p)
        sm = _SITEMAP_REF.match(line)
        if sm:
            p = _same_host_path(sm.group(1), host)
            if p:
                out.add(p)
    return out


def parse_sitemap(body: bytes, base_url: str) -> set[str]:
    host = urlparse(base_url).netloc
    out: set[str] = set()
    for m in _LOC.findall(body):
        p = _same_host_path(m.decode("latin-1").strip(), host)
        if p:
            out.add(p)
    return out


def _sitemap_refs(body: bytes, base_url: str) -> list[str]:
    """`Sitemap:` lines from robots.txt → absolute URLs to fetch."""
    out = []
    for line in body.decode("latin-1").splitlines():
        m = _SITEMAP_REF.match(line.strip())
        if m:
            out.append(urljoin(base_url, m.group(1).strip()))
    return out


async def harvest(engine, base_url: str) -> set[str]:
    """robots.txt rules + sitemap content, following nested sitemapindex files.

    A `<sitemapindex>` lists child sitemaps (not content); we fetch them (capped)
    and parse their `<urlset>` <loc>s — big sites hide their real URL list behind
    one index. Same-host only; paths capped so a 50k-URL sitemap can't flood.
    """
    host = urlparse(base_url).netloc
    paths: set[str] = set()
    queue: list[str] = []

    rp = await engine.fetch(urljoin(base_url, "robots.txt"), keep_body=True)
    if rp.ok and rp.status == 200 and rp.body:
        paths |= parse_robots(rp.body, base_url)            # Disallow/Allow paths
        queue += _sitemap_refs(rp.body, base_url)           # follow declared sitemaps
    queue.append(urljoin(base_url, "sitemap.xml"))

    seen: set[str] = set()
    fetched = 0
    while queue and fetched < MAX_SITEMAPS and len(paths) < MAX_PATHS:
        url = queue.pop(0)
        if url in seen or not same_host(urlparse(url).netloc or host, host):
            continue
        seen.add(url)
        sp = await engine.fetch(url, keep_body=True)
        fetched += 1
        if not (sp.ok and sp.status == 200 and sp.body):
            continue
        is_index = b"<sitemapindex" in sp.body[:4096].lower()
        for loc in _LOC.findall(sp.body):
            raw = loc.decode("latin-1").strip()
            if is_index:                                    # child sitemap → fetch it
                nxt = urljoin(url, raw)
                if nxt not in seen and same_host(urlparse(nxt).netloc or host, host):
                    queue.append(nxt)
            else:
                p = _same_host_path(raw, host)
                if p:
                    paths.add(p)
                    if len(paths) >= MAX_PATHS:
                        break
    return paths
