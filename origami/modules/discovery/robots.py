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
# feed link forms: RSS <link>URL</link>, Atom <link href="URL"/>, <guid>URL</guid>
_LINK_TEXT = re.compile(rb"<link>\s*(https?://[^<\s]+?)\s*</link>", re.I)
_LINK_HREF = re.compile(rb"""<link[^>]+href\s*=\s*["'](https?://[^"']+)["']""", re.I)
_GUID = re.compile(rb"<guid[^>]*>\s*(https?://[^<\s]+?)\s*</guid>", re.I)

# Common feed / sitemap-variant locations to probe (beyond the declared ones).
FEED_PROBES = ("sitemap.xml", "sitemap_index.xml", "sitemap-index.xml",
               "news-sitemap.xml", "feed", "feed.xml", "rss", "rss.xml",
               "atom.xml", "feeds/posts/default")

MAX_SITEMAPS = 24        # cap fetched sitemaps/feeds (index fan-out + probes)
MAX_PATHS = 2000         # cap content paths harvested from sitemaps/feeds


def _content_urls(body: bytes) -> list[str]:
    """Content URLs from a sitemap (`<loc>`) or an RSS/Atom feed (`<link>`,
    `<guid>`) — the real article/page URLs, not the index structure."""
    out: list[str] = []
    for rx in (_LOC, _LINK_TEXT, _LINK_HREF, _GUID):
        out += [m.decode("latin-1").strip() for m in rx.findall(body)]
    return out


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
    """robots.txt rules + sitemap/feed content, following nested sitemapindex files.

    Probes the declared sitemaps plus common sitemap-variant and RSS/Atom feed
    locations; a `<sitemapindex>` lists child sitemaps (not content) which we
    fetch (capped) and parse. Same-host only; paths capped so a 50k-URL sitemap
    can't flood.
    """
    host = urlparse(base_url).netloc
    paths: set[str] = set()
    queue: list[str] = []

    rp = await engine.fetch(urljoin(base_url, "robots.txt"), keep_body=True)
    if rp.ok and rp.status == 200 and rp.body:
        paths |= parse_robots(rp.body, base_url)            # Disallow/Allow paths
        queue += _sitemap_refs(rp.body, base_url)           # follow declared sitemaps
    queue += [urljoin(base_url, p) for p in FEED_PROBES]    # + sitemap variants & feeds

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
        if b"<sitemapindex" in sp.body[:4096].lower():      # index → fetch child sitemaps
            for loc in _LOC.findall(sp.body):
                nxt = urljoin(url, loc.decode("latin-1").strip())
                if nxt not in seen and same_host(urlparse(nxt).netloc or host, host):
                    queue.append(nxt)
        else:                                               # sitemap/feed → content URLs
            for raw in _content_urls(sp.body):
                p = _same_host_path(raw, host)
                if p:
                    paths.add(p)
                    if len(paths) >= MAX_PATHS:
                        break
    return paths
