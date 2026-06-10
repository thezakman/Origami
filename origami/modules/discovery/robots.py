"""Passive discovery from robots.txt and sitemap.xml (§3.7).

Free, zero-bruteforce intel: Disallow/Allow rules and sitemap <loc> entries
routinely point straight at the paths worth looking at. We harvest them as
high-priority seeds (origin "robots"). Wildcards are dropped — they're rules,
not resources.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

_RULE = re.compile(r"(?:dis)?allow\s*:\s*(\S+)", re.I)
_SITEMAP_REF = re.compile(r"sitemap\s*:\s*(\S+)", re.I)
_LOC = re.compile(rb"<loc>\s*([^<]+?)\s*</loc>", re.I)


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


async def harvest(engine, base_url: str) -> set[str]:
    """Fetch robots.txt + sitemap.xml; return same-host candidate paths."""
    paths: set[str] = set()
    for fname, parser in (("robots.txt", parse_robots), ("sitemap.xml", parse_sitemap)):
        p = await engine.fetch(urljoin(base_url, fname), keep_body=True)
        if p.ok and p.status == 200 and p.body:
            paths |= parser(p.body, base_url)
    return paths
