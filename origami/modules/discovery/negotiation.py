"""Apache mod_negotiation (MultiViews) filename disclosure.

With MultiViews enabled, a request for an extensionless name Apache can't resolve
returns **300 Multiple Choices** whose body LISTS the real matching files:

    /script   → /script.php
    /composer → /composer.json  /composer.lock

That is both an information disclosure worth reporting AND a reliable filename-
enumeration primitive — it hands over the *true* extension (`.php5`, `.inc`,
`.phtml`…) without any guessing. This module detects the response and mines the
`<a href>` choices as same-host seed paths. Pure/parser-only (no core imports).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

_HREF = re.compile(rb"""<a\s+href\s*=\s*["']([^"'>\s]+)["']""", re.I)


def is_multiple_choices(body: bytes) -> bool:
    """An Apache mod_negotiation 300 page (title + the tell-tale phrasing)."""
    head = (body or b"")[:2048].lower()
    return b"multiple choices" in head and (b"available documents" in head
                                            or b"we found documents" in head
                                            or b"could not be found" in head)


def parse_choices(body: bytes, base_url: str) -> set[str]:
    """The alternative documents Apache offers → root-absolute, same-host FILE paths."""
    host = urlparse(base_url).netloc
    out: set[str] = set()
    for m in _HREF.finditer((body or b"")[:8192]):
        href = m.group(1).decode("latin-1", "replace").strip()
        if not href or href.startswith(("#", "mailto:", "javascript:")):
            continue
        pu = urlparse(urljoin(base_url, href))
        if pu.netloc and pu.netloc != host:                # off-host link → skip
            continue
        p = pu.path.split("?")[0].split("#")[0]
        if p and p != "/" and not p.endswith("/"):          # the choices are files
            out.add(p if p.startswith("/") else "/" + p)
    return out
