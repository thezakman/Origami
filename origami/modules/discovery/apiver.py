"""API version pivoting (§3.7 — adaptive discovery).

A confirmed versioned endpoint (`/api/v1/users`, `/v2/orders`) almost never lives
alone: the previous and next versions are usually still wired in the backend long
after the UI moved on — classic legacy-surface gold. When Origami confirms a path
carrying a `/vN/` segment, it pivots to the adjacent versions. Pure helper here;
the scanner fold fires and confirms them.
"""

from __future__ import annotations

import re

# A version segment: /v1, /v2/, /api/v3/…  (1–3 digits, bounded by / or end).
_VER = re.compile(r"/v(\d{1,3})(?=/|$)", re.I)


def has_version(path: str) -> bool:
    return _VER.search(path) is not None


def version_variants(path: str, span: int = 2, cap: int = 6) -> list[str]:
    """Sibling paths at adjacent API versions.

    For the first `/vN/` segment, generate `v(N-1) … v(max(N+span,3))` (plus `v0`),
    skipping the current version — e.g. `/api/v1/users` → `/api/v0/users`,
    `/api/v2/users`, `/api/v3/users`. Capped; empty when there's no version."""
    m = _VER.search(path)
    if not m:
        return []
    cur = int(m.group(1))
    out: list[str] = []
    for v in range(max(0, cur - 1), max(cur + span, 3) + 1):
        if v == cur:
            continue
        out.append(path[:m.start()] + f"/v{v}" + path[m.end():])
        if len(out) >= cap:
            break
    return out
