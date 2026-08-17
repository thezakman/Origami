"""API version pivoting (§3.7 — adaptive discovery).

A confirmed versioned endpoint (`/api/v1/users`, `/v2/orders`) almost never lives
alone: the OTHER versions are usually still wired in the backend long after the UI
moved on — classic legacy-surface gold. When Origami confirms a path carrying a
`/vN/` segment, it **sweeps the whole low version band** (`v0`–`v9`), not just the
neighbours — an API on `/v1/` very often still answers `/v3/`, `/v5/`, … that no
wordlist would guess. A high current version extends the sweep upward around
itself too. Pure helper here; the scanner fold fires, dedupes and confirms them.
"""

from __future__ import annotations

import re

# A version segment: /v1, /v2/, /api/v3/…  (1–3 digits, bounded by / or end).
_VER = re.compile(r"/v(\d{1,3})(?=/|$)", re.I)

# How far to sweep by default: the full single-digit band, plus this many past a
# high current version (so /v12/ still probes v13…v15). v0..v9 is the floor.
_VER_FLOOR_HI = 9          # always sweep at least v0..v9
_VER_SPAN_UP = 3           # …and, when the current version is high, this many beyond it
_VER_CAP = 24              # hard cap on variants per endpoint (safety)


def has_version(path: str) -> bool:
    return _VER.search(path) is not None


def version_variants(path: str, lo: int = 0, hi: int = _VER_FLOOR_HI,
                     span: int = _VER_SPAN_UP, cap: int = _VER_CAP) -> list[str]:
    """Sibling paths across the whole low API-version band.

    For the first `/vN/` segment, generate `v{lo} … v{max(hi, N+span)}`, skipping
    the current version — e.g. `/v1/faq` → `/v0/faq`, `/v2/faq`, `/v3/faq`, …,
    `/v9/faq`. Sweeping the full band (not just the neighbours) is the point: an
    API on `/v1/` routinely still answers `/v3/`, `/v5/`, … that a wordlist never
    reaches. The fold dedupes already-confirmed versions against `seen_urls`, so
    the extra breadth costs a request only for versions not already found. Capped;
    empty when there's no version segment."""
    m = _VER.search(path)
    if not m:
        return []
    cur = int(m.group(1))
    top = min(999, max(hi, cur + span))       # v0..v9 floor; extend upward around a high current
    out: list[str] = []
    for v in range(max(0, lo), top + 1):
        if v == cur:
            continue
        out.append(path[:m.start()] + f"/v{v}" + path[m.end():])
        if len(out) >= cap:
            break
    return out
