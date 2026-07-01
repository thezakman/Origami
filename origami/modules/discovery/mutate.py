"""Naming-convention mutation (§3.7 — adaptive discovery).

A confirmed resource names its siblings by convention: `/user` implies `/users`,
`/report1` implies `/report2`, `data.json` implies `data.xml`. This turns each
confirmed finding into a small, high-signal set of sibling guesses — the ones a
developer's naming habit makes likely, not blind brute. Pure helper; the scanner
fold fires and confirms them.
"""

from __future__ import annotations

import re

_TRAILING_NUM = re.compile(r"(\d+)$")


def siblings(path: str, cap: int = 6) -> list[str]:
    """Convention-based sibling paths of a confirmed one (plural/singular toggle,
    trailing-number step, data-format twin). Root-relative in, same shape out;
    the original is never returned. Empty for a bare directory / root."""
    trimmed = path.rstrip("/")
    seg = trimmed.rsplit("/", 1)[-1]
    if not seg:
        return []
    prefix = trimmed[:len(trimmed) - len(seg)]
    stem, dot, ext = seg.partition(".")
    out: list[str] = []

    def add(name: str) -> None:
        out.append(prefix + name)

    # plural/singular toggle on the stem
    if stem.endswith("s") and len(stem) > 3:
        add(stem[:-1] + dot + ext)                 # users → user
    else:
        add(stem + "s" + dot + ext)                # user → users

    # trailing-number step (report1 → report2/report0; admin → admin2)
    m = _TRAILING_NUM.search(stem)
    if m:
        n = int(m.group(1))
        base = stem[:m.start()]
        add(f"{base}{n + 1}{dot}{ext}")
        if n > 0:
            add(f"{base}{n - 1}{dot}{ext}")
    elif stem:
        add(f"{stem}2{dot}{ext}")

    # data-format twin
    if ext in ("json", "xml", "csv"):
        for alt in ("json", "xml", "csv"):
            if alt != ext:
                add(f"{stem}.{alt}")

    # de-dup, drop the original, cap
    seen, ordered = {trimmed.lstrip("/")}, []
    for p in out:
        key = p.lstrip("/")
        if key and key not in seen:
            seen.add(key)
            ordered.append(p)
        if len(ordered) >= cap:
            break
    return ordered
