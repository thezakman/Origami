"""Wappalyzer-fingerprint ingestion → Origami KB rules.

Converts the community Wappalyzer fingerprint database (the active OSS fork at
`tunetheweb/wappalyzer`, JSON `technologies/*.json`) into our overlay-format
rules, so fingerprint coverage comes from a maintained catalog instead of
hand-written signatures. Detection signals only — the curated overlay keeps the
folds (extensions/priority-paths/shortscan), and wins on conflict.

Wappalyzer patterns look like `regex\\;confidence:50\\;version:\\1`; we strip the
annotations and reduce the regex to a usable literal substring for our
substring matcher (skipping signals with no usable literal).
"""

from __future__ import annotations

import re

_WORD = re.compile(r"[A-Za-z0-9_.\-/]{4,}")


def literalize(pattern: str) -> str:
    """Best literal substring from a Wappalyzer regex pattern, or '' if none."""
    pat = str(pattern).split("\\;")[0]                 # drop \;confidence/version
    pat = pat.replace("\\/", "/").replace("\\.", ".").replace("\\-", "-")
    # longest alnum-ish run that isn't a regex quantifier soup
    cands = [m.group(0) for m in _WORD.finditer(pat)]
    cands = [c for c in cands if not any(ch in c for ch in "()[]{}|?*+^$")]
    return max(cands, key=len) if cands else ""


def tech_to_rule(name: str, spec: dict) -> dict | None:
    """One Wappalyzer tech → an overlay-format rule dict (detection only)."""
    signals: list[dict] = []

    for hname, pat in (spec.get("headers") or {}).items():
        lit = literalize(pat)
        signals.append({"type": "header", "name": hname.lower(),
                        "match": lit, "weight": 50})

    for cname in (spec.get("cookies") or {}):
        signals.append({"type": "cookie", "match": cname, "weight": 50})

    body = spec.get("html") or []
    if isinstance(body, str):
        body = [body]
    for pat in body + (spec.get("scriptSrc") if isinstance(spec.get("scriptSrc"), list) else []):
        lit = literalize(pat)
        if len(lit) >= 5:
            signals.append({"type": "body", "match": lit, "weight": 30})

    signals = [s for s in signals if s.get("match") or s["type"] == "cookie"]
    if not signals:
        return None
    return {"tech": name.lower().strip(), "signals": signals}


def db_to_rules(db: dict) -> list[dict]:
    """A Wappalyzer DB (`{TechName: spec, ...}`) → list of rule dicts."""
    out = []
    for name, spec in db.items():
        if not isinstance(spec, dict):
            continue
        rule = tech_to_rule(name, spec)
        if rule:
            out.append(rule)
    return out
