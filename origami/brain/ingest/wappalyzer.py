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

import asyncio
import json
import re
import string

_WORD = re.compile(r"[A-Za-z0-9_.\-/]{4,}")

# Actively-maintained Wappalyzer fingerprint fork (split a-z + _).
SOURCE_BASE = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies"
_SHARDS = ["_"] + list(string.ascii_lowercase)


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

    def _aslist(v):
        return [v] if isinstance(v, str) else (v if isinstance(v, list) else [])

    body_pats = _aslist(spec.get("html")) + _aslist(spec.get("scriptSrc"))
    body_pats += list((spec.get("meta") or {}).values())     # <meta> content
    for pat in body_pats:
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


async def fetch_db(base: str = SOURCE_BASE, timeout: float = 20.0) -> dict:
    """Download and merge all technology shards into one DB."""
    import httpx
    db: dict = {}
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        async def one(shard):
            try:
                r = await client.get(f"{base}/{shard}.json")
                if r.status_code == 200:
                    return json.loads(r.text)
            except (httpx.HTTPError, json.JSONDecodeError):
                pass
            return {}
        for part in await asyncio.gather(*(one(s) for s in _SHARDS)):
            db.update(part)
    return db


async def update_kb(dest_path, base: str = SOURCE_BASE) -> int:
    """Fetch the catalog, convert to KB rules, write YAML to dest_path. Returns
    the number of rules written (0 if the fetch failed)."""
    import yaml
    db = await fetch_db(base)
    rules = db_to_rules(db)
    if not rules:
        return 0
    from pathlib import Path
    Path(dest_path).write_text(yaml.safe_dump(rules, sort_keys=False, allow_unicode=True))
    return len(rules)
