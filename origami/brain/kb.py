"""Knowledge base loader — reads the curated overlay (and, later, the ingested
rules layer) into typed rules the fingerprint engine applies.

MVP loads only `overlay.yaml`. v2 adds an ingested `rules.yaml`; the overlay
takes precedence on conflict (same tech name), per §3.9.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

OVERLAY_PATH = Path(__file__).with_name("overlay.yaml")


@dataclass(slots=True)
class Signal:
    type: str            # "header" | "cookie" | "body"
    match: str           # substring (case-insensitive); "" means presence-only
    weight: float
    name: str = ""       # header name, for type == "header"


@dataclass(slots=True)
class TechRule:
    tech: str
    signals: list[Signal] = field(default_factory=list)
    extensions: list[str] = field(default_factory=list)
    priority_paths: list[str] = field(default_factory=list)
    folds: list[str] = field(default_factory=list)


def load_kb(*paths: Path) -> list[TechRule]:
    """Load and merge KB files. Later files override earlier ones per tech."""
    if not paths:
        paths = (OVERLAY_PATH,)
    by_tech: dict[str, TechRule] = {}
    for p in paths:
        for raw in yaml.safe_load(p.read_text()) or []:
            rule = _parse_rule(raw)
            by_tech[rule.tech] = rule  # last wins
    return list(by_tech.values())


def _parse_rule(raw: dict) -> TechRule:
    oc = raw.get("on_confirm", {}) or {}
    return TechRule(
        tech=raw["tech"],
        signals=[
            Signal(
                type=s["type"],
                match=str(s.get("match", "")),
                weight=float(s["weight"]),
                name=str(s.get("name", "")),
            )
            for s in raw.get("signals", [])
        ],
        extensions=list(oc.get("extensions", [])),
        priority_paths=list(oc.get("priority_paths", [])),
        folds=list(oc.get("folds", [])),
    )
