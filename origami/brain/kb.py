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
RULES_PATH = Path(__file__).with_name("rules.yaml")        # ingested layer (origami --update)


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
    """Load and merge KB layers, keyed by lowercased tech name.

    Default order: ingested `rules.yaml` (if present) first, then the curated
    `overlay.yaml`. Signals from both are UNIONed; `on_confirm` (extensions /
    priority-paths / folds) is taken from the overlay when it has the tech — so
    ingestion broadens *detection* while the overlay keeps the *folds* and wins.
    """
    if not paths:
        paths = tuple(p for p in (RULES_PATH, OVERLAY_PATH) if p.exists())

    by_tech: dict[str, TechRule] = {}
    for p in paths:
        for raw in yaml.safe_load(p.read_text()) or []:
            rule = _parse_rule(raw)
            cur = by_tech.get(rule.tech)
            if cur is None:
                by_tech[rule.tech] = rule
            else:
                cur.signals.extend(rule.signals)          # union signals
                # a later layer's folds/extensions win when it has them
                if rule.extensions:
                    cur.extensions = rule.extensions
                if rule.priority_paths:
                    cur.priority_paths = rule.priority_paths
                if rule.folds:
                    cur.folds = rule.folds
    return list(by_tech.values())


def _parse_rule(raw: dict) -> TechRule:
    oc = raw.get("on_confirm", {}) or {}
    return TechRule(
        tech=str(raw["tech"]).lower().strip(),
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
