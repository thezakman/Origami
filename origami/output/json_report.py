"""JSON report — machine-readable scan output."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime

from origami import __version__
from origami.core.scanner import ScanResult


def finding_record(f, host: str = "") -> dict:
    """Compact, machine-friendly record for one finding (JSONL streaming)."""
    rec = {
        "url": f.url,
        "status": f.status,
        "length": f.length,
        "content_type": f.content_type,
        "confidence": round(f.confidence, 2),
        "origin": f.origin,
        "tags": list(getattr(f, "tags", [])),
    }
    if getattr(f, "note", ""):
        rec["note"] = f.note
    if host:
        rec["host"] = host
    return rec


def to_dict(result: ScanResult) -> dict:
    p = result.profile
    return {
        "schema_version": 2,
        "tool_version": __version__,
        "exported_at": datetime.now(UTC).isoformat(),
        "completed": result.completed,
        "state": "failed" if result.error else "finished" if result.completed else "partial",
        "coverage": "unknown" if result.completed else "partial",
        "error": result.error,
        "pushbacks": result.pushbacks,
        "harvested_paths": sorted(result.harvested_paths),
        "edges": [list(edge) for edge in result.edges],
        "host": p.host,
        "base_url": p.base_url,
        "tech_scores": p.tech_scores,
        "confirmed_techs": p.confirmed_techs(),
        "wildcard": p.wildcard,
        "waf": p.waf,
        "case_sensitive": p.case_sensitive,
        "enabled_extensions": sorted(p.enabled_extensions),
        "parameters": sorted(p.parameters),
        "folds": sorted(result.folds),
        "requests_made": result.requests_made,
        "evidence": [asdict(e) for e in p.evidence],
        "findings": [asdict(f) for f in result.findings],
    }


def dumps(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False)
