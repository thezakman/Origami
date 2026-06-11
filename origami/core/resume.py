"""Scan checkpoint / resume.

Serializes the loop-entry state (the fingerprinted TargetProfile, the findings
so far, the candidate inputs, and the pending directory queue) to a JSON file.
A scan checkpoints after every prefix, so an interrupted run — Ctrl-C, `q`, or
the request cap — can be continued with `--resume` instead of re-fingerprinting
and re-walking everything already covered. The file is removed on clean finish.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from origami.core.evidence import ContextBaseline, Evidence, TargetProfile
from origami.core.response_classifier import Finding

RESUME_DIR = Path.home() / ".origami" / "resume"


def path_for(base_url: str) -> Path:
    slug = re.sub(r"[^\w.-]", "_", (urlparse(base_url).netloc + urlparse(base_url).path).strip("/"))
    return RESUME_DIR / f"{slug or 'root'}.json"


# ---- (de)serialization --------------------------------------------------------

def _cb_to_dict(cb: ContextBaseline) -> dict:
    return {"prefix": cb.prefix, "ext_class": cb.ext_class, "status": cb.status,
            "simhashes": cb.simhashes, "length_lo": cb.length_lo, "length_hi": cb.length_hi,
            "content_type": cb.content_type, "redirect_to": cb.redirect_to,
            "is_soft404": cb.is_soft404, "samples": cb.samples,
            "soft_signatures": [list(s) for s in cb.soft_signatures]}


def _cb_from_dict(d: dict) -> ContextBaseline:
    cb = ContextBaseline(prefix=d["prefix"], ext_class=d["ext_class"], status=d["status"])
    cb.simhashes = d.get("simhashes", [])
    cb.length_lo, cb.length_hi = d.get("length_lo", 0), d.get("length_hi", 0)
    cb.content_type = d.get("content_type", "")
    cb.redirect_to = d.get("redirect_to", "")
    cb.is_soft404 = d.get("is_soft404", False)
    cb.samples = d.get("samples", 0)
    cb.soft_signatures = [tuple(s) for s in d.get("soft_signatures", [])]
    return cb


def _profile_to_dict(p: TargetProfile) -> dict:
    return {
        "host": p.host, "base_url": p.base_url, "tech_scores": p.tech_scores,
        "case_sensitive": p.case_sensitive, "wildcard": p.wildcard, "waf": p.waf,
        "enabled_extensions": sorted(p.enabled_extensions),
        "parameters": sorted(p.parameters),
        "baseline": {k: _cb_to_dict(v) for k, v in p.baseline.items()},
        "evidence": [{"source": e.source, "tech": e.tech, "detail": e.detail,
                      "weight": e.weight, "path_prefix": e.path_prefix} for e in p.evidence],
    }


def _profile_from_dict(d: dict) -> TargetProfile:
    p = TargetProfile(host=d["host"], base_url=d["base_url"])
    p.tech_scores = d.get("tech_scores", {})
    p.case_sensitive = d.get("case_sensitive")
    p.wildcard = d.get("wildcard", False)
    p.waf = d.get("waf", "")
    p.enabled_extensions = set(d.get("enabled_extensions", []))
    p.parameters = set(d.get("parameters", []))
    p.baseline = {k: _cb_from_dict(v) for k, v in d.get("baseline", {}).items()}
    p.evidence = [Evidence(**e) for e in d.get("evidence", [])]
    return p


def _finding_to_dict(f: Finding) -> dict:
    return {"url": f.url, "status": f.status, "length": f.length,
            "content_type": f.content_type, "confidence": f.confidence,
            "origin": f.origin, "note": f.note, "tags": f.tags, "simhash": f.simhash}


def _finding_from_dict(d: dict) -> Finding:
    return Finding(d["url"], d["status"], d["length"], d["content_type"], d["confidence"],
                   d["origin"], d.get("note", ""), d.get("tags", []), d.get("simhash", 0))


# ---- save / load --------------------------------------------------------------

def save(path: Path, *, profile, findings, requests_made, folds, words, exts,
         priority_paths, root_seeds, base_prefix, queue, scanned, start_offset=0,
         front_cands=None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "version": 1,
        "profile": _profile_to_dict(profile),
        "findings": [_finding_to_dict(f) for f in findings],
        "requests_made": requests_made,
        "folds": sorted(folds),
        "words": words, "exts": sorted(exts), "priority_paths": priority_paths,
        "root_seeds": [list(s) for s in root_seeds],
        "base_prefix": base_prefix,
        "queue": [list(q) for q in queue],
        "scanned": sorted(scanned),
        "start_offset": start_offset,        # candidate index to resume the front prefix from
        "front_cands": [list(c) for c in (front_cands or [])],  # exact ordered (path,origin) of the interrupted prefix
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(path)        # atomic


def load(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        d = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if d.get("version") != 1:        # forward-compat: don't misread a newer format
        return None
    d["profile"] = _profile_from_dict(d["profile"])
    d["findings"] = [_finding_from_dict(f) for f in d["findings"]]
    d["root_seeds"] = [tuple(s) for s in d["root_seeds"]]
    d["queue"] = [tuple(q) for q in d["queue"]]
    d["exts"] = set(d["exts"])
    d["front_cands"] = [tuple(c) for c in d.get("front_cands", [])]
    return d


def clear(path: Path) -> None:
    path.unlink(missing_ok=True)
