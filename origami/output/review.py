"""Bounded, read-only review of exported evidence. No network or database access."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

MAX_REPORT_BYTES = 32 * 1024 * 1024


class InvalidReport(ValueError):
    """A safe diagnostic that never includes source values or parser excerpts."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidReport(message)


def _object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise InvalidReport("non-finite JSON number")


def _http_url(value: object) -> bool:
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value):
        return False
    try:
        parsed = urlsplit(value)
        return bool(parsed.scheme in ("http", "https") and parsed.hostname
                    and (parsed.port is None or 0 < parsed.port < 65536))
    except ValueError:
        return False


def review_report(path: Path) -> dict:
    """Summarize exact input bytes without reproducing URLs, credentials or commands.

    A SHA-256 identifies the reviewed file; it is not proof of authenticity.
    Findings remain observations, irrespective of their heuristic confidence.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode), "report must be a regular file")
        _require(info.st_size <= MAX_REPORT_BYTES, "report exceeds 32 MiB limit")
        raw = stream.read(MAX_REPORT_BYTES + 1)
    _require(len(raw) <= MAX_REPORT_BYTES, "report exceeds 32 MiB limit")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                          parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, InvalidReport):
            raise
        raise InvalidReport("invalid UTF-8 JSON report") from None
    _require(isinstance(data, dict), "report must be a JSON object")
    schema = data.get("schema_version")
    _require("schema_version" not in data or (type(schema) is int and schema == 2),
             "unsupported report schema")
    _require(_http_url(data.get("base_url")), "missing or invalid base_url")
    findings = data.get("findings")
    _require(isinstance(findings, list), "findings must be an array")
    requests = data.get("requests_made")
    _require(type(requests) is int and requests >= 0, "invalid requests_made")
    warnings = []
    if schema is None:
        state, coverage = "unknown", "unknown"
        warnings.append("Legacy report: execution state and coverage cannot be established.")
    else:
        completed, error = data.get("completed"), data.get("error")
        _require(type(completed) is bool and isinstance(error, str),
                 "invalid completion metadata")
        state = data.get("state")
        expected = "failed" if error else "finished" if completed else "partial"
        _require(state == expected, "inconsistent execution state")
        coverage = data.get("coverage")
        _require(coverage == ("unknown" if completed else "partial"),
                 "unsupported or inconsistent coverage metadata")
    statuses: Counter = Counter()
    identities: set[tuple] = set()
    duplicates = notes = commands = empty = 0
    for index, finding in enumerate(findings):
        label = f"finding[{index}]"
        _require(isinstance(finding, dict), f"{label} must be an object")
        _require(_http_url(finding.get("url")), f"{label} has an invalid URL")
        status, length = finding.get("status"), finding.get("length")
        _require(type(status) is int and 100 <= status <= 599, f"{label} has invalid status")
        _require(type(length) is int and length >= 0, f"{label} has invalid length")
        confidence = finding.get("confidence")
        _require(type(confidence) in (int, float) and 0 <= confidence <= 1
                 and math.isfinite(confidence), f"{label} has invalid confidence")
        for field in ("content_type", "origin", "note", "repro"):
            _require(isinstance(finding.get(field, ""), str), f"{label} has invalid {field}")
        tags = finding.get("tags", [])
        _require(isinstance(tags, list) and all(isinstance(tag, str) for tag in tags),
                 f"{label} has invalid tags")
        # Exact URL/status/reproduction duplicates are counted, never removed.
        identity = (finding["url"], status, finding.get("repro", ""))
        duplicates += identity in identities
        identities.add(identity)
        statuses[str(status)] += 1
        notes += bool(finding.get("note", "").strip())
        commands += bool(finding.get("repro", "").strip())
        empty += length == 0
    if state != "finished":
        warnings.append("Execution is incomplete, failed or unknown; absence is not evidence of remediation.")
    if duplicates:
        warnings.append("Repeated URL/status/reproduction records exist; all source observations were retained.")
    warnings.append("Heuristic confidence and HTTP success do not establish a confirmed vulnerability.")
    warnings.append("Coverage is not established; this review validates summary fields, not every source field.")
    return {
        "review_schema_version": 1,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_bytes": len(raw),
        "source_schema_version": schema,
        "state": state,
        "coverage": coverage,
        "requests_made": requests,
        "observations": len(findings),
        "status_counts": dict(sorted(statuses.items())),
        "with_notes": notes,
        "without_notes": len(findings) - notes,
        "with_reproduction_text": commands,
        "empty_bodies": empty,
        "repeated_observations": duplicates,
        "warnings": warnings,
    }
