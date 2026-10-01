"""Terminal-only grouping; never removes observations from scanner or exports."""

from __future__ import annotations

import re
from dataclasses import replace

from origami.core.response_classifier import Finding
from origami.core.response_signature import presentation_key

_GROUP_NOTE = re.compile(
    r" ?presentation group: \+\d+ paths (?:"
    r"with similar body fingerprints \(soft-200 wall heuristic; body equality not established\)"
    r"|sharing status \d+ / length \d+B; body equality and resource existence not established)"
)


class ResponsePreview:
    def __init__(self) -> None:
        self.seen: set[tuple] = set()
        self.hidden = 0
        self.notices: set[int] = set()

    def accept(self, finding) -> bool:
        key = presentation_key(finding)
        if key is None:
            return True
        if key in self.seen:
            self.hidden += 1
            return False
        self.seen.add(key)
        return True

    def summary(self) -> str:
        return (f"{self.hidden} repeated response observations grouped in this terminal view; "
                "all accepted URLs retained in JSON/HTML report events." if self.hidden else "")


def terminal_rows(findings) -> tuple[list, str]:
    preview = ResponsePreview()
    return [finding for finding in findings if preview.accept(finding)], preview.summary()


def terminal_findings(result) -> list:
    """Recover full-metadata accepted rows for terminal display after legacy collapse.

    This is a copy for presentation only. Discovery keeps its existing findings
    view and exports keep the immutable event snapshots. Later enrichments on
    surviving findings still take precedence over their emission-time copies.
    """
    modern = {row["url"]: Finding(**row) for row in result.reported_observations
              if row.get("body_digest")}
    if not modern:
        return result.findings
    for finding in result.findings:
        if finding.url in modern:
            # A legacy size/fingerprint grouping note must not obscure distinctions
            # recovered from retained events. Preserve later tags, repro and evidence.
            modern[finding.url] = replace(finding, note=_GROUP_NOTE.sub("", finding.note).strip())
    return list(modern.values()) + [finding for finding in result.findings
                                   if finding.url not in modern]
