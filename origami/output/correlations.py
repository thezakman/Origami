"""Read-only correlations of existing report evidence; no probes or scan actions."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from hashlib import sha256

from origami.core.evidence import Evidence
from origami.core.response_classifier import Finding
from origami.core.response_signature import presentation_key


def fingerprint_correlations(profile) -> list[dict]:
    """Track distinct channels per exact prefix without promoting heuristic scores.

    Repeated signals remain traceable to raw evidence but cannot inflate channel
    counts. Different channels are not claimed to be statistically independent.
    """
    buckets: dict[tuple[str, str], list[tuple[int, Evidence]]] = defaultdict(list)
    for index, evidence in enumerate(profile.evidence):
        buckets[(evidence.tech, evidence.path_prefix)].append((index, evidence))
    output = []
    for (tech, prefix), entries in buckets.items():
        sources = {evidence.source for _, evidence in entries}
        distinct = {(evidence.source, evidence.detail) for _, evidence in entries}
        output.append({
            "tech": tech, "path_prefix": prefix,
            "host_score_heuristic": profile.tech_scores.get(tech),
            "signal_types": sorted(sources),
            "distinct_signal_count": len(distinct),
            "evidence_count": len(entries),
            "evidence_indices": [index for index, _ in entries],
            "support": "multiple_signal_types" if len(sources) > 1 else "single_signal_type",
            "independence": "not_established",
        })
    represented = {entry["tech"] for entry in output}
    for tech, score in profile.tech_scores.items():
        if tech not in represented:
            output.append({
                "tech": tech, "path_prefix": None, "host_score_heuristic": score,
                "signal_types": [], "distinct_signal_count": 0, "evidence_count": 0,
                "evidence_indices": [], "support": "provenance_unavailable",
                "independence": "not_established",
            })
    return output


def response_correlations(result) -> list[dict]:
    """Explain terminal groups with URLs and references to retained records."""
    records = [("reported_observations", index, row)
               for index, row in enumerate(result.reported_observations)]
    observed = {row["url"] for _, _, row in records}
    records.extend(("findings", index, asdict(finding))
                   for index, finding in enumerate(result.findings) if finding.url not in observed)
    groups: dict[tuple, list] = defaultdict(list)
    for collection, index, row in records:
        if not row.get("body_digest"):
            continue
        finding = Finding(**row)
        key = presentation_key(finding)
        if key is not None:
            groups[key].append((collection, index, finding))
    output = []
    for key, entries in groups.items():
        if len(entries) < 2:
            continue
        first = entries[0][2]
        output.append({
            "id": sha256(repr(key).encode("utf-8")).hexdigest()[:16],
            "status": first.status,
            "basis": ("same_redirect_signature_and_destination_masked_body"
                      if 300 <= first.status < 400 else
                      "same_captured_body_status_type_semantic_headers"),
            "raw_body_equal": len({finding.body_digest for _, _, finding in entries}) == 1,
            "count": len(entries),
            "urls": [finding.url for _, _, finding in entries],
            "evidence_refs": [{"collection": collection, "index": index}
                              for collection, index, _ in entries],
            "interpretation": "response_similarity_only_not_resource_or_vulnerability_proof",
        })
    return output
