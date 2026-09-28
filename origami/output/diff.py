"""Conservative comparison of observed URLs; absence is not removal proof."""

from __future__ import annotations

from collections import defaultdict


def compute(prior: dict, findings) -> dict:
    """Compare exact URLs, retaining query/origin identity and ambiguous responses.

    Prior values are (status, length), or None when observations conflict.
    Authentication, filters and coverage are not known to be equivalent.
    """
    current: dict[str, set[tuple[int, int]]] = defaultdict(set)
    for finding in findings:
        current[finding.url].add((finding.status, finding.length))
    result: dict[str, list] = {key: [] for key in ("new", "unobserved", "changed", "ambiguous")}
    for url in sorted(set(prior) | set(current)):
        old = prior.get(url)
        values = current.get(url, set())
        if (url in prior and old is None) or len(values) > 1:
            result["ambiguous"].append({"path": url})
        elif not values:
            assert old is not None
            result["unobserved"].append({"path": url, "was_status": old[0], "was_length": old[1]})
        else:
            status, length = next(iter(values))
            if url not in prior:
                result["new"].append({"path": url, "status": status, "length": length})
            elif old != (status, length):
                assert old is not None
                result["changed"].append({"path": url, "status": status, "length": length,
                                          "was_status": old[0], "was_length": old[1]})
    return result


def is_empty(d: dict) -> bool:
    return not any(d.values())


def render(d: dict, host: str, prior_ts: float | None = None) -> str:
    import datetime
    since = ""
    if prior_ts:
        try:
            since = " since " + datetime.datetime.fromtimestamp(prior_ts).strftime("%Y-%m-%d %H:%M")
        except (ValueError, OSError, OverflowError):
            pass
    lines = [f"diff [{host}]{since}: {len(d['new'])} newly observed; "
             f"{len(d['unobserved'])} not observed; {len(d['changed'])} changed; "
             f"{len(d['ambiguous'])} ambiguous"]
    if is_empty(d):
        lines.append("  no change in recorded observations")
    for entry in d["new"]:
        lines.append(f"  + {entry['status']}  {entry['path']}  ({entry['length']}B)")
    for entry in d["changed"]:
        lines.append(f"  ~ {entry['was_status']}→{entry['status']}  {entry['path']}  "
                     f"({entry['was_length']}→{entry['length']}B)")
    for entry in d["unobserved"]:
        lines.append(f"  ? {entry['path']}  (not observed; removal not established)")
    for entry in d["ambiguous"]:
        lines.append(f"  ? {entry['path']}  (conflicting observations; comparison withheld)")
    lines.append("  Context/coverage equivalence is unknown: absence does not prove remediation, "
                 "and a status change does not prove an authorization change.")
    return "\n".join(lines)
