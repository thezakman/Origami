"""Read-only inventory of captured cookie names and selected metadata."""

from __future__ import annotations

from origami.core.privacy import origin


def _origin_label(url: str) -> str | None:
    try:
        scheme, host, port = origin(url)
    except (ValueError, UnicodeError):
        return None
    host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{host}:{port}"


def summarize_cookies(result) -> dict:
    """Counts are captured headers/responses, never browser cookie-jar contents.

    Same name on different origins is not the same inventory entry. Domain/Path
    were not captured, so even one entry need not represent one stored cookie.
    """
    groups: dict[tuple[str | None, str], dict] = {}
    variants: dict[tuple[str | None, str], dict[tuple, dict]] = {}
    responses = fields = unparsed = 0
    for index, row in enumerate(result.cookie_observations):
        count = row["response_count"]
        responses += count
        fields += count * row["set_cookie_header_count"]
        unparsed += count * row["unparsed_header_count"]
        label = _origin_label(row["url"])
        counted = set()
        for cookie in row["cookies"]:
            key = label, cookie["name"]
            if key not in groups:
                groups[key] = {"origin": label, "name": cookie["name"],
                               "responses_with_name": 0, "statuses": set(), "observation_indices": set()}
                variants[key] = {}
            group = groups[key]
            if key not in counted:
                group["responses_with_name"] += count
                counted.add(key)
            group["statuses"].add(row["status"])
            group["observation_indices"].add(index)
            signature = cookie["secure"], cookie["httponly"], cookie["samesite"]
            if signature not in variants[key]:
                variants[key][signature] = {"secure": signature[0], "httponly": signature[1],
                                           "samesite": signature[2], "header_occurrence_count": 0,
                                           "observation_indices": set()}
            variant = variants[key][signature]
            variant["header_occurrence_count"] += count
            variant["observation_indices"].add(index)
    inventory = []
    for key in sorted(groups, key=lambda item: (item[0] or "", item[1])):
        group = groups[key]
        group["statuses"] = sorted(group["statuses"])
        group["observation_indices"] = sorted(group["observation_indices"])
        group["metadata_variants"] = []
        for signature in sorted(variants[key], key=repr):
            variant = variants[key][signature]
            variant["observation_indices"] = sorted(variant["observation_indices"])
            group["metadata_variants"].append(variant)
        group["metadata_varies"] = len(group["metadata_variants"]) > 1
        inventory.append(group)
    return {"availability": "current_process_headers" if result.cookie_observations_tracked else "unavailable",
            "interpretation": "header_inventory_not_cookie_jar_or_security_verdict",
            "record_count": len(result.cookie_observations),
            "responses_with_set_cookie": responses, "set_cookie_field_count": fields,
            "unparsed_field_count": unparsed,
            "distinct_name_count": len({entry["name"] for entry in inventory}),
            "origin_name_count": len(inventory), "inventory": inventory}
