"""Bounded, offline reference chains from recorded edges, never scan actions."""

from __future__ import annotations

from collections import defaultdict, deque
from urllib.parse import urlsplit


def _url(reference: str, base_url: str) -> str | None:
    """Keep query, case, ports and encoded paths; never guess relative context.

    Legacy graph edges lack the document base for relative references. Fragments
    are not HTTP request identity; their original spelling remains in raw edges.
    """
    if not reference or any(c.isspace() or ord(c) < 32 for c in reference):
        return None
    try:
        base = urlsplit(base_url)
        if reference.startswith("//"):
            candidate = f"{base.scheme}:{reference}"
        elif reference.startswith("/"):
            candidate = f"{base.scheme}://{base.netloc}{reference}"
        else:
            candidate = reference
        parsed = urlsplit(candidate)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            return None
        _ = parsed.port  # invalid ports must not break report export
    except ValueError:
        return None
    return candidate.partition("#")[0]


def _origin(url: str) -> tuple:
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def reference_provenance(result, *, max_edges: int = 4000, max_chains: int = 200,
                         max_hops: int = 4) -> dict:
    """Retain indexed edges and one bounded shortest example per reached node.

    A reported event is only an accepted observation, not existence/impact proof.
    Existing collectors may already have stripped query strings from edges; no
    query-bearing finding is attached by a path-only guess.
    """
    if min(max_edges, max_chains, max_hops) < 1:
        raise ValueError("provenance limits must be positive")
    base = result.profile.base_url
    base_url = _url(base, base)
    adjacency: dict[str, dict[str, list[int]]] = defaultdict(dict)
    incoming: set[str] = set()
    urls: set[str] = set()
    unresolved = []
    for index, (source, destination) in enumerate(result.edges[:max_edges]):
        src, dst = _url(source, base), _url(destination, base)
        if src is None or dst is None:
            unresolved.append(index)
            continue
        adjacency[src].setdefault(dst, []).append(index)
        incoming.add(dst)
        urls.update((src, dst))

    events: dict[str, list[dict]] = defaultdict(list)
    observed = set()
    for index, row in enumerate(result.reported_observations):
        observed.add(row["url"])
        url = _url(row["url"], base)
        if url in urls:
            events[url].append({"collection": "reported_observations", "index": index,
                                "status": row["status"]})
    for index, finding in enumerate(result.findings):
        url = _url(finding.url, base)
        if finding.url not in observed and url in urls:
            events[url].append({"collection": "findings", "index": index,
                                "status": finding.status})

    starts = sorted(urls - incoming)
    anchor_basis = "zero_incoming_recorded_edges"
    if urls and not starts:
        starts = [min(urls)]
        anchor_basis = "cycle_fallback_not_document_root"
    queue: deque[tuple[str, list[str], list[list[int]]]] = deque((start, [start], []) for start in starts)
    visited = set(starts)
    chains: list[dict] = []
    while queue:
        current, path, edge_refs = queue.popleft()
        if len(edge_refs) >= max_hops:
            continue
        for destination in sorted(adjacency.get(current, {})):
            if destination in visited:
                continue
            visited.add(destination)
            extended = edge_refs + [adjacency[current][destination]]
            route = path + [destination]
            if len(chains) < max_chains:
                chains.append({"urls": route, "edge_indices": extended,
                               "endpoint_observation_refs": events.get(destination, [])})
            queue.append((destination, route, extended))
    nodes = [{"url": url, "same_origin_as_base": _origin(url) == _origin(base_url) if base_url else None,
              "observation_state": "accepted_report_event" if events.get(url) else "reference_only",
              "observation_refs": events.get(url, [])} for url in sorted(urls)]
    edges = [{"source": source, "destination": destination, "edge_indices": indices}
             for source in sorted(adjacency)
             for destination, indices in sorted(adjacency[source].items())]
    return {
        "availability": "recorded_edges" if result.edges else "unavailable",
        "coverage": "recorded_edges_only_not_all_requests_or_references",
        "interpretation": "reference_provenance_not_execution_or_exploitation",
        "identity": "full_recorded_http_url_without_fragment_no_path_only_event_matching",
        "limits": {"edges": max_edges, "chain_examples": max_chains, "hops": max_hops},
        "unprocessed_edge_count": max(0, len(result.edges) - max_edges),
        "unresolved_edge_indices": unresolved,
        "nodes": nodes, "edges": edges, "chain_examples": chains,
        "anchor_basis": anchor_basis,
        "nodes_without_chain_example": len(urls - {chain["urls"][-1] for chain in chains}),
        "examples_complete": len(chains) == len(urls - set(starts)),
    }
