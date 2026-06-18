"""GraphQL introspection discovery (§3.7 / work.md).

A reachable GraphQL endpoint with introspection enabled hands over the whole
schema — every query/mutation and its fields. That's both a finding worth
flagging (introspection in production is an info-disclosure) and a rich input
surface: the field names feed params.txt for the next tool. GraphQL lives at a
single endpoint, so the value is the endpoint + the schema, not paths to brute.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse

# Common mount points, ordered by prevalence.
GQL_PATHS = (
    "/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query",
    "/graphql/console", "/api",
)

# Minimal introspection — enough to confirm and to harvest field names.
_INTROSPECTION = ("{__schema{queryType{name} mutationType{name} "
                  "types{name fields{name}}}}")

MAX_FIELDS = 300


def extract_fields(doc: dict) -> set[str]:
    """GraphQL introspection result → set of field names (input-surface intel)."""
    schema = (doc.get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        return set()
    out: set[str] = set()
    for t in schema.get("types") or []:
        if not isinstance(t, dict):
            continue
        if isinstance(t.get("name"), str) and t["name"].startswith("__"):
            continue                                       # skip introspection meta types
        for f in t.get("fields") or []:
            if isinstance(f, dict) and isinstance(f.get("name"), str):
                name = f["name"]
                if name and not name.startswith("__"):     # skip introspection meta
                    out.add(name)
            if len(out) >= MAX_FIELDS:
                return out
    return out


def _is_schema(doc: dict) -> bool:
    return isinstance((doc.get("data") or {}).get("__schema"), dict)


async def harvest(engine, base_url: str) -> tuple[str | None, set[str]]:
    """POST a minimal introspection query to each candidate; on the first that
    returns a schema, return (endpoint_url, field_names)."""
    for cand in GQL_PATHS:
        url = urljoin(base_url, cand.lstrip("/"))
        try:
            probe = await engine.fetch(url, method="POST", keep_body=True,
                                       json={"query": _INTROSPECTION})
        except Exception:
            continue
        if not (probe.ok and probe.body):
            continue
        try:
            doc = json.loads(probe.body)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(doc, dict) and _is_schema(doc):
            return url, extract_fields(doc)
    return None, set()
