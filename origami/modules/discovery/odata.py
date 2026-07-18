"""OData discovery + aggregation leads.

OData exposes a machine-readable schema at ``$metadata`` — the EDMX document that
declares every EntitySet, EntityType property, and Function/Action the service
offers. Like Swagger or GraphQL introspection, that is both an info-disclosure
worth flagging AND a rich recon surface: entity sets fold in as seeds to probe,
property names feed the parameter surface.

On top of the schema, OData's aggregation extension (``$apply``) is a distinct
lead. ``$apply=aggregate(...)``/``groupby(...)`` can return counts and rollups
computed over rows the caller cannot read individually — an authorization bypass
by aggregation — and is a classic DoS amplifier (unbounded group-by over a large
set). We confirm it with a single **read-only** ``aggregate($count)`` probe.

Every probe here is a GET. The active OData surface that changes state — ``$batch``
POSTs, bound/unbound Actions, inserts/updates — is never touched.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

# Metadata mount points, ordered by prevalence. `$metadata` is the schema; the
# service root (no `$metadata`) returns a service document listing entity sets.
METADATA_PATHS = (
    "/$metadata", "/odata/$metadata", "/odata/v4/$metadata", "/api/$metadata",
    "/api/odata/$metadata", "/odata/v2/$metadata", "/web/odata/$metadata",
    "/sap/opu/odata/sap/$metadata",
)
SERVICE_PATHS = ("/odata", "/odata/v4", "/api/odata", "/odata/v2")

MAX_SETS = 300
MAX_PROPS = 400

# Entity sets / functions worth calling out — auth/account/PII/financial/state
# surfaces the schema just handed over. Substring match, EN + PT-BR.
_SENSITIVE = re.compile(
    r"(?i)(user|usuario|account|conta|login|logon|auth|senha|password|passwd|"
    r"credential|token|secret|apikey|admin|role|permission|permissao|"
    r"payment|pagamento|pagar|invoice|fatura|boleto|order|pedido|cartao|card|"
    r"carteira|wallet|cpf|cnpj|extrato|contrato|contract|salary|salario|"
    r"customer|cliente|employee|funcionario|person|pessoa|document|documento)")

# EDMX attribute extractors — bounded regex on the schema XML (dependency-free).
_ENTITYSET = re.compile(r"<EntitySet\b[^>]*\bName\s*=\s*[\"']([^\"']+)[\"']", re.I)
_PROPERTY = re.compile(r"<(?:Property|NavigationProperty)\b[^>]*\bName\s*=\s*[\"']([^\"']+)[\"']", re.I)
_FUNCTION = re.compile(r"<(?:Function|FunctionImport)\b[^>]*\bName\s*=\s*[\"']([^\"']+)[\"']", re.I)
_ACTION = re.compile(r"<(?:Action|ActionImport)\b[^>]*\bName\s*=\s*[\"']([^\"']+)[\"']", re.I)
_VERSION = re.compile(r"<(?:edmx:)?Edmx\b[^>]*\bVersion\s*=\s*[\"']([^\"']+)[\"']", re.I)
# Aggregation declared via the OData aggregation vocabulary annotation.
_AGG_DECL = re.compile(r"(?i)(Aggregation\.V1|ApplySupported|Aggregatable|CustomAggregate)")

_EMPTY: dict = {"entitysets": [], "properties": set(), "functions": [], "actions": [],
                "sensitive": [], "aggregation": False, "service_root": None, "version": ""}


def is_metadata(body: bytes) -> bool:
    """EDMX schema document? (`<Edmx>`/`<edmx:Edmx>` or a bare EDM `<Schema>`)."""
    head = body[:4096].lower()
    return b"<edmx" in head or (b"<schema" in head and b"entitytype" in body[:65536].lower())


def is_service_doc(body: bytes, ctype: str) -> bool:
    """OData v4 JSON service document — identified by the `@odata.context` marker."""
    if "json" not in (ctype or "").lower():
        return False
    return b"@odata.context" in body[:2048]


def parse_metadata(body: bytes, service_root: str | None = None) -> dict:
    """EDMX (`$metadata`) → schema analysis: entity sets (seeds), property names
    (params), Functions/Actions (callable ops), the sensitive subset, whether
    aggregation is declared, and the OData version."""
    text = body.decode("utf-8", "replace")
    sets = list(dict.fromkeys(_ENTITYSET.findall(text)))[:MAX_SETS]
    props = set(_PROPERTY.findall(text))
    if len(props) > MAX_PROPS:
        props = set(sorted(props)[:MAX_PROPS])
    functions = list(dict.fromkeys(_FUNCTION.findall(text)))
    actions = list(dict.fromkeys(_ACTION.findall(text)))
    vmatch = _VERSION.search(text)
    sensitive = [n for n in sets + functions + actions if _SENSITIVE.search(n)]
    return {"entitysets": sets, "properties": props, "functions": functions,
            "actions": actions, "sensitive": list(dict.fromkeys(sensitive)),
            "aggregation": bool(_AGG_DECL.search(text)),
            "service_root": service_root, "version": vmatch.group(1) if vmatch else ""}


def parse_service_doc(body: bytes, service_root: str | None = None) -> dict:
    """OData v4 JSON service document → entity set names (`value[].name`)."""
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return dict(_EMPTY)
    if not isinstance(doc, dict):
        return dict(_EMPTY)
    sets: list[str] = []
    for item in doc.get("value") or []:
        if isinstance(item, dict):
            name = item.get("name")
            # skip non-entity members (singletons/functions are marked with `kind`)
            if isinstance(name, str) and name and item.get("kind") in (None, "EntitySet"):
                sets.append(name)
    sets = list(dict.fromkeys(sets))[:MAX_SETS]
    sensitive = [n for n in sets if _SENSITIVE.search(n)]
    return {"entitysets": sets, "properties": set(), "functions": [], "actions": [],
            "sensitive": sensitive, "aggregation": False,
            "service_root": service_root, "version": "4.0"}


def _service_root(metadata_url: str) -> str:
    """Strip a trailing `$metadata` to get the service root the entity sets hang
    off (so `/odata/$metadata` → `/odata/`)."""
    p = urlparse(metadata_url)
    path = p.path
    if path.endswith("$metadata"):
        path = path[: -len("$metadata")]
    if not path.endswith("/"):
        path += "/"
    return f"{p.scheme}://{p.netloc}{path}"


def entity_set_paths(meta: dict) -> list[str]:
    """Root-absolute seed paths for each entity set (service_root + name)."""
    root = meta.get("service_root")
    if not root:
        return []
    base = urlparse(root).path or "/"
    if not base.endswith("/"):
        base += "/"
    return [base + name for name in meta.get("entitysets", [])]


# --- read-only OData query-option probes --------------------------------------
#
# OData collections accept `$apply` (aggregation), `$top`/`$skip` (paging) and
# `$select`/`$filter`. That matters for access control: a plain listing that is
# blocked (413 "entity too large", 403, a paging requirement) is NOT protected if
# `$top`/`$skip` walk around the block or `$apply=aggregate` rolls the rows up. We
# confirm exposure with two read-only GETs — an aggregate `$count` and a single
# `$top=1` row — never a bulk dump, never a write.

# The `$count as …` alias. Kept NEUTRAL (`Total`, what an analyst writes by hand)
# so the PoC URL carries no tool branding — the report/deliverable must be
# self-contained. Safe against a false positive from a raw entity that happens to
# have a `Total` field because `agg_count` requires the row to be a PURE aggregate
# (only the alias + `@odata.*` metadata), which a real record never is.
_AGG_ALIAS = "Total"
AGG_COUNT = f"$apply=aggregate($count as {_AGG_ALIAS})"

# PII / secret-bearing field names to call out when a probed record comes back
# (EN + PT-BR). We report the field NAMES as evidence — never the values.
_SENS_FIELD = re.compile(
    r"(?i)(cpf|cnpj|\brg\b|identificac|passaporte|passport|cnh|senha|password|"
    r"passwd|token|secret|apikey|e[-_]?mail|email|telefone|phone|celular|"
    r"nascimento|birth|nome|name|salario|salary|cartao|\bcard\b|conta|account|"
    r"endereco|address|credential|documento|document)")


def with_query(url: str, option: str) -> str:
    """Append an OData query option to a URL, respecting an existing query string."""
    sep = "&" if urlparse(url).query else "?"
    return f"{url}{sep}{option}"


def top_query(n: int = 1) -> str:
    """`$top=N` — read at most N rows. The probe uses N=1: enough to prove the
    collection is readable without pulling the whole table."""
    return f"$top={int(n)}"


def build_agg_probe(service_root: str, entityset: str) -> str:
    """A minimal, read-only aggregation query: count the whole set. If it returns
    a number without auth, aggregation is leaking row-level data by rollup."""
    base = service_root if service_root.endswith("/") else service_root + "/"
    return urljoin(base, f"{entityset}?{AGG_COUNT}")


def _agg_rows(doc) -> list | None:
    """The row list from either an OData envelope (`{"value":[…]}`) or a bare
    array (`[…]`) — custom APIs with `$apply` support often return the latter."""
    if isinstance(doc, dict):
        v = doc.get("value")
        return v if isinstance(v, list) else None
    if isinstance(doc, list):
        return doc
    return None


def agg_count(body: bytes):
    """Extract the aggregate count our `$count as Total` probe asked for, from either
    response shape. Returns the number, or None if it isn't a genuine aggregate. The
    false-positive guard: the row must be a PURE aggregate — the numeric alias plus at
    most `@odata.*` metadata — so a raw entity that merely HAS a `Total` field (an
    order amount, say), returned because `$apply` was ignored, is rejected."""
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    rows = _agg_rows(doc)
    if not (rows and isinstance(rows[0], dict)):
        return None
    row = rows[0]
    v = row.get(_AGG_ALIAS)
    data_keys = [k for k in row if k != _AGG_ALIAS and not str(k).startswith("@")]
    if isinstance(v, (int, float)) and not isinstance(v, bool) and not data_keys:
        return v                                   # only the alias (+ @odata metadata) → real aggregate
    return None


def classify_probe(status: int, body: bytes) -> str:
    """Classify a read-only `$apply=aggregate($count)` probe:
      * 'open'        — executed without auth and returned our aggregate alias
                        (data disclosure / authz-by-aggregation bypass);
      * 'reachable'   — past the gate but the query errored (400/`$apply` issue);
      * 'auth'        — the gate blocked it (401/403);
      * 'unsupported' — service rejected `$apply` as not implemented (501);
      * 'error'       — inconclusive."""
    if status in (401, 403):
        return "auth"
    if status == 501:
        return "unsupported"
    if 200 <= status < 300:
        if agg_count(body) is not None:             # our alias came back → aggregate ran
            return "open"
        try:
            json.loads(body)
        except (json.JSONDecodeError, ValueError, TypeError):
            return "error"
        return "reachable"
    if status == 400:
        return "reachable"                          # reached the service; query rejected
    return "error"


def parse_records(status: int, body: bytes) -> list | None:
    """A `$top=1` response → the record list (from envelope or bare array), or None
    if the response isn't a non-empty list of objects."""
    if not (200 <= status < 300):
        return None
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    rows = _agg_rows(doc)
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        # a bare aggregate row (just our alias) is NOT a data record — don't
        # double-count it as an exposed row.
        if len(rows) == 1 and set(rows[0].keys()) == {_AGG_ALIAS}:
            return None
        return [r for r in rows if isinstance(r, dict)]
    return None


def sensitive_fields(record: dict, cap: int = 12) -> list:
    """PII / secret-bearing key names in a record — reported as evidence of what
    the exposure leaks, without ever surfacing the values."""
    out = [k for k in record.keys() if isinstance(k, str) and _SENS_FIELD.search(k)]
    return out[:cap]


async def harvest(engine, base_url: str) -> tuple[str | None, set[str], dict]:
    """Probe the metadata endpoints, then the service roots. On the first that
    yields an EDMX schema or a service document, return
    (source_url, entity_set_names, schema_analysis)."""
    for cand in METADATA_PATHS:
        url = urljoin(base_url, cand.lstrip("/"))
        try:
            pr = await engine.fetch(url, keep_body=True)
        except Exception:
            continue
        if not (pr.ok and pr.body and is_metadata(pr.body)):
            continue
        meta = parse_metadata(pr.body, service_root=_service_root(url))
        return url, set(meta["entitysets"]), meta
    for cand in SERVICE_PATHS:
        url = urljoin(base_url, cand.lstrip("/"))
        try:
            pr = await engine.fetch(url, keep_body=True)
        except Exception:
            continue
        if not (pr.ok and pr.body and is_service_doc(pr.body, pr.content_type or "")):
            continue
        root = url if url.endswith("/") else url + "/"
        meta = parse_service_doc(pr.body, service_root=root)
        if meta["entitysets"]:
            return url, set(meta["entitysets"]), meta
    return None, set(), dict(_EMPTY)
