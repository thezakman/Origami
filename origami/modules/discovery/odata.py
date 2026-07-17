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


# --- read-only aggregation probe ----------------------------------------------

_AGG_ALIAS = "OrigamiC"


def build_agg_probe(service_root: str, entityset: str) -> str:
    """A minimal, read-only aggregation query: count the whole set. If it returns
    a number without auth, aggregation is leaking row-level data by rollup."""
    base = service_root if service_root.endswith("/") else service_root + "/"
    return urljoin(base, f"{entityset}?$apply=aggregate($count as {_AGG_ALIAS})")


def classify_probe(status: int, body: bytes) -> str:
    """Classify a read-only `$apply=aggregate($count)` probe:
      * 'open'        — executed without auth and returned an aggregate row
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
        try:
            doc = json.loads(body)
        except (json.JSONDecodeError, ValueError, TypeError):
            return "error"
        if isinstance(doc, dict):
            val = doc.get("value")
            if isinstance(val, list) and val and isinstance(val[0], dict) \
                    and _AGG_ALIAS in val[0]:
                return "open"                       # aggregate returned unauth → lead
        return "reachable"
    if status == 400:
        return "reachable"                          # reached the service; query rejected
    return "error"


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
