"""GraphQL introspection discovery (§3.7 / work.md).

A reachable GraphQL endpoint with introspection enabled hands over the whole
schema — every query/mutation and its fields. That's both a finding worth
flagging (introspection in production is an info-disclosure) and a rich input
surface: the field names feed params.txt for the next tool. GraphQL lives at a
single endpoint, so the value is the endpoint + the schema, not paths to brute.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin

# Common mount points, ordered by prevalence.
GQL_PATHS = (
    "/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query",
    "/graphql/console", "/api",
)

# Introspection — confirm the endpoint AND harvest the input surface: field names,
# their ARGUMENTS (real params), and which fields are root queries vs mutations
# (mutations change state → higher-value leads).
_INTROSPECTION = ("{__schema{queryType{name} mutationType{name} "
                  "types{name fields{name args{name}}}}}")

MAX_FIELDS = 300

# Operations worth calling out — auth/account/PII/financial/state-changing surfaces
# that introspection just handed over. Substring match on the operation name.
_SENSITIVE = re.compile(
    r"(?i)(login|logon|signin|sign_in|auth|senha|password|passwd|token|"
    r"redefin|reset|recuper|forgot|esqrec|lgpd|consent|admin|delete|remov|"
    r"revog|upload|anexo|arquivo|boleto|pagamento|pagar|cartao|carteira|"
    r"cpf|cnpj|extrato|irpf|mensalidade|contrato|create|insert|update|adicionar)")


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


def analyze_schema(doc: dict) -> dict:
    """Rich schema analysis from an introspection result. Returns:
      * fields  — all field names (input-surface intel, capped);
      * args    — all argument names (the real request params);
      * queries / mutations — root operation names you can actually CALL;
      * sensitive — root operations matching the auth/PII/state patterns.
    Mutations are tracked separately because CALLING them changes state — the
    active probe never touches them."""
    schema = (doc.get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        return {"fields": set(), "args": set(), "queries": [], "mutations": [], "sensitive": []}
    q_root = ((schema.get("queryType") or {}).get("name"))
    m_root = ((schema.get("mutationType") or {}).get("name"))
    fields: set[str] = set()
    args: set[str] = set()
    queries: list[str] = []
    mutations: list[str] = []
    for t in schema.get("types") or []:
        if not isinstance(t, dict):
            continue
        tname = t.get("name")
        if isinstance(tname, str) and tname.startswith("__"):
            continue
        is_query = tname == q_root
        is_mut = tname == m_root
        for f in t.get("fields") or []:
            if not isinstance(f, dict):
                continue
            name = f.get("name")
            if not isinstance(name, str) or not name or name.startswith("__"):
                continue
            if len(fields) < MAX_FIELDS:
                fields.add(name)
            for a in f.get("args") or []:
                if isinstance(a, dict) and isinstance(a.get("name"), str):
                    args.add(a["name"])
            if is_query:
                queries.append(name)
            elif is_mut:
                mutations.append(name)
    sensitive = [op for op in queries + mutations if _SENSITIVE.search(op)]
    return {"fields": fields, "args": args, "queries": queries,
            "mutations": mutations, "sensitive": sensitive}


def build_probe_query(op: str) -> str:
    """A minimal benign query selecting one root QUERY operation. No arguments and
    no sub-selection — enough to learn whether the endpoint lets the operation
    through (data / arg-error) or blocks it at the gate (auth error)."""
    return "{__typename " + op + "}"


# Error messages that mean "the gate blocked you" (auth enforced) vs "you got past
# the gate but the query was invalid" (reachable — an auth-bypass/BOLA surface).
_AUTH_ERR = re.compile(
    r"(?i)(authoriz|authenti|forbidden|permission|access denied|must be logged|"
    r"invalid token|missing token|autoriz|acesso negado|autentic|login required|"
    r"jwt|bearer|401|403)")
# "must provide" is deliberately NOT here — it also appears in auth messages
# ("must provide a token"), which would let a genuine auth block read as validation.
_VALIDATION_ERR = re.compile(
    r"(?i)(argument|of type|required|not provided|cannot query field|unknown|"
    r"expected|selection|subfield|did you mean|syntax)")


def classify_probe(status: int, body: bytes, op: str = "") -> str:
    """Classify a benign GraphQL probe → 'open' (executed without auth),
    'reachable' (past the gate, only a validation error), 'auth' (gate blocked),
    or 'error' (inconclusive). `op` (the probed operation name) is stripped from
    error text before matching so an op literally named `login`/`authenticate`
    can't self-match the auth pattern via the echoed field name."""
    if status in (401, 403):
        return "auth"
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return "error"
    if not isinstance(doc, dict):
        return "error"
    errs = doc.get("errors")
    data = doc.get("data")
    # `__typename` ALWAYS resolves (to the root type name) whenever a query executes,
    # so it must NOT count as "returned data" — else every reachable op that returns
    # null (e.g. `me`/`viewer` unauthenticated) would falsely read as 'open'.
    if isinstance(data, dict):
        real = [v for k, v in data.items() if k != "__typename"]
        if real and any(v is not None for v in real):
            return "open"                          # returned real data w/o auth → BOLA/auth-bypass
    if errs:
        msg = json.dumps(errs).lower()
        if op:
            msg = msg.replace(op.lower(), "")      # don't let the echoed op name match the patterns
        if _AUTH_ERR.search(msg):
            return "auth"
        if _VALIDATION_ERR.search(msg):
            return "reachable"                     # past parse/auth, just needs valid args
        return "error"
    if "data" in doc:                              # data: null, no error → executed, empty result
        return "reachable"
    return "error"


async def harvest(engine, base_url: str) -> tuple[str | None, set[str], dict]:
    """POST a minimal introspection query to each candidate; on the first that
    returns a schema, return (endpoint_url, field_names, schema_analysis)."""
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
            return url, extract_fields(doc), analyze_schema(doc)
    return None, set(), {"fields": set(), "args": set(), "queries": [],
                         "mutations": [], "sensitive": []}
