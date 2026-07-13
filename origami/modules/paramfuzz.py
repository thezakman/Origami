"""Parameter discovery — fire the harvested parameter names and see what sticks.

Origami already learns parameter NAMES from JS query strings and GraphQL schemas
(`profile.parameters`); this turns that intel into findings. For a dynamic
endpoint it sends those names (plus a common-param list) carrying unique canary
values and watches which canaries come back in the response — a reflected
parameter is a real input the app reads, and a lead for XSS / SSTI / open-redirect.

Reflection is batchable and unambiguous: many params go in ONE request, each with
its own canary, so a reflected canary maps straight back to its parameter. A
per-batch CONTROL parameter (a name the app can't know) guards the false positive
where a page echoes the whole query string — if the control reflects, the whole
batch is discarded. Pure helpers here; the scanner fold does the fetching.
"""

from __future__ import annotations

import random
import re
import string

# High-value default parameter names, tried in addition to the harvested ones —
# the classics behind IDOR / LFI / open-redirect / debug toggles / SSRF.
COMMON = [
    "id", "page", "p", "q", "query", "search", "s", "keyword", "file", "filename",
    "path", "dir", "folder", "url", "uri", "link", "redirect", "redirect_uri",
    "return", "returnurl", "next", "continue", "callback", "jsonp", "debug",
    "test", "lang", "locale", "format", "type", "view", "action", "cmd", "exec",
    "cat", "category", "item", "product", "user", "userid", "username", "email",
    "token", "key", "api_key", "access", "role", "sort", "order", "limit",
    "offset", "start", "count", "date", "year", "month", "name", "title", "content",
    "data", "value", "mode", "step", "tab", "ref", "source", "src", "dest",
    "target", "include", "template", "tpl", "module", "do", "op", "method", "func",
]

# A parameter name we'll actually put on the wire must look like one.
_SAFE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.\[\]-]{0,39}")


def safe_names(names) -> list[str]:
    """Keep only well-formed, de-duplicated parameter names."""
    out, seen = [], set()
    for n in names:
        n = (n or "").strip()
        if n and n not in seen and _SAFE_NAME.fullmatch(n):
            seen.add(n)
            out.append(n)
    return out


def run_prefix() -> str:
    """A short random per-run token prefix so canaries don't collide with real
    page content (and differ between runs to dodge a cached reflection)."""
    return "oz" + "".join(random.choices(string.ascii_lowercase, k=5))


def build_batches(params, batch_size: int = 20, run: str | None = None):
    """Chunk params into batches; each batch → (querystring, {canary: param},
    control_canary). Every param gets a unique canary; a control param (a name the
    target can't know) rides along to detect endpoints that echo any query."""
    run = run or run_prefix()
    batches = []
    for start in range(0, len(params), batch_size):
        chunk = params[start:start + batch_size]
        token_map: dict[str, str] = {}
        pairs = []
        for j, p in enumerate(chunk):
            tok = f"{run}{start + j}q"
            token_map[tok] = p
            pairs.append(f"{p}={tok}")
        ctl_tok = f"{run}ctlq"
        pairs.append(f"{run}ctlname={ctl_tok}")     # control: an unknowable param name
        batches.append(("&".join(pairs), token_map, ctl_tok))
    return batches


def reflected(body: bytes, token_map: dict[str, str]) -> list[str]:
    """Params whose canary appears in `body` (case-insensitive — apps sometimes
    upper-case reflected input)."""
    low = body.lower()
    return [param for tok, param in token_map.items() if tok.encode() in low]


# Reflection contexts, ordered by how exploitable a reflection there usually is
# (a smarter signal than a bare "reflects": tells you the injection sink).
_CTX_RANK = {"js": 4, "html": 3, "attr": 2, "json": 1, "body": 0}


def _context_at(low: bytes, idx: int) -> str:
    """Classify where the canary landed: inside <script> (js), inside an open tag
    (attr), or in HTML text (html). Approximate but cheap — no full HTML parse."""
    pre = low[:idx]
    if pre.rfind(b"<script") > pre.rfind(b"</script>"):
        return "js"                                  # inside a <script> block
    if pre.rfind(b"<") > pre.rfind(b">"):
        return "attr"                                # between < and > → tag attribute
    return "html"                                    # HTML text node


def reflection_contexts(body: bytes, token_map: dict[str, str], ctype: str = "") -> dict[str, str]:
    """Map each reflected param → its reflection context (js/html/attr/json/body).
    `js`/`html`/`attr` are XSS-relevant sinks; `json` is an API echo. The richest
    context wins when a param reflects more than once."""
    low = body.lower()
    ct = (ctype or "").lower()
    is_html = "html" in ct or b"<html" in low[:4096] or b"<!doctype html" in low[:64]
    out: dict[str, str] = {}
    for tok, param in token_map.items():
        i = low.find(tok.encode())
        if i < 0:
            continue
        if is_html:
            ctx = _context_at(low, i)
        elif "json" in ct or low[:1] in (b"{", b"["):
            ctx = "json"
        else:
            ctx = "body"
        if _CTX_RANK.get(ctx, 0) >= _CTX_RANK.get(out.get(param, ""), -1):
            out[param] = ctx                          # keep the most exploitable context seen
    return out


def control_reflected(body: bytes, ctl_tok: str) -> bool:
    """True when the control canary reflects → the endpoint echoes ANY query
    param, so per-param reflection carries no signal for it."""
    return ctl_tok.encode() in body.lower()


def reflected_in_location(location: str, token_map: dict[str, str]) -> list[str]:
    """Params whose canary appears in the redirect DESTINATION (scheme/host/path) of
    the `Location` header — a real open-redirect lead (the input steers where the
    redirect goes). A canary that only shows up in the Location's QUERY STRING is
    NOT an open-redirect: it's the server preserving the request query on a
    canonicalization redirect (`/x` → `/x/?<original query>`), which would otherwise
    flag EVERY probed param at once. So the query part is excluded from the match."""
    if not location:
        return []
    from urllib.parse import urlsplit
    try:
        p = urlsplit(location)
    except ValueError:
        return []
    dest = f"{p.scheme}{p.netloc}{p.path}".lower()      # destination only — NOT p.query
    return [param for tok, param in token_map.items() if tok in dest]


# Response headers that legitimately echo request-ish data or are hop-by-hop —
# a canary here is noise, not a header-injection lead.
_SKIP_HEADERS = {"location", "content-length", "date", "age", "connection",
                 "content-type", "vary", "cache-control", "expires"}


def reflected_in_headers(headers: dict, token_map: dict[str, str]) -> dict[str, str]:
    """Map param → response-header NAME for canaries echoed in a header value
    (Location handled separately). Header reflection is a header-injection / cache
    lead. Deduped to the first header a param lands in."""
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        if name.lower() in _SKIP_HEADERS:
            continue
        low = str(value).lower()
        for tok, param in token_map.items():
            if param not in out and tok in low:
                out[param] = name
    return out


# Breakout payload: a value that, if reflected RAW, proves the reflection is
# unescaped (real XSS sink) — and carries an SSTI polyglot. Wrapped in a unique
# sentinel on both sides so `analyze_breakout` can inspect exactly the reflected
# region (and tell an evaluated `49` from a literal `{{7*7}}`).
_BREAKOUT_META = "'\"<>"
_SSTI_PROBE = "{{7*7}}"
_SSTI_EVAL = "49"


def build_breakout_batch(params, run: str | None = None, cap: int = 15):
    """One request that breakout-tests up to `cap` params → (querystring,
    {sentinel: param}). Each param carries `<sentinel>'"<>{{7*7}}<sentinel>` with
    a unique sentinel, so many params are verified in a single follow-up probe."""
    run = run or run_prefix()
    pairs, sent_map = [], {}
    for i, p in enumerate(params[:cap]):
        sent = f"{run}b{i}z"
        sent_map[sent] = p
        pairs.append(f"{p}={sent}{_BREAKOUT_META}{_SSTI_PROBE}{sent}")
    return "&".join(pairs), sent_map


def analyze_breakout(body: bytes, sent_map: dict[str, str]) -> dict[str, dict]:
    """For each param, find its two sentinels in `body` and inspect the region
    between them: which of `< > " '` came back RAW (unescaped → XSS), and whether
    `{{7*7}}` evaluated to `49` (SSTI). Params whose sentinels aren't both present
    are inconclusive and omitted. Returns {param: {"raw": "<>", "ssti": bool}}."""
    text = body.decode("latin-1", "replace")
    out: dict[str, dict] = {}
    for sent, param in sent_map.items():
        i = text.find(sent)
        if i < 0:
            continue
        j = text.find(sent, i + len(sent))
        if j < 0:
            continue
        region = text[i + len(sent):j]                 # exactly the reflected payload
        raw = "".join(c for c in _BREAKOUT_META if c in region)
        ssti = _SSTI_EVAL in region and _SSTI_PROBE not in region
        out[param] = {"raw": raw, "ssti": ssti}
    return out
