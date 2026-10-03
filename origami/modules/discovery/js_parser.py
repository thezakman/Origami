"""JS / HTML endpoint harvesting (§3.7 "JS Feeding").

Extracts paths and endpoints from the root HTML and the same-host scripts it
references, then feeds them back as high-priority candidates. Pulling routes
straight out of the app's own JS is far higher-yield than guessing.

Regex-based and deliberately conservative: we keep things that look like
server paths (start with `/`, or relative endpoints with a known shape) and
drop obvious noise (assets we already have, data URIs, externals).
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from origami.core.scope import same_host, same_site

# Quoted absolute paths: "/api/v1/users", '/admin/login'
# A quoted absolute path. An optional `?query`/`#frag` may sit inside the quotes
# (`'/x/edit.aspx?id='` — a URL the JS builds by concatenation); consume it so the
# PATH is still captured (the query is stripped downstream, its param names are
# harvested separately). Without this, exactly the interesting parameterised
# endpoints (`?id=`, `?license_key=`) were the ones missed.
# The trailing `\\?` tolerates a stray escaped-quote backslash (`...\'`) right
# before the real closing quote — seen in real bundles where a module's own
# source is itself embedded as a string (eval()'d or JSON-serialized).
_ABS = re.compile(rb"""["'`](/[A-Za-z0-9_\-./]{1,100})(?:[?#][^"'`]{0,200})?\\?["'`]""")
# Template-literal URLs: `${this.basePath}/api/v1/foo/${id}/bar`. Codegen'd
# TS/Angular API clients build almost every endpoint this way — a runtime
# base-path var up front and/or a path-param var mid-path — so the literal
# never starts with `/` right after the backtick and _ABS can't see it at
# all. Grab the whole backtick body (bounded — this must not swallow a giant
# `template: \`<div>...\`` component template) and let _strip_template_exprs
# below drop the `${...}` bits before it's handed to `consider()`.
_TEMPLATE = re.compile(rb"`([^`]{1,300})`")
_TPL_EXPR = re.compile(r"\$\{[^{}]*\}")
# href/src/action attributes
_ATTR = re.compile(rb"""(?:href|src|action)\s*=\s*["']([^"'#?]+)["']""", re.I)
# fetch()/axios/url: "..."  call targets
_CALL = re.compile(
    rb"""(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|ajax)|url)\s*[(:]\s*["'`]([^"'`]+)["'`]""",
    re.I,
)
# script src + RequireJS data-main to follow
_SCRIPT_SRC = re.compile(rb"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
_DATA_MAIN = re.compile(rb"""data-main\s*=\s*["']([^"']+)["']""", re.I)

# Third-party libraries carry no app endpoints — skip them so the fetch budget
# goes to the app bundle (app.bootstrap.js etc.), where the routes/templates live.
_VENDOR = re.compile(
    r"(jquery|jquery-migrate|bootstrap|slick|croppie|modernizr|lodash|underscore|"
    r"react|vue|polyfill|moment|popper|select2|datatables|fontawesome|font-awesome|"
    r"tinymce|ckeditor|sha\.js|exif|requirejs|require\.js|babel|core-js|zone\.js|"
    r"swiper|chart\.?js|d3|three|leaflet|mathjax|highlight|prism|jszip|sweetalert|"
    r"toastr|moment-timezone|numeral|clipboard|dropzone|pdfmake)", re.I)
# App-bundle hints get fetched first (highest endpoint yield). Note: "app." so
# app.bootstrap.js is kept while the vendor bootstrap.js lib is still skipped.
_APP_HINT = re.compile(r"(app\.|bundle|main\.|runtime|definitions|chunk|\bapp\b)", re.I)
# webpack/Vue-CLI's own name for "every third-party dep bundled together"
# (`chunk-vendors.<hash>.js`, `vendor.js`, `vendors~main.js`...) — a much
# stronger, deliberate signal than the named-library list above, so it must
# NOT be cancelled by _APP_HINT the way those are: "chunk-vendors" contains
# "chunk" too, and without this override _is_vendor waved it through as an
# "app" bundle. Confirmed on a real 28MB chunk-vendors.js (an OpenLayers-heavy
# vendor bundle): 0 real endpoints, 400+ noise "paths" that were actually the
# library's own internal module references (`../../geom/Point.js`) — pure
# cost, no signal, for a full 20MB-cap fetch.
_VENDOR_STRONG = re.compile(r"vendors?\b", re.I)


def _is_vendor(url: str) -> bool:
    name = url.rsplit("/", 1)[-1]
    if _VENDOR_STRONG.search(name):
        return True
    return bool(_VENDOR.search(name)) and not _APP_HINT.search(name)
# source maps + webpack/module chunk references (reveal more source files)
_SOURCEMAP = re.compile(rb"""sourceMappingURL=([^\s"'*]+)""", re.I)
_JS_REF = re.compile(rb"""["'`]([\w./-]+\.(?:js|mjs|json|map))["'`]""", re.I)
# query parameter names — ONLY from a quoted URL-query string ("…?a=1&b=2"),
# not from minified `a?b:c` ternaries, so the intel is real, not JS-token noise.
# The trailing `\\?` tolerates a stray escaped-quote backslash (`...\'`) right
# before the real closing quote — common when the JS itself is embedded as a
# string (an eval()'d or JSON-serialized module, both seen in real bundles);
# _ABS already tolerates this via its far more permissive query-tail class.
_QUERY = re.compile(rb"""["'`][^"'`\s]{0,200}\?([A-Za-z0-9_=&.%\[\]\-]+)\\?["'`]""")
_PARAM_NAME = re.compile(r"^[A-Za-z_][\w.\-]{0,39}$")

# Method-aware client-route extraction.  This remains passive intelligence:
# callers may export these hints, but they must never replay state-changing
# methods merely because an application bundle mentions one.
_ASSIGN = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]{0,63})\s*=\s*([^;\n]{1,500})(?:;|\n|$)"
)
_CLIENT_CALL = re.compile(
    r"(?<![\w$])(?:(fetch)|(axios)\.(get|post|put|patch|delete|head|options)|"
    r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\."
    r"(getJSON|getScript|get|post|put|patch|delete|head|options))\s*\(", re.I
)
_CONFIG_CALL = re.compile(
    r"(?<![\w$])(?:(axios)(?:\.request)?|"
    r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.request|"
    r"(\$|jQuery)\.ajax)\s*\(", re.I
)
_XHR_OPEN = re.compile(r"\.open\s*\(\s*(['\"])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,", re.I)
_AXIOS_CREATE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]{0,63})\s*=\s*axios\.create\s*\(\s*\{(.{0,800}?)\}\s*\)",
    re.I | re.S,
)
_BASE_URL = re.compile(r"\bbaseURL\s*:\s*([^,}\n]{1,400})", re.I)
_DYNAMIC_EXPR = re.compile(r"\$\{\s*([^{}]{1,100})\s*\}")
_SAFE_DYNAMIC = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$")

# Endings/segments that are just static assets — not interesting as routes.
# Note: .map (source maps) is deliberately NOT here — it's high-value recon.
_ASSET_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
              ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".avif")


def _strip_template_exprs(s: str) -> str:
    """`${this.basePath}/api/v1/foo/${id}/bar` -> /api/v1/foo/bar.

    Drops the `${...}` interpolations a JS template literal builds a URL
    with (a runtime base-path variable, a path-param ID we can't know) and
    collapses the `//` gap each one leaves behind, keeping the static
    segments around them — the same "static prefix" idea apidocs.py already
    applies to OpenAPI's `/users/{id}`, just for template-literal syntax."""
    s = _TPL_EXPR.sub("", s)
    return re.sub(r"/{2,}", "/", s)


def _split_static_expr(expr: str) -> list[str] | None:
    """Split a small JS string concatenation without evaluating JavaScript."""
    parts: list[str] = []
    start = 0
    quote = ""
    escaped = False
    for i, char in enumerate(expr):
        if escaped:
            escaped = False
            continue
        if quote and char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char == "+":
            parts.append(expr[start:i].strip())
            start = i + 1
    if quote:
        return None
    parts.append(expr[start:].strip())
    return parts if all(parts) else None


def _unquote_js(token: str) -> str | None:
    if len(token) < 2 or token[0] not in "'\"`" or token[-1] != token[0]:
        return None
    value = token[1:-1]
    # URL strings primarily need escaped slash/quote/backslash support. Avoid
    # codecs/unicode_escape: it interprets arbitrary attacker-controlled bytes.
    value = value.replace(r"\/", "/")
    value = value.replace("\\" + token[0], token[0]).replace(r"\\", "\\")
    return value


def _static_expr(expr: str, symbols: dict[str, str], *, dynamic: bool = False) -> str | None:
    parts = _split_static_expr(expr.strip())
    if not parts:
        return None
    out: list[str] = []
    for token in parts:
        literal = _unquote_js(token)
        if literal is not None:
            if "${" in literal and not dynamic:
                return None
            out.append(literal)
        elif token in symbols:
            out.append(symbols[token])
        elif dynamic and _SAFE_DYNAMIC.fullmatch(token):
            out.append("{" + token + "}")
        else:
            return None
    value = "".join(out)
    return value if 0 < len(value) <= 500 else None


def _static_symbols(source: str) -> dict[str, str]:
    """Resolve bounded const/let/var string chains (never execute JS)."""
    assignments = _ASSIGN.findall(source)
    symbols: dict[str, str] = {}
    for _ in range(4):
        changed = False
        for name, expr in assignments:
            value = _static_expr(expr, symbols)
            if value is not None and symbols.get(name) != value:
                symbols[name] = value
                changed = True
        if not changed:
            break
    return symbols


def _read_argument(source: str, start: int, limit: int = 700) -> tuple[str, int]:
    """Read one call argument from *start*, respecting quoted/template strings."""
    quote = ""
    escaped = False
    depth = 0
    end = min(len(source), start + limit)
    for i in range(start, end):
        char = source[i]
        if escaped:
            escaped = False
            continue
        if quote and char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif depth == 0 and char in ",)":
            return source[start:i].strip(), i
    return "", start


def _split_top_level(value: str, delimiter: str = ",") -> list[str]:
    """Split a bounded JS fragment outside strings and nested containers."""
    parts: list[str] = []
    start = 0
    quote = ""
    escaped = False
    depth = 0
    for i, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote and char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char in "[{(":
            depth += 1
        elif char in "]})" and depth:
            depth -= 1
        elif char == delimiter and depth == 0:
            parts.append(value[start:i].strip())
            start = i + 1
    parts.append(value[start:].strip())
    return [part for part in parts if part]


def _top_level_colon(value: str) -> int:
    quote = ""
    escaped = False
    depth = 0
    for i, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote and char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char in "[{(":
            depth += 1
        elif char in "]})" and depth:
            depth -= 1
        elif char == ":" and depth == 0:
            return i
    return -1


def _property_name(raw: str) -> str | None:
    raw = raw.strip()
    quoted = _unquote_js(raw)
    if quoted is not None:
        return quoted if 0 < len(quoted) <= 80 and not any(ord(c) < 32 for c in quoted) else None
    return raw if re.fullmatch(r"[A-Za-z_$][\w$-]{0,79}", raw) else None


def _object_properties(expression: str) -> dict[str, str]:
    """Read top-level object-literal properties without evaluating values."""
    expression = expression.strip()
    if not (expression.startswith("{") and expression.endswith("}")) or len(expression) > 2400:
        return {}
    properties: dict[str, str] = {}
    for entry in _split_top_level(expression[1:-1])[:64]:
        if entry.startswith("..."):
            continue
        colon = _top_level_colon(entry)
        if colon < 0:
            name = _property_name(entry)
            if name:
                properties[name] = entry
            continue
        name = _property_name(entry[:colon])
        if name:
            properties[name] = entry[colon + 1:].strip()
    return properties


def _inline_object_keys(expression: str) -> list[str]:
    """Return only field names from an inline object; values never leave the parser."""
    expression = expression.strip()
    if expression.startswith("JSON.stringify"):
        start = expression.find("(")
        if start >= 0:
            expression, _ = _read_argument(expression, start + 1, 2200)
    return sorted(_object_properties(expression))


def _config_metadata(properties: dict[str, str], method: str, *, jquery: bool = False
                     ) -> tuple[list[str], list[str], list[str]]:
    query = _inline_object_keys(properties.get("params", ""))
    data_keys = _inline_object_keys(properties.get("data", properties.get("body", "")))
    if jquery and method == "GET":
        query = sorted(set(query) | set(data_keys))
        body: list[str] = []
    else:
        body = data_keys
    headers = _inline_object_keys(properties.get("headers", ""))
    return query, body, headers


def _dynamic_name(expr: str) -> str:
    expr = expr.strip()
    return expr if _SAFE_DYNAMIC.fullmatch(expr) else "dynamic"


def _render_dynamic(value: str) -> str:
    # A leading `${basePath}` is deployment configuration, not a route param.
    value = re.sub(r"^\$\{[^{}]{1,100}\}(?=/|[A-Za-z0-9])", "", value, count=1)
    return _DYNAMIC_EXPR.sub(lambda m: "{" + _dynamic_name(m.group(1)) + "}", value)


def _combine_base(base: str, route: str) -> str:
    if route.startswith(("http://", "https://", "//")):
        return route
    return base.rstrip("/") + "/" + route.lstrip("/")


def _normalise_route(value: str, base_url: str, client_base: str = "") -> str | None:
    value = value.strip()
    leading_runtime_base = bool(re.match(r"^\$\{[^{}]{1,100}\}(?=/|[A-Za-z0-9])", value))
    value = _render_dynamic(value)
    if not value or len(value) > 400 or any(ord(c) < 32 for c in value):
        return None
    if value.startswith(("data:", "mailto:", "tel:", "javascript:", "#")):
        return None
    if client_base:
        value = _combine_base(client_base, value)
    target_host = urlparse(base_url).netloc
    if value.startswith("//"):
        value = (urlparse(base_url).scheme or "https") + ":" + value
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        if not parsed.netloc or not same_site(parsed.netloc, target_host):
            return None
        value = value.split("#", 1)[0]
    else:
        value = value.split("#", 1)[0]
        if not value.startswith("/"):
            # Require an endpoint-shaped relative string. This rejects common
            # UI noise such as object.get("label"). Preserve a genuinely
            # relative URL so the scanner resolves it against the app prefix;
            # only the established `${basePath}route` convention is root-based.
            if "/" not in value:
                return None
            if leading_runtime_base:
                value = "/" + value
    path = urlparse(value).path
    if not path or path == "/" or path.lower().endswith(_ASSET_EXT):
        return None
    return value


def _hint(method: str, route: str, client: str, *, query_params=(), body_keys=(),
          header_names=()) -> dict:
    path, _, query = route.partition("?")
    path_params = list(dict.fromkeys(re.findall(r"\{([^{}]+)\}", path)))
    url_query_params: list[str] = []
    for pair in query.split("&") if query else ():
        name = pair.split("=", 1)[0].strip()
        if name and name not in url_query_params:
            url_query_params.append(name)
    return {
        "method": method.upper(),
        "route": route,
        "template": bool(path_params or "{" in query),
        "path_params": path_params,
        "query_params": sorted(set(url_query_params) | set(query_params)),
        "body_keys": sorted(set(body_keys)),
        "header_names": sorted(set(header_names)),
        "client": client,
    }


def extract_endpoint_hints(body: bytes, base_url: str, _depth: int = 0) -> list[dict]:
    """Extract passive, method-aware client routes without replaying them.

    Static string concatenations and axios ``baseURL`` instances are resolved;
    runtime path/query values remain explicit ``{param}`` templates. Only
    same-site absolute URLs are retained.
    """
    hints: dict[tuple[str, str, str], dict] = {}

    def put(item: dict) -> None:
        key = (item["method"], item["route"], item["client"])
        previous = hints.get(key)
        if previous is None:
            hints[key] = item
            return
        for field in ("path_params", "query_params", "body_keys", "header_names"):
            previous[field] = sorted(set(previous.get(field, [])) | set(item.get(field, [])))
        previous["template"] = bool(previous.get("template") or item.get("template"))

    if _depth < 2 and _looks_sourcemap(body):
        for blob in parse_sourcemap(body):
            for item in extract_endpoint_hints(blob, base_url, _depth + 1):
                put(item)

    source = body.decode("latin-1", "replace")
    symbols = _static_symbols(source)
    axios_bases: dict[str, str] = {}
    for match in _AXIOS_CREATE.finditer(source):
        base_match = _BASE_URL.search(match.group(2))
        if base_match:
            base = _static_expr(base_match.group(1), symbols)
            if base:
                axios_bases[match.group(1)] = base

    def method_from(properties: dict[str, str], default: str = "GET") -> str:
        expression = properties.get("method", properties.get("type", ""))
        if not expression:
            return default
        value = _static_expr(expression, symbols)
        if value and value.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            return value.upper()
        return "UNKNOWN"

    def add(method: str, expression: str, client: str, client_base: str = "", *,
            query_params=(), body_keys=(), header_names=()) -> None:
        value = _static_expr(expression, symbols, dynamic=True)
        if value is None:
            return
        route = _normalise_route(value, base_url, client_base)
        if route is None:
            return
        put(_hint(method, route, client, query_params=query_params,
                  body_keys=body_keys, header_names=header_names))

    for match in _CLIENT_CALL.finditer(source):
        expression, stop = _read_argument(source, match.end())
        if not expression:
            continue
        if match.group(1):
            method = "GET"
            properties: dict[str, str] = {}
            if source[stop:stop + 1] == ",":
                options, _ = _read_argument(source, stop + 1, 2400)
                properties = _object_properties(options)
                method = method_from(properties)
            query, fetch_body_keys, headers = _config_metadata(properties, method)
            add(method, expression, "fetch", query_params=query,
                body_keys=fetch_body_keys, header_names=headers)
            continue
        if match.group(2):
            method = match.group(3).upper()
            config: dict[str, str] = {}
            axios_body_keys: list[str] = []
            if source[stop:stop + 1] == ",":
                second, second_stop = _read_argument(source, stop + 1, 2400)
                if method in {"POST", "PUT", "PATCH"}:
                    axios_body_keys = _inline_object_keys(second)
                    if source[second_stop:second_stop + 1] == ",":
                        third, _ = _read_argument(source, second_stop + 1, 2400)
                        config = _object_properties(third)
                else:
                    config = _object_properties(second)
            query, config_body, headers = _config_metadata(config, method)
            add(method, expression, "axios", query_params=query,
                body_keys=sorted(set(axios_body_keys) | set(config_body)), header_names=headers)
            continue
        obj, raw_method = match.group(4), match.group(5)
        method = "GET" if raw_method.lower() in {"getjson", "getscript"} else raw_method.upper()
        body_keys = []
        query_params = []
        if method in {"POST", "PUT", "PATCH"} and source[stop:stop + 1] == ",":
            second, _ = _read_argument(source, stop + 1, 2400)
            body_keys = _inline_object_keys(second)
        elif obj.lower() in {"$", "jquery"} and source[stop:stop + 1] == ",":
            second, _ = _read_argument(source, stop + 1, 2400)
            query_params = _inline_object_keys(second)
        if obj in axios_bases:
            add(method, expression, f"axios-instance:{obj}", axios_bases[obj],
                body_keys=body_keys)
        elif obj.lower() in {"$", "jquery"}:
            add(method, expression, "jquery", query_params=query_params, body_keys=body_keys)
        elif obj.lower() in {"http", "$http", "this.http", "client", "api", "apiclient"}:
            add(method, expression, obj, body_keys=body_keys)

    # Axios/jQuery config-object forms carry substantially more pentest input
    # surface than URL-first aliases: method, query/body keys and header names.
    for match in _CONFIG_CALL.finditer(source):
        first, stop = _read_argument(source, match.end(), 2400)
        if not first:
            continue
        config_properties: dict[str, str]
        if first.strip().startswith("{"):
            config_properties = _object_properties(first)
            route_expression = config_properties.get("url", "")
        else:
            route_expression = first
            config_properties = {}
            if source[stop:stop + 1] == ",":
                config_expression, _ = _read_argument(source, stop + 1, 2400)
                config_properties = _object_properties(config_expression)
        if not route_expression:
            continue
        jquery = bool(match.group(3))
        obj = match.group(2) or ""
        if jquery:
            client = "jquery"
            client_base = ""
        elif match.group(1):
            client = "axios-config"
            client_base = ""
        elif obj in axios_bases:
            client = f"axios-instance:{obj}"
            client_base = axios_bases[obj]
        else:
            continue
        configured_base = _static_expr(config_properties.get("baseURL", ""), symbols)
        if configured_base:
            client_base = configured_base
        method = method_from(config_properties)
        query, body_keys, headers = _config_metadata(config_properties, method, jquery=jquery)
        add(method, route_expression, client, client_base, query_params=query,
            body_keys=body_keys, header_names=headers)

    for match in _XHR_OPEN.finditer(source):
        expression, _ = _read_argument(source, match.end())
        add(match.group(2), expression, "xhr")

    # Some generated SDKs assign a route template before passing it through
    # wrappers our regex cannot name. Preserve that route as passive UNKNOWN
    # method intelligence; a method-aware hit for the same route wins.
    known_routes = {item["route"] for item in hints.values()}
    for raw in _TEMPLATE.findall(body):
        value = raw.decode("latin-1", "replace")
        if "${" not in value:
            continue
        route = _normalise_route(value, base_url)
        if route is None or route in known_routes:
            continue
        item = _hint("UNKNOWN", route, "template")
        put(item)
        known_routes.add(route)

    return sorted(hints.values(), key=lambda h: (h["route"], h["method"], h["client"]))


def _clean(raw: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "mailto:", "tel:", "javascript:", "#")):
        return None
    if raw.lower().endswith(_ASSET_EXT):
        return None
    return raw


# URLs / paths inside response-header values (CSP, Link).
_HDR_ABS = re.compile(r"https?://[^\s;,'\"<>()]+")
_HDR_PATH = re.compile(r"[<\s;,](/[A-Za-z0-9_\-./%~]{2,100})")


def extract_header_paths(headers: dict, base_url: str) -> set[str]:
    """Endpoints declared in response headers — free recon, no extra request.

    CSP (connect-src/form-action) and the Link header (rel=preload/prefetch)
    routinely name real same-host endpoints; we pull those out and scope them
    like any other seed.
    """
    host = urlparse(base_url).netloc
    out: set[str] = set()
    for name in ("content-security-policy", "content-security-policy-report-only",
                 "link", "x-pingback"):
        val = headers.get(name, "")
        if not val:
            continue
        for m in _HDR_ABS.findall(val):
            u = urlparse(m)
            if u.netloc and not same_host(u.netloc, host):
                continue                          # cross-host origin → drop
            p = _clean((u.path or "").split("?")[0])
            if p and p.startswith("/") and p != "/":
                out.add(p)
        for m in _HDR_PATH.findall(val):
            p = _clean(m.split("?")[0].split("#")[0])
            # root-absolute only: reject protocol-relative //host/… (off-host;
            # full same-site URLs are handled by the _HDR_ABS branch above)
            if p and p.startswith("/") and not p.startswith("//") and p != "/":
                out.add(p)
    return out


_LISTING_HREF = re.compile(rb'(?i)<a\s+[^>]*href\s*=\s*["\']?([^"\'>\s]+)')


def parse_listing(body: bytes, base_url: str) -> set[str]:
    """Extract the real entries (files + subdirs) from a server autoindex page.

    Resolves each `<a href>` against the listing's URL and keeps same-host paths
    — so a listing at /images/ with `href="logo.png"` yields `/images/logo.png`
    and `href="thumbs/"` yields `/images/thumbs/`. Sort links (`?C=N;O=D`), the
    parent link (`../`) and anything off-host are dropped. When autoindex is on,
    this gives the directory's TRUE contents — no brute-forcing required."""
    host = urlparse(base_url).netloc
    out: set[str] = set()
    for m in _LISTING_HREF.finditer(body or b""):
        href = m.group(1).decode("latin-1", "replace").strip()
        if not href or href[0] in "?#" or href in ("../", "./", "/") or href.startswith(".."):
            continue
        u = urlparse(urljoin(base_url, href))
        if u.netloc == host and u.path and u.path != urlparse(base_url).path:
            out.add(u.path)
    return out


def _looks_sourcemap(body: bytes) -> bool:
    """Cheap gate: a JSON object carrying `sourcesContent` (the original source)."""
    return body[:64].lstrip().startswith(b"{") and b'"sourcesContent"' in body


def parse_sourcemap(body: bytes) -> list[bytes]:
    """The original (un-minified) source blobs a JS source map embeds in
    `sourcesContent` — far richer for endpoint/param extraction than the shipped
    minified bundle (real route strings, comments, internal hosts). `[]` on a
    body that isn't a source map."""
    try:
        d = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return []
    if not isinstance(d, dict) or "mappings" not in d:
        return []
    return [c.encode("utf-8", "replace")
            for c in (d.get("sourcesContent") or []) if isinstance(c, str) and c]


def extract_paths(body: bytes, base_url: str, _depth: int = 0,
                  _endpoint_hints: list[dict] | None = None) -> set[str]:
    """Return same-host candidate paths (relative to base) found in `body`.

    A JS **source map** is transparently reconstructed: its `sourcesContent`
    (the original, un-minified source) is mined too, so `app.min.js.map` yields
    the routes the minified bundle buried. `_depth` caps that reconstruction so a
    crafted sourcemap-inside-sourcesContent can't recurse into a RecursionError."""
    host = urlparse(base_url).netloc
    endpoint_hints = (_endpoint_hints if _endpoint_hints is not None
                      else extract_endpoint_hints(body, base_url))
    found: set[str] = set()
    if _depth < 2 and _looks_sourcemap(body):
        for blob in parse_sourcemap(body):
            # `endpoint_hints` above already reconstructed sourcesContent. The
            # child still needs literal extraction, but must not parse the same
            # method-aware routes a second time on large source maps.
            found |= extract_paths(blob, base_url, _depth + 1, _endpoint_hints=[])

    def consider(s: str) -> None:
        cleaned = _clean(s)
        if cleaned is None:
            return
        s = cleaned
        if s.startswith(("http://", "https://", "//")):   # absolute OR protocol-relative URL
            u = urlparse(s)                  # urlparse("//evil.com/x") → netloc=evil.com
            if u.netloc and not same_site(u.netloc, host):
                return                       # third party → drop (incl. //evil.com)
            if not u.netloc or same_host(u.netloc, host):
                path = "/" + u.path.lstrip("/")      # same host → root-absolute path
            else:                            # same-site CDN → keep FULL URL (scope=site)
                scheme = u.scheme or urlparse(base_url).scheme or "https"  # // inherits page scheme
                path = f"{scheme}://{u.netloc}/{u.path.lstrip('/')}"
        else:
            # KEEP the leading-/ distinction: "/x" is root-absolute, "x/y" is
            # relative to the app base (e.g. an Angular templateUrl under /lms/).
            path = s
        # drop query/fragment — /x?a=1 and /x?b=2 are the SAME resource; the
        # param names are harvested separately as pentest intel.
        path = path.split("?")[0].split("#")[0]
        bare = path.lstrip("/")
        if bare and len(bare) <= 120 and " " not in path and "{" not in path:
            found.add(path)

    for rx in (_ABS, _ATTR, _CALL, _SOURCEMAP, _JS_REF):
        for m in rx.findall(body):
            consider(m.decode("latin-1"))
    for m in _TEMPLATE.findall(body):
        s = m.decode("latin-1")
        if "${" in s:
            rendered = _render_dynamic(s)
            # A runtime value inside the PATH cannot be safely guessed. Keep
            # the full template in endpoint intelligence instead of probing a
            # fabricated collapsed path (`/users/${id}/edit` -> `/users/edit`).
            if "{" in rendered.split("?", 1)[0]:
                continue
            s = _strip_template_exprs(s)
        # Root-absolute ("/x") OR a bare relative build ("sistema/x.aspx" — no
        # leading `${basePath}`, or one that got stripped above): an Angular/TS
        # client routinely builds its OWN endpoints this way (`${prefix}sistema/
        # acessotoken.aspx?token=${t}`). Require an actual '/' before any
        # query/frag so a plain non-path template ("Order-${orderId}", prose
        # with `${x}`) doesn't get treated as a candidate — those never
        # contain one.
        head = s.split("?")[0].split("#")[0]
        if head.startswith("/") or "/" in head:
            if not s.startswith("/"):
                # The stripped `${prefix}`/`${this.API}` (or an un-interpolated
                # literal following the same app convention) is the SITE
                # ORIGIN, not "wherever this scan happens to be rooted" —
                # resolving it relative to the current scan prefix instead
                # doubled a path segment on a real target
                # (sistema/acessotoken.aspx → .../sistema/sistema/…, a 404,
                # when the real working URL is .../sistema/acessotoken.aspx).
                s = "/" + s
            consider(s)
    # Add only fully static, method-aware routes that the simple literal
    # regexes cannot reconstruct (constant concatenation, axios baseURL).
    # Dynamic templates remain report-only and are never turned into probes.
    for hint in endpoint_hints:
        if not hint["template"]:
            consider(hint["route"])
    return found


def _harvest_query(q: bytes, out: set[str]) -> None:
    for pair in q.split(b"&"):
        name = pair.split(b"=")[0].decode("latin-1").strip()
        if _PARAM_NAME.match(name):
            out.add(name)


def extract_params(body: bytes) -> set[str]:
    """Harvest query parameter names from quoted URL-query strings — input
    surface for the pentester, not JS-token noise. Source maps are reconstructed
    (params mined from the original source too)."""
    out: set[str] = set()
    if _looks_sourcemap(body):
        for blob in parse_sourcemap(body):
            if not _looks_sourcemap(blob):          # one level only — no nested-map recursion
                out |= extract_params(blob)
    for q in _QUERY.findall(body):
        _harvest_query(q, out)
    # `${...}`-interpolated query values (`?a=${x}&b=${y}` in a template
    # literal) fail _QUERY outright — its char class deliberately excludes
    # `$`/`{`/`}` to avoid matching minified ternaries. Strip the
    # interpolations first (same as extract_paths) and re-run _QUERY against
    # the now-plain `?a=&b=` string — the param NAMES survive even though
    # their runtime values don't.
    for m in _TEMPLATE.findall(body):
        s = m.decode("latin-1")
        if "${" not in s or "?" not in s:
            continue
        stripped = _strip_template_exprs(s).encode("latin-1", "replace")
        for q in _QUERY.findall(b"`" + stripped + b"`"):
            _harvest_query(q, out)
    return out


def script_urls(body: bytes, base_url: str, limit: int = 40) -> list[str]:
    """App scripts worth fetching: same registrable domain (CDN included),
    third-party libs skipped, app bundles first. Also picks up RequireJS
    data-main (how SPAs point at their real bundle)."""
    host = urlparse(base_url).netloc
    cands: list[str] = []
    for rx in (_SCRIPT_SRC, _DATA_MAIN):
        for m in rx.findall(body):
            url = urljoin(base_url, m.decode("latin-1").strip())
            if same_site(urlparse(url).netloc, host) and url not in cands and not _is_vendor(url):
                cands.append(url)
    # app bundles first (highest endpoint yield), then the rest
    cands.sort(key=lambda u: 0 if _APP_HINT.search(u.rsplit("/", 1)[-1]) else 1)
    return cands[:limit]


# Public — folds.py also checks a wordlist candidate's extension against this
# to decide whether ITS fetch (independent of the harvest below) deserves the
# same elevated cap.
FOLLOW_EXT = (".js", ".mjs", ".map")
# App bundles (esp. webpack "common"/"vendor" chunks) routinely exceed the
# engine's default 2MB OOM-guard cap, which silently truncates the body mid
# stream — the same failure mode apidocs.py already raises SPEC_MAX_BODY for.
# Every fetch below is already scoped to a same-site .js/.mjs/.map file (never
# an arbitrary/hostile response), so a higher cap here is safe.
JS_MAX_BODY = 20_000_000


async def harvest(engine, base_url: str, root_body: bytes,
                  max_scripts: int = 40,
                  on_progress=None, endpoint_hints: list[dict] | None = None
                  ) -> tuple[set[str], set[str], list[tuple[str, str]]]:
    """Parse the root body and same-host scripts, following JS→JS references
    (webpack chunks, source maps) up to a fetch budget.

    Returns (paths, params, edges): paths to scan, query/template parameter
    names (pentest input-surface intel), and provenance edges
    (source_path, target_path) — root→script, root→path, script→path — for the
    endpoint graph.
    """
    host = urlparse(base_url).netloc
    root_src = urlparse(base_url).path or "/"
    hint_keys = {
        (h.get("source", ""), h.get("method", ""), h.get("route", ""), h.get("client", ""))
        for h in (endpoint_hints or [])
    }

    def record_hints(blob: bytes, source_url: str) -> list[dict]:
        extracted = extract_endpoint_hints(blob, base_url)
        if endpoint_hints is None:
            return extracted
        for hint in extracted:
            item = {"source": source_url, **hint}
            key = (item["source"], item["method"], item["route"], item["client"])
            if key not in hint_keys:
                endpoint_hints.append(item)
                hint_keys.add(key)
        return extracted

    def hint_params(items: list[dict]) -> set[str]:
        return {
            name for item in items
            for field in ("path_params", "query_params", "body_keys")
            for name in item.get(field, [])
            if _PARAM_NAME.fullmatch(name)
        }

    root_hints = record_hints(root_body, base_url)
    paths = extract_paths(root_body, base_url, _endpoint_hints=root_hints)
    params = extract_params(root_body) | hint_params(root_hints)
    edges: list[tuple[str, str]] = [(root_src, p) for p in paths]

    scripts = list(script_urls(root_body, base_url, limit=max_scripts))
    edges += [(root_src, urlparse(s).path) for s in scripts]       # root → <script src>
    queue = list(scripts)
    queue += [urljoin(base_url, p) for p in paths
              if p.endswith(FOLLOW_EXT) and not _is_vendor(p)]
    seen: set[str] = set()
    fetched = 0
    while queue and fetched < max_scripts:
        url = queue.pop(0)
        if url in seen or not same_site(urlparse(url).netloc, host):
            continue
        seen.add(url)
        pr = await engine.fetch(url, keep_body=True, max_body=JS_MAX_BODY)
        fetched += 1
        if pr.ok and pr.body:
            src = urlparse(url).path                                # the script we're in
            script_hints = record_hints(pr.body, url)
            new = extract_paths(pr.body, base_url, _endpoint_hints=script_hints)
            paths |= new
            params |= extract_params(pr.body) | hint_params(script_hints)
            edges += [(src, np) for np in new]                      # script → path
            for np in new:
                if np.endswith(FOLLOW_EXT) and not _is_vendor(np):
                    nxt = urljoin(base_url, np)
                    if nxt not in seen:
                        queue.append(nxt)
        if on_progress is not None:        # fills the live bar as scripts are scraped
            on_progress(fetched, min(max_scripts, fetched + len(queue)))
    return paths, params, edges
