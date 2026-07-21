"""JWT + OAuth authorization-weakness detection (passive).

When a response hands over a JWT — a token field in the body, a `Set-Cookie`
session, a `WWW-Authenticate`/`Authorization` header — or exposes an OAuth
authorization request (an authorize URL carrying `response_type` + `client_id`),
Origami decodes/parses it and flags the weaknesses visible WITHOUT forging
anything: the recon lead a JWT/OAuth attack starts from.

Strictly read-only — nothing is signed, forged, or replayed. What it flags:
  * JWT header — `alg:none` (no signature), `kid` path-traversal / URL-injection,
    `jku`/`x5u` remote-key URLs (SSRF / key injection), `x5c` embedded cert
    (RS/ES key-confusion surface);
  * JWT claims — missing `exp`, and privilege claims (`role`/`admin`/`scope`…);
  * OAuth authorize URL — missing `state` (CSRF), PKCE `plain` downgrade or no
    PKCE at all.
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qs, urlparse

# A JWT: base64url header `.` payload `.` signature. The signature may be EMPTY
# (that's exactly alg:none), so the third segment is optional.
_JWT = re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?")

# Response headers that carry tokens.
_TOKEN_HEADERS = ("set-cookie", "authorization", "www-authenticate",
                  "proxy-authenticate", "x-amzn-remapped-authorization", "x-auth-token")

# Privilege-bearing claim names — their VALUES are the evidence (role=admin…).
_PRIV_CLAIM = frozenset({
    "role", "roles", "is_admin", "isadmin", "admin", "scope", "scopes",
    "authorities", "groups", "permissions", "perms", "acl", "priv", "privileges"})

MAX_JWTS = 20


def _b64url(seg: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except (ValueError, TypeError):
        return None


def find_jwts(body: bytes, headers: dict | None = None) -> list[str]:
    """JWTs in a response body + token-bearing headers. Order-preserving, de-duped,
    capped. `headers` keys are expected lowercased (as the engine stores them)."""
    hay = body or b""
    if headers:
        for k in _TOKEN_HEADERS:
            v = headers.get(k)
            if v:
                hay = hay + b"\n" + v.encode("utf-8", "replace")
    out: list[str] = []
    seen: set[str] = set()
    for m in _JWT.finditer(hay):
        t = m.group(0).decode("ascii", "replace")
        if t.count(".") < 1 or t in seen:
            continue
        seen.add(t)
        out.append(t)
        if len(out) >= MAX_JWTS:
            break
    return out


def analyze_jwt(token: str) -> dict:
    """Decode a JWT (NO verification) and flag visible weaknesses. Returns
    `{alg, header, claims, issues, sensitive, sub}`; `issues` is a list of
    `(severity, text)` with severity in {high, med, low}. `{}` if it won't decode."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    hraw, praw = _b64url(parts[0]), _b64url(parts[1])
    try:                                           # a real JWT header decodes to a JSON object;
        header = json.loads(hraw) if hraw else None  # garbage that isn't one → not a JWT
    except (json.JSONDecodeError, ValueError):
        header = None
    if not isinstance(header, dict):
        return {}
    try:
        claims = json.loads(praw) if praw else {}
    except (json.JSONDecodeError, ValueError):
        claims = {}
    if not isinstance(claims, dict):
        claims = {}

    issues: list[tuple[str, str]] = []
    alg = str(header.get("alg", "")).strip()
    if alg.lower() in ("none", ""):
        issues.append(("high", "alg:none — signature not verified (forge any claim)"))

    kid = header.get("kid")
    if isinstance(kid, str) and kid:
        if "../" in kid or "..\\" in kid or kid.startswith("/"):
            issues.append(("high", f"kid path-traversal surface: {kid[:60]}"))
        elif "://" in kid:
            issues.append(("high", f"kid URL-injection / SSRF surface: {kid[:60]}"))
        elif re.search(r"['\";()|]|--|\bunion\b|\bselect\b", kid, re.I):
            issues.append(("med", f"kid injection surface (special chars): {kid[:60]}"))

    for h in ("jku", "x5u"):
        v = header.get(h)
        if isinstance(v, str) and v:
            issues.append(("high", f"{h} remote-key URL — SSRF / key injection: {v[:60]}"))
    if header.get("x5c"):
        issues.append(("med", "x5c embedded cert — RS/ES key-confusion surface"))

    if "exp" not in claims:
        issues.append(("low", "no exp — token does not expire"))

    sensitive = {k: claims[k] for k in claims if str(k).lower() in _PRIV_CLAIM}
    return {"alg": alg or "?", "header": header, "claims": claims,
            "issues": issues, "sensitive": sensitive, "sub": claims.get("sub")}


def _is_authorize_query(q: str) -> bool:
    return "client_id=" in q and "response_type=" in q


def find_oauth_issues(body: bytes, base_url: str | None = None) -> list[dict]:
    """OAuth authorization requests in a body → per-URL weakness flags. Matches an
    authorize URL by its query carrying both `response_type` and `client_id`."""
    text = (body or b"").decode("utf-8", "replace")
    out: list[dict] = []
    seen: set[str] = set()
    for m in re.finditer(r"""https?://[^\s"'<>\\]+""", text):
        u = m.group(0).rstrip('.,);"\'')
        q = urlparse(u).query
        if not _is_authorize_query(q) or u in seen:
            continue
        seen.add(u)
        params = parse_qs(q)
        issues: list[str] = []
        if "state" not in params or not (params.get("state") or [""])[0]:
            issues.append("missing state (CSRF / auth-code injection)")
        method = (params.get("code_challenge_method") or [""])[0].lower()
        if "code_challenge" not in params:
            issues.append("no PKCE (code_challenge absent)")
        elif method == "plain":
            issues.append("PKCE method=plain (S256→plain downgrade)")
        out.append({
            "url": u,
            "client_id": (params.get("client_id") or [""])[0],
            "redirect_uri": (params.get("redirect_uri") or [""])[0],
            "issues": issues,
        })
        if len(out) >= 10:
            break
    return out
