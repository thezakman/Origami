"""Authentication-state check — did your `-H` credentials actually take?

A common silent failure in authenticated scans: you paste a `Cookie:` or
`Authorization:` header that's stale, wrong, or for the wrong host, and the whole
scan runs *unauthenticated* — every protected path 401s/redirects and you only
notice at the end. This catches it up front: when auth headers ARE supplied but
the root still looks like an auth wall (401, a redirect to a login page, or a
login form served at /), warn loudly that the session probably isn't working.

Deliberately conservative — it only speaks when you SAID you're authenticating,
so it can't false-alarm on a normal site whose homepage happens to be a login.
"""

from __future__ import annotations

import re

# Header names that carry a session / credential.
_AUTH_HEADERS = {"cookie", "authorization", "x-api-key", "x-auth-token",
                 "x-csrf-token", "x-access-token", "x-session-token"}

# A Location / path that points at a login / SSO flow.
_LOGIN_RE = re.compile(
    r"(?i)(?:/login|/signin|/sign-in|/sign_in|/account/login|/users/sign_in"
    r"|/wp-login|/session/new|/auth\b|/sso\b|/oauth|/saml|/adfs|/openid|/idp/)")

# A password input in the served body → a login form.
_PW_FORM = re.compile(rb"(?i)<input[^>]+type=[\"']?password")


def has_auth(headers) -> bool:
    """True if the request headers carry a session/credential."""
    return any(k.lower() in _AUTH_HEADERS for k in (headers or {}))


def auth_wall_reason(probe, base_url: str = "") -> str | None:
    """Why the root looks like an auth wall (for the warning), or None if it
    looks authenticated. Only the caller should gate this on has_auth()."""
    if probe is None or not probe.ok:
        return None
    if probe.status in (401, 407):
        return f"root returned {probe.status} (not authenticated)"
    if probe.status in (301, 302, 303, 307, 308) and probe.location:
        if _LOGIN_RE.search(probe.location):
            return f"root redirects to a login page ({probe.location})"
    if 200 <= probe.status < 300 and probe.body_head and _PW_FORM.search(probe.body_head):
        return "a login form is served at the root"
    return None
