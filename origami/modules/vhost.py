"""Virtual-host discovery — a discovery dimension orthogonal to paths.

One IP often serves many sites, routed by the `Host` header: an admin panel, a
staging build, an internal API the public DNS never points at. Behind a CDN/WAF
(Cloudflare, AWS), the edge forwards the Host you send, so probing alternate
Hosts against the same endpoint surfaces vhosts the path scan can't see.

`candidates()` builds Host values from the target's registrable domain (common
sub-host prefixes) plus standalone internal names. The scanner calibrates a bogus
Host (the catch-all for unknown vhosts) and reports any candidate whose response
differs from BOTH that baseline and the default site — a genuinely distinct vhost.
"""

from __future__ import annotations

# Common sub-host prefixes that front a distinct app on the same infrastructure.
_PREFIXES = (
    "admin", "staging", "stage", "dev", "test", "qa", "uat", "demo", "internal",
    "intranet", "api", "api-internal", "portal", "beta", "preprod", "sandbox",
    "old", "new", "backup", "bak", "vpn", "git", "gitlab", "jenkins", "ci",
    "grafana", "kibana", "jira", "confluence", "monitor", "status", "metrics",
    "secret", "private", "corp", "origin", "direct", "www", "web", "app",
    "dashboard", "manage", "console", "auth", "sso", "vault",
)

# Hosts worth trying verbatim (internal routing / default-vhost reveals).
_STANDALONE = ("localhost", "internal", "intranet", "admin", "default")

# Registrable-domain suffixes that span two labels (so the apex is the last THREE).
_MULTI_SUFFIX = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.kr", "co.in", "co.za",
    "co.nz", "com.au", "com.br", "net.br", "org.br", "gov.br", "com.mx",
    "com.ar", "com.tr", "com.cn", "com.sg", "com.hk", "com.tw",
})


def registrable(host: str) -> str:
    """Best-effort registrable domain (apex), handling common 2-label suffixes."""
    host = host.split(":")[0].strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def candidates(host: str, extra=()) -> list[str]:
    """Host header candidates for `host` (deduped; the target itself excluded)."""
    host = host.split(":")[0].strip(".").lower()
    base = registrable(host)
    out: list[str] = []
    seen: set[str] = set()

    def add(h: str) -> None:
        h = h.strip(".").lower()
        if h and h != host and h not in seen:
            seen.add(h)
            out.append(h)

    for p in _PREFIXES:
        add(f"{p}.{base}")
    add(base)                       # the bare apex (target may be www.x → try x)
    for s in _STANDALONE:
        add(s)
    for e in extra:                 # harvested / learned hostnames
        add(e)
    return out
