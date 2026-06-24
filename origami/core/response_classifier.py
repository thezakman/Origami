"""Response classifier — hit vs soft-404 (§3.6).

MVP is deterministic: a candidate is a hit when its response falls *outside*
the calibrated miss profile for its context (structural simhash + status +
redirect comparison, via baseline.looks_like_miss). A trained classifier over
these same features is a v3 upgrade, once v1/v2 have labelled data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from origami.core.baseline import (SIMHASH_MISS_DISTANCE, _redirect_kind, ext_class,
                                    looks_like_miss)
from origami.core.evidence import ContextBaseline, TargetProfile
from origami.core.httpclient import Probe
from origami.core.normalize import hamming
from origami.modules import waf


@dataclass(slots=True)
class Finding:
    url: str
    status: int
    length: int
    content_type: str
    confidence: float
    origin: str          # what produced the candidate: "priority" | "wordlist" | "recursion"
    note: str = ""
    tags: list[str] = field(default_factory=list)  # semantic: disclosure/config/auth/...
    simhash: int = 0     # body fingerprint — for same-content collision collapse


# needle → tag. A finding can carry several. Two needle kinds (see `_matches`):
#   * dot-needles (".bak", ".cs") match a real file EXTENSION or path segment —
#     so ".cs" tags Program.cs but NOT style.css, and ".git" tags /.git/HEAD;
#   * plain needles (substring) catch concatenated names too — Brazilian view
#     templates like `redefinirsenha` / `esqueciminhasenha` still hit "senha".
# Over-broad needles are deliberately avoided ("dashboard" tagged every user
# dashboard as admin; "import" hit "important", ".cs" hit ".css").
_TAG_RULES = [
    ("disclosure", (".env", ".git", ".svn", ".hg", ".bak", ".old", ".swp", ".swo",
                    ".orig", ".save", ".tmp", ".sql", ".sqlite", "dump", "backup",
                    "id_rsa", "id_dsa", ".htpasswd", "credential", ".ds_store",
                    ".key", ".pem", ".pfx", ".p12", ".crt", ".cer", ".ppk", ".ovpn",
                    ".kdbx", ".netrc", ".pgpass", "bash_history", "wp-config", ".tfstate")),
    ("config", ("web.config", ".htaccess", "appsettings", "composer.json",
                "package.json", ".npmrc", "config.php", "settings.py", ".ini",
                ".conf", ".cfg", "web.xml", ".properties", "nginx", "php.ini",
                "dockerfile", "docker-compose")),
    ("api", ("/api/", "swagger", "openapi", "graphql", "/v1/", "/v2/", "/v3/",
             "api-docs", ".wsdl", "/rest/", "/soap", "/rpc", "/jsonrpc")),
    ("admin", ("/admin", "administrator", "administrador", "wp-admin", "phpmyadmin",
               "adminer", "/manager/", "/cpanel", "/webadmin", "/admincp", "/console/")),
    ("auth", ("login", "signin", "sign-in", "signup", "register", "logon", "logout",
              "/auth", "oauth", "/sso", "saml", "senha", "password", "passwd",
              "cadastro", "recuperar", "redefinir", "esqueci", "autentica",
              "/2fa", "/otp", "/mfa")),
    ("upload", ("upload", "/uploads", "/files/", "attachment", "filemanager")),
    ("debug", ("phpinfo", "trace.axd", "actuator", "server-status", "server-info",
               "/debug", "elmah", "/_profiler", "/metrics", "/healthz")),
    ("source", (".java", ".rb", ".go", ".cs", ".py", ".pl", ".lua", ".inc",
                ".phps", ".kt", ".scala", ".class")),
]


_TOKEN_SEP = re.compile(r"[-_/.]+")


def _matches(path: str, needle: str) -> bool:
    """Match a tag needle against a URL path, tuned for low false positives.

      * dot-needle (".cs"): a real extension or whole segment — so ".cs" doesn't
        fire on ".css", and ".git" fires on /.git/HEAD;
      * slash-needle ("/auth", "/api/"): a literal path fragment (slash-anchored);
      * multi-part needle ("sign-in"): boundary-anchored — must sit between
        separators/edges, so it does NOT fire mid-word (the `sign-in` inside
        `de·sign-in·ovador` bug);
      * plain word ("login", "senha"): a substring of a single separator-delimited
        token — still catches concatenated names (`esqueciminha·senha`) but not a
        coincidental hit spanning a separator.
    """
    if needle.startswith("."):
        last = path.rsplit("/", 1)[-1]
        ext = ("." + last.rsplit(".", 1)[-1]) if "." in last else ""
        return ext == needle or last == needle or needle in path.split("/")
    if needle.startswith("/"):
        return needle in path
    if any(sep in needle for sep in "-_./"):    # multi-part (sign-in, id_rsa, web.config)
        return re.search(r"(?:^|[-_/.])" + re.escape(needle) + r"(?:$|[-_/.])", path) is not None
    return any(needle in tok for tok in _TOKEN_SEP.split(path))


def tag_finding(url: str, status: int) -> list[str]:
    p = urlparse(url).path.lower()
    tags = [tag for tag, needles in _TAG_RULES if any(_matches(p, n) for n in needles)]
    if status == 401 and "auth" not in tags:
        tags.append("auth")
    return tags


# Statuses that are never a found resource — handled at the engine level, not
# as a user filter: 404 = not found, 400 = bad request. Dropping them in
# classify (rather than in Filters) keeps soft-404 hosts from flagging a 404
# as a hit just because their baseline is a 200.
NOT_FOUND_STATUS = frozenset({400, 404})


# Directory-listing (autoindex) signatures — Apache/nginx mod_autoindex, IIS,
# Tomcat. Matched against the first bytes of the body (always captured), so no
# extra fetch is needed. High-signal anchors only, to keep false positives ~0.
_DIR_LISTING = re.compile(
    rb"(?i)<title[^>]*>\s*index of /"               # apache / nginx / litespeed
    rb"|<h1>\s*index of /"
    rb"|\[to parent directory\]"                    # IIS
    rb"|directory listing for /"                    # tomcat
    rb"|<a href=\"\?C=[NMSD];O=[AD]\""              # apache column-sort links
    rb"|>\s*parent directory\s*</a>"
)


def is_dir_listing(body: bytes) -> bool:
    """True if `body` looks like a server directory-index page (autoindex on)."""
    return bool(_DIR_LISTING.search(body or b""))


@dataclass
class Filters:
    """ffuf-style match/filter on status code and body size — PRESENTATION ONLY.

    Filters decide what gets *reported*, never what gets *scanned*: a filtered
    403 is still followed for recursion. 404/400 are dropped earlier, in
    classify, as engine truth.
    """
    match_codes: set[int] | None = None
    filter_codes: set[int] = field(default_factory=set)
    match_sizes: set[int] | None = None
    filter_sizes: set[int] | None = None

    def accept(self, status: int, length: int) -> bool:
        if self.match_codes is not None:
            return status in self.match_codes
        if status in self.filter_codes:
            return False
        if self.match_sizes is not None and length not in self.match_sizes:
            return False
        if self.filter_sizes and length in self.filter_sizes:
            return False
        return True


def _path_parts(url: str) -> tuple[str, str]:
    """(directory prefix, extension) for a candidate URL."""
    path = urlparse(url).path or "/"
    last = path.rsplit("/", 1)[-1]
    prefix = path[: len(path) - len(last)] or "/"
    ext = ""
    if "." in last:
        ext = "." + last.rsplit(".", 1)[-1]
    return prefix, ext


def resolve_baseline(profile: TargetProfile, url: str,
                     scan_prefix: str = "") -> ContextBaseline | None:
    """Best matching baseline for a candidate.

    The context is the *prefix being enumerated* (where miss behaviour was
    calibrated) plus the candidate's own extension class — NOT the candidate's
    own subdirectory. Using the candidate's dir would miss the calibrated
    prefix and fall back to root, turning every 403 under a protected dir into
    a false hit. Falls back to root baseline of the same ext_class only when
    the prefix genuinely wasn't calibrated.
    """
    own_prefix, ext = _path_parts(url)
    prefix = scan_prefix or own_prefix
    cls = ext_class(ext)
    key = TargetProfile.context_key(prefix, cls)
    if key in profile.baseline:
        return profile.baseline[key]
    return profile.baseline.get(TargetProfile.context_key("/", cls))


def classify(profile: TargetProfile, probe: Probe, origin: str,
             scan_prefix: str = "") -> Finding | None:
    """Return a Finding if the probe is a real hit, else None.

    Engine truth only — no user filters here (those are presentation, applied
    by the caller). A 404/400 is never a hit, regardless of baseline.
    """
    if not probe.ok or probe.status in NOT_FOUND_STATUS:
        return None

    # A redirect that LEAVES the requested path (→ /login, an auth wall, an SSO
    # gateway, a Firebase/SockJS transport) isn't a discovery hit. Keep only
    # self-redirects (/admin → /admin/) which reveal a real directory.
    if 300 <= probe.status < 400 and _redirect_kind(probe.url, probe.location) != "SELF":
        return None

    # WAF block page → never a hit (it's the firewall, not the app). Record the
    # product so the report surfaces it.
    blocked = waf.detect_block_body(probe.body_head)
    if blocked:
        if not profile.waf:
            profile.waf = blocked
        return None

    cb = resolve_baseline(profile, probe.url, scan_prefix)

    # Semantic tags only on accessible content (2xx). A 403 .htpasswd is blocked,
    # not leaked — tagging it "disclosure" reads like a finding when it isn't.
    tags = tag_finding(probe.url, probe.status) if 200 <= probe.status < 300 else []
    if 200 <= probe.status < 300 and is_dir_listing(probe.body_head):
        tags.append("listing")          # autoindex enabled — exposes the dir's files
    if cb is None:
        if probe.status in (200, 204, 301, 302, 401, 403, 405):
            return Finding(probe.url, probe.status, probe.length, probe.content_type,
                           0.5, origin, note="no-baseline", tags=tags,
                           simhash=probe.body_simhash)
        return None

    if looks_like_miss(probe, cb):
        return None

    confidence = _confidence(probe, cb)
    return Finding(probe.url, probe.status, probe.length, probe.content_type,
                   confidence, origin, tags=tags, simhash=probe.body_simhash)


def _confidence(probe: Probe, cb: ContextBaseline) -> float:
    """Heuristic confidence that a non-miss is a real hit."""
    # Different status family from a miss is a strong signal.
    if probe.status != cb.status:
        if probe.status in (200, 204):
            return 0.95
        if probe.status in (301, 302, 401, 403, 405):
            return 0.85
        return 0.7
    # Same status (soft-404 host) but structurally far from every miss body.
    if cb.simhashes:
        dist = min(hamming(probe.body_simhash, h) for h in cb.simhashes)
        # the further from the miss shape, the more confident
        return max(0.55, min(0.95, dist / 64 * 4))
    return 0.6
