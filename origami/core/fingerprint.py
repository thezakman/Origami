"""Fingerprint — additive, confidence-weighted, evidence-driven (§3.2).

Applies the KB's signals against observed responses (the root probe plus a
couple of forced-error probes) and feeds every match into the profile's
evidence bus. It does *not* segment the attack — it only enriches. The
scheduler decides what to do with confirmed techs.

Signals are matched against headers, Set-Cookie values, and (for error-page
fingerprints) the body head. All case-insensitive.
"""

from __future__ import annotations

import base64
from urllib.parse import urljoin

from origami.brain.kb import Signal, TechRule
from origami.core.evidence import Evidence, TargetProfile
from origami.core.httpclient import Engine, Probe

try:
    import mmh3
except ImportError:
    mmh3 = None   # type: ignore[assignment]  # optional dep; favicon-hash fp degrades gracefully

# Tiny seed map of Shodan-style favicon mmh3 hashes → tech. The full DB
# (FingerprintHub) is a v2 ingestion; even without a match we surface the hash
# so the user can pivot on it.
KNOWN_FAVICONS: dict[int, str] = {
    81586312: "tomcat",
    -297069493: "jenkins",
    116323821: "gitlab",
    -1255347784: "jira",
    1485257654: "grafana",
}


# Body needles that are ordinary words in normal HTML/prose (or JSON content),
# not stack markers. The ingested Wappalyzer layer flattened context-bearing
# patterns (a tag/attribute regex) down to bare substrings, so as *standalone*
# body signals these fire on any sizeable body: `input`/`hidden` sit in every
# HTML form, `website` rides inside URLs (azureWEBSITEs.net), `tecnologia`/
# `framework`/`version` are page copy. A tech that truly matches still confirms
# through its own specific signals (a cookie, a header, a distinctive marker);
# refusing these lone words just stops the false chips. (Curated, lowercase.)
_GENERIC_BODY_NEEDLES: frozenset[str] = frozenset({
    # form / control words (every HTML form has them)
    "input", "hidden", "button", "form", "field", "value", "label", "select",
    "submit", "checkbox", "radio", "option", "textarea",
    # markup-structure tokens (present in essentially every HTML document — the
    # `/title` -> `</title>` family, matched after stripping markup punctuation)
    "html", "head", "body", "title", "div", "span", "meta", "link", "href",
    "src", "class", "style", "script", "data", "type", "name", "charset",
    "content", "header", "footer", "section", "nav", "main", "article",
    # generic page / product / prose words
    "website", "tecnologia", "tecnologias", "framework", "version", "platform",
    "copyright", "powered", "application", "software", "commerce", "ecommerce",
    "builder", "analytics", "bootstrap", "stylesheet", "template", "container",
    "wrapper", "sidebar", "navigation", "menu", "widget", "search", "login",
    "logout", "register", "password", "email", "gallery", "comment", "category",
    "payment", "checkout", "shipping", "product", "service", "module", "project",
    "decimal", "epoch", "description", "keywords", "author", "image", "video",
    "audio", "price", "cart", "shop", "store", "blog", "page", "site", "theme",
    "plugin", "editor", "solucoes", "solucao", "bundle", "bundles", "vendor",
    "runtime", "polyfill", "manifest", "assets", "static", "dist", "build",
})

# Public CDN bases. A body needle that is merely `<cdn>/` (or `<cdn>/npm/`) means
# "this page loads *something* from a shared CDN" — a CDN reference, never proof
# of the specific library the ingested rule attached it to (jsDelivr serving a
# font does not make a page "echarts"). A rule's SPECIFIC asset path
# (`cdnjs.cloudflare.com/ajax/libs/Chart.js/`) is untouched and still fingerprints.
_CDN_HOSTS: frozenset[str] = frozenset({
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "code.jquery.com",
    "ajax.googleapis.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "cdn.skypack.dev", "esm.sh", "ajax.aspnetcdn.com",
})


def _is_bare_cdn_needle(stripped: str) -> bool:
    """`cdn.jsdelivr.net`, `cdn.jsdelivr.net/`, `unpkg.com/npm/` … — a CDN base with
    no library-specific path. True → the needle proves only "uses a CDN", not a tech."""
    s = stripped.rstrip("/")
    if s.endswith("/npm"):
        s = s[:-4]
    return s in _CDN_HOSTS

# markup / whitespace punctuation stripped from a needle's ends before the
# generic-word check, so `/title`, `</title>`, `title>` all normalise to `title`.
# Internal `-`/`_` stay, so `data-nette-rules` / `__NEXT_DATA__` keep their shape.
_NEEDLE_EDGE = "/<>=\"' \t.:;#&?!()[]{}|"

# Content types where an HTML/document body fingerprint is meaningless — a JSON
# API, a script/style asset, an image/font/binary blob. Body signals (curated
# for HTML) are skipped on these: a `"Tecnologia"` category name inside a JSON
# record, or `website` inside an azurewebsites URL, is not a stack marker.
def _body_fingerprintable(content_type: str) -> bool:
    ct = (content_type or "").lower()
    if not ct:
        return True                                   # unknown → allow (be permissive)
    return not any(m in ct for m in (
        "json", "javascript", "ecmascript", "/css", "image/", "font/",
        "audio/", "video/", "octet-stream", "pdf", "zip", "protobuf",
        "grpc", "wasm",
    ))


def _body_contains(needle: str, hay: str) -> bool:
    """Substring match, but word-boundary-aware for alphanumeric-edged needles so
    a token doesn't match inside a longer word: `website` must not hit inside
    `azurewebsites`, `wix` must not hit inside `wixster`. Needles with punctuation
    edges (`data-nette-rules`, `<script`) keep plain-substring behaviour."""
    if not (needle[0].isalnum() and needle[-1].isalnum()):
        return needle in hay
    n = len(needle)
    start = 0
    while True:
        i = hay.find(needle, start)
        if i < 0:
            return False
        before = hay[i - 1] if i > 0 else " "
        after = hay[i + n] if i + n < len(hay) else " "
        if not _is_word_char(before) and not _is_word_char(after):
            return True
        start = i + 1


def _is_word_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def _signal_hit(sig: Signal, probe: Probe) -> str | None:
    """Return a human-readable detail if the signal matches, else None."""
    needle = sig.match.lower()
    if sig.type == "header":
        val = probe.headers.get(sig.name.lower())
        if val is None:
            return None
        if needle == "" or needle in val.lower():
            return f"{sig.name}: {val}"
        return None
    if sig.type == "cookie":
        for c in probe.cookies:
            if needle in c.lower():
                return f"Set-Cookie: {c.split(';')[0]}"
        return None
    if sig.type == "body":
        stripped = needle.strip(_NEEDLE_EDGE)
        if not needle or stripped in _GENERIC_BODY_NEEDLES or _is_bare_cdn_needle(stripped):
            return None                               # empty / generic word / bare CDN ref
        if not _body_fingerprintable(probe.content_type):
            return None                               # JSON/asset/binary body → not HTML fp
        if _body_contains(needle, probe.body_head.lower().decode("latin-1")):
            return f"body~={sig.match!r}"
        return None
    return None


# Default error/landing page → stack (the 0xdf-404 catalogue idea, §3.2). These
# strings appear in a server/framework's *default* error body, so they
# fingerprint the stack even when the Server header is stripped (CDN/WAF) — the
# hard real-world case. Matched ONLY against forced-error probes (high precision:
# the probe responses ARE error pages, not content). (needle, tech, weight).
_ERROR_PAGE_SIGNS: list[tuple[str, str, float]] = [
    ("<center>nginx</center>", "nginx", 60),
    ("<address>apache", "apache", 60),
    ("apache tomcat/", "tomcat", 70),
    ("powered by jetty", "jetty", 70),
    ("cannot get /", "express", 65),                       # Express default 404
    ("whitelabel error page", "springboot", 80),           # Spring Boot
    ("you're seeing this error because you have", "django", 75),  # Django DEBUG
    ("werkzeug", "flask", 55),                             # Werkzeug (Flask) traceback/debugger
    ("whoops, looks like something went wrong", "laravel", 70),
    ("server error in '/' application", "aspnet", 70),     # ASP.NET YSOD
    ("<b>fatal error</b>", "php", 55),                     # PHP fatal error
    ("internet information services", "iis", 55),
]


def apply_error_signals(profile: TargetProfile, error_probes: list[Probe],
                        path_prefix: str = "/") -> None:
    """Fingerprint the stack from default error-page bodies (header-independent).

    De-dupes per tech so one stack matched on several probes scores once.
    """
    seen: set[str] = set()
    for probe in error_probes:
        if not probe.ok or not probe.body_head:
            continue
        body = probe.body_head.lower().decode("latin-1", "replace")
        for needle, tech, weight in _ERROR_PAGE_SIGNS:
            if tech in seen:
                continue
            if needle in body:
                seen.add(tech)
                profile.add_evidence(Evidence(
                    source="error_page", tech=tech,
                    detail=f"default error page ~= {needle!r}",
                    weight=weight, path_prefix=path_prefix))


def apply_signals(profile: TargetProfile, probes: list[Probe], kb: list[TechRule],
                  path_prefix: str = "/") -> None:
    """Match every rule's signals against every probe; emit evidence.

    De-dupes within a single (tech, signal) so the same Server header seen on
    five probes doesn't quintuple the score.
    """
    for rule in kb:
        for sig in rule.signals:
            for probe in probes:
                if not probe.ok:
                    continue
                detail = _signal_hit(sig, probe)
                if detail:
                    profile.add_evidence(Evidence(
                        source=sig.type, tech=rule.tech, detail=detail,
                        weight=sig.weight, path_prefix=path_prefix,
                    ))
                    break  # one hit per signal is enough


async def forced_error_probes(engine: Engine, base_url: str) -> list[Probe]:
    """Force a few error responses whose default bodies fingerprint the stack.

    Uses the 0xdf 404-page catalogue idea: default 400/404/500 bodies are
    distinguishable per server/framework.
    """
    urls = [
        urljoin(base_url, "%ff%fe"),                      # malformed -> 400 on many stacks
        urljoin(base_url, "a" * 200 + ".aspx"),           # nonexistent handler
        urljoin(base_url, "../../../../etc/passwd"),      # traversal -> 400/403 default page
    ]
    return [p for p in await engine.gather(urls) if p.ok]


async def favicon_fingerprint(engine: Engine, base_url: str,
                              profile: TargetProfile) -> int | None:
    """Compute the Shodan-style favicon mmh3 hash; emit evidence if known.

    Returns the hash (or None). The hash itself is valuable intel even when
    unmatched — it identifies a product/version across a whole fleet.
    """
    if mmh3 is None:
        return None
    p = await engine.fetch(urljoin(base_url, "favicon.ico"), keep_body=True)
    if not (p.ok and p.status == 200 and p.body):
        return None
    h = mmh3.hash(base64.encodebytes(p.body))
    tech = KNOWN_FAVICONS.get(h)
    if tech:
        profile.add_evidence(Evidence(source="favicon", tech=tech,
                                      detail=f"favicon mmh3={h}", weight=70))
    return h


def confirmed_actions(profile: TargetProfile, kb: list[TechRule],
                      threshold: float = 50.0) -> tuple[set[str], list[str], set[str]]:
    """For confirmed techs, fold in extensions/priority paths/folds.

    Returns (extensions, priority_paths, folds). Also writes the extensions
    onto the profile so the scheduler can read them directly.
    """
    confirmed = set(profile.confirmed_techs(threshold))
    exts: set[str] = set()
    paths: list[str] = []
    folds: set[str] = set()
    for rule in kb:
        if rule.tech in confirmed:
            exts.update(rule.extensions)
            paths.extend(rule.priority_paths)
            folds.update(rule.folds)
    profile.enabled_extensions.update(exts)
    # de-dupe priority paths, preserve order
    seen, ordered = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return exts, ordered, folds
