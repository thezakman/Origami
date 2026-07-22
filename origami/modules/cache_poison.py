"""Web cache poisoning detection — safe primitive detection (no real-key write).

Cache poisoning: a request input the cache treats as UNKEYED (a header like
`X-Forwarded-Host`, a locale, a custom header) is ignored when the cache builds
its cache KEY but is still processed and REFLECTED by the origin — so the cache
stores and later serves an attacker-influenced response to OTHER users. Classic
Param-Miner / James-Kettle territory.

Origami detects the *primitive* — unkeyed + reflected + cacheable — and stops
there. It NEVER poisons the cache key real users hit: every active probe rides a
unique throwaway cache-buster (`?cb=<token>`), so our traffic lands on isolated
cache entries no real user requests, and the cacheability confirmation re-fetches
that SAME throwaway key. Because the header is unkeyed for the real key and the
sandbox key alike, proving it on the sandbox faithfully demonstrates the bug
without touching production. Weaponizing it (serving the poisoned response to
third parties) is the human's job — out of scope for an automated scanner.

Pure helpers here (cache-layer detection / cacheability / header sets); the
scanner fold (`_cache_poison_fold`) does the fetching.
"""

from __future__ import annotations

from urllib.parse import urlparse

# --- cache-layer / cacheability fingerprint (pure, header-only) --------------

# Vendor → the response headers that give it away. Order matters: the most
# specific signatures are checked first so a Fastly-on-Varnish stack reads as
# "fastly", not "varnish".
_CDN_SIGNATURES = (
    ("cloudflare", ("cf-ray", "cf-cache-status")),
    ("fastly",     ("x-served-by", "x-fastly-request-id", "fastly-debug-digest")),
    ("akamai",     ("x-akamai-transformed", "x-akamai-request-id", "akamai-grn")),
    ("varnish",    ("x-varnish",)),
    ("cloudfront", ("x-amz-cf-id", "x-amz-cf-pop")),
    ("google",     ("x-goog-cache-status",)),
)
# Generic "there is a cache in front" markers — used only if no vendor matched.
_GENERIC_CACHE_HEADERS = ("x-cache", "x-cache-hits", "age", "x-cache-status",
                          "cdn-cache-control", "cache-status")


def detect_cache_layer(headers: dict[str, str]) -> str:
    """Name the CDN/cache layer from response headers (lowercased keys), or "".

    Cheap, header-only — reads what every probe already captured, so it can run
    on the root response with zero extra requests."""
    h = headers or {}
    for name, keys in _CDN_SIGNATURES:
        if any(k in h for k in keys):
            return name
    # vendor strings sometimes only appear in Server / Via
    sv = (h.get("server", "") + " " + h.get("via", "")).lower()
    for vendor in ("cloudflare", "varnish", "akamai", "fastly"):
        if vendor in sv:
            return vendor
    if any(k in h for k in _GENERIC_CACHE_HEADERS):
        return "cache"
    return ""


def cache_status(headers: dict[str, str]) -> str:
    """"HIT" / "MISS" / "" distilled from the common cache-status headers.

    Cloudflare uses `cf-cache-status: HIT|MISS|EXPIRED|DYNAMIC|…`; Varnish/Fastly/
    nginx expose `x-cache: HIT|MISS` (possibly multi-layer, e.g. "HIT, MISS")."""
    h = headers or {}
    blob = " ".join(h.get(k, "") for k in
                    ("cf-cache-status", "x-cache", "x-cache-status", "cache-status",
                     "x-goog-cache-status")).lower()
    if "hit" in blob:
        return "HIT"
    if "miss" in blob or "expired" in blob or "dynamic" in blob or "bypass" in blob:
        return "MISS"
    return ""


def provably_uncacheable(headers: dict[str, str]) -> bool:
    """The response the origin/edge will PROVABLY not store — so it can't be
    poisoned. `Cache-Control: no-store/private/no-cache`, or an edge status that
    says "not cached" (`cf-cache-status: DYNAMIC|BYPASS`). Distinct from an
    ambiguous `MISS` (cacheable, just not stored yet) which stays a lead."""
    h = headers or {}
    cc = (h.get("cache-control") or "").lower()
    if "no-store" in cc or "private" in cc or "no-cache" in cc:
        return True
    raw = ((h.get("cf-cache-status") or "") + " " + (h.get("x-cache-status") or "")).lower()
    return "dynamic" in raw or "bypass" in raw


def is_cacheable(headers: dict[str, str]) -> bool:
    """Conservative "could this response be stored by a shared cache?".

    Explicit `no-store`/`private`/`no-cache` → no. Explicit `public`/`max-age`/
    `s-maxage`, a present `age`, an observed cache HIT, or an `expires` → yes.
    Anything ambiguous → no (we'd rather skip than chase an uncached endpoint)."""
    h = headers or {}
    cc = h.get("cache-control", "").lower()
    if "no-store" in cc or "private" in cc or "no-cache" in cc:
        return False
    if "s-maxage" in cc or "max-age" in cc or "public" in cc:
        return True
    if "age" in h or cache_status(h) == "HIT" or "expires" in h:
        return True
    return False


# --- unkeyed-input header sets ------------------------------------------------
#
# Each entry is (header-name, value-template). A "{canary}" in the template is
# replaced per-probe with a unique benign token so a reflection maps straight
# back to the header (and so the confirmation can spot it served from cache).
# Templates WITHOUT a "{canary}" carry a fixed value (scheme/port/ip/method
# flips): those have no unique marker, so their signal is "the response differs
# from the cache-busted baseline" — i.e. the input is unkeyed but processed.

# ~6 highest-signal headers — the host/URL-override family behind most real bugs.
UNKEYED_LIGHT = [
    ("X-Forwarded-Host", "{canary}.example.com"),
    ("X-Host", "{canary}.example.com"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Forwarded-Proto", "http"),
    ("X-Original-URL", "/{canary}"),
    ("X-Rewrite-URL", "/{canary}"),
]

# ~16 — adds the rest of the forwarding/override family + locale.
UNKEYED_AUTO = UNKEYED_LIGHT + [
    ("X-Forwarded-Server", "{canary}.example.com"),
    ("X-Original-Host", "{canary}.example.com"),
    ("X-Forwarded-Prefix", "/{canary}"),
    ("X-Forwarded-Port", "1337"),
    ("X-Forwarded-Ssl", "off"),
    ("Forwarded", "host={canary}.example.com"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-HTTP-Method-Override", "GET"),
    ("Accept-Language", "{canary}"),
    ("X-Wap-Profile", "http://{canary}.example.com/wap.xml"),
]

# Exhaustive ("full") — IP-trust variants, multi-value tricks, more echo vectors.
UNKEYED_FULL = UNKEYED_AUTO + [
    ("X-Forwarded-Scheme", "nothttps"),
    ("True-Client-IP", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("Fastly-Client-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("X-Original-URL", "/{canary}/.."),
    ("Origin", "https://{canary}.example.com"),
    ("X-Forwarded-Host", "{canary}.example.com, internal"),
    ("User-Agent", "{canary}-ua"),
    ("X-Timezone", "{canary}"),
    ("X-Country-Code", "{canary}"),
    ("X-Forwarded-Path", "/{canary}"),
]

_SETS = {"light": UNKEYED_LIGHT, "auto": UNKEYED_AUTO, "full": UNKEYED_FULL}


def header_set(intensity: str = "auto",
               extra_pairs: list[tuple[str, str]] | None = None
               ) -> list[tuple[str, str]]:
    """Pick the unkeyed-header probe set for an intensity, optionally extended
    with a user wordlist (`extra_pairs`, from `bypass403.load_header_pairs`).
    Custom pairs carry literal values (no canary) → matched on the differ signal.
    Deduped by (lower-cased name, value): same header+value = same wire request."""
    out = list(_SETS.get(intensity, UNKEYED_AUTO))
    if extra_pairs:
        seen = {(n.lower(), v) for n, v in out}
        for n, v in extra_pairs:
            if (n.lower(), v) not in seen:
                out.append((n, v))
                seen.add((n.lower(), v))
    return out


def has_canary(template: str) -> bool:
    return "{canary}" in template


def with_buster(url: str, token: str) -> str:
    """Append a unique cache-buster query param — the throwaway sandbox key that
    keeps every probe off the cache entry real users hit."""
    sep = "&" if urlparse(url).query else "?"
    return f"{url}{sep}cb={token}"


def canary_in_headers(headers: dict[str, str], canary: str) -> bool:
    """True if the canary echoes in any response header value (Location, og:url
    redirects, etc.) — case-insensitive."""
    c = canary.lower()
    return any(c in (v or "").lower() for v in (headers or {}).values())
