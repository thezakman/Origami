"""JS / HTML endpoint harvesting (§3.7 "JS Feeding").

Extracts paths and endpoints from the root HTML and the same-host scripts it
references, then feeds them back as high-priority candidates. Pulling routes
straight out of the app's own JS is far higher-yield than guessing.

Regex-based and deliberately conservative: we keep things that look like
server paths (start with `/`, or relative endpoints with a known shape) and
drop obvious noise (assets we already have, data URIs, externals).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from origami.core.scope import same_host, same_site

# Quoted absolute paths: "/api/v1/users", '/admin/login'
_ABS = re.compile(rb"""["'`](/[A-Za-z0-9_\-./]{1,100})["'`]""")
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


def _is_vendor(url: str) -> bool:
    name = url.rsplit("/", 1)[-1]
    return bool(_VENDOR.search(name)) and not _APP_HINT.search(name)
# source maps + webpack/module chunk references (reveal more source files)
_SOURCEMAP = re.compile(rb"""sourceMappingURL=([^\s"'*]+)""", re.I)
_JS_REF = re.compile(rb"""["'`]([\w./-]+\.(?:js|mjs|json|map))["'`]""", re.I)
# query parameter names — ONLY from a quoted URL-query string ("…?a=1&b=2"),
# not from minified `a?b:c` ternaries, so the intel is real, not JS-token noise.
_QUERY = re.compile(rb"""["'`][^"'`\s]{0,200}\?([A-Za-z0-9_=&.%\[\]\-]+)["'`]""")
_PARAM_NAME = re.compile(r"^[a-z_][\w.\-]{0,39}$")

# Endings/segments that are just static assets — not interesting as routes.
# Note: .map (source maps) is deliberately NOT here — it's high-value recon.
_ASSET_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
              ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".avif")


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
            if p and p.startswith("/") and p != "/":
                out.add(p)
    return out


def extract_paths(body: bytes, base_url: str) -> set[str]:
    """Return same-host candidate paths (relative to base) found in `body`."""
    host = urlparse(base_url).netloc
    found: set[str] = set()

    def consider(s: str) -> None:
        s = _clean(s)
        if s is None:
            return
        if s.startswith(("http://", "https://")):   # absolute URL
            u = urlparse(s)
            if u.netloc and not same_site(u.netloc, host):
                return                       # third party → drop
            if not u.netloc or same_host(u.netloc, host):
                path = "/" + u.path.lstrip("/")      # same host → root-absolute path
            else:                            # same-site CDN → keep FULL URL (scope=site)
                path = f"{u.scheme}://{u.netloc}/{u.path.lstrip('/')}"
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
    return found


def extract_params(body: bytes) -> set[str]:
    """Harvest query parameter names from quoted URL-query strings — input
    surface for the pentester, not JS-token noise."""
    out: set[str] = set()
    for q in _QUERY.findall(body):
        for pair in q.split(b"&"):
            name = pair.split(b"=")[0].decode("latin-1").strip().lower()
            if _PARAM_NAME.match(name):
                out.add(name)
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


_FOLLOW_EXT = (".js", ".mjs", ".map")


async def harvest(engine, base_url: str, root_body: bytes,
                  max_scripts: int = 40,
                  on_progress=None) -> tuple[set[str], set[str], list[tuple[str, str]]]:
    """Parse the root body and same-host scripts, following JS→JS references
    (webpack chunks, source maps) up to a fetch budget.

    Returns (paths, params, edges): paths to scan, query/template parameter
    names (pentest input-surface intel), and provenance edges
    (source_path, target_path) — root→script, root→path, script→path — for the
    endpoint graph.
    """
    host = urlparse(base_url).netloc
    root_src = urlparse(base_url).path or "/"
    paths = extract_paths(root_body, base_url)
    params = extract_params(root_body)
    edges: list[tuple[str, str]] = [(root_src, p) for p in paths]

    scripts = list(script_urls(root_body, base_url, limit=max_scripts))
    edges += [(root_src, urlparse(s).path) for s in scripts]       # root → <script src>
    queue = list(scripts)
    queue += [urljoin(base_url, p) for p in paths
              if p.endswith(_FOLLOW_EXT) and not _is_vendor(p)]
    seen: set[str] = set()
    fetched = 0
    while queue and fetched < max_scripts:
        url = queue.pop(0)
        if url in seen or not same_site(urlparse(url).netloc, host):
            continue
        seen.add(url)
        pr = await engine.fetch(url, keep_body=True)
        fetched += 1
        if pr.ok and pr.body:
            src = urlparse(url).path                                # the script we're in
            new = extract_paths(pr.body, base_url)
            paths |= new
            params |= extract_params(pr.body)
            edges += [(src, np) for np in new]                      # script → path
            for np in new:
                if np.endswith(_FOLLOW_EXT) and not _is_vendor(np):
                    nxt = urljoin(base_url, np)
                    if nxt not in seen:
                        queue.append(nxt)
        if on_progress is not None:        # fills the live bar as scripts are scraped
            on_progress(fetched, min(max_scripts, fetched + len(queue)))
    return paths, params, edges
