"""Scanner — the orchestration loop (§2 pipeline).

calibrate → fingerprint → fold (enable extensions + priority paths) →
scan prefix → classify → recurse into discovered directories → findings.

Scope/recursion are bounded (§3.11): same host, depth cap, request cap.
"""

from __future__ import annotations

import asyncio
import random
import string
import time
from collections import defaultdict
from dataclasses import dataclass, field
from fnmatch import fnmatch
from urllib.parse import urljoin, urlparse

# More than this many byte-identical results (same status+simhash) = a catch-all
# or generic page; collapse to one representative + a count.
COLLISION_MAX = 4
# Blocked/erroring statuses whose identical-body flood is a generic wall — a 403
# block page forbidding every .env*/.git*, or a 5xx upstream-down page served for
# every path (a dead backend, not per-path signal). Muted in the live stream past
# COLLISION_MAX. 2xx/3xx are left to the end-of-scan collapse (keyed on length).
_WALL_STATUS = frozenset({401, 403, 405, 500, 502, 503, 504})
# Origins that come from a DECLARED contract (an OpenAPI/Swagger spec, a
# .well-known index) — a bounded, curated set where every path is a real, named
# endpoint. A 401/403 on one is high-value intel ("exists, needs auth"), not a
# generic-wall flood, so these are exempt from block-wall muting AND the
# same-(status,length) report collapse: the full API surface stays visible.
_DECLARED_ORIGINS = frozenset({"apidocs", "wellknown"})
MAX_BACKUP_FILES = 80   # cap files the backup fold expands around

from origami.brain.bandit import Ranker as Bandit
from origami.brain.bandit import word_of
from origami.brain.kb import load_kb
from origami.brain.ngram import NGram
from origami.core import baseline as bl
from origami.core import overlays
from origami.core import resume as resume_mod
from origami.core import fingerprint as fp
from origami.core.evidence import Evidence, TargetProfile
from origami.core.httpclient import Engine
from origami.core.normalize import hamming, simhash
from origami.core.response_classifier import (NOT_FOUND_STATUS, Filters, Finding,
                                               classify, is_dir_listing, resolve_baseline)
from origami.core.scope import same_host, same_site, path_tenant_host, same_tenant_path
from origami.core.scheduler import (BASE_EXTS, Candidate, build_candidates,
                                     derive_vocabulary, load_wordlists,
                                     target_tokens)
from origami.modules import bypass403, cache_poison, leaks, paramfuzz, secrets, session, vhost, waf
from origami.modules.discovery import (apidocs, apiver, backups, buckets, clientapp,
                                        graphql, js_parser, methods, mutate, originip,
                                        robots, shortname, vcs, wayback, wellknown)
from origami.output.ui import NullObserver

# Extension classes we always calibrate at a prefix before scanning it.
_BASE_CALIB_EXTS = ["", ".txt", ".html"]


def _ext_of(path: str) -> str:
    last = path.rstrip("/").rsplit("/", 1)[-1]
    return ("." + last.rsplit(".", 1)[-1]) if "." in last else ""


def _ext_excluded(path: str, patterns) -> bool:
    """True if `path`'s file extension matches a `--exclude-ext` glob (e.g. `jpg`,
    `png`, `jpg*`). Directories (no extension) are never excluded by this."""
    if not patterns:
        return False
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if "." not in last:
        return False
    ext = last.rsplit(".", 1)[-1].lower()
    return any(fnmatch(ext, pat) for pat in patterns)


# Sanity ceiling on harvested seeds. These are REAL references the app uses
# (high value), so the cap is generous — overall volume is bounded by
# --max-requests, not by starving the best candidates.
MAX_HARVEST_SEEDS = 2000
MAX_WAYBACK_SEEDS = 2000   # cap historical (Wayback/gau) paths folded as candidates
WAYBACK_BUDGET = 12.0      # total wall-clock budget for the (optional) history lookup —
                           # bounds how long the scan will BLOCK on it before starting


def _host_root(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}/"


def _join_candidate(root: str, prefix: str, path: str) -> str:
    """Build the absolute URL for a candidate path.

    An absolute-URL candidate (a same-site CDN seed) is used as-is; a leading-/
    path is root-absolute; anything else resolves under `prefix`.

    Uses `startswith`, NOT `"://" in path`: a wordlist/payload candidate whose
    body merely CONTAINS `://` (e.g. a Struts2 OGNL `${...http://x...}`) is still
    a relative path — treating it as an absolute URL sends a schemeless URL to
    httpx and crashes the scan. Here it becomes `https://host/${...}` (absolute),
    which is what a vuln payload should be anyway.
    """
    if path.startswith(("http://", "https://")):
        return path
    if path.startswith("/"):
        return urljoin(root, path.lstrip("/"))
    return urljoin(root, prefix.lstrip("/") + path)


def _excluded(path: str, opts) -> bool:
    """True if `path` matches a user `--exclude` pattern (case-insensitive
    substring) — never fired, never recursed. Safety rail for destructive or
    out-of-scope endpoints (/logout, /delete, /admin/shutdown)."""
    if _ext_excluded(path, getattr(opts, "exclude_ext", ())):
        return True                       # --exclude-ext: drop static assets (jpg/png/css…)
    if not opts.exclude:
        return False
    low = path.lower()
    return any(pat.lower() in low for pat in opts.exclude)


def _is_self_redirect_dir(location: str, path: str) -> bool:
    """True when the Location ADDS a trailing slash to this same path (/x → /x/)
    — the canonical "this is a directory" signal. Compares the parsed path for
    EQUALITY (so /login → /gateway/login is not a self-redirect), matches an
    absolute Location (http://host/x/), and — crucially — requires the slash to
    be *added*: a STRIP (/x/ → /x) is framework canonicalization, not a directory.
    """
    lp = urlparse(location).path
    return lp.rstrip("/") == path.rstrip("/") and lp.endswith("/") and not path.endswith("/")


def _strips_trailing_slash(location: str, path: str) -> bool:
    """A redirect that removes this path's trailing slash (/x/ → /x) — blanket URL
    canonicalization (Next.js etc.), so a trailing-slash candidate that gets it is
    NOT a real directory and must not be recursed."""
    if not location:
        return False
    lp = urlparse(location).path
    return path.endswith("/") and lp.rstrip("/") == path.rstrip("/") and not lp.endswith("/")


async def _guard(observer, label, coro, default):
    """Run a discovery fold in isolation. A parser bug or a pathological response
    on one fold (malformed JSON spec, weird JS, broken sitemap) skips just that
    fold with a note — the scan keeps going instead of dying on one bad target."""
    try:
        return await coro
    except Exception as e:                       # noqa: BLE001 — isolation is the point
        observer.log(f"{label}: skipped ({type(e).__name__}: {e})", 0, style="yellow")
        return default


def _rel_depth(prefix: str, base_prefix: str) -> int:
    """How many directory levels `prefix` is below the scan base."""
    base = [s for s in base_prefix.strip("/").split("/") if s]
    segs = [s for s in prefix.strip("/").split("/") if s]
    return max(0, len(segs) - len(base))


def _scope_paths(paths, host: str, scope: str) -> set[str]:
    """Reduce harvested references to what we'll SCAN.

    Relative + same-host paths are always in scope. A same-site absolute URL
    (the CDN) is kept as a full URL only when scope == "site" — otherwise we
    read the CDN's JS but never fire requests at it (scope == "host").
    """
    out: set[str] = set()
    for p in paths:
        if p.startswith(("http://", "https://")):   # same-site CDN full URL (js kept it)
            if scope == "site" and same_site(urlparse(p).netloc, host):
                out.add(p)
            continue
        if p.startswith("//"):
            continue
        if p.lstrip("/"):
            out.add(p)                       # keep leading-/ (root-abs vs relative); a
            #                                  payload with an internal :// stays relative
    return out


@dataclass
class ScanOptions:
    max_depth: int = 1            # 0 = root only
    max_requests: int = 0         # hard cap per run (§3.11); 0 = unlimited (default)
    time_limit: float = 0.0       # wall-clock cap in seconds (--time-limit); 0 = unlimited
    replay_proxy: str | None = None       # send confirmed findings through this proxy (--replay-proxy)
    replay_codes: tuple[int, ...] = ()    # only replay these statuses (empty = all reported)
    filter_similar_urls: tuple[str, ...] = ()  # --filter-similar-to: pages whose simhash drops look-alikes
    wordlist_paths: list[str] = field(default_factory=list)  # -w (repeatable); merged. Empty = builtin base
    shortscan: str = "auto"       # "auto" (if IIS fold) | "on" (force) | "off"
    js: bool = True               # harvest endpoints from HTML/JS
    apidocs: bool = True          # probe + parse OpenAPI/Swagger specs into seeds
    backups: bool = True          # VCS/dotfile probes + backup-name folding
    extensions: list[str] = field(default_factory=list)  # user-forced extensions (".php" form)
    ext_only: bool = False        # use ONLY `extensions` (ignore fingerprint + learned)
    max_folds: int = 40           # cap on learned vocabulary names folded into the scan
    scope: str = "host"           # "host" (target only) | "site" (also scan same-site CDN)
    economy: str = "auto"         # bandit candidate ranking: "auto" (WAF/throttle) | "on" | "off"
    exclude: list[str] = field(default_factory=list)  # skip any path containing one of these (safety: /logout, /delete…)
    exclude_ext: list[str] = field(default_factory=list)  # skip paths with these file extensions (glob: jpg,png,jpg* — static-asset noise)
    graph: bool = False           # track provenance edges for the endpoint graph (--graph)
    bypass403: bool = False        # try to bypass 403/401 findings (path/header/method tricks)
    bypass_intensity: str = "auto" # "light" (core only) | "auto" (fingerprint-gated) | "full" (all)
    bypass_headers: bool = False   # use a header-bypass wordlist for the header axis (--bypass-headers)
    bypass_headers_path: str | None = None  # custom header wordlist path (None → bundled 403-headers.txt)
    bypass_prefixes_path: str | None = None  # custom route-prefix wordlist (--bypass-prefixes) for the api/matrix families
    openapi_source: str | None = None  # explicit OpenAPI/Swagger/JSON:API spec (URL or file) to fold (--openapi)
    param_fuzz: bool = False       # fire harvested + common param names at dynamic endpoints (--params)
    cache_poison: str = ""         # "" = off; "light"|"auto"|"full" — probe unkeyed inputs for cache poisoning (--cache-poison)
    cache_headers: str | None = None  # custom unkeyed-header wordlist for --cache-poison (None → bundled set)
    probe_405: bool = False        # on each 405, replay with POST/PATCH (empty & {} body) to find the accepted method (--probe-405)
    buckets: bool = False          # probe referenced S3/GCS/Azure buckets for public listability (--buckets)
    wayback: bool = False          # fold historical URLs (Wayback CDX + Common Crawl) as seeds (--wayback)
    gau: bool = False              # prefer the gau/waybackurls binary for history, native fallback (--gau)
    vhost: bool = False            # virtual-host discovery (Host-header fuzzing on the target IP)
    origin: bool = False           # origin-IP discovery + IP-based WAF bypass (--origin)
    overlays: bool = True          # fold tech-specific path packs from the fingerprint (--no-overlays off)
    filters: Filters = field(default_factory=Filters)
    finding_sink: object = field(default=None, compare=False, repr=False)  # optional callable(finding) — streamed per confirmed finding (JSONL)


@dataclass
class ScanControl:
    """Interactive control shared with the keyboard listener (dirb-style).

    `n` skips the rest of the current directory; `q` ends the scan early.
    """
    skip_prefix: bool = False
    quit: bool = False


@dataclass
class ScanResult:
    profile: TargetProfile
    findings: list[Finding] = field(default_factory=list)
    requests_made: int = 0
    folds: set[str] = field(default_factory=set)
    pushbacks: int = 0            # 429/reset events — target throttled us
    completed: bool = False       # False if interrupted (quit/cap) → resumable
    error: str = ""               # transport error when the root was unreachable (surfaced to the user)
    edges: list[tuple[str, str]] = field(default_factory=list)  # provenance (src→dst) for --graph
    seen_urls: set[str] = field(default_factory=set, compare=False, repr=False)     # reported URLs (raw) — kills cross-source live dupes
    seen_urls_lc: set[str] = field(default_factory=set, compare=False, repr=False)  # …lower-cased, consulted on a case-insensitive host (both kept so a mid-scan case flip is consistent)
    wall_seen: dict = field(default_factory=dict, compare=False, repr=False)      # (status,length) → count, for live block-wall flood suppression


async def scan(engine: Engine, base_url: str, opts: ScanOptions | None = None,
               observer=None, memory=None, control=None, resume_path=None) -> ScanResult:
    opts = opts or ScanOptions()
    observer = observer or NullObserver()
    control = control or ScanControl()
    engine.deadline = (time.monotonic() + opts.time_limit) if opts.time_limit else None
    kb = load_kb()
    host = urlparse(base_url).netloc
    profile = TargetProfile(host=host, base_url=base_url)
    result = ScanResult(profile=profile)

    # 1. baseline at root + fingerprint -----------------------------------
    root = await engine.fetch(base_url, keep_body=True)
    if getattr(engine, "legacy_tls_engaged", False):
        observer.log("tls: server negotiated a weak DH key / legacy cipher — dropped to a "
                     "lower OpenSSL security level to connect (as curl does); the transport "
                     "is less secure", 0, style="yellow")
    if not root.ok:
        observer.log(f"root unreachable: {root.error}", 1, style="red")
        result.error = root.error           # surface WHY (TLS/DNS/reset) instead of a bare "unreachable"
        result.requests_made = engine.total_requests
        return result

    # Follow a canonical ROOT redirect (http→https, www, trailing slash) so we
    # scan the real app, not a wall of 301s. We only follow when the target is
    # the site root — an app-level redirect to /login is an auth wall we want
    # to *detect*, not chase.
    hops = 0
    while root.ok and root.status in (301, 302, 307, 308) and root.location and hops < 3:
        nxt = urljoin(base_url, root.location)
        np = urlparse(nxt)
        if np.path.strip("/") == "" and same_host(np.netloc, urlparse(base_url).netloc):
            base_url = f"{np.scheme}://{np.netloc}/"
            profile.base_url, profile.host = base_url, np.netloc
            observer.log(f"root redirect → following canonical base {base_url}", 0, style="cyan")
            root = await engine.fetch(base_url, keep_body=True)
            hops += 1
        else:
            break

    observer.log(f"root: {root.status} · {root.length}B · "
                 f"{root.content_type or 'no ctype'}", 1)

    # Passive cache-layer fingerprint (free — reads headers we already captured).
    # Always on; just enriches the profile and gates the active --cache-poison fold.
    if root.body:
        profile.bucket_refs |= buckets.find_bucket_refs(root.body)  # cloud refs in the homepage
    profile.cache_layer = cache_poison.detect_cache_layer(root.headers)
    if profile.cache_layer:
        cs = cache_poison.cache_status(root.headers)
        observer.log(f"cache-layer: {profile.cache_layer}" + (f" ({cs})" if cs else ""),
                     1, style="cyan")

    # Authenticated-scan sanity check: if -H credentials were given but the root
    # still looks like an auth wall, the session almost certainly isn't working —
    # warn before spending the whole scan running effectively unauthenticated.
    # `started_authed` (auth supplied AND root NOT a wall) lets us re-check at the
    # end whether the session expired mid-scan.
    started_authed = False
    if session.has_auth(engine.cfg.headers):
        wall = session.auth_wall_reason(root, base_url)
        if wall:
            observer.log(f"auth: credentials supplied but {wall} — the session may be "
                         f"invalid/expired; scan may be running UNAUTHENTICATED", 0, style="bold red")
        else:
            started_authed = True

    # scan starts at the given base path (e.g. /lms/), so calibrate THERE. Path
    # regression: a deep/file target (…/path/arquivo.pdf) scans its DIRECTORY (not
    # the file-as-folder), and every ancestor dir up to root is climbed (seeded
    # below). The file itself is fetched as a seed.
    base_prefix, _climb_file, _climb_ancestors = _path_climb(urlparse(base_url).path)

    observer.phase("calibrate")
    await bl.calibrate(engine, profile, [(base_prefix, e) for e in _BASE_CALIB_EXTS + [".php", ".aspx"]])

    # Kick off the (slow, external) historical-URL lookup NOW, in the background,
    # so it runs while we fingerprint/calibrate; recon folds its result below under
    # a TOTAL wall-clock budget from here (not a fresh wait at the await), so a
    # hung history source can't stall the whole scan — the seeds are optional.
    wb_task = None
    wb_deadline = 0.0
    if opts.wayback or opts.gau:
        wb_task = asyncio.create_task(wayback.harvest(profile.host, use_gau=opts.gau))
        wb_deadline = time.monotonic() + WAYBACK_BUDGET

    observer.phase("fingerprint")
    # The only unguarded code between the wb_task kickoff and its await is the
    # fingerprint block; if it raises, cancel the background harvest so we don't
    # orphan the task (and, with --gau, leak a subprocess). The recon harvests
    # below are _guard-wrapped, and the wayback await self-cancels on error.
    try:
        errors = await fp.forced_error_probes(engine, base_url)
        fp.apply_signals(profile, [root, *errors], kb)
        fp.apply_error_signals(profile, errors)    # default-error-page → stack (header-independent)
        for pr in (root, *errors):
            w = waf.detect(pr)
            if w:
                profile.waf = w
                observer.log(f"WAF detected: {w}", 0, style="bold red")
                break
        fav = await fp.favicon_fingerprint(engine, base_url, profile)
        if fav is not None:
            observer.log(f"favicon mmh3={fav}", 1)
        exts, priority_paths, folds = fp.confirmed_actions(profile, kb)
    except BaseException:
        if wb_task is not None and not wb_task.done():
            wb_task.cancel()
        raise
    # User-forced extensions (-X): replace the auto-detected set under --ext-only,
    # else add to it. Propagates to calibration, candidates and recursion.
    if opts.ext_only and opts.extensions:
        exts = set(opts.extensions)
    elif opts.extensions:
        exts |= set(opts.extensions)
    result.folds = folds
    observer.fingerprint(profile, exts, folds)

    for ev in profile.evidence:
        observer.log(f"  evidence: {ev.tech} +{ev.weight:.0f} "
                     f"({ev.source}: {ev.detail})", 2)
    observer.log("fingerprint: " + (", ".join(
        f"{t}={s:.0f}" for t, s in profile.tech_scores.items()) or "none"), 1)
    confirmed = profile.confirmed_techs()
    if confirmed:
        observer.log(f"confirmed: {', '.join(confirmed)} · ext "
                     f"{' '.join(sorted(exts)) or '-'} · folds "
                     f"{', '.join(sorted(folds)) or '-'}", 1, style="cyan")

    # 2. calibrate EVERY extension class the candidates will use at root.
    # Missing a class (e.g. .json) would drop those candidates to the coarse
    # no-baseline rule, which a soft-404 host defeats. calibrate() de-dupes by
    # ext class, so passing many concrete extensions is cheap.
    # ---- recon: every passive source that yields paths for the dynamic
    # wordlist — methods, memory, JS, service worker + manifest, response
    # headers, robots/sitemap, API specs, .well-known, GraphQL.
    observer.phase("recon")
    # sub-step counter shown in the status bar: "recon: apidocs  4/7"
    recon_total = (3 + (1 if memory is not None else 0)
                   + (1 if (opts.js and root.body) else 0)
                   + (2 if opts.apidocs else 0)
                   + (1 if opts.openapi_source else 0)
                   + (1 if wb_task is not None else 0))
    _recon_k = [0]

    def _recon(name):
        _recon_k[0] += 1
        observer.substep(name, _recon_k[0], recon_total)

    # HTTP methods (OPTIONS) — flag dangerous verbs (PUT/DELETE/TRACE/WebDAV).
    _recon("methods")
    m_status, m_methods, m_danger = await _guard(observer, "methods",
                                                 methods.probe(engine, base_url), (0, [], []))
    if m_methods:
        observer.log(f"methods: {', '.join(m_methods)}", 1)
    if m_danger:
        mf = Finding(base_url, m_status or 200, root.length, root.content_type, 0.7,
                     "methods", note=f"dangerous methods: {', '.join(m_danger)}",
                     tags=["config"])
        result.findings.append(mf)
        observer.finding(mf)
        observer.log(f"methods: dangerous verbs enabled → {', '.join(m_danger)}",
                     0, style="bold red")

    # assemble high-priority root seeds: memory (cross-target) + js + backups
    root_seeds: list[tuple[str, str]] = []

    # Path regression: fetch the target file (if any) and climb every ancestor
    # directory — each is probed as a seed; the ones that exist get recursed by
    # the normal directory machinery, so a deep target explores its whole lineage.
    if _climb_file:
        root_seeds.append((_climb_file, "target"))
    if _climb_ancestors:
        root_seeds += [(a, "climb") for a in _climb_ancestors]
        observer.log(f"path-climb: exploring {len(_climb_ancestors)} ancestor "
                     f"director{'y' if len(_climb_ancestors) == 1 else 'ies'} of "
                     f"{base_prefix} up to root", 0, style="cyan")

    if memory is not None:
        _recon("memory")
        # k-NN over the fingerprint vector (nearest past hosts), falling back to
        # shared-tech recall when there aren't enough fingerprinted hosts yet.
        primed = memory.recall_knn(profile) or memory.recall(profile.confirmed_techs(),
                                                             profile.host)
        root_seeds += [(p, "memory") for p in primed]
        if primed:
            observer.log(f"memory: {len(primed)} primed paths from past scans "
                         f"of similar hosts", 0, style="cyan")

    js_paths: set[str] = set()
    robots_paths: set[str] = set()

    if opts.js and root.body:
        _recon("js-scrape")
        js_paths, js_params, js_edges = await _guard(observer, "js-harvest",
                                           js_parser.harvest(engine, base_url, root.body),
                                           (set(), set(), []))
        # service worker (precache manifest) + web app manifest — more app paths
        ca_paths, ca_edges = await _guard(observer, "clientapp",
                                          clientapp.harvest(engine, base_url), (set(), []))
        js_paths |= ca_paths
        js_edges += ca_edges
        js_paths = _scope_paths(js_paths, profile.host, opts.scope)   # scope discipline
        js_paths = set(sorted(js_paths)[:MAX_HARVEST_SEEDS])          # cap the blast radius
        root_seeds += [(p, "js") for p in sorted(js_paths)]
        profile.parameters |= js_params
        if opts.graph:
            result.edges += js_edges
        if js_paths:
            observer.log(f"js: {len(js_paths)} same-host endpoints harvested from HTML/JS",
                         1, style="cyan")
        if js_params:
            observer.log(f"params: {len(js_params)} parameter names harvested "
                         f"(pentest input surface)", 0, style="cyan")

    # Endpoints declared in the root response headers (CSP, Link) — free, no
    # extra request. Available even when there's no HTML body to harvest.
    if opts.js:
        hdr_paths = _scope_paths(js_parser.extract_header_paths(root.headers, base_url),
                                 profile.host, opts.scope)
        if hdr_paths:
            root_seeds += [(p, "header") for p in sorted(hdr_paths)]
            js_paths |= hdr_paths                     # feed the vocabulary fold too
            observer.log(f"headers: {len(hdr_paths)} endpoints from CSP/Link", 1, style="cyan")
            if opts.graph:
                src = urlparse(base_url).path or "/"
                result.edges += [(src, p) for p in sorted(hdr_paths)]

    # robots.txt + sitemap.xml — free passive intel
    _recon("robots")
    robots_raw = await _guard(observer, "robots", robots.harvest(engine, base_url), set())
    robots_paths = _scope_paths(robots_raw, profile.host, opts.scope)
    if robots_paths:
        root_seeds += [(p, "robots") for p in sorted(robots_paths)]
        observer.log(f"robots/sitemap: {len(robots_paths)} paths", 1, style="cyan")
        if opts.graph:
            result.edges += [("/robots.txt", p) for p in sorted(robots_paths)]

    # OpenAPI/Swagger spec → fold the whole declared API surface in as seeds.
    api_paths: set[str] = set()
    if opts.apidocs:
        _recon("api-docs")
        spec_url, api_paths = await _guard(observer, "api-docs",
                                           apidocs.harvest(engine, base_url),
                                           (None, set()))
        api_paths = _scope_paths(api_paths, profile.host, opts.scope)
        if spec_url:
            root_seeds += [(p, "apidocs") for p in sorted(api_paths)]
            observer.log(f"api-docs: API spec/index at {urlparse(spec_url).path} "
                         f"→ {len(api_paths)} endpoints folded", 0, style="cyan")
            if opts.graph:
                spec_path = urlparse(spec_url).path
                result.edges += [(spec_path, p) for p in sorted(api_paths) if p != spec_path]

    # user-supplied spec (URL or file) → fold its declared surface onto the target.
    # Works independently of auto-discovery (so it still runs under --no-apidocs).
    if opts.openapi_source:
        _recon("api-spec")
        src_label, src_paths = await _guard(observer, "api-spec",
                                            apidocs.ingest_source(engine, opts.openapi_source),
                                            (None, set()))
        src_paths = _scope_paths(src_paths, profile.host, opts.scope)
        if src_label:
            root_seeds += [(p, "apidocs") for p in sorted(src_paths)]
            observer.log(f"api-spec: {len(src_paths)} endpoints folded from "
                         f"{opts.openapi_source}", 0, style="cyan")
        else:
            observer.log(f"api-spec: no endpoints parsed from {opts.openapi_source} "
                         f"(not a recognised OpenAPI/Swagger or JSON:API doc)", 0, style="yellow")

    # historical URLs (kicked off at fingerprint, now in hand) → fold as seeds.
    if wb_task is not None:
        _recon("wayback")
        # Only the time REMAINING in the total budget — recon already ran the task
        # concurrently, so a fast source is already done here (instant), and a hung
        # one is cut at the budget instead of stalling the scan for a fresh 30s.
        remaining = max(0.5, wb_deadline - time.monotonic())
        try:
            wb_paths, wb_params, wb_src = await asyncio.wait_for(wb_task, timeout=remaining)
        except Exception as e:        # timeout/any error: never let history stall/break the scan
            wb_task.cancel()
            wb_paths, wb_params, wb_src = set(), set(), "skipped"
            observer.log(f"wayback: skipped ({type(e).__name__}) — history is optional, "
                         f"scan continues", 0, style="yellow")
        scoped = [p for p in _scope_paths(wb_paths, profile.host, opts.scope)
                  if not _excluded("/" + p.lstrip("/"), opts)][:MAX_WAYBACK_SEEDS]
        if scoped:
            root_seeds += [(p, "wayback") for p in sorted(scoped)]
        if wb_params:
            profile.parameters |= wb_params                   # enrich the --params surface
        if scoped or wb_params:
            observer.log(f"wayback: {len(scoped)} historical paths"
                         f" (+{len(wb_params)} param names) from {wb_src}", 0, style="cyan")

    # .well-known/ — OIDC/OAuth index (auth endpoints), security.txt, etc.
    _recon("well-known")
    wk_paths, wk_edges = await _guard(observer, "well-known",
                                      wellknown.harvest(engine, base_url), (set(), []))
    wk_paths = _scope_paths(wk_paths, profile.host, opts.scope)
    if wk_paths:
        root_seeds += [(p, "wellknown") for p in sorted(wk_paths)]
        observer.log(f"well-known: {len(wk_paths)} paths "
                     f"(OIDC/OAuth + security.txt)", 1, style="cyan")
        if opts.graph:
            result.edges += wk_edges

    # GraphQL introspection — confirm the endpoint + harvest the schema, flag the
    # sensitive operations, and (queries only) probe which respond without auth.
    if opts.apidocs:
        _recon("graphql")
        _empty_meta = {"fields": set(), "args": set(), "queries": [], "mutations": [], "sensitive": []}
        gql_url, gql_fields, gql_meta = await _guard(
            observer, "graphql", graphql.harvest(engine, base_url), (None, set(), _empty_meta))
        if gql_url:
            profile.parameters |= gql_fields | gql_meta["args"]   # fields AND their arguments
            sens = gql_meta["sensitive"]
            n_q, n_m = len(gql_meta["queries"]), len(gql_meta["mutations"])
            note = "introspection enabled"
            tags = ["api"]
            if sens:
                note += " · sensitive ops: " + ", ".join(sens[:8]) \
                    + (f" (+{len(sens) - 8})" if len(sens) > 8 else "")
                tags.append("disclosure")
            gf = Finding(gql_url, 200, 0, "application/json", 0.9, "graphql", note=note, tags=tags)
            result.findings.append(gf)
            observer.finding(gf)
            observer.log(f"graphql: introspection enabled at {urlparse(gql_url).path} → "
                         f"{len(gql_fields)} fields · {n_q} queries + {n_m} mutations · "
                         f"{len(sens)} sensitive", 0, style="cyan")
            if sens:
                observer.log("graphql: sensitive ops → " + ", ".join(sens[:12])
                             + (f" (+{len(sens) - 12})" if len(sens) > 12 else ""), 0, style="yellow")
            await _guard(observer, "graphql-probe",
                         _graphql_probe(engine, opts, observer, gf, gql_url, gql_meta), None)

    if opts.backups:
        root_seeds += [(p, "backup") for p in backups.vcs_probes()]

    # Tech-overlay: fold stack-specific path packs from the confirmed fingerprint
    # (WordPress→wp-*, Spring→actuator/*, Laravel→telescope, …). Additive and
    # root-anchored — fired as base-prefix seeds, never per-directory — so a
    # confirmed stack gets its high-value paths without bloating every recursion.
    if opts.overlays and confirmed:
        ov_paths, ov_packs = overlays.overlay_words(confirmed)
        if ov_paths:
            root_seeds += [(p, "overlay") for p in ov_paths]
            observer.log(f"overlay: folded {len(ov_paths)} stack-specific paths "
                         f"from confirmed tech ({', '.join(ov_packs)})", 0, style="cyan")

    # Tenant confinement on shared path-multitenant hosts (Firestore/Storage/…):
    # history is harvested by DOMAIN and memory is primed by HOST, so both drag in
    # OTHER tenants' paths (e.g. /v1/projects/<someone-else>/…) that host scope
    # can't tell apart. Drop any absolute seed off the target's own path chain so
    # the scan never probes a co-tenant's data. Relative/CDN seeds are unaffected.
    if path_tenant_host(profile.host):
        tgt_path = urlparse(base_url).path or "/"
        before = len(root_seeds)
        root_seeds = [(p, s) for (p, s) in root_seeds
                      if not p.startswith("/") or same_tenant_path(tgt_path, p)]
        dropped = before - len(root_seeds)
        if dropped:
            observer.log(f"scope: dropped {dropped} cross-tenant seed(s) — "
                         f"{profile.host} is shared multi-tenant, confined to "
                         f"{tgt_path}", 0, style="yellow")

    # THE origami fold: learn the target's own vocabulary (names + extensions)
    # from the references discovered above, and weave it into the scan — capped
    # by --max-folds so a chatty SPA can't explode the request budget. Kept by
    # frequency: the most-referenced tokens are the most valuable.
    names_ctr, exts_ctr = derive_vocabulary(js_paths | robots_paths | api_paths)
    learned_names = [n for n, _ in names_ctr.most_common(opts.max_folds)]
    # the target's own name (host labels + base path) is prime vocabulary
    # use the FULL target path (incl. a file segment) so /caminho/path/arquivo.pdf
    # folds arquivo into the vocabulary too, not just the base directory's segments.
    tgt = target_tokens(profile.host, urlparse(base_url).path or base_prefix)
    learned_names = list(dict.fromkeys(list(tgt) + learned_names))
    # extensions multiply the WHOLE wordlist, so they get a tighter cap.
    ext_cap = max(6, opts.max_folds // 8)
    learned_exts = set() if opts.ext_only else (
        {e for e, _ in exts_ctr.most_common(ext_cap)} - exts)
    exts |= learned_exts

    root_exts = (set(_BASE_CALIB_EXTS) | set(BASE_EXTS) | exts
                 | {_ext_of(p) for p in priority_paths}
                 | {_ext_of(p) for p, _ in root_seeds})
    await bl.calibrate(engine, profile, [(base_prefix, e) for e in root_exts])
    observer.log(f"calibrated {len(profile.baseline)} contexts · "
                 f"wildcard/soft-404={'yes' if profile.wildcard else 'no'}", 1)
    for key, cb in profile.baseline.items():
        observer.log(f"  ctx {key} → miss "
                     f"{'soft-404' if cb.is_soft404 else cb.status} · "
                     f"len {cb.length_lo}..{cb.length_hi} · sigs {len(cb.simhashes)}", 2)

    # --filter-similar-to: fetch each reference page against THIS target, keep its
    # body simhash so _report can drop look-alike findings (a noisy soft-200 the
    # auto soft-404 misses). Resolved per target — the refs are relative to this
    # host, and `opts` is shared across a multi-target run, so we must not cache
    # target #1's hashes onto every subsequent host.
    if opts.filter_similar_urls:
        hashes = []
        for ref in opts.filter_similar_urls:
            rp = await engine.fetch(urljoin(base_url, ref), keep_body=False)
            if rp.ok:
                hashes.append(rp.body_simhash)
        opts.filters.similar_hashes = tuple(hashes)
        observer.log(f"filter: dropping responses ~similar to {len(hashes)} reference "
                     f"page(s) (simhash ≤ {opts.filters.similar_distance})", 0, style="cyan")

    words = load_wordlists(opts.wordlist_paths)
    # fold the learned vocabulary in: target's own names tried first, in every dir.
    if learned_names:
        wset = set(words)
        fresh = [w for w in learned_names if w not in wset]   # keep frequency order
        words = fresh + words
        observer.log(f"vocabulary: folded +{len(fresh)} names and "
                     f"+{len(learned_exts)} extensions learned from target references "
                     f"(--max-folds {opts.max_folds})", 0, style="cyan")
    wl_name = " + ".join(opts.wordlist_paths) or "builtin base.txt"
    observer.log(f"wordlist: {wl_name} ({len(words)} words) · "
                 f"extensions {len(exts) or 0} folded", 0)

    # 3. shortscan fold (IIS 8.3) — high-value seeds before the generic scan
    if _should_shortscan(opts, folds):
        await _guard(observer, "shortscan",
                     _shortscan_pass(engine, profile, base_url, words, result, opts,
                                     observer, memory),
                     None)

    # 4. recursive scan + folds (checkpointed) -----------------------------
    queue: list[tuple[str, int]] = [(base_prefix, 0)]   # (prefix, depth)
    result = await _scan_loop(engine, profile, opts, observer, memory, control, result,
                              base_prefix=base_prefix, words=words, exts=exts,
                              priority_paths=priority_paths, root_seeds=root_seeds,
                              queue=queue, scanned=set(), resume_path=resume_path,
                              root_simhash=root.body_simhash)

    # If we started authenticated, re-check the root once: if it's now an auth
    # wall, the session expired DURING the scan and later findings may be partial.
    # The root is a stable reference, so this is a false-positive-free signal.
    # Skipped if the request budget is already spent; counted toward requests_made.
    if started_authed and not (_over_budget(engine, opts)):
        recheck = await engine.fetch(base_url, keep_body=True)
        result.requests_made = engine.spent              # count this extra probe
        reason = session.auth_wall_reason(recheck, base_url)
        if reason:
            observer.log(f"auth: session appears to have EXPIRED during the scan "
                         f"(root now {reason}) — results may be partially unauthenticated; "
                         f"re-run with fresh credentials", 0, style="bold red")

    # --replay-proxy: re-issue confirmed findings through the replay proxy so only
    # the real hits land in Burp/ZAP (a clean sitemap), separate from --proxy which
    # sees every probe. --replay-codes narrows it to specific statuses.
    if opts.replay_proxy:
        await _replay_findings(engine, result, opts, observer)

    return result


async def _replay_findings(engine, result, opts, observer) -> None:
    """GET each reported finding (optionally filtered by --replay-codes) through the
    replay proxy. Best-effort: a proxy that's down logs a warning, never crashes."""
    codes = set(opts.replay_codes)
    targets = [f for f in result.findings if not codes or f.status in codes]
    if not targets:
        return
    observer.log(f"replay: sending {len(targets)} finding(s) to {opts.replay_proxy}"
                 + (f" (codes {sorted(codes)})" if codes else ""), 0, style="cyan")
    try:
        client = engine.replay_client(opts.replay_proxy)   # httpx validates the proxy URL here
    except Exception as e:
        observer.log(f"replay: cannot use proxy {opts.replay_proxy!r} ({e}) — skipped",
                     0, style="yellow")
        return
    sent = 0
    try:
        for f in targets:
            try:
                await client.get(f.url)
                sent += 1
            except Exception:
                pass                              # a single unreachable URL never aborts the replay
    finally:
        await client.aclose()
    if sent < len(targets):
        observer.log(f"replay: {sent}/{len(targets)} delivered "
                     f"(proxy {opts.replay_proxy} may be unreachable)", 0, style="yellow")


async def resume_scan(engine: Engine, state: dict, opts: ScanOptions, observer=None,
                      memory=None, control=None, resume_path=None) -> ScanResult:
    """Continue an interrupted scan from a loaded checkpoint (`resume.load`).

    The expensive setup (calibrate/fingerprint/harvest/vocabulary) is restored
    from the checkpoint, so we drop straight back into the directory loop with
    the same profile, findings, and pending queue.
    """
    observer = observer or NullObserver()
    control = control or ScanControl()
    engine.deadline = (time.monotonic() + opts.time_limit) if opts.time_limit else None
    profile = state["profile"]
    result = ScanResult(profile=profile, findings=list(state["findings"]),
                        folds=set(state.get("folds", [])),
                        edges=[tuple(e) for e in state.get("edges", [])])
    observer.log(f"resume: restored {len(result.findings)} findings · "
                 f"{len(state['queue'])} dirs queued · {len(state['scanned'])} done "
                 f"· {state.get('requests_made', 0)} prior requests",
                 0, style="cyan")
    observer.fingerprint(profile, profile.enabled_extensions, result.folds)
    return await _scan_loop(engine, profile, opts, observer, memory, control, result,
                            base_prefix=state["base_prefix"], words=state["words"],
                            exts=state["exts"], priority_paths=state["priority_paths"],
                            root_seeds=state["root_seeds"], queue=list(state["queue"]),
                            scanned=set(state["scanned"]), resume_path=resume_path,
                            start_offset=state.get("start_offset", 0),
                            front_cands=state.get("front_cands") or None,
                            root_simhash=state.get("root_simhash", 0),
                            prior_requests=state.get("requests_made", 0))


async def _scan_loop(engine, profile, opts, observer, memory, control, result, *,
                     base_prefix, words, exts, priority_paths, root_seeds,
                     queue, scanned, resume_path, start_offset=0, front_cands=None,
                     root_simhash=0, prior_requests=0):
    """The recursive directory walk + post-scan folds, checkpointed per prefix.

    A prefix is added to `scanned` only after every candidate fired. If the scan
    is interrupted (quit / request cap) mid-prefix, the prefix stays at the front
    of the queue and the checkpoint records BOTH the exact ordered candidate list
    of that prefix and the offset reached — so a resume replays the same order
    from where it stopped (works even under economy's per-run shuffle, since the
    order is persisted, not recomputed). Findings are URL-deduped on every
    checkpoint so a re-fired prefix can't duplicate the report. State is flushed
    after every prefix, so a hard kill loses at most one partial prefix.
    """
    engine.prior_requests = prior_requests   # so --max-requests bounds CUMULATIVE spend across resumes
    recurse_exts = set(_BASE_CALIB_EXTS) | set(BASE_EXTS) | exts
    queued: set[str] = {p for p, _ in queue} | scanned

    # Contextual bandit: learning is always on (every probe updates the ranker),
    # but candidate *re-ordering* only kicks in under economy mode — when the
    # request budget is tight enough that order decides what gets tested.
    techs = profile.confirmed_techs()
    ranker = None
    if memory is not None:
        ranker = Bandit(memory.load_word_stats(techs))
    economy = opts.economy == "on" or (opts.economy == "auto" and bool(profile.waf))
    if economy and ranker is not None:
        observer.log("economy mode: ranking candidates by learned hit-rate "
                     "(request budget is tight)", 0, style="cyan")
    # An interrupted prefix's exact ordered candidates, restored from a resume.
    pending = [Candidate(p, 0, o) for p, o in front_cands] if front_cands else None

    def _checkpoint(offset=0, cands=None):
        if resume_path is not None:
            result.findings = _dedup_by_url(result.findings)
            resume_mod.save(resume_path, profile=profile, findings=result.findings,
                            requests_made=prior_requests + engine.total_requests, folds=result.folds,
                            words=words, exts=exts, priority_paths=priority_paths,
                            root_seeds=root_seeds, base_prefix=base_prefix,
                            queue=queue, scanned=scanned, start_offset=offset,
                            front_cands=[(c.path, c.origin) for c in cands] if cands else [],
                            edges=result.edges, root_simhash=root_simhash)

    observer.phase("scan")
    interrupted = False
    disc_round = 0
    harvested_files: set[str] = set()       # files already read by a harvest round (skip re-reads)
    listed_dirs: set[str] = set()           # dirs with autoindex → harvest, don't blind-brute

    # Recurse confirmed directories (real 403/301 dirs) before speculative
    # ancestor dirs — high-value first, so a deep tree can't starve the budget
    # before the obvious directories are explored. Depth is relative to the base.
    # `max_d` lets evidence-based (harvested) dirs recurse past the blind cap.
    def _enqueue(dirs, front, max_d=opts.max_depth):
        for d in dirs:
            if d in scanned or d in queued or _excluded(d, opts):
                continue
            if not d.startswith(base_prefix):
                continue                       # stay in scope — don't recurse a dir
                # outside the requested base (e.g. an ancestor of a root-absolute
                # seed like /admin/ when scanning /lms/); the seed itself is still
                # probed once, we just don't brute-force-recurse out of scope.
            if _rel_depth(d, base_prefix) <= max_d:
                queued.add(d)
                item = (d, _rel_depth(d, base_prefix))
                queue.insert(0, item) if front else queue.append(item)

    while queue:
        if control.quit:
            observer.log("scan: quit requested — stopping", 0, style="yellow")
            interrupted = True
            _checkpoint(0)
            break
        prefix, depth = queue.pop(0)
        if prefix in scanned:
            continue
        offset, start_offset = start_offset, 0      # offset applies to the first popped prefix only

        if prefix != base_prefix:
            observer.directory(prefix, depth)
        await bl.calibrate(engine, profile, [(prefix, e) for e in recurse_exts])

        if pending is not None:                     # resuming this exact prefix order
            cands, pending = pending, None
        elif prefix in listed_dirs:
            # autoindex dir: the listing already shows the real contents (the deep
            # harvest parses them), so skip the blind wordlist — probe only what
            # the index HIDES (dotfiles/backups/VCS via IndexIgnore).
            cands = [Candidate(p, 0, "index-hidden") for p in _INDEX_HIDDEN]
            observer.log(f"scan {prefix} · autoindex — listing parsed, probing "
                         f"{len(cands)} index-hidden names only", 1)
        else:
            is_base = prefix == base_prefix
            cands = build_candidates(priority_paths if is_base else [], words, exts,
                                     extra_seeds=root_seeds if is_base else None,
                                     base_exts=([""] if opts.ext_only else None))
            if economy and ranker is not None:      # rank the wordlist tier (anchored seeds stay first)
                anchored = [c for c in cands if c.origin != "wordlist"]
                wl = [c for c in cands if c.origin == "wordlist"]
                wl.sort(key=lambda c: -ranker.sample(word_of(c.path)))
                cands = anchored + wl
        if prefix not in listed_dirs:
            observer.log(f"scan {prefix} · {len(cands)} candidates"
                         + (f" · depth {depth}" if depth else "")
                         + (f" · resuming from {offset}" if offset else ""), 1)
        observer.start_prefix(prefix, len(cands))
        confirmed, ancestors, consumed, hit_cap = await _scan_prefix(
            engine, profile, prefix, cands, result, opts, observer, control,
            ranker=ranker, skip=offset, listed_dirs=listed_dirs)

        # Interrupted mid-prefix → re-queue at the front and checkpoint the exact
        # ordered candidates + offset reached, so resume replays from there.
        if hit_cap:
            queue.insert(0, (prefix, depth))
            interrupted = True
            _checkpoint(consumed, cands)
            break
        scanned.add(prefix)
        _enqueue(ancestors, front=False)
        _enqueue(confirmed, front=True)
        _checkpoint(0)

        # Discovery round: when the queue drains, read the code the scan just
        # turned up (deep harvest) and recurse the directories the new endpoints
        # live in — a wordlist-found /app/bundle.js → /app/api/v2/users →
        # brute-force /app/api/v2/. Evidence-based, so allowed past the blind
        # depth cap; bounded by MAX_DISCOVERY_ROUNDS. Harvested dirs become normal
        # queue entries (checkpointed), so --resume stays consistent.
        if not queue and not interrupted and opts.js and disc_round < MAX_DISCOVERY_ROUNDS:
            disc_round += 1
            new_dirs = await _guard(observer, "harvest",
                                    _harvest_fold(engine, profile, result, opts, observer,
                                                  base_prefix, harvested_files), set()) or set()
            _enqueue(sorted(new_dirs), front=False, max_d=opts.max_depth + _HARVEST_DEPTH_BONUS)
            if queue:
                observer.phase("scan")
            _checkpoint(0)

    result.requests_made = prior_requests + engine.total_requests
    result.pushbacks = engine.pushback_events
    if memory is not None and ranker is not None:
        memory.record_word_stats(ranker.deltas(), techs)   # learn even if interrupted
    if interrupted:
        # Leave the checkpoint on disk for `--resume`; skip folds + memory
        # (those run once, on the clean finish). Say WHY we stopped — it's our
        # own budget/quit, NOT the target dropping us.
        observer.pushback(engine.pushback_events)
        if control.quit:
            reason = "you pressed q"
        elif opts.max_requests and engine.spent >= opts.max_requests:
            reason = (f"hit the --max-requests {opts.max_requests} budget "
                      f"(raise it with --max-requests N)")
        else:
            reason = (f"hit the --time-limit {opts.time_limit:g}s "
                      f"(raise it with --time-limit)")
        observer.log(f"scan: stopped — {reason}. {len(result.findings)} findings so far; "
                     f"checkpoint saved → continue with --resume", 0, style="yellow")
        return result

    # (deep harvest + recursion of its discoveries ran inside the scan loop as
    # discovery rounds — so harvested findings are in result before the folds.)

    # 4.5 403/401 bypass — try to walk around denials BEFORE the collapse merges
    # the 403 wall, so each blocked resource gets its own attempt.
    if opts.bypass403:
        await _guard(observer, "403-bypass",
                     _bypass_fold(engine, profile, result, opts, observer, root_simhash),
                     None)

    # 5. dedupe + collapse same-content collisions BEFORE expanding ---------
    # (do this first so the backup fold doesn't explode over hundreds of
    # identical pages — the bug behind 849 findings / 10k backup probes).
    result.findings = _dedupe_and_collapse(result.findings, observer,
                                            ci=profile.case_sensitive is False)

    # 6. backup/source fold around confirmed files -------------------------
    if opts.backups:
        await _guard(observer, "backups",
                     _backup_fold(engine, profile, result, opts, observer), None)
        # 6.1 VCS/metadata reconstruction — a leaked .git/.svn/.DS_Store enumerated
        # into its whole file tree (one leak → the repo). Part of the backups family.
        await _guard(observer, "vcs",
                     _vcs_fold(engine, profile, result, opts, observer), None)
        result.findings = _dedupe_and_collapse(result.findings, observer,
                                            ci=profile.case_sensitive is False)

    # 6.5 association fold — corpus rules ("found /backup/ → test /.git/")
    if memory is not None:
        await _guard(observer, "associations",
                     _association_fold(engine, profile, result, opts, observer, memory), None)
        result.findings = _dedupe_and_collapse(result.findings, observer,
                                            ci=profile.case_sensitive is False)

    # 7. secrets — read high-value files (configs/dotfiles/backups/bypassed) and
    # flag credentials inside; the payoff of finding the file at all.
    await _guard(observer, "secrets",
                 _secrets_fold(engine, profile, result, opts, observer), None)

    # 7.1 cloud buckets — report S3/GCS/Azure refs seen in the bodies; with
    # --buckets, probe each for public listability (read-only GET, off-host).
    await _guard(observer, "buckets",
                 _bucket_fold(engine, profile, result, opts, observer), None)

    # 7.2/7.3 speculative amplifier folds — API version pivot (/api/vN → v0/v2/v3)
    # and naming-convention mutation (/user → /users, data.json → data.xml). Pure
    # guesswork multipliers, so they're skipped when the target is throttling us.
    if _throttled(engine, profile, opts):
        observer.log("apiver/mutate: skipped — target throttling (conserving budget)",
                     1, style="yellow")
    else:
        await _guard(observer, "apiver",
                     _apiver_fold(engine, profile, result, opts, observer), None)
        await _guard(observer, "mutate",
                     _mutate_fold(engine, profile, result, opts, observer), None)

    # 7.5 parameter discovery — fire harvested + common param names at dynamic
    # endpoints; a reflected canary is a real input (XSS/SSTI/redirect lead). Opt-in.
    if opts.param_fuzz:
        await _guard(observer, "params",
                     _param_fold(engine, profile, result, opts, observer), None)

    # 7.6 cache poisoning — probe unkeyed inputs (X-Forwarded-Host & friends) on
    # cacheable endpoints; a reflected-and-cached or behaviour-changing unkeyed
    # input is a poisoning primitive. Safe: every probe rides a throwaway
    # cache-buster, never the real key. Opt-in.
    if opts.cache_poison:
        await _guard(observer, "cache-poison",
                     _cache_poison_fold(engine, profile, result, opts, observer, root_simhash), None)

    # (method discovery on a 405 happens INLINE in _scan_prefix the moment the
    # 405 is found — under --probe-405 — so the accepted method rides the finding
    # in the live stream and a partial scan still probes what it discovered.)

    # 8. virtual-host discovery — Host-header fuzzing on the target IP (opt-in).
    if opts.vhost:
        await _guard(observer, "vhost",
                     _vhost_fold(engine, profile, result, opts, observer, root_simhash), None)

    # 9. origin-IP discovery + IP-based WAF bypass (opt-in, off-host connections).
    if opts.origin:
        await _guard(observer, "origin",
                     _origin_fold(engine, profile, result, opts, observer, root_simhash), None)

    observer.pushback(engine.pushback_events)
    result.requests_made = prior_requests + engine.total_requests
    result.pushbacks = engine.pushback_events
    result.completed = True
    result.findings.sort(key=lambda f: (-f.confidence, f.url))

    if memory is not None:
        run_id = memory.record_run(profile, result)
        observer.log(f"memory: run #{run_id} saved · "
                     f"{len(result.findings)} findings recorded", 1)
    return result


async def _is_soft(engine, profile, prefix, probe) -> bool:
    """Sanity-check a surprising hit with a random sibling of the SAME SHAPE.

    The sibling is built in the candidate's OWN directory and mimics its shape
    — a leading dot for dotfiles, the same extension. So a blanket 403 (server
    forbids anything under /.git/, or any dotfile) is recognized: /.git/HEAD's
    403 is only a real finding if /.git/<random> does NOT also 403. Catches both
    multi-modal soft-404 and generic-403 walls; the signature is then cached.
    """
    path = urlparse(probe.url).path
    own_dir = path.rsplit("/", 1)[0] + "/"
    name = path.rsplit("/", 1)[-1]
    lead = "." if name.startswith(".") else ""
    ext = _ext_of(name[1:] if lead else name)
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    sib_path = own_dir.lstrip("/") + lead + rnd + ext
    sib = await engine.fetch(urljoin(_host_root(profile.base_url), sib_path))
    if (sib.ok and sib.status == probe.status
            and hamming(sib.body_simhash, probe.body_simhash) <= bl.SIMHASH_MISS_DISTANCE):
        cb = resolve_baseline(profile, probe.url, own_dir)
        if cb is not None:
            sig = (probe.status, probe.body_simhash)
            if sig not in cb.soft_signatures:
                cb.soft_signatures.append(sig)
        return True
    return False


def _path_climb(raw_path: str) -> tuple[str, str | None, list[str]]:
    """Path regression from a deep target URL → (base_dir, file_seed, ancestors).

    Given `/caminho/path/arquivo.pdf`, Origami should scan the *directory* (the
    file's PARENT, not treat the file as a folder), fetch the file itself, and
    walk every ancestor directory up to root so `/caminho/path/`, `/caminho/` and
    `/` are all explored — "climb the path". The segment names (caminho/path/…)
    are folded into the dynamic vocabulary separately by `target_tokens`.

      * base_dir   — the directory to calibrate/scan at (parent dir for a file)
      * file_seed  — the file path to fetch/harvest, or None when the target is a dir
      * ancestors  — directories strictly ABOVE base_dir, deepest-first, incl. "/"
    """
    path = raw_path or "/"
    last = path.rsplit("/", 1)[-1]
    is_file = bool(last) and "." in last and not path.endswith("/")
    if is_file:
        base_dir = path[: len(path) - len(last)] or "/"
        file_seed: str | None = path
    else:
        base_dir = path if path.endswith("/") else path + "/"
        file_seed = None
    ancestors: list[str] = []
    cur = base_dir.rstrip("/")
    while cur:
        cur = cur.rsplit("/", 1)[0]
        anc = f"{cur}/" if cur else "/"
        ancestors.append(anc)
        if anc == "/":
            break
    return base_dir, file_seed, ancestors


def _over_budget(engine, opts) -> bool:
    """True when the run must stop firing — the request cap (--max-requests) or the
    wall-clock deadline (--time-limit) is reached. Checked in every fold's hot loop
    (the deadline lives on the engine, set once at scan start)."""
    if opts.max_requests and engine.spent >= opts.max_requests:
        return True
    dl = getattr(engine, "deadline", None)
    return dl is not None and time.monotonic() >= dl


async def _confirm(engine, profile, prefix, probe, origin):
    """classify + soft-404 sibling verification. Returns a real Finding or None.

    Folds fire speculative guesses (shortscan 8.3 expansions, backup twins,
    corpus associations); a guess that returns a 5xx is the server erroring on a
    bad path, not a discovered resource — so it's never a fold finding. (The main
    wordlist scan still reports a 5xx, where a single erroring endpoint matters.)
    """
    if probe.ok and probe.status >= 500:
        return None
    finding = classify(profile, probe, origin, prefix)
    if finding is None:
        return None
    if await _is_soft(engine, profile, prefix, probe):
        return None
    return finding


def _dedup_by_url(findings, ci=False):
    """Collapse repeats of the same URL to the highest-confidence one.

    Cheap and safe to run mid-scan — a resumed/re-fired prefix re-discovers URLs
    already in the restored findings, so without this the report would balloon
    with duplicates on every resume.
    """
    best: dict[str, Finding] = {}
    for f in findings:
        key = f.url.lower() if ci else f.url   # ci: a case-insensitive host (IIS)
        cur = best.get(key)                    # serves /Admin == /admin — one finding
        if cur is None or f.confidence > cur.confidence:
            best[key] = f
    return list(best.values())


def _dedupe_and_collapse(findings, observer, ci=False):
    """URL-dedup (keep best confidence) + collapse same-template collisions.

    Groups by (status, body length): a generic page reflected for many paths —
    a server's blanket "403 Forbidden" served for .env/.git/.htaccess/css/build,
    or a catch-all 200 — keeps the SAME length even when the body echoes the
    path (so simhash differs). More than COLLISION_MAX in a group collapse to one
    representative + a count. The real content found by recursion (distinct
    lengths) is untouched.
    """
    deduped = _dedup_by_url(findings, ci=ci)

    # Declared-contract findings (OpenAPI/.well-known) are never collapsed — each
    # is a real named endpoint the user wants listed, even when it returns 401/403.
    out: list = [f for f in deduped if f.origin in _DECLARED_ORIGINS]
    clusters: dict[tuple, list] = defaultdict(list)
    for f in deduped:
        if f.origin not in _DECLARED_ORIGINS:
            clusters[(f.status, f.length)].append(f)

    collapsed = 0
    for (status, length), group in clusters.items():
        if len(group) > COLLISION_MAX:
            rep = min(group, key=lambda f: len(f.url))
            rep.note = (rep.note + " " if rep.note else "") + f"+{len(group) - 1} paths, same {length}B response"
            out.append(rep)
            collapsed += len(group) - 1
        else:
            out.extend(group)
    if collapsed:
        observer.log(f"collapsed {collapsed} same-template results "
                     f"(generic 403/catch-all served for many paths)", 0, style="yellow")
    return out


def _report(observer, result, opts, finding, url, body=None) -> None:
    """Report a finding if it passes presentation filters (recursion already
    decided upstream, filter-independent).

    A URL already reported (by any earlier source — memory primes /trace.axd, then
    the priority list re-finds it; or an IIS host serves /WebServices == /webservices)
    is suppressed live, so the stream never shows the same resource twice. The key
    is case-normalized on a case-insensitive host. The set is primed from restored
    findings on resume."""
    ci = result.profile.case_sensitive is False
    if not result.seen_urls and result.findings:          # prime once (e.g. from findings restored on resume)
        for prev in result.findings:
            result.seen_urls.add(prev.url)
            result.seen_urls_lc.add(prev.url.lower())
    # consult the lower-cased set on a case-insensitive host, the raw one otherwise;
    # both are kept current so a case flip mid-scan stays consistent.
    if (url.lower() in result.seen_urls_lc) if ci else (url in result.seen_urls):
        observer.tick(hit=False)            # not a new resource — count the probe, don't re-list
        observer.request(url, finding.status, False)
        return
    shown = (opts.filters.accept(finding.status, finding.length)
             and opts.filters.accept_body(body, finding.simhash, finding.words, finding.lines))
    observer.tick(hit=shown)
    observer.request(url, finding.status, shown)
    if shown:
        result.seen_urls.add(url)
        result.seen_urls_lc.add(url.lower())
        result.findings.append(finding)
        if opts.finding_sink is not None:
            opts.finding_sink(finding)            # stream this confirmed finding (e.g. JSONL)
        # Block-wall flood control (live only): a server that forbids every
        # .env*/.git* path returns the SAME blocked-status body for each — a
        # generic block keyed on the sensitive substring, which the per-path
        # soft-403 sibling check can't catch (the random sibling lacks the
        # substring). Show the first COLLISION_MAX, then stop STREAMING the rest
        # (they're still kept and folded to one line in the report by
        # _dedupe_and_collapse). 2xx/3xx are left to that end collapse.
        wall = finding.status in _WALL_STATUS and finding.origin not in _DECLARED_ORIGINS
        n = 0
        if wall:
            sig = (finding.status, finding.length)
            n = result.wall_seen.get(sig, 0) + 1
            result.wall_seen[sig] = n
        if wall and n > COLLISION_MAX:
            if n == COLLISION_MAX + 1:
                observer.log(f"{finding.status} block-wall: identical {finding.length}B "
                             f"response repeating across paths — muting the live stream "
                             f"(folded into one in the report)", 0, style="yellow")
            observer.finding(finding, stream=False)     # counted, not printed
        else:
            observer.finding(finding)
            observer.log(f"+ {finding.status} {observer.disp(url)} · "
                         f"conf {finding.confidence:.2f} · {finding.origin}", 1, style="green")


async def _scan_prefix(engine, profile, prefix, cands, result, opts, observer, control,
                       ranker=None, skip=0, listed_dirs=None):
    """Fire candidates under `prefix` (already ordered by the caller). Returns
    (confirmed_dirs, ancestor_dirs, consumed, hit_cap): confirmed dirs (a
    403/301/trailing-slash response) are recursed first; ancestor dirs (merely
    inferred from a deep file path) are speculative. `consumed` is the index of
    the next unfired candidate and `hit_cap` is True when we stopped early on the
    request cap / quit — together they let a resume continue this prefix from
    where it stopped (`skip`) instead of re-running it whole."""
    confirmed_dirs: list[str] = []
    ancestor_dirs: list[str] = []
    first_hit_path: str | None = None
    # URLs already fired this prefix. Distinct candidate strings can resolve to
    # the SAME url — a memory seed "trace.axd" (app-relative) and a priority
    # "/trace.axd" (root-absolute) collide at the root prefix; on IIS case
    # variants collide too. Skip the repeat so we don't re-probe it.
    ci = profile.case_sensitive is False
    fired: set[str] = set()

    consumed = len(cands)
    hit_cap = False
    for idx in range(skip, len(cands)):
        cand = cands[idx]
        if (_over_budget(engine, opts)) or control.quit:
            consumed, hit_cap = idx, True       # stopped here — resume from idx (0 = unlimited)
            break
        if control.skip_prefix:
            control.skip_prefix = False
            if observer.skippable:
                observer.log(f"skip: {prefix} (next)", 0, style="yellow")
                break                           # user skipped the dir → it's done
            # no directory discovered yet → skipping would just end the scan
            # (same as quit), so ignore it.
            observer.log("(n ignored — no subdirectory discovered yet; use q to quit)",
                         0, style="dim")
        # Join against the host root so a base path like /lms/ never doubles.
        # A full URL (same-site CDN, scope=site) is fetched as-is; a leading-/
        # seed is root-absolute; a relative seed (Angular-style templateUrl, or a
        # payload with an internal ://) resolves under the current app prefix.
        url = _join_candidate(_host_root(profile.base_url), prefix, cand.path)
        if _excluded(urlparse(url).path, opts):     # safety rail — never fire it
            observer.tick(hit=False)
            continue
        ukey = url.lower() if ci else url
        if ukey in fired:                           # same URL as an earlier candidate
            observer.tick(hit=False)
            continue
        fired.add(ukey)
        # keep the body only when --filter-regex needs to match it — word/line
        # counts and the simhash are already on every probe, so the main scan
        # otherwise stays body-light for speed/memory.
        probe = await engine.fetch(url, keep_body=opts.filters.needs_body())
        path = urlparse(url).path

        # classify() = is this a REAL response (outside the calibrated miss
        # profile)? — no soft-verification yet. A 404 miss like /internal/ stops
        # here, so it never gets mistaken for a directory.
        finding = classify(profile, probe, cand.origin, prefix)
        if finding is None:
            if ranker is not None:
                ranker.observe(cand.path, hit=False)
            observer.tick(hit=False)
            observer.request(url, probe.status, False)
            continue

        # Directory detection from a REAL response (trailing-slash candidate or a
        # self-redirect to the same path + "/"). Done before the soft-verify so a
        # blanket-403 directory is still recursed (to find real 200s inside) even
        # though /dir/ itself isn't reported. Compare the redirect's PATH for
        # equality (not a suffix) so /login → /gateway/login isn't mistaken for a
        # directory self-redirect, while an absolute Location (http://h/x/) still
        # matches its own path.
        # A trailing-slash candidate is a directory UNLESS the server strips the
        # slash back off (canonicalization → not a real dir); a no-slash candidate
        # is a directory when the server adds the slash.
        redir = 300 <= probe.status < 400
        is_dir = ((cand.path.endswith("/") and not (redir and _strips_trailing_slash(probe.location, path)))
                  or (probe.status in (301, 302, 308)
                      and _is_self_redirect_dir(probe.location, path)))
        if is_dir:
            dpath = path if path.endswith("/") else path + "/"
            confirmed_dirs.append(dpath)
            observer.set_skippable(True)
            if listed_dirs is not None and 200 <= probe.status < 300 \
                    and is_dir_listing(probe.body_head):
                listed_dirs.add(dpath)        # autoindex → harvest it, don't blind-brute

        # soft-verify a surprising hit with a same-shape random sibling — a
        # blanket 403/200 wall is recursed (above) but NOT reported. The sibling
        # fetch is skipped once the request budget is spent (report unverified
        # rather than overrun --max-requests by one probe per finding).
        over_budget = bool(_over_budget(engine, opts))
        if not over_budget and await _is_soft(engine, profile, prefix, probe):
            if ranker is not None:
                ranker.observe(cand.path, hit=False)
            observer.tick(hit=False)
            observer.request(url, probe.status, False)
            continue

        if ranker is not None:
            ranker.observe(cand.path, hit=True)     # real, non-soft → reward the word
        if first_hit_path is None and probe.status == 200:
            first_hit_path = path
        # A confirmed (real, non-soft) path implies its parent dirs exist —
        # recurse them (a deep JS file /lms/x/views/y.html reveals /lms/x/ etc.).
        segs = [s for s in path.strip("/").split("/") if s]
        for i in range(1, len(segs)):
            ancestor_dirs.append("/" + "/".join(segs[:i]) + "/")
            observer.set_skippable(True)

        # --probe-405: the moment a 405 is found, test the write method it accepts
        # (POST/PATCH, empty/{} body) so the verdict rides this finding's live line.
        # Skip if this URL was already reported (and thus already probed) elsewhere.
        if opts.probe_405 and finding.status == 405:
            ci = result.profile.case_sensitive is False
            seen = (url.lower() in result.seen_urls_lc) if ci else (url in result.seen_urls)
            if not seen:
                await _probe_405_finding(engine, finding, opts, observer)

        _report(observer, result, opts, finding, url, body=probe.body or None)

    if first_hit_path:
        await bl.probe_case_sensitivity(engine, profile, first_hit_path)
    return confirmed_dirs, ancestor_dirs, consumed, hit_cap


_HARVEST_EXT = (".js", ".mjs", ".map", ".json", ".xml", ".html", ".htm", ".txt", ".csv")
_HARVEST_CODE = (".js", ".mjs", ".map", ".json")
MAX_HARVEST_FILES = 40    # discovered text responses we re-read for endpoints
MAX_HARVEST_NEW = 400     # new candidate paths a harvest pass may add
MAX_DISCOVERY_ROUNDS = 3  # walk → harvest → recurse new dirs → harvest → … (cap)
_HARVEST_DEPTH_BONUS = 3  # harvested dirs are evidence-based, so recurse them past the blind depth cap

# What an autoindex HIDES (Apache IndexIgnore / IIS hidden segments): the only
# names worth probing in a listed dir, since the listing itself reveals the rest.
_INDEX_HIDDEN = (".htaccess", ".htpasswd", ".git/", ".git/config", ".svn/", ".env",
                 ".DS_Store", ".gitignore", "web.config", "backup.zip", "backup.tar.gz",
                 ".bash_history", ".npmrc", "config.php.bak")


# Config/secret files (often served text/plain) belong to the SECRETS fold, not
# harvest — kept out of _harvestable so the partition routes them there.
_SECRET_CFG_EXT = (".env", ".ini", ".conf", ".cfg", ".yml", ".yaml", ".properties",
                   ".toml", ".pem", ".key", ".log", ".bak", ".old", ".htpasswd")


def _harvestable(f) -> bool:
    """A confirmed 2xx **text** response whose body likely holds more endpoints.

    Any `text/*` type qualifies (so a plain app route, a `text/plain` API dump or
    a CSV is mined, not just files with a known extension); JSON/XML/JS by content
    type too. Vendor libraries, binary/asset responses, and config/secret files
    (which the secrets fold owns) are skipped."""
    if not (200 <= f.status < 300):
        return False
    if js_parser._is_vendor(f.url):           # jquery/bootstrap/etc. — not the app's own code
        return False
    path = urlparse(f.url).path.lower()
    base = path.rstrip("/").rsplit("/", 1)[-1]
    if path.endswith(_SECRET_CFG_EXT) or base.startswith("."):   # config/dotfile → secrets fold
        return False
    ct = (f.content_type or "").lower()
    return (path.endswith(_HARVEST_EXT)
            or ct.startswith("text/")         # text/html, text/plain, text/csv, …
            or any(t in ct for t in ("javascript", "ecmascript", "json", "xml")))


async def _harvest_fold(engine, profile, result, opts, observer, base_prefix,
                        already=None) -> set[str]:
    """Read the target's OWN discovered code for more endpoints — the core fold.

    The root recon reads the homepage and its scripts; this extends that to every
    JS/JSON/spec/HTML file the SCAN itself turned up (a wordlist-found
    `/app/bundle.js` reveals `/app/api/v2/users` no wordlist would guess), then
    probes the new in-scope paths. Returns the set of directories the new findings
    live in, so the caller can recurse them — discovery that compounds: the more
    it finds, the more it reads, the more it finds."""
    files = [f for f in result.findings if _harvestable(f)
             and (already is None or f.url not in already)]   # skip files read in a prior round
    if not files:
        return set()
    # code/specs (js/json/map) before markup; most confident first; cap the radius
    files.sort(key=lambda f: (not urlparse(f.url).path.lower().endswith(_HARVEST_CODE),
                              -f.confidence))
    files = files[:MAX_HARVEST_FILES]
    if already is not None:
        already.update(f.url for f in files)
    observer.phase("harvest")
    observer.log(f"harvest: re-reading {len(files)} discovered files for endpoints",
                 0, style="cyan")
    root = _host_root(profile.base_url)

    # 1. read each file's body, extract referenced paths
    new_paths: dict[str, str] = {}            # path -> source file path (for graph edges)
    for f in files:
        if _over_budget(engine, opts):
            break
        observer.substep(urlparse(f.url).path.rsplit("/", 1)[-1] or f.url)
        pr = await engine.fetch(f.url, keep_body=True)
        if not (pr.ok and pr.body):
            continue
        _scan_body(f, pr.body, observer, opts.finding_sink, profile.bucket_refs)
        extracted = js_parser.extract_paths(pr.body, f.url)
        if is_dir_listing(pr.body):               # autoindex → read its TRUE contents, don't guess
            extracted |= js_parser.parse_listing(pr.body, f.url)
        for p in extracted:
            new_paths.setdefault(p, urlparse(f.url).path)

    # 2. scope + drop what we already probed/found, then cap
    scoped = _scope_paths(set(new_paths), profile.host, opts.scope)
    tgt_path = urlparse(profile.base_url).path or "/"          # tenant chain, shared hosts
    confine = path_tenant_host(profile.host)
    fresh = [(p, new_paths[p]) for p in sorted(scoped)
             if urljoin(root, p.lstrip("/")).lower() not in result.seen_urls_lc
             and not _excluded("/" + p.lstrip("/"), opts)      # honor --exclude / --exclude-ext
             and not (confine and p.startswith("/") and not same_tenant_path(tgt_path, p))]
    fresh = fresh[:MAX_HARVEST_NEW]
    if not fresh:
        observer.log("harvest: no endpoints beyond what's already found", 1)
        return set()
    observer.log(f"harvest: {len(fresh)} new candidate endpoints from discovered code",
                 0, style="cyan")

    # 3. calibrate the contexts they touch, then confirm-probe each
    by_prefix: dict[str, set[str]] = {}
    for p, _ in fresh:
        pth = "/" + p.lstrip("/")
        by_prefix.setdefault(pth.rsplit("/", 1)[0] + "/", set()).add(_ext_of(pth))
    for prefix, pexts in by_prefix.items():
        await bl.calibrate(engine, profile,
                           [(prefix, e) for e in (set(_BASE_CALIB_EXTS) | pexts)])

    observer.start_prefix("harvest", len(fresh))
    new_dirs: set[str] = set()                    # dirs the confirmed endpoints live in
    for p, src in fresh:
        if _over_budget(engine, opts):
            break
        pth = "/" + p.lstrip("/")
        if _excluded(pth, opts):
            continue
        url = urljoin(root, p.lstrip("/"))
        prefix = urlparse(url).path.rsplit("/", 1)[0] + "/"
        probe = await engine.fetch(url)
        finding = await _confirm(engine, profile, prefix, probe, "harvest")
        if finding is None:
            observer.tick(hit=False)
            observer.request(url, probe.status, False)
            continue
        if opts.graph:
            result.edges.append((src, pth))
        _report(observer, result, opts, finding, url)
        new_dirs.add(prefix)                      # recurse the dir this endpoint lives in
    return new_dirs


def _note_secrets(finding, body, observer) -> int:
    """Scan one body for secrets; tag + annotate the finding. Returns count."""
    hits = secrets.scan(body)
    if not hits:
        return 0
    preview = ", ".join(f"{k}={v}" for k, v in hits[:6])
    if "secret" not in finding.tags:
        finding.tags = list(finding.tags) + ["secret"]
    finding.note = (finding.note + " · " if finding.note else "") + f"secrets: {preview}"
    observer.log(f"secret: {observer.disp(finding.url)} → {preview}", 0, style="bold red")
    return len(hits)


def _note_leaks(finding, body, observer) -> int:
    """Scan one body for information disclosure (stack traces, framework debug
    pages, internal IPs/hosts); tag `leak` + annotate the finding. Returns count."""
    # JS bundles: skip the infra (IP/host) patterns — there they're SVG-float /
    # minified-property noise, not real leaks.
    ct = (finding.content_type or "").lower()
    path = urlparse(finding.url).path.lower()
    js = "javascript" in ct or "ecmascript" in ct or path.endswith((".js", ".mjs"))
    hits = leaks.scan(body, js=js)
    if not hits:
        return 0
    preview = ", ".join(f"{k}={v}" for k, v in hits[:4])
    if "leak" not in finding.tags:
        finding.tags = list(finding.tags) + ["leak"]
    finding.note = (finding.note + " · " if finding.note else "") + f"leak: {preview}"
    observer.log(f"leak: {observer.disp(finding.url)} → {preview}", 0, style="bold yellow")
    return len(hits)


def _scan_body(finding, body, observer, sink=None, bucket_refs=None) -> int:
    """Run all body-content analyzers (secrets + content-intel leaks) on a body
    we already have in hand, then re-emit the now-enriched finding ONCE via `sink`
    (opts.finding_sink) so a JSONL consumer sees the secret/leak tags even though
    detection happens post-confirm. Returns the total number of hits. Cloud
    storage references are accumulated into `bucket_refs` for the bucket fold."""
    if bucket_refs is not None:
        bucket_refs |= buckets.find_bucket_refs(body)
    n = _note_secrets(finding, body, observer) + _note_leaks(finding, body, observer)
    if n and sink is not None:
        sink(finding)
    return n


# Files most likely to carry credentials (scanned by the secrets fold).
_SECRET_EXT = (".env", ".json", ".yml", ".yaml", ".xml", ".config", ".ini", ".properties",
               ".toml", ".conf", ".cfg", ".txt", ".bak", ".old", ".pem", ".key", ".log",
               ".js", ".mjs", ".map", ".php", ".rb", ".py", ".sh")
_SECRET_HINT = ("/.env", "/.git/", "config", "secret", "credential", "settings",
                "backup", ".aws", "dump", "wp-config")
MAX_SECRET_FILES = 40


def _content_candidate(f) -> bool:
    # 5xx error pages are a prime stack-trace / debug-leak source — read them too.
    if 500 <= f.status < 600:
        return True
    if not (200 <= f.status < 300):
        return False
    path = urlparse(f.url).path.lower()
    ct = (f.content_type or "").lower()
    return (path.endswith(_SECRET_EXT)
            or any(h in path for h in _SECRET_HINT)
            or bool(set(getattr(f, "tags", [])) & {"config", "disclosure", "source", "debug"})
            or f.origin in ("bypass403", "backup")
            or any(t in ct for t in ("javascript", "json", "xml", "yaml", "plain", "html")))


async def _secrets_fold(engine, profile, result, opts, observer) -> None:
    """Read high-value files (configs/dotfiles/backups/bypassed denials) and 5xx
    error pages, then flag credentials (secrets) AND information disclosure (stack
    traces, framework debug pages, internal IPs) inside — the payoff of finding the
    file in the first place. JS/JSON already read by the harvest fold are skipped
    (no double-fetch); those bodies are scanned there."""
    cands = [f for f in result.findings if _content_candidate(f) and not _harvestable(f)]
    if not cands:
        return
    # configs/dotfiles/bypassed first, then smaller files; cap the radius
    cands.sort(key=lambda f: (f.origin not in ("bypass403", "backup"), f.length))
    cands = cands[:MAX_SECRET_FILES]
    observer.log(f"content: scanning {len(cands)} files for secrets + disclosure", 0, style="cyan")
    total = 0
    cfg_seeds: set[str] = set()          # same-host paths referenced inside configs → new seeds
    for f in cands:
        if _over_budget(engine, opts):
            break
        pr = await engine.fetch(f.url, keep_body=True)
        if pr.ok and pr.body:
            total += _scan_body(f, pr.body, observer, opts.finding_sink, profile.bucket_refs)
            cfg_seeds |= _scope_paths(js_parser.extract_paths(pr.body, f.url),
                                      profile.host, opts.scope)
    if total:
        observer.log(f"content: {total} secret/disclosure hit(s) flagged — see the 'secret'/'leak' tags",
                     0, style="bold yellow")

    # Config-referenced same-host paths become new seeds (a leaked .env/appsettings
    # names /internal endpoints no wordlist would guess). Off-host refs are left to
    # the bucket fold / not scanned. Bounded + de-duped against what's already found.
    host = _host_root(profile.base_url)
    fresh = []
    for p in sorted(cfg_seeds):
        if "://" in p and not p.startswith(("http://", "https://")):
            continue                     # s3://, gs://, mailto: … — not a scannable path
        url = _join_candidate(host, "/", p)
        if url in result.seen_urls or _excluded(urlparse(url).path, opts):
            continue
        fresh.append(url)
    fresh = fresh[:MAX_CONFIG_SEEDS]
    if fresh:
        observer.log(f"config: probing {len(fresh)} path(s) referenced inside config files",
                     0, style="cyan")
        observer.start_prefix("config", len(fresh))
        for url in fresh:
            if _over_budget(engine, opts):
                break
            probe = await engine.fetch(url)
            prefix = urlparse(url).path.rsplit("/", 1)[0] + "/"
            finding = await _confirm(engine, profile, prefix, probe, "config")
            if finding is None:
                observer.tick(hit=False)
                observer.request(url, probe.status, False)
                continue
            _report(observer, result, opts, finding, url)


MAX_CONFIG_SEEDS = 60   # cap paths enumerated from config-file references
MAX_VHOSTS = 60   # cap Host-header candidates probed


MAX_GQL_PROBES = 12   # benign query-op probes (queries ONLY — never mutations)


async def _graphql_probe(engine, opts, observer, gf, gql_url, meta) -> None:
    """Send a benign, no-arg query for the top root QUERY operations — NEVER
    mutations, since calling those changes state — to learn which respond WITHOUT
    auth. An 'open' (returned data) or 'reachable' (past the gate, only a
    validation error) response is an auth-bypass / BOLA lead — the GraphQL analog
    of probing which Swagger paths answer unauthenticated. Sensitive ops go first.
    Annotates the introspection finding with the verdict."""
    q_ops = meta.get("queries") or []
    sens = set(meta.get("sensitive") or [])
    ordered = [o for o in q_ops if o in sens] + [o for o in q_ops if o not in sens]
    ordered = ordered[:MAX_GQL_PROBES]
    if not ordered:
        return
    observer.phase("graphql-probe")
    observer.log(f"graphql: probing {len(ordered)} query op(s) for unauth access "
                 f"(queries only, no mutations)", 0, style="cyan")
    open_ops, reachable_ops = [], []
    for op in ordered:
        if _over_budget(engine, opts):
            break
        try:
            pr = await engine.fetch(gql_url, method="POST", keep_body=True,
                                    json={"query": graphql.build_probe_query(op)})
        except Exception:
            continue
        observer.request(gql_url, pr.status, False)
        verdict = graphql.classify_probe(pr.status, pr.body or b"", op)
        if verdict == "open":
            open_ops.append(op)
        elif verdict == "reachable":
            reachable_ops.append(op)
    if not (open_ops or reachable_ops):
        observer.log("graphql: all probed ops require auth (gate enforced)", 1, style="green")
        return
    # `op!` = returned data unauthenticated (strongest); plain = reachable past the gate.
    detail = ", ".join(f"{o}!" for o in open_ops) \
        + (", " if open_ops and reachable_ops else "") + ", ".join(reachable_ops)
    gf.note = (gf.note + " · " if gf.note else "") + f"reachable WITHOUT auth: {detail}"
    gf.tags = list(dict.fromkeys(gf.tags + ["auth-bypass"]))
    if open_ops:
        gf.confidence = max(gf.confidence, 0.9)
    hot = [o for o in (open_ops + reachable_ops) if o in sens]
    observer.log(f"graphql: {len(open_ops)} op(s) return data + {len(reachable_ops)} reachable "
                 f"WITHOUT auth" + (f" — incl. sensitive: {', '.join(hot[:6])}" if hot else "")
                 + " → auth-bypass/BOLA lead", 0, style="bold red")
    if opts.finding_sink is not None:
        opts.finding_sink(gf)


async def _vhost_fold(engine, profile, result, opts, observer, root_simhash) -> None:
    """Virtual-host discovery: fuzz the Host header on the target's endpoint and
    report Hosts whose response differs from BOTH a bogus-Host baseline (the
    catch-all for unknown vhosts) and the default site — distinct vhosts the path
    scan can't see. Results are de-duped by response signature, so ten aliases of
    one app collapse to one finding."""
    observer.phase("vhost")
    root = _host_root(profile.base_url)
    scheme = urlparse(profile.base_url).scheme or "https"

    # baseline: a bogus Host = how the server answers an unknown vhost
    rnd = "".join(random.choices(string.ascii_lowercase, k=12))
    base = await engine.fetch(root, headers={"Host": f"{rnd}.invalid"})
    cands = vhost.candidates(profile.host)[:MAX_VHOSTS]
    observer.log(f"vhost: probing {len(cands)} Host-header candidates", 0, style="cyan")
    observer.start_prefix("vhost", len(cands))
    seen_sig: set[tuple] = set()
    for cand in cands:
        if _over_budget(engine, opts):
            break
        observer.substep(cand)
        pr = await engine.fetch(root, headers={"Host": cand})
        observer.request(root, pr.status, False)
        # tick per non-hit probe here; _report ticks once for a confirmed vhost
        if not pr.ok or pr.status in NOT_FOUND_STATUS:
            observer.tick(hit=False); continue
        # same as the bogus baseline → not a distinct vhost (server ignores Host)
        if base.ok and pr.status == base.status and \
                hamming(pr.body_simhash, base.body_simhash) <= bl.SIMHASH_MISS_DISTANCE:
            observer.tick(hit=False); continue
        # same as the default site → it's just the target again
        if hamming(pr.body_simhash, root_simhash) <= bl.SIMHASH_MISS_DISTANCE:
            observer.tick(hit=False); continue
        sig = (pr.status, pr.body_simhash)
        if sig in seen_sig:                       # collapse aliases of the same app
            observer.tick(hit=False); continue
        seen_sig.add(sig)
        url = f"{scheme}://{cand}/"
        vf = Finding(url, pr.status, pr.length, pr.content_type, 0.8, "vhost",
                     note=f"distinct vhost on this IP (Host: {cand})",
                     tags=["vhost"], simhash=pr.body_simhash)
        _report(observer, result, opts, vf, url)
        observer.log(f"vhost: {cand} → {pr.status} ({pr.length}B) distinct response",
                     0, style="bold cyan")


MAX_ORIGIN_IPS = 25       # cap candidate IPs we probe directly


def _is_origin_serve(status: int, body_len: int, edge_ip: bool) -> bool:
    """A candidate IP is a possible origin only when it's a NON-edge box that
    actually serves the target Host — a 2xx with a real body. A 404/403/5xx/
    redirect (or the edge IP itself) is NOT a lead: that's what wrongly flagged an
    unrelated sibling's 404 page as a 'possible origin'."""
    return (not edge_ip) and 200 <= status < 300 and body_len > 0


async def _origin_fold(engine, profile, result, opts, observer, root_simhash) -> None:
    """Origin-IP discovery + IP-based WAF bypass. Resolve the host's own A/AAAA
    records, gather OSINT candidate origin IPs (keyed sources, else crt.sh), then
    request each IP directly with the target's `Host` header (TLS verify off). An
    IP that serves distinct content — or opens a path the edge WAF blocks — is a
    likely origin reachable behind the CDN, reported as a bypass lead."""
    import httpx
    observer.phase("origin")
    host = profile.host.split(":")[0]
    pu = urlparse(profile.base_url)
    scheme = pu.scheme or "https"
    port = pu.port or (443 if scheme == "https" else 80)

    edge_ips = await originip.resolve_ips(host, port=port)
    cands, source = await originip.candidate_origin_ips(host)
    all_ips = list(dict.fromkeys(edge_ips + [ip for ip in cands if ip not in edge_ips]))
    all_ips = all_ips[:MAX_ORIGIN_IPS]
    if not all_ips:
        observer.log("origin: no IPs resolved for the target", 0, style="yellow")
        return
    behind = profile.waf or profile.cache_layer
    keyed = originip.configured_sources()
    observer.log(f"origin: {len(edge_ips)} edge IP(s) + {len(cands)} candidate(s) via "
                 f"{source}" + (f" (keyed: {'+'.join(keyed)})" if keyed else " (keyless)")
                 + (f"; edge WAF/CDN: {behind}" if behind else ""), 0, style="cyan")
    observer.start_prefix("origin", len(all_ips))

    # a representative edge-blocked path — if it opens on an IP, that's a real bypass
    blocked = next((urlparse(f.url).path for f in result.findings
                    if f.status in (401, 403)), None)
    seen_sig: set[tuple] = set()

    async with httpx.AsyncClient(verify=False, timeout=engine.cfg.timeout,
                                 follow_redirects=False,
                                 headers={"User-Agent": engine.cfg.user_agent,
                                          **engine.cfg.headers}) as c:
        for ip in all_ips:
            if _over_budget(engine, opts):
                break
            observer.substep(ip)
            hp = f"[{ip}]" if ":" in ip else ip          # bracket IPv6 literals
            root_url = f"{scheme}://{hp}:{port}/"
            try:
                pr = await c.get(root_url, headers={"Host": host})
            except Exception:
                observer.tick(hit=False); continue        # IP not reachable on this port
            observer.request(root_url, pr.status_code, False)
            body = pr.content or b""
            sh = simhash(body)
            edge_ip = ip in edge_ips
            # An origin lead is a NON-edge IP that actually SERVES the target Host —
            # a 2xx with a real body. It means the box is configured for this vhost,
            # i.e. likely the origin reachable behind the CDN. A 404/403/5xx/redirect
            # means the IP is NOT this app's origin (a sibling/unrelated server that
            # merely resolved from crt.sh), so it's not a lead — this is the check
            # that stops flagging every distinct 404 page as a "possible origin".
            origin_serve = _is_origin_serve(pr.status_code, len(body), edge_ip)

            bypass = False
            if blocked and not edge_ip:                   # WAF-bypass angle (only off the edge)
                try:
                    bp = await c.get(f"{scheme}://{hp}:{port}{blocked}", headers={"Host": host})
                    bypass = 200 <= bp.status_code < 300 and len(bp.content or b"") > 0
                except Exception:
                    pass

            if not (origin_serve or bypass):
                observer.tick(hit=False); continue
            sig = (pr.status_code, sh)
            if sig in seen_sig:                           # collapse load-balanced twins
                observer.tick(hit=False); continue
            seen_sig.add(sig)
            role = f"candidate via {source}"
            # a 2xx body matching the edge's = the SAME app served directly (strong
            # origin); a distinct 2xx is a weaker lead (could be an unrelated vhost).
            same_app = origin_serve and hamming(sh, root_simhash) <= bl.SIMHASH_MISS_DISTANCE
            if bypass:
                note = f"WAF bypass: edge-blocked {blocked} → 200 direct on {ip} (Host: {host})"
                conf = 0.85
            elif same_app:
                note = f"{ip} serves the SAME app as the edge directly (Host: {host}) — likely origin behind the CDN [{role}]"
                conf = 0.8
            else:
                note = f"{ip} serves 200 for Host: {host} directly — possible origin/related vhost [{role}]"
                conf = 0.55
            url = f"{scheme}://{ip}/"
            of = Finding(url, pr.status_code, len(body), pr.headers.get("content-type", ""),
                         conf, "origin", note=note,
                         tags=sorted({"origin"} | ({"bypass"} if bypass else set())), simhash=sh)
            _report(observer, result, opts, of, url)
            observer.log(f"origin: {ip} → {'WAF BYPASS' if bypass else 'serves 200 (possible origin)'} "
                         f"({pr.status_code}, {len(body)}B) [{role}]", 0,
                         style="bold green" if bypass else "bold cyan")


MAX_FUZZ_ENDPOINTS = 15   # cap dynamic endpoints we fuzz params on
MAX_FUZZ_PARAMS = 160     # cap distinct param names tried per endpoint
FUZZ_BATCH = 20           # params per request (each gets its own canary)
MAX_BREAKOUT_PARAMS = 15  # XSS-context params verified in ONE breakout probe per endpoint
_DYN_EXT = (".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action", ".cgi",
            ".pl", ".ashx", ".asmx", ".json", ".cfm")


def _fuzz_candidate(f) -> bool:
    """A dynamic endpoint worth fuzzing params on: a 2xx app route / script /
    API (reads query params), or a 3xx redirect (prime open-redirect territory —
    a reflected param in its Location is the lead). Static assets don't qualify."""
    if 300 <= f.status < 400:
        return True                              # redirect endpoint → open-redirect check
    if not (200 <= f.status < 300):
        return False
    last = urlparse(f.url).path.rstrip("/").rsplit("/", 1)[-1].lower()
    ct = (f.content_type or "").lower()
    if last.endswith(_DYN_EXT):
        return True
    if "." not in last:                          # no extension → app route
        return True
    return ("html" in ct or "json" in ct) and bool(set(getattr(f, "tags", [])) & {"api"})


async def _param_fold(engine, profile, result, opts, observer) -> None:
    """Fire harvested + common parameter names at dynamic endpoints and flag the
    ones whose canary reflects — real inputs (XSS/SSTI/open-redirect leads). An
    endpoint that echoes the control canary (any query) is skipped to avoid FPs."""
    targets = [f for f in result.findings if _fuzz_candidate(f)]
    if not targets:
        return
    # api-tagged + dynamic-ext first, then shorter URLs; cap the radius
    targets.sort(key=lambda f: ("api" not in getattr(f, "tags", []),
                                not urlparse(f.url).path.rstrip("/").rsplit("/", 1)[-1].lower().endswith(_DYN_EXT),
                                len(f.url)))
    targets = targets[:MAX_FUZZ_ENDPOINTS]
    params = paramfuzz.safe_names(list(profile.parameters) + paramfuzz.COMMON)[:MAX_FUZZ_PARAMS]
    if not params:
        return
    n_batches = (len(params) + FUZZ_BATCH - 1) // FUZZ_BATCH
    observer.phase("params")
    observer.log(f"params: fuzzing {len(params)} parameter names across "
                 f"{len(targets)} dynamic endpoints", 0, style="cyan")
    observer.start_prefix("params", len(targets) * n_batches)
    total = 0
    for f in targets:
        if _over_budget(engine, opts):
            break
        observer.substep(urlparse(f.url).path.rsplit("/", 1)[-1] or f.url)
        found: dict[str, str] = {}            # param -> reflection context (js/html/attr/json/body)
        redirect_params: set[str] = set()     # canary echoed in Location → open-redirect lead
        header_hits: dict[str, str] = {}       # param -> response-header name it reflected in
        echoes = False
        sep = "&" if urlparse(f.url).query else "?"
        for qs, token_map, ctl in paramfuzz.build_batches(params, FUZZ_BATCH):
            if _over_budget(engine, opts):
                break
            pr = await engine.fetch(f.url + sep + qs, keep_body=True)
            observer.tick(hit=False)
            observer.request(f.url, pr.status, False)
            if not pr.ok:
                continue
            # Location/header reflection is inspected BEFORE the empty-body guard —
            # an open-redirect 3xx usually has no body but a reflected Location.
            redirect_params.update(paramfuzz.reflected_in_location(pr.location, token_map))
            for p, h in paramfuzz.reflected_in_headers(pr.headers, token_map).items():
                header_hits.setdefault(p, h)
            if not pr.body:
                continue
            if paramfuzz.control_reflected(pr.body, ctl):    # echoes any query → no signal
                echoes = True
                break
            for param, ctx in paramfuzz.reflection_contexts(pr.body, token_map, pr.content_type).items():
                found[param] = ctx                # last batch wins; contexts are stable per endpoint
        if echoes:
            observer.log(f"params: {observer.disp(f.url)} reflects any query param — skipped",
                         1, style="yellow")
            continue

        # Breakout verification: for params that reflected into an XSS sink, one
        # extra probe with `'"<>{{7*7}}` proves whether the metacharacters come
        # back RAW (real XSS) vs escaped, and whether {{7*7}} evaluated (SSTI).
        verified: dict[str, dict] = {}
        xss_ctx = [p for p, c in found.items() if c in ("js", "html", "attr")]
        if xss_ctx and not _over_budget(engine, opts):
            bqs, sent_map = paramfuzz.build_breakout_batch(xss_ctx, cap=MAX_BREAKOUT_PARAMS)
            if bqs:
                bpr = await engine.fetch(f.url + sep + bqs, keep_body=True)
                observer.tick(hit=False)
                observer.request(f.url, bpr.status, False)
                if bpr.ok and bpr.body:
                    verified = paramfuzz.analyze_breakout(bpr.body, sent_map)

        if not (found or redirect_params or header_hits):
            continue

        def _verdict(param: str, ctx: str) -> str:
            v = verified.get(param)
            bits = []
            if v:
                if "<" in v["raw"] and ">" in v["raw"]:
                    bits.append(f"UNESCAPED {v['raw']}")
                elif ctx in ("js", "html", "attr"):
                    bits.append("escaped")
                if v["ssti"]:
                    bits.append("SSTI 7*7→49")
            return f"{param} ({ctx}{', ' + ', '.join(bits) if bits else ''})"

        xss = any("<" in v["raw"] and ">" in v["raw"] for v in verified.values())
        ssti = any(v["ssti"] for v in verified.values())
        new_tags = ["param"]
        if xss:
            new_tags.append("xss-lead")           # now: VERIFIED raw reflection in an HTML/JS sink
        if ssti:
            new_tags.append("ssti-lead")
        if redirect_params:
            new_tags.append("redirect-lead")
        f.tags = list(dict.fromkeys(list(f.tags) + new_tags))

        parts = []
        if found:
            ranked = sorted(found.items(), key=lambda kv: (-paramfuzz._CTX_RANK.get(kv[1], 0), kv[0]))
            preview = ", ".join(_verdict(p, c) for p, c in ranked[:8]) \
                + (f" (+{len(ranked) - 8})" if len(ranked) > 8 else "")
            parts.append(f"reflected params: {preview}")
        if redirect_params:
            parts.append("open-redirect: " + ", ".join(sorted(redirect_params)) + " → Location")
        if header_hits:
            parts.append("header reflection: "
                         + ", ".join(f"{p}→{h}" for p, h in sorted(header_hits.items())))
        f.note = (f.note + " · " if f.note else "") + " · ".join(parts)
        style = "bold red" if (xss or ssti) else "bold green"
        observer.log(f"param: {observer.disp(f.url)} ← {' · '.join(parts)}", 0, style=style)
        if opts.finding_sink is not None:
            opts.finding_sink(f)
        total += len(found) + len(redirect_params) + len(header_hits)
    if total:
        observer.log(f"params: {total} reflected input(s) flagged — see 'param'/'xss-lead'/"
                     f"'ssti-lead'/'redirect-lead' tags", 0, style="cyan")


MAX_CACHE_TARGETS = 12          # cap endpoints probed for cache poisoning
MAX_CACHE_TARGETS_LIGHT = 4     # tighter cap at --cache-poison light


def _cache_candidate(f) -> bool:
    """A 2xx endpoint worth probing for cache poisoning."""
    return 200 <= f.status < 300 and f.length > 0


def _differs(a, b) -> bool:
    """True if probe `b`'s response meaningfully differs from baseline `a` —
    a different status or a body beyond soft-404 simhash distance."""
    if not (a.ok and b.ok):
        return False
    if a.status != b.status:
        return True
    return hamming(a.body_simhash, b.body_simhash) > bl.SIMHASH_MISS_DISTANCE


async def _cache_poison_fold(engine, profile, result, opts, observer, root_simhash) -> None:
    """Probe cacheable endpoints for unkeyed inputs (X-Forwarded-Host & friends).

    For each target: fetch a cache-busted baseline, then replay it with one
    unkeyed header at a time (each on its OWN throwaway cache-buster). An input
    is interesting when the response either reflects its canary or differs from
    the baseline (unkeyed-but-processed). It's CONFIRMED poisonable when a final
    re-fetch of that same throwaway key — WITHOUT the header — still serves the
    injected content (proof the cache stored it). Safety invariant: every request
    carries a unique `?cb=` token, so we never read or write the cache key real
    users hit; confirmation re-fetches our sandbox key, never the bare URL."""
    intensity = opts.cache_poison or "auto"
    targets = [f for f in result.findings if _cache_candidate(f)]
    if not targets:
        return
    # cacheable/api endpoints first, then shorter URLs; cap the radius
    targets.sort(key=lambda f: ("cache" not in getattr(f, "tags", []),
                                "api" not in getattr(f, "tags", []),
                                len(f.url)))
    cap = MAX_CACHE_TARGETS_LIGHT if intensity == "light" else MAX_CACHE_TARGETS
    targets = targets[:cap]
    extra = bypass403.load_header_pairs(opts.cache_headers) if opts.cache_headers else None
    if opts.cache_headers and not extra:
        observer.log(f"cache-poison: header wordlist {opts.cache_headers} empty or "
                     f"unreadable — using the built-in set", 0, style="yellow")
    hdrs = cache_poison.header_set(intensity, extra)
    run = paramfuzz.run_prefix()
    observer.phase("cache-poison")
    observer.log(f"cache-poison: probing {len(targets)} endpoints for unkeyed inputs "
                 f"({intensity}, {len(hdrs)} headers)"
                 + (f" · cache-layer {profile.cache_layer}" if profile.cache_layer else ""),
                 0, style="cyan")
    observer.start_prefix("cache-poison", len(targets) * (1 + len(hdrs)))
    found = 0
    for f in targets:
        if _over_budget(engine, opts):
            break
        url = f.url
        observer.substep(urlparse(url).path.rsplit("/", 1)[-1] or url)
        # cache-busted baseline — the sandbox key nothing else ever touches
        burl = cache_poison.with_buster(url, f"{run}base")
        base = await engine.fetch(burl, keep_body=True)
        observer.tick(hit=False); observer.request(burl, base.status, False)
        if not (base.ok and base.body):
            continue
        base_cacheable = (cache_poison.is_cacheable(base.headers)
                          or cache_poison.cache_status(base.headers) == "HIT")
        # auto/light only spend the header budget where caching is plausible;
        # full probes regardless (the cache may simply not advertise itself).
        if intensity != "full" and not (base_cacheable or profile.cache_layer):
            continue
        # If the endpoint echoes its OWN cache-buster, every probe's body differs
        # from the baseline by the (distinct) cb token alone — the "response
        # differs → unkeyed" signal is then worthless and would flag every header.
        # Detect it once and fall back to the robust signal only: a header canary
        # that reflects AND survives the cache (it can't come from the query).
        echoes = f"{run}base".encode() in base.body.lower()
        for i, (name, tmpl) in enumerate(hdrs):
            if _over_budget(engine, opts):
                return
            canary = f"{run}cp{i}"
            has_can = cache_poison.has_canary(tmpl)
            value = tmpl.format(canary=canary) if has_can else tmpl
            purl = cache_poison.with_buster(url, f"{run}h{i}")   # fresh key per probe
            probe = await engine.fetch(purl, keep_body=True, headers={name: value})
            observer.tick(hit=False); observer.request(purl, probe.status, False)
            if not probe.ok:
                continue
            ctx = ""
            if has_can and probe.body:
                ctx = paramfuzz.reflection_contexts(probe.body, {canary: name},
                                                    probe.content_type).get(name, "")
                if not ctx and cache_poison.canary_in_headers(probe.headers, canary):
                    ctx = "header"
            unkeyed = _differs(base, probe) and not echoes
            if not (ctx or unkeyed):
                continue
            # Confirm cacheability on OUR throwaway key: re-fetch the SAME ?cb
            # WITHOUT the header. If the injected content still comes back, the
            # cache stored our poisoned response → confirmed. Never the bare URL.
            confirm = await engine.fetch(purl, keep_body=True)
            observer.request(purl, confirm.status, False)
            if has_can and ctx:
                cached = (confirm.ok and (canary.encode() in confirm.body.lower()
                          or cache_poison.canary_in_headers(confirm.headers, canary)))
            else:
                cached = (_differs(base, confirm) and not _differs(probe, confirm))
            cached = cached or cache_poison.cache_status(confirm.headers) == "HIT"
            where = ctx or "behaviour-change"
            if cached:
                note = f"cache poisoning: unkeyed '{name}' reflected/cached ({where})"
                f.tags = list(dict.fromkeys(list(f.tags) + ["cache", "poisonable"]))
                f.confidence = max(f.confidence, 0.9)
                style = "bold magenta"
            else:
                note = f"cache-poison lead: unkeyed '{name}' ({where}) — cacheability unconfirmed"
                f.tags = list(dict.fromkeys(list(f.tags) + ["cache"]))
                style = "magenta"
            f.note = (f.note + " · " if f.note else "") + note
            observer.log(f"cache-poison: {observer.disp(url)} ← {note}", 0, style=style)
            if opts.finding_sink is not None:
                opts.finding_sink(f)
            found += 1
            break                           # one primitive per endpoint is enough
    if found:
        observer.log(f"cache-poison: {found} endpoint(s) with unkeyed inputs flagged "
                     f"— see the 'poisonable'/'cache' tag", 0, style="cyan")


# Empty-body probes for method discovery, ordered most-likely-accepted first: an
# empty JSON object (modern APIs), a truly empty body, then an empty form. An
# endpoint that processes any of these (a 400/422 validation error, a 401 auth
# wall, or a 2xx) is confirmed to accept the method — without sending real data
# that could create/trigger something.
_METHOD_BODIES = (
    (b"{}", "application/json", "json"),
    (b"", "", "empty"),
    (b"", "application/x-www-form-urlencoded", "form"),
)


def _body_hint(probe, limit: int = 120) -> str:
    """A short one-line snippet of a method-probe response body — usually the JSON
    validation error that reveals the endpoint's expected input (`{"message":
    "username is required"}`). '' for an empty, binary, or HTML-error body."""
    raw = (getattr(probe, "body", b"") or b"")[:400]
    if not raw:
        return ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    text = " ".join(text.split())
    if not text or text.startswith("<"):          # empty or an HTML page — no useful hint
        return ""
    return text[:limit] + ("…" if len(text) > limit else "")

# Statuses that mean "try the next body variant": wrong path/method (404/405), or
# 415 Unsupported Media Type — the body's content-type is wrong, so another
# variant may be accepted (don't stop on the 415, which is the signal to retry).
_METHOD_RETRY = (404, 405, 415)


def _method_probe_rank(pr) -> int:
    """How informative a method-probe response is: a real processing result
    (2xx/400/401/422/500…) > 415 (method accepted, media type wrong) > 404/405
    (path/method wrong) > nothing."""
    if pr is None:
        return -1
    if pr.status in (404, 405):
        return 0
    if pr.status == 415:
        return 1
    return 2


async def _try_method(engine, url, method, opts, observer):
    """Fire `method` at `url` with each empty-body variant; return the most
    informative probe (real processing > 415 > 404/405), or None if all failed.
    A 415 keeps trying the other content-types instead of settling for it.

    Logs each probe to the live request stream but does NOT tick the prefix
    progress bar — these are inline side-probes, not budgeted scan candidates."""
    best, best_label = None, ""
    for body, ctype, label in _METHOD_BODIES:
        if _over_budget(engine, opts):
            break
        kw = {"content": body}
        if ctype:
            kw["headers"] = {"Content-Type": ctype}
        pr = await engine.fetch(url, method=method, keep_body=True, **kw)
        observer.request(url, pr.status, False)
        if not pr.ok:
            continue
        if _method_probe_rank(pr) > _method_probe_rank(best):
            best, best_label = pr, label
        if pr.status not in _METHOD_RETRY:
            break                                 # endpoint actually processed it — stop
    return best, best_label


async def _probe_405_finding(engine, finding, opts, observer) -> bool:
    """Right when a 405 (method-not-allowed) is found, replay it with a safe WRITE
    method — POST, plus PATCH iff the server's `Allow` advertises it (NEVER
    PUT/DELETE) — carrying an empty and a `{}` body, and annotate `finding` in
    place with the method it accepts. Returns True if a write method was accepted.

    Probed inline (under `--probe-405`) so the result rides the finding in the
    live stream and a partial/interrupted scan still tests what it found. Bodies
    are empty/`{}` (usually 400/422) to confirm the method without sending real
    data; `--exclude` paths are skipped (state-changing safety rail)."""
    if _excluded(urlparse(finding.url).path, opts):
        return False
    best, label = await _try_method(engine, finding.url, "POST", opts, observer)
    method = "POST"
    # POST rejected too? consult Allow and try PATCH only if it's advertised.
    if best is not None and best.status == 405:
        allowed, _ = methods.parse_allow(best.headers.get("allow", ""))
        if "PATCH" in allowed:
            pr, plabel = await _try_method(engine, finding.url, "PATCH", opts, observer)
            if pr is not None and pr.status not in (404, 405):
                best, label, method = pr, plabel, "PATCH"
    if best is None or best.status in (404, 405):
        return False                              # no safe method accepted
    finding.tags = list(dict.fromkeys(list(finding.tags) + ["method"]))
    finding.confidence = max(finding.confidence, 0.9)
    verdict = "accepted" if 200 <= best.status < 300 else f"reached ({best.status})"
    hint = _body_hint(best)
    finding.note = ((finding.note + " · " if finding.note else "")
                    + f"{method} ({label}) {verdict}" + (f": {hint}" if hint else ""))
    return True


MAX_APIVER_TARGETS = 15   # cap versioned endpoints we pivot around
MAX_MUTATE_TARGETS = 15   # cap confirmed resources we mutate siblings around


def _throttled(engine, profile, opts) -> bool:
    """The target is throttling us (or we're asked to conserve). When true, the
    speculative amplifier folds (apiver, mutate) are skipped and the enumeration
    caps tighten — so a WAF/rate-limit isn't woken by low-value guesswork."""
    pushback = getattr(engine, "pushback_events", 0)
    if opts.economy == "on":
        return True
    if pushback >= 5:                                        # sustained 429/503
        return True
    return opts.economy == "auto" and (bool(profile.waf) or pushback >= 3)


async def _mutate_fold(engine, profile, result, opts, observer) -> None:
    """Turn each confirmed resource into its convention-based siblings (plural,
    trailing-number, format twin) and probe them — a developer's naming habit
    makes these likely where blind brute wouldn't. On-host, bounded, honours
    `--exclude`."""
    targets = [f for f in result.findings if 200 <= f.status < 300
               and urlparse(f.url).path.rstrip("/").rsplit("/", 1)[-1]]
    if not targets:
        return
    targets = sorted(targets, key=lambda f: (-f.confidence, len(f.url)))[:MAX_MUTATE_TARGETS]
    observer.phase("mutate")
    total = sum(len(mutate.siblings(urlparse(f.url).path)) for f in targets)
    if not total:
        return
    observer.log(f"mutate: probing convention siblings of {len(targets)} confirmed resource(s)",
                 0, style="cyan")
    observer.start_prefix("mutate", total)
    host = _host_root(profile.base_url)
    for f in targets:
        path = urlparse(f.url).path
        prefix = path.rsplit("/", 1)[0] + "/"
        for sib in mutate.siblings(path):
            if _over_budget(engine, opts):
                return
            url = urljoin(host, sib.lstrip("/"))
            if url in result.seen_urls or _excluded(urlparse(url).path, opts):
                observer.tick(hit=False)
                continue
            probe = await engine.fetch(url)
            finding = await _confirm(engine, profile, prefix, probe, "mutate")
            if finding is None:
                observer.tick(hit=False)
                observer.request(url, probe.status, False)
                continue
            _report(observer, result, opts, finding, url)


async def _apiver_fold(engine, profile, result, opts, observer) -> None:
    """Pivot each confirmed versioned endpoint (`/api/v1/…`) to its adjacent API
    versions — the legacy/next versions still wired in the backend. On-host,
    bounded, honours `--exclude`."""
    targets = [f for f in result.findings
               if f.status in (200, 204, 301, 302, 401, 403, 405)
               and apiver.has_version(urlparse(f.url).path)]
    if not targets:
        return
    targets = sorted(targets, key=lambda f: (-f.confidence, len(f.url)))[:MAX_APIVER_TARGETS]
    observer.phase("apiver")
    total = sum(len(apiver.version_variants(urlparse(f.url).path)) for f in targets)
    observer.log(f"apiver: pivoting {len(targets)} versioned endpoint(s) to adjacent versions",
                 0, style="cyan")
    observer.start_prefix("apiver", total)
    host = _host_root(profile.base_url)
    for f in targets:
        path = urlparse(f.url).path
        prefix = path.rsplit("/", 1)[0] + "/"
        for var in apiver.version_variants(path):
            if _over_budget(engine, opts):
                return
            url = urljoin(host, var.lstrip("/"))
            if url in result.seen_urls or _excluded(urlparse(url).path, opts):
                observer.tick(hit=False)
                continue
            probe = await engine.fetch(url)
            finding = await _confirm(engine, profile, prefix, probe, "apiver")
            if finding is None:
                observer.tick(hit=False)
                observer.request(url, probe.status, False)
                continue
            _report(observer, result, opts, finding, url)


async def _bucket_fold(engine, profile, result, opts, observer) -> None:
    """Report cloud-storage references seen in the target's bodies, and — under
    `--buckets` — probe each bucket's read-only listing endpoint to flag the
    publicly-listable ones (with a sample of the objects they expose)."""
    refs = profile.bucket_refs
    if not refs:
        return
    observer.phase("buckets")
    mode = "probing" if opts.buckets else "found"
    observer.log(f"buckets: {len(refs)} cloud-storage reference(s) {mode}", 0, style="cyan")
    observer.start_prefix("buckets", len(refs))
    for ref in sorted(refs, key=lambda r: r.label):
        url = buckets.public_url(ref)
        note = f"cloud bucket referenced: {ref.label}"
        conf, tags = 0.5, ["bucket"]
        if opts.buckets:
            if _over_budget(engine, opts):
                break
            pr = await engine.fetch(buckets.list_url(ref), keep_body=True)
            observer.request(pr.url, pr.status, False)
            if buckets.is_listable(pr.status, pr.body):
                keys = buckets.parse_keys(pr.body)
                sample = ", ".join(keys[:5]) + (f" (+{len(keys) - 5})" if len(keys) > 5 else "")
                note = f"PUBLIC bucket {ref.label} — listable: {sample}"
                conf, tags = 0.95, ["bucket", "listing", "disclosure"]
                observer.log(f"bucket: {ref.label} is PUBLIC/listable → {sample}", 0, style="bold red")
        f = Finding(url, 200, 0, "", conf, "bucket", note=note, tags=tags)
        _report(observer, result, opts, f, url)


async def _backup_fold(engine, profile, result, opts, observer) -> None:
    """For each confirmed file, probe its backup/source twins."""
    file_hits = [f for f in result.findings if backups.is_file_hit(f.url, f.status)]
    if not file_hits:
        return
    # cap: expand backups around the most confident files only (avoid blow-up);
    # tighten hard when the target is throttling (backups is the biggest amplifier).
    cap = 20 if _throttled(engine, profile, opts) else MAX_BACKUP_FILES
    file_hits = sorted(file_hits, key=lambda f: -f.confidence)[:cap]
    observer.phase("backups")
    total = sum(len(backups.variations(urlparse(f.url).path)) for f in file_hits)
    observer.start_prefix("backups", total)   # own progress total (don't overflow)
    for f in file_hits:
        path = urlparse(f.url).path
        prefix = path.rsplit("/", 1)[0] + "/"
        observer.substep(path.rsplit("/", 1)[-1] or path)   # backups: <file>
        for var in backups.variations(path):
            if _over_budget(engine, opts):
                break
            url = urljoin(_host_root(profile.base_url), var)
            if _excluded(urlparse(url).path, opts):
                continue
            probe = await engine.fetch(url)
            finding = await _confirm(engine, profile, prefix, probe, "backup")
            if finding is None:
                observer.tick(hit=False)
                observer.request(url, probe.status, False)
                continue
            # A "backup" byte-identical to the original file isn't a disclosure —
            # it's a route/catch-all serving the same content for ANY suffix
            # (e.g. swagger.json.bak == swagger.json.qualquercoisa == swagger.json).
            # Require the same LENGTH too, so a real backup that merely resembles
            # the original (a slightly older copy) is still kept.
            if (f.simhash and probe.length == f.length
                    and hamming(probe.body_simhash, f.simhash) <= bl.SIMHASH_MISS_DISTANCE):
                observer.tick(hit=False)
                observer.request(url, probe.status, False)
                continue
            _report(observer, result, opts, finding, url)


MAX_VCS_FILES = 300       # cap files enumerated from a VCS/metadata leak


async def _vcs_fold(engine, profile, result, opts, observer) -> None:
    """Turn a leaked `.git/`, `.svn/` or `.DS_Store` into an enumeration.

    Origami already reports the leak; this fetches the index/metadata, parses the
    file list (vcs.py), and fetches each entry from the webroot — one leak becomes
    the whole tree. On-host only; bounded by MAX_VCS_FILES; honours `--exclude`."""
    git_roots, ds_dirs, svn_roots = set(), set(), set()
    for f in result.findings:
        if f.status not in (200, 206):
            continue
        p = urlparse(f.url).path
        lp = p.lower()
        i = lp.find("/.git/")
        if i != -1:
            git_roots.add(p[:i + 1])              # web dir that contains .git/
        j = lp.find("/.svn/")
        if j != -1:
            svn_roots.add(p[:j + 1])
        if lp.endswith("/.ds_store"):
            ds_dirs.add(p[:-len(".DS_Store")])    # the dir the .DS_Store describes
    if not (git_roots or ds_dirs or svn_roots):
        return

    observer.phase("vcs")
    host = _host_root(profile.base_url)
    seeds: list[str] = []                          # root-absolute paths to enumerate

    async def _grab(meta_path, parse, label):
        pr = await engine.fetch(urljoin(host, meta_path.lstrip("/")), keep_body=True)
        observer.request(pr.url, pr.status, False)
        if not (pr.ok and pr.status in (200, 206) and pr.body):
            return
        got = parse(pr.body)
        if got:
            observer.log(f"vcs: {label} → {len(got)} entries", 0, style="bold green")
        return got

    for root in sorted(git_roots):
        files = await _grab(root + ".git/index", vcs.parse_git_index, f"{root}.git/index")
        seeds += [root + fp for fp in (files or [])]
    for d in sorted(ds_dirs):
        names = await _grab(d + ".DS_Store", vcs.parse_ds_store, f"{d}.DS_Store")
        seeds += [d + n for n in (names or [])]
    for root in sorted(svn_roots):
        files = await _grab(root + ".svn/wc.db", vcs.parse_svn, f"{root}.svn/wc.db")
        seeds += [root + fp for fp in (files or [])]

    # de-dup, cap, then fetch each from the webroot and report the real hits.
    uniq, seen = [], set()
    for p in seeds:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    vcs_cap = MAX_VCS_FILES // 4 if _throttled(engine, profile, opts) else MAX_VCS_FILES
    if len(uniq) > vcs_cap:
        observer.log(f"vcs: {len(uniq)} files enumerated — capping fetch at {vcs_cap}",
                     0, style="yellow")
        uniq = uniq[:vcs_cap]
    observer.start_prefix("vcs", len(uniq))
    for p in uniq:
        if _over_budget(engine, opts):
            break
        url = urljoin(host, p.lstrip("/"))
        if _excluded(urlparse(url).path, opts):
            continue
        observer.substep(p.rsplit("/", 1)[-1] or p)
        probe = await engine.fetch(url)
        prefix = urlparse(url).path.rsplit("/", 1)[0] + "/"
        finding = await _confirm(engine, profile, prefix, probe, "vcs")
        if finding is None:
            observer.tick(hit=False)
            observer.request(url, probe.status, False)
            continue
        _report(observer, result, opts, finding, url)


MAX_BYPASS_TARGETS = 20   # cap blocked resources we attempt to bypass
BYPASS_PER_WALL = 3       # …and at most this many per identical 403/401 wall
MAX_BYPASS_PREFIXES = 12  # cap operator --bypass-prefixes carriers (they multiply per target)
# Stacks whose normalizers decode overlong/fullwidth/%u slashes → enable the
# encoded-separator bypass family under "auto" intensity (plus unknown stacks).
_BYPASS_ENC_STACKS = {"iis", "tomcat", "java", "spring", "spring boot", "jetty",
                      "coldfusion", "jboss", "wildfly"}


def _discovered_route_prefixes(findings, cap=6):
    """Path prefixes from confirmed 2xx *directory-ish* routes — reused as the
    `;/` matrix carrier for the management bypass (a real route the ACL already
    lets through, so `<route>/;/actuator/env` is authorized then dispatched).
    Skips files and management paths themselves; deduped, shortest-first, capped."""
    out: list[str] = []
    seen: set[str] = set()
    for f in findings:
        if not (200 <= f.status < 300):
            continue
        seg = urlparse(f.url).path.strip("/")
        if not seg or "." in seg.rsplit("/", 1)[-1]:      # keep dir-ish routes, skip files
            continue
        if bypass403.is_management_path("/" + seg) or seg in seen:
            continue
        seen.add(seg)
        out.append(seg)
    out.sort(key=lambda s: (s.count("/"), len(s)))
    return tuple(out[:cap])


def _select_bypass_targets(findings, per_wall=BYPASS_PER_WALL, cap=MAX_BYPASS_TARGETS):
    """Pick the 403/401 resources worth bypassing → (targets, n_skipped).

    Tagged (interesting) first, then at most `per_wall` per distinct (status,
    body-simhash) wall — a server that 403s every .env*/.git* serves the SAME
    page for all, so 20 attempts at identical walls is 20× waste. Capping per
    wall covers each one while freeing the budget for genuinely distinct 403s
    (/admin, /web.config…)."""
    blocked = _dedup_by_url([f for f in findings if f.status in (401, 403)])
    blocked.sort(key=lambda f: (not f.tags, f.url))   # tagged (interesting) first
    seen: dict[tuple, int] = {}
    diverse, skipped = [], 0
    for f in blocked:
        sig = (f.status, f.simhash)
        if seen.get(sig, 0) >= per_wall:
            skipped += 1
            continue
        seen[sig] = seen.get(sig, 0) + 1
        diverse.append(f)
    return diverse[:cap], skipped + max(0, len(diverse) - cap)


def _bypass_tech_key(path: str, method: str, rpath: str, headers: dict):
    """A resource-INDEPENDENT signature of a bypass technique, so a trick that flips
    one 403 can be recognized and fired FIRST on the next 403. Replacing the resource
    path with a placeholder makes `/admin%2f` and `/users%2f` share the key — the
    suffix/prefix/header/method tricks (the usual WAF weaknesses) transfer across
    resources; the char-case tricks that rewrite the path don't, which is fine."""
    sig = rpath.replace(path, "\x00") if path and path in rpath else rpath
    return (method, sig, frozenset((headers or {}).items()))


async def _bypass_fold(engine, profile, result, opts, observer, root_simhash) -> None:
    """For each 403/401, fire curated bypass variants; report a surviving 2xx.

    A variant counts as a real bypass only when it passes the soft-404
    sibling check (_confirm) AND its body isn't the homepage (the X-Original-URL
    trick otherwise just returns `/`)."""
    blocked, skipped = _select_bypass_targets(result.findings)
    if not blocked:
        return
    # Optional user/bundled header-bypass wordlist (--bypass-headers): replaces the
    # built-in IP-trust header axis. Loaded once; [] (curated built-ins) on failure.
    header_pairs = (bypass403.load_header_pairs(opts.bypass_headers_path)
                    if opts.bypass_headers else None)
    if opts.bypass_headers and opts.bypass_headers_path and not header_pairs:
        observer.log(f"403-bypass: header wordlist {opts.bypass_headers_path} empty or "
                     f"unreadable — falling back to the built-in header axis", 0, style="yellow")
    ci = profile.case_sensitive is False              # IIS/Windows ACL ignores case
    # Fingerprint gates for the stack-specific families (used in "auto" intensity):
    # encoded-separator tricks only make sense where a decoding normalizer lives
    # (IIS/Tomcat/Java/Spring, or an unidentified stack); API-prefix only on
    # API-ish targets. "light"/"full" ignore these in variants().
    intensity = getattr(opts, "bypass_intensity", "auto")
    techs = {t.lower() for t in profile.confirmed_techs()}
    enc_stack = (not techs) or bool(techs & _BYPASS_ENC_STACKS)

    def _api_gate(f) -> bool:
        path = urlparse(f.url).path.lower()
        return ("api" in (getattr(f, "tags", None) or [])
                or any(s in path for s in ("/api/", "/api.", "/v1/", "/v2/", "/v3/"))
                or "graphql" in techs)

    # Real 2xx routes the scan confirmed → data-driven prefixes for BOTH the
    # api-prefix family (`/<route>/blocked`) and the matrix management family
    # (`/<route>/;/actuator/*`), so neither is limited to a static guess list; a
    # route the ACL already lets through is the highest-signal carrier. The
    # matrix family is additionally gated to Spring/Java/Tomcat/unknown stacks
    # (same set as encoded-separator) and management-ish paths only.
    # Operator-supplied mounts (--bypass-prefixes) come FIRST — they're known-good,
    # so they lead the carrier list — then the 2xx routes the scan confirmed.
    custom_prefixes = (bypass403.load_prefixes(opts.bypass_prefixes_path)
                       if opts.bypass_prefixes_path else ())
    if opts.bypass_prefixes_path and not custom_prefixes:
        observer.log(f"403-bypass: prefix wordlist {opts.bypass_prefixes_path} empty or "
                     f"unreadable — using seeds + discovered routes only", 0, style="yellow")
    # Cap custom carriers: each one multiplies across every blocked resource × 2
    # families, so a huge prefix file would balloon the request count. Keep the
    # first N (file order = operator priority) and say what was dropped.
    if len(custom_prefixes) > MAX_BYPASS_PREFIXES:
        observer.log(f"403-bypass: using the first {MAX_BYPASS_PREFIXES} of "
                     f"{len(custom_prefixes)} --bypass-prefixes (raise --max-requests to widen)",
                     0, style="yellow")
        custom_prefixes = custom_prefixes[:MAX_BYPASS_PREFIXES]
    route_prefixes = tuple(dict.fromkeys(custom_prefixes + _discovered_route_prefixes(result.findings)))
    # "full" intensity fires the matrix-management family regardless of stack;
    # "auto"/"light" keep it gated to Spring/Java/Tomcat/unknown stacks.
    mgmt_stack = enc_stack or intensity == "full"

    def _vars_for(f):
        p = urlparse(f.url).path
        return bypass403.variants(
            p, case_insensitive=ci, header_pairs=header_pairs, intensity=intensity,
            encoded=enc_stack, api=_api_gate(f),
            mgmt=mgmt_stack and bypass403.is_management_path(p), route_prefixes=route_prefixes)

    # Cross-resource learning: a technique that bypassed one 403 is fired FIRST on
    # the next (same WAF → same weakness), so with the per-resource early-exit the
    # 2nd..Nth bypassable wall usually costs ~1 request instead of the whole battery.
    winners: list = []

    def _ordered_vars(f):
        vs = _vars_for(f)
        if not winners:
            return vs
        p = urlparse(f.url).path
        rank = {k: i for i, k in enumerate(winners)}
        # stable sort → known winners lead (in discovery order), the rest keep order
        return sorted(vs, key=lambda v: rank.get(_bypass_tech_key(p, v[1], v[2], v[3]),
                                                  len(winners)))

    observer.phase("403-bypass")
    msg = f"403-bypass: probing {len(blocked)} blocked resources ({intensity})"
    if header_pairs:
        msg += f" with {len(header_pairs)} bypass headers"
    if custom_prefixes:
        msg += f", {len(custom_prefixes)} custom route prefixes"
    if skipped:
        msg += f" ({skipped} same-wall/over-cap 403s skipped)"
    observer.log(msg, 0, style="cyan")
    # count with the SAME gates/case as the firing loop, else the bar miscounts
    total = sum(len(_vars_for(f)) for f in blocked)
    observer.start_prefix("403-bypass", total)
    root = _host_root(profile.base_url)
    for f in blocked:
        path = urlparse(f.url).path
        prefix = path.rsplit("/", 1)[0] + "/"
        observer.substep(path.rstrip("/").rsplit("/", 1)[-1] or path)   # 403-bypass: <resource>
        for label, method, rpath, headers in _ordered_vars(f):
            if _over_budget(engine, opts):
                return
            url = urljoin(root, rpath.lstrip("/"))
            probe = await engine.fetch(url, method=method, headers=headers or None)
            observer.request(url, probe.status, False)
            # tick per non-hit probe here; _report ticks once for the confirmed hit
            if not (probe.ok and 200 <= probe.status < 300 and probe.length > 0):
                observer.tick(hit=False); continue        # 2xx with actual content only
            if hamming(probe.body_simhash, root_simhash) <= bl.SIMHASH_MISS_DISTANCE:
                observer.tick(hit=False); continue        # just the homepage — not a bypass
            if f.simhash and hamming(probe.body_simhash, f.simhash) <= bl.SIMHASH_MISS_DISTANCE:
                observer.tick(hit=False); continue        # same body as the 403 page — only the status flipped
            if await _confirm(engine, profile, prefix, probe, "bypass403") is None:
                observer.tick(hit=False); continue        # soft-404 / catch-all
            bf = Finding(f.url, probe.status, probe.length, probe.content_type, 0.9,
                         "bypass403", note=f"403→{probe.status} bypass: {label}",
                         tags=sorted(set(f.tags) | {"bypass"}), simhash=probe.body_simhash)
            # A confirmed bypass SUPERSEDES the wall it came from: drop the original
            # 403 (and clear it from the live-dedup set) so the bypass — which reuses
            # the blocked URL — is actually appended/streamed/reported instead of
            # being suppressed as a duplicate of that 403.
            if f in result.findings:
                result.findings.remove(f)
            result.seen_urls.discard(f.url)
            result.seen_urls_lc.discard(f.url.lower())
            _report(observer, result, opts, bf, f.url)
            key = _bypass_tech_key(path, method, rpath, headers)
            learned = key in winners
            if not learned:
                winners.append(key)                       # remember the working trick for later 403s
            observer.log(f"403-bypass: {observer.disp(f.url)} → {probe.status} via {label}"
                         + (" (learned)" if learned else ""), 0, style="bold green")
            break                                         # one confirmed bypass per resource


async def _association_fold(engine, profile, result, opts, observer, memory) -> None:
    """Test paths the corpus says co-occur with what we already found."""
    found = [urlparse(f.url).path for f in result.findings]
    assoc = memory.associate(found)
    if not assoc:
        return
    observer.phase("associations")
    observer.log(f"associations: {len(assoc)} paths from corpus rules", 0, style="cyan")
    observer.start_prefix("associations", len(assoc))
    root = _host_root(profile.base_url)
    ci = profile.case_sensitive is False
    for path in assoc:
        if _over_budget(engine, opts):
            break
        p = "/" + path.lstrip("/")
        url = urljoin(root, p.lstrip("/"))
        if _excluded(p, opts):
            continue
        # already discovered by another source → don't re-probe/re-calibrate it.
        if (url.lower() in result.seen_urls_lc) if ci else (url in result.seen_urls):
            continue
        prefix = p.rsplit("/", 1)[0] + "/"
        observer.substep(p.rstrip("/").rsplit("/", 1)[-1] or p)   # associations: <path>
        await bl.calibrate(engine, profile, [(prefix, _ext_of(p))])
        probe = await engine.fetch(urljoin(root, p.lstrip("/")))
        finding = await _confirm(engine, profile, prefix, probe, "assoc")
        if finding is None:
            observer.tick(hit=False)
            observer.request(probe.url, probe.status, False)
            continue
        _report(observer, result, opts, finding, probe.url)


def _should_shortscan(opts: ScanOptions, folds: set[str]) -> bool:
    if opts.shortscan == "off":
        return False
    if opts.shortscan == "on":
        return True
    return "shortscan" in folds          # auto: IIS confirmed the fold


async def _shortscan_pass(engine, profile, base_url, words, result, opts, observer,
                          memory=None) -> None:
    """Gate on shortscan's own vuln check, expand 8.3 names, scan the seeds."""
    observer.phase("shortscan")
    res = await shortname.run_shortscan(
        base_url,
        insecure=not engine.cfg.verify_tls,
        user_agent=engine.cfg.user_agent,
        concurrency=engine.cfg.concurrency,
        timeout=int(engine.cfg.timeout),
    )
    if not res.available:
        observer.log(f"shortscan: skipped ({res.error})", 1, style="yellow")
        return
    if res.error:
        observer.log(f"shortscan: {res.error}", 1, style="yellow")
    if not res.vulnerable:
        observer.log("shortscan: target not vulnerable to 8.3 enumeration", 1)
        return

    observer.log(f"shortscan: VULNERABLE · {len(res.entries)} 8.3 names leaked", 1, style="cyan")
    profile.add_evidence(Evidence(source="shortscan", tech="iis",
                                  detail=f"8.3 leak · {len(res.entries)} names", weight=20))
    # 8.3 short names only exist on Windows/NTFS, which is case-insensitive —
    # a definitive signal, available NOW (before the first main-scan hit that
    # detect_case_sensitivity would otherwise wait for). Setting it here makes
    # the case-variant dedup below (and in _report / the final collapse) fire on
    # this fold's own findings, so /WEBSERVICES == /webservices == /WebServices.
    if profile.case_sensitive is None:
        profile.case_sensitive = False
    for e in res.entries:
        observer.log(f"  8.3: {e.tilde}.{e.ext}"
                     + (f" → {e.fullname}" if e.fullname else ""), 2)

    tech_exts = tuple(sorted(profile.enabled_extensions))
    # Cross-target memory: real names seen on past targets help reverse an 8.3
    # prefix into a name we've met before (§4 learning loop). Folded into both
    # the constraint-filter and the n-gram corpus.
    mem_names = memory.recall_names() if memory is not None else []
    if mem_names:
        observer.log(f"shortscan: {len(mem_names)} names recalled from past scans "
                     f"(cross-target completion)", 1, style="cyan")
    sc_words = list(dict.fromkeys(list(words) + mem_names))
    cands = shortname.expand(res.entries, sc_words, tech_exts,
                             case_insensitive=profile.case_sensitive is False)

    # Regime 2: n-gram completion of truncated prefixes the wordlist can't cover.
    ng = NGram(order=3).train(sc_words)
    gen_exts = tech_exts or (".aspx", ".asmx", ".ashx", "")
    n_gen = 0
    for e in res.entries:
        if e.fullname or len(e.prefix) < 6:     # only fully-truncated, no autocomplete
            continue
        fams = shortname.ext_family(e.ext) if e.ext else gen_exts
        for name in ng.complete(e.prefix.lower(), n_results=5):
            for ext in fams:
                cands.append((e.baseurl, name + ext))
                n_gen += 1
    cands = list(dict.fromkeys(cands))          # de-dupe, preserve order
    if not cands:
        observer.log("shortscan: no candidates after expansion", 1)
        return
    observer.log(f"shortscan: {len(cands)} candidates "
                 f"({n_gen} from n-gram completion)", 1, style="cyan")

    # calibrate every (prefix, ext class) the seeds touch, then fire them.
    # On a case-insensitive host (IIS) collapse case variants BEFORE firing —
    # WEBSERVICES / webservices / WebServices are one resource, so probing all
    # three just burns the (often WAF-throttled) request budget. Keep the first,
    # which is the highest-confidence form thanks to expand()'s tier ordering.
    ci = profile.case_sensitive is False
    by_prefix: dict[str, set[str]] = {}
    urls: list[tuple[str, str]] = []
    seen_u: set[str] = set()
    for baseurl, path in cands:
        url = urljoin(baseurl, path)
        ukey = url.lower() if ci else url
        if ukey in seen_u:
            continue
        seen_u.add(ukey)
        prefix = urlparse(url).path.rsplit("/", 1)[0] + "/"
        by_prefix.setdefault(prefix, set()).add(_ext_of(path))
        urls.append((url, prefix))
    for prefix, pexts in by_prefix.items():
        await bl.calibrate(engine, profile,
                           [(prefix, e) for e in (set(_BASE_CALIB_EXTS) | pexts)])

    observer.start_prefix("shortscan", len(urls))
    for url, prefix in urls:
        if _over_budget(engine, opts):
            break
        pth = urlparse(url).path
        # drop malformed expansions: empty-filename segments (control/.ashx),
        # query/fragment junk — never a valid 8.3-derived path.
        if "?" in url or "#" in url or "/." in ("/" + pth.lstrip("/"))[1:]:
            continue
        if _excluded(pth, opts):
            continue
        probe = await engine.fetch(url)
        finding = await _confirm(engine, profile, prefix, probe, "shortscan")
        if finding is None:
            observer.tick(hit=False)
            observer.request(url, probe.status, False)
            continue
        _report(observer, result, opts, finding, url)
