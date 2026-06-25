"""Scanner — the orchestration loop (§2 pipeline).

calibrate → fingerprint → fold (enable extensions + priority paths) →
scan prefix → classify → recurse into discovered directories → findings.

Scope/recursion are bounded (§3.11): same host, depth cap, request cap.
"""

from __future__ import annotations

import asyncio
import random
import string
from collections import defaultdict
from dataclasses import dataclass, field
from fnmatch import fnmatch
from urllib.parse import urljoin, urlparse

# More than this many byte-identical results (same status+simhash) = a catch-all
# or generic page; collapse to one representative + a count.
COLLISION_MAX = 4
# Blocked statuses whose identical-body flood is a generic block wall (forbids
# every .env*/.git*…) — muted in the live stream past COLLISION_MAX. 2xx/3xx are
# left to the end-of-scan collapse, which keys on length without this gate.
_WALL_STATUS = frozenset({401, 403, 405})
MAX_BACKUP_FILES = 80   # cap files the backup fold expands around

from origami.brain.bandit import Ranker as Bandit
from origami.brain.bandit import word_of
from origami.brain.kb import TechRule, load_kb
from origami.brain.ngram import NGram
from origami.core import baseline as bl
from origami.core import resume as resume_mod
from origami.core import fingerprint as fp
from origami.core.evidence import Evidence, TargetProfile
from origami.core.httpclient import Engine
from origami.core.normalize import hamming
from origami.core.response_classifier import (NOT_FOUND_STATUS, Filters, Finding,
                                               classify, is_dir_listing, resolve_baseline)
from origami.core.scope import same_host, same_site
from origami.core.scheduler import (BASE_EXTS, Candidate, build_candidates,
                                     derive_vocabulary, load_wordlist, target_tokens)
from origami.modules import bypass403, leaks, paramfuzz, secrets, vhost, waf
from origami.modules.discovery import (apidocs, backups, clientapp, graphql, js_parser,
                                        methods, robots, shortname, wayback, wellknown)
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

# Origins whose paths are root-absolute (joined from the host root, not the
# current prefix) — harvested references point at app-root paths.
_SEED_ORIGINS = {"memory", "js", "robots", "apidocs", "wellknown", "header", "wayback"}


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
    """True when a 301/302 Location points at this same path (the server adding
    a trailing slash) — the canonical "this is a directory" signal. Compares the
    parsed path for EQUALITY (so /login → /gateway/login is not a self-redirect),
    while still matching an absolute Location (http://host/x/) against its path.
    """
    return urlparse(location).path.rstrip("/") == path.rstrip("/")


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
    wordlist_path: str | None = None
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
    bypass_headers: bool = False   # use a header-bypass wordlist for the header axis (--bypass-headers)
    bypass_headers_path: str | None = None  # custom header wordlist path (None → bundled 403-headers.txt)
    openapi_source: str | None = None  # explicit OpenAPI/Swagger/JSON:API spec (URL or file) to fold (--openapi)
    param_fuzz: bool = False       # fire harvested + common param names at dynamic endpoints (--params)
    wayback: bool = False          # fold historical URLs (Wayback CDX + Common Crawl) as seeds (--wayback)
    gau: bool = False              # prefer the gau/waybackurls binary for history, native fallback (--gau)
    vhost: bool = False            # virtual-host discovery (Host-header fuzzing on the target IP)
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
    edges: list[tuple[str, str]] = field(default_factory=list)  # provenance (src→dst) for --graph
    seen_urls: set[str] = field(default_factory=set, compare=False, repr=False)     # reported URLs (raw) — kills cross-source live dupes
    seen_urls_lc: set[str] = field(default_factory=set, compare=False, repr=False)  # …lower-cased, consulted on a case-insensitive host (both kept so a mid-scan case flip is consistent)
    wall_seen: dict = field(default_factory=dict, compare=False, repr=False)      # (status,length) → count, for live block-wall flood suppression


async def scan(engine: Engine, base_url: str, opts: ScanOptions | None = None,
               observer=None, memory=None, control=None, resume_path=None) -> ScanResult:
    opts = opts or ScanOptions()
    observer = observer or NullObserver()
    control = control or ScanControl()
    kb = load_kb()
    host = urlparse(base_url).netloc
    profile = TargetProfile(host=host, base_url=base_url)
    result = ScanResult(profile=profile)

    # 1. baseline at root + fingerprint -----------------------------------
    root = await engine.fetch(base_url, keep_body=True)
    if not root.ok:
        observer.log(f"root unreachable: {root.error}", 1, style="red")
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

    # scan starts at the given base path (e.g. /lms/), so calibrate THERE.
    base_prefix = urlparse(base_url).path or "/"
    if not base_prefix.endswith("/"):
        base_prefix += "/"

    observer.phase("calibrate")
    await bl.calibrate(engine, profile, [(base_prefix, e) for e in _BASE_CALIB_EXTS + [".php", ".aspx"]])

    # Kick off the (slow, external) historical-URL lookup NOW, in the background,
    # so it runs while we fingerprint/calibrate; recon awaits its result below.
    wb_task = None
    if opts.wayback or opts.gau:
        wb_task = asyncio.create_task(wayback.harvest(profile.host, use_gau=opts.gau))

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
        try:
            wb_paths, wb_params, wb_src = await asyncio.wait_for(wb_task, timeout=30)
        except Exception as e:        # timeout/any error: never let history stall/break the scan
            wb_task.cancel()
            wb_paths, wb_params, wb_src = set(), set(), "skipped"
            observer.log(f"wayback: skipped ({type(e).__name__})", 0, style="yellow")
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

    # GraphQL introspection — confirm the endpoint + harvest schema field names.
    if opts.apidocs:
        _recon("graphql")
        gql_url, gql_fields = await _guard(observer, "graphql",
                                           graphql.harvest(engine, base_url), (None, set()))
        if gql_url:
            profile.parameters |= gql_fields
            gf = Finding(gql_url, 200, 0, "application/json", 0.9, "graphql",
                         note="introspection enabled", tags=["api"])
            result.findings.append(gf)
            observer.finding(gf)
            observer.log(f"graphql: introspection enabled at {urlparse(gql_url).path} "
                         f"→ {len(gql_fields)} schema fields harvested", 0, style="cyan")

    if opts.backups:
        root_seeds += [(p, "backup") for p in backups.vcs_probes()]

    # THE origami fold: learn the target's own vocabulary (names + extensions)
    # from the references discovered above, and weave it into the scan — capped
    # by --max-folds so a chatty SPA can't explode the request budget. Kept by
    # frequency: the most-referenced tokens are the most valuable.
    names_ctr, exts_ctr = derive_vocabulary(js_paths | robots_paths | api_paths)
    learned_names = [n for n, _ in names_ctr.most_common(opts.max_folds)]
    # the target's own name (host labels + base path) is prime vocabulary
    tgt = target_tokens(profile.host, base_prefix)
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

    words = load_wordlist(_wordlist_path(opts))
    # fold the learned vocabulary in: target's own names tried first, in every dir.
    if learned_names:
        wset = set(words)
        fresh = [w for w in learned_names if w not in wset]   # keep frequency order
        words = fresh + words
        observer.log(f"vocabulary: folded +{len(fresh)} names and "
                     f"+{len(learned_exts)} extensions learned from target references "
                     f"(--max-folds {opts.max_folds})", 0, style="cyan")
    wl_name = opts.wordlist_path or "builtin base.txt"
    observer.log(f"wordlist: {wl_name} ({len(words)} words) · "
                 f"extensions {len(exts) or 0} folded", 0)
    recurse_exts = set(_BASE_CALIB_EXTS) | set(BASE_EXTS) | exts

    # 3. shortscan fold (IIS 8.3) — high-value seeds before the generic scan
    if _should_shortscan(opts, folds):
        await _guard(observer, "shortscan",
                     _shortscan_pass(engine, profile, base_url, words, result, opts,
                                     observer, memory),
                     None)

    # 4. recursive scan + folds (checkpointed) -----------------------------
    queue: list[tuple[str, int]] = [(base_prefix, 0)]   # (prefix, depth)
    return await _scan_loop(engine, profile, opts, observer, memory, control, result,
                            base_prefix=base_prefix, words=words, exts=exts,
                            priority_paths=priority_paths, root_seeds=root_seeds,
                            queue=queue, scanned=set(), resume_path=resume_path,
                            root_simhash=root.body_simhash)


async def resume_scan(engine: Engine, state: dict, opts: ScanOptions, observer=None,
                      memory=None, control=None, resume_path=None) -> ScanResult:
    """Continue an interrupted scan from a loaded checkpoint (`resume.load`).

    The expensive setup (calibrate/fingerprint/harvest/vocabulary) is restored
    from the checkpoint, so we drop straight back into the directory loop with
    the same profile, findings, and pending queue.
    """
    observer = observer or NullObserver()
    control = control or ScanControl()
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
        else:
            reason = (f"hit the --max-requests {opts.max_requests} budget "
                      f"(raise it with --max-requests N)")
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

    # 7.5 parameter discovery — fire harvested + common param names at dynamic
    # endpoints; a reflected canary is a real input (XSS/SSTI/redirect lead). Opt-in.
    if opts.param_fuzz:
        await _guard(observer, "params",
                     _param_fold(engine, profile, result, opts, observer), None)

    # 8. virtual-host discovery — Host-header fuzzing on the target IP (opt-in).
    if opts.vhost:
        await _guard(observer, "vhost",
                     _vhost_fold(engine, profile, result, opts, observer, root_simhash), None)

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

    clusters: dict[tuple, list] = defaultdict(list)
    for f in deduped:
        clusters[(f.status, f.length)].append(f)

    out, collapsed = [], 0
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


def _report(observer, result, opts, finding, url) -> None:
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
    shown = opts.filters.accept(finding.status, finding.length)
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
        wall = finding.status in _WALL_STATUS
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
        if (opts.max_requests and engine.spent >= opts.max_requests) or control.quit:
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
        probe = await engine.fetch(url)
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
        is_dir = (cand.path.endswith("/")
                  or (probe.status in (301, 302)
                      and _is_self_redirect_dir(probe.location, path)))
        if is_dir:
            dpath = path if path.endswith("/") else path + "/"
            confirmed_dirs.append(dpath)
            observer.set_skippable(True)
            if listed_dirs is not None and 200 <= probe.status < 300 \
                    and is_dir_listing(probe.body_head):
                listed_dirs.add(dpath)        # autoindex → harvest it, don't blind-brute

        # soft-verify a surprising hit with a same-shape random sibling — a
        # blanket 403/200 wall is recursed (above) but NOT reported.
        if await _is_soft(engine, profile, prefix, probe):
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

        _report(observer, result, opts, finding, url)

    if first_hit_path:
        await bl.probe_case_sensitivity(engine, profile, first_hit_path)
    return confirmed_dirs, ancestor_dirs, consumed, hit_cap


def _wordlist_path(opts: ScanOptions):
    from pathlib import Path
    return Path(opts.wordlist_path) if opts.wordlist_path else None


_HARVEST_EXT = (".js", ".mjs", ".map", ".json", ".xml", ".html", ".htm", ".txt", ".csv")
_HARVEST_CODE = (".js", ".mjs", ".map", ".json")
MAX_HARVEST_FILES = 30    # discovered files we re-read for endpoints
MAX_HARVEST_NEW = 400     # new candidate paths a harvest pass may add
MAX_DISCOVERY_ROUNDS = 3  # walk → harvest → recurse new dirs → harvest → … (cap)
_HARVEST_DEPTH_BONUS = 3  # harvested dirs are evidence-based, so recurse them past the blind depth cap

# What an autoindex HIDES (Apache IndexIgnore / IIS hidden segments): the only
# names worth probing in a listed dir, since the listing itself reveals the rest.
_INDEX_HIDDEN = (".htaccess", ".htpasswd", ".git/", ".git/config", ".svn/", ".env",
                 ".DS_Store", ".gitignore", "web.config", "backup.zip", "backup.tar.gz",
                 ".bash_history", ".npmrc", "config.php.bak")


def _harvestable(f) -> bool:
    """A confirmed 2xx text file whose body likely holds more endpoints."""
    if not (200 <= f.status < 300):
        return False
    if js_parser._is_vendor(f.url):           # jquery/bootstrap/etc. — not the app's own code
        return False
    path = urlparse(f.url).path.lower()
    ct = (f.content_type or "").lower()
    return (path.endswith(_HARVEST_EXT)
            or any(t in ct for t in ("javascript", "ecmascript", "json", "xml", "html")))


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
        if opts.max_requests and engine.spent >= opts.max_requests:
            break
        observer.substep(urlparse(f.url).path.rsplit("/", 1)[-1] or f.url)
        pr = await engine.fetch(f.url, keep_body=True)
        if not (pr.ok and pr.body):
            continue
        _scan_body(f, pr.body, observer, opts.finding_sink)   # body's here — scan creds + leaks too
        extracted = js_parser.extract_paths(pr.body, f.url)
        if is_dir_listing(pr.body):               # autoindex → read its TRUE contents, don't guess
            extracted |= js_parser.parse_listing(pr.body, f.url)
        for p in extracted:
            new_paths.setdefault(p, urlparse(f.url).path)

    # 2. scope + drop what we already probed/found, then cap
    scoped = _scope_paths(set(new_paths), profile.host, opts.scope)
    fresh = [(p, new_paths[p]) for p in sorted(scoped)
             if urljoin(root, p.lstrip("/")).lower() not in result.seen_urls_lc
             and not _excluded("/" + p.lstrip("/"), opts)]   # honor --exclude / --exclude-ext
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
        if opts.max_requests and engine.spent >= opts.max_requests:
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


def _scan_body(finding, body, observer, sink=None) -> int:
    """Run all body-content analyzers (secrets + content-intel leaks) on a body
    we already have in hand, then re-emit the now-enriched finding ONCE via `sink`
    (opts.finding_sink) so a JSONL consumer sees the secret/leak tags even though
    detection happens post-confirm. Returns the total number of hits."""
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
    for f in cands:
        if opts.max_requests and engine.spent >= opts.max_requests:
            break
        pr = await engine.fetch(f.url, keep_body=True)
        if pr.ok and pr.body:
            total += _scan_body(f, pr.body, observer, opts.finding_sink)
    if total:
        observer.log(f"content: {total} secret/disclosure hit(s) flagged — see the 'secret'/'leak' tags",
                     0, style="bold yellow")


MAX_VHOSTS = 60   # cap Host-header candidates probed


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
        if opts.max_requests and engine.spent >= opts.max_requests:
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


MAX_FUZZ_ENDPOINTS = 15   # cap dynamic endpoints we fuzz params on
MAX_FUZZ_PARAMS = 160     # cap distinct param names tried per endpoint
FUZZ_BATCH = 20           # params per request (each gets its own canary)
_DYN_EXT = (".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action", ".cgi",
            ".pl", ".ashx", ".asmx", ".json", ".cfm")


def _fuzz_candidate(f) -> bool:
    """A dynamic endpoint worth fuzzing params on: a 2xx app route / script /
    API — not a static asset (those don't read query params)."""
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
        if opts.max_requests and engine.spent >= opts.max_requests:
            break
        observer.substep(urlparse(f.url).path.rsplit("/", 1)[-1] or f.url)
        found: list[str] = []
        echoes = False
        for qs, token_map, ctl in paramfuzz.build_batches(params, FUZZ_BATCH):
            if opts.max_requests and engine.spent >= opts.max_requests:
                break
            sep = "&" if urlparse(f.url).query else "?"
            url = f.url + sep + qs
            pr = await engine.fetch(url, keep_body=True)
            observer.tick(hit=False)
            observer.request(url, pr.status, False)
            if not (pr.ok and pr.body):
                continue
            if paramfuzz.control_reflected(pr.body, ctl):    # echoes any query → no signal
                echoes = True
                break
            found += paramfuzz.reflected(pr.body, token_map)
        if echoes:
            observer.log(f"params: {observer.disp(f.url)} reflects any query param — skipped",
                         1, style="yellow")
            continue
        found = list(dict.fromkeys(found))
        if found:
            preview = ", ".join(found[:8]) + (f" (+{len(found) - 8})" if len(found) > 8 else "")
            if "param" not in f.tags:
                f.tags = list(f.tags) + ["param"]
            f.note = (f.note + " · " if f.note else "") + f"reflected params: {preview}"
            observer.log(f"param: {observer.disp(f.url)} ← reflects {preview}", 0, style="bold green")
            if opts.finding_sink is not None:
                opts.finding_sink(f)
            total += len(found)
    if total:
        observer.log(f"params: {total} reflected parameter(s) flagged — see the 'param' tag",
                     0, style="cyan")


async def _backup_fold(engine, profile, result, opts, observer) -> None:
    """For each confirmed file, probe its backup/source twins."""
    file_hits = [f for f in result.findings if backups.is_file_hit(f.url, f.status)]
    if not file_hits:
        return
    # cap: expand backups around the most confident files only (avoid blow-up).
    file_hits = sorted(file_hits, key=lambda f: -f.confidence)[:MAX_BACKUP_FILES]
    observer.phase("backups")
    total = sum(len(backups.variations(urlparse(f.url).path)) for f in file_hits)
    observer.start_prefix("backups", total)   # own progress total (don't overflow)
    for f in file_hits:
        path = urlparse(f.url).path
        prefix = path.rsplit("/", 1)[0] + "/"
        observer.substep(path.rsplit("/", 1)[-1] or path)   # backups: <file>
        for var in backups.variations(path):
            if opts.max_requests and engine.spent >= opts.max_requests:
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
            _report(observer, result, opts, finding, url)


MAX_BYPASS_TARGETS = 20   # cap blocked resources we attempt to bypass
BYPASS_PER_WALL = 3       # …and at most this many per identical 403/401 wall


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
    observer.phase("403-bypass")
    msg = f"403-bypass: probing {len(blocked)} blocked resources"
    if header_pairs:
        msg += f" with {len(header_pairs)} bypass headers"
    if skipped:
        msg += f" ({skipped} same-wall/over-cap 403s skipped)"
    observer.log(msg, 0, style="cyan")
    # count with the SAME case_insensitive as the firing loop, else the bar overcounts
    total = sum(len(bypass403.variants(urlparse(f.url).path, case_insensitive=ci,
                                       header_pairs=header_pairs)) for f in blocked)
    observer.start_prefix("403-bypass", total)
    root = _host_root(profile.base_url)
    for f in blocked:
        path = urlparse(f.url).path
        prefix = path.rsplit("/", 1)[0] + "/"
        observer.substep(path.rstrip("/").rsplit("/", 1)[-1] or path)   # 403-bypass: <resource>
        for label, method, rpath, headers in bypass403.variants(
                path, case_insensitive=ci, header_pairs=header_pairs):
            if opts.max_requests and engine.spent >= opts.max_requests:
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
            observer.log(f"403-bypass: {observer.disp(f.url)} → {probe.status} via {label}",
                         0, style="bold green")
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
    for path in assoc:
        if opts.max_requests and engine.spent >= opts.max_requests:
            break
        p = "/" + path.lstrip("/")
        if _excluded(p, opts):
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
        if opts.max_requests and engine.spent >= opts.max_requests:
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
