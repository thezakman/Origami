"""Scanner — the orchestration loop (§2 pipeline).

calibrate -> fingerprint -> fold -> scan prefix -> classify -> recurse into
discovered directories -> findings. Scope/recursion are bounded (§3.11).

This package: types (dataclasses), util (leaf helpers), _common (shared
classification/report), folds (discovery strategies), and this loop."""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urljoin, urlparse

from origami.brain.bandit import Ranker as Bandit
from origami.brain.bandit import word_of
from origami.brain.kb import load_kb
from origami.core import baseline as bl
from origami.core import fingerprint as fp
from origami.core import overlays
from origami.core import resume as resume_mod
from origami.core.evidence import TargetProfile
from origami.core.httpclient import Engine
from origami.core.response_classifier import Finding
from origami.core.scanner._common import (
    _BASE_CALIB_EXTS,
    _DECLARED_ORIGINS,
    _WALL_STATUS,
    COLLISION_MAX,
    _collapse_slash_twins,
    _confirm,
    _dedup_by_url,
    _dedupe_and_collapse,
    _is_soft,
    _note_leaks,
    _note_secrets,
    _report,
    _scan_body,
)
from origami.core.scanner.folds import (
    _HARVEST_DEPTH_BONUS,
    _INDEX_HIDDEN,
    BYPASS_PER_WALL,
    MAX_BACKUP_FILES,
    MAX_DISCOVERY_ROUNDS,
    _apiver_fold,
    _association_fold,
    _authz_candidate,
    _authz_diff_fold,
    _authz_fold,
    _authz_report,
    _backup_fold,
    _body_hint,
    _bucket_fold,
    _bypass_fold,
    _bypass_tech_key,
    _cache_candidate,
    _cache_poison_fold,
    _content_candidate,
    _differs,
    _discovered_route_prefixes,
    _fuzz_candidate,
    _graphql_probe,
    _harvest_fold,
    _harvestable,
    _is_origin_serve,
    _method_probe_rank,
    _mutate_fold,
    _odata_probe,
    _odata_query_candidate,
    _odata_query_fold,
    _odata_try,
    _origin_fold,
    _param_fold,
    _probe_405_finding,
    _scan_prefix,
    _secrets_fold,
    _select_bypass_targets,
    _shortscan_one,
    _shortscan_pass,
    _should_shortscan,
    _throttled,
    _try_method,
    _vcs_fold,
    _vhost_fold,
)
from origami.core.scanner.types import ScanControl, ScanOptions, ScanResult
from origami.core.scanner.util import (
    _climb_brute_split,
    _curl_cmd,
    _excluded,
    _ext_excluded,
    _ext_of,
    _guard,
    _host_root,
    _is_self_redirect_dir,
    _join_candidate,
    _over_budget,
    _path_climb,
    _rel_depth,
    _scope_paths,
    _strips_trailing_slash,
)
from origami.core.scheduler import (
    BASE_EXTS,
    Candidate,
    build_candidates,
    derive_vocabulary,
    load_wordlists,
    target_tokens,
)
from origami.core.scope import path_tenant_host, same_host, same_tenant_path
from origami.modules import (
    cache_poison,
    session,
    waf,
)
from origami.modules.discovery import (
    apidocs,
    backups,
    buckets,
    clientapp,
    graphql,
    js_parser,
    methods,
    odata,
    robots,
    wayback,
    wellknown,
)
from origami.output.ui import NullObserver

# Extension classes we always calibrate at a prefix before scanning it live
# in _common (shared with the folds). These bound harvest/history volume.
MAX_HARVEST_SEEDS = 2000
MAX_WAYBACK_SEEDS = 2000   # cap historical (Wayback/gau) paths folded as candidates
WAYBACK_BUDGET = 12.0      # total wall-clock budget for the optional history lookup

__all__ = [
    "scan",
    "resume_scan",
    "ScanOptions",
    "ScanControl",
    "ScanResult",
    "MAX_HARVEST_SEEDS",
    "MAX_WAYBACK_SEEDS",
    "WAYBACK_BUDGET",
    "_climb_brute_split",
    "_curl_cmd",
    "_excluded",
    "_ext_excluded",
    "_ext_of",
    "_guard",
    "_host_root",
    "_is_self_redirect_dir",
    "_join_candidate",
    "_over_budget",
    "_path_climb",
    "_rel_depth",
    "_scope_paths",
    "_strips_trailing_slash",
    "COLLISION_MAX",
    "_WALL_STATUS",
    "_DECLARED_ORIGINS",
    "_BASE_CALIB_EXTS",
    "_is_soft",
    "_confirm",
    "_dedup_by_url",
    "_collapse_slash_twins",
    "_dedupe_and_collapse",
    "_report",
    "_note_secrets",
    "_note_leaks",
    "_scan_body",
    "MAX_BACKUP_FILES",
    "BYPASS_PER_WALL",
    "_HARVEST_DEPTH_BONUS",
    "MAX_DISCOVERY_ROUNDS",
    "_INDEX_HIDDEN",
    "_scan_prefix",
    "_harvestable",
    "_harvest_fold",
    "_content_candidate",
    "_secrets_fold",
    "_authz_candidate",
    "_authz_report",
    "_authz_fold",
    "_authz_diff_fold",
    "_graphql_probe",
    "_odata_probe",
    "_odata_query_candidate",
    "_odata_try",
    "_odata_query_fold",
    "_vhost_fold",
    "_is_origin_serve",
    "_origin_fold",
    "_fuzz_candidate",
    "_param_fold",
    "_cache_candidate",
    "_differs",
    "_cache_poison_fold",
    "_body_hint",
    "_method_probe_rank",
    "_try_method",
    "_probe_405_finding",
    "_throttled",
    "_mutate_fold",
    "_apiver_fold",
    "_bucket_fold",
    "_backup_fold",
    "_vcs_fold",
    "_discovered_route_prefixes",
    "_select_bypass_targets",
    "_bypass_tech_key",
    "_bypass_fold",
    "_association_fold",
    "_should_shortscan",
    "_shortscan_pass",
    "_shortscan_one",
]


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
    # directory. Each ancestor is at least single-probed as a seed. Under
    # `climb_brute`, the top N ancestors (deepest-first) are instead promoted to
    # full brute-force PREFIXES (seeded into the queue below) so the whole wordlist
    # runs at each level — that's what surfaces sibling resources living in the
    # parent dir (e.g. /prod/api/usuarios when the target is /prod/api/motoristas),
    # which the scope gate otherwise never reaches from a deep target.
    climb_brute_dirs: list[str] = []
    if _climb_file:
        root_seeds.append((_climb_file, "target"))
    if _climb_ancestors:
        climb_brute_dirs, seed_only = _climb_brute_split(_climb_ancestors, opts.climb_brute)
        root_seeds += [(a, "climb") for a in seed_only]   # levels we won't sweep: single probe as before
        observer.log(f"path-climb: exploring {len(_climb_ancestors)} ancestor "
                     f"director{'y' if len(_climb_ancestors) == 1 else 'ies'} of "
                     f"{base_prefix} up to root", 0, style="cyan")
        if climb_brute_dirs:
            observer.log(f"climb-brute: sweeping the full wordlist at "
                         f"{len(climb_brute_dirs)} ancestor "
                         f"director{'y' if len(climb_brute_dirs) == 1 else 'ies'}: "
                         f"{', '.join(climb_brute_dirs)}", 0, style="cyan")

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
        spec_urls, api_paths = await _guard(observer, "api-docs",
                                            apidocs.harvest(engine, base_url),
                                            ([], set()))
        api_paths = _scope_paths(api_paths, profile.host, opts.scope)
        if spec_urls:
            root_seeds += [(p, "apidocs") for p in sorted(api_paths)]
            where = ", ".join(urlparse(u).path for u in spec_urls[:3]) \
                + (f" (+{len(spec_urls) - 3})" if len(spec_urls) > 3 else "")
            observer.log(f"api-docs: {len(spec_urls)} API spec(s) — {where} "
                         f"→ {len(api_paths)} endpoints folded", 0, style="cyan")
            if opts.graph:
                spec_path = urlparse(spec_urls[0]).path
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
        _empty_meta: dict[str, object] = {"fields": set(), "args": set(), "queries": [], "mutations": [], "sensitive": []}
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

    # OData — the enterprise analogue of GraphQL introspection. `$metadata` (EDMX)
    # hands over every entity set + property + Function/Action; fold the sets as
    # seeds, enrich params, flag sensitive surfaces, and (read-only) probe whether
    # aggregation (`$apply`) leaks data without auth.
    if opts.apidocs:
        _recon("odata")
        od_url, od_sets, od_meta = await _guard(
            observer, "odata", odata.harvest(engine, base_url), (None, set(), dict(odata._EMPTY)))
        if od_url:
            profile.parameters |= od_meta["properties"]
            sens = od_meta["sensitive"]
            note = (f"OData {od_meta['version'] or 'service'} metadata exposed · "
                    f"{len(od_sets)} entity sets")
            tags = ["api"]
            if sens:
                note += " · sensitive: " + ", ".join(sens[:8]) \
                    + (f" (+{len(sens) - 8})" if len(sens) > 8 else "")
                tags.append("disclosure")
            of = Finding(od_url, 200, 0, "application/xml", 0.9, "odata", note=note, tags=tags)
            result.findings.append(of)
            observer.finding(of)
            observer.log(f"odata: metadata at {urlparse(od_url).path} → {len(od_sets)} entity "
                         f"sets · {len(od_meta['properties'])} props · {len(od_meta['functions'])} "
                         f"functions · {len(sens)} sensitive", 0, style="cyan")
            if sens:
                observer.log("odata: sensitive sets/ops → " + ", ".join(sens[:12])
                             + (f" (+{len(sens) - 12})" if len(sens) > 12 else ""), 0, style="yellow")
            es_paths = _scope_paths(set(odata.entity_set_paths(od_meta)), profile.host, opts.scope)
            if es_paths:
                root_seeds += [(p, "odata") for p in sorted(es_paths)]
            await _guard(observer, "odata-probe",
                         _odata_probe(engine, opts, observer, of, od_meta), None)

    # Early OData exposure check on the TARGET collection itself — if the user points
    # at `…/api/motoristas`, report its `$top`/`$apply` exposure UP FRONT (right after
    # fingerprint), not buried at the end-of-scan fold. The late fold covers what the
    # scan discovers; this one is deduped against it via result.odata_probed.
    if opts.apidocs:
        await _guard(observer, "odata-query",
                     _odata_query_fold(engine, profile, result, opts, observer, target_only=True),
                     None)

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
    if _should_shortscan(opts, folds, profile):
        await _guard(observer, "shortscan",
                     _shortscan_pass(engine, profile, base_url, words, result, opts,
                                     observer, memory),
                     None)

    # 4. recursive scan + folds (checkpointed) -----------------------------
    # Base target first (prioritized), then each climb-brute ancestor as its own
    # depth-0 scan root — deepest-first so the closest parent is swept before the
    # broader ones. They run AFTER the base, so they never steal its budget.
    queue: list[tuple[str, int]] = [(base_prefix, 0)]   # (prefix, depth)
    queue += [(a, 0) for a in climb_brute_dirs]
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

    # 7.05 authz — JWT/OAuth weakness analysis on auth walls + login/token/OAuth
    # pages (a token in a Set-Cookie/body, an authorize URL missing state/PKCE).
    await _guard(observer, "authz",
                 _authz_fold(engine, profile, result, opts, observer), None)

    # 7.06 authz-diff — multi-identity access-control differential (BOLA/BFLA/broken
    # auth). Replay the discovered surface under the --as identities (+ implicit anon)
    # and flag where a lesser identity reaches what only the privileged session should.
    # Runs when extra identities are given, or the scan itself is authenticated (free
    # anon-vs-authed diff). Read-only GETs.
    if opts.identities or session.has_auth(engine.cfg.headers):
        await _guard(observer, "authz-diff",
                     _authz_diff_fold(engine, profile, result, opts, observer), None)

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

    # 7.55 OData query-option exposure — on discovered API collections (no $metadata
    # needed), probe $apply=aggregate($count) + $top=1 read-only. A count or a row
    # returned WITHOUT auth — especially where the plain listing is blocked (413/403)
    # — is an authorization-bypass data-exposure lead.
    if opts.apidocs:
        await _guard(observer, "odata-query",
                     _odata_query_fold(engine, profile, result, opts, observer), None)

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
