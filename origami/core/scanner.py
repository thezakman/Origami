"""Scanner — the orchestration loop (§2 pipeline).

calibrate → fingerprint → fold (enable extensions + priority paths) →
scan prefix → classify → recurse into discovered directories → findings.

Scope/recursion are bounded (§3.11): same host, depth cap, request cap.
"""

from __future__ import annotations

import random
import string
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

# More than this many byte-identical results (same status+simhash) = a catch-all
# or generic page; collapse to one representative + a count.
COLLISION_MAX = 4
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
from origami.core.response_classifier import Filters, Finding, classify, resolve_baseline
from origami.core.scope import same_host, same_site
from origami.core.scheduler import (BASE_EXTS, Candidate, build_candidates,
                                     derive_vocabulary, load_wordlist, target_tokens)
from origami.modules import waf
from origami.modules.discovery import apidocs, backups, js_parser, robots, shortname
from origami.output.ui import NullObserver

# Extension classes we always calibrate at a prefix before scanning it.
_BASE_CALIB_EXTS = ["", ".txt", ".html"]


def _ext_of(path: str) -> str:
    last = path.rstrip("/").rsplit("/", 1)[-1]
    return ("." + last.rsplit(".", 1)[-1]) if "." in last else ""


# Sanity ceiling on harvested seeds. These are REAL references the app uses
# (high value), so the cap is generous — overall volume is bounded by
# --max-requests, not by starving the best candidates.
MAX_HARVEST_SEEDS = 2000

# Origins whose paths are root-absolute (joined from the host root, not the
# current prefix) — harvested references point at app-root paths.
_SEED_ORIGINS = {"memory", "js", "robots", "apidocs"}


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
    graph: bool = False           # track provenance edges for the endpoint graph (--graph)
    filters: Filters = field(default_factory=Filters)


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

    observer.phase("fingerprint")
    errors = await fp.forced_error_probes(engine, base_url)
    fp.apply_signals(profile, [root, *errors], kb)
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
    # assemble high-priority root seeds: memory (cross-target) + js + backups
    root_seeds: list[tuple[str, str]] = []

    if memory is not None:
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
        observer.phase("js-harvest")
        js_paths, js_params, js_edges = await _guard(observer, "js-harvest",
                                           js_parser.harvest(engine, base_url, root.body,
                                                             on_progress=observer.progress),
                                           (set(), set(), []))
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

    # robots.txt + sitemap.xml — free passive intel
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
        observer.phase("api-docs")
        spec_url, api_paths = await _guard(observer, "api-docs",
                                           apidocs.harvest(engine, base_url,
                                                           on_progress=observer.progress),
                                           (None, set()))
        api_paths = _scope_paths(api_paths, profile.host, opts.scope)
        if spec_url:
            root_seeds += [(p, "apidocs") for p in sorted(api_paths)]
            observer.log(f"api-docs: API spec/index at {urlparse(spec_url).path} "
                         f"→ {len(api_paths)} endpoints folded", 0, style="cyan")
            if opts.graph:
                spec_path = urlparse(spec_url).path
                result.edges += [(spec_path, p) for p in sorted(api_paths) if p != spec_path]

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
                     _shortscan_pass(engine, profile, base_url, words, result, opts, observer),
                     None)

    # 4. recursive scan + folds (checkpointed) -----------------------------
    queue: list[tuple[str, int]] = [(base_prefix, 0)]   # (prefix, depth)
    return await _scan_loop(engine, profile, opts, observer, memory, control, result,
                            base_prefix=base_prefix, words=words, exts=exts,
                            priority_paths=priority_paths, root_seeds=root_seeds,
                            queue=queue, scanned=set(), resume_path=resume_path)


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
                            front_cands=state.get("front_cands") or None)


async def _scan_loop(engine, profile, opts, observer, memory, control, result, *,
                     base_prefix, words, exts, priority_paths, root_seeds,
                     queue, scanned, resume_path, start_offset=0, front_cands=None):
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
                            requests_made=engine.total_requests, folds=result.folds,
                            words=words, exts=exts, priority_paths=priority_paths,
                            root_seeds=root_seeds, base_prefix=base_prefix,
                            queue=queue, scanned=scanned, start_offset=offset,
                            front_cands=[(c.path, c.origin) for c in cands] if cands else [],
                            edges=result.edges)

    observer.phase("scan")
    interrupted = False
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
        observer.log(f"scan {prefix} · {len(cands)} candidates"
                     + (f" · depth {depth}" if depth else "")
                     + (f" · resuming from {offset}" if offset else ""), 1)
        observer.start_prefix(prefix, len(cands))
        confirmed, ancestors, consumed, hit_cap = await _scan_prefix(
            engine, profile, prefix, cands, result, opts, observer, control,
            ranker=ranker, skip=offset)

        # Interrupted mid-prefix → re-queue at the front and checkpoint the exact
        # ordered candidates + offset reached, so resume replays from there.
        if hit_cap:
            queue.insert(0, (prefix, depth))
            interrupted = True
            _checkpoint(consumed, cands)
            break
        scanned.add(prefix)

        # Confirmed directories (real 403/301 dirs) are recursed before the
        # speculative ancestor dirs — high-value first, so a deep tree can't
        # starve the budget before the obvious directories are explored. Depth
        # is relative to the base, so a deep file recurses each of its parents.
        def _enqueue(dirs, front):
            for d in dirs:
                if d in scanned or d in queued or _excluded(d, opts):
                    continue
                if _rel_depth(d, base_prefix) <= opts.max_depth:
                    queued.add(d)
                    item = (d, _rel_depth(d, base_prefix))
                    queue.insert(0, item) if front else queue.append(item)

        _enqueue(ancestors, front=False)
        _enqueue(confirmed, front=True)
        _checkpoint(0)

    result.requests_made = engine.total_requests
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

    # 5. dedupe + collapse same-content collisions BEFORE expanding ---------
    # (do this first so the backup fold doesn't explode over hundreds of
    # identical pages — the bug behind 849 findings / 10k backup probes).
    result.findings = _dedupe_and_collapse(result.findings, observer)

    # 6. backup/source fold around confirmed files -------------------------
    if opts.backups:
        await _guard(observer, "backups",
                     _backup_fold(engine, profile, result, opts, observer), None)
        result.findings = _dedupe_and_collapse(result.findings, observer)

    # 6.5 association fold — corpus rules ("found /backup/ → test /.git/")
    if memory is not None:
        await _guard(observer, "associations",
                     _association_fold(engine, profile, result, opts, observer, memory), None)
        result.findings = _dedupe_and_collapse(result.findings, observer)

    observer.pushback(engine.pushback_events)
    result.requests_made = engine.total_requests
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
    """classify + soft-404 sibling verification. Returns a real Finding or None."""
    finding = classify(profile, probe, origin, prefix)
    if finding is None:
        return None
    if await _is_soft(engine, profile, prefix, probe):
        return None
    return finding


def _dedup_by_url(findings):
    """Collapse repeats of the same URL to the highest-confidence one.

    Cheap and safe to run mid-scan — a resumed/re-fired prefix re-discovers URLs
    already in the restored findings, so without this the report would balloon
    with duplicates on every resume.
    """
    best: dict[str, Finding] = {}
    for f in findings:
        cur = best.get(f.url)
        if cur is None or f.confidence > cur.confidence:
            best[f.url] = f
    return list(best.values())


def _dedupe_and_collapse(findings, observer):
    """URL-dedup (keep best confidence) + collapse same-template collisions.

    Groups by (status, body length): a generic page reflected for many paths —
    a server's blanket "403 Forbidden" served for .env/.git/.htaccess/css/build,
    or a catch-all 200 — keeps the SAME length even when the body echoes the
    path (so simhash differs). More than COLLISION_MAX in a group collapse to one
    representative + a count. The real content found by recursion (distinct
    lengths) is untouched.
    """
    deduped = _dedup_by_url(findings)

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
    decided upstream, filter-independent)."""
    shown = opts.filters.accept(finding.status, finding.length)
    observer.tick(hit=shown)
    observer.request(url, finding.status, shown)
    if shown:
        result.findings.append(finding)
        observer.finding(finding)
        observer.log(f"+ {finding.status} {observer.disp(url)} · "
                     f"conf {finding.confidence:.2f} · {finding.origin}", 1, style="green")


async def _scan_prefix(engine, profile, prefix, cands, result, opts, observer, control,
                       ranker=None, skip=0):
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

    consumed = len(cands)
    hit_cap = False
    for idx in range(skip, len(cands)):
        cand = cands[idx]
        if (opts.max_requests and engine.total_requests >= opts.max_requests) or control.quit:
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
            confirmed_dirs.append(path if path.endswith("/") else path + "/")
            observer.set_skippable(True)

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
        for var in backups.variations(path):
            if opts.max_requests and engine.total_requests >= opts.max_requests:
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
        if opts.max_requests and engine.total_requests >= opts.max_requests:
            break
        p = "/" + path.lstrip("/")
        if _excluded(p, opts):
            continue
        prefix = p.rsplit("/", 1)[0] + "/"
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


async def _shortscan_pass(engine, profile, base_url, words, result, opts, observer) -> None:
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
    for e in res.entries:
        observer.log(f"  8.3: {e.tilde}.{e.ext}"
                     + (f" → {e.fullname}" if e.fullname else ""), 2)

    tech_exts = tuple(sorted(profile.enabled_extensions))
    cands = shortname.expand(res.entries, words, tech_exts)

    # Regime 2: n-gram completion of truncated prefixes the wordlist can't cover.
    ng = NGram(order=3).train(words)
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
    by_prefix: dict[str, set[str]] = {}
    urls: list[tuple[str, str]] = []
    for baseurl, path in cands:
        url = urljoin(baseurl, path)
        prefix = urlparse(url).path.rsplit("/", 1)[0] + "/"
        by_prefix.setdefault(prefix, set()).add(_ext_of(path))
        urls.append((url, prefix))
    for prefix, pexts in by_prefix.items():
        await bl.calibrate(engine, profile,
                           [(prefix, e) for e in (set(_BASE_CALIB_EXTS) | pexts)])

    observer.start_prefix("shortscan", len(urls))
    for url, prefix in urls:
        if opts.max_requests and engine.total_requests >= opts.max_requests:
            break
        if _excluded(urlparse(url).path, opts):
            continue
        probe = await engine.fetch(url)
        finding = await _confirm(engine, profile, prefix, probe, "shortscan")
        if finding is None:
            observer.tick(hit=False)
            observer.request(url, probe.status, False)
            continue
        _report(observer, result, opts, finding, url)
