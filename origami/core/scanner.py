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

from origami.brain.kb import TechRule, load_kb
from origami.brain.ngram import NGram
from origami.core import baseline as bl
from origami.core import fingerprint as fp
from origami.core.evidence import Evidence, TargetProfile
from origami.core.httpclient import Engine
from origami.core.normalize import hamming
from origami.core.response_classifier import Filters, Finding, classify, resolve_baseline
from origami.core.scope import same_host, same_site
from origami.core.scheduler import (BASE_EXTS, Candidate, build_candidates,
                                     derive_vocabulary, load_wordlist, target_tokens)
from origami.modules import waf
from origami.modules.discovery import backups, js_parser, robots, shortname
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
_SEED_ORIGINS = {"memory", "js", "robots"}


def _host_root(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}/"


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
        if "://" in p:                       # same-site CDN full URL (js kept it)
            if scope == "site" and same_site(urlparse(p).netloc, host):
                out.add(p)
            continue
        if p.startswith("//"):
            continue
        if p.lstrip("/"):
            out.add(p)                       # keep leading-/ (root-abs vs relative)
    return out


@dataclass
class ScanOptions:
    max_depth: int = 1            # 0 = root only
    max_requests: int = 5000      # hard cap per run (§3.11)
    wordlist_path: str | None = None
    shortscan: str = "auto"       # "auto" (if IIS fold) | "on" (force) | "off"
    js: bool = True               # harvest endpoints from HTML/JS
    backups: bool = True          # VCS/dotfile probes + backup-name folding
    max_folds: int = 40           # cap on learned vocabulary names folded into the scan
    scope: str = "host"           # "host" (target only) | "site" (also scan same-site CDN)
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


async def scan(engine: Engine, base_url: str, opts: ScanOptions | None = None,
               observer=None, memory=None, control=None) -> ScanResult:
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
        js_paths, js_params = await js_parser.harvest(engine, base_url, root.body)
        js_paths = _scope_paths(js_paths, profile.host, opts.scope)   # scope discipline
        js_paths = set(sorted(js_paths)[:MAX_HARVEST_SEEDS])          # cap the blast radius
        root_seeds += [(p, "js") for p in sorted(js_paths)]
        profile.parameters |= js_params
        if js_paths:
            observer.log(f"js: {len(js_paths)} same-host endpoints harvested from HTML/JS",
                         1, style="cyan")
        if js_params:
            observer.log(f"params: {len(js_params)} parameter names harvested "
                         f"(pentest input surface)", 0, style="cyan")

    # robots.txt + sitemap.xml — free passive intel
    robots_paths = _scope_paths(await robots.harvest(engine, base_url), profile.host, opts.scope)
    if robots_paths:
        root_seeds += [(p, "robots") for p in sorted(robots_paths)]
        observer.log(f"robots/sitemap: {len(robots_paths)} paths", 1, style="cyan")

    if opts.backups:
        root_seeds += [(p, "backup") for p in backups.vcs_probes()]

    # THE origami fold: learn the target's own vocabulary (names + extensions)
    # from the references discovered above, and weave it into the scan — capped
    # by --max-folds so a chatty SPA can't explode the request budget. Kept by
    # frequency: the most-referenced tokens are the most valuable.
    names_ctr, exts_ctr = derive_vocabulary(js_paths | robots_paths)
    learned_names = [n for n, _ in names_ctr.most_common(opts.max_folds)]
    # the target's own name (host labels + base path) is prime vocabulary
    tgt = target_tokens(profile.host, base_prefix)
    learned_names = list(dict.fromkeys(list(tgt) + learned_names))
    # extensions multiply the WHOLE wordlist, so they get a tighter cap.
    ext_cap = max(6, opts.max_folds // 8)
    learned_exts = {e for e, _ in exts_ctr.most_common(ext_cap)} - exts
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
        await _shortscan_pass(engine, profile, base_url, words, result, opts, observer)

    # 4. recursive scan ----------------------------------------------------
    observer.phase("scan")
    queue: list[tuple[str, int]] = [(base_prefix, 0)]   # (prefix, depth)
    scanned_prefixes: set[str] = set()
    while queue:
        if control.quit:
            observer.log("scan: quit requested — stopping", 0, style="yellow")
            break
        prefix, depth = queue.pop(0)
        if prefix in scanned_prefixes:
            continue
        scanned_prefixes.add(prefix)

        if prefix != base_prefix:
            observer.directory(prefix, depth)
        await bl.calibrate(engine, profile, [(prefix, e) for e in recurse_exts])

        is_base = prefix == base_prefix
        cands = build_candidates(priority_paths if is_base else [], words, exts,
                                 extra_seeds=root_seeds if is_base else None)
        observer.log(f"scan {prefix} · {len(cands)} candidates"
                     + (f" · depth {depth}" if depth else ""), 1)
        observer.start_prefix(prefix, len(cands))
        dirs = await _scan_prefix(engine, profile, prefix, cands, result, opts, observer, control)

        # Queue discovered dirs (incl. ancestors of deep hits) by their depth
        # relative to the base — a depth cap, not a "+1 per level" rule, so a
        # deep file like /lms/x/views/y.html recurses /lms/x/ and /lms/x/views/.
        for d in dirs:
            if d not in scanned_prefixes and _rel_depth(d, base_prefix) <= opts.max_depth:
                queue.append((d, _rel_depth(d, base_prefix)))

    # 5. dedupe + collapse same-content collisions BEFORE expanding ---------
    # (do this first so the backup fold doesn't explode over hundreds of
    # identical pages — the bug behind 849 findings / 10k backup probes).
    result.findings = _dedupe_and_collapse(result.findings, observer)

    # 6. backup/source fold around confirmed files -------------------------
    if opts.backups:
        await _backup_fold(engine, profile, result, opts, observer)
        result.findings = _dedupe_and_collapse(result.findings, observer)

    # 6.5 association fold — corpus rules ("found /backup/ → test /.git/")
    if memory is not None:
        await _association_fold(engine, profile, result, opts, observer, memory)
        result.findings = _dedupe_and_collapse(result.findings, observer)

    observer.pushback(engine.pushback_events)
    result.requests_made = engine.total_requests
    result.pushbacks = engine.pushback_events
    result.findings.sort(key=lambda f: (-f.confidence, f.url))

    if memory is not None:
        run_id = memory.record_run(profile, result)
        observer.log(f"memory: run #{run_id} saved · "
                     f"{len(result.findings)} findings recorded", 1)
    return result


async def _is_soft(engine, profile, prefix, probe) -> bool:
    """Sanity-check a surprising hit with a random sibling.

    Multi-modal soft-404 hosts (302 most paths, generic 200 for others) defeat
    a single baseline. So before trusting a hit, fire one random sibling of the
    same shape; if it comes back the same (status + body shape), the response
    is generic — learn the signature so the rest are filtered for free.
    """
    path = urlparse(probe.url).path
    ext = _ext_of(path)
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    sib = await engine.fetch(urljoin(profile.base_url, prefix.lstrip("/") + rnd + ext))
    if (sib.ok and sib.status == probe.status
            and hamming(sib.body_simhash, probe.body_simhash) <= bl.SIMHASH_MISS_DISTANCE):
        cb = resolve_baseline(profile, probe.url, prefix)
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


def _dedupe_and_collapse(findings, observer):
    """URL-dedup (keep best confidence) + collapse same-content collisions.

    Collapsing byte-identical results (same status+simhash) into one + a count
    is what stops a catch-all page (or one file reachable via many query
    strings/paths) from drowning the report in hundreds of dupes.
    """
    best: dict[str, Finding] = {}
    for f in findings:
        cur = best.get(f.url)
        if cur is None or f.confidence > cur.confidence:
            best[f.url] = f

    clusters: dict[tuple, list] = defaultdict(list)
    for f in best.values():
        clusters[(f.status, f.simhash)].append(f)

    out, collapsed = [], 0
    for (status, sh), group in clusters.items():
        if sh and len(group) > COLLISION_MAX:
            rep = min(group, key=lambda f: len(f.url))
            rep.note = (rep.note + " " if rep.note else "") + f"+{len(group) - 1} paths, same content"
            out.append(rep)
            collapsed += len(group) - 1
        else:
            out.extend(group)
    if collapsed:
        observer.log(f"collapsed {collapsed} same-content results "
                     f"(catch-all / one file via many paths)", 0, style="yellow")
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


async def _scan_prefix(engine, profile, prefix, cands, result, opts, observer, control) -> list[str]:
    """Fire candidates under `prefix`, classify, return discovered subdirs."""
    discovered_dirs: list[str] = []
    first_hit_path: str | None = None

    for cand in cands:
        if engine.total_requests >= opts.max_requests or control.quit:
            break
        if control.skip_prefix:
            control.skip_prefix = False
            if observer.skippable:
                observer.log(f"skip: {prefix} (next)", 0, style="yellow")
                break
            # no directory discovered yet → skipping would just end the scan
            # (same as quit), so ignore it.
            observer.log("(n ignored — no subdirectory discovered yet; use q to quit)",
                         0, style="dim")
        # Join against the host root so a base path like /lms/ never doubles.
        # A full URL (same-site CDN, scope=site) is fetched as-is; a leading-/
        # seed is root-absolute; a relative seed (Angular-style templateUrl)
        # resolves under the current app prefix.
        root = _host_root(profile.base_url)
        if "://" in cand.path:
            url = cand.path
        elif cand.path.startswith("/"):
            url = urljoin(root, cand.path.lstrip("/"))
        else:
            url = urljoin(root, prefix.lstrip("/") + cand.path)
        probe = await engine.fetch(url)

        finding = await _confirm(engine, profile, prefix, probe, cand.origin)
        if finding is None:
            observer.tick(hit=False)
            observer.request(url, probe.status, False)
            continue

        # recursion/dir detection from the real hit — filter-INDEPENDENT, so a
        # filtered-out 403 dir is still followed into.
        path = urlparse(url).path
        if first_hit_path is None and probe.status == 200:
            first_hit_path = path
        last = path.rstrip("/").rsplit("/", 1)[-1]
        has_ext = "." in last
        is_dir = (cand.path.endswith("/")
                  or (probe.status == 403 and not has_ext)
                  or (probe.status in (301, 302)
                      and probe.location.rstrip("/").endswith(path.rstrip("/"))))
        if is_dir:
            discovered_dirs.append(path if path.endswith("/") else path + "/")
            observer.set_skippable(True)   # a dir now exists → [n] skip becomes useful

        # Any confirmed path implies its parent directories exist — recurse them
        # (a deep JS-harvested file like /lms/x/views/y.html reveals /lms/x/ and
        # /lms/x/views/, which the wordlist+vocab then explore).
        segs = [s for s in path.strip("/").split("/") if s]
        for i in range(1, len(segs)):
            discovered_dirs.append("/" + "/".join(segs[:i]) + "/")
            observer.set_skippable(True)

        _report(observer, result, opts, finding, url)

    if first_hit_path:
        await bl.probe_case_sensitivity(engine, profile, first_hit_path)
    return discovered_dirs


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
            if engine.total_requests >= opts.max_requests:
                break
            url = urljoin(_host_root(profile.base_url), var)
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
        if engine.total_requests >= opts.max_requests:
            break
        p = "/" + path.lstrip("/")
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
        if engine.total_requests >= opts.max_requests:
            break
        probe = await engine.fetch(url)
        finding = await _confirm(engine, profile, prefix, probe, "shortscan")
        if finding is None:
            observer.tick(hit=False)
            observer.request(url, probe.status, False)
            continue
        _report(observer, result, opts, finding, url)
