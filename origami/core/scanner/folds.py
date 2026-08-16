"""Scanner discovery folds — the extended strategies (harvest, secrets, authz,
graphql/odata, vhost/origin, param/cache, method/apiver/mutate, bucket/backup/
vcs, bypass, association, shortscan) plus the per-prefix scan. Imports shared
helpers from _common; never imports the package __init__ (keeps it acyclic)."""

from __future__ import annotations

import random
import string
from urllib.parse import urljoin, urlparse

from origami.brain.ngram import NGram
from origami.core import baseline as bl
from origami.core.evidence import Evidence
from origami.core.normalize import hamming, simhash
from origami.core.response_classifier import (
    NOT_FOUND_STATUS,
    Finding,
    classify,
    is_dir_listing,
)
from origami.core.scanner._common import (
    _BASE_CALIB_EXTS,
    _confirm,
    _dedup_by_url,
    _is_soft,
    _report,
    _scan_body,
)
from origami.core.scanner.types import ScanOptions
from origami.core.scanner.util import (
    _curl_cmd,
    _excluded,
    _ext_of,
    _host_root,
    _is_self_redirect_dir,
    _join_candidate,
    _over_budget,
    _scope_paths,
    _strips_trailing_slash,
)
from origami.core.scope import path_tenant_host, same_tenant_path
from origami.modules import (
    authz,
    bypass403,
    cache_poison,
    paramfuzz,
    vhost,
)
from origami.modules.discovery import (
    apiver,
    backups,
    buckets,
    graphql,
    js_parser,
    methods,
    mutate,
    negotiation,
    odata,
    originip,
    shortname,
    vcs,
)

MAX_BACKUP_FILES = 80   # cap files the backup fold expands around


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
            # Apache mod_negotiation (MultiViews): a 300 whose body LISTS the REAL
            # files behind an extensionless name — an info-disclosure AND a filename
            # primitive (the true extension, no guessing). BUT a MultiViews-on host
            # returns a 300 for ANY unresolvable name, suggesting only `/./x`/`/../x`
            # traversal noise — parse_choices drops that, so require ≥1 real sibling
            # before reporting (else every probed dotfile floods as a phantom leak).
            # Apache mod_negotiation (MultiViews): a 300 lists the REAL files behind a
            # name the server can't resolve. The 300 itself is just the mechanism — and
            # on a MultiViews host EVERY extension-fold variant (/x.bak, /x.inc, /x.php…)
            # 300s toward the same real file, which would flood the report. So DON'T
            # report the 300s; instead flag the misconfig ONCE, then validate each
            # DISCLOSED file inline exactly once (found → test), reporting the real hits.
            mv = probe.status == 300 and negotiation.is_multiple_choices(probe.body_head)
            if mv:
                if not result.multiviews_seen:
                    result.multiviews_seen = True
                    _report(observer, result, opts,
                            Finding(url, 300, probe.length, probe.content_type, 0.8, "negotiation",
                                    note="mod_negotiation MultiViews ENABLED — extensionless / wrong-"
                                         "extension requests enumerate real filenames (server misconfig)",
                                    tags=["config", "negotiation"], simhash=probe.body_simhash,
                                    words=probe.words, lines=probe.lines), url)
                for cp in sorted(negotiation.parse_choices(probe.body_head, url)):
                    if cp in result.multiviews_choices or _over_budget(engine, opts):
                        continue
                    result.multiviews_choices.add(cp)
                    curl = _join_candidate(_host_root(profile.base_url), "/", cp)
                    ck = curl.lower() if ci else curl
                    if ck in fired:
                        continue
                    fired.add(ck)
                    try:
                        cpr = await engine.fetch(curl, keep_body=opts.filters.needs_body())
                    except Exception:
                        continue
                    cpref = urlparse(curl).path.rsplit("/", 1)[0] + "/"
                    cf = classify(profile, cpr, "negotiation", cpref)
                    if cf is None or (not _over_budget(engine, opts)
                                      and await _is_soft(engine, profile, cpref, cpr)):
                        observer.request(curl, cpr.status, False)
                        continue
                    _report(observer, result, opts, cf, curl)
            if ranker is not None:
                ranker.observe(cand.path, hit=False)
            observer.tick(hit=False)
            observer.request(url, probe.status, False)     # the 300 request itself: mechanism, not a finding
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


MAX_AUTHZ_FILES = 30      # cap endpoints re-read for JWT/OAuth weakness analysis
_AUTHZ_HINT = ("oauth", "authoriz", "openid", "/token", "jwt", "login", "signin",
               "sign-in", "/auth", "sso", "saml", "session", "bearer", "connect/",
               "/me", "/account", "/profile", "/user", "whoami", "identity", "graphql")
_AUTHZ_TAGS = {"auth", "oauth", "jwt", "graphql"}
_SEV_STYLE = {"high": "bold red", "med": "yellow", "low": "dim"}


def _authz_candidate(f) -> bool:
    """A finding likely to carry a JWT or an OAuth authorize URL. An auth wall
    (401/403 — where a token cookie / WWW-Authenticate lives) always qualifies; a
    2xx page qualifies only when it's auth-RELEVANT (a login/token/OAuth path or an
    auth-ish tag) — not every JSON/HTML page, so generic content isn't re-fetched
    (it's already read by the secrets/harvest folds). Static assets stay out."""
    if f.status not in (200, 201, 202, 401, 403):
        return False
    path = urlparse(f.url).path.lower()
    if any(path.endswith(e) for e in (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2", ".ico")):
        return False
    if f.status in (401, 403):
        return True
    ct = (f.content_type or "").lower()
    return ("jwt" in ct
            or any(h in path for h in _AUTHZ_HINT)
            or bool(set(getattr(f, "tags", []) or []) & _AUTHZ_TAGS))


def _authz_report(finding, body, headers, observer, opts, result) -> int:
    """Analyze one response (body + headers) for JWT / OAuth weaknesses and emit
    findings. Returns the number of leads flagged."""
    n = 0
    for token in authz.find_jwts(body, headers):
        info = authz.analyze_jwt(token)
        if not info:
            continue
        issues = info["issues"]
        sev = ("high" if any(s == "high" for s, _ in issues)
               else "med" if any(s == "med" for s, _ in issues) else "low")
        bits = [t for _, t in issues]
        if info["sensitive"]:
            bits.append("claims " + ", ".join(f"{k}={v}" for k, v in list(info["sensitive"].items())[:4]))
        note = (f"JWT ({info['alg']}"
                + (f", sub={info['sub']}" if info.get("sub") else "") + ")"
                + (" — " + " · ".join(bits) if bits else " disclosed"))
        tags = ["jwt", "disclosure"]
        if any(s == "high" for s, _ in issues):
            tags.append("auth-bypass")
        f = Finding(finding.url, finding.status, len(token), "application/jwt",
                    0.9 if sev == "high" else 0.75, "authz", note=note, tags=tags)
        result.findings.append(f)
        observer.finding(f)
        observer.log(f"jwt: {observer.disp(finding.url)} ← {note}", 0,
                     style=_SEV_STYLE.get(sev, "yellow"))
        if opts.finding_sink is not None:
            opts.finding_sink(f)
        n += 1
    for oa in authz.find_oauth_issues(body):
        if not oa["issues"]:
            continue
        note = (f"OAuth authorize flow (client_id={oa['client_id']}) — "
                + " · ".join(oa["issues"]))
        f = Finding(oa["url"], finding.status, 0, "text/html", 0.85, "authz",
                    note=note, tags=["oauth", "auth-bypass"])
        result.findings.append(f)
        observer.finding(f)
        observer.log(f"oauth: {observer.disp(oa['url'])} ← {note}", 0, style="bold red")
        if opts.finding_sink is not None:
            opts.finding_sink(f)
        n += 1
    return n


async def _authz_fold(engine, profile, result, opts, observer) -> None:
    """Re-read auth-relevant endpoints (auth walls + login/token/OAuth pages) and
    flag JWT + OAuth weaknesses in their bodies AND headers — a token in a `Set-Cookie`
    or `{"token":…}`, an OAuth authorize URL missing `state`/PKCE. Read-only: nothing
    is forged or replayed; this is the recon lead, not the exploit."""
    cands = [f for f in result.findings if _authz_candidate(f)]
    if not cands:
        return
    # auth walls + auth-ish paths first, then smaller bodies; cap the radius
    cands.sort(key=lambda f: (f.status not in (401, 403)
                              and not any(h in f.url.lower() for h in _AUTHZ_HINT), f.length))
    cands = cands[:MAX_AUTHZ_FILES]
    observer.phase("authz")
    observer.log(f"authz: analyzing {len(cands)} endpoint(s) for JWT/OAuth weaknesses",
                 0, style="cyan")
    seen: set[str] = set()
    total = 0
    for f in cands:
        if _over_budget(engine, opts):
            break
        key = f.url.split("?", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        try:
            pr = await engine.fetch(f.url, keep_body=True)
        except Exception:
            continue
        total += _authz_report(f, pr.body or b"", pr.headers, observer, opts, result)
    if total:
        observer.log(f"authz: {total} JWT/OAuth lead(s) flagged — see the 'jwt'/'oauth' tags",
                     0, style="bold yellow")


# Tags that mark a resource as plausibly non-public — the convergence signal
# (a lesser identity reaching the same content) only fires on these, so a
# legitimately-shared public page isn't flagged.
_AUTHZ_SENSITIVE_TAGS = frozenset({"auth", "admin", "api", "config", "disclosure",
                                   "upload", "debug", "source", "secret", "leak", "listing"})
# Static-asset extensions — public by design, skipped unless a sensitive tag says otherwise.
_AUTHZ_STATIC_EXT = frozenset({".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg",
                               ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf",
                               ".eot", ".otf", ".mp4", ".webm", ".pdf"})
MAX_AUTHZ_DIFF_ENDPOINTS = 40   # cap endpoints replayed under every identity


def _authz_diff_candidate(f) -> bool:
    """An endpoint worth replaying under each identity: a reachable app resource
    (2xx/3xx) or an auth wall (401/403). Static assets are skipped unless a
    sensitive tag overrides — they're public by design and only add noise."""
    if not (200 <= f.status < 400 or f.status in (401, 403)):
        return False
    path = urlparse(f.url).path
    if path.rstrip("/") == "":
        return False                          # the site root is public by nature — no authz bug there
    if _ext_of(path) in _AUTHZ_STATIC_EXT and not (set(f.tags) & _AUTHZ_SENSITIVE_TAGS):
        return False
    return True


async def _authz_diff_fold(engine, profile, result, opts, observer) -> None:
    """Multi-identity authorization differential (§ authz_diff). Replay each
    discovered endpoint under the primary session + every `--as` identity (+ an
    implicit anon), then flag where they CONVERGE but should diverge — a lesser
    identity reaching the same content as the privileged session (BOLA/BFLA/broken
    auth) — or the inverse (the privileged session denied where a lesser one is
    served). Read-only GETs; findings enrich the existing endpoint in place."""
    import httpx

    from origami.modules import authz_diff as az
    ids = az.build_identities(engine.cfg.headers, opts.identities or {},
                              include_anon=opts.authz_anon)
    if len(ids) < 2:
        return                                # nothing to diff against
    cands = [f for f in result.findings if _authz_diff_candidate(f)]
    if not cands:
        return
    # sensitive-tagged and auth-wall endpoints first; then dedupe by resource (no query).
    cands.sort(key=lambda f: (not (set(f.tags) & _AUTHZ_SENSITIVE_TAGS),
                              f.status not in (401, 403), f.url))
    seen_urls: set[str] = set()
    uniq = []
    for f in cands:
        k = f.url.split("?", 1)[0]
        if k not in seen_urls:
            seen_urls.add(k)
            uniq.append(f)
    cands = uniq[:MAX_AUTHZ_DIFF_ENDPOINTS]

    observer.phase("authz-diff")
    label_str = ", ".join(i.label + ("*" if i.authed else "") for i in ids)
    observer.log(f"authz-diff: replaying {len(cands)} endpoint(s) under {len(ids)} "
                 f"identities ({label_str}) — * = authenticated", 0, style="cyan")
    observer.start_prefix("authz-diff", len(cands))

    # areas known to enforce access control: parent dirs where SOME finding is a wall.
    protected = {urlparse(f.url).path.rsplit("/", 1)[0] + "/"
                 for f in result.findings if f.status in (401, 403)}

    clients: dict[str, httpx.AsyncClient] = {}
    found = 0
    try:
        for i in ids:
            clients[i.label] = httpx.AsyncClient(
                verify=False, timeout=engine.cfg.timeout, follow_redirects=False,
                headers={"User-Agent": engine.cfg.user_agent, **i.headers})
        for f in cands:
            if _over_budget(engine, opts):
                break
            observer.substep(observer.disp(f.url))
            obs: dict[str, az.Obs] = {}
            for i in ids:
                try:
                    r = await clients[i.label].get(f.url)
                except Exception:
                    continue                  # this identity couldn't reach it — omit its row
                body = r.content or b""
                obs[i.label] = az.Obs(i.label, r.status_code, simhash(body),
                                      len(body), True, i.authed)
            primary = obs.get("primary")
            observer.request(f.url, primary.status if primary else 0, False)
            if primary is None:
                observer.tick(hit=False)
                continue
            parent = urlparse(f.url).path.rsplit("/", 1)[0] + "/"
            mixed = (any(az._blocked(o) for o in obs.values())
                     and any(az._reached(o) for o in obs.values()))
            sensitive = (bool(set(f.tags) & _AUTHZ_SENSITIVE_TAGS)
                         or parent in protected or mixed)
            verdict = az.diff_verdict(obs, sensitive=sensitive)
            if verdict is None:
                observer.tick(hit=False)
                continue
            matrix = " · ".join(f"{o.label}={o.status}" for o in obs.values())
            # Enrich the EXISTING finding in place (its URL is already reported, so a
            # fresh Finding would be deduped away) — same pattern as secrets/leaks/authz.
            f.tags = sorted(set(f.tags) | set(verdict["tags"]))
            f.note = (f.note + " · " if f.note else "") + verdict["note"] + f" [{matrix}]"
            if verdict["kind"] == "broken-auth":
                f.confidence = max(f.confidence, verdict["confidence"])
            if opts.finding_sink is not None:
                opts.finding_sink(f)          # re-emit so a JSONL consumer sees the authz tag
            found += 1
            observer.tick(hit=True)
            observer.log(f"authz-diff: {verdict['kind']} → {observer.disp(f.url)} [{matrix}]",
                         0, style="bold yellow" if verdict["kind"] == "bola-lead" else "bold red")
    finally:
        for c in clients.values():
            try:
                await c.aclose()
            except Exception:
                pass
    if found:
        observer.log(f"authz-diff: {found} access-control lead(s) flagged — see the 'authz' tag",
                     0, style="bold red")


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


MAX_ODATA_PROBES = 6   # entity sets tested for unauth aggregation (read-only $count)


async def _odata_probe(engine, opts, observer, of, meta) -> None:
    """Read-only aggregation probe: for the top entity sets (sensitive first), GET
    `<set>?$apply=aggregate($count as …)`. A count returned WITHOUT auth means the
    service exposes row-level data by rollup even when the rows themselves may be
    gated — an authorization-by-aggregation bypass (and a DoS amplifier). Strictly
    GET; `$batch`/Actions/writes are never touched. Annotates the metadata finding."""
    root = meta.get("service_root")
    sets = meta.get("entitysets") or []
    if not (root and sets):
        return
    sens = set(meta.get("sensitive") or [])
    ordered = [s for s in sets if s in sens] + [s for s in sets if s not in sens]
    ordered = ordered[:MAX_ODATA_PROBES]
    observer.phase("odata-probe")
    observer.log(f"odata: probing {len(ordered)} entity set(s) for unauth aggregation "
                 f"($apply=aggregate, read-only)", 0, style="cyan")
    open_sets, reachable_sets = [], []
    for es in ordered:
        if _over_budget(engine, opts):
            break
        url = odata.build_agg_probe(root, es)
        try:
            pr = await engine.fetch(url, keep_body=True)
        except Exception:
            continue
        observer.request(url, pr.status, False)
        verdict = odata.classify_probe(pr.status, pr.body or b"")
        if verdict == "open":
            open_sets.append(es)
        elif verdict == "reachable":
            reachable_sets.append(es)
    if not (open_sets or reachable_sets):
        observer.log("odata: aggregation blocked/unsupported on probed sets (gate enforced)",
                     1, style="green")
        return
    detail = ", ".join(f"{s}!" for s in open_sets) \
        + (", " if open_sets and reachable_sets else "") + ", ".join(reachable_sets)
    of.note = (of.note + " · " if of.note else "") + f"aggregation WITHOUT auth: {detail}"
    of.tags = list(dict.fromkeys(of.tags + ["odata-agg"] + (["auth-bypass"] if open_sets else [])))
    if open_sets:
        of.confidence = max(of.confidence, 0.9)
    hot = [s for s in (open_sets + reachable_sets) if s in sens]
    observer.log(f"odata: {len(open_sets)} set(s) leak an aggregate + {len(reachable_sets)} "
                 f"reachable WITHOUT auth"
                 + (f" — incl. sensitive: {', '.join(hot[:6])}" if hot else "")
                 + " → authz-by-aggregation lead", 0,
                 style="bold red" if open_sets else "yellow")
    if opts.finding_sink is not None:
        opts.finding_sink(of)


MAX_ODATA_QUERY_ENDPOINTS = 12   # discovered API collections probed for $apply/$top


def _odata_query_candidate(f) -> bool:
    """A discovered endpoint that looks like an OData-queryable API collection: a
    JSON / api-tagged / `/api/`|`/odata/` resource path with no file extension
    (collections are extensionless — `/api/motoristas`, not `/app.js`)."""
    path = urlparse(f.url).path
    last = path.rstrip("/").rsplit("/", 1)[-1].lower()
    if not last or "." in last:
        return False
    ct = (f.content_type or "").lower()
    pl = path.lower()
    return ("json" in ct or "/api/" in pl or "/odata" in pl
            or bool(set(getattr(f, "tags", []) or []) & {"api"}))


async def _odata_try(engine, base, plain_status, opts, observer, result) -> bool:
    """Probe `$apply=aggregate($count)` + `$top=1` (read-only) on ONE collection URL
    and emit a standard finding PER successful payload — the finding's URL IS the
    reproducing request (`…?$top=1`), with its real status/size, so it lines up with
    every other finding row and is copy-paste ready. De-duped via `result.odata_probed`
    (the early target probe and the late fold never double-hit). Returns True on a hit."""
    key = urlparse(base).path.rstrip("/")
    if key in result.odata_probed:
        return False
    result.odata_probed.add(key)
    if plain_status is None:                       # not known yet → learn it
        try:
            plain_status = (await engine.fetch(base)).status
        except Exception:
            plain_status = 0
    blocked = not (200 <= (plain_status or 0) < 300)
    bypass = f" · bypasses HTTP {plain_status} on the plain collection" if blocked else ""
    hits: list = []           # (payload_url, status, length, confidence, note, tags)

    try:
        u = odata.with_query(base, odata.AGG_COUNT)
        pr = await engine.fetch(u, keep_body=True)
        observer.request(base, pr.status, False)
        if odata.classify_probe(pr.status, pr.body or b"") == "open":
            c = odata.agg_count(pr.body or b"")
            tags = ["api", "odata-agg"] + (["auth-bypass"] if blocked else [])
            hits.append((u, pr.status, len(pr.body or b""), 0.9,
                         f"unauth aggregate via $apply=aggregate($count)={c}{bypass}", tags))
    except Exception:
        pass
    try:
        u = odata.with_query(base, odata.top_query(1))
        pr2 = await engine.fetch(u, keep_body=True)
        observer.request(base, pr2.status, False)
        recs = odata.parse_records(pr2.status, pr2.body or b"")
        if recs:
            sens = odata.sensitive_fields(recs[0])
            tags = ["api", "odata-agg", "disclosure"] + (["auth-bypass"] if blocked else [])
            hits.append((u, pr2.status, len(pr2.body or b""), 0.95,
                         f"unauth record read via $top=1 — {len(recs[0])} fields"
                         + (f", sensitive: {', '.join(sens[:6])}" if sens else "") + bypass, tags))
    except Exception:
        pass

    for url, status, length, conf, note, tags in hits:
        f = Finding(url, status, length, "application/json", conf, "odata",
                    note=note, tags=list(dict.fromkeys(tags)))
        result.findings.append(f)
        observer.finding(f)                        # standard row; the URL carries the payload
        if opts.finding_sink is not None:
            opts.finding_sink(f)
    return bool(hits)


async def _odata_query_fold(engine, profile, result, opts, observer, target_only=False) -> None:
    """Probe OData query options on API collections — no `$metadata` required. Each
    candidate gets a read-only `$apply=aggregate($count)` + `$top=1`; a count or a
    record returned WITHOUT auth is an authorization-bypass data-exposure lead,
    strongest where the plain listing is BLOCKED (413 'entity too large' / 403) but
    `$top`/`$apply` walk around it. Strictly GET; `$top=1` reads one row, never a bulk
    dump; writes never touched.

    `target_only` runs the EARLY pass: probe just the target collection (its status is
    the root fetch's), so pointing at a collection reports its exposure up front instead
    of only after the whole scan. The late pass then covers discovered collections."""
    cands: list = []          # (base_url_without_query, plain_status | None)
    seen = set(result.odata_probed)               # PATH keys already probed by an earlier pass
    # The TARGET itself — pointing directly AT a collection whose plain listing is
    # BLOCKED (413/403) never yields a finding, yet `?$top=1` may leak a row.
    tpath = urlparse(profile.base_url).path
    tlast = tpath.rstrip("/").rsplit("/", 1)[-1].lower()
    if tlast and "." not in tlast and tpath.rstrip("/") not in seen:
        seen.add(tpath.rstrip("/"))
        cands.append((profile.base_url.split("?", 1)[0], None))
    if not target_only:
        for f in result.findings:
            key = urlparse(f.url).path.rstrip("/")
            if key in seen or not _odata_query_candidate(f):
                continue
            seen.add(key)
            cands.append((f.url.split("?", 1)[0], f.status))
    cands = cands[:MAX_ODATA_QUERY_ENDPOINTS]
    if not cands:
        return
    observer.phase("odata-query")
    if not target_only:
        observer.log(f"odata: probing {len(cands)} API collection(s) for OData query-option "
                     f"exposure ($apply/$top, read-only)", 0, style="cyan")
    any_hit = False
    for base, plain_status in cands:
        if _over_budget(engine, opts):
            break
        if await _odata_try(engine, base, plain_status, opts, observer, result):
            any_hit = True
    if not any_hit and not target_only:
        observer.log("odata: no query-option exposure on probed collections", 1, style="green")


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

        def _verdict(param: str, ctx: str, verified=verified) -> str:
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
            # A response the origin/edge PROVABLY won't cache — Cache-Control
            # no-store/private/no-cache, or CF-Cache-Status DYNAMIC/BYPASS (the edge
            # saying "not cached", vs an ambiguous MISS that still could be) — cannot
            # be poisoned. A bare "behaviour-change" lead there is noise (the unkeyed
            # header just routes the attacker's OWN request). Suppress it unless the
            # canary actually reflected (still worth a look) or the cache confirmed it.
            if not cached and not ctx and cache_poison.provably_uncacheable(base.headers):
                observer.tick(hit=False)
                continue                        # not poisonable — no cache to store it
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
    host = _host_root(profile.base_url)
    for f in file_hits:
        path = urlparse(f.url).path
        prefix = path.rsplit("/", 1)[0] + "/"
        observer.substep(path.rsplit("/", 1)[-1] or path)   # backups: <file>
        # Suffix-catch-all guard: probe a RANDOM extension on this base once. If the
        # route serves 2xx content for `<path>.<garbage>`, it serves the same page for
        # ANY suffix (a form platform's /f/<slug>.<anything>), so its .bak/.old/… are
        # that page, not disclosures. A per-request nonce (fresh CSRF/timestamp) defeats
        # the simhash check but NOT the length — the catch-all keeps it constant — so
        # gate the drop on (status, length) matching this probe.
        catchall = None
        if not _over_budget(engine, opts):
            rnd = "".join(random.choices(string.ascii_lowercase, k=8))
            try:
                cp = await engine.fetch(f"{urljoin(host, path.lstrip('/'))}.{rnd}")
                if cp.ok and 200 <= cp.status < 300 and cp.length > 0:
                    catchall = (cp.status, cp.length)
            except Exception:
                pass
        for var in backups.variations(path):
            if _over_budget(engine, opts):
                break
            url = urljoin(host, var)
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
            # …and a variant matching the random-suffix catch-all is that same page
            # served for any extension (simhash-proof against per-request nonces).
            if catchall and (probe.status, probe.length) == catchall:
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
    # The site's DEFAULT route: the X-Original-URL / X-Rewrite-URL family often just
    # routes the request to the app index (a generic "restricted"/login/index page),
    # and `root_simhash` is the TARGET's body — useless when the target is a deep or
    # empty-bodied API endpoint (as here: /api/…/document returned 0B). Fetch the host
    # index once so an index-routing "200" is rejected, not flagged as a bypass.
    home_simhash = 0
    try:
        hp = await engine.fetch(root)
        if hp.ok and 200 <= hp.status < 300 and hp.length > 0:
            home_simhash = hp.body_simhash
    except Exception:
        pass
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
                observer.tick(hit=False); continue        # just the target's body — not a bypass
            if home_simhash and hamming(probe.body_simhash, home_simhash) <= bl.SIMHASH_MISS_DISTANCE:
                observer.tick(hit=False); continue        # the site index / default route — not the blocked resource
            if f.simhash and hamming(probe.body_simhash, f.simhash) <= bl.SIMHASH_MISS_DISTANCE:
                observer.tick(hit=False); continue        # same body as the 403 page — only the status flipped
            if await _confirm(engine, profile, prefix, probe, "bypass403") is None:
                observer.tick(hit=False); continue        # soft-404 / catch-all
            bf = Finding(f.url, probe.status, probe.length, probe.content_type, 0.9,
                         "bypass403", note=f"403→{probe.status} bypass: {label}",
                         tags=sorted(set(f.tags) | {"bypass"}), simhash=probe.body_simhash,
                         repro=_curl_cmd(url, method, headers))   # the exact header/method trick
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


# The 8.3 short-name leak lives on the WINDOWS/NTFS filesystem, so it survives ANY
# front server — an nginx (or a CDN) reverse-proxying IIS still leaks. Gating `auto`
# purely on an "iis" fingerprint misses exactly that: a .NET app (DotNetNuke,
# SharePoint, Sitecore…) behind nginx. Any of these stack signals, or an ASP.NET
# extension, is enough to spend shortscan's own (cheap, self-gating) vuln check.
_WINDOWS_STACKS = frozenset({
    "iis", "asp.net", "aspnet", "asp.net mvc", "dnn", "dotnetnuke", "sharepoint",
    "umbraco", "sitecore", "kentico", "sitefinity", "orchard",
    "nopcommerce", "episerver", "windows", ".net", "blazor",
})
_ASPNET_EXTS = frozenset({".asp", ".aspx", ".ashx", ".asmx", ".axd", ".cshtml", ".vbhtml"})


def _should_shortscan(opts: ScanOptions, folds: set[str], profile) -> bool:
    if opts.shortscan == "off":
        return False
    if opts.shortscan == "on":
        return True
    # --deep is a thorough sweep: spend shortscan's own (cheap, self-gating) vuln
    # check on EVERY target, so an IIS-behind-nginx host with no detectable .NET
    # fingerprint (a bare API / static front) is still caught. `off` above still wins.
    if opts.deep:
        return True
    if "shortscan" in folds:             # auto: IIS confirmed the fold
        return True
    # …or any Windows/.NET signal, even behind an nginx/CDN front (shortscan's own
    # vuln check is the real gate and is cheap on a non-vulnerable target). Substring
    # match so a scored tech like "microsoft asp.net" still hits "asp.net".
    techs = [t.lower() for t in getattr(profile, "tech_scores", {})]
    if any(w in t for t in techs for w in _WINDOWS_STACKS):
        return True
    if profile.case_sensitive is False:  # NTFS/Windows already proven case-insensitive
        return True
    return bool({e.lower() for e in getattr(profile, "enabled_extensions", ())} & _ASPNET_EXTS)


MAX_SHORTSCAN_DIRS = 12   # cap total shortscan runs (root + recursed dirs) under --deep
MAX_SHORTSCAN_DEPTH = 3    # how deep the 8.3 dir recursion goes


async def _shortscan_pass(engine, profile, base_url, words, result, opts, observer,
                          memory=None) -> None:
    """Run shortscan at the base, then — under --deep — recurse into each DIRECTORY
    it reveals: 8.3 enumeration is per-directory, so `/SALESFORCE/` leaks its own
    short names the root run can't see. Bounded by MAX_SHORTSCAN_DIRS / _DEPTH."""
    observer.phase("shortscan")
    seen: set[str] = {base_url.rstrip("/")}
    queue: list[tuple[str, int]] = [(base_url, 0)]
    runs = 0
    while queue and runs < MAX_SHORTSCAN_DIRS:
        if _over_budget(engine, opts):
            break
        url, depth = queue.pop(0)
        try:
            ran, dir_urls = await _shortscan_one(engine, profile, url, words, result, opts,
                                                 observer, memory, is_root=(runs == 0))
        except Exception as ex:                   # one bad subdir must not kill the recursion
            if runs == 0:                         # …but a root error ends the pass
                observer.log(f"shortscan: skipped ({type(ex).__name__})", 1, style="yellow")
                return
            observer.log(f"shortscan: {urlparse(url).path} errored, skipping "
                         f"({type(ex).__name__})", 2, style="yellow")
            runs += 1
            continue
        runs += 1
        if runs == 1 and not ran:
            return                                # root not vulnerable/available → stop
        if opts.deep and ran and depth < MAX_SHORTSCAN_DEPTH:
            for d in dir_urls:                    # recurse into confirmed 8.3 directories
                k = d.rstrip("/")
                if k not in seen:
                    seen.add(k)
                    queue.append((d, depth + 1))
    if runs > 1:
        observer.log(f"shortscan: recursed into {runs - 1} discovered "
                     f"director{'y' if runs == 2 else 'ies'} (--deep)", 1, style="cyan")


async def _shortscan_one(engine, profile, base_url, words, result, opts, observer,
                         memory=None, is_root=True) -> tuple[bool, list[str]]:
    """Run shortscan at ONE url: gate on its vuln check, expand 8.3 names, scan the
    seeds. Returns (ran, dir_urls) — dir_urls are the DIRECTORY entries (named, no
    extension) to recurse into. Verbose banner/evidence only on the root run."""
    res = await shortname.run_shortscan(
        base_url,
        insecure=not engine.cfg.verify_tls,
        user_agent=engine.cfg.user_agent,
        concurrency=engine.cfg.concurrency,
        timeout=int(engine.cfg.timeout),
    )
    if not res.available:
        if is_root:
            observer.log(f"shortscan: skipped ({res.error})", 1, style="yellow")
        return False, []
    if res.error and is_root:
        observer.log(f"shortscan: {res.error}", 1, style="yellow")
    if not res.vulnerable:
        if is_root:
            observer.log("shortscan: target not vulnerable to 8.3 enumeration", 1)
        return False, []

    where = urlparse(base_url).path or "/"
    observer.log(f"shortscan: VULNERABLE · {len(res.entries)} 8.3 names leaked"
                 + ("" if is_root else f" at {where}"), 1, style="cyan")
    if is_root:
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
    # directory entries (a reconstructed name with NO extension) → recurse targets.
    # An extensionless 8.3 name can also be a FILE (README, LICENSE); verify each
    # candidate actually resolves to a directory before spending a whole recursive
    # run (and a slot of the MAX_SHORTSCAN_DIRS budget) on a 404.
    root = base_url if base_url.endswith("/") else base_url + "/"
    dir_urls: list[str] = []
    for e in res.entries:
        if not (e.fullname and not e.ext):
            continue
        d = urljoin(root, e.fullname + "/")
        try:
            pr = await engine.fetch(d)
            if pr.status != 404 and pr.status < 500:   # a real dir answers 2xx/3xx/403
                dir_urls.append(d)
        except Exception:
            pass

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
        if is_root:
            observer.log("shortscan: no candidates after expansion", 1)
        return True, dir_urls
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
    return True, dir_urls
