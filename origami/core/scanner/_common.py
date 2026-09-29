"""Scanner shared helpers — classification/confirmation, finding reporting,
and dedup/collapse. Depended on by both the orchestration loop (__init__) and
the discovery folds, so it sits below both to keep imports acyclic."""

from __future__ import annotations

import random
import string
from collections import defaultdict
from dataclasses import asdict
from urllib.parse import urljoin, urlparse

from origami.core import baseline as bl
from origami.core.normalize import hamming
from origami.core.response_classifier import (
    Finding,
    classify,
    resolve_baseline,
)
from origami.core.scanner.util import (
    _ext_of,
    _host_root,
)
from origami.modules import (
    leaks,
    secrets,
)
from origami.modules.discovery import (
    buckets,
)

# More than this many byte-identical results (same status+simhash) = a
# catch-all/generic page; collapse to one representative + a count.
COLLISION_MAX = 4
# Blocked/erroring statuses whose identical-body flood is a generic wall.
_WALL_STATUS = frozenset({401, 403, 405, 500, 502, 503, 504})
# Origins from a DECLARED contract (OpenAPI/.well-known) — exempt from
# wall-muting and the same-(status,length) report collapse.
_DECLARED_ORIGINS = frozenset({"apidocs", "wellknown"})
# Extension classes always calibrated at a prefix before scanning it
# (shared by the top-level scan and the fold-side prefix/shortscan passes).
_BASE_CALIB_EXTS = ["", ".txt", ".html"]


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


def _collapse_slash_twins(findings, ci=False):
    """Collapse a trailing-slash twin: `/x` and `/x/` that return an IDENTICAL
    response (same status + body fingerprint) are ONE resource — listing both is
    noise (`/health` 7B == `/health/` 7B). A redirect or a differing body keeps
    both, since then they genuinely behave differently. Keeps the no-slash form
    (or, tie, the higher-confidence one)."""
    def _same(a, b):
        if a.status != b.status:
            return False
        if a.simhash and b.simhash:
            return a.simhash == b.simhash
        return a.length == b.length

    groups: dict[str, list] = defaultdict(list)
    for f in findings:
        key = f.url.rstrip("/")
        groups[key.lower() if ci else key].append(f)
    out: list = []
    for group in groups.values():
        if len(group) > 1 and all(_same(group[0], g) for g in group[1:]):
            # one resource served under both spellings — keep the canonical one
            group = [min(group, key=lambda f: (f.url.endswith("/"), -f.confidence, len(f.url)))]
        out.extend(group)
    return out


def _cluster_near_simhash(findings, distance):
    """Greedy-group findings by same status + body simhash within `distance`
    bits. Not transitive (each member joins the first bucket it's near), which
    is the conservative choice — it won't chain two distinct pages together.
    Small n, so O(n²) is fine.
    """
    buckets: list[list] = []
    for f in findings:
        for b in buckets:
            if b[0].status == f.status and hamming(b[0].simhash, f.simhash) <= distance:
                b.append(f)
                break
        else:
            buckets.append([f])
    return buckets


def _dedupe_and_collapse(findings, observer, ci=False):
    """URL-dedup (keep best confidence) + collapse same-template collisions.

    Groups by (status, body length): a generic page reflected for many paths —
    a server's blanket "403 Forbidden" served for .env/.git/.htaccess/css/build,
    or a catch-all 200 — keeps the SAME length even when the body echoes the
    path (so simhash differs). More than COLLISION_MAX in a group collapse to one
    representative + a count. The real content found by recursion (distinct
    lengths) is untouched.
    """
    deduped = _collapse_slash_twins(_dedup_by_url(findings, ci=ci), ci=ci)

    # Declared-contract findings (OpenAPI/.well-known) are never collapsed — each
    # is a real named endpoint the user wants listed, even when it returns 401/403.
    out: list = [f for f in deduped if f.origin in _DECLARED_ORIGINS]
    non_declared = [f for f in deduped if f.origin not in _DECLARED_ORIGINS]
    collapsed = 0

    # Soft-200 catch-all / WAF-challenge wall: many distinct paths answered by
    # the same 2xx body whose per-request nonce jitters the LENGTH (6733/6734/
    # 6735…). The exact-(status,length) key below would strand each length in
    # its own short group and never fold them, so a nonce-varying wall survives
    # as a flood of look-alike hits. Pre-merge 2xx by body simhash so it folds
    # to one line; a path-echoing catch-all (stable length, distinct simhash)
    # and genuinely distinct files don't merge here and fall through untouched.
    twoxx = [f for f in non_declared if 200 <= f.status < 300 and f.simhash]
    rest = [f for f in non_declared if not (200 <= f.status < 300 and f.simhash)]
    remaining: list = []
    for bucket in _cluster_near_simhash(twoxx, bl.SIMHASH_MISS_DISTANCE):
        if len(bucket) > COLLISION_MAX:
            rep = min(bucket, key=lambda f: len(f.url))
            rep.note = (rep.note + " " if rep.note else "") + \
                f"presentation group: +{len(bucket) - 1} paths with similar body fingerprints " \
                "(soft-200 wall heuristic; body equality not established)"
            out.append(rep)
            collapsed += len(bucket) - 1
        else:
            remaining.extend(bucket)
    remaining.extend(rest)

    clusters: dict[tuple, list] = defaultdict(list)
    for f in remaining:
        clusters[(f.status, f.length)].append(f)

    for (_status, length), group in clusters.items():
        if len(group) > COLLISION_MAX:
            rep = min(group, key=lambda f: len(f.url))
            rep.note = (rep.note + " " if rep.note else "") + \
                f"presentation group: +{len(group) - 1} paths sharing status {_status} / length {length}B; " \
                "body equality and resource existence not established"
            out.append(rep)
            collapsed += len(group) - 1
        else:
            out.extend(group)
    if collapsed:
        observer.log(f"presentation grouped {collapsed} observations by response signatures; "
                     "similarity does not establish body equality or resource existence", 0, style="yellow")
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
    result.report_events_tracked = True
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
    # Suppress an identical trailing-slash twin LIVE: /x and /x/ that returned the
    # same response (status + body fingerprint) are one resource — the report-time
    # _collapse_slash_twins folds them, but the stream would still show both. A twin
    # with a DIFFERENT response (a redirect, a different body) is left to show.
    nkey = url.rstrip("/") or "/"
    nkey = nkey.lower() if ci else nkey
    tsig = (finding.status, finding.simhash if finding.simhash else -finding.length)
    if result.twin_sig.get(nkey) == tsig:
        observer.tick(hit=False)
        observer.request(url, finding.status, False)
        return
    shown = (opts.filters.accept(finding.status, finding.length)
             and opts.filters.accept_body(body, finding.simhash, finding.words, finding.lines))
    observer.tick(hit=shown)
    observer.request(url, finding.status, shown)
    if shown:
        result.seen_urls.add(url)
        result.seen_urls_lc.add(url.lower())
        result.twin_sig[nkey] = tsig          # register so an identical twin is suppressed
        result.findings.append(finding)
        # Immutable-at-emission snapshots are for evidence export only. Discovery
        # keeps consuming the existing findings view; grouping cannot erase these.
        result.reported_observations.append(asdict(finding))
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
        # Soft-200 wall: a 2xx catch-all / WAF challenge / stale-cache page that
        # goes up mid-scan answers MANY distinct paths with the same body — the
        # same flood as a 403 block-wall, but 200 (so _WALL_STATUS misses it) and
        # with a per-request nonce that jitters the length (so the length key
        # misses it). Key on the body simhash instead: distinct REAL 2xx files
        # have distinct bodies → distinct sigs → never muted; only a repeating
        # look-alike page trips it. The per-hit soft-404 sibling check normally
        # catches this, but it's skipped once the request budget is spent — this
        # backstop needs no extra request. Left to the report collapse for the tail.
        softwall = (not wall and 200 <= finding.status < 300
                    and finding.simhash
                    and finding.origin not in _DECLARED_ORIGINS)
        if softwall:
            sig = (finding.status, finding.simhash)
            n = result.softwall_seen.get(sig, 0) + 1
            result.softwall_seen[sig] = n
        if (wall or softwall) and n > COLLISION_MAX:
            if n == COLLISION_MAX + 1:
                kind = "soft-200 wall" if softwall else "block-wall"
                basis = "shared status/body fingerprint" if softwall else "shared status/length"
                observer.log(f"{finding.status} {kind}: repeated {basis} — muting presentation "
                             "(body equality and path existence not established; report events retained)",
                             0, style="yellow")
            observer.finding(finding, stream=False)     # counted, not printed
        else:
            observer.finding(finding)
            observer.log(f"+ {finding.status} {observer.disp(url)} · "
                         f"heuristic score {finding.confidence:.2f} · {finding.origin}", 1, style="green")


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
