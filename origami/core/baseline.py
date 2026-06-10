"""Baseline / calibration — the heart of Origami (§3.1).

Before any real attack we learn what a *miss* looks like, per context. A
context is (directory prefix, extension class): a 404 for `.aspx` rarely looks
like a 404 for `.php`, and `/admin/<rnd>` can hit a custom error page that
`/<rnd>` doesn't. ffuf's `-ac` and feroxbuster calibrate one global filter;
we keep a profile per context, which is where they leak false positives.

For each context we fire several guaranteed-nonexistent probes with different
shapes (plain random, random+ext, deep path, special chars) and record a
ContextBaseline. Later, a candidate response is a hit iff it falls *outside*
the matching baseline (see `looks_like_miss`).
"""

from __future__ import annotations

import random
import string
from urllib.parse import urljoin, urlparse

from origami.core.evidence import ContextBaseline, TargetProfile
from origami.core.httpclient import Engine, Probe
from origami.core.normalize import hamming

# Same-structure threshold: bodies within this Hamming distance are "the same
# page". 64-bit simhash; ~3 is a conservative, low-false-merge default.
SIMHASH_MISS_DISTANCE = 3

# Extension -> class. The class (not the literal ext) keys the baseline, so
# `.asp` and `.aspx` share calibration where servers treat them alike.
EXT_CLASS = {
    "": "none",
    ".html": "static", ".htm": "static", ".txt": "static",
    ".php": "php", ".php3": "php", ".php5": "php", ".phtml": "php",
    ".asp": "asp", ".aspx": "asp", ".asmx": "asp", ".ashx": "asp", ".ascx": "asp",
    ".jsp": "java", ".do": "java", ".action": "java",
    ".js": "js", ".json": "js",
}


def ext_class(ext: str) -> str:
    return EXT_CLASS.get(ext.lower(), "other")


def _rand(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _probe_paths(prefix: str, ext: str, samples: int) -> list[str]:
    """A spread of guaranteed-nonexistent paths for one context."""
    prefix = prefix if prefix.endswith("/") else prefix + "/"
    paths = []
    for _ in range(samples):
        paths.append(f"{prefix}{_rand()}{ext}")
    # one deep path and one with a special char — catch handlers that branch
    paths.append(f"{prefix}{_rand()}/{_rand()}{ext}")
    paths.append(f"{prefix}{_rand()}%2e{ext}")
    return paths


async def calibrate_context(
    engine: Engine, base_url: str, prefix: str, ext: str, samples: int = 4
) -> ContextBaseline:
    cls = ext_class(ext)
    urls = [urljoin(base_url, p) for p in _probe_paths(prefix, ext, samples)]
    probes = [p for p in await engine.gather(urls) if p.ok]

    cb = ContextBaseline(prefix=prefix, ext_class=cls, status=404)
    if not probes:
        return cb

    statuses = [p.status for p in probes]
    cb.status = max(set(statuses), key=statuses.count)  # modal status of a miss
    cb.simhashes = _dedupe_simhashes([p.body_simhash for p in probes])
    cb.length_lo = min(p.length for p in probes)
    cb.length_hi = max(p.length for p in probes)
    cb.content_type = max(
        set(p.content_type for p in probes), key=[p.content_type for p in probes].count
    )
    cb.samples = len(probes)

    # A "miss" that answers 2xx — or 3xx to a fixed place — is a soft-404.
    if 200 <= cb.status < 300:
        cb.is_soft404 = True
    elif 300 <= cb.status < 400:
        kinds = {_redirect_kind(p.url, p.location) for p in probes if p.location}
        if len(kinds) == 1:
            cb.redirect_to = next(iter(kinds))
            cb.is_soft404 = True
    return cb


def _dedupe_simhashes(hashes: list[int]) -> list[int]:
    """Keep one representative per cluster of near-identical bodies."""
    reps: list[int] = []
    for h in hashes:
        if all(hamming(h, r) > SIMHASH_MISS_DISTANCE for r in reps):
            reps.append(h)
    return reps


def _generalize_location(req_url: str, location: str) -> str:
    """Replace the random token from the request in the redirect target.

    A miss that redirects to `/error?from=<token>` is still a fixed pattern;
    blanking the token lets two misses compare equal.
    """
    tail = urlparse(req_url).path.rsplit("/", 1)[-1]
    token = tail.split(".")[0]
    return location.replace(token, "*") if token else location


def _redirect_kind(req_url: str, location: str) -> str:
    """Classify a redirect so misses across different paths compare equal.

      "SELF"  — redirect to the same path (http→https, www, trailing slash);
                every path self-redirects, so this is a global wall.
      "->X"   — redirect to a constant target (e.g. /action/login auth wall),
                token-blanked so the random probe path doesn't leak in.

    This is what makes a scheme-upgrade or login wall read as a single soft-404
    pattern instead of "every path is a unique hit".
    """
    if not location:
        return ""
    loc = urljoin(req_url, location)
    rp = urlparse(req_url).path.rstrip("/")
    lp = urlparse(loc).path.rstrip("/")
    if lp == rp:
        return "SELF"
    return "->" + _generalize_location(req_url, loc)


async def calibrate(
    engine: Engine, profile: TargetProfile, contexts: list[tuple[str, str]]
) -> None:
    """Populate `profile.baseline` for each (prefix, ext) and flag wildcard.

    Idempotent per context key — re-calling for already-calibrated contexts is
    cheap to guard against, so callers can lazily calibrate new extension
    classes after fingerprinting adds them.
    """
    for prefix, ext in contexts:
        key = TargetProfile.context_key(prefix, ext_class(ext))
        if key in profile.baseline:
            continue
        cb = await calibrate_context(engine, profile.base_url, prefix, ext)
        profile.baseline[key] = cb
        # Root soft-404 == wildcard/catch-all routing.
        if prefix in ("/", "") and cb.is_soft404:
            profile.wildcard = True


async def probe_case_sensitivity(
    engine: Engine, profile: TargetProfile, known_hit_path: str
) -> None:
    """Determine path case-sensitivity using a path known to be a hit.

    Case-insensitive paths are a strong Windows/IIS signal. We can only judge
    this against a path we *know* exists, so the scanner calls this opportun-
    istically once it has its first confirmed hit.
    """
    if profile.case_sensitive is not None or not known_hit_path:
        return
    swapped = "".join(c.upper() if c.islower() else c.lower() for c in known_hit_path)
    if swapped == known_hit_path:
        return
    a, b = await engine.gather(
        [urljoin(profile.base_url, known_hit_path), urljoin(profile.base_url, swapped)]
    )
    if a.ok and b.ok:
        same = a.status == b.status and hamming(a.body_simhash, b.body_simhash) <= SIMHASH_MISS_DISTANCE
        profile.case_sensitive = not same


def looks_like_miss(probe: Probe, cb: ContextBaseline) -> bool:
    """True if `probe` matches the miss profile for its context."""
    if not probe.ok:
        return True
    if probe.status != cb.status:
        return False
    if 300 <= probe.status < 400:
        if _redirect_kind(probe.url, probe.location) == cb.redirect_to:
            return True
    # same status family: compare body structure against known miss bodies
    if cb.simhashes and any(
        hamming(probe.body_simhash, h) <= SIMHASH_MISS_DISTANCE for h in cb.simhashes
    ):
        return True
    # dynamically-learned soft signatures (multi-modal soft-404 hosts)
    for st, sh in cb.soft_signatures:
        if probe.status == st and hamming(probe.body_simhash, sh) <= SIMHASH_MISS_DISTANCE:
            return True
    # no structural match, but if length is inside the miss band it's ambiguous
    return False
