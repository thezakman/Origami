"""Scanner leaf helpers — pure functions with no dependency on the fold loop.

Path/URL manipulation, scope reduction, exclusion matching, the budget check and
the fold-isolation guard. Kept apart from the orchestration in `__init__` so they
stay independently readable and testable; re-exported from `origami.core.scanner`.
"""

from __future__ import annotations

import time
from fnmatch import fnmatch
from urllib.parse import urljoin, urlparse

from origami.core.scope import same_site


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


def _host_root(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}/"


def _curl_cmd(url: str, method: str = "GET", headers: dict | None = None) -> str:
    """A copy-paste curl that reproduces a request — the exact method + headers a
    fold used, so a header/method bypass is runnable as-is. `-sk`: quiet + insecure
    (targets under test often have self-signed / legacy TLS)."""
    parts = ["curl", "-sk"]
    if method and method.upper() != "GET":
        parts += ["-X", method.upper()]
    for k, v in (headers or {}).items():
        parts += ["-H", "'" + f"{k}: {v}".replace("'", "'\\''") + "'"]
    parts.append("'" + url.replace("'", "'\\''") + "'")
    return " ".join(parts)


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


def _climb_brute_split(ancestors: list[str], climb_brute: int) -> tuple[list[str], list[str]]:
    """Split climbed ancestors into (brute_dirs, seed_only) by the climb-brute level.

    `ancestors` is deepest-first (immediate parent … root). `climb_brute` levels of
    them (from the deepest) are promoted to full-wordlist prefixes; the rest stay
    single-probe seeds. 0 = none promoted; negative = all promoted (to root).
    """
    if climb_brute < 0:
        n = len(ancestors)
    else:
        n = max(0, min(climb_brute, len(ancestors)))
    return ancestors[:n], ancestors[n:]


def _over_budget(engine, opts) -> bool:
    """True when the run must stop firing — the request cap (--max-requests) or the
    wall-clock deadline (--time-limit) is reached. Checked in every fold's hot loop
    (the deadline lives on the engine, set once at scan start)."""
    if opts.max_requests and engine.spent >= opts.max_requests:
        return True
    dl = getattr(engine, "deadline", None)
    return dl is not None and time.monotonic() >= dl
