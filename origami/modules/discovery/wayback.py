"""Historical URLs — the passive, *past* dimension of discovery.

The other folds read the target's present (live JS, robots, specs). This one asks
public archives what the host looked like *before*: legacy endpoints, forgotten
files, routes pulled from the UI but still wired in the backend — classic pentest
gold that no amount of crawling the current site reveals. The harvested paths are
folded as candidates (origin `wayback`); the scan confirms which still respond.

Sources are hybrid:
  * native (zero-dependency, default for ``--wayback``): the Wayback Machine CDX
    API and the Common Crawl index, fetched over httpx;
  * external (``--gau``): the user's ``gau`` / ``waybackurls`` binary if present
    (inheriting its providers/keys), falling back to native when it isn't.

URLs also carry query strings, so we additionally harvest their parameter NAMES
to enrich the ``--params`` surface. Everything here is best-effort: a slow or
down archive must never break the scan, so harvest() never raises.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse

import httpx

from origami.brain.memory import _is_asset       # canonical static-asset filter
from origami.core.scope import same_site

# A plain, honest UA — archives rate-limit/great-wall anonymous floods.
_UA = "origami-discovery/1.0 (+historical-url harvest)"
_TIMEOUT = 25.0
DEFAULT_CAP = 2000                                # max paths folded from history
_FETCH_ROWS = 10000                               # raw rows pulled before extraction/cap
_GAU_BINARIES = ("gau", "waybackurls")


# ---- pure helpers (offline-testable) ------------------------------------------

def cdx_query_url(host: str, cap: int = _FETCH_ROWS, subs: bool = False) -> str:
    """Wayback CDX endpoint: distinct original URLs for the host (collapsed)."""
    target = f"*.{host}/*" if subs else f"{host}/*"
    return ("https://web.archive.org/cdx/search/cdx"
            f"?url={target}&output=text&fl=original&collapse=urlkey&limit={cap}")


def cc_index_url(index_api: str, host: str, cap: int = _FETCH_ROWS, subs: bool = False) -> str:
    """Common Crawl index query for the host (JSON lines)."""
    target = f"*.{host}/*" if subs else f"{host}/*"
    return f"{index_api}?url={target}&output=json&limit={cap}"


def parse_url_lines(text: str) -> set[str]:
    """One URL per line (Wayback CDX `output=text` and gau/waybackurls stdout)."""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("http://", "https://")):
            out.add(line)
    return out


def parse_cc_json(text: str) -> set[str]:
    """Common Crawl returns JSON object per line; pull the `url` field."""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        u = rec.get("url") if isinstance(rec, dict) else None
        if isinstance(u, str) and u.startswith(("http://", "https://")):
            out.add(u)
    return out


def extract_paths_and_params(urls, host: str, subs: bool = False) -> tuple[set[str], set[str]]:
    """From raw archived URLs → (root-absolute same-host paths, query param names).

    Off-host URLs are dropped (or kept only for registrable-site matches when
    `subs`); query strings are stripped from the path but their parameter NAMES
    are harvested; static assets (images/fonts/media) are filtered out."""
    paths: set[str] = set()
    params: set[str] = set()
    for u in urls:
        try:
            pu = urlparse(u)
        except ValueError:
            continue
        netloc = pu.netloc.lower()
        if netloc != host.lower() and not (subs and same_site(netloc, host)):
            continue
        path = pu.path or "/"
        if not path.startswith("/"):
            continue
        for pair in pu.query.split("&"):
            name = pair.split("=", 1)[0].strip()
            if name:
                params.add(name)
        if path != "/" and not _is_asset(path):
            paths.add(path)
    return paths, params


# ---- async fetchers -----------------------------------------------------------

async def _get(client: httpx.AsyncClient, url: str) -> str:
    r = await client.get(url)
    return r.text if r.status_code == 200 else ""


async def from_cdx(host: str, cap: int = _FETCH_ROWS, subs: bool = False) -> set[str]:
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True,
                                 headers={"User-Agent": _UA}) as c:
        return parse_url_lines(await _get(c, cdx_query_url(host, cap, subs)))


async def from_commoncrawl(host: str, cap: int = _FETCH_ROWS, subs: bool = False) -> set[str]:
    """Best-effort Common Crawl: resolve the latest index, then query it."""
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True,
                                 headers={"User-Agent": _UA}) as c:
        try:
            info = json.loads(await _get(c, "https://index.commoncrawl.org/collinfo.json"))
        except (json.JSONDecodeError, ValueError):
            return set()
        if not (isinstance(info, list) and info and isinstance(info[0], dict)):
            return set()
        api = info[0].get("cdx-api")             # newest index first
        if not api:
            return set()
        return parse_cc_json(await _get(c, cc_index_url(api, host, cap, subs)))


_GAU_TIMEOUT = 25.0


async def _reap(proc) -> None:
    """Kill + reap a subprocess so it doesn't survive the scan (or warn at GC)."""
    if proc.returncode is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        await proc.wait()
    except BaseException:
        pass


async def from_gau(host: str, binaries=_GAU_BINARIES, cap: int = _FETCH_ROWS,
                   subs: bool = False) -> set[str] | None:
    """Shell out to gau/waybackurls if present. None if no binary is available.

    The child is always reaped: on its own timeout, and on cancellation (the
    scanner cancels the background task at 30s) — never left running detached."""
    for binary in binaries:
        args = [binary]
        if binary == "gau":
            args += ["--threads", "5", "--timeout", "20"]
            if subs:
                args += ["--subs"]
        args.append(host)
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        except (FileNotFoundError, OSError):
            continue                             # binary not installed — try the next
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=_GAU_TIMEOUT)
        except asyncio.TimeoutError:
            await _reap(proc)
            return set()
        except BaseException:                    # cancellation / loop teardown
            await _reap(proc)
            raise
        return parse_url_lines(out.decode("utf-8", "replace"))
    return None                                  # no binary found → caller falls back


# ---- driver -------------------------------------------------------------------

async def harvest(host: str, *, use_gau: bool = False, cap: int = DEFAULT_CAP,
                  subs: bool = False) -> tuple[set[str], set[str], str]:
    """Collect historical paths + param names for `host`.

    Returns (paths, params, source_label). Best-effort — never raises; on total
    failure returns (set(), set(), "none"). `paths` is capped at `cap`."""
    urls: set[str] = set()
    source = "none"
    if use_gau:
        gau = await _safe(from_gau(host, cap=_FETCH_ROWS, subs=subs))
        if gau is not None:
            urls = gau
            source = "gau"
    if not urls:                                 # native (default, or gau fallback)
        cdx = await _safe(from_cdx(host, cap=_FETCH_ROWS, subs=subs)) or set()
        cc = await _safe(from_commoncrawl(host, cap=_FETCH_ROWS, subs=subs)) or set()
        urls = cdx | cc
        source = "wayback+cc" if (cdx and cc) else "wayback" if cdx else "commoncrawl" if cc else "none"
    paths, params = extract_paths_and_params(urls, host, subs=subs)
    if len(paths) > cap:
        paths = set(sorted(paths)[:cap])
    return paths, params, source


async def _safe(coro):
    try:
        return await coro
    except Exception:
        return None
