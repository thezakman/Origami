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
# Per-source HTTP timeout. Kept comfortably UNDER the scanner's total history budget
# (WAYBACK_BUDGET, 12s) so the concurrent gather() always returns with whatever
# sources answered before the scan cuts it off — a single hung source (e.g. a slow
# Common Crawl index) times out here and the fast sources' results are still kept,
# instead of the whole harvest being cancelled and everything lost.
_TIMEOUT = 8.0
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


def urlscan_query_url(host: str) -> str:
    """urlscan.io search — URLs seen on the host (keyless, rate-limited)."""
    return f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=1000"


def parse_urlscan(text: str) -> set[str]:
    """urlscan.io search JSON → the page/task URLs of each result."""
    out: set[str] = set()
    try:
        d = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return out
    for r in (d.get("results") or []) if isinstance(d, dict) else []:
        if not isinstance(r, dict):
            continue
        for key in ("page", "task"):
            sub = r.get(key)
            u = sub.get("url") if isinstance(sub, dict) else None
            if isinstance(u, str) and u.startswith(("http://", "https://")):
                out.add(u)
    return out


def otx_query_url(host: str) -> str:
    """AlienVault OTX passive URL list for the hostname (keyless)."""
    return (f"https://otx.alienvault.com/api/v1/indicators/hostname/{host}"
            "/url_list?limit=500&page=1")


def parse_otx(text: str) -> set[str]:
    """OTX `url_list` JSON → the archived URLs."""
    out: set[str] = set()
    try:
        d = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return out
    for r in (d.get("url_list") or []) if isinstance(d, dict) else []:
        u = r.get("url") if isinstance(r, dict) else None
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


async def from_urlscan(host: str, cap: int = _FETCH_ROWS, subs: bool = False) -> set[str]:
    """urlscan.io — keyless search for URLs seen on the host."""
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True,
                                 headers={"User-Agent": _UA}) as c:
        return parse_urlscan(await _get(c, urlscan_query_url(host)))


async def from_otx(host: str, cap: int = _FETCH_ROWS, subs: bool = False) -> set[str]:
    """AlienVault OTX — keyless passive URL list for the hostname."""
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True,
                                 headers={"User-Agent": _UA}) as c:
        return parse_otx(await _get(c, otx_query_url(host)))


_GAU_TIMEOUT = 10.0                               # subprocess wait — just above gau's own --timeout


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
    scanner cuts the background task at its history budget) — never left detached."""
    for binary in binaries:
        args = [binary]
        if binary == "gau":
            # --timeout kept under the scanner's history budget so gau returns
            # whatever the providers gave instead of being cut off with nothing.
            args += ["--threads", "5", "--timeout", "8"]
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
            return None                          # gau hung → treat as unavailable, try native

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
    gau_ran = False
    if use_gau:
        gau = await _safe(from_gau(host, cap=_FETCH_ROWS, subs=subs))
        if gau is not None:                      # None == binary absent → native fallback
            urls = gau
            source = "gau"
            gau_ran = True                        # gau covers the SAME providers → don't re-query
    if not urls and not gau_ran:                 # native only when no gau binary was found
        # all four passive sources concurrently — a slow/down one can't hold up the rest
        cdx, cc, us, otx = await asyncio.gather(
            _safe(from_cdx(host, cap=_FETCH_ROWS, subs=subs)),
            _safe(from_commoncrawl(host, cap=_FETCH_ROWS, subs=subs)),
            _safe(from_urlscan(host, cap=_FETCH_ROWS, subs=subs)),
            _safe(from_otx(host, cap=_FETCH_ROWS, subs=subs)))
        cdx, cc, us, otx = cdx or set(), cc or set(), us or set(), otx or set()
        urls = cdx | cc | us | otx
        parts = [n for n, s in (("wayback", cdx), ("cc", cc),
                                ("urlscan", us), ("otx", otx)) if s]
        source = "+".join(parts) or "none"
    paths, params = extract_paths_and_params(urls, host, subs=subs)
    if len(paths) > cap:
        paths = set(sorted(paths)[:cap])
    return paths, params, source


async def _safe(coro):
    try:
        return await coro
    except Exception:
        return None
