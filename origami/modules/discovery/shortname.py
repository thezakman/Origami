"""Shortscan fold — IIS 8.3 short-name enumeration (§4).

The best fold for IIS: the tilde leak collapses the search space from
impossible to tractable. We don't reimplement it — we drive the user's
`shortscan` binary (v0.11+, ndjson output), gate on its own vulnerability
check, then turn each `PREFIX~N.EXT` into concrete candidates:

  * Regime 1 (deterministic): constraint-filter the wordlist — only words
    that start with the (≤6 char) short prefix, paired with the extension
    family the 3-char truncation maps to. 100k words collapse to a handful.
  * autocomplete seeds: shortscan often reconstructs the full name itself
    (`fullname`); those go straight in as highest-value candidates.

Confirmed expansions are labelled data `(truncated -> real name)` — the seed
of the cross-target n-gram learner in a later phase.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from dataclasses import dataclass, field

# 3-char truncated extension -> real extension family (lookup, not guesswork).
EXT_FAMILY = {
    "ASP": [".asp", ".aspx"], "ASA": [".asa", ".asax"], "ASM": [".asmx"],
    "ASH": [".ashx"], "ASC": [".ascx"], "CON": [".config"], "CS": [".cs", ".cshtml"],
    "CSH": [".cshtml"], "VB": [".vb"], "MAS": [".master"], "SVC": [".svc"],
    "AXD": [".axd"], "RES": [".resx", ".res"], "SOA": [".soap"], "REM": [".rem"],
    "HTM": [".htm", ".html"], "PHP": [".php", ".php3", ".php5"], "JS": [".js"],
    "MAP": [".map"], "JSO": [".json"], "TXT": [".txt"], "XML": [".xml"], "DLL": [".dll"],
    "BAK": [".bak"], "ZIP": [".zip"], "RAR": [".rar"], "MDB": [".mdb", ".mdf"],
    "XLS": [".xls", ".xlsx"], "DOC": [".doc", ".docx"], "PDF": [".pdf"],
    "INC": [".inc"], "OLD": [".old"], "SQL": [".sql"], "CSV": [".csv"],
}


def shortscan_path() -> str | None:
    """Locate the shortscan binary (~/go/bin first, then PATH)."""
    p = os.path.expanduser("~/go/bin/shortscan")
    if os.path.exists(p):
        return p
    return shutil.which("shortscan")


@dataclass(slots=True)
class ShortEntry:
    baseurl: str
    tilde: str          # "ADMIN~1"
    prefix: str         # "ADMIN"  (up to 6 chars, case-insensitive)
    ext: str            # "ASP"    (3-char truncated, may be "")
    fullname: str = ""  # shortscan's autocompleted full name, if any
    fullmatch: bool = False


@dataclass
class ShortscanResult:
    available: bool
    vulnerable: bool = False
    server: str = ""
    entries: list[ShortEntry] = field(default_factory=list)
    error: str = ""


async def run_shortscan(url: str, *, insecure: bool = True, user_agent: str | None = None,
                        concurrency: int = 20, timeout: int = 10,
                        extra_args: list[str] | None = None) -> ShortscanResult:
    """Run shortscan as a subprocess and parse its ndjson output."""
    binp = shortscan_path()
    if not binp:
        return ShortscanResult(available=False, error="shortscan binary not found")

    args = [binp, "--output", "ndjson", "--quiet",
            "-c", str(concurrency), "-t", str(int(timeout))]
    if insecure:
        args.append("-k")
    if user_agent:
        args += ["-A", user_agent]
    if extra_args:
        args += extra_args
    args.append(url)

    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except OSError as e:
        return ShortscanResult(available=True, error=f"spawn failed: {e}")
    # Bound the wait: a hung shortscan child must not stall the scan forever, and
    # must always be reaped (killed + awaited) — never left running detached.
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=_SHORTSCAN_TIMEOUT)
    except asyncio.TimeoutError:
        await _reap(proc)
        return ShortscanResult(available=True, error=f"timed out after {_SHORTSCAN_TIMEOUT:.0f}s")
    except BaseException:                         # cancellation / loop teardown
        await _reap(proc)
        raise

    return parse_ndjson(out.decode("utf-8", "replace"), fallback_url=url,
                        stderr=err.decode("utf-8", "replace"))


_SHORTSCAN_TIMEOUT = 300.0   # overall cap on the shortscan child (it self-limits per-request via -t)


async def _reap(proc) -> None:
    """Kill + reap a subprocess so a hung/cancelled shortscan leaves no zombie."""
    if proc.returncode is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        await proc.wait()
    except BaseException:
        pass


def parse_ndjson(text: str, fallback_url: str = "", stderr: str = "") -> ShortscanResult:
    res = ShortscanResult(available=True)
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") == "status" and "vulnerable" in obj:
            # shortscan emits one status line per recursed directory; the target
            # is vulnerable if ANY of them is (the deepest dir is often "No").
            res.vulnerable = res.vulnerable or bool(obj["vulnerable"])
            res.server = res.server or obj.get("server", "")
        elif "shorttilde" in obj or "shortfile" in obj:
            # Coerce every field to str: shortscan output is untrusted, and a
            # non-string value (null/number/list) would later crash .lower()/.upper()
            # and forfeit the WHOLE fold over one malformed line.
            def _s(v):
                return v if isinstance(v, str) else ""
            res.entries.append(ShortEntry(
                baseurl=_s(obj.get("baseurl")) or _s(obj.get("url")) or fallback_url,
                tilde=_s(obj.get("shorttilde")),
                prefix=_s(obj.get("shortfile")),
                ext=_s(obj.get("shortext")),
                fullname=_s(obj.get("fullname")),
                fullmatch=bool(obj.get("fullmatch", False)),
            ))
    if not res.entries and not res.vulnerable and stderr.strip():
        res.error = stderr.strip()[:200]
    return res


def ext_family(shortext: str) -> list[str]:
    if not shortext:
        return [""]
    return EXT_FAMILY.get(shortext.upper(), ["." + shortext.lower()])


def expand(entries: list[ShortEntry], words: list[str],
           exts: tuple[str, ...] = (), case_insensitive: bool = False) -> list[tuple[str, str]]:
    """Turn 8.3 entries into concrete (baseurl, path) candidates.

    On a case-insensitive host (`case_insensitive=True` — always the case for the
    IIS/Windows targets 8.3 enumeration applies to) candidates that differ only in
    case (WEBSERVICES / webservices / WebServices — one from the resolved fullname,
    one from the lowercased prefix, one from a wordlist match) collapse to the
    first, highest-confidence form, so the WAF-throttled budget isn't spent thrice
    on one resource.

    Candidates are emitted in **global confidence tiers** (across ALL entries),
    not per-entry — so that on a throttled target (a WAF cutting the run short,
    economy mode), the names shortscan already *resolved* fire before any
    speculative wordlist guess. Per-entry ordering used to bury a late entry's
    resolved fullname (e.g. DEFAULT.ASPX, the last leak) behind hundreds of
    earlier entries' wordlist expansions, so it never got requested under load.

    Tiers, highest first:
      1. shortscan's autocomplete `fullname` — a name it already reconstructed;
      2. the raw 8.3 name itself — `APF785~1[.ext]` — directly requestable on IIS;
      3. the 6-char prefix as a file (leaked ext family, else enabled tech exts)
         AND as a directory — the prefix is very often the real start/whole name
         (e.g. APIINT~1 → /apiint, /apiint/);
      4. the wordlist constrained to entries starting with the prefix (speculative).
    """
    seen: set[tuple[str, str]] = set()
    tiers: list[list[tuple[str, str]]] = [[], [], [], []]

    def add(tier: int, baseurl: str, path: str) -> None:
        key = (baseurl, path.lower() if case_insensitive else path)
        if path and key not in seen:
            seen.add(key)
            tiers[tier].append((baseurl, path))

    tech_exts = list(exts)
    for e in entries:
        prefix = e.prefix.lower()
        # leaked ext family, or — when no ext leaked — every enabled tech ext + none
        fams = ext_family(e.ext) if e.ext else (tech_exts + [""])

        if e.fullname:
            add(0, e.baseurl, e.fullname)
        # raw 8.3 short name — `tilde` IS the complete 8.3 name (e.g. "WEBREF~1");
        # it already embeds the prefix, so request it as-is (+ leaked ext). Joining
        # prefix+tilde used to double it ("WEBREFWEBREF~1") → a guaranteed 404.
        if e.tilde:
            add(1, e.baseurl, f"{e.tilde}.{e.ext}" if e.ext else e.tilde)
        if prefix:
            for ext in fams:                 # prefix as file
                add(2, e.baseurl, prefix + ext)
            add(2, e.baseurl, prefix + "/")   # prefix as directory
            for w in words:                   # constraint-filtered wordlist
                if w.lower().startswith(prefix):
                    for ext in fams:
                        add(3, e.baseurl, w + ext)
    return [c for tier in tiers for c in tier]
