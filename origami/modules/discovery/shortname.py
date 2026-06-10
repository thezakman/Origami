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
from urllib.parse import urljoin

# 3-char truncated extension -> real extension family (lookup, not guesswork).
EXT_FAMILY = {
    "ASP": [".asp", ".aspx"], "ASA": [".asa", ".asax"], "ASM": [".asmx"],
    "ASH": [".ashx"], "ASC": [".ascx"], "CON": [".config"], "CS": [".cs", ".cshtml"],
    "HTM": [".htm", ".html"], "PHP": [".php", ".php3", ".php5"], "JS": [".js"],
    "JSO": [".json"], "TXT": [".txt"], "XML": [".xml"], "DLL": [".dll"],
    "BAK": [".bak"], "ZIP": [".zip"], "RAR": [".rar"], "MDB": [".mdb"],
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
        out, err = await proc.communicate()
    except OSError as e:
        return ShortscanResult(available=True, error=f"spawn failed: {e}")

    return parse_ndjson(out.decode("utf-8", "replace"), fallback_url=url,
                        stderr=err.decode("utf-8", "replace"))


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
            res.entries.append(ShortEntry(
                baseurl=obj.get("baseurl") or obj.get("url") or fallback_url,
                tilde=obj.get("shorttilde", ""),
                prefix=obj.get("shortfile", ""),
                ext=obj.get("shortext", ""),
                fullname=obj.get("fullname", ""),
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
           exts: tuple[str, ...] = ()) -> list[tuple[str, str]]:
    """Turn 8.3 entries into concrete (baseurl, path) candidates.

    For each leaked short name we try, in priority order:
      1. shortscan's autocomplete `fullname` (if any);
      2. the raw 8.3 name itself — `APF785~1[.ext]` — directly requestable on IIS;
      3. the 6-char prefix as a file (with the leaked ext family, or all enabled
         tech extensions when no ext leaked) AND as a directory — the prefix is
         very often the real start/whole name (e.g. APIINT~1 → /apiint, /apiint/);
      4. the wordlist constrained to entries starting with the prefix.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(baseurl: str, path: str) -> None:
        key = (baseurl, path)
        if path and key not in seen:
            seen.add(key)
            out.append((baseurl, path))

    tech_exts = list(exts)
    for e in entries:
        prefix = e.prefix.lower()
        # leaked ext family, or — when no ext leaked — every enabled tech ext + none
        fams = ext_family(e.ext) if e.ext else (tech_exts + [""])

        if e.fullname:
            add(e.baseurl, e.fullname)
        # raw 8.3 short name (shortfile + tilde [+ ext])
        if e.prefix and e.tilde:
            raw = f"{e.prefix}{e.tilde}"
            add(e.baseurl, f"{raw}.{e.ext}" if e.ext else raw)
        if prefix:
            for ext in fams:                 # prefix as file
                add(e.baseurl, prefix + ext)
            add(e.baseurl, prefix + "/")      # prefix as directory
            for w in words:                   # constraint-filtered wordlist
                if w.lower().startswith(prefix):
                    for ext in fams:
                        add(e.baseurl, w + ext)
    return out
