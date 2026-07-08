"""Origami CLI — `origami <url>`.

Runs the full MVP pipeline: calibrate → fingerprint → fold → adaptive scan →
classify → recurse, with a live `rich` UI, then prints a persistent report
(and optional JSON).
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from origami import __version__, banner
from origami.brain.memory import DEFAULT_DB, Memory
from origami.control import keyboard_control
from origami.core import resume as resume_mod
from origami.core.httpclient import _UA_POOL, Engine, EngineConfig
from origami.core.response_classifier import Filters
from origami.core.scanner import ScanControl, ScanOptions, resume_scan, scan
from origami.core.scheduler import resolve_wordlist
from origami.output import artifacts, graph, html_report, json_report, ui


def _int_set(s: str | None) -> set[int] | None:
    if not s:
        return None
    try:
        return {int(x) for x in s.replace(" ", "").split(",") if x}
    except ValueError:
        raise SystemExit(f"[!] expected a comma list of integers, got: {s!r}")


def _ext_list(items) -> list[str]:
    """`-X php,asp -X bak` (comma and/or repeated) → ['.php', '.asp', '.bak'],
    normalized: stripped, leading-dot, lowercased, de-duplicated, order kept."""
    out: list[str] = []
    for raw in items or []:
        for part in raw.split(","):
            e = part.strip().lstrip(".").lower()
            if e:
                dotted = "." + e
                if dotted not in out:
                    out.append(dotted)
    return out


def _ext_globs(items) -> list[str]:
    """`--exclude-ext jpg,png -X jpg*` → ['jpg','png','jpg*']: stripped, dot-less,
    lowercased, glob preserved, de-duplicated."""
    out: list[str] = []
    for raw in items or []:
        for part in raw.split(","):
            e = part.strip().lstrip(".").lower()
            if e and e not in out:
                out.append(e)
    return out


def _parse_headers(items) -> dict[str, str]:
    """`-H "Name: Value"` (repeatable) → header dict. Used for authenticated
    scans (Cookie:, Authorization:, custom headers)."""
    out: dict[str, str] = {}
    for raw in items or []:
        if ":" not in raw:
            raise SystemExit(f"[!] bad header (need 'Name: Value'): {raw!r}")
        name, _, value = raw.partition(":")
        name = name.strip()
        if not name:
            raise SystemExit(f"[!] bad header (empty name): {raw!r}")
        out[name] = value.strip()
    return out


def _build_filters(args) -> Filters:
    f = Filters()
    f.match_codes = _int_set(args.mc)
    if args.fc is not None:                       # explicit --fc overrides the default
        f.filter_codes = _int_set(args.fc) or set()
    f.match_sizes = _int_set(args.ms)
    f.filter_sizes = _int_set(args.fs)
    f.filter_words = _int_set(args.filter_word_count) or set()
    f.filter_lines = _int_set(args.filter_line_count) or set()
    if args.filter_regex:
        try:
            f.filter_regex = re.compile(args.filter_regex)
        except re.error as e:
            raise SystemExit(f"[!] bad --filter-regex: {e}")
    # similar_hashes are resolved in the scanner (needs a live fetch); the URLs
    # travel via ScanOptions.filter_similar_urls.
    return f


def _parse_duration(s: str | None) -> float:
    """'30s' / '10m' / '1h' / bare seconds → seconds. 0.0 when unset."""
    if not s:
        return 0.0
    s = s.strip().lower()
    mult = {"s": 1, "m": 60, "h": 3600}.get(s[-1:])
    try:
        return float(s[:-1]) * mult if mult else float(s)
    except ValueError:
        raise SystemExit(f"[!] bad --time-limit (use 30s/10m/1h or seconds): {s!r}")


def _normalize_url(raw: str) -> str:
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    if not p.netloc:
        raise SystemExit(f"[!] invalid URL: {raw!r}")
    base = f"{p.scheme}://{p.netloc}"
    return base + (p.path if p.path and p.path != "/" else "/")


def _read_url_lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def _collect_targets(args) -> list[str]:
    raw = list(args.url or [])
    # stdin targets were read once during validation (bare pipe or `-l -`).
    raw += list(getattr(args, "_stdin_targets", None) or [])
    if args.list and args.list != "-":
        raw += _read_url_lines(Path(args.list).read_text())
    seen, out = set(), []
    for r in raw:
        u = _normalize_url(r)
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _slug(url: str) -> str:
    p = urlparse(url)
    return re.sub(r"[^\w.-]", "_", (p.netloc + p.path).strip("/")) or "root"


def _suffix(path: str, slug: str) -> str:
    p = Path(path)
    return str(p.with_name(f"{p.stem}.{slug}{p.suffix}"))


def _write_outputs(args, result, target, multi: bool) -> None:
    # The scan already ran — a write failure (unwritable dir, --out pointing at an
    # existing file, full disk) must not crash with a traceback or, in multi-target
    # mode, abort the remaining targets. Report it cleanly and move on.
    try:
        if args.json:
            path = _suffix(args.json, _slug(target)) if multi else args.json
            Path(path).write_text(json_report.dumps(result))
            print(f"[+] JSON written to {path}")
        if args.html:
            path = _suffix(args.html, _slug(target)) if multi else args.html
            html_report.write(result, path)
            print(f"[+] HTML report written to {path}")
        if args.out:
            d = str(Path(args.out) / _slug(target)) if multi else args.out
            info = artifacts.write_artifacts(result, d)
            print(f"[+] artifacts written to {info['dir']}/ "
                  f"(report.html, graph.html [{info['hidden']} hidden], findings.json, "
                  f"params.txt={info['params']}, urls.txt={info['urls']})")
        if args.graph:
            path = _suffix(args.graph, _slug(target)) if multi else args.graph
            hp, dp, n_hidden = graph.write(result, path)
            print(f"[+] endpoint graph written to {hp} (+ {Path(dp).name}) · "
                  f"{n_hidden} hidden endpoints")
    except OSError as e:
        print(f"[!] could not write output for {target}: {e}", file=sys.stderr)


async def run(args: argparse.Namespace) -> int:
    targets = _collect_targets(args)
    if not targets:
        print("[!] no targets (give a URL or --list FILE)")
        return 2

    shortscan = "on" if args.shortscan else "off" if args.no_shortscan else "auto"
    # -w is repeatable (merged, deduped). Under --deep the base list is always
    # included, so `--deep -w custom` runs base + custom (bare --deep = base).
    wordlists = list(args.wordlist or [])
    if args.deep:
        wordlists = ["base"] + wordlists
    opts = ScanOptions(
        max_depth=args.depth, max_requests=args.max_requests,
        wordlist_paths=wordlists, shortscan=shortscan,
        js=not args.no_js, apidocs=not args.no_apidocs, backups=not args.no_backups,
        max_folds=args.max_folds, scope=args.scope, economy=args.economy,
        exclude=args.exclude or [], exclude_ext=_ext_globs(args.exclude_ext),
        extensions=_ext_list(args.ext),
        ext_only=args.ext_only, graph=bool(args.graph or args.out),  # --out bundle includes the graph
        bypass403=(args.bypass_403 is not None) or (args.bypass_headers is not None)
                  or (args.bypass_prefixes is not None) or args.deep,
        bypass_intensity=args.bypass_403 or "auto",   # bare flag / --bypass-headers / --deep → auto
        bypass_headers=args.bypass_headers is not None,
        bypass_headers_path=args.bypass_headers if isinstance(args.bypass_headers, str) else None,
        bypass_prefixes_path=args.bypass_prefixes,
        openapi_source=args.openapi, vhost=args.vhost, param_fuzz=args.params or args.deep,
        wayback=args.wayback or args.gau or args.deep, gau=args.gau,
        cache_poison=(args.cache_poison or ("auto" if (args.cache_headers or args.deep) else "")),
        cache_headers=args.cache_headers,
        probe_405=args.probe_405 or args.deep, buckets=args.buckets or args.deep,
        filters=_build_filters(args),
        time_limit=_parse_duration(args.time_limit),
        replay_proxy=args.replay_proxy,
        replay_codes=tuple(_int_set(args.replay_codes) or ()),
        filter_similar_urls=tuple(args.filter_similar_to or ()),
    )

    # JSONL streaming: one record per confirmed finding, written live. `-` streams
    # to stdout for piping (origami url --jsonl - | nuclei …), which forces --no-ui
    # and silences the human preamble/report so stdout stays pure JSON Lines.
    jsonl_fh = None
    jsonl_stdout = bool(args.jsonl) and args.jsonl == "-"
    _status_out = sys.stderr if jsonl_stdout else sys.stdout   # keep stdout pure JSONL in pipe mode
    if args.jsonl:
        import json as _json
        from origami.output.json_report import finding_record
        if jsonl_stdout:
            jsonl_fh = sys.stdout
            args.no_ui = True
        else:
            jsonl_fh = open(args.jsonl, "w", encoding="utf-8")
        def _emit_jsonl(f):
            jsonl_fh.write(_json.dumps(finding_record(f), ensure_ascii=False) + "\n")
            jsonl_fh.flush()
        opts.finding_sink = _emit_jsonl

    memory = None if args.no_learn else Memory(args.db)
    control = ScanControl()

    # Human preamble — suppressed when streaming JSONL to stdout (keep it pure).
    if not jsonl_stdout:
        filt = opts.filters
        fdesc = (f"match {sorted(filt.match_codes)}" if filt.match_codes
                 else f"drop {sorted(filt.filter_codes)}" if filt.filter_codes else "none")
        print(f"  targets  : {len(targets)}" + (f"  (list: {args.list})" if args.list else ""))
        print(f"  started  : {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  wordlist : {' + '.join(wordlists) or 'builtin base.txt'}")
        exts = _ext_list(args.ext)
        if exts:
            print(f"  extensions: {', '.join(e.lstrip('.') for e in exts)}"
                  + (" (only)" if args.ext_only else " (+ auto)"))
        print(f"  filters  : codes {fdesc}")
        if args.deep:
            print(f"  deep     : bypass-403 + cache-poison + probe-405 + buckets + params + wayback")
        if args.header:
            print(f"  headers  : {len(args.header)} custom ({', '.join(h.split(':',1)[0].strip() for h in args.header)})")
        if args.user_agent:
            print(f"  user-agent: {args.user_agent}"
                  + ("  (--rotate-ua ignored: -A pins it)" if args.rotate_ua else ""))
        elif args.rotate_ua:
            print(f"  user-agent: rotating per request (pool of {len(_UA_POOL)} browsers)")
        if args.proxy:
            print(f"  proxy    : {args.proxy} (TLS verification off)")
        if args.replay_proxy:
            codes = f" (codes {args.replay_codes})" if args.replay_codes else ""
            print(f"  replay   : {args.replay_proxy}{codes} — confirmed findings only")
        if args.time_limit:
            print(f"  time-limit: {args.time_limit}")
        _bf = [n for n, v in (("word", args.filter_word_count), ("line", args.filter_line_count),
                              ("regex", args.filter_regex),
                              ("similar", args.filter_similar_to)) if v]
        if _bf:
            print(f"  filters+ : {', '.join(_bf)}")
        if args.exclude:
            print(f"  exclude  : {', '.join(args.exclude)}")
        if args.exclude_ext:
            print(f"  excl-ext : {', '.join(_ext_globs(args.exclude_ext))}")
        if args.graph:
            print(f"  graph    : {args.graph} (endpoint provenance + orphans)")
        if args.openapi:
            print(f"  openapi  : {args.openapi} (folded as seeds)")
        if args.bypass_headers is not None:
            src = args.bypass_headers if isinstance(args.bypass_headers, str) else "bundled 403-headers.txt"
            print(f"  bypass-hdr: {src}")
        if args.bypass_prefixes:
            print(f"  bypass-pfx: {args.bypass_prefixes} (api-prefix + matrix carriers)")
        if args.params:
            print(f"  params   : reflection fuzzing on dynamic endpoints")
        if args.cache_poison or args.cache_headers:
            lvl = args.cache_poison or "auto"
            extra = f" + {args.cache_headers}" if args.cache_headers else ""
            print(f"  cache    : poisoning probe ({lvl}{extra}) — throwaway cache-buster, never the real key")
        if args.probe_405:
            print(f"  methods  : 405 → POST/PATCH (empty & {{}} body) — state-changing, never PUT/DELETE")
        if args.wayback or args.gau:
            print(f"  history  : {'gau/waybackurls (native fallback)' if args.gau else 'Wayback CDX + Common Crawl'}")
        if args.rate:
            print(f"  rate     : {args.rate:g} req/s cap (aggregate)")
        if args.delay:
            print(f"  delay    : {args.delay}s per request (stealth)")
        if args.jsonl:
            print(f"  jsonl    : {args.jsonl}")
        if sys.stdin.isatty() and not args.no_ui:
            print("  controls : [q] quit   ([n] skip directory — once one is discovered)\n")

    # Proxy rotation: load the list once (one URL per line, # comments allowed).
    proxy_list: list[str] = []
    if args.proxy_file:
        try:
            for ln in Path(args.proxy_file).read_text().splitlines():
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    proxy_list.append(ln)
        except OSError as e:
            raise SystemExit(f"[!] --proxy-file unreadable: {e}")
        if not proxy_list:
            raise SystemExit(f"[!] --proxy-file {args.proxy_file} has no proxies")
        if not jsonl_stdout:
            print(f"  proxies  : rotating across {len(proxy_list)} (from {args.proxy_file})",
                  file=_status_out)

    # HTTP/2 needs the optional `h2` package; check once, warn + fall back if absent.
    use_http2 = False
    if args.http2:
        import importlib.util
        use_http2 = importlib.util.find_spec("h2") is not None
        if not jsonl_stdout:
            print(f"  http2    : {'on (ALPN)' if use_http2 else 'unavailable — pip install h2; using HTTP/1.1'}",
                  file=_status_out)

    rc = 0
    try:
        async with keyboard_control(control):
            for i, target in enumerate(targets, 1):
                if control.quit:
                    print("[!] quit — skipping remaining targets", file=_status_out)
                    break
                if len(targets) > 1:
                    print(f"\n━━━ [{i}/{len(targets)}] {target} ━━━", file=_status_out)
                # Fresh Engine + Observer + TargetProfile per URL → each target
                # is scanned clean (no learned vocab/extensions/baseline bleed
                # from the previous one). Cross-target SQLite memory is shared by
                # design (use --no-learn to isolate fully).
                observer = ui.make_observer(target, enabled=not args.no_ui,
                                            verbosity=args.verbose, full_url=args.full_url,
                                            log_stream=sys.stderr if jsonl_stdout else None)
                cfg = EngineConfig(concurrency=args.concurrency, timeout=args.timeout,
                                   delay=args.delay, rate=args.rate,
                                   verify_tls=not (args.insecure or args.proxy or proxy_list
                                                   or args.replay_proxy),
                                   proxy=args.proxy or "", proxies=proxy_list,
                                   headers=_parse_headers(args.header),
                                   user_agent=args.user_agent or EngineConfig.user_agent,
                                   rotate_ua=args.rotate_ua and not args.user_agent,
                                   http2=use_http2)
                rpath = resume_mod.path_for(target)
                saved = resume_mod.load(rpath) if args.resume else None
                if args.resume and saved is None:
                    print(f"[!] no checkpoint for {target} — scanning fresh", file=_status_out)
                async with Engine(cfg) as engine:
                    engine.on_request = observer.on_request   # live heartbeat, every phase
                    observer.attach_engine(engine)            # live adaptive-throttle readout
                    with observer:
                        if saved is not None:
                            result = await resume_scan(engine, saved, opts, observer,
                                                       memory, control, rpath)
                        else:
                            result = await scan(engine, target, opts, observer, memory,
                                                control, rpath)
                if result.completed:
                    resume_mod.clear(rpath)   # finished cleanly → drop the checkpoint

                if (result.requests_made <= 1 and not result.profile.tech_scores
                        and not result.findings):
                    print(f"[!] {target} unreachable", file=_status_out)
                    rc = 2
                    continue
                if not jsonl_stdout:           # keep stdout pure JSONL in pipe mode
                    streamed = getattr(observer, "streamed", False)
                    ui.print_report(result, full_url=args.full_url, show_findings=not streamed,
                                    show_fingerprint=(not streamed) or args.fp)
                _write_outputs(args, result, target, multi=len(targets) > 1)
    finally:
        if memory is not None:
            memory.close()
        if jsonl_fh is not None and jsonl_fh is not sys.stdout:
            jsonl_fh.close()
    return rc


def _forget(args) -> int:
    mem = Memory(args.db)
    target = args.forget
    if target.lower() == "all":
        n = mem.forget(None)
        print(f"[+] memory wiped — removed {n} corpus paths (all hosts)")
    else:
        host = urlparse(target).netloc or target
        n = mem.forget(host)
        print(f"[+] forgot {host} — removed {n} corpus paths")
    mem.close()
    return 0


def _forget_noise(args) -> int:
    mem = Memory(args.db)
    n = mem.prune_fingerprinted()
    print(f"[+] pruned {n} content-hashed/fingerprinted entries from memory")
    mem.close()
    return 0


def _show_history(args) -> int:
    first = args.url[0] if args.url else None
    host = (urlparse(first).netloc or first) if first else None
    mem = Memory(args.db)
    rows = mem.history(host=host)
    if not rows:
        print("no scan history yet")
    else:
        print(f"{'when':<20} {'host':<28} {'reqs':>6} {'hits':>5}  techs")
        for _id, host, ts, reqs, hits, techs in rows:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
            print(f"{when:<20} {host:<28} {reqs:>6} {hits:>5}  {techs or '-'}")
    mem.close()
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="origami", description="Adaptive content discovery engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  origami https://example.com\n"
            "  origami https://example.com/app/ -w wordlist.txt -d 2\n"
            "  origami -l targets.txt --out results/\n"
            "  origami https://example.com -H 'Cookie: session=abc' -H 'Authorization: Bearer X'\n"
            "  origami https://example.com --resume          # continue an interrupted scan\n"
            "  origami --update                               # refresh the fingerprint catalog\n"
        ))
    ap.add_argument("-V", "--version", action="version",
                    version=f"origami {__version__}")
    ap.add_argument("url", nargs="*", help="target base URL(s), e.g. http://example.com")
    ap.add_argument("-u", "--url", dest="url_opt", action="append", metavar="URL",
                    help="target base URL as a flag (repeatable) — lets you keep the URL "
                         "last and swap only it between runs: origami -F --gau -u https://…")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="file with target URLs, one per line (# comments allowed)")
    ap.add_argument("-c", "--concurrency", type=int, default=20,
                    help="max parallel requests — the AIMD ceiling (default 20; adapts down "
                         "on 429/503 pushback, ramps back on clean responses)")
    ap.add_argument("-t", "--timeout", type=float, default=10.0,
                    help="per-request timeout in seconds (default 10)")
    ap.add_argument("--rate", type=float, default=0.0, metavar="RPS",
                    help="cap the aggregate request rate (requests/sec across all "
                         "workers) — the knob for a WAF's req/s threshold; unlike "
                         "--delay it doesn't scale with concurrency")
    ap.add_argument("--delay", type=float, default=0.0, metavar="SECONDS",
                    help="fixed delay before every request (stealth / rate-sensitive "
                         "targets); on top of the adaptive backoff")
    ap.add_argument("-d", "--depth", type=int, default=1, help="recursion depth (0 = root only)")
    ap.add_argument("-w", "--wordlist", action="append", metavar="NAME|FILE",
                    help="wordlist: a file path, or a bundled name — 'base' (~540, default) or "
                         "'big' (~1250, exhaustive). Repeatable to MERGE several. Under --deep "
                         "the base list is always included, so `--deep -w custom` = base + custom. "
                         "Point at SecLists for the widest coverage")
    ap.add_argument("-X", "--ext", "--extensions", action="append", metavar="LIST",
                    help="extensions to brute-force, comma list and/or repeatable "
                         "(e.g. -X php,asp,bak); ADDED to the fingerprint-detected ones")
    ap.add_argument("--ext-only", action="store_true",
                    help="use ONLY the -X extensions (ignore fingerprint-detected and "
                         "learned extensions)")
    ap.add_argument("--max-requests", type=int, default=0,
                    help="request budget per target (default 0 = unlimited); set N to cap "
                         "a slow/throttled target, or stop with q and --resume later")
    ap.add_argument("--time-limit", metavar="DURATION",
                    help="wall-clock budget per target, e.g. 30s / 10m / 1h (or bare seconds); "
                         "the scan stops cleanly when it's reached (like --max-requests, by time)")
    ap.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("-H", "--header", action="append", metavar="'Name: Value'",
                    help="extra header sent on every request; repeatable "
                         "(e.g. -H 'Cookie: sid=…' -H 'Authorization: Bearer …') — "
                         "for authenticated scans")
    ap.add_argument("-A", "--user-agent", metavar="UA",
                    help="override the User-Agent header")
    ap.add_argument("--rotate-ua", action="store_true",
                    help="rotate the User-Agent per request from a pool of real browsers "
                         "(WAF-evasion; ignored if -A pins a specific UA)")
    ap.add_argument("--proxy", metavar="URL",
                    help="route all traffic through an intercepting proxy "
                         "(e.g. http://127.0.0.1:8080 for Burp/ZAP); implies -k")
    ap.add_argument("--proxy-file", metavar="FILE",
                    help="rotate egress across a list of proxies (one URL per line) — spreads "
                         "requests so a per-source rate-limit/ban can't pin the scan; implies -k")
    ap.add_argument("--replay-proxy", metavar="URL",
                    help="re-issue only CONFIRMED findings through this proxy at the end of the "
                         "scan — Burp/ZAP gets a clean sitemap of just the hits, separate from "
                         "--proxy (which sees every probe); implies -k")
    ap.add_argument("--replay-codes", metavar="CODES",
                    help="restrict --replay-proxy to these status codes (comma list; "
                         "default = every reported finding)")
    ap.add_argument("--http2", action="store_true",
                    help="negotiate HTTP/2 (matches modern CDNs/WAFs; needs the 'h2' package — "
                         "pip install h2; silently falls back to HTTP/1.1 if absent)")
    ap.add_argument("--json", help="write JSON report to this path")
    ap.add_argument("--jsonl", metavar="FILE",
                    help="stream findings as JSON Lines to FILE as they're confirmed "
                         "(use - for stdout, which implies --no-ui; pipe into nuclei/etc.)")
    ap.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    ap.add_argument("--out", metavar="DIR",
                    help="write pentest artifacts to DIR (findings.json, params.txt, urls.txt, "
                         "report.html, graph.html)")
    ap.add_argument("--graph", metavar="FILE",
                    help="write an endpoint graph (provenance + orphan/hidden endpoints) "
                         "to FILE.html, plus a Graphviz FILE.dot")
    ap.add_argument("--db", default=str(DEFAULT_DB),
                    help=f"memory DB path (default: {DEFAULT_DB})")
    ap.add_argument("--no-learn", action="store_true",
                    help="don't read/write the memory DB this run")
    ap.add_argument("--resume", action="store_true",
                    help="continue an interrupted scan from its saved checkpoint "
                         "(scans always checkpoint; an interrupted run leaves one behind)")
    ap.add_argument("--update", action="store_true",
                    help="fetch the Wappalyzer fingerprint catalog into the KB and exit")
    ap.add_argument("--history", action="store_true",
                    help="show past scan history (optionally filtered by the given host) and exit")
    ap.add_argument("--forget", metavar="HOST|all",
                    help="erase cross-target memory for a host (www/apex together) or 'all', then exit")
    ap.add_argument("--forget-noise", action="store_true",
                    help="prune content-hashed/fingerprinted bundle names (app.a1b2c3d4.js, "
                         "GUIDs, timestamps) from cross-target memory, then exit")
    ap.add_argument("--no-ui", action="store_true", help="disable the live rich UI")
    ap.add_argument("-F", "--full-url", action="store_true",
                    help="show full URLs instead of just paths")
    ap.add_argument("--fp", "--fingerprint", action="store_true", dest="fp",
                    help="print the fingerprint panel (tech/WAF/folds/params) at the end")
    sc = ap.add_mutually_exclusive_group()
    sc.add_argument("--shortscan", action="store_true",
                    help="force the IIS 8.3 shortscan fold (default: auto when IIS detected)")
    sc.add_argument("--no-shortscan", action="store_true",
                    help="disable the shortscan fold")
    ap.add_argument("--no-js", action="store_true",
                    help="disable JS/HTML endpoint harvesting")
    ap.add_argument("--no-apidocs", action="store_true",
                    help="disable OpenAPI/Swagger spec discovery + endpoint folding")
    ap.add_argument("--openapi", "--swagger", "--spec", metavar="URL|FILE", dest="openapi",
                    help="feed an OpenAPI/Swagger or JSON:API doc (URL or local file) "
                         "and fold its declared endpoints onto the target as seeds — "
                         "works even with --no-apidocs (an off-host docs server, a client file)")
    ap.add_argument("--no-backups", action="store_true",
                    help="disable VCS/dotfile probes and backup-name folding")
    ap.add_argument("--bypass-403", nargs="?", const="auto", default=None,
                    choices=["light", "auto", "full"], metavar="light|auto|full",
                    help="on each 403/401, try path/header/method bypass tricks (incl. "
                         "hop-by-hop/encoded-sep/api-prefix); a surviving 2xx is reported. "
                         "Bare = 'auto' (fingerprint-gated families); 'light' = core only; "
                         "'full' = everything (exhaustive)")
    ap.add_argument("--bypass-headers", nargs="?", const=True, default=None, metavar="FILE",
                    help="403/401 header-bypass via a wordlist (implies --bypass-403): "
                         "bare flag uses the bundled 403-headers.txt, or pass FILE for "
                         "your own 'Header: value' list (replaces the built-in header axis)")
    ap.add_argument("--bypass-prefixes", metavar="FILE",
                    help="route-prefix wordlist for --bypass-403 (one mount per line, e.g. "
                         "rest/v1): fed to the api-prefix and matrix-management (`/<route>/;/"
                         "actuator/*`) families as extra carriers, on top of the curated seeds "
                         "and discovered 2xx routes (implies --bypass-403)")
    ap.add_argument("--vhost", action="store_true",
                    help="virtual-host discovery: fuzz the Host header on the target IP "
                         "and report distinct vhosts (admin/staging/internal/… on the CDN)")
    ap.add_argument("--params", action="store_true",
                    help="parameter discovery: fire harvested + common parameter names at "
                         "dynamic endpoints and flag the ones that reflect (XSS/SSTI/redirect leads)")
    ap.add_argument("--cache-poison", nargs="?", const="auto", default=None,
                    choices=["light", "auto", "full"], metavar="light|auto|full",
                    help="web cache poisoning: probe cacheable endpoints for UNKEYED inputs "
                         "(X-Forwarded-Host & friends) that reflect or change the cached "
                         "response. Safe — every probe rides a throwaway cache-buster, never "
                         "the real key. Bare = 'auto' (only where caching is detected); "
                         "'light' = core headers; 'full' = exhaustive (all headers, any endpoint)")
    ap.add_argument("--cache-headers", metavar="FILE",
                    help="custom unkeyed-header wordlist for --cache-poison ('Header: value' "
                         "lines), added to the built-in set (implies --cache-poison)")
    ap.add_argument("--deep", action="store_true",
                    help="aggressive discovery preset: turns on --bypass-403, --cache-poison, "
                         "--probe-405, --buckets, --params and --wayback at once (state-changing "
                         "probes and off-host bucket GETs included). Just: origami --deep -u <url>")
    ap.add_argument("--buckets", action="store_true",
                    help="probe S3/GCS/Azure buckets referenced in the target's code for public "
                         "listability (read-only GET, off-host) and enumerate exposed objects; "
                         "the references themselves are surfaced for free without this flag")
    ap.add_argument("--probe-405", action="store_true",
                    help="on each 405 (method-not-allowed), replay with POST (and PATCH if the "
                         "Allow header lists it — never PUT/DELETE) using an empty and a {} body "
                         "to reveal the method the endpoint accepts. State-changing → opt-in; "
                         "the Allow header is surfaced for free without this flag")
    ap.add_argument("--wayback", action="store_true",
                    help="fold HISTORICAL URLs (Wayback Machine CDX + Common Crawl) as seeds — "
                         "legacy/forgotten paths that may still respond; runs in the background "
                         "during fingerprint (zero external dependency)")
    ap.add_argument("--gau", action="store_true",
                    help="like --wayback but prefer your gau/waybackurls binary (richer providers); "
                         "falls back to the native sources if the binary isn't installed")
    ap.add_argument("-x", "--exclude", action="append", metavar="PATTERN",
                    help="never request or recurse a path containing PATTERN "
                         "(case-insensitive, repeatable) — safety rail for "
                         "destructive/out-of-scope endpoints (/logout, /delete)")
    ap.add_argument("--exclude-ext", action="append", metavar="LIST",
                    help="drop paths with these file extensions from scraping/probing "
                         "(comma-list, repeatable, glob ok: jpg,png,css or jpg*) — cuts "
                         "the static-asset noise harvested from listings/JS")
    ap.add_argument("--economy", choices=["auto", "on", "off"], default="auto",
                    help="rank candidates by learned hit-rate so the request budget "
                         "buys the most likely names first (auto: on when a WAF is "
                         "detected; needs the memory DB to learn)")
    ap.add_argument("--scope", choices=["host", "site"], default="host",
                    help="host: scan only the target host (CDN JS is still read for intel); "
                         "site: also scan same-registrable-domain hosts (e.g. the CDN)")
    ap.add_argument("--max-folds", type=int, default=40,
                    help="max vocabulary names learned from target references to fold "
                         "into the wordlist (default 40; 0 disables; higher = more reach, "
                         "more requests)")
    ap.add_argument("-mc", "--mc", metavar="CODES",
                    help="match only these status codes (comma list); overrides filters")
    ap.add_argument("-fc", "--fc", metavar="CODES",
                    help="filter out these status codes from the report (404/400 are always dropped)")
    ap.add_argument("-ms", "--ms", metavar="SIZES",
                    help="match only these body sizes in bytes (comma list)")
    ap.add_argument("-fs", "--fs", metavar="SIZES",
                    help="filter out these body sizes in bytes (comma list)")
    ap.add_argument("--filter-word-count", metavar="N",
                    help="filter out responses with these word counts (comma list)")
    ap.add_argument("--filter-line-count", metavar="N",
                    help="filter out responses with these line counts (comma list)")
    ap.add_argument("--filter-regex", metavar="RE",
                    help="filter out responses whose body matches this regex")
    ap.add_argument("--filter-similar-to", action="append", metavar="URL",
                    help="filter out responses whose body is ~identical (simhash) to this "
                         "reference page; repeatable — great for a known soft-200/error page")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="-v: phases, calibration, fingerprint, hits; -vv: every request")
    args = ap.parse_args()
    # -u/--url merges into the positional target list, so everything downstream
    # (which reads args.url) works unchanged whichever form the user used.
    if args.url_opt:
        args.url = list(args.url or []) + args.url_opt

    if args.update:
        from origami.brain.ingest import wappalyzer
        from origami.brain.kb import RULES_PATH
        print("[*] fetching Wappalyzer fingerprint catalog…")
        n = asyncio.run(wappalyzer.update_kb(RULES_PATH))
        print(f"[+] wrote {n} ingested detection rules to {RULES_PATH}" if n
              else "[!] update failed (network?) — KB unchanged")
        sys.exit(0 if n else 2)
    if args.history:
        sys.exit(_show_history(args))
    if args.forget:
        sys.exit(_forget(args))
    if args.forget_noise:
        sys.exit(_forget_noise(args))
    # stdin counts as a target source: `-l -`, or a bare pipe when nothing else
    # given. Read it eagerly (once) so an empty pipe still hits the error below.
    args._stdin_targets = []
    if args.list == "-" or (not sys.stdin.isatty() and not args.url and not args.list):
        args._stdin_targets = _read_url_lines(sys.stdin.read())
    if not args.url and not args.list and not args._stdin_targets:
        ap.error("give at least one target URL or --list FILE (or pipe URLs on stdin)")
    if args.ext_only and not args.ext:
        ap.error("--ext-only requires -X/--ext (the extensions to use)")
    for wl in (args.wordlist or []):
        if not resolve_wordlist(Path(wl)).is_file():
            ap.error(f"wordlist not found: {wl} (a path, or a bundled name: base / big)")
    if args.list and args.list != "-" and not Path(args.list).is_file():
        ap.error(f"target list not found: {args.list}")

    if args.jsonl == "-":
        args.no_ui = True              # pure JSONL on stdout — no banner/UI
    if not args.no_ui:
        banner.show()
    try:
        sys.exit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        print("\n[!] interrupted — continue with --resume")
        sys.exit(130)


if __name__ == "__main__":
    main()
