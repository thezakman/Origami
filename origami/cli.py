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
from origami.output import artifacts, graph, html_report, json_report, ui


def _int_set(s: str | None) -> set[int] | None:
    if not s:
        return None
    return {int(x) for x in s.replace(" ", "").split(",") if x}


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
    return f


def _normalize_url(raw: str) -> str:
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    if not p.netloc:
        raise SystemExit(f"[!] invalid URL: {raw!r}")
    base = f"{p.scheme}://{p.netloc}"
    return base + (p.path if p.path and p.path != "/" else "/")


def _collect_targets(args) -> list[str]:
    raw = list(args.url or [])
    if args.list:
        raw += [ln.strip() for ln in Path(args.list).read_text().splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]
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


async def run(args: argparse.Namespace) -> int:
    targets = _collect_targets(args)
    if not targets:
        print("[!] no targets (give a URL or --list FILE)")
        return 2

    shortscan = "on" if args.shortscan else "off" if args.no_shortscan else "auto"
    opts = ScanOptions(
        max_depth=args.depth, max_requests=args.max_requests,
        wordlist_path=args.wordlist, shortscan=shortscan,
        js=not args.no_js, apidocs=not args.no_apidocs, backups=not args.no_backups,
        max_folds=args.max_folds, scope=args.scope, economy=args.economy,
        exclude=args.exclude or [], exclude_ext=_ext_globs(args.exclude_ext),
        extensions=_ext_list(args.ext),
        ext_only=args.ext_only, graph=bool(args.graph or args.out),  # --out bundle includes the graph
        bypass403=args.bypass_403 or args.bypass_headers is not None,  # --bypass-headers implies bypass
        bypass_headers=args.bypass_headers is not None,
        bypass_headers_path=args.bypass_headers if isinstance(args.bypass_headers, str) else None,
        openapi_source=args.openapi, vhost=args.vhost, param_fuzz=args.params,
        wayback=args.wayback or args.gau, gau=args.gau,
        filters=_build_filters(args),
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
        print(f"  wordlist : {args.wordlist or 'builtin base.txt'}")
        exts = _ext_list(args.ext)
        if exts:
            print(f"  extensions: {', '.join(e.lstrip('.') for e in exts)}"
                  + (" (only)" if args.ext_only else " (+ auto)"))
        print(f"  filters  : codes {fdesc}")
        if args.header:
            print(f"  headers  : {len(args.header)} custom ({', '.join(h.split(':',1)[0].strip() for h in args.header)})")
        if args.user_agent:
            print(f"  user-agent: {args.user_agent}"
                  + ("  (--rotate-ua ignored: -A pins it)" if args.rotate_ua else ""))
        elif args.rotate_ua:
            print(f"  user-agent: rotating per request (pool of {len(_UA_POOL)} browsers)")
        if args.proxy:
            print(f"  proxy    : {args.proxy} (TLS verification off)")
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
        if args.params:
            print(f"  params   : reflection fuzzing on dynamic endpoints")
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
                                   verify_tls=not (args.insecure or args.proxy),  # proxy = TLS intercept
                                   proxy=args.proxy or "", headers=_parse_headers(args.header),
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
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="file with target URLs, one per line (# comments allowed)")
    ap.add_argument("-c", "--concurrency", type=int, default=20)
    ap.add_argument("-t", "--timeout", type=float, default=10.0)
    ap.add_argument("--rate", type=float, default=0.0, metavar="RPS",
                    help="cap the aggregate request rate (requests/sec across all "
                         "workers) — the knob for a WAF's req/s threshold; unlike "
                         "--delay it doesn't scale with concurrency")
    ap.add_argument("--delay", type=float, default=0.0, metavar="SECONDS",
                    help="fixed delay before every request (stealth / rate-sensitive "
                         "targets); on top of the adaptive backoff")
    ap.add_argument("-d", "--depth", type=int, default=1, help="recursion depth (0 = root only)")
    ap.add_argument("-w", "--wordlist", help="path to wordlist (default: builtin base.txt)")
    ap.add_argument("-X", "--ext", "--extensions", action="append", metavar="LIST",
                    help="extensions to brute-force, comma list and/or repeatable "
                         "(e.g. -X php,asp,bak); ADDED to the fingerprint-detected ones")
    ap.add_argument("--ext-only", action="store_true",
                    help="use ONLY the -X extensions (ignore fingerprint-detected and "
                         "learned extensions)")
    ap.add_argument("--max-requests", type=int, default=0,
                    help="request budget per target (default 0 = unlimited); set N to cap "
                         "a slow/throttled target, or stop with q and --resume later")
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
    ap.add_argument("--http2", action="store_true",
                    help="negotiate HTTP/2 (matches modern CDNs/WAFs; needs the 'h2' package — "
                         "pip install h2; silently falls back to HTTP/1.1 if absent)")
    ap.add_argument("--json", help="write JSON report to this path")
    ap.add_argument("--jsonl", metavar="FILE",
                    help="stream findings as JSON Lines to FILE as they're confirmed "
                         "(use - for stdout, which implies --no-ui; pipe into nuclei/etc.)")
    ap.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    ap.add_argument("--out", metavar="DIR",
                    help="write pentest artifacts to DIR (findings.json, params.txt, urls.txt)")
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
    ap.add_argument("--bypass-403", action="store_true",
                    help="on each 403/401, try path/header/method bypass tricks "
                         "(nomore403-style); a surviving 2xx is reported as a bypass")
    ap.add_argument("--bypass-headers", nargs="?", const=True, default=None, metavar="FILE",
                    help="403/401 header-bypass via a wordlist (implies --bypass-403): "
                         "bare flag uses the bundled 403-headers.txt, or pass FILE for "
                         "your own 'Header: value' list (replaces the built-in header axis)")
    ap.add_argument("--vhost", action="store_true",
                    help="virtual-host discovery: fuzz the Host header on the target IP "
                         "and report distinct vhosts (admin/staging/internal/… on the CDN)")
    ap.add_argument("--params", action="store_true",
                    help="parameter discovery: fire harvested + common parameter names at "
                         "dynamic endpoints and flag the ones that reflect (XSS/SSTI/redirect leads)")
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
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="-v: phases, calibration, fingerprint, hits; -vv: every request")
    args = ap.parse_args()

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
    if not args.url and not args.list:
        ap.error("give at least one target URL or --list FILE")
    if args.ext_only and not args.ext:
        ap.error("--ext-only requires -X/--ext (the extensions to use)")
    if args.wordlist and not Path(args.wordlist).is_file():
        ap.error(f"wordlist not found: {args.wordlist}")
    if args.list and not Path(args.list).is_file():
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
