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

from origami import banner
from origami.brain.memory import DEFAULT_DB, Memory
from origami.control import keyboard_control
from origami.core import resume as resume_mod
from origami.core.httpclient import Engine, EngineConfig
from origami.core.response_classifier import Filters
from origami.core.scanner import ScanControl, ScanOptions, resume_scan, scan
from origami.output import artifacts, html_report, json_report, ui


def _int_set(s: str | None) -> set[int] | None:
    if not s:
        return None
    return {int(x) for x in s.replace(" ", "").split(",") if x}


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
              f"(report.html, findings.json, params.txt={info['params']}, urls.txt={info['urls']})")


async def run(args: argparse.Namespace) -> int:
    targets = _collect_targets(args)
    if not targets:
        print("[!] no targets (give a URL or --list FILE)")
        return 2

    shortscan = "on" if args.shortscan else "off" if args.no_shortscan else "auto"
    opts = ScanOptions(
        max_depth=args.depth, max_requests=args.max_requests,
        wordlist_path=args.wordlist, shortscan=shortscan,
        js=not args.no_js, backups=not args.no_backups,
        max_folds=args.max_folds, scope=args.scope, economy=args.economy,
        filters=_build_filters(args),
    )
    memory = None if args.no_learn else Memory(args.db)
    control = ScanControl()

    filt = opts.filters
    fdesc = (f"match {sorted(filt.match_codes)}" if filt.match_codes
             else f"drop {sorted(filt.filter_codes)}" if filt.filter_codes else "none")
    print(f"  targets  : {len(targets)}" + (f"  (list: {args.list})" if args.list else ""))
    print(f"  started  : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  wordlist : {args.wordlist or 'builtin base.txt'}")
    print(f"  filters  : codes {fdesc}")
    if sys.stdin.isatty() and not args.no_ui:
        print("  controls : [q] quit   ([n] skip directory — once one is discovered)\n")

    rc = 0
    try:
        async with keyboard_control(control):
            for i, target in enumerate(targets, 1):
                if control.quit:
                    print("[!] quit — skipping remaining targets")
                    break
                if len(targets) > 1:
                    print(f"\n━━━ [{i}/{len(targets)}] {target} ━━━")
                # Fresh Engine + Observer + TargetProfile per URL → each target
                # is scanned clean (no learned vocab/extensions/baseline bleed
                # from the previous one). Cross-target SQLite memory is shared by
                # design (use --no-learn to isolate fully).
                observer = ui.make_observer(target, enabled=not args.no_ui,
                                            verbosity=args.verbose, full_url=args.full_url)
                cfg = EngineConfig(concurrency=args.concurrency, timeout=args.timeout,
                                   verify_tls=not args.insecure)
                rpath = resume_mod.path_for(target)
                saved = resume_mod.load(rpath) if args.resume else None
                if args.resume and saved is None:
                    print(f"[!] no checkpoint for {target} — scanning fresh")
                async with Engine(cfg) as engine:
                    engine.on_request = observer.on_request   # live heartbeat, every phase
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
                    print(f"[!] {target} unreachable")
                    rc = 2
                    continue
                streamed = getattr(observer, "streamed", False)
                ui.print_report(result, full_url=args.full_url, show_findings=not streamed,
                                show_fingerprint=(not streamed) or args.fp)
                _write_outputs(args, result, target, multi=len(targets) > 1)
    finally:
        if memory is not None:
            memory.close()
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
    ap = argparse.ArgumentParser(prog="origami", description="Adaptive content discovery engine.")
    ap.add_argument("url", nargs="*", help="target base URL(s), e.g. http://example.com")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="file with target URLs, one per line (# comments allowed)")
    ap.add_argument("-c", "--concurrency", type=int, default=20)
    ap.add_argument("-t", "--timeout", type=float, default=10.0)
    ap.add_argument("-d", "--depth", type=int, default=1, help="recursion depth (0 = root only)")
    ap.add_argument("-w", "--wordlist", help="path to wordlist (default: builtin base.txt)")
    ap.add_argument("--max-requests", type=int, default=5000)
    ap.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--json", help="write JSON report to this path")
    ap.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    ap.add_argument("--out", metavar="DIR",
                    help="write pentest artifacts to DIR (findings.json, params.txt, urls.txt)")
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
    ap.add_argument("--shortscan", action="store_true",
                    help="force the IIS 8.3 shortscan fold (default: auto when IIS detected)")
    ap.add_argument("--no-shortscan", action="store_true",
                    help="disable the shortscan fold")
    ap.add_argument("--no-js", action="store_true",
                    help="disable JS/HTML endpoint harvesting")
    ap.add_argument("--no-backups", action="store_true",
                    help="disable VCS/dotfile probes and backup-name folding")
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

    if not args.no_ui:
        banner.show()
    try:
        sys.exit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
