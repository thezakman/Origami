"""Live terminal UI built on `rich`.

A scan observer the engine drives via no-op-safe hooks. Renders, inside one
`Live` view:

  * a header panel — target, phase, confirmed tech badges, folds;
  * a status bar — requests, req/s, hits, pushback, current prefix;
  * a progress bar for the prefix being enumerated;
  * a findings table that grows as hits are confirmed.

The scanner only ever calls the small observer interface (phase / start_prefix
/ tick / finding / fingerprint / done), so it stays decoupled from rich. A
NullObserver gives the same interface when --no-ui is passed.
"""

from __future__ import annotations

import sys
import time
from urllib.parse import urlparse

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, ProgressColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
    console = Console()
except ImportError:  # rich is optional; NullObserver works without it
    HAS_RICH = False
    console = None


class NullObserver:
    """No-op observer — same interface, plain logs only when verbose.

    Used when there's no TTY (or --no-ui). With -v/-vv it still streams plain
    log lines so the user can follow what the scanner is doing.
    """

    streamed = False               # did this observer print findings live?

    def __init__(self, verbosity: int = 0, full_url: bool = False, stream=None) -> None:
        self.verbosity = verbosity
        self.full_url = full_url
        self.stream = stream or sys.stdout    # logs go here — stderr when stdout is a JSONL pipe
        self.skippable = False     # [n] skip only meaningful once a dir exists
        self.engine = None         # set via attach_engine for live throttle readout

    def attach_engine(self, engine) -> None:
        """Give the observer the engine so the status bar can read its adaptive
        concurrency (drops under WAF/rate-limit backoff)."""
        self.engine = engine

    def disp(self, url: str) -> str:
        return display_url(url, self.full_url)

    def set_skippable(self, value: bool = True) -> None:
        self.skippable = value

    def phase(self, name: str) -> None: ...
    def substep(self, name: str, done: int | None = None, total: int | None = None) -> None: ...
    def start_prefix(self, prefix: str, total: int) -> None: ...
    def progress(self, done: int, total: int) -> None: ...
    def tick(self, hit: bool = False) -> None: ...
    def on_request(self) -> None: ...
    def finding(self, f, stream: bool = True) -> None: ...
    def fingerprint(self, profile, exts, folds) -> None: ...
    def pushback(self, n: int) -> None: ...
    def done(self) -> None: ...

    def directory(self, prefix: str, depth: int) -> None:
        self.log(f"==> directory: {prefix} (depth {depth})", 0)

    def log(self, msg: str, level: int = 1, style: str = "") -> None:
        if self.verbosity >= level:
            print(msg, file=self.stream)

    def request(self, url: str, status: int, hit: bool) -> None:
        if self.verbosity >= 2:
            print(f"  {status:>3} {'HIT' if hit else '   '}  {url}", file=self.stream)

    def __enter__(self): return self
    def __exit__(self, *a): ...


def display_url(url: str, full: bool) -> str:
    """Full URL when --full-url is set, else just the path."""
    return url if full else (urlparse(url).path or "/")


# Per-origin colour so the stream is scannable at a glance.
ORIGIN_STYLE = {
    "memory": "magenta", "js": "blue", "shortscan": "bright_magenta",
    "backup": "red", "robots": "green", "priority": "cyan",
    "wordlist": "white", "recursion": "yellow", "assoc": "bright_magenta",
    "apidocs": "bright_blue", "wellknown": "bright_cyan", "graphql": "bright_magenta",
    "header": "blue", "methods": "bold red", "bypass403": "bold green",
    "harvest": "bright_blue", "vhost": "bold cyan", "wayback": "bright_green",
    "cache-poison": "bold magenta", "vcs": "bold red", "bucket": "bold yellow",
    "config": "bright_cyan", "apiver": "bright_blue", "mutate": "yellow",
    "index-hidden": "yellow",
}

# Semantic tag colour — `disclosure` deliberately loud.
TAG_STYLE = {
    "secret": "bold white on red", "disclosure": "bold white on red",
    "config": "yellow", "api": "blue",
    "admin": "cyan", "auth": "magenta", "source": "green",
    "upload": "bright_yellow", "debug": "bright_red", "vhost": "bold cyan",
    "listing": "bold yellow", "leak": "bold black on yellow", "bypass": "bold black on green",
    "param": "bold green", "xss-lead": "bold black on bright_red",
    "cache": "cyan", "poisonable": "bold white on magenta",
    "method": "bold cyan", "bucket": "bold yellow",
}


def _tag_markup(tags) -> str:
    return " ".join(f"[{TAG_STYLE.get(t, 'white')}]{t}[/]" for t in (tags or []))


def _status_style(code: int) -> str:
    if 200 <= code < 300:
        return "bold green"
    if 300 <= code < 400:
        return "cyan"
    if code in (401, 403):
        return "yellow"
    if 400 <= code < 500:
        return "magenta"
    return "red"


class _CountColumn(ProgressColumn):
    """`done/total` for a determinate phase; blank when indeterminate (the
    pulsing bar already says 'working') so it never reads a stuck '0/1'."""

    def render(self, task) -> "Text":
        if task.total is None:
            return Text("", style="dim")
        return Text(f"{int(task.completed)}/{int(task.total)}", style="dim")


class _LiveDashboard:
    """Wrapper whose __rich__ rebuilds the whole dashboard on every render, so
    rich's auto-refresh (refresh_per_second) animates reqs/rate/elapsed/conc and
    the progress bar continuously — otherwise they only move on an explicit
    refresh and freeze during a slow request."""

    def __init__(self, ui: "RichUI") -> None:
        self._ui = ui

    def __rich__(self):
        return self._ui._render()


class RichUI(NullObserver):
    streamed = True

    def __init__(self, target: str, verbosity: int = 0, full_url: bool = False) -> None:
        self.verbosity = verbosity
        self.full_url = full_url
        self.engine = None
        self.target = target
        self.phase_name = "starting"
        self.substep_name = ""
        self.prefix = "/"
        self.requests = 0
        self.hits = 0
        self.pushbacks = 0
        self.findings: list = []
        self.techs: dict[str, float] = {}
        self.folds: set[str] = set()
        self.start = time.perf_counter()
        self.start_wall = time.time()
        self.skippable = False
        self._progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None, pulse_style="cyan"),
            _CountColumn(),
            console=console,
            expand=True,
        )
        self._task = self._progress.add_task("waiting", total=1)
        self._ptotal = 1
        self._pcompleted = 0
        # A dynamic renderable so auto-refresh redraws the live stats every tick.
        self._live = Live(_LiveDashboard(self), console=console, refresh_per_second=10,
                          transient=False)

    # ---- lifecycle ----------------------------------------------------------

    def __enter__(self) -> "RichUI":
        self._live.start()
        return self

    def __exit__(self, *a) -> None:
        self._refresh()
        self._live.stop()
        self._print_final()

    # ---- observer hooks -----------------------------------------------------

    def phase(self, name: str) -> None:
        self.phase_name = name
        self.substep_name = ""
        # Setup/harvest phases have no candidate count → an INDETERMINATE bar
        # that pulses (animated by auto-refresh). reset(total=None) keeps the old
        # total in rich, so set it on the task directly. substep()/start_prefix()
        # switch it to a real, filling bar.
        self._ptotal = 0
        self._pcompleted = 0
        task = self._progress.tasks[0]
        task.completed = 0
        task.total = None                          # → animated pulse
        self._progress.update(self._task, description=f"status [bold cyan]{name}[/]")

    def substep(self, name: str, done: int | None = None, total: int | None = None) -> None:
        # name the current sub-step within a phase: `recon: apidocs`, `backups:
        # default.aspx`. With done/total it also fills the bar by step count
        # (recon); without, the bar stays owned by start_prefix+tick (the folds
        # that count requests).
        self.substep_name = name
        desc = f"status [bold cyan]{self.phase_name}: {name}[/]"
        if total is not None:
            self._ptotal = max(total, 1)
            self._pcompleted = min(done or 0, self._ptotal)
            self._progress.update(self._task, completed=self._pcompleted,
                                  total=self._ptotal, description=desc)
        else:
            self._progress.update(self._task, description=desc)

    def start_prefix(self, prefix: str, total: int) -> None:
        self.prefix = prefix
        self._ptotal = max(total, 1)
        self._pcompleted = 0
        self._progress.reset(self._task, total=self._ptotal,
                             description=f"status [bold cyan]{prefix}[/]")
        self._refresh()

    def on_request(self) -> None:
        # fired by the engine on EVERY fetch; the dynamic renderable animates the
        # stats on its own (auto-refresh), so we just count here.
        self.requests += 1

    def progress(self, done: int, total: int) -> None:
        # a request-heavy setup fold (js-harvest, api-docs) reporting how far it
        # is — fills the bar instead of leaving it pinned at 0/1.
        self._ptotal = max(total, 1)
        self._pcompleted = min(done, self._ptotal)
        self._progress.update(self._task, completed=self._pcompleted, total=self._ptotal)

    def tick(self, hit: bool = False) -> None:
        if hit:
            self.hits += 1
        if self._ptotal:                      # known total → advance (clamped)
            self._pcompleted = min(self._ptotal, self._pcompleted + 1)
            self._progress.update(self._task, completed=self._pcompleted)

    def finding(self, f, stream: bool = True) -> None:
        # Print a PERMANENT line that scrolls above the live region — findings
        # are never truncated or lost, unlike a fixed-height table.
        # stream=False: still counted (kept in self.findings for the summary),
        # but not printed — used to mute a block-wall flood in the live view.
        self.findings.append(f)
        if not stream:
            self._refresh()
            return
        style = _status_style(f.status)
        # 2xx = accessible content (a real hit) → bright origin. 401/403/3xx =
        # "exists but blocked / redirect" → dim the origin so the eye doesn't
        # read a forbidden path as a successful find.
        accessible = 200 <= f.status < 300
        ostyle = ORIGIN_STYLE.get(f.origin, "white") if accessible else "dim"
        tags = _tag_markup(getattr(f, "tags", []))
        note = f" [dim]({f.note})[/]" if getattr(f, "note", "") else ""
        # fixed-width columns first, URL last → everything lines up cleanly.
        self._live.console.print(
            f"[{style}]{f.status:>3}[/] [dim]{f.length:>9}B[/] "
            f"[{ostyle}]{f.origin:<9}[/] [dim]{f.confidence:.2f}[/] "
            f"{(tags + ' ') if tags else ''}{self.disp(f.url)}{note}")
        self._refresh()

    def directory(self, prefix: str, depth: int) -> None:
        self._live.console.print(
            f"[bold magenta]==>[/] [bold]directory[/] {prefix} [dim](depth {depth})[/]")

    def fingerprint(self, profile, exts, folds) -> None:
        self.techs = dict(profile.tech_scores)
        self.folds = set(folds)
        self._refresh()

    def pushback(self, n: int) -> None:
        self.pushbacks = n

    def log(self, msg: str, level: int = 1, style: str = "") -> None:
        # Printing through the Live console scrolls the line ABOVE the live
        # dashboard, which stays pinned at the bottom.
        if self.verbosity >= level:
            ts = time.strftime("%H:%M:%S")
            self._live.console.print(f"[dim]{ts}[/] {msg}", style=style or None)

    def request(self, url: str, status: int, hit: bool) -> None:
        if self.verbosity >= 2:
            tag = "[bold green]HIT[/]" if hit else "[dim]···[/]"
            self._live.console.print(
                f"  [{_status_style(status)}]{status:>3}[/] {tag}  [dim]{url}[/]")

    # ---- rendering ----------------------------------------------------------

    def _rate(self) -> float:
        dt = time.perf_counter() - self.start
        return self.requests / dt if dt > 0 else 0.0

    _PHASES = ["calibrate", "fingerprint", "recon", "shortscan", "scan",
               "harvest", "403-bypass", "backups", "associations", "params", "vhost"]

    def _phase_text(self) -> "Text":
        # header shows only the position (the name lives in the status-bar chip)
        if self.phase_name in self._PHASES:
            return Text(f"phase {self._PHASES.index(self.phase_name) + 1}/{len(self._PHASES)}",
                        style="bold cyan")
        return Text(self.phase_name, style="bold cyan")

    def _header(self) -> Panel:
        badges = Text()
        for tech, score in list(self.techs.items())[:6]:
            style = "bold white on dark_green" if score >= 50 else "dim"
            badges.append(f" {tech} ", style=style)
            badges.append(" ")
        if not badges.plain:
            badges = Text("fingerprinting…", style="dim italic")
        fold_txt = Text()
        for fold in sorted(self.folds):
            fold_txt.append(f" ⌘ {fold} ", style="bold black on cyan")

        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right")
        grid.add_row(Text(self.target, style="bold"), self._phase_text())
        grid.add_row(badges, fold_txt)
        return Panel(grid, title="[bold]Origami[/]", border_style="green")

    def _elapsed(self) -> str:
        s = int(time.perf_counter() - self.start)
        return f"{s // 60:d}:{s % 60:02d}"

    def _throttle(self) -> int | None:
        """Adaptive concurrency ceiling, shown only while throttled below max."""
        e = self.engine
        if e is None:
            return None
        lim = e.concurrency_limit
        return lim if lim < e.cfg.concurrency else None

    def _statusbar(self) -> Text:
        t = Text()
        chip = self.phase_name + (f": {self.substep_name}" if self.substep_name else "")
        t.append(f" {chip} ", style="bold white on blue")
        t.append("  reqs ", style="dim"); t.append(f"{self.requests}", style="bold")
        t.append(" · ", style="dim"); t.append(f"{self._rate():.0f}/s", style="bold")
        t.append(" · hits ", style="dim"); t.append(f"{self.hits}", style="bold green")
        t.append(" · ", style="dim"); t.append(self._elapsed(), style="bold")
        if self.pushbacks:
            t.append(" · backoff ", style="dim"); t.append(f"{self.pushbacks}", style="bold red")
        lim = self._throttle()
        if lim is not None:
            t.append(" · ⤓conc ", style="dim"); t.append(f"{lim}", style="bold red")
        t.append("    [n] skip dir  " if self.skippable else "    ", style="dim italic")
        t.append("[q] quit", style="dim italic")
        return t

    def _render(self) -> Group:
        return Group(self._header(), self._progress, self._statusbar())

    def _refresh(self) -> None:
        self._live.update(self._render())

    def _highlights(self) -> str:
        """A one-line tally of the findings that matter for triage."""
        from collections import Counter
        tags = Counter(t for f in self.findings for t in getattr(f, "tags", []))
        origins = Counter(f.origin for f in self.findings)
        parts: list[str] = []
        if tags.get("secret"):
            parts.append(f"[bold white on red] {tags['secret']} SECRET [/]")
        if tags.get("disclosure"):
            parts.append(f"[bold white on red] {tags['disclosure']} disclosure [/]")
        if tags.get("leak"):
            parts.append(f"[bold black on yellow] {tags['leak']} LEAK [/]")
        if origins.get("bypass403"):
            parts.append(f"[bold green]{origins['bypass403']} 403-bypass[/]")
        if origins.get("methods"):
            parts.append(f"[bold red]{origins['methods']} dangerous-methods[/]")
        if origins.get("graphql"):
            parts.append(f"[magenta]{origins['graphql']} graphql[/]")
        if tags.get("listing"):
            parts.append(f"[bold yellow]{tags['listing']} dir-listing[/]")
        compact = [f"{tags[t]} {t}" for t in ("config", "admin", "auth", "source",
                                              "upload", "debug", "api") if tags.get(t)]
        if compact:
            parts.append("[dim]" + " · ".join(compact) + "[/]")
        return "  ".join(parts)

    def _print_final(self) -> None:
        started = time.strftime("%H:%M:%S", time.localtime(self.start_wall))
        ended = time.strftime("%H:%M:%S")
        console.print(f"\n[bold green]✓[/] scan complete — "
                      f"[bold]{len(self.findings)}[/] findings in "
                      f"[bold]{self.requests}[/] requests "
                      f"([bold]{self._rate():.0f}[/] req/s)")
        hi = self._highlights()
        if hi:
            console.print(f"  ⚑ {hi}")
        console.print(f"[dim]  started {started} · ended {ended} · "
                      f"duration {self._elapsed()}[/]\n")


class PlainLiveObserver(NullObserver):
    """Dependency-free live status bar for TTYs without rich.

    Keeps a single status line pinned with `\\r`; findings and verbose logs
    scroll above it. So the scan is never silent even on the system Python
    where rich isn't installed.
    """

    streamed = True

    def __init__(self, target: str, verbosity: int = 0, full_url: bool = False) -> None:
        self.verbosity = verbosity
        self.full_url = full_url
        self.target = target
        self.phase_name = "starting"
        self.substep_name = ""
        self.prefix = "/"
        self.requests = self.hits = self.pushbacks = 0
        self.start = time.perf_counter()
        self.start_wall = time.time()
        self.skippable = False
        self._last_draw = 0.0

    def __enter__(self) -> "PlainLiveObserver":
        return self

    def __exit__(self, *a) -> None:
        sys.stdout.write("\r\x1b[K")
        started = time.strftime("%H:%M:%S", time.localtime(self.start_wall))
        print(f"\x1b[1;32m✓\x1b[0m {self.hits} findings · "
              f"{self.requests} reqs · {self._rate():.0f}/s · "
              f"started {started} · duration {self._elapsed()}")
        sys.stdout.flush()

    def _rate(self) -> float:
        dt = time.perf_counter() - self.start
        return self.requests / dt if dt > 0 else 0.0

    def _elapsed(self) -> str:
        s = int(time.perf_counter() - self.start)
        return f"{s // 60:d}:{s % 60:02d}"

    def _status(self) -> str:
        s = (f"\x1b[44;1m {self.phase_name} \x1b[0m "
             f"reqs \x1b[1m{self.requests}\x1b[0m · {self._rate():.0f}/s · "
             f"hits \x1b[1;32m{self.hits}\x1b[0m · {self._elapsed()}")
        if self.pushbacks:
            s += f" · \x1b[31mbackoff {self.pushbacks}\x1b[0m"
        s += "  \x1b[2m" + ("[n] skip  " if self.skippable else "") + "[q] quit\x1b[0m"
        return s

    def _draw(self, force: bool = False) -> None:
        now = time.perf_counter()
        if not force and now - self._last_draw < 0.1:
            return
        self._last_draw = now
        sys.stdout.write("\r\x1b[K" + self._status())
        sys.stdout.flush()

    def _emit(self, line: str) -> None:
        sys.stdout.write("\r\x1b[K" + line + "\n")
        self._draw(force=True)

    def phase(self, name: str) -> None:
        self.phase_name = name
        self._draw(force=True)

    def start_prefix(self, prefix: str, total: int) -> None:
        self.prefix = prefix
        self._draw(force=True)

    def on_request(self) -> None:
        self.requests += 1
        self._draw()

    def tick(self, hit: bool = False) -> None:
        if hit:
            self.hits += 1
        self._draw()

    def finding(self, f, stream: bool = True) -> None:
        if not stream:                  # block-wall flood — muted in the live view
            return
        tags = f" \x1b[1;31m[{','.join(f.tags)}]\x1b[0m" if getattr(f, "tags", None) else ""
        accessible = 200 <= f.status < 300
        marker = "\x1b[32m+\x1b[0m" if accessible else "\x1b[33m·\x1b[0m"   # + accessible / · blocked
        origin = f"{f.origin:<9}" if accessible else f"\x1b[2m{f.origin:<9}\x1b[0m"
        self._emit(f"{marker} {f.status}  \x1b[2m{f.length:>8}B\x1b[0m  "
                   f"{origin} \x1b[2m{f.confidence:.2f}\x1b[0m {self.disp(f.url)}{tags}")

    def directory(self, prefix: str, depth: int) -> None:
        self._emit(f"\x1b[1;35m==>\x1b[0m directory {prefix} \x1b[2m(depth {depth})\x1b[0m")

    def pushback(self, n: int) -> None:
        self.pushbacks = n

    def log(self, msg: str, level: int = 1, style: str = "") -> None:
        if self.verbosity >= level:
            self._emit(msg)

    def request(self, url: str, status: int, hit: bool) -> None:
        if self.verbosity >= 2:
            self._emit(f"  {status:>3} {'HIT' if hit else '   '}  {url}")


def make_observer(target: str, enabled: bool, verbosity: int = 0, full_url: bool = False,
                  log_stream=None):
    """Pick the best observer for the environment.

    rich + TTY  → RichUI (full dashboard)
    TTY only    → PlainLiveObserver (dependency-free status bar)
    otherwise   → NullObserver (quiet; verbose logs only). `log_stream` routes its
                  logs off stdout (e.g. to stderr when stdout carries JSONL).
    """
    if not enabled:
        return NullObserver(verbosity, full_url, log_stream)
    if HAS_RICH and console and console.is_terminal:
        return RichUI(target, verbosity, full_url)
    if sys.stdout.isatty():
        print(" tip: install 'rich' (or run via the project .venv) "
              "for the full live dashboard")
        return PlainLiveObserver(target, verbosity, full_url)
    return NullObserver(verbosity, full_url)


def print_report(result, full_url: bool = False, show_findings: bool = True,
                 show_fingerprint: bool = True) -> None:
    """Persistent post-scan report (printed after the Live view closes).

    After a live stream, both default to off — the dashboard already showed
    everything and the ✓ line has the count. `--fp` re-enables the fingerprint
    panel (tech / WAF / folds / parameters).
    """
    if not (HAS_RICH and console):
        _plain_report(result, full_url, show_findings, show_fingerprint)
        return
    if not show_fingerprint and not show_findings:
        return
    p = result.profile

    if show_fingerprint:
        fp = Table.grid(padding=(0, 1))
        fp.add_column(justify="right", style="dim")
        fp.add_column()
        techs = " ".join(
            f"[bold white on dark_green] {t} [/]" if s >= 50 else f"[dim]{t}:{s:.0f}[/]"
            for t, s in p.tech_scores.items()
        ) or "[dim]none[/]"
        fp.add_row("tech", techs)
        if p.waf:
            fp.add_row("WAF", f"[bold white on red] {p.waf} [/]")
        fp.add_row("soft-404/wildcard", "[yellow]YES[/]" if p.wildcard else "no")
        if p.case_sensitive is not None:
            fp.add_row("case-sensitive", "yes" if p.case_sensitive else "[yellow]NO (Windows/IIS)[/]")
        if p.enabled_extensions:
            fp.add_row("extensions", " ".join(sorted(p.enabled_extensions)))
        if result.folds:
            fp.add_row("folds", " ".join(f"[bold black on cyan] ⌘ {f} [/]" for f in sorted(result.folds)))
        if p.parameters:
            shown = sorted(p.parameters)
            preview = ", ".join(shown[:18]) + (f"  (+{len(shown) - 18} more)" if len(shown) > 18 else "")
            fp.add_row("parameters", f"[cyan]{len(shown)}[/] [dim]{preview}[/]")
        if result.pushbacks:
            fp.add_row("throttling", f"[bold red]{result.pushbacks} backoff events[/] "
                                     f"[dim](target rate-limited / pushed back)[/]")
        console.print(Panel(fp, title="[bold]Fingerprint[/]", border_style="green", expand=False))

    if not show_findings:
        return    # findings already streamed live; the ✓ summary line has the count

    tbl = Table(title=f"Findings ({len(result.findings)})  ·  {result.requests_made} requests",
                title_justify="left", expand=True, header_style="bold")
    tbl.add_column("code", width=4)
    tbl.add_column("size", justify="right", width=9, style="dim")
    tbl.add_column("src", width=9, style="dim")
    tbl.add_column("conf", width=4, justify="right", style="dim")
    tbl.add_column("tags")
    tbl.add_column("path", ratio=1, no_wrap=True)
    for f in result.findings:
        note = f" [dim]({f.note})[/]" if getattr(f, "note", "") else ""
        tbl.add_row(
            Text(str(f.status), style=_status_style(f.status)),
            f"{f.length}B",
            f"[{ORIGIN_STYLE.get(f.origin, 'white')}]{f.origin}[/]",
            f"{f.confidence:.2f}",
            _tag_markup(getattr(f, "tags", [])),
            display_url(f.url, full_url) + (note or ""),
        )
    console.print(tbl)


def _plain_report(result, full_url: bool = False, show_findings: bool = True,
                  show_fingerprint: bool = True) -> None:
    p = result.profile
    if show_fingerprint:
        print("\n=== Fingerprint ===")
        for t, s in p.tech_scores.items():
            print(f"  [{'✓' if s >= 50 else ' '}] {t:<12} {s:.0f}")
        if p.waf:
            print(f"  WAF: {p.waf}")
        print(f"  wildcard/soft-404: {'YES' if p.wildcard else 'no'}")
        if p.enabled_extensions:
            print(f"  extensions: {' '.join(sorted(p.enabled_extensions))}")
        if result.folds:
            print(f"  folds: {', '.join(sorted(result.folds))}")
        if p.parameters:
            print(f"  parameters ({len(p.parameters)}): {', '.join(sorted(p.parameters))}")
        if result.pushbacks:
            print(f"  throttling: {result.pushbacks} backoff events (target rate-limited)")
    if not show_findings:
        return    # findings already streamed live; the ✓ summary line has the count
    print(f"\n=== Findings ({len(result.findings)}) — {result.requests_made} requests ===")
    for f in result.findings:
        note = f"  ({f.note})" if getattr(f, "note", "") else ""
        tags = f"  [{','.join(f.tags)}]" if getattr(f, "tags", None) else ""
        print(f"  {f.status}  {f.confidence:.2f}  [{f.origin:<8}] {display_url(f.url, full_url)}  "
              f"{f.length}B{tags}{note}")
    print()
