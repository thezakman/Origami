"""Scanner data types — the request/response contract of a scan.

Isolated from the orchestration loop so callers (CLI, JSON report, tests) can
import the shapes without pulling in the whole fold machinery. Re-exported from
`origami.core.scanner` for backwards compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from origami.core.evidence import TargetProfile
from origami.core.response_classifier import Filters, Finding


@dataclass
class ScanOptions:
    max_depth: int = 1            # 0 = root only
    climb_brute: int = 0          # ancestor dirs above the target swept with the FULL wordlist
                                  # (not just single-probed): 0 = off, N = N levels up (deepest-first),
                                  # <0 = all the way to root. CLI resolves it: 1 plain, all under --deep.
    max_requests: int = 0         # hard cap per run (§3.11); 0 = unlimited (default)
    time_limit: float = 0.0       # wall-clock cap in seconds (--time-limit); 0 = unlimited
    replay_proxy: str | None = None       # send confirmed findings through this proxy (--replay-proxy)
    replay_codes: tuple[int, ...] = ()    # only replay these statuses (empty = all reported)
    filter_similar_urls: tuple[str, ...] = ()  # --filter-similar-to: pages whose simhash drops look-alikes
    wordlist_paths: list[str] = field(default_factory=list)  # -w (repeatable); merged. Empty = builtin base
    shortscan: str = "auto"       # "auto" (IIS fold OR any Windows/.NET signal) | "on" (force) | "off"
    deep: bool = False            # --deep: thorough mode — e.g. always spend the shortscan vuln check
    js: bool = True               # harvest endpoints from HTML/JS
    apidocs: bool = True          # probe + parse OpenAPI/Swagger specs into seeds
    backups: bool = True          # VCS/dotfile probes + backup-name folding
    extensions: list[str] = field(default_factory=list)  # user-forced extensions (".php" form)
    ext_only: bool = False        # use ONLY `extensions` (ignore fingerprint + learned)
    max_folds: int = 40           # cap on learned vocabulary names folded into the scan
    scope: str = "host"           # "host" (target only) | "site" (also scan same-site CDN)
    economy: str = "auto"         # bandit candidate ranking: "auto" (WAF/throttle) | "on" | "off"
    exclude: list[str] = field(default_factory=list)  # skip any path containing one of these (safety: /logout, /delete…)
    exclude_ext: list[str] = field(default_factory=list)  # skip paths with these file extensions (glob: jpg,png,jpg* — static-asset noise)
    graph: bool = False           # track provenance edges for the endpoint graph (--graph)
    bypass403: bool = False        # try to bypass 403/401 findings (path/header/method tricks)
    bypass_intensity: str = "auto" # "light" (core only) | "auto" (fingerprint-gated) | "full" (all)
    bypass_headers: bool = False   # use a header-bypass wordlist for the header axis (--bypass-headers)
    bypass_headers_path: str | None = None  # custom header wordlist path (None → bundled 403-headers.txt)
    bypass_prefixes_path: str | None = None  # custom route-prefix wordlist (--bypass-prefixes) for the api/matrix families
    openapi_source: str | None = None  # explicit OpenAPI/Swagger/JSON:API spec (URL or file) to fold (--openapi)
    param_fuzz: bool = False       # fire harvested + common param names at dynamic endpoints (--params)
    cache_poison: str = ""         # "" = off; "light"|"auto"|"full" — probe unkeyed inputs for cache poisoning (--cache-poison)
    cache_headers: str | None = None  # custom unkeyed-header wordlist for --cache-poison (None → bundled set)
    probe_405: bool = False        # on each 405, replay with POST/PATCH (empty & {} body) to find the accepted method (--probe-405)
    buckets: bool = False          # probe referenced S3/GCS/Azure buckets for public listability (--buckets)
    wayback: bool = False          # fold historical URLs (Wayback CDX + Common Crawl) as seeds (--wayback)
    gau: bool = False              # prefer the gau/waybackurls binary for history, native fallback (--gau)
    vhost: bool = False            # virtual-host discovery (Host-header fuzzing on the target IP)
    origin: bool = False           # origin-IP discovery + IP-based WAF bypass (--origin)
    overlays: bool = True          # fold tech-specific path packs from the fingerprint (--no-overlays off)
    filters: Filters = field(default_factory=Filters)
    finding_sink: object = field(default=None, compare=False, repr=False)  # optional callable(finding) — streamed per confirmed finding (JSONL)


@dataclass
class ScanControl:
    """Interactive control shared with the keyboard listener (dirb-style).

    `n` skips the rest of the current directory; `q` ends the scan early.
    """
    skip_prefix: bool = False
    quit: bool = False


@dataclass
class ScanResult:
    profile: TargetProfile
    findings: list[Finding] = field(default_factory=list)
    requests_made: int = 0
    folds: set[str] = field(default_factory=set)
    pushbacks: int = 0            # 429/reset events — target throttled us
    completed: bool = False       # False if interrupted (quit/cap) → resumable
    error: str = ""               # transport error when the root was unreachable (surfaced to the user)
    edges: list[tuple[str, str]] = field(default_factory=list)  # provenance (src→dst) for --graph
    seen_urls: set[str] = field(default_factory=set, compare=False, repr=False)     # reported URLs (raw) — kills cross-source live dupes
    seen_urls_lc: set[str] = field(default_factory=set, compare=False, repr=False)  # …lower-cased, consulted on a case-insensitive host (both kept so a mid-scan case flip is consistent)
    wall_seen: dict = field(default_factory=dict, compare=False, repr=False)      # (status,length) → count, for live block-wall flood suppression
    twin_sig: dict = field(default_factory=dict, compare=False, repr=False)       # slash-normalized URL → response sig, to suppress an identical /x vs /x/ twin live
    odata_probed: set = field(default_factory=set, compare=False, repr=False)     # collection paths already OData-probed (early target + late fold don't double-probe)
    multiviews_seen: bool = field(default=False, compare=False, repr=False)       # reported the "MultiViews enabled" misconfig once already
    multiviews_choices: set = field(default_factory=set, compare=False, repr=False)  # MultiViews-disclosed files already validated (dedup: /x.bak, /x.inc … all → /x.php)
