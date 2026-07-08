# Origami

> *Origami is an adaptive content discovery engine that folds its strategy around the target's behavior, technology and response patterns.*

An evolution of ffuf/dirb: instead of blind brute-force, Origami **calibrates before attacking**, does **additive fingerprinting** (it enriches the attack, it doesn't segment it) and **folds** its strategy as technology patterns appear — by header, cookie, response, directory or file. Every finding becomes evidence that re-weights the modules and expands the wordlist in real time. Over time, it learns across targets.

Intended use:

```bash
origami http://www.example.com
```

---

## Locked decisions

| Decision | Choice |
|---|---|
| Language | **Python 3.11+** (`asyncio` + `httpx`), with a clean engine/brain boundary so only the engine needs rewriting later if throughput demands it |
| Detection | **Hybrid, in order:** start with a **curated overlay** (~10-15 hand-written techs) so the engine isn't blocked; **multi-source ingestion** (Wappalyzer fork `tunetheweb`, nuclei tech-templates, the 0xdf 404-pages catalog, favicon-hash DBs) lands later. The overlay always precedes the ingested layer and receives the learning write-back |
| ML strategy | **Phased (algorithm → memory → trained model)** — first only algorithms (simhash/rules, no trained model); then cross-target memory (k-NN + association mining); a trained model **only when there's data** (FP-classifier, n-gram, bandit under budget). Detail in §3.8 |
| Shortscan | **Gated auto-trigger** (IIS confirmed **and** the tilde leaks) + `--shortscan`/`--no-shortscan` flags; drives the Go binary at `~/go/bin/shortscan` |
| Test/eval | **Local harness** (fake server: IIS soft-404, wildcard, custom 404, rate-limit) + a north-star **hits/request vs ffuf** metric |
| MVP scope | **Lean adaptive core** — per-context calibration + fingerprint + evidence bus + priority scheduler + FP classifier + IIS/PHP modules + SQLite + JSON output |

---

## 1. Design principles

1. **Calibrate before attacking.** No attack without confirming the channel. The baseline measures the real behavior of 404/403/401/500, and only then does the scan begin.
2. **Additive, per-path-prefix fingerprint.** The real web is legacy + proxy + multiple apps on one host. `/api/` can be Node while `/portal/` is classic ASP. Fingerprint enriches, it doesn't segment, and it's kept **per prefix**.
3. **Evidence bus.** Header, cookie, shortscan, JS, robots, sitemap, favicon, git leak — everything becomes `Evidence{source, evidence, confidence}` feeding the decision engine.
4. **Interpretability > black box.** Most of the "adaptation" is deterministic rule, externalized in YAML (nuclei-style), not ML. ML only enters where rules can't, and always justifiable in a report.
5. **Clean engine ↔ brain boundary.** Engine = fast request worker pool. Brain = orchestration + decision + learning. They exchange messages. If throughput becomes the bottleneck, rewrite only the engine (Go/Rust) without touching the brain.
6. **Don't invent signatures — ingest a maintained catalog.** Tech fingerprints, 404 pages and favicon hashes come from updatable community sources (Wappalyzer fork, nuclei, 0xdf-404, FingerprintHub). Origami's KB = ingested baseline **+** own overlay. Trades eternal maintenance for `git pull` upstream, and the overlay is where accumulated (incl. cross-target) knowledge is written.

## 2. Architecture

```
                 ┌──────────────────────────── BRAIN ───────────────────────────────────┐
                 │                                                                       │
  calibration ─▶ │  TargetProfile  ◀── EvidenceBus ◀── Fingerprint                       │
   (baseline)    │       │                  ▲                                            │
                 │       ▼                  │                                            │
                 │  KnowledgeBase(YAML) ─▶ Scheduler(priority queue) ─▶ prioritized batch│
                 │       ▲                                              │                 │
                 │   Memory(SQLite)  ◀───────── feedback ──────────────┤                 │
                 └───────┼──────────────────────────────────────────────┼───────────────┘
                         │                                              ▼
                 ┌───────┴────────────────── ENGINE (request) ──────────────────────────┐
                 │  worker pool (asyncio+httpx) ─▶ ResponseClassifier ─▶ hits/FP         │
                 └───────────────────────────────────────────────────────────────────────┘
```

**Pipeline:** `calibration → TargetProfile` → `brain queries KB + memory and emits a prioritized batch` → `engine fires and classifies` → `a confirmed hit updates the profile + triggers fold rules` → `the updated corpus feeds future runs`.

## 3. Components

### 3.1 Baseline / Calibration (`core/baseline.py`)
The heart. It builds a **per-context non-existence profile** (per directory and per extension class), not a single global number — soft-404 varies by folder and extension.
- Fires guaranteed-nonexistent probes with distinct shapes: plain random, random + each extension class to be tested, deep path, path with a special char.
- Compares across multiple dimensions: status, content-length, word/line count, content-type, redirect target, and a **simhash of the normalized body** (strips CSRF tokens, nonces, timestamps, WAF support-IDs — dynamic noise that breaks length-only comparison).
- Detects **wildcard routing** and path **case-sensitivity** (case-insensitive is already a strong Windows/IIS signal).
- **Redirect handling:** a self-redirect (`/x` → `/x/`, http→https) and a constant-target redirect (every miss → `/action/login`, an auth wall) are both recognized as a single soft-404 pattern instead of "every path is a unique hit".

**Prior art (don't reinvent):** calibration borrows the autocalibration logic of **ffuf `-ac/-acc`** (clustering wildcard responses), **feroxbuster** and **gobuster**. Origami extends it to a **per-context profile** (per directory + extension class) instead of a global filter — exactly those tools' weak spot.

### 3.2 Fingerprint (`core/fingerprint.py`)
Additive, confidence-weighted, **per path prefix**. Signals come from the curated overlay (and, later, ingested catalogs). Signals:
- **Headers:** `Server`, `X-Powered-By`, ordering/casing, HTTP version.
- **Cookies:** `ASP.NET_SessionId`, `.AspNetCore`, `JSESSIONID`, `PHPSESSID`, `laravel_session`, `ci_session`, `connect.sid`.
- **Forced error pages:** force 400/403/404/500 and fingerprint the body. Basis: the **0xdf default-404-page catalog** (<https://0xdf.gitlab.io/cheatsheets/404>) — maps a default error body → stack (nginx, Apache, IIS, Flask, Django, FastAPI, Gin/Fiber, PHP-FPM, Laravel, Symfony, Express, Next.js, Tomcat, Spring Boot, Jetty, Rails, Sinatra, ASP.NET, Blazor). It is a *fingerprint-by-error-page* catalog, not a soft-404 guide.
- **Favicon hash (mmh3):** one of the strongest, most under-used signals — maps a whole product. Basis: FingerprintHub and favicon-hash DBs.
- **WAF / block-page detection:** F5 BIG-IP ASM, Cloudflare, Imperva, Akamai, ModSecurity, Sucuri, etc., by body signature + headers + cookies. A block page is never a finding and the WAF shows in the fingerprint.
- **Passive discovery:** robots.txt, sitemap.xml.

### 3.3 Evidence Bus + TargetProfile (`core/evidence.py`)
Everything becomes typed evidence and the profile is the target's persistent state (also the source of cross-target learning). The "bus" is deliberately simple: a scored list + a reducer that re-weights `tech_scores` — no pub/sub, no message queue.

### 3.4 Knowledge Base (`brain/overlay.yaml`)
Externalized rules, extensible without touching code. `tech → signals → extensions/wordlists/paths/folds`.

```yaml
- tech: iis
  signals:
    - {type: header, name: server, match: "microsoft-iis", weight: 60}
    - {type: cookie, match: "ASP.NET_SessionId", weight: 80}
  on_confirm:
    extensions: [".aspx", ".asmx", ".ashx", ".asp", ".config", ".asax", ".ascx"]
    priority_paths: ["web.config", "trace.axd", "elmah.axd", "bin/", "App_Data/"]
    folds: ["shortscan"]            # gated: only fires if the tilde leaks
```

### 3.5 Scheduler (`core/scheduler.py`)
Priority queue. Combines evidence and emits batches:
```
ASP.NET + ADMIN~1 + api/v1  →
  P0: memory / js / robots / backup / shortscan seeds   (evidence-derived)
  P1: word × tech extensions
  P2: word × base extensions + dir probe
```
A shortscan/JS-derived candidate has top priority (much higher hit probability than a wordlist guess).

### 3.6 Response Classifier (`core/response_classifier.py`)
Decides real hit vs soft-404. Engine truth: 404/400 are never hits; a redirect that leaves the requested path is dropped; WAF block pages are dropped. A candidate is a hit when it falls outside the calibrated miss profile for its context (simhash distance + status + redirect kind). Multi-modal soft-404 hosts are handled by **random-sibling verification** (verify a surprising hit with a same-shape random probe; learn the signature). User **filters** (`-mc/-fc/-ms/-fs` + body filters `--filter-word-count/-line-count/-regex/-similar-to`) are presentation-only — they never change what gets scanned/recursed.

### 3.7 Discovery fold modules (`modules/`)
Triggered by evidence/calibration. Each **emits high-confidence seeds**; it doesn't compete with the brute.
- **tech overlay** — per-stack extension/path packs (IIS, PHP, Apache, nginx, Tomcat, Express, Laravel, WordPress, Django).
- **discovery/shortname.py** — IIS 8.3 shortscan; see §4.
- **discovery/js_parser.py** — harvests endpoints/routes from HTML/JS; follows webpack chunks and **reconstructs source maps** (`sourcesContent` → the original un-minified routes/params the bundle buried), skips vendor libraries, picks up the RequireJS `data-main` bundle; harvests query/template **parameter names**. Any `text/*` response is mined, not just known extensions.
- **discovery/backups.py** — `.git/`, `.svn/`, `.DS_Store`, `.swp`, `~`, `.bak`, `.old`; generates variations of discovered names. A "backup" byte-identical to the original (same length + simhash) is dropped as a catch-all echo, not a disclosure.
- **discovery/vcs.py** — VCS/metadata **tree reconstruction**: a leaked `.git/index` (DIRC), `.DS_Store`, or `.svn/wc.db` (SQLite) is parsed and every file it lists is fetched from the webroot — one leak becomes the whole repo/tree. On-host, capped.
- **discovery/robots.py** — robots.txt + sitemap.xml (follows nested `<sitemapindex>`) **plus RSS/Atom feeds and sitemap-index variants** (`/feed`, `/rss`, `/atom.xml`, `sitemap_index.xml`).
- **discovery/apidocs.py** — OpenAPI/Swagger + JSON:API spec discovery and folding; also ingests a spec handed in directly (`--openapi URL|FILE`).
- **discovery/apiver.py** — API **version pivot**: a confirmed `/api/v1/…` endpoint → its adjacent versions (`v0`/`v2`/`v3`), the legacy/next surface still wired in the backend.
- **discovery/mutate.py** — naming-convention **mutation**: `/user` → `/users`, `report1` → `report2`, `data.json` → `data.xml` — high-signal siblings from a developer's naming habit.
- **discovery/buckets.py** — cloud-storage discovery: S3/GCS/Azure bucket references in the target's code are surfaced free; with `--buckets`, each is probed at its read-only listing endpoint for public listability + exposed objects.
- **discovery/wellknown.py / graphql.py / clientapp.py / methods.py** — `.well-known/` (OIDC/OAuth + security.txt), GraphQL introspection, service-worker/web-app-manifest, HTTP-method (OPTIONS) discovery. On a **405**, the `Allow` header is surfaced free, and `--probe-405` replays with POST/PATCH (empty & `{}` body, never PUT/DELETE) to reveal the accepted write method.
- **discovery/wayback.py** — historical-URL sourcing (`--wayback`/`--gau`): Wayback CDX + Common Crawl + **urlscan.io + AlienVault OTX** natively (all four concurrent, keyless), or the `gau`/`waybackurls` binary; fetched in the background and folded as candidates.
- **config → seeds** — a config/`.env`/`appsettings` read for secrets is also mined for the same-host paths it references, which become scanned seeds (`config` origin).
- **modules/secrets.py** — credential detection inside high-value bodies (provider keys, private keys, JWTs, DB URIs, guarded generic `api_key=`).
- **modules/leaks.py** — content intelligence: stack traces, framework debug pages, internal IP/host disclosure (tagged `leak`).
- **modules/paramfuzz.py** — reflected-parameter discovery (`--params`): harvested + common names, batched canaries, control-param FP guard.
- **modules/vhost.py** — virtual-host discovery (`--vhost`): Host-header fuzzing on the target IP.
- **modules/bypass403.py** — 403/401 bypass battery (`--bypass-403`, `--bypass-headers`, `--bypass-prefixes`): path/header/method tricks plus a **matrix-param management bypass** (`/<route>/;/actuator/*`) carried on curated + discovered + operator-supplied route mounts.
- **modules/cache_poison.py** — web cache poisoning (`--cache-poison`): passive cache-layer fingerprint + safe unkeyed-input probing (every probe rides a throwaway cache-buster, never the real key); reports the unkeyed+reflected+cacheable primitive without poisoning production.
- **modules/session.py** — authenticated-scan sanity check: warns when `-H` credentials don't actually authenticate.
- **modules/waf.py** — WAF/block-page detection (see §3.2).
- **Vocabulary folding:** the target's own names + extensions (from JS/robots/sitemap + the host/subdomain/path) become scan vocabulary.
- **Parent-directory recursion:** a deep hit (`/app/x/views/y.html`) reveals `/app/x/` and `/app/x/views/`, which the wordlist+vocab then explore.
- **WAF-adapt:** 429 / signed-403 / captcha → slow down, jitter (the backoff is already in the engine).

### 3.8 Memory / learning (`brain/memory.py` + `memory.sqlite`)

> *The differentiator isn't training a model — it's **memory + retrieval + statistics**.* Hence the honest split: cheap, interpretable algorithms enter early; a trained model only once there's labeled data to justify it.

**Algorithms (early, interpretable):**
- **simhash/cluster** for soft-404 (feeds the classifier).
- **constraint-filter** for shortscan Regime 1 (see §4).
- **k-NN over the fingerprint vector** — corpus `(target fingerprint → paths that existed)`; "the N most similar targets had these paths, prioritize them". It's RAG for fuzzing, **the "gets better each run"**, and it's algorithmic, not trained.
- **association mining** — "when `/backup/` exists, `/.git/` exists with confidence X", mined from the corpus.
- **n-gram / Markov** to reconstruct a truncated shortscan name (Regime 2): `apiint` → `apiintegracao`.

**Trained model (deferred until there's data):**
- **FP-classifier (logistic/GBM)** over the §3.6 features — only after early runs label hits/soft-404.
- **contextual bandit (Thompson sampling)** — **only matters under tight budget** (WAF/rate-limit); without that you test everything and ranking is irrelevant. Optimizes **hits per request**.
- **LLM / neural net in the hot loop: no** — latency, cost, hallucinated paths.

### 3.9 Knowledge Base: ingestion + overlay (future)
The KB will have **two layers**:
- **Ingested layer (upstream):** adapters convert `wappalyzer technologies/*.json` (fork `tunetheweb`), nuclei tech-templates and the 0xdf-404 catalog → rules + favicon-hash tables. Updatable via `origami update`. No manual signature maintenance.
- **Overlay layer (ours):** `brain/overlay.yaml` — curated rules + what cross-target learning discovers. It's the versioned reference and **wins over the ingested layer on conflict**.
- **Licensing:** record each source's license (Wappalyzer fork, SecLists MIT, nuclei) and respect the terms.

### 3.10 Operational safety — rate-limit / WAF (`core/httpclient.py`)
First-class and implemented: a configurable concurrency cap; **AIMD adaptive concurrency + delay floor** (a 429/503 both halves the in-flight ceiling and raises a shared delay, clean responses ramp back); an **aggregate token-bucket rate cap** (`--rate`) and a per-request floor (`--delay`) + jitter; **`Retry-After` honored exactly** on 429/503 (the server's own wait, capped); **User-Agent rotation** (`--rotate-ua`) and **proxy-pool rotation** (`--proxy-file`) to spread a per-UA/per-source heuristic; **HTTP/2** (`--http2`, optional `h2`); a hostile-body size cap. Transport errors (timeout/DNS/reset) retry but do NOT count as throttle, so a few dead URLs can't collapse a healthy scan. The bandit that **optimizes** budget under throttle is §3.8. Goal: don't get blocked and keep the scan within what the target can take.

### 3.11 Scope and recursion (`core/scanner.py`)
Recursion-depth cap, same-host/scheme restriction, path-exclusion, and a per-run request ceiling. Two distinct scopes (`core/scope.py`): **parse scope** (same registrable domain — reads the org's own CDN JS) vs **scan scope** (the exact target host — `--scope site` to also scan the CDN). Canonical root redirects (http→https, www) are auto-followed; harvested paths join from the host root so a base path like `/lms/` never doubles.

## 4. Shortscan module (8.3 / tilde) — the best IIS fold

The tilde **collapses the search space from impossible to tractable**: it leaks a prefix of up to 6 chars + a 3-char truncated extension, plus `~N` on collision.

**Calibration gate:** only enabled if IIS is confirmed **and** the tilde leaks. Origami gates on shortscan's own vulnerability check (the tool emits one status line per recursed directory; the target is vulnerable if **any** is).

**Two regimes:**
- **Regime 1 — in the wordlist (deterministic, huge gain, no ML):** the short name becomes a *constraint filter*. `ADMINI~1.ASP` → only test entries matching `^admini` of the `asp` family. 100k entries → ~20 candidates. Plus the raw 8.3 name (`ADMINI~1`) and the prefix as a file (with tech extensions) and a directory.
- **Regime 2 — not in any wordlist (light intelligence):** prefix > 6 chars and uncommon → an **n-gram/Markov generator** conditioned on the prefix + a corpus (the target's own vocabulary + cross-target memory). `apiint` → `apiintegracao`, `apimensagem`, etc.

**Bidirectional loop (the origami folding):** confirming `ADMINI~1.ASP → administration.aspx` is labeled data `(truncated → real full name)`. Accumulated across targets, the Regime-2 generator improves each scan.

**Truncated → extension-family table** (fixed lookup): `ASP → {.asp,.aspx}` · `ASA → {.asax,.asa}` · `ASM → {.asmx}` · `ASH → {.ashx}` · `ASC → {.ascx}` · `CON → {.config}` · `CS → {.cs}`.

**Integration:** drives `~/go/bin/shortscan` with `--output ndjson`, parses the result, and turns each leaked name into prioritized seeds. Flags `--shortscan` (force) / `--no-shortscan` (disable).

## 5. Tech stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| HTTP engine | `asyncio` + `httpx` (bounded-concurrency worker pool) |
| Knowledge base | `PyYAML` |
| Response similarity | own simhash/LSH |
| Favicon hash | `mmh3` |
| Persistence | `sqlite3` (stdlib) |
| Output | JSON + HTML; CLI with `rich` |
| External | `shortscan` (Go, `~/go/bin/shortscan`) |

**Why not Go/Rust yet:** Origami's edge is the *brain* (k-NN, association, n-gram, bandit), trivial in Python; raw throughput isn't the bottleneck. The clean boundary lets the engine be ported later.

## 6. Directory structure

```
origami/
  cli.py                      # entrypoint: origami <url> [<url> ...]
  banner.py  control.py
  core/
    scanner.py                # orchestrates the pipeline
    httpclient.py             # async worker pool + backoff
    baseline.py               # per-context calibration
    fingerprint.py            # additive per-prefix fingerprint (+ favicon, WAF)
    evidence.py               # Evidence + ContextBaseline + TargetProfile
    scheduler.py              # priority queue + vocabulary folding
    response_classifier.py    # hit vs soft-404 + filters + tags
    normalize.py  scope.py  resume.py
  modules/
    waf.py  secrets.py  leaks.py  paramfuzz.py  vhost.py  bypass403.py  cache_poison.py  session.py
    discovery/   robots.py  js_parser.py  backups.py  shortname.py  apidocs.py
                 wellknown.py  graphql.py  clientapp.py  methods.py  wayback.py  vcs.py  buckets.py  apiver.py  mutate.py
  brain/
    overlay.yaml              # curated KB
    memory.py                 # SQLite corpus, k-NN, association, host-normalized
    ngram.py                  # shortscan Regime-2 completer
    bandit.py  kb.py  ingest/
  wordlists/     base.txt  403-headers.txt
  output/        json_report.py  html_report.py  graph.py  artifacts.py  ui.py
tests/
  fakeserver/    server.py    # IIS soft-404, wildcard, custom 404, rate-limit
  benchmark/     bench_folds.py
  test_core.py
```

## 7. Status & roadmap

**Implemented and tested** (fake server 404/soft-404/wildcard + real targets, 270+ unit tests + an end-to-end integration scan):
- per-context calibration (simhash soft-404, wildcard, case-sensitivity, redirect-kind);
- additive fingerprint + folds (headers/cookies + **favicon mmh3**, **WAF detection**, and a **default-error-page → stack catalogue** that fingerprints nginx/Apache/IIS/Tomcat/Jetty/Express/Spring-Boot/Django/Flask/Laravel/ASP.NET/PHP header-independently — the hard CDN/WAF case);
- async engine + backoff; soft-404 classifier with **`-mc/-fc/-ms/-fs`** status/size filters plus **body filters** (`--filter-word-count`/`--filter-line-count`/`--filter-regex`/`--filter-similar-to`, feroxbuster-style — word/line counts and the body simhash ride every probe, so those filters apply to *all* findings; only `--filter-regex` keeps the body; 404/400 dropped by default) and random-sibling verification of surprising hits;
- scoped recursion + parent-directory recursion from deep hits;
- **shortscan** (gate + constraint-filter + raw 8.3 + prefix-as-dir/file + **n-gram Regime-2 completer**, primed by **cross-target name memory** so 8.3 prefixes reverse into names seen on past targets — the §4 learning loop; 5xx guesses and case-dupes filtered);
- **recon phase** (single pass feeding the dynamic wordlist): **js_parser** (JS→JS chunks/sourcemaps, skips vendor, `data-main`) + **service worker** (precache) + **web app manifest** + **CSP/Link header** endpoints + **parameter** intel; **backups/VCS**; **robots/sitemap** (follows nested `<sitemapindex>` files); **OpenAPI/Swagger + JSON:API** spec discovery; **`.well-known/`** (OIDC/OAuth auth-endpoint folding + security.txt); **GraphQL introspection** (confirms the endpoint + harvests schema fields); **HTTP method discovery** (OPTIONS → flags PUT/DELETE/TRACE/PATCH/WebDAV); **403/401 bypass** (`--bypass-403` + `--bypass-headers` + `--bypass-prefixes`: path/header/method tricks and a **matrix-param management bypass** `/<route>/;/actuator/*` on curated/discovered/operator route mounts, surviving 2xx-with-content reported); **content intelligence** (`leaks.py`: stack traces, framework debug pages, internal IP/host disclosure, tagged `leak`); **parameter discovery** (`--params`: reflected-canary fuzzing of harvested + common names); **historical URLs** (`--wayback`/`--gau`: Wayback CDX + Common Crawl + urlscan.io + AlienVault OTX, background-fetched); **virtual-host discovery** (`--vhost`); **origin-IP discovery + IP-based WAF bypass** (`--origin`: resolve A/AAAA + candidate origin IPs via keyed OSINT (Shodan/SecurityTrails/Censys) or keyless crt.sh, then request each IP directly with the target Host — an edge-blocked path that opens on an IP is a real bypass); **web cache poisoning** (`--cache-poison`: passive cache-layer fingerprint + safe unkeyed-input probing on throwaway cache-busters, reporting the poisoning primitive without touching the real key); **method discovery** (a 405 surfaces its `Allow` header free; `--probe-405` replays POST/PATCH with empty/`{}` body to reveal the accepted write method, never PUT/DELETE); **VCS/metadata tree reconstruction** (a leaked `.git/index`/`.DS_Store`/`.svn/wc.db` enumerated into its whole file tree); **source-map reconstruction** (`sourcesContent` mined for the original routes); **API version pivot** (`/api/v1` → `v0`/`v2`/`v3`); **naming-convention mutation** (`/user` → `/users`, `data.json` → `data.xml`); **cloud bucket discovery** (`--buckets`: S3/GCS/Azure refs surfaced free, listability probed on demand); **config → seeds** (same-host paths inside read configs become candidates); **feeds & sitemap variants** (RSS/Atom + `sitemap_index`); **directory-listing–aware harvest** (parse the autoindex, probe only what it hides);
- **vocabulary folding** (names+extensions from references + host/subdomain/path);
- **SQLite memory**: **k-NN over fingerprint vectors** + **association mining** + cross-target priming + `--history`;
- **multi-source KB ingestion** (`--update`: Wappalyzer catalog → KB rules, overlay wins on conflict);
- **mid-scan resume** (`--resume`): checkpoint the loop state per directory, continue an interrupted run with no re-fingerprinting;
- **contextual bandit** (`--economy`): Beta-Thompson candidate ranking by learned hit-rate, conditioned on confirmed techs, for request economy under WAFs;
- scope discipline (`--scope host|site` with a **public-suffix-aware** `same_site` that splits shared-hosting co-tenants, canonical-redirect auto-upgrade, host-root joins, `-x/--exclude` safety rail, `-X/--ext` + `--ext-only` manual extensions, `--exclude-ext` static-asset filter);
- pentest plumbing: custom headers (`-H`, authenticated scans) with an **auth-wall sanity check**, `-A` user-agent + **`--rotate-ua`**, `--proxy` and **`--proxy-file`** rotation, **`--replay-proxy`/`--replay-codes`** (send only confirmed hits to Burp/ZAP for a clean sitemap), **`--http2`**, **`Retry-After`** honoring, AIMD adaptive concurrency + body-size cap, **`--time-limit`** wall-clock budget (alongside `--max-requests`), **stdin targets** (`cat urls | origami` or `-l -`), explicit spec ingest (`--openapi`), memory hygiene (www/apex normalization, content-hashed bundle-name filtering + ≥2-host n-gram floor, **`--forget`**/**`--forget-noise`**);
- **multi-target** scanning (`-l/--list`, multiple URLs, or `-u/--url` to keep the target last), each scanned clean; **`--deep`** preset turns on the aggressive discovery bundle at once;
- **endpoint graph** (`--graph`): provenance edges (js/robots/apidocs → target) → self-contained SVG + DOT, with orphan/hidden-endpoint detection;
- output: live `rich` dashboard (streaming findings, status bar, `==> directory`, semantic tags, origin colors) with a dependency-free fallback; **JSON + HTML report + `--out`** (params.txt/urls.txt/findings.json); installable package (`pip install -e .` → `origami`).

**Next:**
- favicon/tech DBs beyond Wappalyzer (nuclei tech-templates, FingerprintHub favicon hashes) into the ingestion layer;
- a deferred trained FP-classifier once the corpus is large enough to label.

## 8. Testing & evaluation

- **Local harness (`tests/fakeserver/`):** a server emulating IIS soft-404, wildcard routing, custom 404, case-insensitive paths and rate-limit. Lets baseline/classifier be developed deterministically, without hitting a real target.
- **Benchmark (`tests/benchmark/`):** scenarios measuring **hits/request** and **FP-rate** vs ffuf `-ac`. The proof that adaptive > blind — without it, "it's better" is just a claim.
