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
Decides real hit vs soft-404. Engine truth: 404/400 are never hits; a redirect that leaves the requested path is dropped; WAF block pages are dropped. A candidate is a hit when it falls outside the calibrated miss profile for its context (simhash distance + status + redirect kind). Multi-modal soft-404 hosts are handled by **random-sibling verification** (verify a surprising hit with a same-shape random probe; learn the signature). User **filters** (`-mc/-fc/-ms/-fs`) are presentation-only — they never change what gets scanned/recursed.

### 3.7 Discovery fold modules (`modules/`)
Triggered by evidence/calibration. Each **emits high-confidence seeds**; it doesn't compete with the brute.
- **tech overlay** — per-stack extension/path packs (IIS, PHP, Apache, nginx, Tomcat, Express, Laravel, WordPress, Django).
- **discovery/shortname.py** — IIS 8.3 shortscan; see §4.
- **discovery/js_parser.py** — harvests endpoints/routes from HTML/JS; follows webpack chunks and source maps, skips vendor libraries, picks up the RequireJS `data-main` bundle; harvests query/template **parameter names** as pentest intel.
- **discovery/backups.py** — `.git/`, `.svn/`, `.DS_Store`, `.swp`, `~`, `.bak`, `.old`; folds aggressively, generating variations of already-discovered names.
- **discovery/robots.py** — robots.txt + sitemap.xml.
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
First-class: configurable concurrency cap, jitter, and **adaptive backoff** on 429 / signed-403 / captcha / connection reset; light UA/header rotation. The bandit that **optimizes** budget comes later (§3.8). Goal: don't get blocked and keep the scan within what the target can take.

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
    normalize.py  scope.py
  modules/
    waf.py
    discovery/   robots.py  js_parser.py  backups.py  shortname.py
  brain/
    overlay.yaml              # curated KB
    memory.py                 # SQLite corpus, k-NN, association
    ngram.py                  # shortscan Regime-2 completer
    kb.py
  wordlists/     base.txt
  output/        json_report.py  html_report.py  artifacts.py  ui.py
tests/
  fakeserver/    server.py    # IIS soft-404, wildcard, custom 404, rate-limit
  benchmark/     bench_folds.py
  test_core.py
```

## 7. Status & roadmap

**Implemented and tested** (fake server 404/soft-404/wildcard + real targets, 100 unit tests):
- per-context calibration (simhash soft-404, wildcard, case-sensitivity, redirect-kind);
- additive fingerprint + folds (headers/cookies + **favicon mmh3**, **WAF detection**, and a **default-error-page → stack catalogue** that fingerprints nginx/Apache/IIS/Tomcat/Jetty/Express/Spring-Boot/Django/Flask/Laravel/ASP.NET/PHP header-independently — the hard CDN/WAF case);
- async engine + backoff; soft-404 classifier with **`-mc/-fc/-ms/-fs`** filters (404/400 dropped by default) and random-sibling verification of surprising hits;
- scoped recursion + parent-directory recursion from deep hits;
- **shortscan** (gate + constraint-filter + raw 8.3 + prefix-as-dir/file + **n-gram Regime-2 completer**);
- **recon phase** (single pass feeding the dynamic wordlist): **js_parser** (JS→JS chunks/sourcemaps, skips vendor, `data-main`) + **service worker** (precache) + **web app manifest** + **CSP/Link header** endpoints + **parameter** intel; **backups/VCS**; **robots/sitemap** (follows nested `<sitemapindex>` files); **OpenAPI/Swagger + JSON:API** spec discovery; **`.well-known/`** (OIDC/OAuth auth-endpoint folding + security.txt); **GraphQL introspection** (confirms the endpoint + harvests schema fields); **HTTP method discovery** (OPTIONS → flags PUT/DELETE/TRACE/PATCH/WebDAV); **403/401 bypass** (`--bypass-403`: path/header/method tricks, surviving 2xx-with-content reported);
- **vocabulary folding** (names+extensions from references + host/subdomain/path);
- **SQLite memory**: **k-NN over fingerprint vectors** + **association mining** + cross-target priming + `--history`;
- **multi-source KB ingestion** (`--update`: Wappalyzer catalog → KB rules, overlay wins on conflict);
- **mid-scan resume** (`--resume`): checkpoint the loop state per directory, continue an interrupted run with no re-fingerprinting;
- **contextual bandit** (`--economy`): Beta-Thompson candidate ranking by learned hit-rate, conditioned on confirmed techs, for request economy under WAFs;
- scope discipline (`--scope host|site`, canonical-redirect auto-upgrade, host-root joins, `-x/--exclude` safety rail, `-X/--ext` + `--ext-only` manual extensions);
- pentest plumbing: custom headers (`-H`, authenticated scans), `-A` user-agent, `--proxy` (Burp/ZAP), AIMD adaptive concurrency + body-size cap;
- **multi-target** scanning (`-l/--list`, multiple URLs), each scanned clean;
- **endpoint graph** (`--graph`): provenance edges (js/robots/apidocs → target) → self-contained SVG + DOT, with orphan/hidden-endpoint detection;
- output: live `rich` dashboard (streaming findings, status bar, `==> directory`, semantic tags, origin colors) with a dependency-free fallback; **JSON + HTML report + `--out`** (params.txt/urls.txt/findings.json); installable package (`pip install -e .` → `origami`).

**Next:**
- favicon/tech DBs beyond Wappalyzer (nuclei tech-templates, FingerprintHub favicon hashes) into the ingestion layer;
- a deferred trained FP-classifier once the corpus is large enough to label.

## 8. Testing & evaluation

- **Local harness (`tests/fakeserver/`):** a server emulating IIS soft-404, wildcard routing, custom 404, case-insensitive paths and rate-limit. Lets baseline/classifier be developed deterministically, without hitting a real target.
- **Benchmark (`tests/benchmark/`):** scenarios measuring **hits/request** and **FP-rate** vs ffuf `-ac`. The proof that adaptive > blind — without it, "it's better" is just a claim.
