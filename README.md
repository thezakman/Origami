# Origami

[![Python](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/github/license/thezakman/Origami?color=green)](LICENSE)
[![Tests](https://github.com/thezakman/Origami/actions/workflows/tests.yml/badge.svg)](https://github.com/thezakman/Origami/actions/workflows/tests.yml)
[![Last commit](https://img.shields.io/github/last-commit/thezakman/Origami)](https://github.com/thezakman/Origami/commits/main)
[![Stars](https://img.shields.io/github/stars/thezakman/Origami?style=flat)](https://github.com/thezakman/Origami/stargazers)

> Adaptive content discovery engine that **folds its strategy around the target's behavior, technology and response patterns.**

Origami is an evolution of `ffuf`/`dirb`: instead of brute-forcing blindly, it **calibrates before attacking**, fingerprints the stack (additively, per path-prefix), and then *folds* its strategy as evidence appears — by header, cookie, response, directory or file. Every finding becomes evidence that re-weights the modules and expands the wordlist in real time. With each run it also learns across targets.

```
   /\                                 .
  /  \        .                      /_\
 / /\ \  _ __ _  __ _  __ _ _ __ ___  _
/_/  \_\| '__| |/ _` |/ _` | '_ ` _ \| |
\ \  / /| |  | | (_| | (_| | | | | | | |
 \ \/ / |_|  |_|\__, |\__,_|_| |_| |_|_|
  \  / adaptive |___/ content discovery
   \/
```

## Why it's different

Blind brute-forcers (`ffuf`, `dirb`, `dirsearch`) fire one fixed wordlist at every target, bury you in soft-404 noise, and ignore everything the app reveals about itself. **Origami exists to make content discovery *adaptive*** — it calibrates to the target, fingerprints the stack, and folds its strategy around the evidence, so it finds more with fewer requests. Six ideas set it apart:

1. **Calibrate before attacking.** A per-context soft-404 profile — per directory *and* extension class, over a normalized-body **simhash** — means CSRF tokens, nonces, timestamps and WAF support-IDs never masquerade as hits.
2. **The wordlist writes itself from the fingerprint.** Every path-prefix carries its own evidence-weighted stack fingerprint; confirming a technology folds in *its* extensions **and a curated path pack** — WordPress → `wp-admin`/`wp-json`/`xmlrpc.php`, Spring → `actuator/heapdump`/`env`/`gateway`, Laravel → `telescope`/`horizon`, Rails → `rails/info/routes`, Next.js → `_next/*`, and 15 stacks in all. **Additive, never replacing** the base list (real hosts are hybrid), so a generic scanner's wasted `/wp-admin`-at-a-Spring-app guesses become high-value paths fired only where the tech actually is. No other buster selects its wordlist from the live fingerprint.
3. **Discovery compounds.** It reads the target's own code — JS, API specs, robots, headers, archives — then re-reads every file *it* uncovers and recurses the directories they live in. Give it a deep URL (`…/caminho/path/arquivo.pdf`) and it **climbs the path** — scans the file's directory (not the file-as-folder), fetches the file, walks every ancestor dir up to root, and folds each segment into the dynamic wordlist. The more it finds, the more it finds.
4. **Reads content, not just status codes.** Response bodies are mined for credentials, information-disclosure leaks, and reflected parameters graded into **verified injection leads** — a reflection isn't just flagged, it's *proven*: a follow-up breakout probe (`'"<>{{7*7}}`) confirms whether the metacharacters come back **raw** (real XSS sink, `xss-lead`) vs escaped, whether `{{7*7}}→49` (template injection, `ssti-lead`), and whether a canary lands in the `Location` header (open-redirect, `redirect-lead`) or any response header. It tells you *what's exploitable*, not just a wall of `200`s.
5. **Stays alive under a WAF.** Per-context calibration, AIMD backoff, honored `Retry-After`, UA/proxy rotation and a learned request-economy bandit keep it under the radar and spend a tight budget on the hits most likely to land.
6. **Gets smarter every run — and tracks change over time.** A SQLite corpus, k-NN over fingerprint vectors and a character n-gram completer prime each new scan from everything past ones turned up. `--diff` compares a scan against the last stored run of the same host and reports what **appeared, disappeared, or newly opened up** (`403 → 200`) — recon-over-time / attack-surface monitoring, not just a one-shot.

## Demo

A real run against the test target — fingerprint, findings streaming live, a **403 → 200 bypass**, and a leaked **`.env`** (AWS key + DB URI + an internal-host leak):

![Origami scanning a target: live dashboard, fingerprint, a 403→200 bypass and a leaked .env](docs/demo.svg)

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/thezakman/Origami
cd Origami
python3.11 -m venv .venv
.venv/bin/pip install -e .
```

This installs the `origami` command into the venv (with `rich` for the live dashboard). Or run without installing: `PYTHONPATH=. python3 -m origami ...`. For HTTP/2 support (`--http2`) also install the optional extra: `.venv/bin/pip install -e '.[http2]'`.

## Usage

```bash
origami https://example.com                 # scan one target
origami https://example.com/app/            # scan under a base path
origami -l targets.txt --out results/       # scan a list, artifacts per host
origami -F --gau --bypass-403 -u https://…  # -u/--url keeps the target last, swap only it between runs
origami --deep -w big -u https://…          # maximal: aggressive folds + the big wordlist
```

Common flags:

| flag | meaning |
|---|---|
| `-u`/`--url URL` | target base URL as a flag (repeatable) — lets you keep the URL last and swap only it between runs; same as the positional argument |
| `--deep` | aggressive-discovery preset: `--bypass-403 --cache-poison --probe-405 --buckets --params --wayback --origin` at once (state-changing/off-host probes included). Just `origami --deep -u <url>` |
| `-w NAME\|FILE` | wordlist: a file path or a bundled name — `base` (~540, default) or `big` (~1250, exhaustive). **Repeatable to merge** several. Under `--deep` the base list is always included (`--deep -w custom` = base + custom). Point at SecLists for the widest coverage |
| `-X php,asp,bak` | extensions to brute-force, added to the fingerprint-detected ones (repeatable) |
| `--ext-only` | use only the `-X` extensions (ignore fingerprint-detected + learned) |
| `-d N` | recursion depth (default 1) |
| `-c N` / `-t S` | concurrency / timeout |
| `--rate RPS` | cap the **aggregate** request rate (req/s across all workers) — the knob for a WAF's req/s threshold; unlike `--delay` it doesn't scale with concurrency |
| `--delay S` | fixed delay before every request (stealth / rate-sensitive targets) |
| `-k` | skip TLS verification |
| `--legacy-tls` | lower the OpenSSL security level (`SECLEVEL=1`) for servers with weak DH keys / old ciphers — reaches what curl reaches. **Auto-engaged** on a weak-TLS handshake error even without the flag |
| `-H 'Name: Value'` | extra request header, repeatable (auth/cookies — see below) |
| `-A UA` | override the User-Agent |
| `--rotate-ua` | rotate the User-Agent per request from a pool of real browsers (WAF-evasion; ignored if `-A` is set) |
| `--proxy URL` | route through an intercepting proxy (Burp/ZAP); implies `-k` |
| `--proxy-file FILE` | rotate egress across a list of proxies (one URL per line) — spreads requests so a per-source rate-limit/ban can't pin the scan; implies `-k` |
| `--http2` | negotiate HTTP/2 (matches modern CDNs/WAFs; needs `pip install h2`, else falls back to HTTP/1.1) |
| `-mc` / `-fc` / `-ms` / `-fs` | match/filter status codes & sizes (ffuf-style) |
| `--no-overlays` | disable **tech-overlay** path packs (on by default): when a stack is fingerprinted, Origami folds its high-value paths (`wp-*`, `actuator/*`, `telescope`, `_next/*`…) as root seeds — additive, never replacing the base |
| `--vhost` | virtual-host discovery (Host-header fuzzing on the target IP) |
| `--origin` | origin-IP discovery + **IP-based WAF bypass**: resolve A/AAAA, gather candidate origin IPs (Shodan/SecurityTrails/Censys if their env keys are set, else crt.sh), request each IP directly with the target `Host` — an IP that opens an edge-blocked path is a real bypass (off-host, opt-in) |
| `--params` | parameter discovery: fire harvested + common param names at dynamic endpoints; flag reflected ones and **verify** them — breakout probe confirms raw-vs-escaped (`xss-lead`), `{{7*7}}→49` (`ssti-lead`), canary in `Location`/headers (`redirect-lead`) |
| `--wayback` | fold historical URLs (Wayback CDX + Common Crawl) as seeds — legacy/forgotten paths that may still respond (runs in background during fingerprint) |
| `--gau` | like `--wayback` but prefer your `gau`/`waybackurls` binary (richer providers), native fallback if absent |
| `--bypass-403 [light\|auto\|full]` | on each 403/401, fire bypass tricks; a surviving 2xx is reported. Bare = **auto** (stack-specific families gated by fingerprint); **light** = core only; **full** = exhaustive |
| `--bypass-headers [FILE]` | header-bypass via a wordlist (implies `--bypass-403`): bare flag uses the bundled `403-headers.txt`, or pass your own `Header: value` list (replaces the built-in header axis) |
| `--bypass-prefixes FILE` | route-prefix wordlist (one mount per line, e.g. `rest/v1`) fed to the api-prefix and **matrix-management** (`/<route>/;/actuator/*`) bypass families as extra carriers, on top of the curated seeds and discovered 2xx routes (implies `--bypass-403`) |
| `--replay-proxy URL` / `--replay-codes CODES` | at end of scan, re-issue only **confirmed findings** through a proxy — Burp/ZAP gets a clean sitemap of just the hits (separate from `--proxy`); `--replay-codes` narrows by status |
| `--filter-word-count` / `--filter-line-count` / `--filter-regex` / `--filter-similar-to URL` | body filters (feroxbuster-style): drop responses by word/line count, body regex, or simhash-similarity to a reference page |
| `--time-limit DURATION` | wall-clock budget per target (`30s`/`10m`/`1h` or seconds) alongside `--max-requests`; stops cleanly, leaves a `--resume` checkpoint |
| `--cache-poison [light\|auto\|full]` | web cache poisoning: probe cacheable endpoints for **unkeyed** inputs (`X-Forwarded-Host` & friends) that reflect or change the cached response. **Safe** — every probe rides a throwaway cache-buster, never the real key. Bare = **auto** (only where caching is detected); **light** = core headers; **full** = exhaustive |
| `--cache-headers FILE` | custom unkeyed-header wordlist for `--cache-poison` (`Header: value` lines), added to the built-in set (implies `--cache-poison`) |
| `--probe-405` | the moment a **405** is found, replay with POST (and PATCH if `Allow` lists it — **never** PUT/DELETE) using an empty and a `{}` body to reveal the accepted method. State-changing → opt-in; the `Allow` header is surfaced for free without it |
| `--buckets` | probe S3/GCS/Azure buckets referenced in the target's code for **public listability** (read-only GET, off-host) and enumerate exposed objects. The references themselves are surfaced for free without this flag |
| `--openapi URL\|FILE` | feed an OpenAPI/Swagger or JSON:API doc (URL **or** local file) and fold its endpoints onto the target — works even with `--no-apidocs` (off-host docs server, a client-supplied spec). Aliases: `--swagger`, `--spec` |
| `--scope host\|site` | scan only the host (default) or also same-site CDN |
| `--shortscan` / `--no-shortscan` | force / disable the IIS 8.3 fold (auto when IIS detected) |
| `--no-js` / `--no-apidocs` / `--no-backups` | disable those discovery folds |
| `-x PATTERN` | never request/recurse a path containing PATTERN (safety; repeatable) |
| `--exclude-ext LIST` | drop paths with these extensions from scraping/probing (glob: `jpg,png,css` or `jpg*`) — cuts static-asset noise from listings/JS |
| `--max-folds N` | cap learned-vocabulary names folded in (default 40) |
| `--economy auto\|on\|off` | rank candidates by learned hit-rate (auto: on under a WAF) |
| `-v` / `-vv` | verbose: phases & hits / every request |
| `-F` | show full URLs instead of paths |
| `--json FILE` / `--html FILE` / `--out DIR` | reports & artifacts |
| `--jsonl FILE` | stream findings as JSON Lines, live (use `-` for stdout → pipe into `nuclei`/`httpx`/…) |
| `--graph FILE` | endpoint graph (provenance + orphan/hidden endpoints) → FILE.html + FILE.dot |
| `--no-learn` | don't read/write the cross-target memory |
| `--history` | show past scan history |
| `--diff` | after the scan, show what changed vs the last stored run of this host — **new / gone / newly-accessible** endpoints (`403→200`); recon-over-time / attack-surface monitoring (needs the memory DB) |
| `--forget HOST\|all` | erase cross-target memory for a host (www/apex together) or everything |
| `--forget-noise` | prune content-hashed bundle names (`app.a1b2c3d4.js`, GUIDs, timestamps) from memory — one-off build artifacts that carry no cross-target signal |
| `--resume` | continue an interrupted scan from its checkpoint |
| `--update` | refresh the fingerprint catalog (Wappalyzer) into the KB |
| `-V` | print version |

Run `origami -h` for the full list. Live controls: **`n`** skip the current directory (once one is discovered), **`q`** quit.

### Authenticated scans

Pass session cookies or tokens with `-H` (repeatable) to scan behind a login — they're sent on every request. If you supply credentials but the root still looks like an auth wall (a 401, a redirect to a login page, or a login form at `/`), Origami warns up front that the **session is probably invalid/expired** — and if the session was valid at the start but the root turns into an auth wall by the end, it warns that the session **expired mid-scan** (so you know later results may be partial). Both are false-positive-free — they only fire when you actually supplied credentials:

```bash
origami https://app.example.com \
  -H 'Cookie: session=…; csrf=…' \
  -H 'Authorization: Bearer eyJ…'
```

Route everything through Burp/ZAP to inspect or replay what Origami sends (`--proxy` turns off TLS verification, since intercepting proxies present their own cert):

```bash
origami https://app.example.com --proxy http://127.0.0.1:8080
```

Every scan checkpoints its state (fingerprint, findings, pending directory queue)
after each directory, so an interrupted run — `q`, Ctrl-C, or the `--max-requests`
cap — can be picked up where it left off:

```bash
origami https://example.com --max-requests 2000   # hits the cap, saves a checkpoint
origami https://example.com --resume               # continues; no re-fingerprinting
```

A clean finish removes the checkpoint. The checkpoint records the candidate
offset within the directory in progress, so a resume continues from where it
stopped (not from the directory's start), and findings are URL-deduped on every
checkpoint so repeated resumes never duplicate the report.

## Output

- **Live dashboard** — findings stream as permanent lines under a pinned status bar with phase, req/s, hits, duration, the adaptive concurrency (drops as `⤓conc N` under WAF backoff) and `==> directory` markers.
- **`--out DIR`** writes `findings.json`, `report.html` (browsable, filterable, links to the graph), **`graph.html`** (endpoint topology with an "only hidden" filter) + `graph.dot`, `params.txt` (harvested parameter surface — a drop-in fuzzing list) and `urls.txt`.

The final report groups findings by confidence, tagged by kind (`secret`, `leak`, `xss-lead`, `ssti-lead`, `redirect-lead`, `auth-bypass`, `disclosure`, `config`, `api`, `admin`, `auth`, `source`, `param`, `listing`, `vhost`, `bypass`…) and coloured by where each came from (`js`, `robots`, `backup`, `wordlist`, `memory`, `shortscan`, `wayback`, `bypass403`…):

```
Findings (16)  ·  fingerprint: iis, asp.net
┏━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ code ┃      size ┃ src       ┃ conf ┃ tags       ┃ path                      ┃
┡━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 200  │       15B │ js        │ 0.95 │ api admin  │ /api/v2/admin/secret      │
│ 200  │       32B │ js        │ 0.95 │            │ /reports/export.ashx      │
│ 200  │       52B │ robots    │ 0.95 │ admin      │ /private/dashboard.aspx   │
│ 200  │       21B │ backup    │ 0.95 │ disclosure │ /.git/HEAD                │
│ 200  │       36B │ backup    │ 0.95 │ disclosure │ /.env                     │
│ 403  │       48B │ priority  │ 0.85 │ config     │ /web.config               │
│ 200  │       68B │ wordlist  │ 0.95 │ admin auth │ /admin/login.aspx         │
└──────┴───────────┴───────────┴──────┴────────────┴───────────────────────────┘
```

## What it does

**Recon & discovery**
- Reads the target's own code → seeds: JS (webpack chunks, **source maps reconstructed** — `sourcesContent` mined for the original un-minified routes/params the bundle buried, skips vendor libs, RequireJS `data-main`), service worker, web-app manifest, CSP/`Link` headers, robots/sitemap.
- Deep harvest + bounded recursion rounds (walk → harvest → recurse → harvest…), past the blind depth cap for evidence-based dirs; mines **any `text/*` response** (plain dumps/CSV, not just known extensions).
- **API version pivot** — a confirmed `/api/v1/…` endpoint pivots to its adjacent versions (`v0`/`v2`/`v3`), the legacy/next surface still wired in the backend.
- **Naming-convention mutation** — a confirmed `/user` → `/users`, `report1` → `report2`, `data.json` → `data.xml`: high-signal siblings, not blind brute.
- **Feeds & sitemap variants** — RSS/Atom feeds + sitemap-index variants parsed for content URLs, alongside robots.txt/sitemap.xml.
- **Directory-listing aware** — parses an autoindex and folds its real contents instead of brute-forcing, probing only what `IndexIgnore` hides (`.git/`, `.env`, backups).
- **VCS/metadata tree reconstruction** — a leaked `.git/`, `.svn/` or `.DS_Store` isn't just reported: Origami parses `.git/index` (DIRC), a `.DS_Store`, or a `.svn/wc.db` (SQLite) and fetches every file it lists — one leak becomes the whole repo/tree (source, configs, `.env`, backups). On-host, capped, honours `--exclude`.
- **Cloud bucket discovery** (`--buckets`) — recognizes S3/GCS/Azure buckets referenced in the app's code (free), then probes each for **public listability** and enumerates the exposed objects.
- **API surface** — OpenAPI/Swagger + JSON:API + `.well-known/` (OIDC/OAuth); or hand it a spec with `--openapi URL|FILE` (`--swagger`/`--spec`).
- **GraphQL, mined not just found** — introspection confirms the endpoint, then Origami *reads the schema*: it extracts every query/mutation and **their arguments** (real input surface), flags the **sensitive operations** (`login`/`token`/`senha`/`redefinir`/`lgpd`/`boleto`/…) instead of just counting fields, and — like probing which Swagger paths answer unauthenticated — **sends a benign, no-arg query (queries only, never mutations) for the top operations to see which respond WITHOUT auth**: an op that returns data or gets past the gate is flagged `auth-bypass` (a BOLA / missing-authZ lead).
- **IIS 8.3 shortscan** — drives [`shortscan`](https://github.com/thezakman/shortscan), expands leaks in confidence tiers, and completes truncated names with an n-gram model (`APIINT~1` → `apiintegracao`).
- **Historical URLs** (`--wayback` / `--gau`) — Wayback CDX + Common Crawl + urlscan.io + AlienVault OTX (or your `gau`/`waybackurls` binary), fetched in the background during fingerprint; old query strings also feed `--params`.
- **Virtual-host discovery** (`--vhost`) — Host-header fuzzing on the target IP (registrable-domain + internal names, baseline-calibrated; `.com.br` etc. handled).
- **Origin-IP discovery + IP-based WAF bypass** (`--origin`) — behind a CDN/WAF the public DNS points at the *edge*. Origami resolves the host's A/AAAA records and gathers candidate **origin** IPs (Shodan / SecurityTrails historical-A / Censys when their keys are set, otherwise keyless **crt.sh** Certificate-Transparency siblings), then requests each IP **directly with the target `Host`**. A non-edge IP that **serves `2xx` for that Host** (strongest when the body matches the app the edge serves) — or **opens a path the edge WAF blocks** — is a reachable origin, reported as a bypass lead; `404`/`403`/`5xx` from an unrelated sibling are ignored. Off-host connections; included in `--deep`.

  **OSINT credentials (optional).** The keyed sources are looked up **environment-variable first, then a private config file** — nothing is stored in the repo, logged, or written to reports. Set whichever you have; with none set, `--origin` falls back to keyless crt.sh.

  ```bash
  # option A — environment (CI / one-off)
  export SHODAN_API_KEY=…        export SECURITYTRAILS_API_KEY=…
  export CENSYS_API_ID=…         export CENSYS_API_SECRET=…

  # option B — persistent config file (recommended). Scaffold it (creates the
  # file mode 0600 with a template), then fill in the keys you have:
  origami --init-credentials
  #   → ~/.config/origami/credentials.toml   ($XDG_CONFIG_HOME honored)
  [shodan]
  api_key = "…"
  [securitytrails]
  api_key = "…"
  [censys]
  api_id = "…"
  api_secret = "…"
  ```
  The file is created **private (0600)** by construction; Origami re-warns if it later becomes group/other-readable (keys are bearer secrets). Environment variables always override the file. A committed [`credentials.example.toml`](credentials.example.toml) shows the exact format (copy it to `~/.config/origami/credentials.toml` if you prefer not to use `--init-credentials`).
- **Vocabulary folding** — the org's own names/extensions (from references + host/subdomain/path) become scan vocabulary.

**Analysis & content intelligence**
- **Secrets in bodies** — AWS/Google/GitHub/GitLab/Slack/Stripe keys, modern provider tokens (OpenAI, Anthropic, DigitalOcean, Shopify, Square, Telegram, Azure Storage), private keys, JWTs, DB URIs, guarded `api_key=…` (placeholders rejected); tagged `secret`, redacted.
- **Disclosure leaks** — stack traces (Py/PHP/Java/.NET/Ruby/Node), framework debug pages (Django/Laravel/Symfony/Rails/Flask/ASP.NET), internal IPs/hosts; tagged `leak`. 5xx pages are read because that's where traces live.
- **Parameter discovery + verified injection leads** (`--params`) — fires harvested + common names with unique canaries, grades each reflection by injection context (HTML / attribute / `<script>` / JSON), then **verifies** it with one breakout probe (`'"<>{{7*7}}`): raw metacharacters that survive → `xss-lead` (an *escaped* reflection is downgraded to plain `param`), `{{7*7}}→49` → `ssti-lead`, and a canary reflected into the `Location` header or any response header → `redirect-lead` / header-injection note. One extra request per endpoint, so a reflection becomes a *graded, verified* lead rather than a bare "reflects".
- **Web cache poisoning** (`--cache-poison`) — passively fingerprints the cache layer (Cloudflare/Fastly/Varnish/Akamai/CloudFront, free on every scan), then probes cacheable endpoints for **unkeyed** inputs (`X-Forwarded-Host`, `X-Original-URL`, `X-Forwarded-Scheme`…) that reflect or change the response. A primitive is **confirmed** only when a re-fetch of the *same throwaway key* (no header) still serves the injected content. **Safe by design**: every probe rides a unique `?cb=` cache-buster, so it proves the bug on a sandbox key and never poisons the entry real users hit — `poisonable` (confirmed) vs `cache` (lead). Intensity `light`/`auto`/`full`; custom headers via `--cache-headers`.
- **HTTP method discovery** — one OPTIONS flags dangerous verbs (PUT/DELETE, TRACE/TRACK, PATCH, WebDAV).
- **Endpoint graph** (`--graph`) — a self-contained HTML/DOT graph of who-references-whom that surfaces **orphan/hidden endpoints** (reachable only from JS or a spec).

**403/401 bypass & WAF evasion**
- **`--bypass-403`** — per blocked resource, a curated battery (path tricks, trust/IP headers, URL-rewrite set, method swaps, **case** flips, **character percent-encoding** — encode a path letter single/double `%6E`/`%256E` so a WAF regex on the literal word misses while the server decodes it, **normalization-diff** slash/dot/trailing-`;` tricks + **traversal that resolves back to the target** `/admin/../admin`, **hop-by-hop** Connection-strip, **encoded-separator** `%c0%af`/`%ef%bc%8f`/`%u` slashes, **API version-prefix**, **matrix-param**); a surviving 2xx-with-content (simhash-verified) is a real bypass. **Fingerprint-gated** by default — `light` (core) / `auto` / `full` (exhaustive). **Learns the WAF's weakness**: a technique that flips one 403 is fired first on the next, so once one wall falls the rest bypass in ~1 request each.
- **`--bypass-headers`** — swap the header axis for a wordlist (bundled `403-headers.txt` or your own).
- **`--bypass-prefixes`** — feed known app route mounts (`rest/v1`, `/gateway`) that carry the **matrix-param management bypass** (`/<route>/;/actuator/env`): a Spring Security rule matching `/actuator/**` is evaluated before MVC strips the `;matrix` segment, so the route is authorized yet the endpoint is dispatched. Discovered 2xx routes are used automatically too.
- **WAF / block-page detection** (F5, Cloudflare, Imperva, Akamai, ModSecurity, Sucuri…) — block pages never become findings; the WAF shows in the fingerprint.
- **Throttle control** — `--rate` (aggregate cap), `--delay`, AIMD backoff, exact `Retry-After`, `--rotate-ua`, `--proxy-file` rotation, `--http2`.
- **Legacy-TLS reach** — a server with a weak DH key / old cipher that Python's default OpenSSL rejects (but `curl` accepts) no longer reads as "unreachable": the engine auto-drops to `SECLEVEL=1` and retries (with a "less secure transport" warning), or force it with `--legacy-tls`.

**Learning, hygiene & output**
- **Cross-target memory** — SQLite corpus + k-NN over fingerprint vectors + association mining + n-gram, `www`/apex collapsed to one key; content-hashed bundle names (`app.a1b2c3d4.js`) are filtered out so they never pollute recall, and the n-gram only learns names seen on ≥2 hosts; `--forget HOST|all` / `--forget-noise` clear it.
- **Request economy** (`--economy`) — Thompson-sampling bandit ranks candidates by learned hit-rate (auto-on under a WAF).
- **Smart noise control** — 404/400 never hit; auth-wall and URL-canonicalization redirects dropped (an `/x/`→`/x` slash-strip or http→https is noise, only `/x`→`/x/` confirms a directory); same-content collisions collapsed; one finding per resource (case-variant + cross-source dedup).
- **Authenticated-scan session detection** — warns if `-H` credentials don't actually authenticate, or if the session expires mid-scan.
- **Mid-scan resume** (`--resume`) — checkpointed per directory; pick up exactly where an interrupted run stopped.
- **Pentest-ready output** — live `rich` dashboard (never loses findings), JSON, self-contained HTML report, `--out` bundle (`params.txt`/`urls.txt`/graph), and **`--jsonl -`** to stream straight into the next tool (`origami https://t --jsonl - | nuclei`).

## How it works

```
calibration → TargetProfile → brain (KB + memory + vocab) → priority batch
   → engine (async httpx, backoff) → classify → fold → feedback → next runs
```

See [`origami.md`](origami.md) for the full design.

## Development

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'   # unit tests
python tests/fakeserver/server.py --profile iis-soft404         # test target
python tests/benchmark/bench_folds.py                           # fold-budget benchmark
python tests/benchmark/bench_adaptive.py                        # adaptive vs blind (hits/request)
```

## Status & roadmap

The full roadmap is implemented and tested: core engine + discovery folds (IIS shortscan, JS/HTML, robots/sitemap, backups/VCS, OpenAPI/Swagger/JSON:API + `.well-known`/GraphQL), vocabulary folding, WAF detection, SQLite memory, the n-gram completer, k-NN over fingerprint vectors, association mining, multi-source KB ingestion (`--update`, Wappalyzer catalog), mid-scan resume (`--resume`) and a contextual bandit for request economy under WAFs (`--economy`).

On top of that core: **content intelligence** (secrets — incl. modern provider tokens — plus stack-trace/debug-page/internal-infra disclosure), **parameter discovery with verified injection leads** (`--params` — reflection graded and *proven* with a breakout probe: unescaped `xss-lead`, `{{7*7}}→49` `ssti-lead`, `Location`/header `redirect-lead`), **GraphQL schema-mining** (introspection → args + sensitive-op flagging + a queries-only unauth probe → `auth-bypass`/BOLA leads), **web cache poisoning** (`--cache-poison` — passive cache-layer fingerprint + safe unkeyed-input probing with throwaway cache-busters), **historical-URL sourcing** (`--wayback`/`--gau`), **virtual-host discovery** (`--vhost`), **origin-IP discovery + IP-based WAF bypass** (`--origin` — crt.sh/Shodan/SecurityTrails/Censys → direct-IP probing behind the CDN), **403/401 bypass** (`--bypass-403` with fingerprint-gated `light|auto|full` intensity — path/case tricks, character percent-encoding, normalization-diff + traversal-resolve, hop-by-hop, encoded-separator, API-prefix, matrix-management; **learns the WAF's weakness** and fires the winning trick first; `--bypass-headers`/`--bypass-prefixes`), **directory-listing–aware harvesting**, an **endpoint graph** (`--graph`), explicit **OpenAPI ingest** (`--openapi`), **authenticated-scan session detection** (invalid-at-start + expired-mid-scan), **method discovery** (`--probe-405`: a 405 surfaces its `Allow` header free, then opt-in POST/PATCH probing reveals the accepted write method), **scan diffing** (`--diff` — recon-over-time), **memory hygiene** (www/apex normalization, content-hash bundle filtering + ≥2-host n-gram floor, `--forget`/`--forget-noise`), public-suffix-aware scope, and full anti-WAF realism (`Retry-After` honoring, `--rotate-ua`, `--proxy-file` rotation, `--replay-proxy`, `--http2`, **weak-DH/legacy-TLS auto-fallback**). 316 unit tests + a live integration scan.

### Request economy (contextual bandit)

When a target throttles you — a WAF, a 429 wall, a tight `--max-requests` — the order candidates fire in decides what you actually get. With `--economy on` (automatic when a WAF is detected) Origami ranks each candidate by the probability it pays off, learned from past scans: every word is a Bernoulli arm with a Beta(hits, misses) reward posterior conditioned on the target's confirmed technologies, ordered by a Thompson sample. Proven names go first, the budget buys more hits. Learning is always on (every probe updates the store); ranking is the lever economy mode pulls.

## Authorization

Only run Origami against targets you own, that are in scope of a bug-bounty program, a CTF, or a written engagement. You are responsible for staying in scope.
