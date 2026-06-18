# Origami

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

- **Calibrate before attacking.** Per-context soft-404 profiling (per directory *and* extension class) using a normalized-body **simhash** — so CSRF tokens, nonces, timestamps and WAF support-IDs don't fool it.
- **Evidence-guided folding.** Detect IIS → fold in `.aspx/.asmx/.ashx/.config`, priority paths and the shortscan module. Detect PHP/Apache/Tomcat/Express/Laravel/WordPress/Django → their own packs.
- **Reads the target's own code.** Harvests endpoints from HTML/JS — follows webpack chunks and source maps, **skips vendor libraries**, picks up the RequireJS `data-main` bundle — and from **response headers** (CSP `connect-src`/`form-action`, `Link` preload). Same-site CDN JS is read for intel; only the target host is scanned (`--scope site` to also scan the CDN).
- **GraphQL introspection.** Probes common GraphQL mounts and, if introspection is enabled (a production info-disclosure), confirms the endpoint and harvests the schema's field names into the parameter surface.
- **Folds in the whole API surface.** Probes the common OpenAPI/Swagger spec locations (`/swagger.json`, `/openapi.json`, `/v3/api-docs`…), **the JSON:API index** (`/jsonapi`, Drupal-style) **and `.well-known/`** (the OIDC/OAuth metadata lists every auth endpoint — authorize, token, jwks, userinfo); when one parses, every declared path / resource link / endpoint becomes a seed, surfacing endpoints no wordlist would guess.
- **Vocabulary folding** — the org's own names and extensions (from JS/robots/sitemap **and** the host/subdomain/path) become scan vocabulary.
- **IIS 8.3 shortscan** — drives the [`shortscan`](https://github.com/thezakman/shortscan) binary, constraint-filters the wordlist, tries the raw 8.3 name and the prefix as dir/file, and **completes truncated names with a character n-gram model** (`APIINT~1` → `apiintegracao`).
- **WAF / block-page detection** (F5 ASM, Cloudflare, Imperva, Akamai, ModSecurity, Sucuri…) — block pages never become findings, and the WAF shows in the fingerprint.
- **HTTP method discovery.** One OPTIONS request flags dangerous verbs enabled in production — PUT/DELETE, TRACE/TRACK (XST), PATCH, and the WebDAV set (PROPFIND/MKCOL/MOVE/COPY).
- **Smart noise control** — 404/400 are never hits; redirects that leave the path (auth walls) are dropped; identical-content collisions collapse; deep hits reveal their parent directories for recursion.
- **Cross-target memory** — SQLite corpus primes new scans from past ones; the n-gram completer improves as it grows.
- **Endpoint graph** (`--graph`) — turns the harvested references into a self-contained HTML graph (who references whom) that highlights **orphan/hidden endpoints**: paths reachable only from JavaScript or an API spec, never linked from a page — often the interesting ones.
- **Pentest-ready output** — live `rich` dashboard (streaming, never loses findings), JSON, self-contained HTML report, and a `--out` directory with `params.txt` / `urls.txt` for the next tool.

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/thezakman/Origami
cd Origami
python3.11 -m venv .venv
.venv/bin/pip install -e .
```

This installs the `origami` command into the venv (with `rich` for the live dashboard). Or run without installing: `PYTHONPATH=. python3 -m origami ...`.

## Usage

```bash
origami https://example.com                 # scan one target
origami https://example.com/app/            # scan under a base path
origami -l targets.txt --out results/       # scan a list, artifacts per host
```

Common flags:

| flag | meaning |
|---|---|
| `-w FILE` | wordlist (default: curated ~280-word builtin; point at SecLists/Assetnote for exhaustive runs) |
| `-X php,asp,bak` | extensions to brute-force, added to the fingerprint-detected ones (repeatable) |
| `--ext-only` | use only the `-X` extensions (ignore fingerprint-detected + learned) |
| `-d N` | recursion depth (default 1) |
| `-c N` / `-t S` | concurrency / timeout |
| `-k` | skip TLS verification |
| `-H 'Name: Value'` | extra request header, repeatable (auth/cookies — see below) |
| `-A UA` | override the User-Agent |
| `--proxy URL` | route through an intercepting proxy (Burp/ZAP); implies `-k` |
| `-mc` / `-fc` / `-ms` / `-fs` | match/filter status codes & sizes (ffuf-style) |
| `--scope host\|site` | scan only the host (default) or also same-site CDN |
| `--shortscan` / `--no-shortscan` | force / disable the IIS 8.3 fold (auto when IIS detected) |
| `--no-js` / `--no-apidocs` / `--no-backups` | disable those discovery folds |
| `-x PATTERN` | never request/recurse a path containing PATTERN (safety; repeatable) |
| `--max-folds N` | cap learned-vocabulary names folded in (default 40) |
| `--economy auto\|on\|off` | rank candidates by learned hit-rate (auto: on under a WAF) |
| `-v` / `-vv` | verbose: phases & hits / every request |
| `-F` | show full URLs instead of paths |
| `--json FILE` / `--html FILE` / `--out DIR` | reports & artifacts |
| `--graph FILE` | endpoint graph (provenance + orphan/hidden endpoints) → FILE.html + FILE.dot |
| `--no-learn` | don't read/write the cross-target memory |
| `--history` | show past scan history |
| `--resume` | continue an interrupted scan from its checkpoint |
| `--update` | refresh the fingerprint catalog (Wappalyzer) into the KB |
| `-V` | print version |

Run `origami -h` for the full list. Live controls: **`n`** skip the current directory (once one is discovered), **`q`** quit.

### Authenticated scans

Pass session cookies or tokens with `-H` (repeatable) to scan behind a login — they're sent on every request:

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

The final report groups findings by confidence, tagged by kind (`disclosure`, `config`, `api`, `admin`, `auth`, `source`) and coloured by where each came from (`js`, `robots`, `backup`, `wordlist`, `memory`, `shortscan`…):

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

The full roadmap is implemented and tested: core engine + discovery folds (IIS shortscan, JS/HTML, robots/sitemap, backups/VCS), vocabulary folding, WAF detection, SQLite memory, the n-gram completer, k-NN over fingerprint vectors, association mining, multi-source KB ingestion (`--update`, Wappalyzer catalog), mid-scan resume (`--resume`) and a contextual bandit for request economy under WAFs (`--economy`).

### Request economy (contextual bandit)

When a target throttles you — a WAF, a 429 wall, a tight `--max-requests` — the order candidates fire in decides what you actually get. With `--economy on` (automatic when a WAF is detected) Origami ranks each candidate by the probability it pays off, learned from past scans: every word is a Bernoulli arm with a Beta(hits, misses) reward posterior conditioned on the target's confirmed technologies, ordered by a Thompson sample. Proven names go first, the budget buys more hits. Learning is always on (every probe updates the store); ranking is the lever economy mode pulls.

## Authorization

Only run Origami against targets you own, that are in scope of a bug-bounty program, a CTF, or a written engagement. You are responsible for staying in scope.
