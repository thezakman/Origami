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
- **Reads the target's own code.** Harvests endpoints from HTML/JS — follows webpack chunks and source maps, **skips vendor libraries**, picks up the RequireJS `data-main` bundle. Same-site CDN JS is read for intel; only the target host is scanned (`--scope site` to also scan the CDN).
- **Vocabulary folding** — the org's own names and extensions (from JS/robots/sitemap **and** the host/subdomain/path) become scan vocabulary.
- **IIS 8.3 shortscan** — drives the [`shortscan`](https://github.com/thezakman/shortscan) binary, constraint-filters the wordlist, tries the raw 8.3 name and the prefix as dir/file, and **completes truncated names with a character n-gram model** (`APIINT~1` → `apiintegracao`).
- **WAF / block-page detection** (F5 ASM, Cloudflare, Imperva, Akamai, ModSecurity, Sucuri…) — block pages never become findings, and the WAF shows in the fingerprint.
- **Smart noise control** — 404/400 are never hits; redirects that leave the path (auth walls) are dropped; identical-content collisions collapse; deep hits reveal their parent directories for recursion.
- **Cross-target memory** — SQLite corpus primes new scans from past ones; the n-gram completer improves as it grows.
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
| `-w FILE` | wordlist (default: small builtin; point at SecLists/Assetnote) |
| `-d N` | recursion depth (default 1) |
| `-c N` / `-t S` | concurrency / timeout |
| `-k` | skip TLS verification |
| `-mc` / `-fc` / `-ms` / `-fs` | match/filter status codes & sizes (ffuf-style) |
| `--scope host\|site` | scan only the host (default) or also same-site CDN |
| `--shortscan` / `--no-shortscan` | force / disable the IIS 8.3 fold (auto when IIS detected) |
| `--no-js` / `--no-backups` | disable those discovery folds |
| `--max-folds N` | cap learned-vocabulary names folded in (default 40) |
| `-v` / `-vv` | verbose: phases & hits / every request |
| `-F` | show full URLs instead of paths |
| `--json FILE` / `--html FILE` / `--out DIR` | reports & artifacts |
| `--no-learn` | don't read/write the cross-target memory |
| `--history` | show past scan history |

Live controls: **`n`** skip the current directory (once one is discovered), **`q`** quit.

## Output

- **Live dashboard** — findings stream as permanent lines (`code size origin conf url tags`) under a pinned status bar with phase, req/s, hits, duration and `==> directory` markers.
- **`--out DIR`** writes `findings.json`, `report.html` (browsable, filterable), `params.txt` (harvested parameter surface — a drop-in fuzzing list) and `urls.txt`.

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
```

## Status & roadmap

Core engine + discovery folds (IIS shortscan, JS/HTML, robots/sitemap, backups/VCS), vocabulary folding, WAF detection, SQLite memory and the n-gram completer are implemented and tested. Planned: k-NN over fingerprint vectors, association mining, multi-source KB ingestion (Wappalyzer/nuclei), mid-scan resume, and a contextual bandit for request economy under WAFs.

## Authorization

Only run Origami against targets you own, that are in scope of a bug-bounty program, a CTF, or a written engagement. You are responsible for staying in scope.
