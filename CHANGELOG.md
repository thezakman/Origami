# Changelog

All notable changes to Origami are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/). Version is single-sourced from
`origami/__init__.py`.

## [0.75.0] — Source-map reconstruction
- A JS `.map` is no longer just regexed as text: Origami parses its `sourcesContent`
  and mines the **original, un-minified source** for endpoints and parameter names —
  the routes/paths/internal hosts the shipped bundle buried. Transparent (every
  `extract_paths`/`extract_params` over a source map benefits); broken JSON falls
  back to the regex path safely.

## [0.74.0] — VCS/metadata tree reconstruction
- A leaked `.git/`, `.svn/` or `.DS_Store` is no longer just reported — it's **enumerated**:
  Origami parses `.git/index` (DIRC v2–v4), a macOS `.DS_Store`, or a `.svn/wc.db` (SQLite)
  and fetches every file it lists from the webroot. One leak becomes the whole repo/tree
  (source, configs, `.env`, backups). On-host only, capped at 300 files, honours `--exclude`;
  part of the backups family (off under `--no-backups`).

## [0.73.0] — Richer 405 probes + memory case hygiene
- `--probe-405` now reports the **response-body hint** and the **content-type that
  worked**: `POST (json) reached (400): {"message":"username is required"}` — the
  validation error reveals the endpoint's expected input, the real payoff.
- Memory no longer primes both `/MANIFEST.JSON` and `/manifest.json`: recall
  collapses case-variant paths (preferring the lowercase, conventional casing), and
  a **case-insensitive** host stores paths lowercased (casing is meaningless there)
  so the corpus stays clean. Case-sensitive hosts keep their exact casing.

## [0.72.1] — --probe-405: don't stop on 415
- A `415 Unsupported Media Type` on a method probe now means "try the next
  content-type" instead of being the final verdict: variants are JSON `{}`, empty,
  then empty form (most-likely-accepted first), and the most informative response
  (real processing > 415 > 404/405) is reported. A login API that 415'd the empty
  body now surfaces its real `400`/`422` validation response.

## [0.72.0] — --probe-405 goes inline
- `--probe-405` now tests the write method **the moment a 405 is found** (inline in
  the scan), not in a phase at the end — so the accepted method rides the finding's
  live line, and a partial/interrupted scan still probes what it discovered (instead
  of waiting behind the slower `--bypass-403`/`--cache-poison` passes).

## [0.71.1] — CI fix
- Make `test_from_gau_timeout_reaps_child` environment-independent: pass the fake
  `sleep` binary explicitly instead of rebinding a module global that's a def-time
  default (which silently no-op'd, so the test passed only where `gau` was installed
  and failed in CI). No production change.

## [0.71.0] — Method discovery on 405
- A 405 finding now surfaces the server's `Allow` header for free (`405 · Allow: POST`),
  telling you which method the existing resource wants — no extra request.
- New opt-in `--probe-405`: replays each 405 with POST (and PATCH iff `Allow` advertises
  it — **never** PUT/DELETE) using an empty and a `{}` body, and flags the method the
  endpoint accepts (a 400/422/2xx confirms it without sending real data). Honors `--exclude`.

## [0.70.0] — API surface stays visible
- Declared-contract findings (OpenAPI/Swagger + `.well-known`) are now exempt from
  block-wall muting and the same-`(status,length)` report collapse: every spec-declared
  endpoint stays listed — even a wall of `401`/`403` — because each is real, named intel
  ("exists, needs auth"), not generic-wall noise. Guessed wordlist paths still collapse.

## [0.69.1] — Design-doc sync
- `origami.md` (the design doc / PyPI long-description) brought current: cache-poisoning
  fold, content-hash memory hygiene, `--forget-noise`, directory structure, test count.

## [0.69.0] — Sale-readiness polish
- Project packaging metadata completed (authors, license, URLs, classifiers, keywords).
- Added `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`.
- Added GitHub Actions CI running the test suite on Python 3.11 / 3.12.
- Cleaned `requirements.txt`; removed stray tracked run artifacts; package docstrings.

## [0.68.0] — Memory hygiene
- Filter content-hashed bundle names (`app.a1b2c3d4.js`, GUIDs, timestamps) from the
  cross-target corpus; n-gram completer only learns names seen on ≥2 hosts.
- New `--forget-noise` / `Memory.prune_fingerprinted()`; self-healing prune on each run.

## [0.67.0 – 0.67.1] — Web cache poisoning
- `--cache-poison [light|auto|full]`: passive cache-layer fingerprint + safe unkeyed-input
  probing (every probe rides a throwaway cache-buster — never the real key); `--cache-headers`.
- Guard against query-reflecting endpoints (false-positive fix).

## [0.66.0 – 0.66.1] — Robustness
- Fix 308 slash-canonicalization flood (Next.js/Cloudflare): distinguish add-slash (directory)
  from strip-slash (framework canonicalization) redirects.
- Don't crash on a raw `ssl.SSLError` mid-scan.

## [0.64.0 – 0.65.4] — Bypass intensity, param intelligence, README
- `--bypass-403` fingerprint-gated families with `light|auto|full` intensity; hop-by-hop
  (spoof+strip chain desync), encoded-separator and API version-prefix classes.
- Parameter discovery grades reflections by injection context (HTML/attr/`<script>`/JSON → `xss-lead`).
- README: badges, animated demo, reordered "Why it's different".

## [0.57.0 – 0.63.0] — Content intelligence & WAF realism
- Modern provider secret tokens; stack-trace / debug-page / internal-infra disclosure leaks.
- Authenticated-scan session detection (invalid-at-start + expired-mid-scan).
- `--proxy-file` egress rotation; `--http2`; `--rotate-ua`; honor `Retry-After`.
- Public-suffix–aware scope; www/apex memory normalization + `--forget`.

## [0.49.0 – 0.56.0] — Discovery dimensions
- Historical URLs as seeds (`--wayback` / `--gau`).
- Parameter discovery (`--params`); virtual-host discovery (`--vhost`).
- Directory-listing detection + autoindex-aware harvest (probe only what the listing hides).
- Header-bypass wordlist; explicit OpenAPI ingest (`--openapi`).
- ReDoS / subprocess-leak hardening; leak false-positive fixes.

## [0.38.0 – 0.48.1] — Compounding discovery & economy
- Deep harvest: re-read discovered code; recurse the directories it reveals.
- Secret detection inside discovered files; JSON Lines streaming (`--jsonl`).
- 403/401 bypass fold expanded toward nomore403 parity; per-wall caps.
- Contextual-bandit request economy; cross-target name memory closes the shortscan loop.

## [0.17.0 – 0.37.0] — Recon surface & graph
- Endpoint graph (`--graph`): provenance + orphan/hidden endpoints.
- GraphQL introspection, `.well-known/`, CSP/Link header harvest, HTTP method discovery.
- Default-error-page fingerprinting; sitemapindex following.
- `--rate` aggregate req/s cap; `--delay` stealth; block-wall flood muting.

## [0.1.0 – 0.16.0] — Core engine
- Async httpx engine with AIMD adaptive concurrency; per-context soft-404 calibration
  over normalized-body simhash; additive per-prefix stack fingerprint; recursion + scope
  bounds; SQLite cross-target memory; rich live UI; HTML/JSON reports.

[0.69.0]: https://github.com/thezakman/Origami/commits/main
