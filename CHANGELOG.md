# Changelog

All notable changes to Origami are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/). Version is single-sourced from
`origami/__init__.py`.

## [0.99.2] — 403-bypass learns the WAF's weakness (winner-first, cross-resource)
- The bypass battery is now **adaptive**: when a technique flips one 403→2xx, that
  technique is remembered and fired **first** on every subsequent 403. Combined with the
  existing per-resource early-exit, the 2nd..Nth bypassable wall (same WAF → same weakness)
  usually costs **~1 request** instead of the whole battery — the same thoroughness, far
  fewer requests when a weakness exists. The reused trick is logged `(learned)`.
- Technique keys are **resource-independent** (`/admin%2f` and `/users%2f` share a key), so
  suffix/prefix/header/method weaknesses transfer across resources. New `_bypass_tech_key()`.
- Reordering never changes *which* variants are tried (no bypass missed) — only the order,
  so a known-good trick is found immediately. The fold remains **401/403-only**.

## [0.99.1] — 403-bypass: normalization-difference variants (slash/dot/traversal)
- More `--bypass-403` path tricks that exploit normalization differences between the
  edge (CDN/WAF/proxy) and the app router:
  - bare trailing suffixes `/admin..`, `/admin;`, `/admin.`, `/admin/..`, encoded-dot
    suffixes `/admin/%2e/`, `/admin/%2e%2e/`, extension spoofs `.js`/`.txt` and
    `/admin;.json`, `/admin.json;` (content-negotiation/extension routing past the ACL);
  - **traversal that resolves back to the target** — `/admin/../admin`, `/x/../admin`
    (+ encoded/double-encoded `..`): the edge matches its ACL on the raw string, the app
    collapses the traversal and routes to `/admin` anyway. New `_traversal_resolve_variants()`.
- All under the `path` family (unit-tested). Deliberately NOT added: PUT/DELETE and
  arbitrary verbs (state-changing / low-signal — the method swap stays POST/PATCH, which
  can return the content); "content below the blocked dir" is already covered by the
  scanner's 403-directory recursion.

## [0.99.0] — 403-bypass: character percent-encoding of the path
- New bypass family in `--bypass-403`: **percent-encode individual path characters** so a
  WAF/ACL matching the literal word (`/admin`) misses while the server decodes it back —
  encode the last letter (the canonical trick), the first letter, and the whole segment,
  each **single** (`/hidde%6E`) and **double** (`/hidde%256E`, defeats filters that decode
  once). Operates on the last path segment; the parent dir and trailing slash are preserved.
  Grouped under the `path` family (rides `light` mode too). Verified end-to-end that httpx
  sends the encoded path verbatim on the wire. New `_char_encode_variants()` (unit-tested).

## [0.98.1] — Faster simhash (runs on every response) — byte-identical output
- Rewrote `normalize.simhash` — the structural fingerprint computed on **every** HTTP
  response (soft-404 calibration, dedup, `--diff`, corpus k-NN). Two lossless changes:
  duplicate shingles are hashed **once** and weighted by count (HTML repeats a lot of
  markup), and the 64 lane counters are packed into one big integer updated with a single
  add per unique shingle instead of a 64-iteration Python loop (bit-sliced popcount).
- **~4× faster on repetitive HTML, ~2× on unique/JSON bodies** (e.g. a 250 KB page: 25 ms → 6 ms).
  Output is **byte-identical** to the old implementation — locked by a golden-value test, so
  simhashes stored in the memory DB stay comparable across versions. No behavior change.

## [0.98.0] — GraphQL: read the schema, flag sensitive ops, probe unauth access
- GraphQL is no longer just *detected* — the schema is **mined**:
  - **Deeper introspection** extracts every query/mutation **argument** (the real input
    surface), not only field names; args feed the parameter corpus.
  - **Sensitive-operation flagging** — root ops matching `login`/`token`/`senha`/`redefinir`/
    `lgpd`/`admin`/`boleto`/`cpf`/… are surfaced in the finding (`disclosure` tag) instead of a
    bare "300 fields" count; queries and mutations are counted separately.
  - **Unauthenticated-access probe** — like testing which Swagger paths answer unauthenticated,
    Origami sends a benign no-arg query (**queries only — never mutations**, so no state change)
    for the top ops and classifies each: `open` (returned data w/o auth), `reachable` (past the
    gate, only a validation error), or `auth` (gate enforced). Ops reachable without auth →
    the finding is tagged **`auth-bypass`** (a BOLA / missing-authZ lead). Bounded by `MAX_GQL_PROBES`.
- New `graphql` helpers `analyze_schema()` / `build_probe_query()` / `classify_probe()` and the
  `_graphql_probe` fold (all unit-tested). Validated live against a healthcare GraphQL portal
  (32 queries / 28 mutations; `beneficiarioValidarToken` returned data unauthenticated, 11 more
  sensitive ops reachable past the gate).

## [0.97.0] — Legacy-TLS auto-fallback + surface the real "unreachable" reason
- **Fix a false "unreachable".** A server with a weak Diffie-Hellman key or an old cipher
  (`[SSL: DH_KEY_TOO_SMALL]`, handshake failure) is rejected by Python's default OpenSSL
  security level — even though `curl` reaches it. Origami reported the target as *unreachable*
  and gave up after 1 request. Now, on such a handshake error, the engine transparently drops
  to **`SECLEVEL=1`**, rebuilds its client pool, and retries — so the scan proceeds (a clear
  "weak DH / legacy cipher — transport is less secure" warning is logged). New `--legacy-tls`
  forces it from the start.
- **Surface the reason.** When the root really is unreachable, the message now includes the
  transport error (`… unreachable — ConnectError: [SSL: …]` / DNS / reset), instead of a bare
  "unreachable" that left you guessing. New `ScanResult.error`.

## [0.96.0] — Verified injection leads: breakout, SSTI, open-redirect, header reflection
- The `--params` reflection fold no longer stops at *"the value reflects."* It now grades a
  reflection into a **verified lead**:
  - **Breakout probe** — one follow-up request per endpoint sends `'"<>{{7*7}}` (wrapped in a
    unique sentinel) at the params that reflected into an HTML/JS sink. `xss-lead` is now set
    only when the metacharacters come back **raw** (real, unescaped sink); an *escaped*
    reflection is downgraded to plain `param`. If `{{7*7}}→49`, the finding gets **`ssti-lead`**.
  - **Open-redirect** — a canary reflected into the `Location` header → **`redirect-lead`**
    (checked before the empty-body guard, and 3xx endpoints are now fuzz candidates).
  - **Header reflection** — a canary echoed in any response header is noted (header-injection lead).
- New `paramfuzz` helpers `build_breakout_batch()` / `analyze_breakout()` / `reflected_in_location()`
  / `reflected_in_headers()` (all unit-tested); one extra request per endpoint (bounded by
  `MAX_BREAKOUT_PARAMS`). New tags: `ssti-lead`, `redirect-lead`.

## [0.95.0] — Path regression: climb a deep target URL up to root
- A deep/file target URL (`…/caminho/path/arquivo.pdf`) is now **climbed**: Origami scans
  the file's **directory** (previously it treated the file as a folder and scanned *under*
  it), fetches the file itself as a seed, and probes **every ancestor directory up to root**
  (`/caminho/path/`, `/caminho/`, `/`) — existing ones get recursed by the normal directory
  machinery. Each path segment (`caminho`, `path`, `arquivo`) folds into the dynamic
  vocabulary. New pure helper `_path_climb()` (unit-tested).

## [0.94.1] — Fix `--origin` false positives (a sibling's 404 flagged as origin)
- The origin heuristic flagged **any** IP whose response differed from the edge as a
  "possible origin" — so an unrelated crt.sh sibling returning a `404` page (distinct
  body) was wrongly reported. That's backwards: an exposed origin serves the **same**
  app, while distinct content is usually an unrelated host.
- An origin lead now requires a **non-edge IP that serves `2xx` with a real body** for
  the target Host (`404`/`403`/`5xx`/redirect and the edge IP itself are rejected).
  Confidence is graded: same-app-as-edge `2xx` = likely origin (0.8), distinct `2xx` =
  weaker lead (0.55), edge-blocked-path-opens = confirmed bypass (0.85). New pure helper
  `_is_origin_serve()` (unit-tested against the reported 404 case).

## [0.94.0] — `--diff`: recon-over-time / attack-surface change tracking
- New **`--diff`**: after a scan, compares it against the **last stored run of the same host**
  (the memory DB already keeps a per-run findings snapshot) and reports what **appeared**,
  **disappeared**, or **changed** — with the headline being paths that became **newly
  ACCESSIBLE** (`403/404/401 → 2xx`). Turns Origami into a recon-over-time / attack-surface
  monitor, not just a one-shot buster. Needs the memory DB (not `--no-learn`).
- New `origami/output/diff.py` (pure compare + render) and `Memory.latest_run_findings()`.

## [0.93.0] — Tech-overlay wordlists: the wordlist writes itself from the fingerprint
- New **tech-overlay path packs** (`origami/wordlists/overlays/<tech>.txt`, 15 stacks):
  when a technology is *confirmed* by the fingerprint, its high-value paths are folded in
  as **root seeds** — WordPress (`wp-admin`, `wp-json`, `xmlrpc.php`), Spring
  (`actuator/heapdump`/`env`/`gateway`), Laravel (`telescope`/`horizon`), Rails, Django,
  Next.js (`_next/*`), Tomcat, Jenkins, Drupal, Joomla, Symfony, Node, ASP.NET, Grafana,
  GitLab. **Additive** — never replaces the base list (real hosts are hybrid), root-anchored
  (fired at the base prefix, not per-directory), and gated to confirmed techs only.
- On by default; `--no-overlays` to disable. New module `origami/core/overlays.py`
  (tech-name → pack mapping) + packs bundled in the wheel.

## [0.92.1] — `--init-credentials`: turnkey secure setup for option B
- New **`--init-credentials`**: scaffolds `~/.config/origami/credentials.toml` with a
  template and **mode 0600 by construction** (dir 0700), then exits — no manual mkdir/chmod.
  Idempotent (re-tightens perms if the file already exists).

## [0.92.0] — `--origin` in `--deep` + secure OSINT credential storage
- **`--deep` now includes `--origin`** — the aggressive preset already makes off-host
  (bucket) GETs and external (wayback) calls, so origin-IP probing fits; bare `--deep`
  runs it keylessly (crt.sh), or with keys if configured.
- **Secure credential resolution** (`origami/core/credentials.py`): OSINT API keys are
  read **environment-variable first, then `~/.config/origami/credentials.toml`** (XDG-aware,
  `tomllib`, no new dependency). Keys are never logged, never written to reports/checkpoints,
  and never shown in the preamble (only source *names* are). A group/other-readable config
  file triggers a `chmod 600` warning (bearer-secret hygiene). `.gitignore` now covers
  `credentials.toml`/`.env`/`*.credentials`.

## [0.91.0] — `--origin`: origin-IP discovery + IP-based WAF bypass
- New **`--origin`** fold (opt-in, off-host): behind a CDN/WAF the public DNS points at
  the edge — this resolves the host's A/AAAA records and gathers candidate **origin** IPs,
  then requests each IP **directly with the target `Host`**. An IP serving distinct content,
  or opening a path the edge WAF blocks, is reported as a reachable origin / bypass lead.
- **Layered candidate sourcing** (the "keyed, else crt.sh fallback" design): keyed OSINT —
  Shodan (`SHODAN_API_KEY`), SecurityTrails historical-A (`SECURITYTRAILS_API_KEY`), Censys
  (`CENSYS_API_ID`/`CENSYS_API_SECRET`) — is used when configured; otherwise keyless
  **crt.sh** Certificate-Transparency siblings. IP-literal / localhost targets skip OSINT
  (no domain to query) so the fold never stalls on them.
- New module `origami/modules/discovery/originip.py` (pure URL-builders + parsers, unit-tested).

## [0.90.1] — Lint clean: remove dead imports/locals, fix placeholder-less f-strings
- Removed unused imports (`TechRule`, `load_wordlist`, `SIMHASH_MISS_DISTANCE`, `urlparse`
  in html_report/graphql, `urljoin` in shortname) and a dead local (`recurse_exts` in
  `scan()`, recomputed inside the loop). Converted three placeholder-less f-strings to plain
  strings. `pyflakes origami/` is now clean.

## [0.90.0] — Polish pass: crash fixes, per-target similar-to, docs, dead code
- **Fix crash:** `--proxy-file` errors called `ap.error()` from a scope where the parser
  wasn't defined (`NameError`); now a clean `SystemExit`. Same clean-exit treatment for
  non-numeric filter/replay code lists (`_int_set`) instead of a bare `ValueError` traceback.
- **Fix `--filter-similar-to` across targets:** the reference simhashes were resolved once
  and cached on the shared options, so every target after the first reused target #1's page.
  Now resolved **per target** against that host.
- **Harden `--replay-proxy`:** a malformed proxy URL (e.g. missing scheme) is caught at
  client construction and skipped with a warning — a bad proxy can't turn a finished scan
  into a traceback.
- **Cap `--bypass-prefixes`:** operator carriers are capped (12) since each multiplies across
  every blocked resource × 2 families; the drop is logged.
- Docs: `--bypass-prefixes`, `--replay-proxy`, body filters and `--time-limit` added to the
  README flag table + bullets; matrix-management bypass documented; test count refreshed.
- Removed dead code (`_SEED_ORIGINS`, `scope.host_of` + its now-unused import); added help
  text to `-c/--concurrency` and `-t/--timeout`; `--out` help now lists all five artifacts.

## [0.89.1] — Body filters use precomputed probe counts (apply to all findings)
- Refinement of the 0.89.0 body filters: word/line counts and the body simhash are
  already computed on **every** probe, so `--filter-word-count`/`--filter-line-count`/
  `--filter-similar-to` now apply to **all findings** (main scan + every fold) at zero
  extra cost — no body kept, no re-decoding. Only `--filter-regex` still keeps the body,
  and only on the main scan. `Finding` now carries `words`/`lines` from the probe.

## [0.89.0] — feroxbuster parity: replay-proxy, body filters, time-limit, stdin
- **`--replay-proxy URL` + `--replay-codes CODES`**: at the end of a scan, re-issue only
  the CONFIRMED findings through a replay proxy — Burp/ZAP gets a clean sitemap of just
  the hits, separate from `--proxy` (which sees every probe). `--replay-codes` narrows it
  to specific statuses. Best-effort: an unreachable proxy warns, never crashes. Implies `-k`.
- **Body-based filters** (feroxbuster-style): `--filter-word-count`, `--filter-line-count`,
  `--filter-regex` and `--filter-similar-to URL` (repeatable). word/line/regex apply to the
  main wordlist scan (bodies are kept only when a body filter is active); `--filter-similar-to`
  drops look-alikes by simhash across ALL findings — great for a known soft-200/error page.
- **`--time-limit DURATION`** (`30s`/`10m`/`1h` or bare seconds): a wall-clock budget per
  target alongside `--max-requests`; the scan stops cleanly and leaves a `--resume` checkpoint.
- **stdin targets**: `cat urls | origami` (bare pipe) or `-l -` reads target URLs from stdin.

## [0.88.0] — `--bypass-prefixes` (custom route carriers) + `full` ungates matrix
- New **`--bypass-prefixes FILE`**: an operator route-prefix wordlist (one mount per
  line, e.g. `rest/v1`, `/gateway`) fed to BOTH the api-prefix and matrix-management
  families as extra `;/` carriers — on top of the curated seeds and the 2xx routes
  discovered in-scan. Known-good mounts lead the carrier list. Implies `--bypass-403`.
- **`--bypass-403 full`** now fires the matrix-management family regardless of the
  detected stack (`auto`/`light` keep it gated to Spring/Java/Tomcat/unknown), so an
  exhaustive run isn't held back when fingerprinting is inconclusive.

## [0.87.0] — Matrix-param management bypass + data-driven route prefixes
- New **matrix-param management bypass** family in the 403 fold: reaches a blocked
  actuator/JMX endpoint by carrying it on a mapped route + `;/` matrix segment
  (`/rest/v1/;/actuator/env`), so a Spring Security rule matching `/actuator/**` —
  evaluated *before* MVC strips the `;matrix` content — authorizes the route yet
  still dispatches to the endpoint.
- **Data-driven prefixes:** the api-prefix and matrix families no longer rely only
  on static guess lists — every **real 2xx route the scan confirmed** is fed in as
  a bypass carrier (`/<route>/blocked` and `/<route>/;/actuator/*`), so app-specific
  mounts (`/gateway`, `/rest/v1`…) are covered from observed data, not guesswork.
- **Gated** to Spring/Java/Tomcat/unknown stacks (same set as the encoded-separator
  family) and management-ish paths only (`actuator`, `jolokia`, `gateway`, `heapdump`,
  `env`, `metrics`…), so it never inflates an ordinary 403's request budget.

## [0.86.0] — Repeatable `-w` (merge wordlists) + `--deep` always includes base
- `-w`/`--wordlist` is now **repeatable** and the lists are **merged** (de-duplicated,
  order-preserving): `-w base -w big -w custom.txt` runs all three.
- Under `--deep`, the **base list is always included**, so `--deep -w custom` runs
  `base + custom` (and bare `--deep` runs base, as before). Preamble shows `base + big`.

## [0.85.0] — New `big` wordlist + name resolver
- New bundled **`big.txt`** (~1250 curated names) — a superset of `base.txt` (which fires
  first, prevalence-ordered) with a broad high-value tail across admin/auth/api/config/
  files/backups/devops/infra/monitoring/db-tools/cms/security/business/content/i18n/actions.
  Select it with **`-w big`** (bundled-name resolver: `-w base`/`-w big` work without a path).
- `base.txt` grown to ~540 (`redoc`, `apidoc`, `whoami`, `echo`, `nodeinfo`, `debugbar`,
  `serviceworker`, `manifest`, `webmanifest`, `humans`).
- `clientapp.py`: a service worker served with an empty content-type but an HTML body
  (catch-all) is no longer parsed as JS.

## [0.84.0] — Full-app review: correctness & robustness fixes
- **Calibration soft-404 coverage** (`baseline.py`): stopped fuzzy-deduping the miss
  simhashes — a near-but-distinct shape was being dropped, which let real soft-404s
  near it slip through as findings. Now keeps every distinct miss shape (exact-dedup).
- **Budget guarantee** (`scanner.py`): the surprising-hit soft-verification (a sibling
  fetch per finding) is skipped once `--max-requests` is spent, instead of overrunning it.
- **Association fold** (`scanner.py`): skips URLs already discovered — no more re-fetch
  and re-calibration of paths another source already confirmed.
- **Source-map recursion** (`js_parser.py`): capped so a crafted sourcemap-in-sourcesContent
  can't recurse into a `RecursionError`.
- **`ui.py` imports without rich**: the "dependency-free fallback" is now real — a rich-only
  base class no longer breaks the import when rich is absent (`make_observer` → NullObserver).
- Removed dead code (`vcs.parse_git_config`). Reviewed html_report/graph — confirmed
  XSS-safe (`html.escape` throughout).

## [0.83.0] — Throttle-aware folds
- When the target is throttling us (sustained 429/503) or we're asked to conserve
  (`--economy on`, or `auto` + a detected WAF), the speculative amplifier folds
  (API version pivot, naming mutation) are **skipped**, and the biggest enumerators
  (backups, VCS tree) tighten their caps — so low-value guesswork doesn't wake a
  WAF/rate-limit block on the exact targets that need care.

## [0.82.1] — Design-doc sync
- `origami.md` (design doc / PyPI long-description) brought current with the recent
  discovery folds (VCS tree, source maps, API version pivot, naming mutation, cloud
  buckets, config→seeds, method discovery, urlscan/OTX sources, `--deep`, `-u/--url`).

## [0.82.0] — `--deep` aggressive-discovery preset
- One flag turns on the aggressive bundle at once: `--bypass-403 --cache-poison --probe-405
  --buckets --params --wayback`. Just `origami --deep -u <url>` instead of typing the whole
  string. Includes the state-changing/off-host probes, so it's a knowing power-user opt-in.

## [0.81.2] — Backup fold: drop catch-all echoes
- A "backup" whose response is **byte-identical** to the original file (same length +
  near-identical simhash) is no longer reported: it's a route/catch-all serving the same
  content for any suffix (`swagger.json.bak` == `swagger.json.qualquercoisa` == the file),
  not a real backup disclosure. A genuinely distinct backup (different content/length) is
  still flagged. Kills the `.bak/.old/.copy/.1/.2/.swp` false-positive flood on such routes.

## [0.81.1] — Base wordlist: second enrichment pass
- Grew `base.txt` to ~530 with more universal, high-hit-rate names (stack-specific
  paths still stay the overlay's job): CRUD/action route names (`list`, `edit`,
  `create`, `delete`, `view`, `browse` — high-yield under discovered dirs on recursion),
  blog/content (`posts`, `article`, `page`, `tag`, `author`), app sections (`overview`,
  `summary`, `activity`, `explore`), monitoring (`stats`, `monitor`), localization
  (`lang`, `locale`, `i18n`, `translations`), and commonly-exposed webmail/remote/hosting
  panels (`webmail`, `roundcube`, `owa`, `vpn`, `plesk`, `whm`). De-duplicated.

## [0.81.0] — `-u`/`--url` target flag
- The target URL can now be passed as `-u`/`--url` (repeatable) in addition to the
  positional argument — so you can keep the URL last and swap only it between runs
  (`origami -F --gau --bypass-403 -u https://…`). Merges with the positional/`--list`.

## [0.80.0] — Base wordlist review + enrichment
- Reviewed and grew the default `base.txt` from ~360 to ~480 curated names — filling the
  modern high-value gaps while staying lean (stack-specific paths remain the overlay's job):
  auth/identity endpoints (`authorize`, `userinfo`, `jwks`, `introspect`), API surface
  (`v0`, `mobile`, `hasura`, `altair`, `graphql-playground`), commonly-exposed infra tools
  (`pgadmin`, `portainer`, `sonarqube`, `nexus`, `vault`, `keycloak`, `sentry`, `rabbitmq`,
  `minio`, `metabase`, `airflow`), devops files (`terraform`, `ansible`, `k8s`, `helm`,
  `docker-compose`), commerce (`payment`, `invoice`, `billing`, `subscription`, `wallet`),
  a few actuator-family (`jolokia`, `httptrace`, `readiness`/`liveness`), and generic PT-BR
  business terms (`cliente`, `produto`, `pedido`, `venda`, `funcionario`, `fornecedor`).
  Ordered by prevalence; still bare-name-only and de-duplicated.

## [0.79.0] — Four adaptive discovery folds
- **API version pivot**: a confirmed `/api/v1/…` endpoint pivots to its adjacent versions
  (`v0`, `v2`, `v3`) — the legacy/next surface still wired in the backend. On-host, bounded.
- **Feeds & sitemap variants**: robots/sitemap discovery now also probes RSS/Atom feeds and
  sitemap-index variants (`/feed`, `/rss`, `/atom.xml`, `sitemap_index.xml`…) and parses their
  content URLs.
- **Broader body harvesting**: any `text/*` response (plain dumps, CSV) is now mined for
  endpoints, not just files with a known extension — config/secret files stay with the secrets fold.
- **Naming-convention mutation**: a confirmed `/user` → `/users`, `report1` → `report2`,
  `data.json` → `data.xml` — high-signal siblings from a developer's naming habit, not blind brute.

## [0.78.0] — More passive URL sources
- `--wayback` now unions **urlscan.io** and **AlienVault OTX** (both keyless) with the
  Wayback CDX + Common Crawl sources — all four fetched concurrently, best-effort, so a
  slow/down source can't hold up the rest. More historical/indexed URLs → more seeds.

## [0.77.0] — Config files → new seeds
- Config/`.env`/`appsettings` bodies (already read for secrets) are now mined for the
  **same-host paths they reference** — a leaked config names `/internal/...` endpoints
  no wordlist would guess, and those become scanned seeds (origin `config`). Off-host
  refs are left to the bucket fold / not scanned; bounded and de-duped. This completes
  the "mine the structural leaks you already find" roadmap (VCS · source maps · buckets · configs).

## [0.76.0] — Cloud bucket discovery
- S3/GCS/Azure bucket references in the target's own code/configs are now recognized
  and surfaced for free (on-host, reads bodies already fetched). With `--buckets`,
  each is probed at its read-only listing endpoint: publicly-listable buckets are
  flagged `bucket`/`listing`/`disclosure` with a sample of the objects they expose.
  Distinguishes virtual-hosted from path-style URLs (an object key isn't a bucket).

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
