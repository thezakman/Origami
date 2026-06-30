# Contributing to Origami

Thanks for working on Origami. This guide covers the setup and the conventions
that keep the codebase consistent.

## Development setup

Requires **Python 3.11+**.

```bash
git clone https://github.com/thezakman/Origami.git
cd Origami
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[http2]"          # editable install + optional HTTP/2 extra
```

## Running the tests

The whole suite is pure-Python and offline (an in-process fake server stands in
for the network), so it runs anywhere with no setup:

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```

CI runs the same suite on Python 3.11 and 3.12 (`.github/workflows/tests.yml`).
Every change should keep the suite green and add a test for new behavior — the
preferred style is a regression test that **fails without the fix** (verify by
temporarily reverting the change).

## Architecture at a glance

```
origami/
  core/        engine, calibration, fingerprint, classification, scheduler, scope
  modules/     content folds (bypass403, cache_poison, secrets, leaks, params…)
    discovery/ passive seed sources (js, apidocs, robots, wayback, shortname…)
  brain/       cross-target memory (SQLite), bandit, n-gram, knowledge base
  output/      live UI, HTML/JSON reports, endpoint graph
```

See `origami.md` for the full design rationale.

## Conventions

- **Folds** follow one shape: `async def _x_fold(engine, profile, result, opts,
  observer)` — select targets from `result.findings`, probe with `engine.fetch`,
  report via `opts.finding_sink` / `_report`. Mirror an existing fold
  (`_param_fold`, `_bypass_fold`) when adding one.
- **Pure helpers** (parsing, classification, detection) live in `modules/` with
  unit tests; the scanner does the fetching. Keep I/O out of the testable core.
- **Docstrings** explain the *why* (the failure mode or design tension), not just
  the *what* — match the density of the surrounding code.
- **New active behavior is opt-in** behind a flag; passive/free intelligence can
  be always-on.
- Run the linters/formatters your editor provides, but match the existing style
  over any tool default.

## Reporting issues

Bugs and feature ideas: open a GitHub issue. Security issues: see `SECURITY.md`
(report privately).
