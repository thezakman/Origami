"""Secure credential resolution for optional OSINT API keys (Shodan, SecurityTrails,
Censys — used by the `--origin` fold).

Design (least-surprise, 12-factor, no secrets in the repo or in output):

  1. **Environment variable first** — `SHODAN_API_KEY` etc. Perfect for CI, Docker,
     `direnv`, and one-off `KEY=… origami …` invocations; nothing touches disk.
  2. **User config file** — `~/.config/origami/credentials.toml` (XDG-aware), for a
     persistent local setup. It MUST be private (mode 0600); a group/other-readable
     file is loaded but warned about, since API keys are bearer secrets.

Keys are read on demand and never logged, never written to reports/checkpoints, and
never echoed in the preamble (only the *source names* are shown). `tomllib` is stdlib
on 3.11+, so this adds no dependency.

Config file format:

    [shodan]
    api_key = "…"

    [securitytrails]
    api_key = "…"

    [censys]
    api_id = "…"
    api_secret = "…"
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path

# env var → (toml section, toml key). Single source of truth for both layers.
_MAP: dict[str, tuple[str, str]] = {
    "SHODAN_API_KEY": ("shodan", "api_key"),
    "SECURITYTRAILS_API_KEY": ("securitytrails", "api_key"),
    "CENSYS_API_ID": ("censys", "api_id"),
    "CENSYS_API_SECRET": ("censys", "api_secret"),
}


def config_path() -> Path:
    """`$XDG_CONFIG_HOME/origami/credentials.toml`, or `~/.config/...` by default."""
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "origami" / "credentials.toml"


_cache: dict | None = None
_warned = False


def _load_file() -> dict:
    """Parse the config file once (cached). Warns — once — if the file is readable
    by group/other (bearer secrets belong in a 0600 file). Never raises."""
    global _cache, _warned
    if _cache is not None:
        return _cache
    _cache = {}
    path = config_path()
    try:
        st = path.stat()
    except OSError:
        return _cache                      # no file → env-only, which is fine
    if (st.st_mode & 0o077) and not _warned:
        _warned = True
        print(f"[!] {path} is readable by others (mode {oct(st.st_mode & 0o777)}); "
              f"API keys are secrets — run: chmod 600 {path}", file=sys.stderr)
    try:
        with path.open("rb") as f:
            _cache = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        print(f"[!] could not read {path}: {e}", file=sys.stderr)
        _cache = {}
    return _cache


def get(env_name: str) -> str | None:
    """Resolve one credential: environment variable first, then the config file.
    Returns None when neither is set (the caller then skips that OSINT source)."""
    val = os.environ.get(env_name)
    if val:
        return val
    section, key = _MAP.get(env_name, (None, None))
    if section:
        sect = _load_file().get(section)
        if isinstance(sect, dict):
            v = sect.get(key)
            if isinstance(v, str) and v:
                return v
    return None


_TEMPLATE = """\
# Origami OSINT API credentials — used by the --origin fold.
# Fill in ONLY the sources you have; leave the rest commented out. With none set,
# --origin falls back to keyless crt.sh. Environment variables override these.
# Keep this file private (it is created mode 0600).

# [shodan]              # SHODAN_API_KEY
# api_key = ""

# [securitytrails]      # SECURITYTRAILS_API_KEY  (historical A records)
# api_key = ""

# [censys]              # CENSYS_API_ID / CENSYS_API_SECRET
# api_id = ""
# api_secret = ""
"""


def scaffold() -> tuple[Path, bool]:
    """Create the config dir (0700) and a template credentials file (0600) if it
    doesn't exist; if it does, tighten it back to 0600. Returns (path, created).
    Makes option B turnkey — no manual mkdir/chmod, secure perms by construction."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    created = not path.exists()
    if created:
        path.write_text(_TEMPLATE)
    os.chmod(path, 0o600)
    _reset_cache_for_tests()          # re-read on next get() (perms/content may have changed)
    return path, created


def _reset_cache_for_tests() -> None:
    global _cache, _warned
    _cache, _warned = None, False
