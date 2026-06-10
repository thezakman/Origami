"""Backup / source-disclosure fold (§3.7).

Two moves:

  * **VCS / dotfile probes** — always-valuable leaks (`.git/`, `.svn/`,
    `.DS_Store`, `.env`, `.htaccess`, stray archives) injected as seeds.
  * **name variations** — for every confirmed file, fold aggressively into its
    backup/source twins (`x.php` → `x.php.bak`, `x.php~`, `.x.php.swp`, …).
    On real targets this is where the good stuff hides.
"""

from __future__ import annotations

from urllib.parse import urlparse

# High-value disclosure paths to seed at the root. Conservative, well-known.
VCS_PROBES = [
    ".git/HEAD", ".git/config", ".git/index", ".gitignore",
    ".svn/entries", ".svn/wc.db",
    ".hg/store", ".bzr/README",
    ".DS_Store", ".env", ".env.bak", ".env.local",
    ".htaccess", ".htpasswd",
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql",
    "www.zip", "site.zip", "release.zip",
    "composer.lock", "package-lock.json", "yarn.lock",
    "id_rsa", ".aws/credentials", ".npmrc",
]

# Backup/source suffixes appended to a discovered file.
_SUFFIXES = ["~", ".bak", ".old", ".orig", ".save", ".tmp", ".copy", ".1", ".2", ".swp"]


def vcs_probes() -> list[str]:
    return list(VCS_PROBES)


def variations(path: str) -> list[str]:
    """Backup/source twins of one discovered file path.

    Skips directories and extension-less paths. Produces both whole-name
    suffixes (`x.php.bak`, `x.php~`) and the editor swap form (`.x.php.swp`).
    """
    path = path.lstrip("/")
    if not path or path.endswith("/"):
        return []
    last = path.rsplit("/", 1)[-1]
    if "." not in last:
        return []
    prefix = path[: len(path) - len(last)]
    out: list[str] = []
    for suf in _SUFFIXES:
        out.append(f"{path}{suf}")                  # x.php.bak / x.php~
    # vim swap: dir/.name.swp
    out.append(f"{prefix}.{last}.swp")
    # replace extension with .bak/.old (x.php -> x.bak)
    stem = path.rsplit(".", 1)[0]
    out.append(f"{stem}.bak")
    out.append(f"{stem}.old")
    # de-dup, preserve order
    seen, ordered = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered


def is_file_hit(url: str, status: int) -> bool:
    """A confirmed file worth folding backups around (200/OK, has extension)."""
    if status not in (200, 206):
        return False
    last = (urlparse(url).path or "").rstrip("/").rsplit("/", 1)[-1]
    return "." in last
