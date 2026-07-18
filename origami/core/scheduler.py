"""Scheduler — turns evidence + wordlist into a priority-ordered candidate list
(§3.5).

MVP is a static priority sort, not yet a live queue: candidates derived from
fingerprint evidence (priority paths, tech extensions) come before generic
wordlist guesses. The contextual-bandit reordering is a later upgrade; the
ordering here already makes the scan "less blind".
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from origami.core.scope import reg_domain

_SEP = re.compile(r"[-_.]+")


def target_tokens(host: str, path: str = "") -> set[str]:
    """Vocabulary from the target's own name: subdomain/domain labels (minus
    the public suffix) and base-path segments. www.exemplo.com → {www, exemplo};
    sub.dominio.site.com/path → {sub, dominio, site, path}. The org's name is
    very often a directory or file on the target."""
    host = host.split(":")[0]
    suffix = set(reg_domain(host).split(".")[1:])     # e.g. {com, br}
    out: set[str] = set()
    for label in host.split("."):
        if label and label not in suffix:
            out.update(_SEP.split(label))
    for seg in (path or "").split("/"):
        if seg:
            out.update(_SEP.split(seg.split(".")[0]))
    return {t.lower() for t in out if len(t) >= 2 and not t.isdigit()}

WORDLIST_DIR = Path(__file__).resolve().parent.parent / "wordlists"

# Always-tried extensions regardless of fingerprint (cheap, high value).
BASE_EXTS = ["", ".txt", ".html", ".bak", ".old"]


@dataclass(slots=True)
class Candidate:
    path: str            # relative to the prefix being scanned
    priority: int        # lower = scanned first
    origin: str          # "priority" | "wordlist"


def derive_vocabulary(paths) -> tuple[Counter, Counter]:
    """Learn the target's own naming from discovered references (§3.7 folding).

    This is the origami move: filenames and extensions seen in JS/robots/sitemap
    become scan vocabulary — the learned NAMES get tried in every directory and
    the learned EXTENSIONS get tried on every word. A target that references
    `getOrders.ashx` teaches us the token `getorders` and the ext `.ashx`.

    Returns (names, extensions) as Counters keyed by frequency, so callers can
    keep the most-referenced (and thus most valuable) under a fold budget.
    Names are split on -_. into tokens.
    """
    names: Counter = Counter()
    exts: Counter = Counter()
    for p in paths:
        if p.startswith(("http://", "https://")):   # full CDN URL — don't tokenize host into vocab
            p = p.split("://", 1)[1].split("/", 1)[-1]
        for seg in p.strip("/").split("/"):
            if not seg:
                continue
            if "." in seg:
                base, _, ext = seg.rpartition(".")
                if ext.isalnum() and 1 <= len(ext) <= 6:
                    exts["." + ext.lower()] += 1
                seg = base or seg
            for tok in _SEP.split(seg):
                if tok and 2 <= len(tok) <= 40 and not tok.isdigit():
                    names[tok.lower()] += 1
    return names, exts


def resolve_wordlist(path: Path | None) -> Path:
    """A `-w` value that isn't an existing file but matches a bundled list name
    (`base`, `big`, with or without `.txt`) resolves to the bundled wordlist —
    so `-w big` just works. Otherwise the path is returned as-is."""
    if path is None:
        return WORDLIST_DIR / "base.txt"
    if path.is_file():
        return path                        # an actual file — a directory named
                                           # `base` in the CWD must NOT shadow the
                                           # bundled list (it'd IsADirectoryError)
    name = path.name if path.name.endswith(".txt") else path.name + ".txt"
    bundled = WORDLIST_DIR / name
    return bundled if bundled.exists() else path


def load_wordlist(path: Path | None = None) -> list[str]:
    p = resolve_wordlist(path)
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def load_wordlists(names) -> list[str]:
    """Load and MERGE one or more wordlists (file paths or bundled names), de-
    duplicated and order-preserving. An empty/None list → the default base list.
    Lets `-w` be repeatable (e.g. `--deep` implies base, `-w custom` adds to it)."""
    if not names:
        return load_wordlist()
    out, seen = [], set()
    for n in names:
        for w in load_wordlist(Path(n)):
            if w not in seen:
                seen.add(w)
                out.append(w)
    return out


def build_candidates(
    priority_paths: list[str],
    words: list[str],
    enabled_extensions: set[str],
    extra_seeds: list[tuple[str, str]] | None = None,
    base_exts: list[str] | None = None,
) -> list[Candidate]:
    """Ordered, de-duplicated candidate list for one prefix.

    P0 extra seeds (memory / js / backup) + evidence-derived priority paths →
    P1 word×tech-ext → P2 word×base-ext. `extra_seeds` is (path, origin).
    `base_exts` overrides the generic P2 extension set (used by --ext-only).
    """
    base_exts = BASE_EXTS if base_exts is None else base_exts
    seen: set[str] = set()
    out: list[Candidate] = []

    def add(path: str, prio: int, origin: str):
        if path and path not in seen:
            seen.add(path)
            out.append(Candidate(path, prio, origin))

    for path, origin in (extra_seeds or []):          # P0: memory / js / backup
        add(path, 0, origin)        # keep leading-/ (root-absolute vs app-relative)
    for p in priority_paths:                          # P0: evidence-derived
        add(p, 0, "priority")

    tech_exts = sorted(enabled_extensions)
    for w in words:                                  # P1: tech-specific extensions
        for ext in tech_exts:
            add(f"{w}{ext}", 1, "wordlist")
    for w in words:                                  # P2: generic extensions + dir probe
        for ext in base_exts:
            add(f"{w}{ext}", 2, "wordlist")
        add(f"{w}/", 2, "wordlist")                  # trailing slash -> directory

    out.sort(key=lambda c: c.priority)
    return out
