"""Technology-aware wordlist overlays — the "the wordlist writes itself from the
fingerprint" differentiator.

A generic wordlist wastes budget: it fires `/wp-admin` at a Spring app and
`/actuator` at WordPress. Origami already fingerprints the stack per prefix, so it
can do better — when a technology is *confirmed*, it folds that stack's high-value
path pack into the scan. Crucially this is **additive**: the base list is never
replaced (real hosts are hybrid — legacy + proxy + multiple apps), the overlay only
*enriches* the scan where the tech actually appears, with paths a generic list
would never carry (`/actuator/heapdump`, `/telescope`, `/_next/static`, …).

Packs live in `origami/wordlists/overlays/<pack>.txt` (bare paths, one per line,
`#` comments allowed). `packs_for()` maps confirmed tech names → packs; the scanner
folds `overlay_words()` in right after the target's own learned vocabulary.
"""

from __future__ import annotations

from pathlib import Path

OVERLAY_DIR = Path(__file__).resolve().parent.parent / "wordlists" / "overlays"

# (keywords that may appear in a confirmed tech name) → overlay pack basename.
# Matched as substrings against the lower-cased confirmed-tech string, so
# "spring boot" and "spring" both hit the spring pack. Order = first-match wins
# only for the label; every matching pack is loaded.
_TECH_TO_PACK: list[tuple[tuple[str, ...], str]] = [
    (("wordpress", "woocommerce"), "wordpress"),
    (("drupal",), "drupal"),
    (("joomla",), "joomla"),
    (("laravel",), "laravel"),
    (("symfony",), "symfony"),
    (("django",), "django"),
    (("rails", "ruby on rails"), "rails"),
    (("spring",), "spring"),
    (("tomcat", "jboss", "wildfly", "jetty"), "tomcat"),
    (("jenkins",), "jenkins"),
    (("next.js", "nextjs"), "nextjs"),
    (("express", "node.js", "nodejs"), "node"),
    (("asp.net", "aspnet", "iis"), "aspnet"),
    (("grafana",), "grafana"),
    (("gitlab",), "gitlab"),
]

_cache: dict[str, list[str]] = {}


def packs_for(techs) -> list[str]:
    """Overlay pack names whose tech keywords appear in the confirmed techs.
    De-duplicated, in `_TECH_TO_PACK` order (stable for logging)."""
    low = " ".join(t.lower() for t in techs)
    out: list[str] = []
    for keys, pack in _TECH_TO_PACK:
        if pack not in out and any(k in low for k in keys):
            out.append(pack)
    return out


def load_pack(pack: str) -> list[str]:
    """Bare paths from `overlays/<pack>.txt` (deduped, order-preserving). Cached.
    [] if the pack file is missing/unreadable."""
    if pack in _cache:
        return _cache[pack]
    out: list[str] = []
    seen: set[str] = set()
    try:
        lines = (OVERLAY_DIR / f"{pack}.txt").read_text(errors="replace").splitlines()
    except OSError:
        lines = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and line not in seen:
            seen.add(line)
            out.append(line)
    _cache[pack] = out
    return out


def overlay_words(techs) -> tuple[list[str], list[str]]:
    """(words, matched_pack_names) — the additive stack-specific paths for the
    confirmed techs, de-duplicated across packs. ([], []) when nothing matches."""
    packs = packs_for(techs)
    words: list[str] = []
    seen: set[str] = set()
    for pack in packs:
        for w in load_pack(pack):
            if w not in seen:
                seen.add(w)
                words.append(w)
    return words, packs
