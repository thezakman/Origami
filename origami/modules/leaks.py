"""Content intelligence — turn a response body into disclosure findings.

Discovery finds the endpoint; this reads what the endpoint *says*. A stack trace,
a framework debug page, or an internal IP in the body is high-value pentest intel
that no status code reveals. Companion to `secrets.py` (credentials): this catches
information disclosure — the leak, not the key.

Patterns are curated for LOW false positives: each is a shape that essentially
only appears in a real error/debug page (a `.java:NN` frame, a `:line NN` .NET
frame, "DEBUG = True", a Whoops page) or a genuine private-network address. The
match is trimmed to a short single-line snippet so a report is actionable without
dumping the whole trace.
"""

from __future__ import annotations

import re

# (kind, compiled pattern). Highest-signal first. Each pattern is a shape that
# realistically only occurs in an error/debug response, so a single hit is enough.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # --- language stack traces ---
    ("python-traceback",   re.compile(rb"Traceback \(most recent call last\):")),
    ("php-error",          re.compile(rb"(?i)\b(?:Fatal error|Parse error|Warning|Notice)\b.{0,8}?:.{0,120}?\bin\b.{0,200}?\bon line\b.{0,8}?\d+")),
    ("php-stacktrace",     re.compile(rb"Stack trace:\s*#0\s")),
    ("java-stacktrace",    re.compile(rb"\bat [\w.$]+\([\w ]*\.java:\d+\)")),
    ("dotnet-stacktrace",  re.compile(rb"\bat [\w.<>+]+\([^\n)]*\) in .{0,200}?:line \d+")),
    ("dotnet-yellowscreen",re.compile(rb"(?i)Server Error in '.{0,80}?' Application")),
    ("ruby-stacktrace",    re.compile(rb"[\w./-]+\.rb:\d+:in [`']")),
    ("node-stacktrace",    re.compile(rb"\bat [\w.<>\[\] ]+ \(/[^\n)]*\.js:\d+:\d+\)")),
    # --- framework debug / error pages ---
    ("django-debug",       re.compile(rb"(?i)You're seeing this error because you have[\s\S]{0,60}?DEBUG = True")),
    ("django-debug",       re.compile(rb"(?i)<th>Django Version:</th>")),
    ("laravel-whoops",     re.compile(rb"(?i)Whoops[\\,]? ?\\?looks like something went wrong")),
    ("laravel-trace",      re.compile(rb"Illuminate\\\\(?:Foundation|Database|Http)\\\\")),
    ("symfony-debug",      re.compile(rb"Symfony\\\\Component\\\\")),
    ("rails-exception",    re.compile(rb"(?i)Action Controller: Exception caught|<title>Action Controller")),
    ("flask-werkzeug",     re.compile(rb"(?i)Werkzeug Debugger|werkzeug\.exceptions\.")),
    ("aspnet-exception",   re.compile(rb"\[(?:Sql|Http|NullReference|InvalidOperation|Argument)\w*Exception[ :]")),
    # --- internal infrastructure leaks ---
    # RFC1918 with VALID octets (0-255, no leading zeros) and NOT embedded in a
    # longer dotted-decimal run — rejects SVG path data / minified-JS float blobs
    # like "8.585 10.55.109.024.221" (octet 024 invalid + trailing .221).
    ("internal-ip",        re.compile(
        rb"(?<![\w.])(?:"
        rb"10(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
        rb"|192\.168(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}"
        rb"|172\.(?:1[6-9]|2\d|3[01])(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}"
        rb")(?![\d.])")),
    # internal hostname — only when it's plausibly a HOST, not a JS property
    # (this.internal, ue.local): in URL/authority context (//host, user@host,
    # host:port) OR the label carries a digit/hyphen (db01.internal, web-prod.corp).
    ("internal-host",      re.compile(rb"(?:(?<=//)|(?<=@))[a-z0-9][\w.-]{1,60}\.(?:local|internal|intranet|corp|lan)\b")),
    ("internal-host",      re.compile(rb"\b[a-z0-9.-]{0,40}[0-9-][a-z0-9.-]{0,40}\.(?:local|internal|intranet|corp|lan)\b")),
    ("internal-host",      re.compile(rb"\b[a-z0-9][\w.-]{1,60}\.(?:local|internal|intranet|corp|lan)(?=:\d)")),
]

# Infra patterns are dominated by noise in JavaScript bundles (SVG path floats,
# minified `x.internal` property access), so they're skipped on JS bodies.
_INFRA_KINDS = {"internal-ip", "internal-host"}

# Kinds where DISTINCT values are worth listing (a few), vs once-per-kind for the
# trace/debug shapes (one hit proves the disclosure; no need to repeat).
_MULTI_VALUE = {"internal-ip", "internal-host"}
_MAX_VALUES = 5          # distinct values per multi-value kind
_MAX_HITS = 12           # overall cap per body


def _snippet(raw: bytes, limit: int = 90) -> str:
    s = raw.decode("latin-1", "replace")
    s = " ".join(s.split())                  # collapse newlines/runs of whitespace
    return s if len(s) <= limit else s[:limit] + "…"


def scan(body: bytes, js: bool = False) -> list[tuple[str, str]]:
    """Return de-duplicated (kind, snippet) disclosures found in `body`.

    `js=True` (a JavaScript bundle) skips the internal-IP/host patterns, which are
    almost all false positives there (SVG float data, minified property access)."""
    if not body:
        return []
    out: list[tuple[str, str]] = []
    seen_kind: set[str] = set()
    seen_val: set[bytes] = set()
    for kind, pat in _PATTERNS:
        if js and kind in _INFRA_KINDS:
            continue
        if kind in _MULTI_VALUE:
            n = 0
            for m in pat.finditer(body):
                v = m.group(0)
                if v in seen_val:
                    continue
                seen_val.add(v)
                out.append((kind, _snippet(v)))
                n += 1
                if n >= _MAX_VALUES or len(out) >= _MAX_HITS:
                    break
        else:
            if kind in seen_kind:            # same framework matched twice → once
                continue
            m = pat.search(body)
            if m:
                seen_kind.add(kind)
                out.append((kind, _snippet(m.group(0))))
        if len(out) >= _MAX_HITS:
            break
    return out
