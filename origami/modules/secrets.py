"""Secret detection — turn a found file into the thing you actually wanted.

Finding `/.env`, a config, a source map or a JS bundle is half the job; the
payoff is the credential inside. This scans a response body for high-signal
secrets and returns `(kind, redacted)` pairs. Patterns are curated for LOW false
positives: provider-specific key shapes (which are unambiguous) plus a guarded
generic `key = "value"` rule that rejects obvious placeholders. The match is
redacted (head…tail) so it's actionable in a report/screenshot without dumping
the full secret into logs — the finding points at the file for full retrieval.
"""

from __future__ import annotations

import re

# (kind, compiled pattern, group index of the secret). Provider shapes first —
# these are essentially zero-false-positive. The generic/contextual rules carry
# a capture group and are filtered through _is_placeholder.
_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("aws-access-key",   re.compile(rb"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b"), 1),
    ("google-api-key",   re.compile(rb"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    ("github-token",     re.compile(rb"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{22,})\b"), 1),
    ("slack-token",      re.compile(rb"\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b"), 1),
    ("slack-webhook",    re.compile(rb"(https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+)"), 1),
    ("stripe-key",       re.compile(rb"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,})\b"), 1),
    ("twilio-key",       re.compile(rb"\b(SK[0-9a-fA-F]{32})\b"), 1),
    ("sendgrid-key",     re.compile(rb"\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b"), 1),
    ("npm-token",        re.compile(rb"\b(npm_[0-9A-Za-z]{36})\b"), 1),
    ("private-key",      re.compile(rb"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"), 1),
    ("jwt",              re.compile(rb"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"), 1),
    ("google-oauth-id",  re.compile(rb"\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b"), 1),
    # credentials embedded in a connection URI (user:pass@host)
    ("db-uri-creds",     re.compile(rb"\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|amqp|ftp)://[^\s:@/]+:[^\s:@/]{3,}@[^\s/'\"]+)"), 1),
    # contextual aws secret (40-char base64 next to an aws_secret hint)
    ("aws-secret-key",   re.compile(rb"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+]{40})['\"]"), 1),
    # guarded generic: api_key/secret/token/password = "value". The value must
    # be credential-SHAPED — start alphanumeric and contain only token chars
    # (base64/hex/url-safe + . _ - + / = ~). This rejects minified-JS string
    # concatenation like  "...secret="+this.foo+"...#]/,"  whose captured fragment
    # starts with an operator and carries code punctuation (#, ], comma, …).
    ("generic-secret",   re.compile(rb"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd)\b['\"]?\s*[:=]\s*['\"]([A-Za-z0-9][\w./+\-=~]{5,79})['\"]"), 1),
    # unquoted env-style: KEY=value (.env / shell), value long enough to be real
    ("env-secret",       re.compile(rb"(?im)^[\w.\-]*(?:api[_-]?key|secret[_-]?key|access[_-]?key|secret|token|password|passwd|pwd)[\w.\-]*\s*[:=]\s*([^\s'\"#]{12,120})\s*$"), 1),
    ("bearer-token",     re.compile(rb"(?i)\bbearer\s+([A-Za-z0-9._\-]{20,})"), 1),
]

# Substrings that mark a generic match as a placeholder/example, not a real leak.
_PLACEHOLDER = re.compile(rb"(?i)(?:xxx|your[_-]?|example|changeme|placeholder|dummy|test123|"
                          rb"<[^>]*>|\{\{|\$\{|%[a-z_]+%|\benv\b|null|none|true|false|undefined)")
_MAX_PER_BODY = 25


def _is_placeholder(value: bytes) -> bool:
    if len(set(value)) <= 3:                 # "aaaaaa", "000000" — not a real secret
        return True
    return bool(_PLACEHOLDER.search(value))


# A captured value that is really a code expression, not a credential: a JS
# member-access / dotted-identifier chain (this.foo.bar, window.cfg.token,
# obj.prop) or anything with a `..` run.
_CODE_CHAIN = re.compile(rb"^[A-Za-z_$][\w$]*(?:\.[\w$]+)+$")


def _token_like(seg: bytes) -> bool:
    """A dotted segment that looks like a real credential token, not an
    identifier: long, or mixed letters+digits — `ab9Xk2mZ7q1P` vs `config`."""
    has_d = any(48 <= c <= 57 for c in seg)
    has_a = any(65 <= c <= 90 or 97 <= c <= 122 for c in seg)
    return len(seg) >= 16 or (len(seg) >= 10 and has_d and has_a)


def _looks_like_code(value: bytes) -> bool:
    if b".." in value:
        return True
    if not _CODE_CHAIN.match(value):
        return False
    # A dotted chain is CODE only when NO segment looks like a token — a long /
    # mixed-alnum segment means it's a structured secret (v1.ab9Xk2mZ7q1P,
    # key1234abcd.def5678ghij), which we must keep, not a `this.config.password`
    # identifier chain, which we drop.
    return not any(_token_like(seg) for seg in value.split(b"."))


def _redact(value: bytes) -> str:
    s = value.decode("latin-1", "replace")
    if len(s) <= 12:
        return s[:3] + "…"
    return f"{s[:6]}…{s[-4:]}"


_EXAMPLE = re.compile(rb"(?i)example|sample|0123456789abcdef")   # doc placeholders (AWS' AKIA…EXAMPLE etc.)


def scan(body: bytes) -> list[tuple[str, str]]:
    """Return de-duplicated (kind, redacted_value) secrets found in `body`."""
    if not body:
        return []
    out: list[tuple[str, str]] = []
    seen: set[bytes] = set()                    # by VALUE — a key matched by a specific
    for kind, pat, gi in _PATTERNS:             # provider rule AND the generic one shows once
        for m in pat.finditer(body):
            value = m.group(gi)
            if kind != "private-key" and _EXAMPLE.search(value):
                continue                       # canonical doc/example key, not a real leak
            if kind in ("generic-secret", "env-secret", "bearer-token", "aws-secret-key") and _is_placeholder(value):
                continue
            if kind in ("generic-secret", "env-secret", "bearer-token") and _looks_like_code(value):
                continue                       # JS member chain / dotted identifier — not a secret
            if value in seen:
                continue
            seen.add(value)
            out.append((kind, _redact(value)))
            if len(out) >= _MAX_PER_BODY:
                return out
    return out
