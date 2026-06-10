"""Body normalization + 64-bit simhash.

Comparing responses by raw Content-Length breaks the moment a page carries a
CSRF token, a CSP nonce, a timestamp or a ViewState — anything dynamic shifts
the size every request. We instead strip the volatile bits, tokenize what's
left, and compute a locality-sensitive hash (simhash) of the *structure*. Two
responses are "the same shape" when their simhashes are within a small Hamming
distance.

Uses blake2b (stable across processes) rather than the builtin hash(), whose
randomization would make simhashes non-reproducible between runs.
"""

from __future__ import annotations

import hashlib
import re

# Volatile fragments we blank out before hashing, so dynamic noise doesn't move
# the structural fingerprint. Order doesn't matter; all are applied.
_VOLATILE = [
    re.compile(rb"<[^>]+>", re.I),                                  # all tags -> drop attrs/nonces
    re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
               rb"[0-9a-f]{4}-[0-9a-f]{12}", re.I),                 # UUID (WAF support IDs etc.)
    re.compile(rb"[0-9a-f]{16,}", re.I),                            # long hex blobs (tokens, hashes)
    re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}"),                       # base64-ish blobs (viewstate, csrf)
    re.compile(rb"\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}", re.I),   # ISO timestamps
    re.compile(rb"\b\d{10,13}\b"),                                  # epoch timestamps
    re.compile(rb"\s+"),                                            # collapse whitespace
]

_TOKEN = re.compile(rb"[a-z0-9]{2,}", re.I)
_MASK64 = (1 << 64) - 1


def normalize(body: bytes) -> bytes:
    """Strip volatile fragments and collapse whitespace."""
    out = body
    for pat in _VOLATILE:
        out = pat.sub(b" ", out)
    return out.strip().lower()


def _shingles(norm: bytes, k: int = 3) -> list[bytes]:
    """k-word shingles over the normalized body — captures local structure."""
    tokens = _TOKEN.findall(norm)
    if len(tokens) < k:
        return tokens or [norm]
    return [b" ".join(tokens[i : i + k]) for i in range(len(tokens) - k + 1)]


def simhash(body: bytes) -> int:
    """64-bit simhash of the normalized body."""
    norm = normalize(body)
    v = [0] * 64
    for sh in _shingles(norm):
        h = int.from_bytes(hashlib.blake2b(sh, digest_size=8).digest(), "big")
        for i in range(64):
            v[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(64):
        if v[i] > 0:
            out |= 1 << i
    return out


def hamming(a: int, b: int) -> int:
    """Bit distance between two simhashes (0 == identical structure)."""
    return ((a ^ b) & _MASK64).bit_count()
