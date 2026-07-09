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
from collections import Counter

# Volatile fragments we blank out before hashing, so dynamic noise doesn't move
# the structural fingerprint. Order doesn't matter; all are applied.
_VOLATILE = [
    re.compile(rb"<!--.*?-->", re.S),                              # HTML comments dropped WHOLE (a `>` inside one would truncate the tag rule below)
    re.compile(rb"<[^<>]*>", re.I),                                 # all tags -> drop attrs/nonces. `[^<>]` (not `[^>]+`) so a run of unclosed `<` can't trigger O(n^2) backtracking (ReDoS) — simhash runs on every body
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

# Fast lane accumulation (bit-sliced popcount) — see simhash(). Each of the 64
# simhash lanes gets a `_LANE` -bit counter block inside one big integer, so all
# 64 per-shingle updates become ONE add instead of a 64-iteration Python loop.
# `_LANE = 32` gives 4.3 billion headroom per lane — a lane count can't exceed the
# shingle count, itself bounded by the body-size cap, so this never overflows.
_LANE = 32
_LANE_MASK = (1 << _LANE) - 1
# _SPREAD[b] scatters the 8 bits of byte value `b` into 8 lane blocks (bit j → the
# low bit of block j), so a byte's contribution to the counter is a single lookup.
_SPREAD = [sum((1 << (j * _LANE)) for j in range(8) if (b >> j) & 1) for b in range(256)]


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
    """64-bit simhash of the normalized body.

    Byte-identical to the naive `for i in range(64): v[i] += ±1 per shingle`, but:
      * duplicate shingles are hashed ONCE and weighted by count (HTML repeats a
        lot of markup — nav/footer/list rows — so this collapses most of the work);
      * the 64 lane counters live packed in one big integer, updated with a single
        weighted add per unique shingle instead of a 64-iteration Python loop.
    Result and semantics are unchanged (the simhashes stored in the memory DB stay
    comparable across versions); it's ~2–4× faster per response — and simhash runs
    on every response, so this is pure throughput."""
    counts = Counter(_shingles(normalize(body)))
    acc = 0
    total = 0
    for sh, w in counts.items():
        d = hashlib.blake2b(sh, digest_size=8).digest()   # 8 bytes, big-endian
        # d[7] is the least-significant byte → lanes 0..7; d[0] → lanes 56..63.
        spread = (_SPREAD[d[7]] | _SPREAD[d[6]] << 8 * _LANE | _SPREAD[d[5]] << 16 * _LANE
                  | _SPREAD[d[4]] << 24 * _LANE | _SPREAD[d[3]] << 32 * _LANE
                  | _SPREAD[d[2]] << 40 * _LANE | _SPREAD[d[1]] << 48 * _LANE
                  | _SPREAD[d[0]] << 56 * _LANE)
        acc += w * spread
        total += w
    out = 0
    for i in range(64):                                   # once, not per shingle
        if 2 * ((acc >> (i * _LANE)) & _LANE_MASK) - total > 0:
            out |= 1 << i
    return out


def hamming(a: int, b: int) -> int:
    """Bit distance between two simhashes (0 == identical structure)."""
    return ((a ^ b) & _MASK64).bit_count()
