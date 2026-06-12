"""Contextual bandit — candidate ranking for request economy (§3.8 / roadmap 5).

When a target throttles us (a WAF, a 429 wall, a tight `--max-requests`), the
order candidates are fired in stops being free: whatever runs before the budget
runs out is all we get. This ranks each candidate by the probability it pays off
— learned from past scans — so the high-value names go first.

Each candidate word is a Bernoulli arm: hit or miss. Its reward posterior is
Beta(hits + α, misses + β), conditioned on the target's confirmed technologies
(the "context"). We order by a Thompson sample from each posterior — exploiting
words that have paid off while still occasionally exploring rarely-tried ones.
The prior (α small, β larger) encodes the base rate that *most* wordlist entries
miss, so an unseen word sits below a proven hit and above a proven miss.

Learning is always on (every scan updates the store); ranking is the lever the
scanner pulls only under economy mode. No model training — counts + Beta.
"""

from __future__ import annotations

import random
from urllib.parse import urlparse

# Base-rate prior: a wordlist entry misses far more often than it hits, so the
# miss pseudo-count dominates. mean = α/(α+β) ≈ 0.11 for an unseen word.
PRIOR_HIT = 0.5
PRIOR_MISS = 4.0


def word_of(path: str) -> str:
    """The candidate's basename without extension, lowercased — the unit that
    generalizes across hosts (``/api/login.aspx`` and ``/login`` share ``login``)."""
    # startswith, NOT `"://" in path`: a wordlist/payload candidate whose path
    # merely CONTAINS `://` (e.g. an OGNL `${...http://x...}`) is still relative,
    # and running urlparse on arbitrary payload chars is best avoided.
    last = (urlparse(path).path.rstrip("/").rsplit("/", 1)[-1]
            if path.startswith(("http://", "https://"))
            else path.rstrip("/").rsplit("/", 1)[-1])
    if "." in last:
        last = last.rsplit(".", 1)[0]
    return last.lower()


class Ranker:
    """Beta-Thompson ranker over candidate words, seeded from the corpus.

    `stats` maps word → (hits, misses) loaded from memory for the host's techs.
    In-memory `_delta` accumulates this run's observations for write-back.
    """

    def __init__(self, stats: dict[str, tuple[int, int]] | None = None,
                 prior_hit: float = PRIOR_HIT, prior_miss: float = PRIOR_MISS,
                 rng: random.Random | None = None) -> None:
        self.stats = dict(stats or {})
        self.prior_hit = prior_hit
        self.prior_miss = prior_miss
        self._rng = rng or random.Random()
        self._delta: dict[str, list[int]] = {}

    def _ab(self, word: str) -> tuple[float, float]:
        h, m = self.stats.get(word, (0, 0))
        dh, dm = self._delta.get(word, (0, 0))   # list when present, tuple default — both unpack
        return self.prior_hit + h + dh, self.prior_miss + m + dm

    def expected(self, word: str) -> float:
        """Posterior-mean P(hit) — deterministic, used for inspection/tests."""
        a, b = self._ab(word)
        return a / (a + b)

    def sample(self, word: str) -> float:
        """A Thompson draw from the word's reward posterior."""
        a, b = self._ab(word)
        return self._rng.betavariate(a, b)

    def order(self, words):
        """Stable rank of `words` by a Thompson sample, best first."""
        return sorted(words, key=lambda w: -self.sample(word_of(w)))

    def update(self, word: str, hit: bool) -> None:
        d = self._delta.setdefault(word, [0, 0])
        d[0 if hit else 1] += 1

    def observe(self, path: str, hit: bool) -> None:
        self.update(word_of(path), hit)

    def deltas(self) -> dict[str, tuple[int, int]]:
        return {w: (d[0], d[1]) for w, d in self._delta.items() if d[0] or d[1]}
