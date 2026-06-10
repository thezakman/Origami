"""Character n-gram name completer — the shortscan Regime-2 generator (§4).

8.3 truncates a name to 6 chars (`APIINT~1`), and the real name is often longer
(`apiintegracao`). When the full name isn't referenced anywhere (so the
constraint-filter can't find it), we *generate* plausible completions with a
small character-level Markov model trained on a corpus of names.

Deliberately tiny and interpretable — order-N char model + beam search, no ML
framework. It improves as the corpus grows (the target's own vocabulary + the
cross-target memory of confirmed names), which is exactly the "gets better each
run" property, learned not trained.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict

_START = "\x02"
_END = "\x03"


class NGram:
    def __init__(self, order: int = 3) -> None:
        self.order = order
        self.model: dict[str, Counter] = defaultdict(Counter)

    def train(self, names) -> "NGram":
        for raw in names:
            n = "".join(c for c in str(raw).lower() if c.isalnum() or c in "-_")
            if not n:
                continue
            s = _START * self.order + n + _END
            for i in range(self.order, len(s)):
                self.model[s[i - self.order:i]][s[i]] += 1
        return self

    @property
    def trained(self) -> bool:
        return bool(self.model)

    def complete(self, prefix: str, n_results: int = 8, max_len: int = 24,
                 beam: int = 12, branch: int = 4) -> list[str]:
        """Top plausible full names starting with `prefix` (beam search)."""
        prefix = "".join(c for c in prefix.lower() if c.isalnum() or c in "-_")
        if not prefix or not self.model:
            return []
        beams = [(prefix, 0.0)]
        done: list[tuple[str, float]] = []
        for _ in range(max_len):
            nxt: list[tuple[str, float]] = []
            for s, score in beams:
                ctx = (_START * self.order + s)[-self.order:]
                counts = self.model.get(ctx)
                if not counts:
                    done.append((s, score))
                    continue
                total = sum(counts.values())
                for ch, c in counts.most_common(branch):
                    ns = score - math.log(c / total)
                    if ch == _END:
                        done.append((s, ns))
                    else:
                        nxt.append((s + ch, ns))
            if not nxt:
                break
            nxt.sort(key=lambda x: x[1])
            beams = nxt[:beam]
        done += beams
        out, seen = [], set()
        for s, _ in sorted(done, key=lambda x: x[1]):
            if len(s) > len(prefix) and s not in seen:
                seen.add(s)
                out.append(s)
            if len(out) >= n_results:
                break
        return out
