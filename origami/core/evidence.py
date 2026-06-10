"""Evidence bus + TargetProfile — the brain's state for one host.

MVP keeps the "bus" deliberately simple (§3.3): evidence is a scored list and
`tech_scores` is recomputed by a plain reducer. No pub/sub, no message queue.
Everything a fold needs to decide is reachable from the TargetProfile.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Evidence:
    """One scored signal about the target."""

    source: str            # "header" | "cookie" | "favicon" | "shortscan" | "error_page" | ...
    tech: str              # technology the signal points at, e.g. "iis", "php"
    detail: str            # human-readable: "Server: Microsoft-IIS/10.0"
    weight: float          # contribution to the tech score (roughly 0..100)
    path_prefix: str = "/"  # fingerprint is per-prefix, not global


@dataclass(slots=True)
class ContextBaseline:
    """The "what a miss looks like" profile for one context.

    A context is (directory prefix, extension class) — soft-404 behaviour
    varies by both, so we never collapse this to a single global number.
    Built from several guaranteed-nonexistent probes; a real candidate is a
    hit when it falls *outside* this profile.
    """

    prefix: str
    ext_class: str
    status: int                       # representative status of a miss
    simhashes: list[int] = field(default_factory=list)  # miss-body fingerprints
    length_lo: int = 0
    length_hi: int = 0
    content_type: str = ""
    redirect_to: str = ""             # normalized redirect target of a miss, if any
    is_soft404: bool = False          # miss returns 2xx/3xx instead of 404
    samples: int = 0
    # (status, simhash) signatures learned mid-scan for multi-modal soft-404
    # hosts — e.g. one that 302s most paths but serves a generic 200 for others.
    soft_signatures: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class TargetProfile:
    """Persistent state of one target — also the seed of cross-target learning."""

    host: str
    base_url: str
    tech_scores: dict[str, float] = field(default_factory=dict)
    baseline: dict[str, ContextBaseline] = field(default_factory=dict)
    case_sensitive: bool | None = None     # None == not determined yet
    wildcard: bool = False
    waf: str = ""                          # detected WAF/block product, if any
    enabled_extensions: set[str] = field(default_factory=set)
    parameters: set[str] = field(default_factory=set)  # harvested param names (pentest intel)
    evidence: list[Evidence] = field(default_factory=list)

    # ---- evidence bus (list + reducer) -------------------------------------

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        self._reduce()

    def _reduce(self) -> None:
        """Recompute tech_scores from the full evidence list.

        Additive, capped at 100, per technology. Cheap enough to redo on every
        new signal at MVP volumes; swap for incremental if it ever matters.
        """
        scores: dict[str, float] = {}
        for ev in self.evidence:
            scores[ev.tech] = min(100.0, scores.get(ev.tech, 0.0) + ev.weight)
        self.tech_scores = dict(sorted(scores.items(), key=lambda kv: -kv[1]))

    def confirmed_techs(self, threshold: float = 50.0) -> list[str]:
        return [t for t, s in self.tech_scores.items() if s >= threshold]

    @staticmethod
    def context_key(prefix: str, ext_class: str) -> str:
        return f"{prefix}|{ext_class}"
