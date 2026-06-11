"""Persistent memory — SQLite store + cross-target retrieval (§3.8 v2 seed).

Two jobs:

  * **persist** every run (profile, evidence, findings) so scans are durable
    and inspectable (`--history`);
  * **recall** — the cheap, interpretable version of "gets better each run":
    paths that existed on *other* hosts sharing a confirmed technology become
    high-priority candidates here. It's retrieval, not a trained model — k-NN
    over a richer fingerprint vector is the next step, but this already learns.

No heavy deps: stdlib sqlite3. The DB doubles as the corpus that a later
n-gram / association-mining phase will train on.
"""

from __future__ import annotations

import json
import math
import sqlite3
import time
from collections import defaultdict
from pathlib import Path

DEFAULT_DB = Path.home() / ".origami" / "memory.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id         INTEGER PRIMARY KEY,
    host       TEXT, base_url TEXT, ts REAL,
    requests   INTEGER, techs TEXT, findings INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
    run_id INTEGER, host TEXT, url TEXT, path TEXT,
    status INTEGER, confidence REAL, origin TEXT, length INTEGER, ctype TEXT
);
CREATE TABLE IF NOT EXISTS host_techs (
    host TEXT, tech TEXT,
    PRIMARY KEY (host, tech)
);
CREATE TABLE IF NOT EXISTS corpus (
    host TEXT, path TEXT, status INTEGER,
    PRIMARY KEY (host, path)
);
CREATE INDEX IF NOT EXISTS idx_corpus_path ON corpus(path);
CREATE TABLE IF NOT EXISTS host_fp (
    host TEXT PRIMARY KEY, vec TEXT          -- fingerprint vector (JSON) for k-NN
);
CREATE TABLE IF NOT EXISTS word_stats (
    tech   TEXT,                             -- confirmed tech, or '*' = context-free
    word   TEXT,                             -- candidate basename (no extension)
    hits   INTEGER DEFAULT 0,
    misses INTEGER DEFAULT 0,
    PRIMARY KEY (tech, word)                 -- the contextual-bandit reward table
);
"""


def fingerprint_vector(profile) -> dict:
    """A sparse feature vector for k-NN: tech scores + structural flags + the
    enabled extension set. Two hosts are 'near' when these line up."""
    vec: dict[str, float] = {f"tech:{t}": s / 100.0 for t, s in profile.tech_scores.items()}
    if profile.waf:
        vec["waf"] = 1.0
    if profile.wildcard:
        vec["wildcard"] = 1.0
    if profile.case_sensitive is False:
        vec["case_insensitive"] = 1.0
    for e in profile.enabled_extensions:
        vec[f"ext:{e}"] = 1.0
    return vec


def _cosine(a: dict, b: dict) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b[k] for k in a.keys() & b.keys())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


class Memory:
    def __init__(self, db_path: Path | str = DEFAULT_DB) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path), timeout=10.0)
        # WAL + a busy timeout so concurrent scans (multi-target, parallel runs)
        # sharing one DB don't fail with "database is locked".
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(_SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def __enter__(self): return self
    def __exit__(self, *a): self.close()

    # ---- recall (cross-target priming) -------------------------------------

    def recall(self, techs: list[str], exclude_host: str, limit: int = 200) -> list[str]:
        """Paths seen on other hosts that share >=1 confirmed technology,
        ranked by how many such hosts had them."""
        if not techs:
            return []
        qmarks = ",".join("?" * len(techs))
        rows = self.db.execute(
            f"""SELECT c.path, COUNT(DISTINCT c.host) AS freq
                  FROM corpus c
                  JOIN host_techs ht ON ht.host = c.host
                 WHERE ht.tech IN ({qmarks})
                   AND c.host != ?
                 GROUP BY c.path
                 ORDER BY freq DESC, c.path
                 LIMIT ?""",
            (*techs, exclude_host, limit),
        ).fetchall()
        return [r[0] for r in rows]

    def recall_knn(self, profile, k: int = 5, limit: int = 200) -> list[str]:
        """Prime from the k most *similar* past hosts (cosine over fingerprint
        vectors), pooling their corpus paths weighted by similarity. More
        precise than shared-tech recall — a near host's exact paths matter more
        than any host that merely shares one technology."""
        vec = fingerprint_vector(profile)
        if not vec:
            return []
        rows = self.db.execute("SELECT host, vec FROM host_fp WHERE host != ?",
                               (profile.host,)).fetchall()
        sims = []
        for host, vjson in rows:
            try:
                s = _cosine(vec, json.loads(vjson))
            except (json.JSONDecodeError, TypeError):
                continue
            if s > 0.1:
                sims.append((s, host))
        sims.sort(reverse=True)
        if not sims:
            return []
        scores: dict[str, float] = defaultdict(float)
        for s, host in sims[:k]:
            for path, _ in self.prior_findings(host):
                scores[path] += s
        return sorted(scores, key=lambda p: -scores[p])[:limit]

    def associate(self, found_paths, min_support: int = 2, min_conf: float = 0.3,
                  limit: int = 60) -> list[str]:
        """Association mining over the corpus: given paths already found on this
        host, return paths that co-occur with them on other hosts above a
        confidence threshold. conf(B|A) = hosts-with-A-and-B / hosts-with-A.
        This is the "found /backup/ → also test /.git/" rule, learned from data.
        """
        found = set(found_paths)
        if not found:
            return []
        best: dict[str, float] = {}
        for a in found:
            hosts_a = [r[0] for r in self.db.execute(
                "SELECT host FROM corpus WHERE path = ?", (a,))]
            if len(hosts_a) < min_support:
                continue
            qm = ",".join("?" * len(hosts_a))
            rows = self.db.execute(
                f"SELECT path, COUNT(DISTINCT host) FROM corpus "
                f"WHERE host IN ({qm}) GROUP BY path", hosts_a).fetchall()
            for b, cnt in rows:
                if b in found:
                    continue
                conf = cnt / len(hosts_a)
                if conf >= min_conf and conf > best.get(b, 0):
                    best[b] = conf
        return sorted(best, key=lambda b: -best[b])[:limit]

    # ---- contextual-bandit reward store ------------------------------------

    def load_word_stats(self, techs: list[str]) -> dict[str, tuple[int, int]]:
        """Pool (hits, misses) per candidate word across the host's confirmed
        techs plus the context-free '*' row — the prior the ranker scores with."""
        keys = list(dict.fromkeys(["*"] + [t for t in techs]))
        qm = ",".join("?" * len(keys))
        rows = self.db.execute(
            f"SELECT word, SUM(hits), SUM(misses) FROM word_stats "
            f"WHERE tech IN ({qm}) GROUP BY word", keys).fetchall()
        return {w: (h or 0, m or 0) for w, h, m in rows}

    def record_word_stats(self, deltas: dict[str, tuple[int, int]], techs: list[str]) -> None:
        """Persist accumulated (hit, miss) deltas under each confirmed tech and
        the global '*' row, so future scans of similar hosts rank smarter."""
        if not deltas:
            return
        for tech in dict.fromkeys(["*"] + list(techs)):
            for word, (h, m) in deltas.items():
                if not h and not m:
                    continue
                self.db.execute(
                    "INSERT INTO word_stats (tech, word, hits, misses) VALUES (?,?,?,?) "
                    "ON CONFLICT(tech, word) DO UPDATE SET hits = hits + ?, misses = misses + ?",
                    (tech, word, h, m, h, m))
        self.db.commit()

    def prior_findings(self, host: str) -> list[tuple[str, int]]:
        rows = self.db.execute(
            "SELECT path, status FROM corpus WHERE host = ? ORDER BY path", (host,)
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    # ---- persistence -------------------------------------------------------

    def record_run(self, profile, result) -> int:
        confirmed = profile.confirmed_techs()
        cur = self.db.execute(
            "INSERT INTO runs (host, base_url, ts, requests, techs, findings) "
            "VALUES (?,?,?,?,?,?)",
            (profile.host, profile.base_url, time.time(), result.requests_made,
             ",".join(confirmed), len(result.findings)),
        )
        run_id = cur.lastrowid

        self.db.executemany(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
            [(run_id, profile.host, f.url, _path(f.url), f.status, f.confidence,
              f.origin, f.length, f.content_type) for f in result.findings],
        )
        for tech in confirmed:
            self.db.execute("INSERT OR IGNORE INTO host_techs VALUES (?,?)",
                            (profile.host, tech))
        # store the fingerprint vector for k-NN priming of future scans
        self.db.execute("INSERT OR REPLACE INTO host_fp VALUES (?,?)",
                        (profile.host, json.dumps(fingerprint_vector(profile))))
        # corpus: only real, low-noise hits (200/3xx/401/403) become memory.
        for f in result.findings:
            if f.status in (200, 204, 301, 302, 401, 403):
                self.db.execute(
                    "INSERT OR REPLACE INTO corpus VALUES (?,?,?)",
                    (profile.host, _path(f.url), f.status))
        self.db.commit()
        return run_id

    def history(self, host: str | None = None, limit: int = 20) -> list[tuple]:
        if host:
            q = ("SELECT id, host, ts, requests, findings, techs FROM runs "
                 "WHERE host = ? ORDER BY ts DESC LIMIT ?")
            return self.db.execute(q, (host, limit)).fetchall()
        q = ("SELECT id, host, ts, requests, findings, techs FROM runs "
             "ORDER BY ts DESC LIMIT ?")
        return self.db.execute(q, (limit,)).fetchall()


def _path(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).path or "/"
