"""Async request engine — the fast half of the engine/brain split.

A thin wrapper over httpx.AsyncClient that the rest of Origami talks to. It
owns three operational-safety concerns that belong here and nowhere else
(§3.10 of origami.md):

  * a concurrency cap (semaphore) so we never open more sockets than asked;
  * jitter between requests;
  * adaptive backoff when the target pushes back (429 / 503 / connection
    reset) — first line of WAF/rate-limit politeness. The smart budget
    optimization (bandit) comes later and sits in the brain, not here.

Every fetch returns a Probe: a normalized, comparable view of the response
(status, sizes, content-type, redirect target, body simhash, elapsed). The
brain never sees a raw httpx.Response.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field

import httpx

from origami.core.normalize import simhash

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


@dataclass(slots=True)
class Probe:
    """A normalized, comparable view of one HTTP response."""

    url: str
    method: str
    status: int
    length: int           # body length in bytes (post-read)
    words: int
    lines: int
    content_type: str
    location: str         # redirect target (Location header), '' if none
    body_simhash: int
    elapsed_ms: float
    headers: dict[str, str] = field(default_factory=dict)   # lowercased keys
    cookies: list[str] = field(default_factory=list)        # raw Set-Cookie values
    body_head: bytes = b""                                   # first bytes, for error-page fp
    body: bytes = b""                                        # full body (only when keep_body=True)
    error: str = ""       # transport error, if the request never completed

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class EngineConfig:
    concurrency: int = 20
    timeout: float = 10.0
    jitter: tuple[float, float] = (0.0, 0.05)   # seconds, uniform
    max_retries: int = 2
    user_agent: str = DEFAULT_UA
    headers: dict[str, str] = field(default_factory=dict)   # extra headers (auth/cookies) sent on every request
    proxy: str = ""                             # route through an intercepting proxy (Burp/ZAP), e.g. http://127.0.0.1:8080
    follow_redirects: bool = False              # we want to *see* redirects
    verify_tls: bool = False                    # pentest targets: don't choke on certs
    backoff_base: float = 0.8                   # seconds, grows on pushback
    max_body: int = 2_000_000                   # cap body read (bytes) — OOM guard on hostile/huge responses


# Statuses that mean "slow down", not "answer".
_PUSHBACK = {429, 503}


class Engine:
    """Owns the httpx client + an *adaptive* concurrency gate + backoff state.

    Politeness under a WAF/rate-limit is AIMD (TCP-style): a pushback (429/503/
    transport reset) both raises the shared per-request delay floor AND halves
    the in-flight limit (multiplicative decrease); clean responses decay the
    delay and ramp the limit back up one slot at a time (additive increase). So
    a target that keeps pushing back doesn't just see slower requests — it sees
    *fewer concurrent* ones, down to a single serial trickle if it stays angry.
    """

    def __init__(self, cfg: EngineConfig | None = None) -> None:
        self.cfg = cfg or EngineConfig()
        self._client: httpx.AsyncClient | None = None
        # Adaptive concurrency: a float limit between 1 and cfg.concurrency,
        # gated by a condition over the live in-flight count.
        self._cond = asyncio.Condition()
        self._inflight = 0
        self._limit = float(self.cfg.concurrency)
        # Cooperative backoff: when the target pushes back we raise a floor on
        # the per-request delay that every worker observes.
        self._delay_floor = 0.0
        self.pushback_events = 0
        self.total_requests = 0      # every logical fetch (calibration, harvests, scan)
        self.on_request = None       # optional callback, fired once per fetch (UI heartbeat)

    @property
    def concurrency_limit(self) -> int:
        """Current adaptive in-flight ceiling (telemetry)."""
        return max(1, int(self._limit))

    async def __aenter__(self) -> "Engine":
        # User-Agent first so an explicit -H "User-Agent: ..." override wins.
        self._client = httpx.AsyncClient(
            timeout=self.cfg.timeout,
            follow_redirects=self.cfg.follow_redirects,
            verify=self.cfg.verify_tls,
            proxy=self.cfg.proxy or None,
            headers={"User-Agent": self.cfg.user_agent, **self.cfg.headers},
            limits=httpx.Limits(max_connections=self.cfg.concurrency * 2),
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _sleep_before(self) -> None:
        lo, hi = self.cfg.jitter
        await asyncio.sleep(self._delay_floor + random.uniform(lo, hi))

    async def _acquire(self) -> None:
        async with self._cond:
            while self._inflight >= self._limit:
                await self._cond.wait()
            self._inflight += 1

    async def _release(self) -> None:
        async with self._cond:
            self._inflight -= 1
            self._cond.notify_all()      # wake waiters to re-read the (possibly grown) limit

    def _note_pushback(self) -> None:
        self.pushback_events += 1
        # Grow the shared delay floor; cap so we don't stall forever.
        self._delay_floor = min(5.0, max(self.cfg.backoff_base, self._delay_floor * 2))
        # Multiplicative decrease: halve the concurrency ceiling (floor of 1).
        self._limit = max(1.0, self._limit / 2.0)

    def _relax(self) -> None:
        # Decay the floor on clean responses so we recover after a burst.
        if self._delay_floor:
            self._delay_floor = max(0.0, self._delay_floor * 0.9 - 0.01)
        # Additive increase: ramp the ceiling back one slot at a time.
        if self._limit < self.cfg.concurrency:
            self._limit = min(float(self.cfg.concurrency), self._limit + 0.5)

    async def fetch(self, url: str, method: str = "GET", keep_body: bool = False, **kw) -> Probe:
        assert self._client is not None, "use `async with Engine() as engine`"
        last_err = ""
        self.total_requests += 1
        if self.on_request is not None:
            self.on_request()
        await self._acquire()
        try:
            for attempt in range(self.cfg.max_retries + 1):
                await self._sleep_before()
                try:
                    probe = await self._stream_probe(url, method, keep_body, kw)
                except (httpx.TransportError, httpx.HTTPError) as e:
                    last_err = f"{type(e).__name__}: {e}"
                    self._note_pushback()
                    continue
                except (ValueError, UnicodeError, httpx.InvalidURL) as e:
                    # A malformed candidate URL — e.g. a wordlist/payload whose raw
                    # chars (`${...}`, quotes, braces) break httpx/urllib URL
                    # parsing — raises a NON-httpx error that retrying can't fix.
                    # Skip just this one URL with an error probe so a single bad
                    # candidate can't crash the whole scan.
                    return Probe(url, method, 0, 0, 0, 0, "", "", 0, 0.0,
                                 error=f"bad-url: {type(e).__name__}: {e}")

                if probe.status in _PUSHBACK and attempt < self.cfg.max_retries:
                    self._note_pushback()
                    continue

                self._relax()
                return probe
        finally:
            await self._release()

        return Probe(url, method, 0, 0, 0, 0, "", "", 0, 0.0, error=last_err or "max_retries")

    async def _stream_probe(self, url: str, method: str, keep_body: bool, kw: dict) -> Probe:
        """Stream the response, reading at most cfg.max_body bytes — so a hostile
        or accidental multi-GB body can't OOM the scan or hang on split()."""
        t0 = time.perf_counter()        # r.elapsed is unset when we break mid-body
        async with self._client.stream(method, url, **kw) as r:
            chunks: list[bytes] = []
            total = 0
            cap = self.cfg.max_body
            async for chunk in r.aiter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= cap:
                    break
            body = b"".join(chunks)[:cap]
            text_ct = r.headers.get("content-type", "").split(";")[0].strip().lower()
            return Probe(
                url=url,
                method=method,
                status=r.status_code,
                length=len(body),
                words=len(body.split()),
                lines=body.count(b"\n") + 1,
                content_type=text_ct,
                location=r.headers.get("location", ""),
                body_simhash=simhash(body),
                elapsed_ms=(time.perf_counter() - t0) * 1000,
                headers={k.lower(): v for k, v in r.headers.items()},
                cookies=r.headers.get_list("set-cookie"),
                body_head=body[:2048],
                body=body if keep_body else b"",
            )

    async def gather(self, urls: list[str], method: str = "GET") -> list[Probe]:
        """Fire many requests; the semaphore bounds real concurrency."""
        return await asyncio.gather(*(self.fetch(u, method) for u in urls))
