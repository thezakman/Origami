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
import ssl
import time
from dataclasses import dataclass, field

import httpx

from origami.core.normalize import simhash

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# A pool of realistic, current browser UAs for --rotate-ua: spreading requests
# across plausible clients makes a per-UA rate-limit / fingerprint heuristic
# harder to pin on the scan (a crude but real WAF-evasion lever).
_UA_POOL = [
    DEFAULT_UA,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 Edg/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


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
    rate: float = 0.0                           # max AGGREGATE requests/sec across all workers (0 = unlimited)
    delay: float = 0.0                          # fixed per-request floor (stealth / rate control)
    jitter: tuple[float, float] = (0.0, 0.05)   # seconds, uniform
    max_retries: int = 2
    user_agent: str = DEFAULT_UA
    rotate_ua: bool = False                     # pick a random UA from _UA_POOL per request (--rotate-ua)
    headers: dict[str, str] = field(default_factory=dict)   # extra headers (auth/cookies) sent on every request
    proxy: str = ""                             # route through an intercepting proxy (Burp/ZAP), e.g. http://127.0.0.1:8080
    proxies: list[str] = field(default_factory=list)   # rotate per request across these (--proxy-file); overrides `proxy`
    http2: bool = False                         # negotiate HTTP/2 (ALPN) — matches modern CDNs (--http2; needs the h2 pkg)
    follow_redirects: bool = False              # we want to *see* redirects
    verify_tls: bool = False                    # pentest targets: don't choke on certs
    legacy_tls: bool = False                    # start with a lowered OpenSSL security level (weak-DH/legacy servers); auto-engaged on a weak-TLS handshake error
    backoff_base: float = 0.8                   # seconds, grows on pushback
    max_body: int = 2_000_000                   # cap body read (bytes) — OOM guard on hostile/huge responses


# Statuses that mean "slow down", not "answer".
_PUSHBACK = {429, 503}

# TLS handshake errors that a *lowered security level* (SECLEVEL=1) resolves —
# a weak Diffie-Hellman key, an old cipher, or legacy renegotiation the modern
# default rejects. These are the servers curl reaches but a strict Python OpenSSL
# refuses; we drop the security level and retry rather than call them "unreachable".
_WEAK_TLS = ("dh_key_too_small", "dh key too small", "key_too_small",
             "handshake_failure", "handshake failure", "unsafe_legacy",
             "md_too_weak", "ca_md_too_weak", "sslv3_alert", "no_ciphers",
             "unsupported_protocol", "wrong_signature_type", "legacy")


def _looks_weak_tls(err: str) -> bool:
    """True when a transport error is a TLS handshake rejection that lowering the
    OpenSSL security level (SECLEVEL=1) would fix."""
    e = err.lower()
    return ("ssl" in e or "tls" in e) and any(s in e for s in _WEAK_TLS)


def _legacy_ssl_context(verify: bool) -> ssl.SSLContext:
    """A permissive TLS context for legacy servers (weak DH params / old ciphers)
    that a default OpenSSL security level rejects — mirrors what curl reaches.
    Drops to SECLEVEL=1; cert verification is kept unless `verify` is False."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx

# Cap on an honored Retry-After: a server (or a hostile WAF) can send
# `Retry-After: 86400` — we respect the signal but never stall the scan for a day.
_RETRY_AFTER_CAP = 30.0


def _parse_retry_after(value: str | None, now: float) -> float | None:
    """Parse an HTTP `Retry-After` header → seconds to wait (>= 0), or None if
    absent/unparseable. Handles both forms: delta-seconds (`"120"`) and an
    HTTP-date (`"Wed, 21 Oct 2015 07:28:00 GMT"`)."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if dt is None:
        return None
    try:
        return max(0.0, dt.timestamp() - now)
    except (ValueError, OverflowError, OSError):
        return None


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
        self._clients: list[httpx.AsyncClient] = []   # one per proxy (rotated)
        # Adaptive concurrency: a float limit between 1 and cfg.concurrency,
        # gated by a condition over the live in-flight count.
        self._cond = asyncio.Condition()
        self._inflight = 0
        self._limit = float(self.cfg.concurrency)
        # Cooperative backoff: when the target pushes back we raise a floor on
        # the per-request delay that every worker observes.
        self._delay_floor = 0.0
        # Aggregate rate cap (token-bucket style): a monotonic "next slot" time
        # every worker reserves under a lock, so request STARTS leave at most
        # cfg.rate per second no matter how many workers are in flight. This is
        # the knob that respects a WAF's req/s threshold (unlike --delay, which
        # is per-worker and so scales with concurrency).
        self._rate_lock = asyncio.Lock()
        self._next_slot = 0.0
        self.pushback_events = 0
        self.total_requests = 0      # every logical fetch THIS run (calibration, harvests, scan)
        self.prior_requests = 0      # requests spent on earlier runs of this target (set on --resume)
        self.on_request = None       # optional callback, fired once per fetch (UI heartbeat)
        # Legacy-TLS: some (often enterprise/legacy) servers negotiate a weak DH
        # key or an old cipher that a default OpenSSL security level rejects — the
        # handshake fails where curl succeeds. We start strict and, on the first
        # such handshake error, transparently drop to SECLEVEL=1 and retry.
        self._legacy_active = bool(self.cfg.legacy_tls)
        self.legacy_tls_engaged = False   # True once the fallback actually kicked in (for a warning)

    @property
    def concurrency_limit(self) -> int:
        """Current adaptive in-flight ceiling (telemetry)."""
        return max(1, int(self._limit))

    @property
    def spent(self) -> int:
        """Total requests against this target across runs — what --max-requests
        bounds (so a resumed scan doesn't get a fresh budget each time)."""
        return self.prior_requests + self.total_requests

    def _new_client(self, proxy: str | None) -> httpx.AsyncClient:
        # User-Agent first so an explicit -H "User-Agent: ..." override wins.
        # `verify` is a lowered-security SSL context once legacy-TLS is engaged.
        verify = _legacy_ssl_context(self.cfg.verify_tls) if self._legacy_active else self.cfg.verify_tls
        return httpx.AsyncClient(
            timeout=self.cfg.timeout,
            follow_redirects=self.cfg.follow_redirects,
            verify=verify,
            proxy=proxy or None,
            http2=self.cfg.http2,             # negotiated via ALPN; CLI guards the h2 dep
            headers={"User-Agent": self.cfg.user_agent, **self.cfg.headers},
            limits=httpx.Limits(max_connections=self.cfg.concurrency * 2),
        )

    def replay_client(self, proxy: str) -> httpx.AsyncClient:
        """A standalone client bound to a replay proxy (--replay-proxy): confirmed
        findings are re-issued through it so only real hits reach Burp/ZAP, keeping
        the intercept sitemap clean (separate from --proxy, which sees every probe).
        The caller owns it and must aclose() it."""
        return self._new_client(proxy)

    async def __aenter__(self) -> "Engine":
        # One client per proxy when --proxy-file gives a pool (requests spread
        # across egress IPs — a per-source rate-limit/ban can't pin the scan);
        # otherwise a single client (the --proxy one, or none).
        proxies = self.cfg.proxies or [self.cfg.proxy or ""]
        self._clients = [self._new_client(p or None) for p in proxies]
        self._client = self._clients[0]       # default/first (back-compat)
        return self

    async def _enable_legacy_tls(self) -> None:
        """Rebuild the client pool with a lowered TLS security level after a
        weak-DH/legacy handshake failure — so the rest of the scan reaches the
        server that curl can. Idempotent; happens at most once (usually the root
        fetch, before concurrency ramps)."""
        if self._legacy_active:
            return
        self._legacy_active = True
        self.legacy_tls_engaged = True
        old = self._clients
        proxies = self.cfg.proxies or [self.cfg.proxy or ""]
        self._clients = [self._new_client(p or None) for p in proxies]
        self._client = self._clients[0]
        for c in old:
            try:
                await c.aclose()
            except Exception:
                pass

    def _pick_client(self) -> httpx.AsyncClient:
        return self._clients[0] if len(self._clients) == 1 else random.choice(self._clients)

    async def __aexit__(self, *exc) -> None:
        for c in getattr(self, "_clients", []):
            await c.aclose()
        self._clients = []
        self._client = None

    async def _sleep_before(self) -> None:
        lo, hi = self.cfg.jitter
        await asyncio.sleep(self.cfg.delay + self._delay_floor + random.uniform(lo, hi))

    async def _pace(self) -> None:
        """Block until this worker's aggregate-rate slot opens (no-op if rate=0).

        Reserving the slot under the lock spaces request *starts* by 1/rate; the
        HTTP round-trips still overlap up to the concurrency limit, so throughput
        is capped at the rate without forcing serial requests."""
        if not self.cfg.rate:
            return
        interval = 1.0 / self.cfg.rate
        # Reserve this worker's slot under the lock, then release BEFORE sleeping
        # so other workers can grab their own slots concurrently — request starts
        # end up spaced by 1/rate while the actual round-trips still overlap.
        async with self._rate_lock:
            now = time.monotonic()
            slot = self._next_slot if self._next_slot > now else now
            self._next_slot = slot + interval
        wait = slot - now
        if wait > 0:
            await asyncio.sleep(wait)

    async def _acquire(self) -> None:
        async with self._cond:
            while self._inflight >= self._limit:
                await self._cond.wait()
            self._inflight += 1

    async def _release(self) -> None:
        async with self._cond:
            self._inflight -= 1
            self._cond.notify_all()      # wake waiters to re-read the (possibly grown) limit

    def _note_pushback(self, retry_after: float | None = None) -> None:
        self.pushback_events += 1
        if retry_after and retry_after > 0:
            # Honor the server's EXPLICIT Retry-After (capped) — it tells us exactly
            # how long to wait, better than guessing. _sleep_before reads the floor,
            # so the retry + subsequent requests respect it; _relax decays it after.
            self._delay_floor = min(_RETRY_AFTER_CAP, max(self._delay_floor, retry_after))
        else:
            # No header: AIMD guess — grow the shared delay floor (capped).
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
                await self._pace()            # inside the loop so retries also honor --rate
                await self._sleep_before()
                try:
                    probe = await self._stream_probe(url, method, keep_body, kw)
                except (httpx.TransportError, httpx.HTTPError, OSError) as e:
                    # Transient transport failure (timeout, connection reset/refused,
                    # DNS, or a raw ssl.SSLError — a subclass of OSError — that escapes
                    # httpx's wrapping on a flaky TLS read, common with CDN/WAF
                    # tarpitting). Retry, but do NOT treat it as throttle pushback: a
                    # handful of slow/dead URLs must not collapse global concurrency
                    # (and inflate pushback_events) for the whole, otherwise-healthy
                    # scan. Only an explicit 429/503 status (below) is a reliable
                    # overload signal. The held in-flight slot already slows us.
                    last_err = f"{type(e).__name__}: {e}"
                    # A weak-DH/legacy-cipher handshake the strict default rejects:
                    # drop to SECLEVEL=1 and retry (reaches what curl reaches).
                    if _looks_weak_tls(last_err) and not self._legacy_active:
                        await self._enable_legacy_tls()
                    continue
                except (ValueError, UnicodeError, httpx.InvalidURL) as e:
                    # A malformed candidate URL — e.g. a wordlist/payload whose raw
                    # chars (`${...}`, quotes, braces) break httpx/urllib URL
                    # parsing — raises a NON-httpx error that retrying can't fix.
                    # Skip just this one URL with an error probe so a single bad
                    # candidate can't crash the whole scan.
                    return Probe(url, method, 0, 0, 0, 0, "", "", 0, 0.0,
                                 error=f"bad-url: {type(e).__name__}: {e}")

                if probe.status in _PUSHBACK:
                    # honor an explicit Retry-After if the server sent one
                    self._note_pushback(_parse_retry_after(probe.headers.get("retry-after"), time.time()))
                    if attempt < self.cfg.max_retries:
                        continue          # _sleep_before waits the (now Retry-After-aware) floor
                    return probe          # out of retries — return the throttle, but DON'T relax

                self._relax()
                return probe
        finally:
            await self._release()

        return Probe(url, method, 0, 0, 0, 0, "", "", 0, 0.0, error=last_err or "max_retries")

    async def _stream_probe(self, url: str, method: str, keep_body: bool, kw: dict) -> Probe:
        """Stream the response, reading at most cfg.max_body bytes — so a hostile
        or accidental multi-GB body can't OOM the scan or hang on split()."""
        t0 = time.perf_counter()        # r.elapsed is unset when we break mid-body
        if self.cfg.rotate_ua:          # per-request UA from the pool (merge, don't clobber kw headers)
            hdrs = dict(kw.get("headers") or {})
            hdrs["User-Agent"] = random.choice(_UA_POOL)
            kw = {**kw, "headers": hdrs}
        # Optional per-request body-cap override (kept out of the kwargs httpx sees):
        # a legitimate OpenAPI spec can exceed the default OOM guard, and truncating
        # it to invalid JSON silently loses the whole declared API surface.
        cap = kw.get("max_body") or self.cfg.max_body
        kw = {k: v for k, v in kw.items() if k != "max_body"}
        async with self._pick_client().stream(method, url, **kw) as r:
            chunks: list[bytes] = []
            total = 0
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
