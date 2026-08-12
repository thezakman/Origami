"""Origami unit tests — param fuzzing, cache poisoning, session/auth-wall detection.

Split from tests/test_core.py; run via unittest discover.
"""
import unittest

from origami.core.normalize import hamming, simhash
from origami.core.evidence import ContextBaseline, TargetProfile
from origami.core.httpclient import Probe
from origami.core.response_classifier import Filters, classify
from origami.modules import waf
from origami.modules.discovery import backups, js_parser, robots, shortname


def make_probe(status=200, body=b"<html>hi</html>", url="http://t/x", ctype="text/html",
               location="", headers=None):
    return Probe(url=url, method="GET", status=status, length=len(body),
                 words=len(body.split()), lines=body.count(b"\n") + 1,
                 content_type=ctype, location=location,
                 body_simhash=simhash(body), elapsed_ms=1.0,
                 headers=headers or {},
                 body_head=body[:2048], body=body)


def make_finding(url, status=200):
    from origami.core.response_classifier import Finding
    return Finding(url, status, 100, "text/html", 0.9, "wordlist")


def _git_index(paths):
    import struct
    body = b"DIRC" + struct.pack(">II", 2, len(paths))
    for p in paths:
        name = p.encode()
        entry = b"\x00" * 60 + struct.pack(">H", len(name)) + name
        entry += b"\x00" * (8 - (len(entry) % 8))
        body += entry
    return body


def _ds_store(names):
    import struct
    body = b"\x00" * 8
    for n in names:
        nb = n.encode("utf-16-be")
        body += struct.pack(">I", len(n)) + nb + b"Iloc" + b"blob"
    return body + b"\x00" * 4


def _svn_wcdb(relpaths):
    import sqlite3
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE nodes (local_relpath TEXT)")
    con.executemany("INSERT INTO nodes VALUES (?)", [("",)] + [(p,) for p in relpaths])
    con.commit()
    data = con.serialize()
    con.close()
    return data



class TestParamFuzz(unittest.TestCase):
    def test_safe_names_and_batches(self):
        from origami.modules import paramfuzz as P
        names = P.safe_names(["id", "q", "bad name", "x;y", "id", "redirect"])
        self.assertEqual(names, ["id", "q", "redirect"])           # junk + dupes dropped
        (qs, tmap, ctl), = P.build_batches(["id"], batch_size=5, run="oztest")
        self.assertIn("id=oztest0q", qs)
        self.assertIn("oztestctlname=", qs)                        # control param present
        self.assertEqual(P.reflected(b"echo oztest0q here", tmap), ["id"])
        self.assertTrue(P.control_reflected(b"... oztestctlq ...", ctl))

    def test_fold_flags_reflected_param(self):
        import asyncio
        from urllib.parse import urlparse, parse_qs
        from origami.core.scanner import _param_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class FakeEngine:                       # reflects ONLY the 'q' param's canary
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                q = parse_qs(urlparse(url).query)
                body = (b"results for " + q["q"][0].encode()) if "q" in q else b"home"
                return make_probe(200, body, url=url, ctype="text/html")

        prof = TargetProfile(host="h", base_url="https://h/")
        prof.parameters = {"q"}                 # harvested param name
        f = Finding("https://h/search.php", 200, 10, "text/html", 0.9, "wordlist")
        result = ScanResult(profile=prof, findings=[f])
        streamed = []
        opts = ScanOptions(param_fuzz=True, finding_sink=streamed.append)
        asyncio.run(_param_fold(FakeEngine(), prof, result, opts, NullObserver()))
        self.assertIn("param", f.tags)
        self.assertIn("xss-lead", f.tags)              # breakout confirmed a raw HTML-sink reflection
        self.assertIn("q (html", f.note)               # graded by injection context
        self.assertIn("UNESCAPED", f.note)             # the breakout probe proved metachars came back raw
        self.assertTrue(any(s is f for s in streamed))             # streamed for JSONL

    def test_fold_flags_open_redirect_and_header(self):
        import asyncio
        from urllib.parse import urlparse, parse_qs
        from origami.core.scanner import _param_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class FakeEngine:                       # 3xx endpoint: reflects 'url' into Location
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                q = parse_qs(urlparse(url).query)
                loc = q.get("url", [""])[0]     # open-redirect: canary echoed into Location
                hdrs = {"location": loc}
                if "q" in q:
                    hdrs["x-echo"] = q["q"][0]  # header reflection
                return make_probe(302, b"", url=url, location=loc, headers=hdrs)

        prof = TargetProfile(host="h", base_url="https://h/")
        f = Finding("https://h/redir", 302, 0, "", 0.9, "wordlist")
        result = ScanResult(profile=prof, findings=[f])
        opts = ScanOptions(param_fuzz=True)
        asyncio.run(_param_fold(FakeEngine(), prof, result, opts, NullObserver()))
        self.assertIn("redirect-lead", f.tags)         # canary in Location → open-redirect
        self.assertIn("open-redirect: url", f.note)
        self.assertIn("header reflection: q", f.note)  # canary echoed in x-echo header

    def test_reflection_contexts_classify_sink(self):
        from origami.modules import paramfuzz as P
        (qs, tmap, ctl), = P.build_batches(["q", "name", "data"], batch_size=5, run="oztest")
        tok = {p: t for t, p in tmap.items()}
        html = (b"<html>search: " + tok["q"].encode() + b"</html>"
                b'<input value="' + tok["name"].encode() + b'">'
                b'<script>var x="' + tok["data"].encode() + b'";</script>')
        ctx = P.reflection_contexts(html, tmap, "text/html")
        self.assertEqual(ctx["q"], "html")
        self.assertEqual(ctx["name"], "attr")
        self.assertEqual(ctx["data"], "js")
        jb = b'{"q":"' + tok["q"].encode() + b'"}'
        self.assertEqual(P.reflection_contexts(jb, tmap, "application/json")["q"], "json")

    def test_fold_skips_endpoint_that_echoes_any_query(self):
        import asyncio
        from origami.core.scanner import _param_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class EchoEngine:                       # echoes the WHOLE query → control reflects
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                EchoEngine.total_requests += 1
                from urllib.parse import urlparse
                return make_probe(200, b"you sent: " + urlparse(url).query.encode(),
                                  url=url, ctype="text/html")

        prof = TargetProfile(host="h", base_url="https://h/")
        f = Finding("https://h/x.php", 200, 10, "text/html", 0.9, "wordlist")
        result = ScanResult(profile=prof, findings=[f])
        asyncio.run(_param_fold(EchoEngine(), prof, result, ScanOptions(param_fuzz=True), NullObserver()))
        self.assertNotIn("param", f.tags)       # echoes-any → no false reflections

class TestCachePoison(unittest.TestCase):
    def test_detect_cache_layer(self):
        from origami.modules.cache_poison import detect_cache_layer
        self.assertEqual(detect_cache_layer({"cf-ray": "abc", "server": "cloudflare"}), "cloudflare")
        self.assertEqual(detect_cache_layer({"x-served-by": "cache-fra"}), "fastly")
        self.assertEqual(detect_cache_layer({"x-varnish": "12345"}), "varnish")
        self.assertEqual(detect_cache_layer({"x-amz-cf-id": "z"}), "cloudfront")
        self.assertEqual(detect_cache_layer({"via": "1.1 varnish (Varnish/6.0)"}), "varnish")
        self.assertEqual(detect_cache_layer({"x-cache": "MISS"}), "cache")   # generic
        self.assertEqual(detect_cache_layer({"content-type": "text/html"}), "")

    def test_cache_status(self):
        from origami.modules.cache_poison import cache_status
        self.assertEqual(cache_status({"cf-cache-status": "HIT"}), "HIT")
        self.assertEqual(cache_status({"x-cache": "MISS, MISS"}), "MISS")
        self.assertEqual(cache_status({"x-cache": "HIT, MISS"}), "HIT")   # any layer HIT → cached
        self.assertEqual(cache_status({"cf-cache-status": "DYNAMIC"}), "MISS")
        self.assertEqual(cache_status({}), "")

    def test_is_cacheable(self):
        from origami.modules.cache_poison import is_cacheable
        self.assertFalse(is_cacheable({"cache-control": "no-store, private"}))
        self.assertFalse(is_cacheable({"cache-control": "no-cache"}))
        self.assertFalse(is_cacheable({}))
        self.assertTrue(is_cacheable({"cache-control": "public, max-age=300"}))
        self.assertTrue(is_cacheable({"age": "42"}))
        self.assertTrue(is_cacheable({"cf-cache-status": "HIT"}))
        self.assertTrue(is_cacheable({"expires": "Wed, 21 Oct 2099 07:28:00 GMT"}))

    def test_provably_uncacheable(self):
        from origami.modules.cache_poison import provably_uncacheable
        # explicit no-store / private / no-cache → can't be poisoned
        self.assertTrue(provably_uncacheable({"cache-control": "no-cache, no-store, max-age=0"}))
        self.assertTrue(provably_uncacheable({"cache-control": "private"}))
        # the edge says it did NOT cache it (Cloudflare DYNAMIC / BYPASS)
        self.assertTrue(provably_uncacheable({"cf-cache-status": "DYNAMIC"}))
        self.assertTrue(provably_uncacheable({"x-cache-status": "BYPASS"}))
        # an ambiguous MISS (cacheable, just not stored yet) stays a lead — NOT suppressed
        self.assertFalse(provably_uncacheable({"cf-cache-status": "MISS", "cache-control": "max-age=60"}))
        self.assertFalse(provably_uncacheable({}))

    def test_header_set_intensity_and_custom(self):
        from origami.modules.cache_poison import header_set
        light, auto, full = header_set("light"), header_set("auto"), header_set("full")
        self.assertLess(len(light), len(auto))
        self.assertLess(len(auto), len(full))
        # X-Forwarded-Host (the #1 vector) is present at every level
        for s in (light, auto, full):
            self.assertTrue(any(n == "X-Forwarded-Host" for n, _ in s))
        # custom pairs are appended, deduped by (lower name, value)
        custom = [("X-Custom-Cache", "evil"), ("x-forwarded-host", "{canary}.example.com")]
        merged = header_set("light", custom)
        self.assertIn(("X-Custom-Cache", "evil"), merged)
        self.assertEqual(sum(1 for n, v in merged
                             if n.lower() == "x-forwarded-host" and v == "{canary}.example.com"), 1)

    # --- fold: a fake cache that keys on the query but NOT on the headers ----
    def _cprobe(self, body, url, headers):
        p = make_probe(200, body, url=url, ctype="text/html")
        p.headers = headers
        return p

    def _run_fold(self, mode):
        """mode: 'poison' (reflected+cached), 'lead' (reflected, not cached),
        'keyed' (header ignored)."""
        import asyncio
        from urllib.parse import urlparse, parse_qs
        from origami.core.scanner import _cache_poison_fold, ScanResult, ScanOptions
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver
        outer = self

        class CacheEngine:
            total_requests = 0
            spent = 0
            def __init__(self):
                self.calls = []
                self.store = {}          # cb token -> cached (poisoned) body
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                CacheEngine.total_requests += 1
                CacheEngine.spent += 1
                self.calls.append((url, headers or {}))
                cb = parse_qs(urlparse(url).query).get("cb", [""])[0]
                base_hdrs = {"cache-control": "public, max-age=60"}
                if cb in self.store:                       # cache HIT on a poisoned key
                    return outer._cprobe(self.store[cb], url, {**base_hdrs, "x-cache": "HIT"})
                if mode == "echo":
                    # endpoint reflects its OWN query string heavily, ignores headers —
                    # the classic differ-signal trap (each cb differs the body).
                    body = b"<html>" + (b"q-" + cb.encode() + b" ") * 40 + b"</html>"
                    return outer._cprobe(body, url, base_hdrs)
                xfh = (headers or {}).get("X-Forwarded-Host", "")
                if xfh and "example.com" in xfh:
                    body = b"<html><a href='https://" + xfh.encode() + b"/login'>go</a></html>"
                    if mode == "poison":
                        self.store[cb] = body              # the cache stores our injected body
                        return outer._cprobe(body, url, base_hdrs)
                    if mode == "lead":
                        return outer._cprobe(body, url, base_hdrs)   # reflected but never cached
                # keyed / baseline / confirm-without-header → clean page
                return outer._cprobe(b"<html>clean homepage</html>", url, base_hdrs)

        profile = TargetProfile(host="t.example.com", base_url="https://t.example.com/")
        profile.cache_layer = "cloudflare"
        result = ScanResult(profile=profile)
        result.findings.append(Finding("https://t.example.com/page", 200, 30, "text/html",
                                       0.5, "wordlist"))
        eng = CacheEngine()
        asyncio.run(_cache_poison_fold(eng, profile, result, ScanOptions(cache_poison="auto"),
                                       NullObserver(), simhash(b"<html>clean homepage</html>")))
        return result, eng

    def test_reflected_and_cached_is_poisonable(self):
        result, _ = self._run_fold("poison")
        f = result.findings[0]
        self.assertIn("poisonable", f.tags)
        self.assertIn("cache", f.tags)
        self.assertGreaterEqual(f.confidence, 0.9)
        self.assertIn("cache poisoning", f.note)

    def test_reflected_but_not_cached_is_lead_only(self):
        result, _ = self._run_fold("lead")
        f = result.findings[0]
        self.assertIn("cache", f.tags)
        self.assertNotIn("poisonable", f.tags)
        self.assertIn("lead", f.note)

    def test_keyed_input_not_flagged(self):
        result, _ = self._run_fold("keyed")
        f = result.findings[0]
        self.assertNotIn("poisonable", f.tags)
        self.assertNotIn("cache", f.tags)

    def test_query_reflecting_endpoint_not_flagged_via_differ(self):
        # An endpoint that echoes its own cache-buster must NOT be flagged just
        # because each probe's body differs (it differs by the cb token alone).
        result, _ = self._run_fold("echo")
        f = result.findings[0]
        self.assertNotIn("poisonable", f.tags)
        self.assertNotIn("cache", f.tags)

    def test_safety_every_probe_rides_a_cache_buster(self):
        # The core safety invariant: we NEVER touch the real cache key. Every
        # request carries a unique ?cb= token; the bare URL is never fetched.
        _, eng = self._run_fold("poison")
        self.assertTrue(eng.calls, "fold made no requests")
        for url, _hdrs in eng.calls:
            self.assertIn("cb=", url, f"probe without a cache-buster: {url}")
            self.assertNotEqual(url, "https://t.example.com/page")   # never the real key

class TestSessionAuthWall(unittest.TestCase):
    def _p(self, status, loc="", body=b""):
        return make_probe(status, body or b"x", url="http://h/", ctype="text/html", location=loc)

    def test_has_auth(self):
        from origami.modules import session as S
        self.assertTrue(S.has_auth({"Cookie": "s=1"}))
        self.assertTrue(S.has_auth({"authorization": "Bearer x"}))
        self.assertTrue(S.has_auth({"X-API-Key": "k"}))
        self.assertFalse(S.has_auth({"X-Custom": "1"}))
        self.assertFalse(S.has_auth({}))

    def test_auth_wall_detected(self):
        from origami.modules import session as S
        self.assertIsNotNone(S.auth_wall_reason(self._p(401)))
        self.assertIsNotNone(S.auth_wall_reason(self._p(302, "https://h/account/login?next=/")))
        self.assertIsNotNone(S.auth_wall_reason(self._p(302, "https://h/users/sign_in")))
        self.assertIsNotNone(S.auth_wall_reason(
            self._p(200, body=b'<form><input name=pw type="password"></form>')))

    def test_no_false_positive_on_authenticated_root(self):
        from origami.modules import session as S
        self.assertIsNone(S.auth_wall_reason(self._p(200, body=b"<html>welcome to your dashboard</html>")))
        self.assertIsNone(S.auth_wall_reason(self._p(302, "https://h/dashboard")))   # redirect, not to login
        self.assertIsNone(S.auth_wall_reason(self._p(200, body=b"<html>home</html>")))

    def _run_scan(self, engine):
        import asyncio, os, tempfile
        from origami.core.scanner import scan, ScanOptions
        from origami.output.ui import NullObserver
        wl = tempfile.mktemp(suffix=".txt")
        with open(wl, "w") as fh:
            fh.write("admin\nindex\n")          # tiny list → fast walk over the fake engine
        logs = []
        class L(NullObserver):
            def log(self, m, *a, **k): logs.append(m)
        async def main():
            await scan(engine, "https://h/", observer=L(), memory=None,
                       opts=ScanOptions(max_depth=0, wordlist_paths=[str(wl)], js=False,
                                        apidocs=False, backups=False, max_folds=0))
        try:
            asyncio.run(main())
        finally:
            os.unlink(wl)
        return logs

    def _engine(self, headers, root_seq):
        # root_seq: list of (status, location, body) returned for successive root fetches
        from origami.core.httpclient import Probe, EngineConfig
        class FakeEngine:
            def __init__(s):
                s.total_requests = 0; s.prior_requests = 0; s.pushback_events = 0
                s.on_request = None; s.cfg = EngineConfig(headers=headers); s._i = 0
            @property
            def spent(s): return s.prior_requests + s.total_requests
            async def fetch(s, url, method="GET", keep_body=False, headers=None):
                s.total_requests += 1
                root = url.rstrip("/").endswith("h") or url.endswith("/")
                if root:
                    st, loc, body = root_seq[min(s._i, len(root_seq) - 1)]; s._i += 1
                    return Probe(url, "GET", st, len(body), 0, 0, "text/html", loc, 0, 1.0,
                                 body_head=body, body=body)
                return Probe(url, "GET", 404, 0, 0, 0, "text/html", "", 0, 1.0)
            async def gather(s, urls, method="GET"): return [await s.fetch(u) for u in urls]
        return FakeEngine()

    def test_scan_warns_on_midscan_session_expiry(self):
        # started authed (root 200), then root flips to a login redirect → warn
        eng = self._engine({"Cookie": "s=1"},
                           [(200, "", b"<html>dashboard</html>")] * 3 +
                           [(302, "https://h/account/login", b"")])
        logs = self._run_scan(eng)
        self.assertTrue(any("EXPIRED during the scan" in m for m in logs))

    def test_scan_no_warning_when_session_stays_valid(self):
        eng = self._engine({"Cookie": "s=1"}, [(200, "", b"<html>dashboard</html>")])
        logs = self._run_scan(eng)
        self.assertFalse(any("EXPIRED" in m for m in logs))

    def test_scan_no_recheck_without_auth(self):
        # no auth headers → never re-checks / warns, even if root would look walled
        eng = self._engine({}, [(200, "", b"<html>home</html>"),
                                (302, "https://h/login", b"")])
        logs = self._run_scan(eng)
        self.assertFalse(any("EXPIRED" in m for m in logs))


if __name__ == "__main__":
    unittest.main()
