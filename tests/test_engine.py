"""Origami unit tests — request engine — backoff, legacy TLS, resume, throttle, live progress.

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



class TestEngineBackoff(unittest.TestCase):
    def _engine(self, c=20):
        from origami.core.httpclient import Engine, EngineConfig
        return Engine(EngineConfig(concurrency=c))

    def test_pushback_halves_limit(self):
        e = self._engine(20)
        self.assertEqual(e.concurrency_limit, 20)
        e._note_pushback()
        self.assertEqual(e._limit, 10.0)
        e._note_pushback()
        self.assertEqual(e._limit, 5.0)

    def test_limit_floor_is_one(self):
        e = self._engine(20)
        for _ in range(50):
            e._note_pushback()
        self.assertEqual(e._limit, 1.0)

    def test_relax_ramps_back_to_ceiling(self):
        e = self._engine(8)
        e._note_pushback()           # 8 -> 4
        self.assertEqual(e._limit, 4.0)
        for _ in range(100):
            e._relax()
        self.assertEqual(e.concurrency_limit, 8)

    def test_pushback_grows_delay_floor(self):
        e = self._engine()
        self.assertEqual(e._delay_floor, 0.0)
        e._note_pushback()
        self.assertGreater(e._delay_floor, 0.0)
        self.assertLessEqual(e._delay_floor, 5.0)

    def test_proxy_rotation_builds_pool(self):
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig
        async def run():
            e = Engine(EngineConfig(proxies=["http://p1:8080", "http://p2:8080", "http://p3:8080"]))
            async with e:
                picks = {id(e._pick_client()) for _ in range(80)}
                return len(e._clients), len(picks)
            return 0, 0
        n_clients, n_picked = asyncio.run(run())
        self.assertEqual(n_clients, 3)              # one client per proxy
        self.assertEqual(n_picked, 3)              # all rotated over many requests

    def test_no_proxy_single_client(self):
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig
        async def run():
            e = Engine(EngineConfig())
            async with e:
                return len(e._clients), e._pick_client() is e._client
        n, stable = asyncio.run(run())
        self.assertEqual(n, 1)
        self.assertTrue(stable)                    # single client, deterministic pick

    def test_http2_config_builds_client(self):
        # the engine must build with http2 off always, and on only when h2 is present
        import asyncio, importlib.util
        from origami.core.httpclient import Engine, EngineConfig
        async def build(flag):
            async with Engine(EngineConfig(http2=flag)):
                return True
        self.assertTrue(asyncio.run(build(False)))
        if importlib.util.find_spec("h2"):
            self.assertTrue(asyncio.run(build(True)))

    def test_spent_counts_prior_plus_current(self):
        # --max-requests must bound CUMULATIVE spend so --resume can't grant a
        # fresh budget each time
        e = self._engine()
        e.prior_requests = 700
        e.total_requests = 250
        self.assertEqual(e.spent, 950)
        e.prior_requests = 0
        self.assertEqual(e.spent, e.total_requests)   # fresh scan: spent == this-run total

    def test_parse_retry_after(self):
        import time
        from origami.core.httpclient import _parse_retry_after as P
        now = time.time()
        self.assertEqual(P("120", now), 120.0)                       # delta-seconds
        self.assertIsNone(P(None, now))
        self.assertIsNone(P("", now))
        self.assertIsNone(P("soon", now))                            # unparseable
        self.assertEqual(P("Wed, 21 Oct 2015 07:28:00 GMT", now), 0.0)  # past date → 0
        future = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now + 90))
        self.assertAlmostEqual(P(future, now), 90, delta=2)          # HTTP-date

    def test_rotate_ua_picks_pool_and_keeps_headers(self):
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig, _UA_POOL

        class _Hdrs(dict):
            def get_list(self, k): return []
        class _Resp:
            status_code = 200
            headers = _Hdrs({"content-type": "text/html"})
            async def aiter_bytes(self):
                if False:
                    yield b""
        class _Stream:
            async def __aenter__(self): return _Resp()
            async def __aexit__(self, *a): return False

        async def run():
            e = Engine(EngineConfig(rotate_ua=True))
            async with e:
                seen, captured = set(), {}
                def fake_stream(method, url, **kw):
                    h = kw.get("headers", {})
                    seen.add(h.get("User-Agent"))
                    captured.update(h)
                    return _Stream()
                e._client.stream = fake_stream
                for _ in range(60):
                    await e._stream_probe("http://t/x", "GET", False, {"headers": {"X-Custom": "keep"}})
                return seen, captured
        seen, captured = asyncio.run(run())
        self.assertGreater(len(seen), 1)                 # actually rotates
        self.assertTrue(seen <= set(_UA_POOL))           # only real pool UAs
        self.assertEqual(captured.get("X-Custom"), "keep")  # caller headers preserved

    def test_no_rotation_when_disabled(self):
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig
        class _Hdrs(dict):
            def get_list(self, k): return []
        class _Resp:
            status_code = 200; headers = _Hdrs({"content-type": "text/html"})
            async def aiter_bytes(self):
                if False:
                    yield b""
        class _Stream:
            async def __aenter__(self): return _Resp()
            async def __aexit__(self, *a): return False
        async def run():
            e = Engine(EngineConfig(rotate_ua=False))
            async with e:
                sent = []
                def fake_stream(method, url, **kw):
                    sent.append(kw.get("headers"))
                    return _Stream()
                e._client.stream = fake_stream
                await e._stream_probe("http://t/x", "GET", False, {})
                return sent
        sent = asyncio.run(run())
        self.assertEqual(sent, [None])                   # no per-request UA header injected

    def test_retry_after_sets_and_caps_floor(self):
        from origami.core.httpclient import _RETRY_AFTER_CAP
        e = self._engine(40)
        e._note_pushback(12.0)                                       # explicit Retry-After
        self.assertEqual(e._delay_floor, 12.0)                       # honored exactly
        self.assertEqual(e._limit, 20.0)                             # still halves concurrency
        e2 = self._engine(40)
        e2._note_pushback(86400.0)                                   # hostile huge value
        self.assertEqual(e2._delay_floor, _RETRY_AFTER_CAP)          # capped, never stalls forever

    def test_transport_errors_do_not_collapse_concurrency(self):
        # regression: a few dead/slow URLs (timeout/reset/DNS) must NOT be treated
        # as WAF throttle — they must not halve the limit or inflate pushback_events
        import asyncio, httpx
        from origami.core.httpclient import Engine, EngineConfig
        e = Engine(EngineConfig(concurrency=40, max_retries=2))
        async def run():
            async with e:
                async def boom(url, method, keep_body, kw):
                    raise httpx.ReadTimeout("simulated slow host")
                e._stream_probe = boom
                for i in range(3):
                    pr = await e.fetch(f"http://dead/{i}")
                    self.assertTrue(pr.error)             # returns an error probe
        asyncio.run(run())
        self.assertEqual(e._limit, 40.0)                 # concurrency intact
        self.assertEqual(e.pushback_events, 0)           # not counted as throttle
        self.assertEqual(e._delay_floor, 0.0)

    def test_raw_ssl_error_does_not_crash_fetch(self):
        # a raw ssl.SSLError (subclass of OSError) escaping httpx's wrapping on a
        # flaky TLS read must become an error probe, not crash the whole scan
        import asyncio, ssl
        from origami.core.httpclient import Engine, EngineConfig
        e = Engine(EngineConfig(concurrency=10, max_retries=1))
        async def run():
            async with e:
                async def boom(url, method, keep_body, kw):
                    raise ssl.SSLError("record layer failure (_ssl.c:2580)")
                e._stream_probe = boom
                return await e.fetch("https://t/x")
        pr = asyncio.run(run())
        self.assertFalse(pr.ok)                 # error probe, not an exception
        self.assertIn("SSLError", pr.error)
        self.assertEqual(e.pushback_events, 0)  # transport fault ≠ throttle
        self.assertEqual(e._limit, 10.0)        # concurrency not collapsed

    def test_real_429_still_backs_off(self):
        # the genuine throttle signal must still trigger AIMD backoff
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig, Probe
        e = Engine(EngineConfig(concurrency=40, max_retries=2))
        async def run():
            async with e:
                async def four29(url, method, keep_body, kw):
                    return Probe(url, method, 429, 0, 0, 0, "", "", 0, 1.0)
                e._stream_probe = four29
                await e.fetch("http://t/x")
        asyncio.run(run())
        self.assertLess(e._limit, 40.0)
        self.assertGreater(e.pushback_events, 0)

class TestLegacyTLS(unittest.TestCase):
    """Weak-DH / legacy-cipher servers: detect the handshake error, drop SECLEVEL."""

    def test_looks_weak_tls_matches_dh_and_handshake(self):
        from origami.core.httpclient import _looks_weak_tls
        self.assertTrue(_looks_weak_tls("ConnectError: [SSL: DH_KEY_TOO_SMALL] dh key too small"))
        self.assertTrue(_looks_weak_tls("SSLError: [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]"))
        self.assertTrue(_looks_weak_tls("SSLError: unsafe legacy renegotiation disabled"))
        # NOT a security-level issue → don't lower TLS for these
        self.assertFalse(_looks_weak_tls("ConnectTimeout: timed out"))
        self.assertFalse(_looks_weak_tls("ConnectError: [Errno 111] Connection refused"))
        self.assertFalse(_looks_weak_tls("SSLError: CERTIFICATE_VERIFY_FAILED"))  # cert, handled by -k

    def test_legacy_ssl_context_lowers_security(self):
        import ssl
        from origami.core.httpclient import _legacy_ssl_context
        ctx = _legacy_ssl_context(verify=False)
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)      # verify off → no cert check
        self.assertFalse(ctx.check_hostname)
        ctx2 = _legacy_ssl_context(verify=True)
        self.assertEqual(ctx2.verify_mode, ssl.CERT_REQUIRED)  # verify on → cert still checked

class TestResume(unittest.TestCase):
    def _state(self, path):
        from origami.core import resume as R
        from origami.core.evidence import Evidence
        from origami.core.response_classifier import Finding
        p = TargetProfile(host="h.example", base_url="https://h.example/app/")
        p.tech_scores = {"iis": 70.0}
        p.enabled_extensions = {".aspx", ".asmx"}
        p.parameters = {"id", "q"}
        p.wildcard = True
        p.add_evidence(Evidence(source="header", tech="iis", detail="Server: IIS", weight=70))
        cb = ContextBaseline(prefix="/app/", ext_class=".aspx", status=404)
        cb.simhashes = [123, 456]
        cb.soft_signatures = [(200, 999)]
        p.baseline["/app/|.aspx"] = cb
        findings = [Finding("https://h.example/app/login.aspx", 200, 10, "text/html",
                            0.9, "wordlist", note="x", tags=["auth"], simhash=42,
                            words=7, lines=3)]
        R.save(path, profile=p, findings=findings, requests_made=17, folds={"shortscan"},
               words=["a", "b"], exts={".aspx"}, priority_paths=["/p"],
               root_seeds=[("/x", "js")], base_prefix="/app/",
               queue=[("/app/sub/", 1)], scanned={"/app/"})

    def test_roundtrip(self):
        import tempfile
        from pathlib import Path
        from origami.core import resume as R
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            self._state(path)
            st = R.load(path)
            self.assertEqual(st["profile"].host, "h.example")
            self.assertEqual(st["profile"].tech_scores["iis"], 70.0)
            self.assertEqual(st["profile"].enabled_extensions, {".aspx", ".asmx"})
            self.assertTrue(st["profile"].wildcard)
            cb = st["profile"].baseline["/app/|.aspx"]
            self.assertEqual(cb.simhashes, [123, 456])
            self.assertEqual(cb.soft_signatures, [(200, 999)])
            self.assertEqual(len(st["findings"]), 1)
            self.assertEqual(st["findings"][0].url, "https://h.example/app/login.aspx")
            self.assertEqual(st["findings"][0].tags, ["auth"])
            self.assertEqual((st["findings"][0].words, st["findings"][0].lines), (7, 3))
            self.assertEqual(st["requests_made"], 17)
            self.assertEqual(st["queue"], [("/app/sub/", 1)])
            self.assertEqual(st["scanned"], ["/app/"])
            self.assertEqual(st["exts"], {".aspx"})
            self.assertEqual(st["root_seeds"], [("/x", "js")])

    def test_missing_returns_none(self):
        from pathlib import Path
        from origami.core import resume as R
        self.assertIsNone(R.load(Path("/nonexistent/nope.json")))

    def test_start_offset_roundtrip(self):
        import tempfile
        from pathlib import Path
        from origami.core import resume as R
        from origami.core.evidence import TargetProfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            R.save(path, profile=TargetProfile(host="h", base_url="http://h/"),
                   findings=[], requests_made=0, folds=set(), words=[], exts=set(),
                   priority_paths=[], root_seeds=[], base_prefix="/",
                   queue=[("/a/", 1)], scanned=set(), start_offset=137,
                   edges=[("/app.js", "/api/x")])
            st = R.load(path)
            self.assertEqual(st["start_offset"], 137)
            self.assertEqual(st["edges"], [("/app.js", "/api/x")])   # graph survives resume

    def test_bad_version_rejected(self):
        import json
        import tempfile
        from pathlib import Path
        from origami.core import resume as R
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            path.write_text(json.dumps({"version": 99}))
            self.assertIsNone(R.load(path))

class TestThrottleAwareFolds(unittest.TestCase):
    def _eng(self, pushback):
        return type("E", (), {"pushback_events": pushback})()

    def test_throttled_signal(self):
        from origami.core.scanner import _throttled, ScanOptions
        from origami.core.evidence import TargetProfile
        p = TargetProfile(host="h", base_url="http://h/")
        # economy forced on → always conserve
        self.assertTrue(_throttled(self._eng(0), p, ScanOptions(economy="on")))
        # sustained 429/503 → conserve regardless of economy
        self.assertTrue(_throttled(self._eng(5), p, ScanOptions(economy="off")))
        # economy auto + WAF detected → conserve
        p.waf = "cloudflare"
        self.assertTrue(_throttled(self._eng(0), p, ScanOptions(economy="auto")))
        # clean target, no WAF, no pushback → run everything
        clean = TargetProfile(host="h", base_url="http://h/")
        self.assertFalse(_throttled(self._eng(0), clean, ScanOptions(economy="off")))
        self.assertFalse(_throttled(self._eng(0), clean, ScanOptions(economy="auto")))

class TestLiveProgress(unittest.TestCase):
    def _ui(self):
        try:
            from origami.output.ui import RichUI
        except Exception:
            self.skipTest("rich not available")
        return RichUI("http://x")

    def test_setup_phase_is_indeterminate_then_fills(self):
        ui = self._ui()
        ui.phase("fingerprint")
        self.assertIsNone(ui._progress.tasks[0].total)   # pulse, not a stuck 0/1
        ui.phase("js-harvest")
        self.assertIsNone(ui._progress.tasks[0].total)
        ui.progress(3, 10)                                # fold reports → fills
        task = ui._progress.tasks[0]
        self.assertEqual(task.completed, 3)
        self.assertEqual(task.total, 10)
        ui.progress(40, 40)
        self.assertEqual(ui._progress.tasks[0].completed, 40)

    def test_substep_sets_label_and_step_bar(self):
        ui = self._ui()
        ui.phase("recon")
        ui.substep("apidocs", 4, 7)
        self.assertEqual(ui.substep_name, "apidocs")        # status-bar sub-label
        task = ui._progress.tasks[0]
        self.assertEqual(task.completed, 4)                  # bar = step k/total
        self.assertEqual(task.total, 7)
        ui.phase("scan")
        self.assertEqual(ui.substep_name, "")                # cleared on new phase

    def test_count_column_blank_when_indeterminate(self):
        from origami.output.ui import _CountColumn
        ui = self._ui()
        ui.phase("calibrate")
        col = _CountColumn().render(ui._progress.tasks[0])
        self.assertEqual(str(col), "")                    # no "0/1"
        ui.start_prefix("/admin/", 50)
        self.assertIn("/", str(_CountColumn().render(ui._progress.tasks[0])))

    def test_highlights_surface_high_value(self):
        from origami.core.response_classifier import Finding
        ui = self._ui()
        ui.findings = [Finding("u1", 200, 1, "", 0.9, "js", tags=["disclosure", "config"]),
                       Finding("u2", 200, 1, "", 0.9, "bypass403", tags=["admin"]),
                       Finding("u3", 200, 1, "", 0.7, "methods", tags=["config"])]
        h = ui._highlights()
        self.assertIn("disclosure", h)
        self.assertIn("403-bypass", h)
        self.assertIn("dangerous-methods", h)
        self.assertIn("config", h)
        self.assertEqual(self._ui()._highlights(), "")   # empty when no findings

    def test_dynamic_dashboard_rerenders(self):
        from origami.output.ui import _LiveDashboard
        ui = self._ui()
        dash = _LiveDashboard(ui)
        self.assertIsNotNone(dash.__rich__())     # rebuilds the renderable each call
        self.assertIsNotNone(dash.__rich__())


if __name__ == "__main__":
    unittest.main()
