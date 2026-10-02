"""In-memory header capture: no target traffic or cookie/session values exported."""

import asyncio
import io
import unittest

import httpx

from origami.core.cookies import CookieRecorder, attach_cookie_recorder, cookie_metadata
from origami.core.evidence import TargetProfile
from origami.core.httpclient import Engine, EngineConfig
from origami.core.response_classifier import classify
from origami.core.scanner.types import ScanResult
from origami.output import html_report, json_report, ui


class TestCookieObservations(unittest.TestCase):
    def test_multiple_headers_expires_commas_and_empty_deletion_values(self):
        cookies, unparsed = cookie_metadata([
            "SESSION=secret; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; Secure; SameSite=Lax",
            "preference=; Max-Age=0; SameSite=Strict", "Session=second; SameSite=None"])
        self.assertEqual([c["name"] for c in cookies], ["SESSION", "preference", "Session"])
        self.assertTrue(cookies[0]["secure"])
        self.assertTrue(cookies[0]["httponly"])
        self.assertEqual(cookies[0]["samesite"], "lax")
        self.assertEqual(unparsed, 0)
        self.assertNotIn("secret", repr(cookies))

    def test_unparsed_headers_are_counted_and_not_echoed(self):
        cookies, unparsed = cookie_metadata(["bad name=secret", "secret", "a=x, b=secret",
                                            "ok=secret; SameSite=unexpected"])
        self.assertEqual(unparsed, 3)
        self.assertEqual(cookies, [{"name": "ok", "secure": False, "httponly": False, "samesite": None}])

    def test_rotation_dedup_per_url_and_bounded_notices_preserve_records(self):
        notices = []
        limits = []
        recorder = CookieRecorder(notify=notices.append, notice_limit=2,
                                  notify_limit=lambda: limits.append(True))
        recorder.record("https://example.test/a", 200, ["session=secret1"])
        recorder.record("https://example.test/a", 200, ["session=secret2"])
        recorder.record("https://example.test/b", 200, ["session=secret3"])
        recorder.record("https://example.test/b", 200, ["session=secret4; HttpOnly"])
        recorder.record("https://example.test/c", 200, ["different=secret5"])
        self.assertEqual(len(notices), 2)
        self.assertEqual(len(recorder.records), 4)
        self.assertEqual(recorder.records[0]["response_count"], 2)
        self.assertEqual(recorder.suppressed_notices, 1)
        self.assertEqual(limits, [True])
        self.assertNotIn("secret", repr(recorder.records))

    def test_hooks_capture_redirect_and_non_finding_with_no_extra_requests(self):
        async def exercise():
            engine = Engine(EngineConfig(follow_redirects=True, jitter=(0, 0)))
            scan = ScanResult(TargetProfile("example.test", "https://example.test/"))
            output = io.StringIO()
            attach_cookie_recorder(engine, scan, ui.NullObserver(stream=output))
            calls = []

            def respond(request):
                calls.append(str(request.url))
                if request.url.path == "/start":
                    return httpx.Response(302, headers=[("Location", "/missing"),
                                                       ("Set-Cookie", "SESSION=private; HttpOnly")])
                return httpx.Response(404, headers=[("Set-Cookie", "OTHER=private2"),
                                                   ("Set-Cookie", "THIRD=private3; Secure")], content=b"missing")

            # Use the actual engine hook configuration, replacing only transport.
            engine._client = engine._new_client(None)
            await engine._client.aclose()
            engine._client = httpx.AsyncClient(transport=httpx.MockTransport(respond),
                                              follow_redirects=True,
                                              event_hooks={"response": [engine._observe_cookie_headers]})
            engine._clients = [engine._client]
            try:
                probe = await engine.fetch("https://example.test/start")
            finally:
                await engine._client.aclose()
            self.assertEqual(probe.status, 404)
            self.assertIsNone(classify(scan.profile, probe, "wordlist"))
            self.assertEqual(calls, ["https://example.test/start", "https://example.test/missing"])
            self.assertEqual([row["status"] for row in scan.cookie_observations], [302, 404])
            self.assertEqual([c["name"] for c in scan.cookie_observations[1]["cookies"]], ["OTHER", "THIRD"])
            self.assertIn("Set-Cookie: SESSION", output.getvalue())
            self.assertIn("HttpOnly", output.getvalue())
            self.assertIn("Set-Cookie: OTHER, THIRD", output.getvalue())
            self.assertNotIn("private", output.getvalue())
            exported = json_report.to_dict(scan)
            self.assertEqual(exported["cookie_observations"], scan.cookie_observations)
            exported["cookie_observations"][0]["cookies"][0]["name"] = "modified"
            self.assertEqual(scan.cookie_observations[0]["cookies"][0]["name"], "SESSION")
            rendered = html_report.render(scan)
            self.assertIn("Observed Set-Cookie headers", rendered)
            self.assertNotIn("private", rendered)

        asyncio.run(exercise())

    def test_headers_remain_recorded_when_body_stream_fails(self):
        class BrokenBody(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"partial"
                raise httpx.ReadError("broken body")

        async def exercise():
            engine = Engine(EngineConfig(max_retries=0, jitter=(0, 0)))
            client = httpx.AsyncClient(transport=httpx.MockTransport(
                lambda request: httpx.Response(200, headers={"Set-Cookie": "SID=secret"},
                                               stream=BrokenBody())),
                event_hooks={"response": [engine._observe_cookie_headers]})
            engine._client = client
            engine._clients = [client]
            try:
                probe = await engine.fetch("https://example.test/broken")
            finally:
                await client.aclose()
            self.assertFalse(probe.ok)
            self.assertEqual(len(engine.cookie_recorder.records), 1)
            self.assertEqual(engine.cookie_recorder.records[0]["cookies"][0]["name"], "SID")
        asyncio.run(exercise())

    def test_real_client_configuration_has_header_hook_and_legacy_capture(self):
        async def exercise():
            engine = Engine()
            client = engine._new_client(None)
            try:
                self.assertIn(engine._observe_cookie_headers, client.event_hooks["response"])
            finally:
                await client.aclose()
        asyncio.run(exercise())

    def test_old_result_does_not_claim_complete_cookie_retention(self):
        scan = ScanResult(TargetProfile("example.test", "https://example.test/"))
        self.assertEqual(json_report.to_dict(scan)["cookie_observation_retention"], "unavailable")
