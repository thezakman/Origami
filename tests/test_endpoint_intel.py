"""Structured client-code route intelligence with no target traffic."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from origami.core import resume
from origami.core.evidence import TargetProfile
from origami.core.scanner import ScanResult
from origami.modules.discovery import js_parser
from origami.output import artifacts, html_report, json_report


class TestEndpointIntel(unittest.TestCase):
    def hints(self, body):
        return js_parser.extract_endpoint_hints(body, "https://example.test/app/")

    def test_literal_clients_preserve_methods_and_query_names(self):
        body = (b'fetch("/api/search?q=x&page=1");'
                b'axios.post("/api/users", payload);'
                b'this.http.patch(`/api/users/${id}/status`, body);'
                b'xhr.open("DELETE", "/api/users/42", true);')
        hints = self.hints(body)
        self.assertIn({"method": "GET", "route": "/api/search?q=x&page=1",
                       "template": False, "path_params": [], "query_params": ["page", "q"],
                       "client": "fetch"}, hints)
        self.assertTrue(any(h["method"] == "POST" and h["route"] == "/api/users"
                            and h["client"] == "axios" for h in hints))
        dynamic = next(h for h in hints if h["method"] == "PATCH")
        self.assertEqual(dynamic["route"], "/api/users/{id}/status")
        self.assertTrue(dynamic["template"])
        self.assertEqual(dynamic["path_params"], ["id"])
        self.assertTrue(any(h["method"] == "DELETE" and h["route"] == "/api/users/42"
                            and h["client"] == "xhr" for h in hints))

    def test_static_constants_and_concatenation_are_resolved(self):
        body = (b'const api = "/api/v3"; const users = api + "/users";'
                b'fetch(users + "/active");')
        hints = self.hints(body)
        self.assertTrue(any(h["route"] == "/api/v3/users/active" and h["method"] == "GET"
                            and h["client"] == "fetch" for h in hints))
        self.assertIn("/api/v3/users/active",
                      js_parser.extract_paths(body, "https://example.test/app/"))

    def test_axios_instance_baseurl_is_correlated_with_calls(self):
        body = (b'const admin = axios.create({ baseURL: "/internal/api/v2" });'
                b'admin.get("/users"); admin.post("roles", data);')
        hints = self.hints(body)
        routes = {(h["method"], h["route"], h["client"]) for h in hints}
        self.assertIn(("GET", "/internal/api/v2/users", "axios-instance:admin"), routes)
        self.assertIn(("POST", "/internal/api/v2/roles", "axios-instance:admin"), routes)
        paths = js_parser.extract_paths(body, "https://example.test/app/")
        self.assertIn("/internal/api/v2/users", paths)
        self.assertIn("/internal/api/v2/roles", paths)

    def test_dynamic_routes_are_intel_but_not_probeable_candidates(self):
        body = b'fetch(`/accounts/${accountId}/invoices/${invoice.id}?format=${fmt}`);'
        hints = self.hints(body)
        self.assertEqual(hints[0]["route"], "/accounts/{accountId}/invoices/{invoice.id}?format={fmt}")
        self.assertEqual(hints[0]["path_params"], ["accountId", "invoice.id"])
        self.assertEqual(hints[0]["query_params"], ["format"])
        self.assertNotIn("/accounts/invoices", js_parser.extract_paths(body, "https://example.test/app/"))

    def test_same_site_absolute_kept_and_cross_site_dropped(self):
        body = (b'fetch("https://api.example.test/v1/profile");'
                b'fetch("https://evil.test/collect");')
        hints = self.hints(body)
        self.assertTrue(any(h["route"] == "https://api.example.test/v1/profile" for h in hints))
        self.assertFalse(any("evil.test" in h["route"] for h in hints))

    def test_noise_and_unsafe_schemes_are_rejected(self):
        body = (b'object.get("label"); fetch("javascript:alert(1)");'
                b'fetch("data:text/plain,x"); fetch(dynamicCall());')
        self.assertEqual(self.hints(body), [])

    def test_results_are_deterministic_deduplicated_and_json_safe(self):
        body = b'fetch("/api/items"); fetch("/api/items");'
        first = self.hints(body)
        second = self.hints(body)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        json.dumps(first)

    def test_fetch_method_does_not_bleed_from_the_next_call(self):
        hints = self.hints(b'fetch("/api/read"); fetch("/api/write", {method: "POST"});')
        methods = {h["route"]: h["method"] for h in hints}
        self.assertEqual(methods, {"/api/read": "GET", "/api/write": "POST"})

    def test_harvest_retains_source_provenance_without_extra_requests(self):
        class Engine:
            async def fetch(self, *_args, **_kwargs):
                raise AssertionError("max_scripts=0 must not fetch")

        collected = []
        asyncio.run(js_parser.harvest(
            Engine(), "https://example.test/app/",
            b'fetch("/api/me"); axios.delete(`/api/session/${id}`);',
            max_scripts=0, endpoint_hints=collected))
        self.assertEqual({h["source"] for h in collected}, {"https://example.test/app/"})
        self.assertTrue(any(h["method"] == "DELETE" and h["template"] for h in collected))

    def test_reports_and_bundle_export_passive_routes(self):
        result = ScanResult(TargetProfile(host="example.test",
                                          base_url="https://example.test/app/"))
        result.endpoint_hints = [{
            "source": "https://example.test/app/main.js", "method": "POST",
            "route": "/api/users/{id}/reset", "template": True,
            "path_params": ["id"], "query_params": [], "client": "axios",
        }]
        exported = json_report.to_dict(result)
        self.assertEqual(exported["endpoint_hint_count"], 1)
        self.assertEqual(exported["endpoint_hints"], result.endpoint_hints)
        rendered = html_report.render(result)
        self.assertIn("Passive client routes (1)", rendered)
        self.assertIn("/api/users/{id}/reset", rendered)
        with tempfile.TemporaryDirectory() as folder:
            summary = artifacts.write_artifacts(result, folder)
            routes = json.loads((Path(folder) / "client_routes.json").read_text())
            self.assertEqual(routes, result.endpoint_hints)
            self.assertEqual(summary["client_routes"], 1)

    def test_checkpoint_retains_routes_and_static_harvest(self):
        profile = TargetProfile(host="example.test", base_url="https://example.test/app/")
        hints = [{"source": profile.base_url, "method": "GET", "route": "/api/me",
                  "template": False, "path_params": [], "query_params": [],
                  "client": "fetch"}]
        with tempfile.TemporaryDirectory() as folder:
            checkpoint = Path(folder) / "resume.json"
            resume.save(checkpoint, profile=profile, findings=[], requests_made=3, folds=set(),
                        words=[], exts=set(), priority_paths=[], root_seeds=[], base_prefix="/app/",
                        queue=[], scanned=set(), harvested_paths={"https://example.test/api/me"},
                        endpoint_hints=hints)
            state = resume.load(checkpoint)
        self.assertEqual(state["endpoint_hints"], hints)
        self.assertEqual(state["harvested_paths"], ["https://example.test/api/me"])
