"""Synthetic response grouping with full observation retention and difference controls."""

import asyncio
import contextlib
import io
import unittest
from dataclasses import asdict, replace
from unittest.mock import patch

import httpx

from origami.core.evidence import Evidence, TargetProfile
from origami.core.httpclient import Engine, EngineConfig
from origami.core.normalize import simhash
from origami.core.response_classifier import Finding, classify
from origami.core.response_signature import body_digests
from origami.core.resume import _finding_from_dict, _finding_to_dict
from origami.core.scanner._common import _dedupe_and_collapse, _report
from origami.core.scanner.types import ScanOptions, ScanResult
from origami.output import html_report, json_report, ui
from origami.output.correlations import fingerprint_correlations, response_correlations
from origami.output.response_groups import ResponsePreview, terminal_findings, terminal_rows


def observation(path, body=b"<html><form action='/login'>Login</form></html>",
                status=200, location="", **kwargs):
    url = "https://example.test" + path
    digest, redirect_digest = body_digests(body, url, location)
    return Finding(url, status, len(body), "text/html", .95, "wordlist",
                   simhash=simhash(body), body_digest=digest, redirect_digest=redirect_digest,
                   location=location, **kwargs)


class TestResponsePresentation(unittest.TestCase):
    def test_log_families_have_one_row_each_without_losing_urls(self):
        redirect = b'<h1>Moved</h1><a href="/sistema/service/">here</a>'
        login = b"<html><form action='/login'>Login</form></html>"
        target = observation("/sistema/index.php", login)
        target.origin = "target"
        rows = [target, observation("/sistema/", login),
                observation("/sistema/index.php?redirect=", login),
                observation("/sistema/service?Wsdl", redirect, 301, "/sistema/service/"),
                observation("/sistema/service?wsdl", redirect, 301, "/sistema/service/")]
        rows += [observation(f"/sistema/static/..;/.{ext}", b"<html>Static response</html>")
                 for ext in ("php", "php3", "php5", "phtml")]
        before = [asdict(row) for row in rows]
        visible, summary = terminal_rows(rows)
        self.assertEqual(len(visible), 3)
        self.assertIn("6 repeated response observations", summary)
        self.assertEqual([asdict(row) for row in rows], before)

    def test_same_size_and_simhash_but_different_html_attributes_stay_visible(self):
        a = observation("/a", b"<html><form action='/login'>Login</form></html>")
        b = observation("/b", b"<html><form action='/admin'>Login</form></html>")
        self.assertEqual(a.length, b.length)
        self.assertEqual(a.simhash, b.simhash)
        visible, _ = terminal_rows([a, b])
        self.assertEqual(visible, [a, b])

    def test_meaningful_changes_are_never_muted(self):
        base = observation("/a")
        controls = [
            observation("/b", b"<html>Other page</html>"),
            replace(base, url="https://example.test/b", status=201),
            replace(base, url="https://example.test/b", content_type="application/json"),
            replace(base, url="https://example.test/b", header_digest="changed-auth-header"),
            replace(base, url="https://example.test/b", tags=["secret"]),
            replace(base, url="https://example.test/b", tags=["debug"]),
            replace(base, url="https://example.test/b", origin="apidocs"),
            replace(base, url="https://example.test/b", note="different evidence"),
            replace(base, url="https://example.test/b", repro="explicit reproduction"),
            replace(base, url="https://example.test/b", truncated=True),
            replace(base, url="https://another.test/a"),
        ]
        for changed in controls:
            with self.subTest(changed=asdict(changed)):
                self.assertEqual(terminal_rows([base, changed])[0], [base, changed])

    def test_redirect_echo_jitter_groups_but_different_destinations_do_not(self):
        def redirect(query, destination=None):
            loc = destination or f"/service/?{query}"
            return observation(f"/service?{query}", f'<a href="{loc}">Moved</a>'.encode(), 301, loc)
        a, b = redirect("Wsdl"), redirect("wsdl")
        self.assertNotEqual(a.body_digest, b.body_digest)
        self.assertEqual(terminal_rows([a, b])[0], [a])
        for changed in (redirect("wsdl", "/login"), redirect("Wsdl", "/other/"),
                        redirect("Wsdl", "/service/?mode=admin"),
                        redirect("Wsdl", "https://another.test/service/?Wsdl")):
            self.assertEqual(terminal_rows([a, changed])[0], [a, changed])

    def test_unrelated_directory_redirects_remain_visible(self):
        a = observation("/admin", b"Moved", 301, "/admin/")
        b = observation("/users", b"Moved", 301, "/users/")
        self.assertEqual(terminal_rows([a, b])[0], [a, b])

    def test_missing_fingerprint_never_groups_by_size(self):
        a = replace(observation("/a"), body_digest="")
        b = replace(a, url="https://example.test/b")
        self.assertEqual(terminal_rows([a, b])[0], [a, b])

    def test_different_denials_with_digest_bypass_the_old_four_line_cap(self):
        observer = ui.NullObserver(stream=io.StringIO())
        for index in range(8):
            finding = observation(f"/denied/{index}", f"denial {index}".encode(), status=403)
            self.assertTrue(observer._preview_response(finding, True))

    def test_report_keeps_all_events_and_jsonl_even_when_terminal_groups(self):
        sink = []
        result = ScanResult(profile=TargetProfile("example.test", "https://example.test/"))
        observer = ui.NullObserver(stream=io.StringIO())
        opts = ScanOptions(finding_sink=sink.append)
        findings = [observation("/a"), observation("/a/"), observation("/a?q=1")]
        for finding in findings:
            _report(observer, result, opts, finding, finding.url)
        self.assertEqual(len(result.findings), 3)
        self.assertEqual(len(result.reported_observations), 3)
        self.assertEqual(len(sink), 3)
        exported = json_report.to_dict(result)
        for finding in findings:
            self.assertIn(finding.url, html_report.render(result))
            self.assertTrue(any(row["url"] == finding.url
                                for row in exported["reported_observations"]))
            self.assertEqual(json_report.finding_record(finding)["body_digest"], finding.body_digest)

    def test_resume_roundtrips_signatures_and_old_fields_default_safely(self):
        finding = observation("/service?Wsdl", b"Moved", 301, "/service/")
        self.assertEqual(asdict(_finding_from_dict(_finding_to_dict(finding))), asdict(finding))
        old = _finding_to_dict(finding)
        for field in ("body_digest", "redirect_digest", "header_digest", "location", "truncated"):
            del old[field]
        self.assertEqual(_finding_from_dict(old).body_digest, "")

    def test_plain_live_groups_and_preserves_query_and_summary(self):
        output = io.StringIO()
        observer = ui.PlainLiveObserver("https://example.test/")
        with contextlib.redirect_stdout(output):
            observer.finding(observation("/a?q=1"))
            observer.finding(observation("/a?q=2"))
            observer.__exit__(None, None, None)
        self.assertIn("https://example.test/a?q=1", output.getvalue())
        self.assertNotIn("https://example.test/a?q=2", output.getvalue())
        self.assertIn("1 repeated response observations", output.getvalue())

    @unittest.skipUnless(ui.HAS_RICH, "rich optional")
    def test_rich_live_keeps_full_list_while_grouping_visible_rows(self):
        from rich.console import Console
        output = io.StringIO()
        with patch.object(ui, "console", Console(file=output, width=280, color_system=None)):
            observer = ui.RichUI("https://example.test/", full_url=True)
            with patch.object(observer, "_refresh"):
                observer.finding(observation("/a"))
                observer.finding(observation("/b"))
                observer._print_final()
        self.assertEqual(len(observer.findings), 2)
        self.assertIn("https://example.test/a", output.getvalue())
        self.assertNotIn("https://example.test/b", output.getvalue())
        self.assertIn("1 repeated response observations", output.getvalue())

    def test_engine_fingerprints_full_captured_body_without_retaining_it(self):
        async def run():
            body = b"A" * 2048 + b"<form action='/admin'>tail</form>"
            async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=body, headers={"Content-Type": "text/html"})
            )) as client:
                engine = Engine(EngineConfig())
                engine._client = client
                engine._clients = [client]
                probe = await engine._stream_probe("https://example.test/a", "GET", False, {})
            self.assertEqual(probe.body, b"")
            self.assertEqual(probe.body_digest, body_digests(body, probe.url)[0])
            finding = classify(TargetProfile("example.test", "https://example.test/"), probe, "wordlist")
            self.assertIsNotNone(finding)
            self.assertEqual(finding.body_digest, probe.body_digest)
            self.assertEqual(finding.header_digest, probe.header_digest)
        asyncio.run(run())

    def test_malformed_redirect_location_cannot_crash_fingerprinting(self):
        raw, redirected = body_digests(b"Moved", "https://example.test/a", "http://[invalid")
        self.assertTrue(raw)
        self.assertEqual(redirected, "")
        preview = ResponsePreview()
        self.assertTrue(preview.accept(observation("/a", b"Moved", 301, "http://[invalid")))

    def test_final_terminal_recovers_distinct_same_size_bodies_after_legacy_collapse(self):
        output = io.StringIO()
        observer = ui.NullObserver(stream=output)
        result = ScanResult(profile=TargetProfile("example.test", "https://example.test/"))
        for index in range(7):
            body = f"<html><form action='/page{index}'>Login</form></html>".encode()
            finding = observation(f"/different/{index}", body)
            _report(observer, result, ScanOptions(), finding, finding.url)
        before = list(result.reported_observations)
        result.findings = _dedupe_and_collapse(result.findings, observer)
        self.assertEqual(len(result.findings), 1)  # existing discovery view stays unchanged
        self.assertEqual(len(terminal_rows(terminal_findings(result))[0]), 7)
        with contextlib.redirect_stdout(output):
            ui._plain_report(result, full_url=True, show_fingerprint=False)
        for index in range(7):
            self.assertIn(f"https://example.test/different/{index}", output.getvalue())
        self.assertEqual(result.reported_observations, before)
        self.assertEqual(len(result.findings), 1)
        result.findings[0].note += " · later evidence"
        result.findings[0].tags.append("secret")
        recovered = terminal_findings(result)
        enriched = next(row for row in recovered if row.url == result.findings[0].url)
        self.assertIn("later evidence", enriched.note)
        self.assertIn("secret", enriched.tags)
        self.assertNotIn("presentation group:", enriched.note)

    def test_correlations_explain_repeats_and_link_every_evidence_record(self):
        result = ScanResult(profile=TargetProfile("example.test", "https://example.test/"))
        observer = ui.NullObserver(stream=io.StringIO())
        for index in range(4):
            finding = observation(f"/repeated/{index}")
            _report(observer, result, ScanOptions(), finding, finding.url)
        groups = response_correlations(result)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 4)
        self.assertTrue(groups[0]["raw_body_equal"])
        for reference, url in zip(groups[0]["evidence_refs"], groups[0]["urls"], strict=True):
            self.assertEqual(reference["collection"], "reported_observations")
            self.assertEqual(result.reported_observations[reference["index"]]["url"], url)
        exported = json_report.to_dict(result)
        self.assertEqual(exported["response_correlations"], groups)
        self.assertIn("Response presentation groups", html_report.render(result))

    def test_fingerprint_correlations_dedup_signals_and_preserve_prefixes(self):
        profile = TargetProfile("example.test", "https://example.test/")
        header = Evidence("header", "php", "X-Powered-By: PHP", 70, "/app/")
        profile.evidence = [header, header,
                            Evidence("cookie", "php", "PHPSESSID", 80, "/app/"),
                            Evidence("body", "php", "PHP error page", 50, "/other/")]
        profile.tech_scores = {"php": 100, "nginx": 60}
        before = [asdict(item) for item in profile.evidence]
        rows = fingerprint_correlations(profile)
        app = next(row for row in rows if row["path_prefix"] == "/app/")
        self.assertEqual(app["distinct_signal_count"], 2)
        self.assertEqual(app["evidence_indices"], [0, 1, 2])
        self.assertEqual(app["support"], "multiple_signal_types")
        other = next(row for row in rows if row["path_prefix"] == "/other/")
        self.assertEqual(other["signal_types"], ["body"])
        self.assertEqual(other["support"], "single_signal_type")
        orphan = next(row for row in rows if row["tech"] == "nginx")
        self.assertEqual(orphan["support"], "provenance_unavailable")
        self.assertEqual([asdict(item) for item in profile.evidence], before)
        self.assertEqual(profile.tech_scores, {"php": 100, "nginx": 60})

    def test_html_correlation_sections_escape_server_controlled_evidence(self):
        result = ScanResult(profile=TargetProfile("example.test", "https://example.test/"))
        result.profile.evidence = [Evidence("header", "<script>tech</script>", "detail", 70)]
        result.findings = [observation("/<script>a</script>"), observation("/<script>b</script>")]
        rendered = html_report.render(result)
        self.assertIn("&lt;script&gt;tech&lt;/script&gt;", rendered)
        self.assertIn("&lt;script&gt;a&lt;/script&gt;", rendered)
        self.assertNotIn("<script>tech</script>", rendered)
