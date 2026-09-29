"""Repeated denied observations are summarized without changing scanner inputs."""

import contextlib
import io
import unittest
from unittest.mock import patch

from origami.core.evidence import TargetProfile
from origami.core.response_classifier import Finding
from origami.core.scanner._common import _report
from origami.core.scanner.types import ScanOptions, ScanResult
from origami.output import html_report, ui


@unittest.skipUnless(ui.HAS_RICH, "rich optional")
class TestDeniedPresentation(unittest.TestCase):
    def test_different_lengths_do_not_restart_denied_preview(self):
        from rich.console import Console
        output = io.StringIO()
        findings = [Finding(f"https://example.test/denied/{index:02d}", 403, 200 + index,
                            "text/plain", .85, "wordlist") for index in range(20)]
        with patch.object(ui, "console", Console(file=output, width=280, color_system=None)):
            observer = ui.RichUI("https://example.test/", full_url=True)
            with patch.object(observer, "_refresh"):
                for finding in findings:
                    observer.finding(finding)
                observer._print_final()
        visible = sum(finding.url in output.getvalue() for finding in findings)
        self.assertEqual(visible, 4)
        self.assertEqual(len(observer.findings), 20)
        self.assertIn("16 denied observations hidden", output.getvalue())
        self.assertIn("does not establish path existence", output.getvalue())

    def test_declared_contract_observations_remain_visible(self):
        from rich.console import Console
        output = io.StringIO()
        with patch.object(ui, "console", Console(file=output, width=280, color_system=None)):
            observer = ui.RichUI("https://example.test/", full_url=True)
            with patch.object(observer, "_refresh"):
                for index in range(8):
                    observer.finding(Finding(f"https://example.test/declared/{index}", 401, 0,
                                             "text/plain", .85, "apidocs"))
        for index in range(8):
            self.assertIn(f"https://example.test/declared/{index}", output.getvalue())


class TestObservationDetailHtml(unittest.TestCase):
    def test_plain_terminal_has_same_bounded_denied_preview(self):
        output = io.StringIO()
        observer = ui.PlainLiveObserver("https://example.test/", full_url=True)
        with contextlib.redirect_stdout(output):
            for index in range(20):
                observer.finding(Finding(f"https://example.test/denied/{index:02d}", 403,
                                         200 + index, "text/plain", .85, "wordlist"))
            observer.__exit__(None, None, None)
        self.assertEqual(sum(f"https://example.test/denied/{index:02d}" in output.getvalue()
                             for index in range(20)), 4)
        self.assertIn("16 denied observations hidden", output.getvalue())

    def test_group_notice_is_not_repeated_for_each_denied_length(self):
        output = io.StringIO()
        observer = ui.NullObserver(stream=output)
        result = ScanResult(profile=TargetProfile(host="example.test", base_url="https://example.test/"))
        for index in range(12):
            finding = Finding(f"https://example.test/denied/{index}", 403,
                              200 + index // 6, "text/plain", .85, "wordlist")
            _report(observer, result, ScanOptions(), finding, finding.url)
        self.assertEqual(output.getvalue().count("block-wall:"), 1)
        self.assertEqual(len(result.reported_observations), 12)

    def test_emitted_urls_and_notes_remain_inspectable_after_grouping(self):
        from origami.core.scanner._common import _dedupe_and_collapse
        result = ScanResult(profile=TargetProfile(host="example.test", base_url="https://example.test/"))
        observer = ui.NullObserver(stream=io.StringIO())
        for index in range(8):
            finding = Finding(f"https://example.test/fixture/{index}", 403, 210,
                              "text/plain", .85, "wordlist", note=f"<note-{index}>")
            _report(observer, result, ScanOptions(), finding, finding.url)
        result.findings = _dedupe_and_collapse(result.findings, observer)
        text = html_report.render(result)
        for index in range(8):
            self.assertIn(f"https://example.test/fixture/{index}", text)
            self.assertIn(f"&lt;note-{index}&gt;", text)
        self.assertNotIn("<note-0>", text)
