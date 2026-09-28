"""Terminal presentation must not interpret evidence as controls or markup."""

import contextlib
import io
import unittest
from unittest.mock import patch

from origami.core.evidence import TargetProfile
from origami.core.response_classifier import Finding
from origami.core.scanner.types import ScanResult
from origami.output import json_report, ui


def fixture():
    return ScanResult(profile=TargetProfile(host="example.test", base_url="https://example.test/"),
                      findings=[Finding("https://example.test/[bold]literal[/bold]", 200, 10,
                                        "text/plain", .5, "fixture", note="[/unexpected]\x1b[2J\rhidden",
                                        tags=["[bold]tag[/bold]"])])


class TestTerminalSafety(unittest.TestCase):
    def test_plain_logs_escape_controls_and_keep_literal_markup(self):
        output = io.StringIO()
        observer = ui.NullObserver(verbosity=2, stream=output)
        observer.log("[bold]literal[/bold]\x1b[2J\rhidden\u202etext")
        value = output.getvalue()
        self.assertNotIn("\x1b", value)
        self.assertNotIn("\r", value)
        self.assertNotIn("\u202e", value)
        self.assertIn("[bold]literal[/bold]", value)

    def test_plain_report_does_not_mutate_raw_evidence(self):
        result = fixture()
        before = json_report.to_dict(result)["findings"]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ui._plain_report(result, full_url=True)
        self.assertNotIn("\x1b", output.getvalue())
        self.assertNotIn("\r", output.getvalue())
        self.assertEqual(before, json_report.to_dict(result)["findings"])

    @unittest.skipUnless(ui.HAS_RICH, "rich optional")
    def test_rich_report_preserves_literal_evidence(self):
        from rich.console import Console
        output = io.StringIO()
        with patch.object(ui, "console", Console(file=output, width=260, color_system=None)):
            ui.print_report(fixture(), full_url=True)
        self.assertIn("[bold]literal[/bold]", output.getvalue())
        self.assertIn("[/unexpected]", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())

    @unittest.skipUnless(ui.HAS_RICH, "rich optional")
    def test_live_surfaces_treat_data_as_literal(self):
        from rich.console import Console
        output = io.StringIO()
        with patch.object(ui, "console", Console(file=output, width=260, color_system=None)):
            observer = ui.RichUI("https://example.test/", verbosity=2, full_url=True)
            with patch.object(observer, "_refresh"):
                observer.finding(fixture().findings[0])
                observer.log("[/unexpected]\x1b[2J")
                observer.directory("[/unexpected]", 1)
                observer.start_prefix("[/unexpected]", 1)
                observer.substep("[/unexpected]", 0, 1)
                ui.console.print(observer._render())
        self.assertIn("[/unexpected]", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())

    def test_diff_escapes_terminal_controls(self):
        from origami.output import diff
        result = fixture()
        result.findings[0].url += "\x1b[2J\rhidden"
        value = diff.render(diff.compute({}, result.findings), "example.test")
        self.assertNotIn("\x1b", value)
        self.assertNotIn("\r", value)

    @unittest.skipUnless(ui.HAS_RICH, "rich optional")
    def test_final_ui_does_not_assert_scan_completion(self):
        from rich.console import Console
        output = io.StringIO()
        with patch.object(ui, "console", Console(file=output, color_system=None)):
            ui.RichUI("https://example.test/")._print_final()
        self.assertIn("session ended", output.getvalue())
        self.assertNotIn("scan complete", output.getvalue())

    def test_plain_live_sanitizes_data_but_retains_own_controls(self):
        output = io.StringIO()
        observer = ui.PlainLiveObserver("https://example.test/", verbosity=2, full_url=True)
        with contextlib.redirect_stdout(output):
            observer.log("raw\x1b[2J\rhidden")
            observer.directory("raw\x1b[2J", 1)
        self.assertNotIn("\x1b[2J", output.getvalue())
        self.assertIn("\\x1b[2J", output.getvalue())
