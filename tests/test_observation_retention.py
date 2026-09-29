"""Synthetic reporting regressions; no requests or discovery expansion."""

import io
import json
import tempfile
import unittest
from pathlib import Path

from origami.brain.memory import Memory
from origami.core.evidence import TargetProfile
from origami.core.response_classifier import Finding
from origami.core.scanner._common import _dedupe_and_collapse, _report
from origami.core.scanner.types import ScanOptions, ScanResult
from origami.output import html_report, json_report, ui


def reported(count=8):
    result = ScanResult(profile=TargetProfile(host="example.test", base_url="https://example.test/"))
    observer = ui.NullObserver(stream=io.StringIO())
    for index in range(count):
        finding = Finding(f"https://example.test/fixture/{index}", 403, 210,
                          "text/plain", .85, "wordlist", note=f"evidence {index}", simhash=index + 1)
        _report(observer, result, ScanOptions(), finding, finding.url)
    return result


class TestObservationRetention(unittest.TestCase):
    def test_grouping_preserves_all_report_events_in_json(self):
        result = reported()
        result.findings = _dedupe_and_collapse(result.findings, ui.NullObserver(stream=io.StringIO()))
        data = json_report.to_dict(result)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(len(data["reported_observations"]), 8)
        self.assertEqual(data["reported_observations"][0]["note"], "evidence 0")
        self.assertEqual(len({row["url"] for row in data["reported_observations"]}), 8)
        self.assertEqual(data["confidence_kind"], "uncalibrated_heuristic")

    def test_observation_snapshots_are_not_changed_by_later_enrichment(self):
        result = reported(1)
        result.findings[0].note = "later enrichment"
        self.assertEqual(json_report.to_dict(result)["reported_observations"][0]["note"], "evidence 0")

    def test_unknown_legacy_retention_is_not_claimed_as_complete(self):
        result = ScanResult(profile=TargetProfile(host="example.test", base_url="https://example.test/"))
        data = json_report.to_dict(result)
        self.assertEqual(data["observation_retention"], "unavailable")

    def test_complete_events_survive_database_snapshot(self):
        result = reported()
        result.findings = _dedupe_and_collapse(result.findings, ui.NullObserver(stream=io.StringIO()))
        with tempfile.TemporaryDirectory() as directory, Memory(Path(directory) / "db") as memory:
            run_id = memory.record_run(result.profile, result)
            data = json.loads(memory.report_snapshot(run_id))
        self.assertEqual(len(data["reported_observations"]), 8)

    def test_size_collision_is_labeled_as_presentation_not_body_equality(self):
        result = reported()
        result.findings = _dedupe_and_collapse(result.findings, ui.NullObserver(stream=io.StringIO()))
        self.assertNotIn("same 210B response", result.findings[0].note)
        self.assertIn("presentation group", result.findings[0].note)

    def test_html_explains_score_and_retention(self):
        result = reported()
        result.findings = _dedupe_and_collapse(result.findings, ui.NullObserver(stream=io.StringIO()))
        text = html_report.render(result)
        self.assertIn("uncalibrated heuristic", text)
        self.assertIn("8 reported observations", text)
        self.assertIn("1 presentation rows", text)
