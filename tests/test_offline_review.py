"""Offline evidence review contracts, without scanner or network execution."""

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from origami import cli
from origami.output.review import InvalidReport, review_report


def fixture():
    return {
        "schema_version": 2, "base_url": "https://example.test/", "completed": True,
        "error": "", "state": "finished", "coverage": "unknown", "requests_made": 2,
        "findings": [{"url": "https://example.test/?token=secret-sentinel", "status": 200,
                      "length": 10, "confidence": .8, "origin": "fixture",
                      "note": "secret-sentinel", "repro": "do-not-execute secret-sentinel"}],
    }


class TestOfflineReview(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "report.json"

    def write(self, data):
        self.path.write_text(json.dumps(data), encoding="utf-8")

    def test_summary_fingerprint_and_source_preservation(self):
        data = fixture()
        data["findings"] *= 2
        self.write(data)
        before = self.path.read_bytes()
        summary = review_report(self.path)
        self.assertEqual(summary["source_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(summary["observations"], 2)
        self.assertEqual(summary["repeated_observations"], 1)
        self.assertEqual(summary["with_notes"], 2)
        self.assertEqual(summary["status_counts"], {"200": 2})
        self.assertNotIn("secret-sentinel", json.dumps(summary))
        self.assertEqual(before, self.path.read_bytes())

    def test_legacy_state_is_unknown(self):
        data = fixture()
        del data["schema_version"]
        self.write(data)
        self.assertEqual(review_report(self.path)["state"], "unknown")

    def test_invalid_or_ambiguous_json(self):
        for raw in (b'[]', b'{"findings":[],"findings":[]}', b'{"a":NaN}',
                    b'{"a":Infinity}', b'\xff', b'{', b'[' * 2000):
            with self.subTest(raw=raw[:30]):
                self.path.write_bytes(raw)
                with self.assertRaises(InvalidReport):
                    review_report(self.path)

    def test_rejects_invalid_metadata(self):
        for key, value in (("schema_version", True), ("schema_version", 3),
                           ("schema_version", None),
                           ("state", "partial"), ("completed", "true"),
                           ("coverage", "complete"), ("requests_made", -1),
                           ("base_url", "file:///etc/passwd")):
            with self.subTest(key=key):
                data = fixture()
                data[key] = value
                self.write(data)
                with self.assertRaises(InvalidReport):
                    review_report(self.path)

    def test_rejects_invalid_observations_without_echoing_values(self):
        for key, value in (("url", "secret-sentinel"), ("status", True),
                           ("confidence", 10**500), ("confidence", -1),
                           ("length", -1), ("tags", "secret-sentinel"),
                           ("note", ["secret-sentinel"])):
            with self.subTest(key=key):
                data = fixture()
                data["findings"][0][key] = value
                self.write(data)
                with self.assertRaises(InvalidReport) as cm:
                    review_report(self.path)
                self.assertNotIn("secret-sentinel", str(cm.exception))

    def test_size_limit(self):
        self.write(fixture())
        with patch("origami.output.review.MAX_REPORT_BYTES", 10), self.assertRaises(InvalidReport):
            review_report(self.path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.path)
        with self.assertRaises(InvalidReport):
            review_report(self.path)

    def run_cli(self, *extra):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.argv", ["origami", "--review-report", str(self.path), *extra]), \
             patch.object(cli, "run", side_effect=AssertionError("unexpected scanner")), \
             patch.object(cli, "Memory", side_effect=AssertionError("unexpected DB")), \
             patch.object(cli, "Engine", side_effect=AssertionError("unexpected HTTP client")), \
             patch("sys.stdin", None), contextlib.redirect_stdout(stdout), \
             contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as cm:
            cli.main()
        return cm.exception.code, stdout.getvalue(), stderr.getvalue()

    def test_cli_offline_and_exit_status(self):
        for state, completed, error, expected in (("finished", True, "", 0),
                                                  ("partial", False, "", 3),
                                                  ("failed", False, "secret-sentinel", 3)):
            data = fixture()
            data.update(state=state, completed=completed, error=error,
                        coverage="unknown" if completed else "partial")
            self.write(data)
            code, stdout, stderr = self.run_cli()
            self.assertEqual(code, expected)
            self.assertEqual(json.loads(stdout)["state"], state)
            self.assertNotIn("sentinel", stdout + stderr)

    def test_cli_rejects_operational_combinations(self):
        self.write(fixture())
        for extra in (("--update",), ("--forget", "all"), ("https://example.test/",),
                      ("--out", str(Path(self.directory.name) / "unused"))):
            with self.subTest(extra=extra):
                code, stdout, stderr = self.run_cli(*extra)
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertIn("must be used alone", stderr)

    def test_cli_malformed_report_is_safe_error(self):
        self.path.write_text("secret-sentinel", encoding="utf-8")
        code, stdout, stderr = self.run_cli()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertNotIn("sentinel", stderr)
