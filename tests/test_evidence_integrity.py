"""Persistence and comparison regressions using only synthetic local evidence."""

import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from origami.brain.memory import Memory
from origami.core.evidence import TargetProfile
from origami.core.response_classifier import Finding
from origami.core.scanner.types import ScanResult


def sample(url="https://example.test/app.a1b2c3d4.js"):
    return ScanResult(
        profile=TargetProfile(host="example.test", base_url="https://example.test/"),
        completed=False, requests_made=2,
        findings=[Finding(url, 200, 10, "text/plain", .8, "fixture",
                          note="raw note", tags=["fixture"], repro="inert reproduction text")],
    )


class TestEvidencePersistence(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.memory = Memory(Path(directory.name) / "evidence.db")
        self.addCleanup(self.memory.close)

    def test_pruning_learning_data_preserves_historical_evidence(self):
        result = sample()
        run_id = self.memory.record_run(result.profile, result)
        self.memory.db.execute("INSERT INTO corpus VALUES (?, ?, ?)",
                               ("example.test", "/app.a1b2c3d4.js", 200))
        self.memory.db.commit()
        self.memory.prune_fingerprinted()
        count = self.memory.db.execute("SELECT COUNT(*) FROM findings WHERE run_id=?", (run_id,)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_forget_failure_rolls_back_before_other_writes(self):
        result = sample()
        self.memory.record_run(result.profile, result)
        self.memory.db.execute("CREATE TRIGGER reject_delete BEFORE DELETE ON findings "
                               "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
        self.memory.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.memory.forget("example.test")
        self.assertFalse(self.memory.db.in_transaction)
        self.memory.record_word_stats({"fixture": (1, 0)}, [])
        self.assertEqual(len(self.memory.history()), 1)

    def test_snapshot_preserves_notes_commands_and_partial_state(self):
        result = sample()
        run_id = self.memory.record_run(result.profile, result)
        raw = self.memory.report_snapshot(run_id)
        report = json.loads(raw)
        self.assertEqual(report["findings"][0]["note"], "raw note")
        self.assertEqual(report["findings"][0]["repro"], "inert reproduction text")
        self.assertEqual(report["state"], "partial")
        self.assertEqual(report["findings"][0]["tags"], ["fixture"])
        self.memory.forget("example.test")
        self.assertIsNone(self.memory.report_snapshot(run_id))

    def test_snapshot_write_failure_rolls_back_entire_run(self):
        self.memory.db.execute("CREATE TRIGGER reject_snapshot BEFORE INSERT ON report_snapshots "
                               "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
        self.memory.db.commit()
        result = sample()
        with self.assertRaises(sqlite3.IntegrityError):
            self.memory.record_run(result.profile, result)
        self.assertFalse(self.memory.db.in_transaction)
        self.assertEqual(self.memory.history(), [])
        self.assertEqual(self.memory.db.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 0)

    def test_recovery_exact_bytes_and_existing_output_protected(self):
        from origami.output.archive import export_saved_report
        result = sample()
        run_id = self.memory.record_run(result.profile, result)
        destination = self.memory.path.parent / "recovered.json"
        export_saved_report(self.memory.path, run_id, destination)
        self.assertEqual(destination.read_text(), self.memory.report_snapshot(run_id))
        with self.assertRaises(FileExistsError):
            export_saved_report(self.memory.path, run_id, destination)
        with self.assertRaises(FileExistsError):
            export_saved_report(self.memory.path, run_id, self.memory.path)
        self.assertEqual(self.memory.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_legacy_database_is_extended_without_fabricating_snapshots(self):
        self.memory.db.execute("DROP TABLE report_snapshots")
        self.memory.db.execute("INSERT INTO runs (host) VALUES ('legacy.test')")
        self.memory.db.commit()
        with Memory(self.memory.path) as reopened:
            self.assertIsNone(reopened.report_snapshot(1))
            self.assertEqual(len(reopened.history()), 1)

    def test_forget_all_failure_preserves_snapshot(self):
        result = sample()
        run_id = self.memory.record_run(result.profile, result)
        self.memory.db.execute("CREATE TRIGGER reject_delete BEFORE DELETE ON findings "
                               "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
        self.memory.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.memory.forget()
        self.assertIsNotNone(self.memory.report_snapshot(run_id))
        self.assertEqual(len(self.memory.history()), 1)

    def test_cli_recovers_without_scanner_or_writable_memory(self):
        from origami import cli
        result = sample()
        run_id = self.memory.record_run(result.profile, result)
        destination = self.memory.path.parent / "cli.json"
        with patch("sys.argv", ["origami", "--export-run", str(run_id), "--db",
                                str(self.memory.path), "--json", str(destination)]), \
             patch.object(cli, "run", side_effect=AssertionError("scanner invoked")), \
             patch.object(cli, "Memory", side_effect=AssertionError("writable DB opened")), \
             patch("sys.stdin", None), contextlib.redirect_stdout(io.StringIO()), \
             self.assertRaises(SystemExit) as cm:
            cli.main()
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(destination.read_text(), self.memory.report_snapshot(run_id))
