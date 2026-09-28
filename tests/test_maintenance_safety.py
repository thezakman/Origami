"""Local maintenance must not initialize databases or leak resources on failure."""

import contextlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from origami import cli
from origami.brain.memory import Memory


class TestMaintenanceSafety(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "history.db"

    def test_history_does_not_create_missing_database(self):
        args = SimpleNamespace(db=str(self.path), url=[])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli._show_history(args), 0)
        self.assertFalse(self.path.exists())

    def test_history_does_not_migrate_legacy_database(self):
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE runs (id, host, ts, requests, findings, techs)")
        before = self.path.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            cli._show_history(SimpleNamespace(db=str(self.path), url=[]))
        self.assertEqual(before, self.path.read_bytes())

    def test_failed_forget_closes_connection(self):
        mem = Memory(self.path)
        args = SimpleNamespace(db=str(self.path), forget="all")
        with patch.object(cli, "Memory", return_value=mem), \
             patch.object(mem, "forget", side_effect=sqlite3.OperationalError("sentinel")):
            with self.assertRaises(sqlite3.OperationalError):
                cli._forget(args)
        try:
            with self.assertRaises(sqlite3.ProgrammingError):
                mem.db.execute("SELECT 1")
        finally:
            mem.close()

    def test_forget_missing_database_does_not_create_it(self):
        with self.assertRaises(FileNotFoundError):
            cli._forget(SimpleNamespace(db=str(self.path), forget="all"))
        self.assertFalse(self.path.exists())

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.argv", ["origami", "--db", str(self.path), *args]), \
             patch.object(cli, "run", side_effect=AssertionError("unexpected scan")), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
             self.assertRaises(SystemExit) as cm:
            cli.main()
        return cm.exception.code, stdout.getvalue(), stderr.getvalue()

    def test_corrupt_db_is_safe_cli_error(self):
        self.path.write_bytes(b"secret-sentinel-not-a-database")
        code, stdout, stderr = self.invoke("--history")
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertNotIn("sentinel", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_conflicting_maintenance_actions_are_rejected(self):
        code, _, _ = self.invoke("--history", "--forget", "all")
        self.assertEqual(code, 2)
        self.assertFalse(self.path.exists())
