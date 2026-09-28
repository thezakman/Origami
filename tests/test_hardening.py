"""Offline regressions for operator safety and local persistence."""

import asyncio
import contextlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from origami import cli
from origami.brain.memory import Memory
from origami.core.evidence import TargetProfile
from origami.core.files import atomic_write
from origami.core.httpclient import Engine, EngineConfig
from origami.core.response_classifier import Finding
from origami.core.scanner.types import ScanResult


def arguments(*extra):
    """Use the real parser without running a scan or touching the memory DB."""
    captured = []

    async def capture(args):
        captured.append(args)
        return 0

    argv = ["origami", "https://example.test/", "--no-ui", "--no-learn", *extra]
    with patch("sys.argv", argv), patch.object(cli, "run", capture):
        with contextlib.redirect_stdout(io.StringIO()):
            with unittest.TestCase().assertRaises(SystemExit) as cm:
                cli.main()
    assert cm.exception.code == 0
    return captured[0]


def result():
    return ScanResult(
        profile=TargetProfile(host="example.test", base_url="https://example.test/"),
        requests_made=2, completed=True,
        findings=[Finding("https://example.test/item", 200, 10, "text/plain", .8,
                          "fixture", note="synthetic evidence", tags=["fixture"])],
    )


class TestInputSafety(unittest.TestCase):
    def test_invalid_durations(self):
        for value in ("-1s", "nan", "inf", "-inf", "1e999", " "):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                cli._parse_duration(value)
        self.assertEqual(cli._parse_duration("2m"), 120)
        self.assertEqual(cli._parse_duration("0"), 0)

    def test_invalid_urls(self):
        for value in ("ftp://example.test/", "https://user:secret@example.test/",
                      "https://example.test:bad/", "https://[broken/"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                cli._normalize_url(value)
        self.assertEqual(cli._normalize_url("https://[::1]:8443/a"), "https://[::1]:8443/a")

    def test_header_names_case_insensitive_and_no_secret_errors(self):
        headers = cli._parse_headers(["X-Test: first", "x-test: last"])
        self.assertEqual(len(headers), 1)
        self.assertEqual(next(iter(headers.values())), "last")
        with self.assertRaises(SystemExit) as cm:
            cli._parse_headers(["Authorization secret-marker"])
        self.assertNotIn("secret-marker", str(cm.exception))

    def test_validation_preserves_previous_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.jsonl"
            path.write_text("previous evidence\n")
            variants = [("--proxy-file", str(Path(directory) / "missing")),
                        ("--concurrency", "0"), ("--rate", "nan"),
                        ("--header", "invalid")]
            for flags in variants:
                with self.subTest(flags=flags):
                    args = arguments("--jsonl", str(path), *flags)
                    with patch.object(cli, "Engine") as engine:
                        with contextlib.redirect_stdout(io.StringIO()):
                            with self.assertRaises(SystemExit):
                                asyncio.run(cli.run(args))
                        engine.assert_not_called()
                    self.assertEqual(path.read_text(), "previous evidence\n")


class TestResourceSafety(unittest.TestCase):
    def test_partial_client_construction_closes_first(self):
        async def check():
            client = type("Client", (), {"aclose": AsyncMock()})()
            engine = Engine(EngineConfig(proxies=["first", "second"]))
            with patch.object(engine, "_new_client", side_effect=[client, ValueError("invalid")]):
                with self.assertRaises(ValueError):
                    await engine.__aenter__()
            client.aclose.assert_awaited_once()
            self.assertEqual(engine._clients, [])
        asyncio.run(check())

    def test_close_failure_still_closes_remaining_clients(self):
        async def check():
            first = type("Client", (), {"aclose": AsyncMock(side_effect=OSError("close"))})()
            second = type("Client", (), {"aclose": AsyncMock()})()
            engine = Engine()
            engine._clients = [first, second]
            engine._client = first
            with self.assertRaises(OSError):
                await engine.__aexit__(None, None, None)
            second.aclose.assert_awaited_once()
            self.assertIsNone(engine._client)
        asyncio.run(check())

    def test_failed_transaction_cannot_be_committed_later(self):
        with tempfile.TemporaryDirectory() as directory, Memory(Path(directory) / "memory.db") as mem:
            mem.db.execute("CREATE TRIGGER reject_fixture BEFORE INSERT ON findings "
                           "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;")
            mem.db.commit()
            r = result()
            with self.assertRaises(sqlite3.IntegrityError):
                mem.record_run(r.profile, r)
            self.assertFalse(mem.db.in_transaction)
            mem.record_word_stats({"fixture": (1, 0)}, [])
            self.assertEqual(mem.history(), [])


class TestOutputSafety(unittest.TestCase):
    def test_output_failure_is_not_swallowed_by_stage_guard(self):
        from origami.core.files import OutputWriteError
        from origami.core.scanner.util import _guard
        from origami.output.ui import NullObserver

        async def failing_output():
            raise OutputWriteError("synthetic")

        with self.assertRaises(OutputWriteError):
            asyncio.run(_guard(NullObserver(), "fixture", failing_output(), None))

    def test_cli_failure_preserves_checkpoint_and_sets_status(self):
        class FakeEngine:
            def __init__(self, cfg): self.cfg = cfg
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass

        with tempfile.TemporaryDirectory() as directory:
            args = arguments("--json", str(Path(directory) / "missing" / "result.json"))
            with patch.object(cli, "Engine", FakeEngine), \
                 patch.object(cli, "scan", AsyncMock(return_value=result())), \
                 patch.object(cli.resume_mod, "clear") as clear, \
                 patch.object(cli.ui, "print_report"), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(asyncio.run(cli.run(args)), 3)
                clear.assert_not_called()

    def test_existing_jsonl_is_not_truncated_even_with_valid_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.jsonl"
            path.write_text("previous\n")
            with self.assertRaises(FileExistsError):
                asyncio.run(cli.run(arguments("--jsonl", str(path))))
            self.assertEqual(path.read_text(), "previous\n")

    def test_outputs_independent_and_status_not_on_jsonl_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            args = arguments("--jsonl", "-", "--json", str(Path(directory) / "missing" / "bad.json"),
                             "--html", str(Path(directory) / "good.html"))
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                outcome = cli._write_outputs(args, result(), "https://example.test/", False)
            self.assertEqual(stdout.getvalue(), "")
            self.assertTrue((Path(directory) / "good.html").exists())
            self.assertTrue(outcome["errors"])

    def test_success_status_stays_off_jsonl_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            args = arguments("--jsonl", "-", "--json", str(Path(directory) / "good.json"))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                outcome = cli._write_outputs(args, result(), "https://example.test/", False)
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(outcome["errors"])

    def test_atomic_failure_preserves_previous_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("previous")
            with patch("origami.core.files.os.replace", side_effect=OSError("disk")):
                with self.assertRaises(OSError):
                    atomic_write(path, "new")
            self.assertEqual(path.read_text(), "previous")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_private_artifacts_and_notes(self):
        from origami.output import artifacts, html_report, json_report
        with tempfile.TemporaryDirectory() as directory:
            previous = os.umask(0)
            try:
                r = result()
                r.completed = False
                info = artifacts.write_artifacts(r, Path(directory) / "bundle")
                self.assertFalse(info.get("errors"))
                path = Path(directory) / "bundle" / "findings.json"
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                data = json.loads(path.read_text())
                self.assertFalse(data["completed"])
                self.assertIn("synthetic evidence", html_report.render(r))
                self.assertIn("schema_version", json_report.to_dict(r))
            finally:
                os.umask(previous)

    def test_database_private_under_permissive_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.umask(0)
            try:
                path = Path(directory) / "private" / "memory.db"
                with Memory(path):
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                    for suffix in ("-wal", "-shm"):
                        sidecar = Path(str(path) + suffix)
                        if sidecar.exists():
                            self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600)
            finally:
                os.umask(previous)

    def test_partial_bundle_has_manifest_and_other_artifacts(self):
        from origami.output import artifacts
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(artifacts.graph, "write", side_effect=OSError("synthetic")):
                info = artifacts.write_artifacts(result(), directory)
            manifest = json.loads((Path(directory) / "manifest.json").read_text())
            self.assertFalse(manifest["completed"])
            self.assertIn("graph", info["errors"])
            self.assertIn("report.html", manifest["files"])
            self.assertTrue((Path(directory) / "findings.json").exists())

    def test_slug_has_origin_and_path_identity(self):
        urls = ["http://example.test/a", "https://example.test/a",
                "https://example.test/a/b", "https://example.test/a_b"]
        self.assertEqual(len({cli._slug(url) for url in urls}), len(urls))


if __name__ == "__main__":
    unittest.main()
