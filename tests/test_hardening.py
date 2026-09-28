"""Offline regressions for operator safety and local persistence."""

import asyncio
import contextlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from origami import cli
from origami.brain.memory import Memory
from origami.core.evidence import TargetProfile
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


if __name__ == "__main__":
    unittest.main()
