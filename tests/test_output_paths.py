"""Reject destructive output aliases before resources or discovery are opened."""

import asyncio
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from origami import cli


def arguments(*extra):
    captured = []

    async def capture(args):
        captured.append(args)
        return 0

    with patch("sys.argv", ["origami", "https://example.test/", "--no-ui", *extra]), \
         patch.object(cli, "run", capture), unittest.TestCase().assertRaises(SystemExit):
        cli.main()
    return captured[0]


class TestOutputPaths(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)

    def reject(self, *flags):
        args = arguments(*flags)
        with patch.object(cli, "Engine", side_effect=AssertionError("HTTP must not be opened")), \
             patch.object(cli, "Memory", side_effect=AssertionError("DB must not be opened")), \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            asyncio.run(cli.run(args))

    def test_report_cannot_replace_database_or_sidecars(self):
        database = self.folder / "project.db"
        database.write_bytes(b"preserve database")
        for target in (database, Path(str(database) + "-wal"), Path(str(database) + "-shm")):
            with self.subTest(target=target):
                self.reject("--db", str(database), "--json", str(target))
        self.assertEqual(database.read_bytes(), b"preserve database")

    def test_report_formats_cannot_overwrite_each_other(self):
        destination = str(self.folder / "report")
        self.reject("--json", destination, "--html", destination)

    def test_graph_implicit_sibling_cannot_replace_json(self):
        self.reject("--graph", str(self.folder / "graph.html"),
                    "--json", str(self.folder / "graph.dot"))

    def test_bundle_cannot_replace_stream(self):
        stream = self.folder / "findings.json"
        self.reject("--out", str(self.folder), "--jsonl", str(stream))
        self.assertFalse(stream.exists())

    def test_client_routes_artifact_cannot_replace_stream(self):
        stream = self.folder / "client_routes.json"
        self.reject("--out", str(self.folder), "--jsonl", str(stream))
        self.assertFalse(stream.exists())

    def test_input_wordlist_alias_is_preserved(self):
        source = self.folder / "words.txt"
        source.write_text("fixture\n")
        self.reject("-w", str(source), "--json", str(source))
        self.assertEqual(source.read_text(), "fixture\n")

    def test_existing_hardlink_alias_is_rejected(self):
        source = self.folder / "words.txt"
        source.write_text("fixture\n")
        alias = self.folder / "alias.json"
        os.link(source, alias)
        self.reject("-w", str(source), "--json", str(alias))

    def test_existing_symlink_alias_is_rejected(self):
        source = self.folder / "words.txt"
        source.write_text("fixture\n")
        alias = self.folder / "alias.json"
        alias.symlink_to(source)
        self.reject("-w", str(source), "--json", str(alias))

    def test_multitarget_effective_filename_is_checked(self):
        target = "https://example.test/"
        requested = str(self.folder / "report.json")
        effective = cli._suffix(requested, cli._slug(target))
        self.reject("-u", "https://other.test/", "--db", effective, "--json", requested)

    def test_target_list_and_checkpoint_are_protected(self):
        source = self.folder / "targets.txt"
        source.write_text("https://example.test/\n")
        self.reject("-l", str(source), "--json", str(source))
        checkpoint = self.folder / "checkpoint.json"
        with patch.object(cli.resume_mod, "path_for", return_value=checkpoint):
            self.reject("--json", str(checkpoint))

    def test_credentials_path_is_protected(self):
        credentials = self.folder / "credentials.toml"
        with patch("origami.core.credentials.config_path", return_value=credentials):
            self.reject("--json", str(credentials))

    def test_file_directory_output_conflict_is_rejected(self):
        self.reject("--json", str(self.folder / "bundle"), "--out", str(self.folder / "bundle"))

    def test_independent_outputs_remain_allowed_without_creating_files(self):
        args = arguments("--json", str(self.folder / "summary.json"),
                         "--html", str(self.folder / "summary.html"),
                         "--out", str(self.folder / "bundle"))
        cli._validate_output_paths(args, ["https://example.test/"])
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_no_file_outputs_need_no_path_preflight(self):
        args = arguments("--jsonl", "-")
        with patch("origami.output.paths.check_output_paths") as check:
            cli._validate_output_paths(args, ["https://example.test/"])
        check.assert_not_called()

    def test_unresolvable_path_is_a_controlled_validation_error(self):
        from origami.output.paths import check_output_paths
        with patch.object(Path, "resolve", side_effect=RuntimeError("synthetic loop")), \
             self.assertRaises(ValueError):
            check_output_paths([("json", self.folder / "output")], [])
