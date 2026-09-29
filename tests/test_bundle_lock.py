"""A bundle has one writer until its completion manifest is committed."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from origami.core.evidence import TargetProfile
from origami.core.scanner.types import ScanResult
from origami.output import artifacts


class TestBundleLock(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)
        self.result = ScanResult(profile=TargetProfile(host="example.test", base_url="https://example.test/"))

    def test_existing_lock_preserves_all_previous_outputs(self):
        artifacts.write_artifacts(self.result, self.folder)
        before = {p.name: p.read_bytes() for p in self.folder.iterdir()}
        lock = self.folder / ".origami-export.lock"
        lock.mkdir()
        with self.assertRaises(FileExistsError):
            artifacts.write_artifacts(self.result, self.folder)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.folder.iterdir() if p != lock})

    def test_second_writer_is_rejected_before_manifest_changes(self):
        original = artifacts.atomic_write
        attempted = False

        def writing(path, text):
            nonlocal attempted
            if not attempted:
                attempted = True
                with self.assertRaises(FileExistsError):
                    artifacts.write_artifacts(self.result, self.folder)
                self.assertFalse((self.folder / "manifest.json").exists())
            return original(path, text)

        with patch.object(artifacts, "atomic_write", side_effect=writing):
            artifacts.write_artifacts(self.result, self.folder)
        self.assertFalse((self.folder / ".origami-export.lock").exists())

    def test_interruption_releases_owned_lock(self):
        with patch.object(artifacts, "atomic_write", side_effect=KeyboardInterrupt), \
             self.assertRaises(KeyboardInterrupt):
            artifacts.write_artifacts(self.result, self.folder)
        self.assertFalse((self.folder / ".origami-export.lock").exists())
        artifacts.write_artifacts(self.result, self.folder)
        self.assertTrue((self.folder / "manifest.json").exists())
