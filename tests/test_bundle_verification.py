"""Local bundle integrity and safe-reader contracts; no target requests."""

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
from origami.core.evidence import TargetProfile
from origami.core.scanner.types import ScanResult
from origami.output import artifacts
from origami.output import bundle_verify as verification


class TestBundleVerification(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.folder = Path(self.directory.name) / "bundle"
        scan = ScanResult(TargetProfile("example.test", "https://example.test/"))
        artifacts.write_artifacts(scan, self.folder)

    def verify(self):
        return verification.verify_bundle(self.folder)

    def manifest(self):
        return json.loads((self.folder / "manifest.json").read_text())

    def write_manifest(self, data):
        (self.folder / "manifest.json").write_text(json.dumps(data), encoding="utf-8")

    def invoke(self, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with patch("sys.argv", ["origami", *arguments]), \
                patch.object(cli, "run", side_effect=AssertionError("scanner invoked")), \
                patch.object(cli, "Memory", side_effect=AssertionError("database opened")), \
                patch("sys.stdin", None), contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
            cli.main()
        return raised.exception.code, output.getvalue(), errors.getvalue()

    def test_exported_bundle_verifies_without_modifying_files(self):
        before = {p.name: p.read_bytes() for p in self.folder.iterdir()}
        report = self.verify()
        self.assertTrue(report["verified"])
        self.assertEqual(report["state"], "verified")
        self.assertEqual(report["checked_file_count"], 7)
        self.assertEqual(report["scan_state"], "not_evaluated")
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.folder.iterdir()})

    def test_same_size_tampering_fails_digest_check(self):
        path = self.folder / "report.html"
        raw = path.read_bytes()
        path.write_bytes(b"X" + raw[1:])
        report = self.verify()
        self.assertFalse(report["verified"])
        row = next(row for row in report["files"] if row["name"] == "report.html")
        self.assertEqual(row["state"], "mismatch")
        self.assertEqual(row["expected_bytes"], row["actual_bytes"])

    def test_matching_rewritten_manifest_is_not_authenticity_proof(self):
        payload = b"changed artifact"
        (self.folder / "urls.txt").write_bytes(payload)
        manifest = self.manifest()
        manifest["integrity"]["urls.txt"] = {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        self.write_manifest(manifest)
        report = self.verify()
        self.assertTrue(report["verified"])
        self.assertEqual(report["interpretation"], "consistency_with_unsigned_manifest_only")
        self.assertIn("not authenticity", report["warnings"][0])

    def test_cli_offline_path_does_not_touch_scanner_database_or_stdin(self):
        code, output, errors = self.invoke(["--verify-bundle", str(self.folder)])
        self.assertEqual(code, 0, errors)
        self.assertTrue(json.loads(output)["verified"])

    def test_missing_file_is_explicit_and_not_verified(self):
        (self.folder / "urls.txt").unlink()
        report = self.verify()
        self.assertFalse(report["verified"])
        self.assertEqual(next(row["state"] for row in report["files"] if row["name"] == "urls.txt"), "missing")

    def test_read_failure_is_reported_without_exception_contents(self):
        original = verification._read_file

        def fail(root, name, cap, **kwargs):
            if name == "params.txt":
                raise PermissionError("private-sentinel")
            return original(root, name, cap, **kwargs)

        with patch.object(verification, "_read_file", side_effect=fail):
            report = self.verify()
        self.assertFalse(report["verified"])
        self.assertEqual(next(row["state"] for row in report["files"] if row["name"] == "params.txt"), "unreadable")
        self.assertNotIn("private-sentinel", json.dumps(report))

    def test_incomplete_export_cannot_pass_even_with_matching_files(self):
        data = self.manifest()
        data["completed"] = False
        self.write_manifest(data)
        report = self.verify()
        self.assertEqual(report["state"], "incomplete_export")
        self.assertFalse(report["verified"])
        self.assertEqual(report["checked_file_count"], 7)

    def test_pending_manifest_is_incomplete_not_an_empty_success(self):
        self.write_manifest({"schema_version": 1, "completed": False, "files": {}, "integrity": {},
                             "errors": {"export": "in_progress"}})
        report = self.verify()
        self.assertEqual(report["state"], "incomplete_export")
        self.assertFalse(report["verified"])
        self.assertEqual(report["checked_file_count"], 0)

    def test_invalid_json_and_ambiguous_keys_are_rejected(self):
        for raw in (b'{', b'[]', b'{"schema_version":1,"schema_version":1}',
                    b'{"secret":NaN}', b'\xff', b'[' * 2000):
            with self.subTest(raw=raw[:20]):
                (self.folder / "manifest.json").write_bytes(raw)
                with self.assertRaises(verification.InvalidBundle):
                    self.verify()

    def test_manifest_schema_and_integrity_are_strict(self):
        original = self.manifest()
        changes = [("schema_version", True), ("schema_version", 2), ("completed", 1),
                   ("files", []), ("integrity", None), ("errors", {"private-sentinel": "oops"})]
        for key, value in changes:
            with self.subTest(key=key):
                data = json.loads(json.dumps(original))
                data[key] = value
                self.write_manifest(data)
                with self.assertRaises(verification.InvalidBundle):
                    self.verify()
        for field, value in (("bytes", True), ("bytes", -1), ("sha256", "private-sentinel")):
            data = json.loads(json.dumps(original))
            data["integrity"]["params.txt"][field] = value
            self.write_manifest(data)
            with self.assertRaises(verification.InvalidBundle):
                self.verify()

    def test_completed_manifest_cannot_omit_files_or_claim_export_errors(self):
        original = self.manifest()
        data = json.loads(json.dumps(original))
        del data["files"]["urls.txt"]
        del data["integrity"]["urls.txt"]
        self.write_manifest(data)
        with self.assertRaises(verification.InvalidBundle):
            self.verify()
        original["errors"] = {"export": "in_progress"}
        self.write_manifest(original)
        with self.assertRaises(verification.InvalidBundle):
            self.verify()

    def test_unexpected_paths_are_rejected_before_artifact_reads(self):
        original = self.manifest()
        for name in ("../private-sentinel", "/private-sentinel", "nested/urls.txt", "unknown.txt"):
            with self.subTest(name=name):
                data = json.loads(json.dumps(original))
                data["files"][name] = "written"
                data["integrity"][name] = {"bytes": 0, "sha256": "0" * 64}
                self.write_manifest(data)
                with patch.object(verification, "_read_file", wraps=verification._read_file) as reader:
                    with self.assertRaises(verification.InvalidBundle):
                        self.verify()
                    self.assertEqual([call.args[1] for call in reader.call_args_list], ["manifest.json"])

    def test_symlink_artifact_is_not_opened(self):
        external = self.folder.parent / "outside"
        external.write_text("private-sentinel")
        path = self.folder / "params.txt"
        path.unlink()
        path.symlink_to(external)
        with patch.object(verification.os, "open", wraps=os.open) as opener:
            with patch.object(verification.os, "supports_dir_fd", os.supports_dir_fd | {opener}):
                report = self.verify()
        self.assertFalse(report["verified"])
        self.assertEqual(next(row["state"] for row in report["files"] if row["name"] == "params.txt"), "unsafe_file")
        self.assertNotIn("params.txt", [call.args[0] for call in opener.call_args_list])
        self.assertNotIn("private-sentinel", json.dumps(report))

    def test_manifest_and_bundle_root_symlinks_are_refused(self):
        manifest = self.folder / "manifest.json"
        external = self.folder.parent / "external-manifest"
        manifest.rename(external)
        manifest.symlink_to(external)
        with self.assertRaises(verification.InvalidBundle):
            self.verify()
        alias = self.folder.parent / "alias"
        alias.symlink_to(self.folder, target_is_directory=True)
        with self.assertRaises(OSError):
            verification.verify_bundle(alias)

    def test_hardlink_and_fifo_artifacts_are_refused(self):
        path = self.folder / "params.txt"
        os.link(path, self.folder.parent / "hardlink")
        self.assertEqual(next(row["state"] for row in self.verify()["files"] if row["name"] == "params.txt"), "unsafe_file")
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(next(row["state"] for row in self.verify()["files"] if row["name"] == "params.txt"), "unsafe_file")

    def test_lock_blocks_reads_and_is_never_removed(self):
        lock = self.folder / artifacts.BUNDLE_LOCK
        lock.mkdir()
        (self.folder / "manifest.json").write_text("malformed")
        with patch.object(verification, "_read_file", side_effect=AssertionError("read while locked")):
            report = self.verify()
        self.assertEqual(report["state"], "busy")
        self.assertTrue(lock.is_dir())

    def test_earlier_artifact_change_during_later_hash_is_detected(self):
        original = verification._read_file

        def change(root, name, cap, **kwargs):
            result = original(root, name, cap, **kwargs)
            if name == "urls.txt":
                (self.folder / "params.txt").write_text("changed after hash")
            return result

        with patch.object(verification, "_read_file", side_effect=change):
            report = self.verify()
        self.assertEqual(report["state"], "changed_during_verification")
        self.assertFalse(report["verified"])

    def test_same_bytes_manifest_replacement_is_detected(self):
        original = verification._read_file

        def replace(root, name, cap, **kwargs):
            result = original(root, name, cap, **kwargs)
            if name == "urls.txt":
                manifest = self.folder / "manifest.json"
                temporary = self.folder / "replacement"
                temporary.write_bytes(manifest.read_bytes())
                os.replace(temporary, manifest)
            return result

        with patch.object(verification, "_read_file", side_effect=replace):
            report = self.verify()
        self.assertEqual(report["state"], "changed_during_verification")
        self.assertFalse(report["verified"])

    def test_lock_appearing_during_verification_cannot_pass(self):
        original = verification._read_file

        def lock(root, name, cap, **kwargs):
            result = original(root, name, cap, **kwargs)
            if name == "urls.txt":
                (self.folder / artifacts.BUNDLE_LOCK).mkdir()
            return result

        with patch.object(verification, "_read_file", side_effect=lock):
            report = self.verify()
        self.assertEqual(report["state"], "busy")
        self.assertFalse(report["verified"])

    def test_limits_fail_explicitly_without_partial_digest_claims(self):
        with patch.object(verification, "MAX_MANIFEST_BYTES", 1):
            with self.assertRaises(verification.InvalidBundle):
                self.verify()
        for limit in ("MAX_FILE_BYTES", "MAX_TOTAL_BYTES"):
            with self.subTest(limit=limit), patch.object(verification, limit, 0):
                report = self.verify()
                self.assertFalse(report["verified"])
                rows = [row for row in report["files"] if row["state"] == "read_limit_exceeded"]
                self.assertTrue(rows)
                self.assertTrue(all("actual_sha256" not in row for row in rows))

    def test_extra_undeclared_files_are_ignored_not_authenticated(self):
        extra = self.folder / "older-run.txt"
        extra.write_text("private-sentinel")
        report = self.verify()
        self.assertTrue(report["verified"])
        self.assertNotIn("older-run.txt", json.dumps(report))

    def test_cli_conflicts_are_rejected_without_scanner_or_database(self):
        for extra in (["https://example.test/"], ["-u", "https://example.test/"],
                      ["--db", "private-sentinel"], ["--review-report", "file"],
                      ["--export-run", "1", "--json", "output"]):
            with self.subTest(extra=extra):
                code, output, _ = self.invoke(["--verify-bundle", str(self.folder), *extra])
                self.assertEqual(code, 2)
                self.assertEqual(output, "")

    def test_cli_integrity_failure_returns_json_and_nonzero_status(self):
        (self.folder / "urls.txt").write_text("changed")
        code, output, errors = self.invoke(["--verify-bundle", str(self.folder)])
        self.assertEqual(code, 2, errors)
        self.assertFalse(json.loads(output)["verified"])

    def test_cli_invalid_inputs_never_echo_values_paths_or_tracebacks(self):
        (self.folder / "manifest.json").write_text('{"private-sentinel":')
        code, output, errors = self.invoke(["--verify-bundle", str(self.folder)])
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertNotIn("private-sentinel", errors)
        self.assertNotIn("Traceback", errors)
        code, _, errors = self.invoke(["--verify-bundle", str(self.folder.parent / "private-sentinel")])
        self.assertEqual(code, 2)
        self.assertNotIn("private-sentinel", errors)

    def test_root_descriptor_is_closed_after_success_and_invalid_manifest(self):
        for malformed in (False, True):
            with self.subTest(malformed=malformed):
                if malformed:
                    (self.folder / "manifest.json").write_text("malformed")
                with patch.object(verification, "_read_file", wraps=verification._read_file) as reader:
                    if malformed:
                        with self.assertRaises(verification.InvalidBundle):
                            self.verify()
                    else:
                        self.assertTrue(self.verify()["verified"])
                root = reader.call_args_list[0].args[0]
                with self.assertRaises(OSError):
                    os.fstat(root)

    def test_file_growth_during_read_is_bounded(self):
        root = os.open(self.folder, os.O_RDONLY | os.O_DIRECTORY)
        original = os.fstat
        changed = False

        def grow(fd):
            nonlocal changed
            info = original(fd)
            if not changed:
                changed = True
                (self.folder / "params.txt").write_bytes(b"X")
            return info

        try:
            with patch.object(verification.os, "fstat", side_effect=grow):
                with self.assertRaises(verification._ReadLimit):
                    verification._read_file(root, "params.txt", 0)
        finally:
            os.close(root)

    def test_directory_replacement_during_read_is_detected(self):
        original = verification._read_file

        def replace(root, name, cap, **kwargs):
            result = original(root, name, cap, **kwargs)
            if name == "urls.txt":
                self.folder.rename(self.folder.parent / "prior-bundle")
                self.folder.mkdir()
            return result

        with patch.object(verification, "_read_file", side_effect=replace):
            report = self.verify()
        self.assertEqual(report["state"], "changed_during_verification")
        self.assertFalse(report["verified"])

    def test_failed_reads_still_consume_the_shared_budget(self):
        original = verification._read_file
        first_size = (self.folder / "findings.json").stat().st_size

        def fail_after_read(root, name, cap, **kwargs):
            result = original(root, name, cap, **kwargs)
            if name == "findings.json":
                raise verification._ChangedFile()
            return result

        with patch.object(verification, "MAX_TOTAL_BYTES", first_size), \
                patch.object(verification, "_read_file", side_effect=fail_after_read):
            report = self.verify()
        self.assertFalse(report["verified"])
        self.assertEqual(report["artifact_bytes_read"], first_size)
        remaining = [row for row in report["files"] if row["name"] == "report.html"]
        self.assertEqual(remaining[0]["state"], "read_limit_exceeded")

    def test_unsupported_platform_fails_before_opening_files(self):
        with patch.object(verification.os, "supports_dir_fd", set()), \
                patch.object(verification.os, "open", side_effect=AssertionError("unsafe fallback")):
            with self.assertRaises(verification.InvalidBundle):
                self.verify()
