"""Bounded, descriptor-relative verification of an unsigned local bundle."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from origami.output.artifacts import BUNDLE_LOCK

ARTIFACT_NAMES = frozenset({"findings.json", "params.txt", "urls.txt", "js_endpoints.txt",
                            "graph.html", "graph.dot", "report.html"})
MAX_MANIFEST_BYTES = 64 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class InvalidBundle(ValueError):
    """Controlled diagnostics never contain manifest values or file contents."""


class _UnsafeFile(ValueError):
    pass


class _ChangedFile(ValueError):
    pass


class _ReadLimit(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidBundle(message)


def _object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise InvalidBundle("non-finite JSON number")


def _stamp(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _named_stat(root: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=root, follow_symlinks=False)


def _lock_present(root: int) -> bool:
    try:
        _named_stat(root, BUNDLE_LOCK)
    except FileNotFoundError:
        return False
    return True  # any entry at the lock name blocks verification; never remove it


def _read_file(root: int, name: str, cap: int, *, capture: bool = False,
               budget: list[int] | None = None) -> tuple:
    if cap < 0:
        raise _ReadLimit()
    initial = _named_stat(root, name)
    if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
        raise _UnsafeFile()
    # Nonblocking + no-follow also protects the interval between stat and open.
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if _stamp(before) != _stamp(initial):
            raise _ChangedFile()
        if before.st_size > cap:
            raise _ReadLimit()
        digest, total, chunks = hashlib.sha256(), 0, []
        while chunk := stream.read(min(65536, cap - total + 1)):
            total += len(chunk)
            if budget is not None:
                budget[0] -= len(chunk)  # failed/changed reads still consume the shared budget
            if total > cap:
                raise _ReadLimit()
            digest.update(chunk)
            if capture:
                chunks.append(chunk)
        if _stamp(os.fstat(stream.fileno())) != _stamp(before):
            raise _ChangedFile()
    try:
        if _stamp(_named_stat(root, name)) != _stamp(before):
            raise _ChangedFile()
    except FileNotFoundError:
        raise _ChangedFile() from None
    return b"".join(chunks), total, digest.hexdigest(), _stamp(before)


def _manifest(raw: bytes) -> dict:
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, InvalidBundle):
            raise
        raise InvalidBundle("invalid UTF-8 JSON manifest") from None
    _require(isinstance(data, dict), "manifest must be an object")
    _require(type(data.get("schema_version")) is int and data["schema_version"] == 1,
             "unsupported manifest schema")
    _require(type(data.get("completed")) is bool, "invalid export completion flag")
    files, integrity, errors = data.get("files"), data.get("integrity"), data.get("errors")
    _require(isinstance(files, dict) and isinstance(integrity, dict) and isinstance(errors, dict),
             "manifest lacks supported files, integrity or errors objects")
    _require(set(files) <= ARTIFACT_NAMES, "manifest contains unexpected artifact names")
    _require(all(value == "written" for value in files.values()), "unsupported artifact state")
    _require(set(integrity) == set(files), "artifact and integrity entries differ")
    _require(set(errors) <= ARTIFACT_NAMES | {"graph", "export"}
             and all(isinstance(value, str) for value in errors.values()), "invalid export errors")
    _require(not data["completed"] or (not errors and set(files) == ARTIFACT_NAMES),
             "completed export must declare all artifacts without errors")
    for entry in integrity.values():
        _require(isinstance(entry, dict), "integrity entry must be an object")
        _require(type(entry.get("bytes")) is int and entry["bytes"] >= 0, "invalid artifact byte count")
        _require(isinstance(entry.get("sha256"), str) and bool(_SHA256.fullmatch(entry["sha256"])),
                 "invalid artifact SHA-256")
    return data


def verify_bundle(directory: Path) -> dict:
    """Check consistency with declared digests, not authenticity or scan coverage.

    Single-link regular files only. Lock, descriptor/path metadata and manifest
    replacement checks detect observable concurrent changes. This is not an
    atomic filesystem snapshot, and cannot prevent changes after verification.
    """
    _require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
             and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd,
             "platform lacks safe descriptor-relative verification")
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root_identity = os.fstat(root)
        report: dict = {
            "verification_schema_version": 1, "verified": False, "state": "busy",
            "interpretation": "consistency_with_unsigned_manifest_only",
            "scan_state": "not_evaluated", "export_completed": None,
            "checked_file_count": 0, "artifact_bytes_read": 0, "manifest_sha256": None, "files": [],
            "limits": {"manifest_bytes": MAX_MANIFEST_BYTES, "file_bytes": MAX_FILE_BYTES,
                       "total_file_bytes": MAX_TOTAL_BYTES},
            "warnings": ["Hashes are not authenticity, scan coverage or vulnerability proof.",
                         "Not an atomic filesystem snapshot; later changes are not covered.",
                         "Only declared artifacts are checked; undeclared extra files are ignored."],
        }
        if _lock_present(root):
            return report
        try:
            raw, _, manifest_digest, manifest_stamp = _read_file(root, "manifest.json", MAX_MANIFEST_BYTES,
                                                                capture=True)
        except _ReadLimit:
            raise InvalidBundle("manifest exceeds read limit") from None
        except _UnsafeFile:
            raise InvalidBundle("manifest must be a single-link regular file") from None
        except _ChangedFile:
            report["state"] = "changed_during_verification"
            return report
        manifest = _manifest(raw)
        report.update(export_completed=manifest["completed"], manifest_sha256=manifest_digest)
        snapshots = {"manifest.json": manifest_stamp}
        budget = [MAX_TOTAL_BYTES]
        for name in sorted(manifest["files"]):
            expected = manifest["integrity"][name]
            row = {"name": name, "expected_bytes": expected["bytes"], "expected_sha256": expected["sha256"]}
            try:
                _, size, digest, stamp = _read_file(root, name, min(MAX_FILE_BYTES, budget[0]), budget=budget)
                snapshots[name] = stamp
                report["checked_file_count"] += 1
                row.update(actual_bytes=size, actual_sha256=digest,
                           state="verified" if size == expected["bytes"] and digest == expected["sha256"] else "mismatch")
            except FileNotFoundError:
                row["state"] = "missing"
            except _UnsafeFile:
                row["state"] = "unsafe_file"
            except _ReadLimit:
                row["state"] = "read_limit_exceeded"
            except _ChangedFile:
                row["state"] = "changed_during_verification"
            except OSError:
                row["state"] = "unreadable"
            report["files"].append(row)
        report["artifact_bytes_read"] = MAX_TOTAL_BYTES - budget[0]
        report["state"] = ("incomplete_export" if not manifest["completed"] else
                           "verified" if all(row["state"] == "verified" for row in report["files"])
                           else "verification_failed")
        # Recheck every sampled path after all reads; an earlier file can change
        # while later files are hashed, even if each individual read was stable.
        try:
            final_root = os.stat(directory, follow_symlinks=False)
            unchanged = ((final_root.st_dev, final_root.st_ino) == (root_identity.st_dev, root_identity.st_ino)
                         and all(_stamp(_named_stat(root, name)) == stamp for name, stamp in snapshots.items()))
        except OSError:
            unchanged = False
        if _lock_present(root):
            report["state"] = "busy"
        elif not unchanged:
            report["state"] = "changed_during_verification"
        report["verified"] = report["state"] == "verified"
        return report
    finally:
        os.close(root)
