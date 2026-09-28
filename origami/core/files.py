"""Private local files and atomic replacement for evidence artifacts."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import TextIO


class OutputWriteError(OSError):
    """An essential live output failed; discovery must stop instead of swallowing it."""


def private_directory(path: Path) -> None:
    """Create missing directories privately; never chmod existing ancestors."""
    if path.is_dir():
        return
    if path.parent != path:
        private_directory(path.parent)
    path.mkdir(mode=0o700, exist_ok=True)


def private_file(path: Path, *, exclusive: bool = False) -> int:
    """Open a regular private file without following a final symlink."""
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    if exclusive:
        flags |= os.O_EXCL
    if path.is_symlink():
        raise OSError("refusing a symlink output")
    fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("output must be a regular file")
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        return fd
    except BaseException:
        os.close(fd)
        raise


def new_private_stream(path: Path) -> TextIO:
    """JSONL streams use a new file, so an old run is never silently truncated."""
    return os.fdopen(private_file(path, exclusive=True), "w", encoding="utf-8")


def atomic_write(path: str | Path, text: str) -> None:
    """UTF-8 replacement; failed writes preserve the previous file.

    Parent creation is the caller's decision. Replacement is atomic on the same
    filesystem; this is not a promise of directory-entry durability after power loss.
    """
    path = Path(path)
    if path.is_symlink():
        raise OSError("refusing a symlink output")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
