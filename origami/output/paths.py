"""Read-only collision checks for planned local output files."""

from __future__ import annotations

from pathlib import Path


def check_output_paths(outputs: list[tuple[str, Path]], inputs: list[Path]) -> None:
    """Reject pathname, symlink and existing inode aliases before opening outputs.

    This is preflight validation, not a defense against concurrent filesystem
    mutation. Callers must enumerate effective filenames, including sidecars.
    """
    identities: dict[Path, tuple[int, int] | None] = {}

    def resolved(path: Path) -> Path:
        try:
            path = path.resolve()
        except RuntimeError:
            raise ValueError("cannot resolve output/input path safely") from None
        if path not in identities:
            try:
                info = path.stat()
                identities[path] = info.st_dev, info.st_ino
            except FileNotFoundError:
                identities[path] = None
        return path

    protected = [resolved(path) for path in inputs]
    planned: list[Path] = []
    for label, path in outputs:
        dest = resolved(path)
        for other in (*protected, *planned):
            if (dest == other or dest in other.parents or other in dest.parents
                    or (identities[dest] is not None and identities[dest] == identities[other])):
                raise ValueError(f"output path collision involving {label}; choose separate destinations")
        planned.append(dest)
