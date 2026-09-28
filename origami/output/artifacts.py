"""Scan artifacts — write pentest-ready files to a directory.

  findings.json    — full structured report
  params.txt       — harvested parameter names, one per line (drop-in fuzzing list)
  urls.txt         — confirmed URLs, one per line (feed to the next tool)
  js_endpoints.txt — same-host paths harvested from HTML/JS, one per line, REGARDLESS
                     of whether firing them ever surfaced a distinct finding — an
                     auth-gated API routinely answers every real and fake path
                     identically, so none of them become a `finding`, but the
                     endpoint NAMES are still the point: re-test once you have a
                     session.

The point: Origami's recon becomes direct input for the next step (param
fuzzing, manual review) instead of dying in the terminal scrollback.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from origami.core.files import atomic_write, private_directory
from origami.output import graph, html_report, json_report


def _write_lines(path: Path, items) -> int:
    items = sorted(set(items))
    atomic_write(path, "\n".join(items) + ("\n" if items else ""))
    return len(items)


def write_artifacts(result, out_dir: str | Path) -> dict:
    d = Path(out_dir)
    private_directory(d)
    # Invalidate the previous success marker BEFORE replacing any artifact. A
    # crash or failed final manifest cannot authenticate a mixed-generation set.
    pending = {"schema_version": 1, "completed": False, "files": {}, "integrity": {},
               "errors": {"export": "in_progress"},
               "note": "Export has not committed; do not treat existing files as a complete bundle."}
    atomic_write(d / "manifest.json", json.dumps(pending, indent=2))
    files, errors, integrity = {}, {}, {}
    params = set(result.profile.parameters)
    urls = {f.url for f in result.findings}
    paths = set(result.harvested_paths)
    n_hidden = None

    def write_graph():
        nonlocal n_hidden
        _, _, n_hidden = graph.write(result, str(d / "graph.html"))

    writers = {
        "findings.json": lambda: atomic_write(d / "findings.json", json_report.dumps(result)),
        "params.txt": lambda: _write_lines(d / "params.txt", params),
        "urls.txt": lambda: _write_lines(d / "urls.txt", urls),
        "js_endpoints.txt": lambda: _write_lines(d / "js_endpoints.txt", paths),
        "graph": write_graph,
        "report.html": lambda: html_report.write(result, str(d / "report.html"), n_hidden=n_hidden),
    }
    for name, writer in writers.items():
        try:
            writer()
            names = ("graph.html", "graph.dot") if name == "graph" else (name,)
            for written in names:
                digest = hashlib.sha256()
                size = 0
                with (d / written).open("rb") as stream:
                    while chunk := stream.read(65536):
                        digest.update(chunk)
                        size += len(chunk)
                integrity[written] = {"sha256": digest.hexdigest(), "bytes": size}
                files[written] = "written"
        except (OSError, ValueError, RecursionError) as exc:
            errors[name] = type(exc).__name__
    manifest = {"schema_version": 1, "completed": not errors,
                "files": files, "errors": errors, "integrity": integrity,
                "note": "Only files marked written belong to this export; other files may be from older runs."}
    atomic_write(d / "manifest.json", json.dumps(manifest, indent=2))

    return {"dir": str(d), "findings": len(result.findings),
            "params": len(params), "urls": len(urls), "js_endpoints": len(paths),
            "hidden": n_hidden or 0, "errors": errors}
