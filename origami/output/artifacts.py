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
    files, errors = {}, {}
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
            if name == "graph":
                files.update({"graph.html": "written", "graph.dot": "written"})
            else:
                files[name] = "written"
        except (OSError, ValueError, RecursionError) as exc:
            errors[name] = type(exc).__name__
    manifest = {"schema_version": 1, "completed": not errors,
                "files": files, "errors": errors,
                "note": "Only files marked written belong to this export; other files may be from older runs."}
    atomic_write(d / "manifest.json", json.dumps(manifest, indent=2))

    return {"dir": str(d), "findings": len(result.findings),
            "params": len(params), "urls": len(urls), "js_endpoints": len(paths),
            "hidden": n_hidden or 0, "errors": errors}
