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

from pathlib import Path

from origami.output import graph, html_report, json_report


def _write_lines(path: Path, items) -> int:
    items = sorted(set(items))
    path.write_text("\n".join(items) + ("\n" if items else ""))
    return len(items)


def write_artifacts(result, out_dir: str | Path) -> dict:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)

    (d / "findings.json").write_text(json_report.dumps(result))
    n_params = _write_lines(d / "params.txt", result.profile.parameters)
    n_urls = _write_lines(d / "urls.txt", (f.url for f in result.findings))
    n_js = _write_lines(d / "js_endpoints.txt", result.harvested_paths)

    # Endpoint graph is part of the standard bundle (built only when edges were
    # collected; empty otherwise — still a valid, near-empty file).
    _, _, n_hidden = graph.write(result, str(d / "graph.html"))
    html_report.write(result, str(d / "report.html"), n_hidden=n_hidden)

    return {"dir": str(d), "findings": len(result.findings),
            "params": n_params, "urls": n_urls, "js_endpoints": n_js, "hidden": n_hidden}
