"""Scan diffing — "what changed since the last scan of this host".

Origami's memory DB stores a per-run snapshot of every finding. `--diff` compares
the current scan against the most recent prior run and reports what **appeared**,
**disappeared**, or **changed** (status or size). This turns Origami from a one-shot
buster into a recon-over-time / attack-surface monitor — a moat straight out of the
memory architecture no stateless dir-buster has.

`compute()` is pure (dict + findings → structured diff) and unit-tested; `render()`
formats it for the terminal. Status transitions are graded: 403/404 → 2xx (a path
that just opened up) is the headline, called out first.
"""

from __future__ import annotations

_OPENED_FROM = {401, 403, 404, 500, 502, 503}   # was-closed statuses
_ACCESSIBLE = range(200, 300)


def _path(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).path or "/"


def compute(prior: dict, findings) -> dict:
    """Diff a prior snapshot ({path: (status, length)}) against current findings.

    Returns {new, gone, changed, opened} where each is a list of dicts. `opened`
    is the high-signal subset of `changed`: a path whose status went from a
    closed/blocked code to 2xx (e.g. 403 → 200) — surfaced separately because it's
    the thing a monitor most wants to know."""
    cur: dict[str, tuple[int, int]] = {}
    meta: dict[str, object] = {}
    for f in findings:
        p = _path(f.url)
        cur[p] = (f.status, f.length)
        meta[p] = f
    new, gone, changed, opened = [], [], [], []
    for p, (status, length) in sorted(cur.items()):
        if p not in prior:
            new.append({"path": p, "status": status, "length": length})
        else:
            ostatus, olength = prior[p]
            if status != ostatus or length != olength:
                entry = {"path": p, "status": status, "was_status": ostatus,
                         "length": length, "was_length": olength}
                changed.append(entry)
                if ostatus in _OPENED_FROM and status in _ACCESSIBLE:
                    opened.append(entry)
    for p, (ostatus, olength) in sorted(prior.items()):
        if p not in cur:
            gone.append({"path": p, "was_status": ostatus, "was_length": olength})
    return {"new": new, "gone": gone, "changed": changed, "opened": opened}


def is_empty(d: dict) -> bool:
    return not (d["new"] or d["gone"] or d["changed"])


def render(d: dict, host: str, prior_ts: float | None = None) -> str:
    """Human-readable diff summary. Empty diff → a one-line 'no change'."""
    import datetime
    since = ""
    if prior_ts:
        try:
            since = " since " + datetime.datetime.fromtimestamp(prior_ts).strftime("%Y-%m-%d %H:%M")
        except (ValueError, OSError, OverflowError):
            since = ""
    if is_empty(d):
        return f"diff [{host}]: no change{since} ({len(d.get('new', []))} new)"
    lines = [f"diff [{host}]{since}:  +{len(d['new'])} new  -{len(d['gone'])} gone  "
             f"~{len(d['changed'])} changed"]
    if d["opened"]:
        lines.append(f"  ⚠ {len(d['opened'])} newly ACCESSIBLE (was blocked):")
        for e in d["opened"]:
            lines.append(f"    {e['was_status']}→{e['status']}  {e['path']}")
    for e in d["new"]:
        lines.append(f"  + {e['status']:>3}  {e['path']}  ({e['length']}B)")
    for e in d["changed"]:
        if e in d["opened"]:
            continue                     # already shown above
        lines.append(f"  ~ {e['was_status']}→{e['status']}  {e['path']}  "
                     f"({e['was_length']}→{e['length']}B)")
    for e in d["gone"]:
        lines.append(f"  - {e['was_status']:>3}  {e['path']}  (gone)")
    return "\n".join(lines)
