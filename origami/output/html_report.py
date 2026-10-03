"""Self-contained HTML report — shareable, browsable, filterable.

One file, embedded CSS + a tiny vanilla-JS live filter. No external assets, so
it opens anywhere. Surfaces the fingerprint (tech / WAF / folds), the harvested
parameter surface, and the findings with colour-coded status + semantic tags.
"""

from __future__ import annotations

import html
import time
from collections import Counter

from origami.core.files import atomic_write
from origami.output.cookie_summary import summarize_cookies
from origami.output.correlations import fingerprint_correlations, response_correlations
from origami.output.provenance import reference_provenance
from origami.output.response_groups import terminal_findings, terminal_rows

_CSS = """
:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--bd:#30363d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
header{padding:18px 24px;border-bottom:1px solid var(--bd);display:flex;gap:16px;align-items:baseline;flex-wrap:wrap}
h1{font-size:20px;margin:0;color:#e3b341}
.sub{color:var(--mut)}
.wrap{padding:20px 24px;max-width:1500px;margin:0 auto}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px 16px}
.card b{color:var(--mut);font-weight:400;margin-right:8px}
.card a{color:#79c0ff;text-decoration:none}.card .hidden{color:#f85149}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;margin:2px;font-size:12px}
.tech{background:#1f6f3f;color:#fff}.waf{background:#8b1a1a;color:#fff}
.fold{background:#1f6feb;color:#fff}.tag{background:#30363d;color:#c9d1d9}
.tag.disclosure{background:#8b1a1a;color:#fff}.tag.config{background:#9e6a03;color:#fff}
.tag.api{background:#1f6feb;color:#fff}.tag.auth{background:#6e40c9;color:#fff}
.tag.admin{background:#0e7490;color:#fff}.tag.source{background:#1f6f3f;color:#fff}
.tag.upload{background:#9e6a03;color:#fff}.tag.debug{background:#b91c1c;color:#fff}
.tag.secret{background:#b91c1c;color:#fff}.tag.leak{background:#a16207;color:#fff}
.tag.bypass{background:#15803d;color:#fff}.tag.param{background:#1f6f3f;color:#fff}
.tag.listing{background:#9e6a03;color:#fff}.tag.vhost{background:#0e7490;color:#fff}
input{background:var(--card);border:1px solid var(--bd);color:var(--fg);padding:8px 12px;border-radius:6px;width:340px;margin-bottom:12px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--bd);white-space:nowrap}
th{color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--bg);cursor:pointer;user-select:none}
th[data-sort]::after{content:attr(data-dir);color:#79c0ff;margin-left:4px}
td.path{white-space:normal;word-break:break-all}
td.path a{color:#79c0ff;text-decoration:none}
.s2{color:#3fb950}.s3{color:#39c5cf}.s4{color:#e3b341}.s5{color:#f85149}
.params{columns:4;font-size:13px;color:var(--mut)}
.params span{display:block}
"""

_JS = """
const table=document.getElementById('findings-table'),q=document.getElementById('q'),
 rows=[...table.querySelectorAll('tbody tr')];
q.addEventListener('input',()=>{const v=q.value.toLowerCase();
 rows.forEach(r=>r.style.display=r.textContent.toLowerCase().includes(v)?'':'none')});
// click a column header to sort (numeric for code/size/conf, text otherwise)
const tb=table.querySelector('tbody');
table.querySelectorAll('th[data-sort]').forEach((th,i)=>{let asc=true;
 th.addEventListener('click',()=>{const num=th.dataset.sort==='num';
  const trs=[...tb.querySelectorAll('tr')];
  trs.sort((a,b)=>{let x=a.children[i].textContent.trim(),y=b.children[i].textContent.trim();
   if(num){return (asc?1:-1)*((parseFloat(x)||0)-(parseFloat(y)||0));}
   return (asc?1:-1)*x.localeCompare(y);});
  asc=!asc;trs.forEach(r=>tb.appendChild(r));
  table.querySelectorAll('th[data-sort]').forEach(h=>h.dataset.dir='');
  th.dataset.dir=asc?'▼':'▲';});});
"""


def _scls(code: int) -> str:
    return f"s{code // 100}" if 100 <= code < 600 else "s4"


def render(result, n_hidden: int | None = None) -> str:
    p = result.profile
    e = html.escape
    observations = terminal_findings(result)
    presentation_rows, presentation_summary = terminal_rows(observations, view="HTML")
    cookie_summary = summarize_cookies(result)
    techs = "".join(f'<span class="badge tech">{e(t)} {s:.0f}</span>'
                    for t, s in p.tech_scores.items()) or '<span class="sub">none</span>'
    folds = "".join(f'<span class="badge fold">⌘ {e(f)}</span>' for f in sorted(result.folds))
    state = "failed" if result.error else "finished" if result.completed else "partial"
    retention = (f"{len(result.reported_observations)} reported observations · {len(presentation_rows)} presentation rows"
                 if result.report_events_tracked else "reported-observation retention unavailable")
    cards = [f'<div class="card"><b>execution</b>{state} · coverage not established</div>', f'<div class="card"><b>tech</b>{techs}</div>']
    cards.append(f'<div class="card"><b>retention</b>{retention}</div>')
    if result.cookie_observations_tracked:
        cards.append(f'<div class="card"><b>Set-Cookie headers</b>'
                     f'{cookie_summary["distinct_name_count"]} names · '
                     f'{cookie_summary["responses_with_set_cookie"]} captured responses</div>')
    if result.endpoint_hints:
        route_templates = sum(bool(h.get("template")) for h in result.endpoint_hints)
        cards.append(f'<div class="card"><b>client routes</b>{len(result.endpoint_hints)} hints · '
                     f'{route_templates} runtime templates</div>')
    if p.waf:
        cards.append(f'<div class="card"><b>WAF</b><span class="badge waf">{e(p.waf)}</span></div>')
    if p.enabled_extensions:
        cards.append(f'<div class="card"><b>extensions</b>{e(" ".join(sorted(p.enabled_extensions)))}</div>')
    if folds:
        cards.append(f'<div class="card"><b>folds</b>{folds}</div>')
    if p.pushbacks if hasattr(p, "pushbacks") else result.pushbacks:
        cards.append(f'<div class="card"><b>throttling</b>{result.pushbacks} backoff</div>')
    if n_hidden is not None:
        cards.append(f'<div class="card"><b>topology</b>'
                     f'<a href="graph.html">endpoint graph →</a> '
                     f'<span class="hidden">{n_hidden} hidden</span></div>')
    codes = Counter(f.status for f in observations)
    if codes:
        summary = "  ".join(f"{c}×{n}" for c, n in sorted(codes.items()))
        cards.append(f'<div class="card"><b>status</b>{e(summary)}</div>')

    rows = []
    for f in presentation_rows:
        tags = "".join(f'<span class="badge tag {e(t)}">{e(t)}</span>' for t in getattr(f, "tags", []))
        path = e(f.url)
        # link only http(s) URLs — a server-controlled javascript:/data: URL must
        # never become a clickable link in a shared report (defense-in-depth).
        cell = (f'<a href="{path}" target="_blank" rel="noreferrer">{path}</a>'
                if f.url.startswith(("http://", "https://")) else path)
        if f.note:
            cell += f'<details><summary>Evidence notes</summary><p>{e(f.note)}</p></details>'
        rows.append(
            f'<tr><td class="{_scls(f.status)}">{f.status}</td>'
            f'<td>{f.length}</td><td class="sub">{e(f.origin)}</td>'
            f'<td>{f.confidence:.2f}</td><td>{tags}</td>'
            f'<td class="path">{cell}</td></tr>')

    params = "".join(f"<span>{e(x)}</span>" for x in sorted(p.parameters))
    params_block = (f'<h2>Parameters ({len(p.parameters)})</h2><div class="params">{params}</div>'
                    if p.parameters else "")
    route_rows = "".join(
        f'<tr><td>{e(str(h.get("method", "UNKNOWN")))}</td>'
        f'<td class="path">{e(str(h.get("route", "")))}</td>'
        f'<td>{"yes" if h.get("template") else "no"}</td>'
        f'<td>{e(", ".join(h.get("path_params", [])))}</td>'
        f'<td>{e(", ".join(h.get("query_params", [])))}</td>'
        f'<td>{e(", ".join(h.get("body_keys", [])))}</td>'
        f'<td>{e(", ".join(h.get("header_names", [])))}</td>'
        f'<td>{e(str(h.get("client", "")))}</td>'
        f'<td class="path">{e(str(h.get("source", "")))}</td></tr>'
        for h in result.endpoint_hints)
    routes_block = (
        f'<details open><summary>Passive client routes ({len(result.endpoint_hints)})</summary>'
        '<p class="sub">Extracted from HTML/JavaScript without replaying state-changing methods. '
        'Runtime values remain explicit templates; UNKNOWN means the wrapper did not expose a method.</p>'
        '<table><thead><tr><th>method</th><th>route</th><th>template</th>'
        '<th>path params</th><th>query params</th><th>body keys</th><th>header names</th>'
        '<th>client</th><th>source</th></tr></thead>'
        f'<tbody>{route_rows}</tbody></table></details>' if route_rows else "")
    observation_details = ""
    if result.report_events_tracked:
        event_rows = "".join(
            f'<tr><td>{e(str(row["status"]))}</td><td>{e(str(row["length"]))}</td>'
            f'<td class="path">{e(row["url"])}</td><td><pre>{e(row.get("note", ""))}</pre></td></tr>'
            for row in result.reported_observations)
        observation_details = (
            f'<details><summary>Reported observations — current process ({len(result.reported_observations)})</summary>'
            '<p class="sub">Accepted events at emission, before presentation grouping and later note updates. '
            'This is not every HTTP request or raw response.</p>'
            '<table><thead><tr><th>code</th><th>size</th><th>URL</th><th>original note</th></tr></thead>'
            f'<tbody>{event_rows}</tbody></table></details>')
    fingerprint_rows = "".join(
        f'<tr><td>{e(row["tech"])}</td><td>{e(row["path_prefix"] or "unknown")}</td>'
        f'<td>{e(", ".join(row["signal_types"]) or "unknown")}</td>'
        f'<td>{e(", ".join(row["signal_channels"]) or "unknown")} '
        f'({e(row["channel_support"])})</td><td>{e(str(row["evidence_indices"]))}</td></tr>'
        for row in fingerprint_correlations(p))
    fingerprints = (
        '<details><summary>Fingerprint evidence correlations</summary>'
        '<p class="sub">Raw signal types and acquisition channels are distinct: cookie/header '
        'share response headers; body/error-page share response body. Rotating cookie values '
        'do not add cookie names. Independent corroboration is not established; host scores '
        'are heuristics, not probabilities.</p>'
        '<table><thead><tr><th>technology</th><th>prefix</th><th>signal types</th>'
        '<th>channels</th><th>evidence indices (JSON)</th></tr></thead>'
        f'<tbody>{fingerprint_rows}</tbody></table></details>' if fingerprint_rows else '')
    response_details = "".join(
        f'<details><summary>{group["status"]} · {group["count"]} observations · '
        f'{e(group["basis"])}</summary><ul>'
        + "".join(f'<li>{e(url)}</li>' for url in group["urls"])
        + '</ul></details>' for group in response_correlations(result))
    correlations = (f'<details><summary>Response presentation groups</summary>'
                    f'<p class="sub">Similarity of recorded responses only; all member URLs '
                    f'are listed. This does not prove resource identity or a vulnerability.</p>'
                    f'{response_details}</details>' if response_details else '')
    provenance = reference_provenance(result)
    reference_details = "".join(
        '<li>' + ' → '.join(e(url) for url in chain["urls"])
        + f' · edge indices: {e(str(chain["edge_indices"]))}'
        + f' · accepted observation refs: {e(str(chain["endpoint_observation_refs"]))}</li>'
        for chain in provenance["chain_examples"])
    references = (
        '<details><summary>Recorded reference chains (offline)</summary>'
        '<p class="sub">Bounded examples from existing edges, not execution or exploitation. '
        'An accepted response does not prove resource existence. Relative references without '
        'document context are unresolved; legacy edges may lack queries. Full indexed edges '
        'and node observations are available in JSON.</p>'
        f'<p class="sub">Unprocessed edges: {provenance["unprocessed_edge_count"]}; '
        f'unresolved indices: {e(str(provenance["unresolved_edge_indices"]))}; '
        f'nodes without examples: {provenance["nodes_without_chain_example"]} '
        '(includes starting nodes).</p>'
        f'<ul>{reference_details}</ul></details>' if result.edges else '')
    cookie_rows = "".join(
        f'<tr><td class="path">{e(row["url"])}</td><td>{row["status"]}</td>'
        f'<td>{e(str(row["cookies"]))}</td><td>{row["response_count"]}</td>'
        f'<td>{row["unparsed_header_count"]}</td></tr>' for row in result.cookie_observations)
    inventory_rows = "".join(
        f'<tr><td class="path">{e(row["origin"] or "unknown")}</td><td>{e(row["name"])}</td>'
        f'<td>{row["responses_with_name"]}</td><td>{e(str(row["statuses"]))}</td>'
        f'<td>{len(row["metadata_variants"])}</td>'
        f'<td>{e(str(row["observation_indices"]))}</td></tr>' for row in cookie_summary["inventory"])
    cookie_details = (
        '<details><summary>Observed Set-Cookie headers (values omitted)</summary>'
        '<p class="sub">Current-process response headers, including redirects and responses '
        'not accepted as findings. Cookie names and selected attributes only; cookie values, '
        'browser acceptance and authentication state are not inferred. Repeated per-URL '
        'metadata is counted, not discarded.</p>'
        f'<p class="sub">{cookie_summary["set_cookie_field_count"]} captured fields; '
        f'{cookie_summary["unparsed_field_count"]} unparsed. Inventory separates origins and '
        'names; multiple selected-metadata variants are not a security verdict. Domain/Path '
        'were not captured, so these entries are not cookie-jar identities.</p>'
        '<table><thead><tr><th>origin</th><th>name</th><th>responses with name</th>'
        '<th>codes</th><th>metadata variants</th><th>cookie observation indices (JSON)</th></tr></thead>'
        f'<tbody>{inventory_rows}</tbody></table>'
        '<details><summary>All per-URL cookie observations</summary>'
        '<table><thead><tr><th>URL</th><th>code</th><th>cookie metadata</th>'
        '<th>responses</th><th>unparsed fields</th></tr></thead>'
        f'<tbody>{cookie_rows}</tbody></table></details></details>' if cookie_rows else '')
    when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Origami — {e(p.host)}</title><style>{_CSS}</style></head><body>
<header><h1>Origami</h1><span class="sub">{e(p.base_url)}</span>
<span class="sub">· {when} · {len(observations)} observations · {len(presentation_rows)} presentation rows · {result.requests_made} requests</span></header>
<div class="wrap"><div class="cards">{''.join(cards)}</div>
{params_block}
{routes_block}
<h2>Findings ({len(observations)}) · {len(presentation_rows)} presentation rows</h2>
<p class="sub">Score is an uncalibrated heuristic, not a measured probability.
HTTP success does not confirm a vulnerability; denial does not establish path existence.
Grouping does not establish identical bodies. Recorded report events are preserved in JSON
when retention is available; they do not include every request or raw HTTP bodies.</p>
<p class="sub">{e(presentation_summary)}</p>
<label for="q">Filter findings</label>
<input id="q" placeholder="filter findings…" autofocus>
<table id="findings-table"><thead><tr><th data-sort="num">code</th><th data-sort="num">size</th>
<th data-sort="str">src</th><th data-sort="num">score</th><th data-sort="str">tags</th>
<th data-sort="str">path</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>{observation_details}{fingerprints}{correlations}{references}{cookie_details}</div>
<script>{_JS}</script></body></html>"""


def write(result, path: str, n_hidden: int | None = None) -> None:
    atomic_write(path, render(result, n_hidden=n_hidden))
