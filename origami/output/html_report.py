"""Self-contained HTML report — shareable, browsable, filterable.

One file, embedded CSS + a tiny vanilla-JS live filter. No external assets, so
it opens anywhere. Surfaces the fingerprint (tech / WAF / folds), the harvested
parameter surface, and the findings with colour-coded status + semantic tags.
"""

from __future__ import annotations

import html
import time
from collections import Counter
from urllib.parse import urlparse

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
const q=document.getElementById('q'),rows=[...document.querySelectorAll('tbody tr')];
q.addEventListener('input',()=>{const v=q.value.toLowerCase();
 rows.forEach(r=>r.style.display=r.textContent.toLowerCase().includes(v)?'':'none')});
// click a column header to sort (numeric for code/size/conf, text otherwise)
const tb=document.querySelector('tbody');
document.querySelectorAll('th[data-sort]').forEach((th,i)=>{let asc=true;
 th.addEventListener('click',()=>{const num=th.dataset.sort==='num';
  const trs=[...tb.querySelectorAll('tr')];
  trs.sort((a,b)=>{let x=a.children[i].textContent.trim(),y=b.children[i].textContent.trim();
   if(num){return (asc?1:-1)*((parseFloat(x)||0)-(parseFloat(y)||0));}
   return (asc?1:-1)*x.localeCompare(y);});
  asc=!asc;trs.forEach(r=>tb.appendChild(r));
  document.querySelectorAll('th[data-sort]').forEach(h=>h.dataset.dir='');
  th.dataset.dir=asc?'▼':'▲';});});
"""


def _scls(code: int) -> str:
    return f"s{code // 100}" if 100 <= code < 600 else "s4"


def render(result, n_hidden: int | None = None) -> str:
    p = result.profile
    e = html.escape
    techs = "".join(f'<span class="badge tech">{e(t)} {s:.0f}</span>'
                    for t, s in p.tech_scores.items()) or '<span class="sub">none</span>'
    folds = "".join(f'<span class="badge fold">⌘ {e(f)}</span>' for f in sorted(result.folds))
    cards = [f'<div class="card"><b>tech</b>{techs}</div>']
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
    codes = Counter(f.status for f in result.findings)
    if codes:
        summary = "  ".join(f"{c}×{n}" for c, n in sorted(codes.items()))
        cards.append(f'<div class="card"><b>status</b>{e(summary)}</div>')

    rows = []
    for f in result.findings:
        tags = "".join(f'<span class="badge tag {e(t)}">{e(t)}</span>' for t in getattr(f, "tags", []))
        path = e(f.url)
        rows.append(
            f'<tr><td class="{_scls(f.status)}">{f.status}</td>'
            f'<td>{f.length}</td><td class="sub">{e(f.origin)}</td>'
            f'<td>{f.confidence:.2f}</td><td>{tags}</td>'
            f'<td class="path"><a href="{path}" target="_blank" rel="noreferrer">{path}</a></td></tr>')

    params = "".join(f"<span>{e(x)}</span>" for x in sorted(p.parameters))
    params_block = (f'<h2>Parameters ({len(p.parameters)})</h2><div class="params">{params}</div>'
                    if p.parameters else "")
    when = time.strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Origami — {e(p.host)}</title><style>{_CSS}</style></head><body>
<header><h1>Origami</h1><span class="sub">{e(p.base_url)}</span>
<span class="sub">· {when} · {len(result.findings)} findings · {result.requests_made} requests</span></header>
<div class="wrap"><div class="cards">{''.join(cards)}</div>
{params_block}
<h2>Findings ({len(result.findings)})</h2>
<input id="q" placeholder="filter findings…" autofocus>
<table><thead><tr><th data-sort="num">code</th><th data-sort="num">size</th>
<th data-sort="str">src</th><th data-sort="num">conf</th><th data-sort="str">tags</th>
<th data-sort="str">path</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
<script>{_JS}</script></body></html>"""


def write(result, path: str, n_hidden: int | None = None) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(result, n_hidden=n_hidden))
