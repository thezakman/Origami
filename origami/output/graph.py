"""Endpoint graph — provenance + topology of what was discovered.

Origami harvests references (JS, robots/sitemap, OpenAPI/JSON:API) and folds them
as seeds; this turns the *who-references-whom* into a graph so a pentester can
see the app's shape and, crucially, the **orphan/hidden endpoints** — paths only
referenced from JavaScript or an API spec, never linked from a page (often the
interesting ones).

Output is self-contained (one HTML file, inline SVG + tiny vanilla JS, no CDN),
mirroring output/html_report.py. A Graphviz `.dot` is emitted alongside for
import into Gephi/cytoscape. Opt-in via `--graph`.
"""

from __future__ import annotations

import html
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse

from origami.core.scope import same_host

# A source ending in one of these (or whose name looks like an API spec) is a
# "machine" reference — a target reached ONLY through these is hidden/orphan.
_MACHINE_EXT = (".js", ".mjs", ".map")
_SPEC_HINT = ("swagger", "openapi", "api-docs", "jsonapi")

# Cap edges so a chatty SPA can't produce a multi-MB graph; findings are always
# kept, only the reference fan-out is bounded.
MAX_EDGES = 4000


@dataclass
class Node:
    path: str
    status: int | None = None      # from a finding; None = referenced-but-not-confirmed
    origin: str = "referenced"
    tags: list[str] = field(default_factory=list)
    hidden: bool = False           # referenced only by JS/spec — not page-linked


@dataclass
class GraphModel:
    nodes: dict[str, Node]
    edges: list[tuple[str, str]]   # normalized, deduped, no self-loops


def _pathkey(s: str) -> str:
    """Normalize any reference (full URL or path) to a root-absolute path key."""
    if s.startswith(("http://", "https://")):
        s = urlparse(s).path
    s = (s or "/").split("?")[0].split("#")[0]
    return "/" + s.lstrip("/") if s.strip("/") else "/"


def _is_machine(src: str) -> bool:
    low = src.lower()
    return low.endswith(_MACHINE_EXT) or any(h in low for h in _SPEC_HINT)


def _in_scope(ref: str, host: str) -> bool:
    """Keep relative/root-absolute refs and same-host absolute URLs; drop a
    cross-host reference (else _pathkey would collapse cdn1/x and cdn2/x into
    one wrong node)."""
    if ref.startswith(("http://", "https://")):
        return same_host(urlparse(ref).netloc, host)
    return True


def build(result) -> GraphModel:
    """Assemble the graph from a ScanResult's findings + provenance edges."""
    host = result.profile.host
    nodes: dict[str, Node] = {}
    for f in result.findings:
        k = _pathkey(f.url)
        nodes[k] = Node(k, status=f.status, origin=f.origin,
                        tags=list(getattr(f, "tags", [])))

    edges: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    incoming: dict[str, list[str]] = defaultdict(list)
    for s, d in getattr(result, "edges", []):
        if len(edges) >= MAX_EDGES:
            break
        if not (_in_scope(s, host) and _in_scope(d, host)):
            continue
        sk, dk = _pathkey(s), _pathkey(d)
        if sk == dk:
            continue
        nodes.setdefault(sk, Node(sk))
        nodes.setdefault(dk, Node(dk))
        incoming[dk].append(sk)
        if (sk, dk) not in seen:
            seen.add((sk, dk))
            edges.append((sk, dk))

    # Orphan/hidden: every incoming reference is from a machine source (JS/spec).
    for dk, srcs in incoming.items():
        if srcs and all(_is_machine(s) for s in srcs):
            nodes[dk].hidden = True
    return GraphModel(nodes, edges)


def orphans(m: GraphModel) -> list[str]:
    return sorted(k for k, n in m.nodes.items() if n.hidden)


# ---- Graphviz export ----------------------------------------------------------

def _dot_color(status: int | None) -> str:
    if status is None:
        return "#6e7681"
    if 200 <= status < 300:
        return "#238636"
    if 300 <= status < 400:
        return "#1f6feb"
    if status in (401, 403):
        return "#9e6a03"
    return "#8b1a1a"


def _dq(s: str) -> str:
    """Escape a string for a DOT double-quoted id/label."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def to_dot(m: GraphModel) -> str:
    out = ['digraph endpoints {', '  rankdir=LR;',
           '  node [style=filled, fontname="monospace", fontcolor="#ffffff"];']
    for k in sorted(m.nodes):
        n = m.nodes[k]
        label = k.rstrip("/").rsplit("/", 1)[-1] or "/"
        ring = ', penwidth=2, color="#f85149"' if n.hidden else ''
        out.append(f'  "{_dq(k)}" [label="{_dq(label)}", fillcolor="{_dot_color(n.status)}"{ring}];')
    for s, d in m.edges:
        out.append(f'  "{_dq(s)}" -> "{_dq(d)}";')
    out.append('}')
    return "\n".join(out)


# ---- self-contained HTML (inline SVG) ----------------------------------------

_COL_W = 210
_ROW_H = 24
_MARGIN = 30


def _svg_color(status: int | None) -> str:
    if status is None:
        return "#6e7681"
    if 200 <= status < 300:
        return "#3fb950"
    if 300 <= status < 400:
        return "#39c5cf"
    if status in (401, 403):
        return "#e3b341"
    return "#f85149"


def _tree(m: GraphModel):
    """Parent (nearest existing ancestor node, else root) + tidy layout.

    Returns (pos: path->(x,y), containment: set[(parent,child)], w, h)."""
    keys = set(m.nodes)
    keys.add("/")
    m.nodes.setdefault("/", Node("/"))

    def parent_of(k: str) -> str | None:
        if k == "/":
            return None
        segs = [s for s in k.strip("/").split("/") if s]
        for i in range(len(segs) - 1, 0, -1):
            for cand in ("/" + "/".join(segs[:i]) + "/", "/" + "/".join(segs[:i])):
                if cand in keys and cand != k:
                    return cand
        return "/"

    children: dict[str, list[str]] = defaultdict(list)
    containment: set[tuple[str, str]] = set()
    for k in keys:
        par = parent_of(k)
        if par is not None:
            children[par].append(k)
            containment.add((par, k))
    for v in children.values():
        v.sort()

    pos: dict[str, tuple[float, float]] = {}
    row = [0]

    def layout(k: str, depth: int) -> float:
        ch = children.get(k, [])
        if not ch:
            y = row[0]
            row[0] += 1
        else:
            ys = [layout(c, depth + 1) for c in ch]
            y = sum(ys) / len(ys)
        pos[k] = (_MARGIN + depth * _COL_W, _MARGIN + y * _ROW_H)
        return y

    layout("/", 0)
    max_x = max((x for x, _ in pos.values()), default=_MARGIN)
    w = int(max_x) + 180          # node x + room for the label
    h = _MARGIN * 2 + max(1, row[0]) * _ROW_H
    return pos, containment, w, h


def to_html(m: GraphModel, host: str) -> str:
    e = html.escape
    pos, containment, w, h = _tree(m)
    parts = []
    # containment edges (solid, faint) — the directory backbone
    for s, d in containment:
        if s in pos and d in pos:
            x1, y1 = pos[s]
            x2, y2 = pos[d]
            parts.append(f'<path d="M{x1:.0f},{y1:.0f} C{x1+_COL_W/2:.0f},{y1:.0f} '
                         f'{x2-_COL_W/2:.0f},{y2:.0f} {x2:.0f},{y2:.0f}" '
                         f'class="edge tree"/>')
    # reference edges (dashed, accent) — provenance not already shown as containment
    for s, d in m.edges:
        if (s, d) in containment or s not in pos or d not in pos:
            continue
        x1, y1 = pos[s]
        x2, y2 = pos[d]
        parts.append(f'<path d="M{x1:.0f},{y1:.0f} C{x1+_COL_W/2:.0f},{y1:.0f} '
                     f'{x2-_COL_W/2:.0f},{y2:.0f} {x2:.0f},{y2:.0f}" class="edge ref"/>')
    # nodes
    for k, (x, y) in pos.items():
        n = m.nodes[k]
        label = e(k.rstrip("/").rsplit("/", 1)[-1] or "/")
        title = e(f"{k}  [{n.status if n.status is not None else 'ref'}  {n.origin}"
                  f"{'  HIDDEN' if n.hidden else ''}]")
        ring = ' node-hidden' if n.hidden else ''
        parts.append(
            f'<g class="node{ring}"><title>{title}</title>'
            f'<circle cx="{x:.0f}" cy="{y:.0f}" r="5" fill="{_svg_color(n.status)}"/>'
            f'<text x="{x+9:.0f}" y="{y+4:.0f}">{label}</text></g>')

    orphan_list = orphans(m)
    orphan_html = ("".join(f"<li>{e(o)}</li>" for o in orphan_list)
                   if orphan_list else "<li class='sub'>none</li>")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Origami graph — {e(host)}</title><style>{_GRAPH_CSS}</style></head><body>
<header><h1>Origami</h1><span class="sub">endpoint graph · {e(host)} ·
{len(m.nodes)} nodes · {len(m.edges)} refs · {len(orphan_list)} hidden</span></header>
<div class="legend">
<span><i style="background:#3fb950"></i>2xx</span><span><i style="background:#e3b341"></i>401/403</span>
<span><i style="background:#39c5cf"></i>3xx</span><span><i style="background:#f85149"></i>other</span>
<span><i style="background:#6e7681"></i>referenced</span>
<span><i class="ring"></i>hidden (JS/spec-only)</span>
<span>— containment&nbsp;&nbsp;– – reference</span>
<label class="only"><input type="checkbox" id="oo"> only hidden</label></div>
<div id="vp"><svg id="g" viewBox="0 0 {w} {h}" width="{w}" height="{h}">{''.join(parts)}</svg></div>
<div class="orphans"><b>Hidden / orphan endpoints</b><ul>{orphan_html}</ul></div>
<script>{_GRAPH_JS}</script></body></html>"""


_GRAPH_CSS = """
:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--bd:#30363d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.5 ui-monospace,Menlo,monospace}
header{padding:14px 22px;border-bottom:1px solid var(--bd)}
h1{display:inline;font-size:18px;color:#e3b341;margin-right:12px}
.sub{color:var(--mut)}
.legend{padding:8px 22px;border-bottom:1px solid var(--bd);display:flex;gap:16px;flex-wrap:wrap;color:var(--mut)}
.legend i{display:inline-block;width:11px;height:11px;border-radius:50%;vertical-align:-1px;margin-right:4px}
.legend i.ring{background:transparent;border:2px solid #f85149}
#vp{overflow:auto;height:calc(100vh - 200px);cursor:grab}
svg{background:var(--bg)}
.edge{fill:none}.edge.tree{stroke:#30363d;stroke-width:1}
.edge.ref{stroke:#6e40c9;stroke-width:1;stroke-dasharray:4 3;opacity:.7}
.node text{fill:var(--fg);font-size:11px}
.node-hidden circle{stroke:#f85149;stroke-width:2}
.node-hidden text{fill:#f85149}
.only{margin-left:auto;color:var(--fg);cursor:pointer}
svg.only-hidden .node:not(.node-hidden){opacity:.12}
svg.only-hidden .edge{opacity:.05}
.orphans{padding:12px 22px;border-top:1px solid var(--bd)}
.orphans ul{columns:3;margin:6px 0 0;padding-left:18px}
.orphans b{color:#f85149}
"""

# Minimal pan (drag) + zoom (wheel) on the SVG viewBox — no library.
_GRAPH_JS = """
const vp=document.getElementById('vp');let d=0,sx,sy,sl,st;
vp.addEventListener('mousedown',e=>{d=1;sx=e.clientX;sy=e.clientY;sl=vp.scrollLeft;st=vp.scrollTop;vp.style.cursor='grabbing'});
addEventListener('mouseup',()=>{d=0;vp.style.cursor='grab'});
addEventListener('mousemove',e=>{if(d){vp.scrollLeft=sl-(e.clientX-sx);vp.scrollTop=st-(e.clientY-sy)}});
const g=document.getElementById('g');let s=1;
vp.addEventListener('wheel',e=>{if(!e.ctrlKey&&!e.metaKey)return;e.preventDefault();
 s=Math.min(4,Math.max(.2,s*(e.deltaY<0?1.1:0.9)));
 g.style.width=(g.viewBox.baseVal.width*s)+'px';g.style.height=(g.viewBox.baseVal.height*s)+'px'},{passive:false});
const oo=document.getElementById('oo');
if(oo)oo.addEventListener('change',e=>g.classList.toggle('only-hidden',e.target.checked));
"""


def write(result, path: str) -> tuple[str, str, int]:
    """Write FILE.html (graph) + FILE.dot. Returns (html_path, dot_path, n_hidden)."""
    from pathlib import Path
    m = build(result)
    p = Path(path)
    html_path = p if p.suffix.lower() in (".html", ".htm") else p.with_suffix(".html")
    dot_path = html_path.with_suffix(".dot")
    html_path.write_text(to_html(m, result.profile.host), encoding="utf-8")
    dot_path.write_text(to_dot(m), encoding="utf-8")
    return str(html_path), str(dot_path), len(orphans(m))
