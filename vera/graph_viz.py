"""Interactive dependency-graph rendering (pyvis / vis-network) for the PoC UI."""
from __future__ import annotations
from collections import defaultdict, deque
from pyvis.network import Network
from .model import SBOM, Component
from . import vuln

COLORS = {
    "root": "#6C5CE7",        # SBOM subject
    "original": "#74B9FF",    # unchanged component
    "repaired": "#FDCB6E",    # field(s) repaired (version / purl / distro ...)
    "recovered": "#55EFC4",   # component added by transitive recovery
    "broken": "#B2BEC3",      # still not scannable (no exact version / identity)
}
VULN_BORDER = "#D63031"


def _status(c: Component) -> str:
    fields = {r.field for r in c.repairs}
    if "component" in fields:
        return "recovered"
    if fields - {"license"}:
        return "repaired"
    if not c.osv_ecosystem() or not c.version or any(ch in (c.version or "") for ch in "^~<>=*,${"):
        return "broken"
    return "original"


def build_graph(s: SBOM, max_nodes: int = 300, only_vuln_paths: bool = False, min_prob: float = 0.5,
                hierarchical: bool = False, height: str = "680px") -> tuple[str, dict]:
    """Return (html, stats). Components without an incoming edge are attached to the root (dashed)."""
    findings = vuln.scan(s)
    by_comp: dict[str, list] = defaultdict(list)
    for f in findings:
        if f.prob >= min_prob or min_prob <= 0:
            by_comp[f.component].append(f)

    root_id = (s.root.bom_ref if s.root and s.root.bom_ref else "__root__")
    comps = {c.bom_ref: c for c in s.components if c.bom_ref}
    children: dict[str, list[str]] = defaultdict(list)
    for parent, deps in s.dependencies.items():
        for d in deps:
            if d in comps and d != parent:
                children[parent].append(d)
    has_parent = {d for p, ds in children.items() for d in ds if p in comps or p == root_id}
    orphans = [r for r in comps if r not in has_parent]

    # node selection: BFS from root (keeps the graph connected); optional filter to vulnerable paths
    keep: set[str]
    if only_vuln_paths:
        parents: dict[str, set] = defaultdict(set)
        for p, ds in children.items():
            for d in ds:
                parents[d].add(p)
        vul = [r for r, c in comps.items() if by_comp.get(c.key())]
        keep = set()
        stack = list(vul)
        while stack and len(keep) < max_nodes:
            r = stack.pop()
            if r in keep or r == root_id:
                continue
            keep.add(r)
            stack.extend(parents.get(r, ()))
    else:
        keep, q = set(), deque([root_id])
        seen = {root_id}
        while q and len(keep) < max_nodes:
            r = q.popleft()
            if r != root_id:
                keep.add(r)
            nxt = children.get(r, []) + (orphans if r == root_id else [])
            for d in nxt:
                if d not in seen:
                    seen.add(d)
                    q.append(d)

    net = Network(height=height, width="100%", directed=True, cdn_resources="in_line", bgcolor="#ffffff", font_color="#2d3436")
    if hierarchical:
        net.set_options('{"layout": {"hierarchical": {"enabled": true, "direction": "LR", "sortMethod": "directed", '
                        '"levelSeparation": 260, "nodeSpacing": 42}}, "physics": {"enabled": false}, '
                        '"edges": {"arrows": {"to": {"scaleFactor": 0.4}}, "smooth": false}, "interaction": {"hover": true}}')
    else:
        net.set_options('{"physics": {"barnesHut": {"gravitationalConstant": -6000, "springLength": 110, "springConstant": 0.02}, '
                        '"stabilization": {"iterations": 200}}, "edges": {"arrows": {"to": {"scaleFactor": 0.4}}, '
                        '"color": {"opacity": 0.5}}, "interaction": {"hover": true, "navigationButtons": true}}')
    root_label = (s.root.name if s.root else "SBOM") or "SBOM"
    net.add_node(root_id, label=root_label, color=COLORS["root"], shape="star", size=30, title=f"SBOM subject: {root_label}")
    stats = defaultdict(int)
    for r in keep:
        c = comps[r]
        st = _status(c)
        stats[st] += 1
        fs = by_comp.get(c.key(), [])
        worst = max((f.severity * f.prob for f in fs), default=0.0)
        if fs:
            stats["vulnerable"] += 1
        label = f"{c.name}@{c.version}" if c.version else c.name
        tip = [c.purl or c.name, f"trạng thái: {st}"]
        for rp in c.repairs:
            if rp.field != "license":
                tip.append(f"[{rp.method}] {rp.field}: {rp.old} → {rp.new} (conf {rp.confidence:.2f})")
        if c.candidates:
            top = sorted(c.candidates.items(), key=lambda x: -x[1])[:4]
            tip.append("P(version): " + ", ".join(f"{v}={p:.2f}" for v, p in top))
        for f in sorted(fs, key=lambda f: -f.severity)[:8]:
            tip.append(f"⚠ {f.vuln} CVSS≈{f.severity:.1f} p={f.prob:.2f} ({f.tier})")
        net.add_node(r, label=label[:40], title="\n".join(tip), shape="dot",
                     size=10 + 2.2 * worst,
                     color={"background": COLORS[st], "border": VULN_BORDER if fs else "#636e72",
                            "highlight": {"background": COLORS[st], "border": "#000"}},
                     borderWidth=4 if fs else 1)
    for p, ds in children.items():
        if p != root_id and p not in keep:
            continue
        for d in ds:
            if d in keep:
                net.add_edge(p, d, color="#636e72")
    linked = {d for p, ds in children.items() for d in ds if (p in keep or p == root_id) and d in keep}
    for r in keep:
        if r not in linked:
            net.add_edge(root_id, r, dashes=True, color="#b2bec3")
    stats["nodes"] = len(keep)
    stats["total_components"] = len(comps)
    stats["edges"] = sum(1 for p, ds in children.items() for d in ds)
    return net.generate_html(notebook=False), dict(stats)
