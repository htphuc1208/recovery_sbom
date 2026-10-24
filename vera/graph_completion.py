"""Recover missing (transitive) components from repaired direct dependencies.
Uses deps.dev dependency graphs for the *edges & declared requirements*, then re-derives each
transitive version with the temporal resolver model at the SBOM timestamp (deps.dev resolves at
its own crawl time, which is not the SBOM's time)."""
from __future__ import annotations
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from .evidence import registry
from .candidates import generate, CandidateSet

SYS2TYPE = {"NPM": "npm", "PYPI": "pypi", "MAVEN": "maven"}


def _split(ptype: str, name: str):
    if ptype == "maven" and ":" in name:
        g, a = name.split(":", 1)
        return g, a
    if ptype == "npm" and name.startswith("@") and "/" in name:
        s, n = name.split("/", 1)
        return s, n
    return None, name


def transitive_requirements(ptype: str, name: str, namespace: str | None, version: str) -> list[tuple[str, str, str]]:
    """[(dep_full_name, requirement, parent_full_name)] for every edge in the deps.dev graph (excluding SELF)."""
    g = registry.resolved_dependencies(ptype, name, version, namespace)
    if not g:
        return []
    nodes = g.get("nodes", [])
    out = []
    for e in g.get("edges", []):
        try:
            to = nodes[e["toNode"]]["versionKey"]
            frm = nodes[e["fromNode"]]["versionKey"]
        except (IndexError, KeyError):
            continue
        req = e.get("requirement") or to.get("version")
        if ptype == "maven":
            req = to.get("version")  # Maven: nearest-wins resolved version is what the build uses
        out.append((to["name"], req, frm["name"]))
    return out


def complete(direct: list[tuple[str, str, str | None, str]], ts: str | None, mu_days: float = 120.0,
             workers: int = 12, temporal: bool = True, t_floor: float | None = None,
             floor_weight: float = 1.0) -> list[dict]:
    """direct: [(ptype, name, namespace, version)] -> list of recovered components
    {ptype, name, namespace, cands: CandidateSet, via: parent}"""
    reqs: dict[tuple[str, str], list[str]] = defaultdict(list)
    via: dict[tuple[str, str], str] = {}
    parents: dict[tuple[str, str], set] = defaultdict(set)
    with ThreadPoolExecutor(workers) as ex:
        results = list(ex.map(lambda d: (d, transitive_requirements(d[0], d[1], d[2], d[3])), direct))
    direct_keys = {(d[0], (f"{d[2]}:{d[1]}" if d[0] == "maven" else f"{d[2]}/{d[1]}" if d[2] else d[1]).lower()) for d in direct}
    for d, edges in results:
        for dep, req, parent in edges:
            k = (d[0], dep)
            if (d[0], dep.lower()) in direct_keys:
                continue
            reqs[k].append(req)
            via.setdefault(k, parent)
            parents[k].add(parent)

    def solve(item):
        (ptype, full), rs = item
        ns, nm = _split(ptype, full)
        uniq = list(dict.fromkeys(rs))
        if ptype == "npm":
            # npm may install several copies; one per distinct requirement group -> take each requirement separately
            out = []
            seen = set()
            for r in uniq[:4]:
                cs = generate(ptype, nm, ns, [r], ts, mu_days, temporal=temporal, t_floor=t_floor, floor_weight=floor_weight)
                if cs.mode and cs.mode not in seen:
                    seen.add(cs.mode)
                    out.append(cs)
            return [(ptype, nm, ns, cs, via[(ptype, full)], parents[(ptype, full)]) for cs in out]
        if ptype == "maven":
            # nearest-wins: first requirement seen (closest to a direct dependency)
            cs = generate(ptype, nm, ns, [uniq[0]], ts, mu_days, temporal=temporal, t_floor=t_floor, floor_weight=floor_weight)
        else:
            cs = generate(ptype, nm, ns, uniq, ts, mu_days, temporal=temporal, t_floor=t_floor, floor_weight=floor_weight)
        return [(ptype, nm, ns, cs, via[(ptype, full)], parents[(ptype, full)])] if cs.dist else []

    out = []
    with ThreadPoolExecutor(workers) as ex:
        for res in ex.map(solve, reqs.items()):
            for ptype, nm, ns, cs, parent, pars in res:
                out.append({"ptype": ptype, "name": nm, "namespace": ns, "cands": cs, "via": parent, "parents": sorted(pars)})
    return out
