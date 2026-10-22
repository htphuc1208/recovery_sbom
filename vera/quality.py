"""Defect diagnosis + quality scoring (NTIA minimum elements + vuln-relevant fields)."""
from __future__ import annotations
import re
from collections import Counter
from dataclasses import dataclass
from .model import SBOM, Component
from .versions import looks_like_range

VULN_CRITICAL = {"MISSING_VERSION", "RANGE_VERSION", "MISSING_PURL", "INVALID_PURL", "MISSING_ECOSYSTEM",
                 "NONCANONICAL_NAME", "MISSING_GROUP"}


@dataclass
class Defect:
    comp: str     # bom_ref
    kind: str
    detail: str = ""


def _purl_ok(c: Component) -> bool:
    p = c.purl_obj()
    return p is not None


def diagnose_component(c: Component) -> list[Defect]:
    d = []
    ref = c.bom_ref or c.name
    v = c.version
    if not v:
        d.append(Defect(ref, "MISSING_VERSION"))
    elif "${" in v:
        d.append(Defect(ref, "RANGE_VERSION", f"unresolved property {v}"))
    elif looks_like_range(v):
        d.append(Defect(ref, "RANGE_VERSION", v))
    if not c.purl:
        d.append(Defect(ref, "MISSING_PURL"))
        if not c.ecosystem_hint:
            d.append(Defect(ref, "MISSING_ECOSYSTEM"))
    elif not _purl_ok(c):
        d.append(Defect(ref, "INVALID_PURL", c.purl))
    else:
        p = c.purl_obj()
        if p.version and v and p.version != v and not looks_like_range(v):
            d.append(Defect(ref, "PURL_VERSION_MISMATCH", f"{p.version} vs {v}"))
        if p.version and looks_like_range(p.version):
            d.append(Defect(ref, "RANGE_VERSION", f"purl version {p.version}"))
        if p.type == "pypi" and p.name != re.sub(r"[-_.]+", "-", p.name).lower():
            d.append(Defect(ref, "NONCANONICAL_NAME", p.name))
        if p.type == "maven" and not p.namespace:
            d.append(Defect(ref, "MISSING_GROUP"))
    if c.ptype == "maven" and not c.group and not (c.purl_obj() and c.purl_obj().namespace):
        if not any(x.kind == "MISSING_GROUP" for x in d):
            d.append(Defect(ref, "MISSING_GROUP"))
    if not c.licenses:
        d.append(Defect(ref, "MISSING_LICENSE"))
    if not c.hashes:
        d.append(Defect(ref, "MISSING_HASH"))
    if not c.supplier:
        d.append(Defect(ref, "MISSING_SUPPLIER"))
    return d


def diagnose(s: SBOM) -> dict:
    defects: list[Defect] = []
    for c in s.components:
        defects += diagnose_component(c)
    sbom_level = []
    n = len(s.components)
    edges = sum(len(v) for v in s.dependencies.values())
    if n and edges == 0:
        sbom_level.append(Defect("<sbom>", "NO_DEPENDENCY_GRAPH"))
    if not s.metadata.get("timestamp"):
        sbom_level.append(Defect("<sbom>", "MISSING_TIMESTAMP"))
    # heuristic: only direct deps listed (root has edges to everything, nothing else has edges)
    root_ref = s.root.bom_ref if s.root else None
    non_root_edges = sum(len(v) for k, v in s.dependencies.items() if k != root_ref)
    root_edges = len(s.dependencies.get(root_ref, [])) if root_ref else 0
    # manifest-only signature: root depends on (almost) everything, nothing depends on anything else
    if n >= 1 and non_root_edges == 0 and root_edges >= 0.8 * n:
        sbom_level.append(Defect("<sbom>", "SUSPECTED_MISSING_TRANSITIVE", "only direct dependencies listed"))
    return {"component_defects": defects, "sbom_defects": sbom_level, "counts": Counter(x.kind for x in defects)}


def ntia_score(s: SBOM) -> dict:
    """Fraction of components satisfying each NTIA minimum element (+ overall)."""
    n = max(len(s.components), 1)
    good_v = sum(1 for c in s.components if c.version and not looks_like_range(c.version))
    uid = sum(1 for c in s.components if c.purl_obj() is not None)
    sup = sum(1 for c in s.components if c.supplier)
    name = sum(1 for c in s.components if c.name)
    edges = 1.0 if sum(len(v) for v in s.dependencies.values()) else 0.0
    ts = 1.0 if s.metadata.get("timestamp") else 0.0
    parts = {"name": name / n, "version": good_v / n, "unique_id": uid / n, "supplier": sup / n,
             "dependencies": edges, "timestamp": ts}
    parts["overall"] = sum(parts.values()) / len(parts)
    return parts


def vuln_readiness(s: SBOM) -> float:
    """Share of components a vulnerability scanner can actually match (exact version + resolvable identity)."""
    n = max(len(s.components), 1)
    ok = sum(1 for c in s.components if c.version and not looks_like_range(c.version) and c.osv_ecosystem())
    return ok / n


def summary(s: SBOM) -> dict:
    d = diagnose(s)
    return {"components": len(s.components), "defects": dict(d["counts"]),
            "sbom_defects": [x.kind for x in d["sbom_defects"]],
            "ntia": ntia_score(s), "vuln_readiness": vuln_readiness(s)}
