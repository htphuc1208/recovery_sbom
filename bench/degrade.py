"""Controlled degradation operators (dataset C). Rates per level are calibrated on the real-SBOM survey (RQ1).
Every operator mirrors a defect observed in real SBOMs."""
from __future__ import annotations
import random
import re
from packageurl import PackageURL
from vera.model import SBOM

LEVELS = {  # probability per component for each operator
    "light":  {"drop_version": 0.10, "range_version": 0.05, "drop_purl": 0.05, "mangle_name": 0.05, "drop_group": 0.05,
               "drop_distro": 0.3, "drop_component": 0.05, "drop_license": 0.3, "drop_hash": 0.3},
    "medium": {"drop_version": 0.25, "range_version": 0.15, "drop_purl": 0.15, "mangle_name": 0.10, "drop_group": 0.15,
               "drop_distro": 0.7, "drop_component": 0.15, "drop_license": 0.6, "drop_hash": 0.6},
    "heavy":  {"drop_version": 0.40, "range_version": 0.20, "drop_purl": 0.30, "mangle_name": 0.20, "drop_group": 0.30,
               "drop_distro": 1.0, "drop_component": 0.30, "drop_license": 1.0, "drop_hash": 1.0},
}


def _range_for(ptype, v):
    m = re.match(r"^(\d+)\.(\d+)", v or "")
    if not m:
        return None
    if ptype == "npm":
        return f"^{m.group(1)}.{m.group(2)}.0"
    if ptype == "pypi":
        return f">={m.group(1)}.{m.group(2)}"
    return None


def _mangle(ptype, name, rnd):
    if ptype == "pypi":
        return rnd.choice([name.replace("-", "_"), name.title(), name.upper().replace("-", "_")])
    if ptype == "npm":
        return rnd.choice([name.upper(), name.replace("-", "_")]) if "-" in name else name.capitalize()
    return name


def degrade(s: SBOM, level: str = "medium", seed: int = 0, keep_direct: set | None = None) -> tuple[SBOM, dict]:
    rnd = random.Random(seed)
    P = LEVELS[level]
    out = s.copy()
    log = {k: 0 for k in P}
    kept = []
    for c in out.components:
        p = c.purl_obj()
        t = p.type if p else None
        if rnd.random() < P["drop_component"] and (keep_direct is None or c.bom_ref not in keep_direct):
            log["drop_component"] += 1
            continue
        c.properties = {}
        if rnd.random() < P["drop_license"] and c.licenses:
            c.licenses = []; log["drop_license"] += 1
        if rnd.random() < P["drop_hash"] and c.hashes:
            c.hashes = {}; log["drop_hash"] += 1
        if p and t in ("deb", "apk", "rpm"):
            if rnd.random() < P["drop_distro"] and (p.qualifiers or {}).get("distro"):
                q = {k: v for k, v in (p.qualifiers or {}).items() if k != "distro"}
                c.purl = PackageURL(p.type, p.namespace, p.name, p.version, q or None).to_string(); log["drop_distro"] += 1
            kept.append(c); continue
        if p and t in ("pypi", "npm", "maven"):
            r = rnd.random()
            if r < P["drop_version"]:
                c.version = None
                c.purl = PackageURL(p.type, p.namespace, p.name, None).to_string(); log["drop_version"] += 1
            elif r < P["drop_version"] + P["range_version"]:
                rg = _range_for(t, c.version)
                if rg:
                    c.version = rg
                    c.purl = PackageURL(p.type, p.namespace, p.name, None).to_string(); log["range_version"] += 1
            p = c.purl_obj()
            if t == "maven" and rnd.random() < P["drop_group"]:
                c.group = None
                c.purl = None; log["drop_group"] += 1
            elif rnd.random() < P["drop_purl"]:
                c.group = p.namespace
                c.name = p.name if t != "npm" or not p.namespace else f"{p.namespace}/{p.name}"
                if t == "npm":
                    c.group = None
                c.purl = None; log["drop_purl"] += 1
            if rnd.random() < P["mangle_name"] and t in ("pypi", "npm"):
                if c.purl:
                    pp = c.purl_obj()
                    newn = _mangle(t, pp.name, rnd)
                    if newn != pp.name:
                        c.purl = PackageURL(pp.type, pp.namespace, newn, pp.version).to_string(); c.name = newn; log["mangle_name"] += 1
                else:
                    newn = _mangle(t, c.name, rnd)
                    if newn != c.name:
                        c.name = newn; log["mangle_name"] += 1
        kept.append(c)
    out.components = kept
    refs = {c.bom_ref for c in kept}
    out.dependencies = {k: [x for x in v if x in refs] for k, v in out.dependencies.items() if k in refs or k == "root"}
    return out, log
