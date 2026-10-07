"""Read CycloneDX (1.4-1.6) / SPDX 2.3 JSON into the internal model; write CycloneDX 1.6."""
from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote
from .model import SBOM, Component


def load(path_or_obj) -> SBOM:
    if isinstance(path_or_obj, (str, Path)):
        obj = json.loads(Path(path_or_obj).read_text())
    elif isinstance(path_or_obj, (bytes, bytearray)):
        obj = json.loads(path_or_obj)
    else:
        obj = path_or_obj
    if "sbom" in obj and isinstance(obj["sbom"], dict):  # GitHub dependency-graph wrapper
        obj = obj["sbom"]
    if obj.get("bomFormat") == "CycloneDX":
        return _from_cdx(obj)
    if "spdxVersion" in obj:
        return _from_spdx(obj)
    raise ValueError("Unknown SBOM format (expect CycloneDX or SPDX JSON)")


# ---------------------------------------------------------------- CycloneDX
def _cdx_licenses(c: dict) -> list[str]:
    out = []
    for l in c.get("licenses", []) or []:
        if "license" in l:
            lic = l["license"]
            out.append(lic.get("id") or lic.get("name") or "")
        elif "expression" in l:
            out.append(l["expression"])
    return [x for x in out if x]


def _cdx_comp(c: dict) -> Component:
    comp = Component(
        name=c.get("name", ""),
        version=c.get("version") or None,
        purl=c.get("purl") or None,
        group=c.get("group") or None,
        type=c.get("type", "library"),
        licenses=_cdx_licenses(c),
        hashes={h.get("alg", ""): h.get("content", "") for h in c.get("hashes", []) or []},
        bom_ref=c.get("bom-ref") or None,
        supplier=(c.get("supplier") or {}).get("name") if isinstance(c.get("supplier"), dict) else None,
        properties={p.get("name", ""): p.get("value", "") for p in c.get("properties", []) or []},
    )
    return comp


def _flatten_cdx(comps):
    for c in comps or []:
        yield c
        yield from _flatten_cdx(c.get("components"))


def _from_cdx(obj: dict) -> SBOM:
    s = SBOM()
    md = obj.get("metadata", {}) or {}
    s.metadata = {"timestamp": md.get("timestamp"), "source_format": f"CycloneDX-{obj.get('specVersion')}",
                  "tools": md.get("tools")}
    if md.get("component"):
        s.root = _cdx_comp(md["component"])
    for c in _flatten_cdx(obj.get("components")):
        s.components.append(_cdx_comp(c))
    for i, c in enumerate(s.components):
        if not c.bom_ref:
            c.bom_ref = f"comp-{i}"
    for d in obj.get("dependencies", []) or []:
        s.dependencies[d.get("ref")] = list(d.get("dependsOn", []) or [])
    return s


# ---------------------------------------------------------------- SPDX
def _spdx_lic(v):
    if not v or v in ("NOASSERTION", "NONE"):
        return []
    return [v]


def _from_spdx(obj: dict) -> SBOM:
    s = SBOM()
    ci = obj.get("creationInfo", {}) or {}
    s.metadata = {"timestamp": ci.get("created"), "source_format": obj.get("spdxVersion"),
                  "tools": ci.get("creators"), "name": obj.get("name")}
    described = set()
    for r in obj.get("relationships", []) or []:
        if r.get("relationshipType") == "DESCRIBES":
            described.add(r.get("relatedSpdxElement"))
    described |= set(obj.get("documentDescribes", []) or [])
    for p in obj.get("packages", []) or []:
        purl = None
        for ref in p.get("externalRefs", []) or []:
            if ref.get("referenceType") == "purl":
                purl = unquote(ref.get("referenceLocator", "")) if "%40" in ref.get("referenceLocator", "") else ref.get("referenceLocator")
        ver = p.get("versionInfo") or None
        comp = Component(
            name=p.get("name", ""), version=ver, purl=purl, bom_ref=p.get("SPDXID"),
            licenses=_spdx_lic(p.get("licenseConcluded")) or _spdx_lic(p.get("licenseDeclared")),
            hashes={h.get("algorithm", ""): h.get("checksumValue", "") for h in p.get("checksums", []) or []},
            supplier=p.get("supplier"),
        )
        if p.get("SPDXID") in described:
            s.root = comp
        else:
            s.components.append(comp)
    for r in obj.get("relationships", []) or []:
        t = r.get("relationshipType")
        a, b = r.get("spdxElementId"), r.get("relatedSpdxElement")
        if t == "DEPENDS_ON":
            s.dependencies.setdefault(a, []).append(b)
        elif t == "DEPENDENCY_OF":
            s.dependencies.setdefault(b, []).append(a)
    return s


# ---------------------------------------------------------------- writer
def to_cyclonedx(s: SBOM, include_vera_props: bool = True) -> dict:
    def comp_json(c: Component) -> dict:
        d: dict = {"type": c.type or "library", "name": c.name}
        if c.bom_ref:
            d["bom-ref"] = c.bom_ref
        if c.group:
            d["group"] = c.group
        if c.version:
            d["version"] = c.version
        if c.purl:
            d["purl"] = c.purl
        if c.supplier:
            d["supplier"] = {"name": c.supplier}
        if c.licenses:
            d["licenses"] = [{"license": {"id": l}} if " " not in l else {"expression": l} for l in c.licenses]
        if c.hashes:
            d["hashes"] = [{"alg": k, "content": v} for k, v in c.hashes.items()]
        props = dict(c.properties)
        if include_vera_props and c.repairs:
            props["vera:repaired_fields"] = ",".join(sorted({r.field for r in c.repairs}))
            props["vera:confidence"] = f"{min(r.confidence for r in c.repairs):.2f}"
            props["vera:evidence"] = " | ".join(e for r in c.repairs for e in r.evidence)[:2000]
        if props:
            d["properties"] = [{"name": k, "value": str(v)} for k, v in props.items()]
        return d

    md: dict = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "tools": {"components": [{"type": "application", "name": "vera", "version": "0.1.0"}]}}
    if s.root:
        md["component"] = comp_json(s.root)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": md,
        "components": [comp_json(c) for c in s.components],
        "dependencies": [{"ref": k, "dependsOn": v} for k, v in s.dependencies.items()],
    }


def dump(s: SBOM, path) -> None:
    Path(path).write_text(json.dumps(to_cyclonedx(s), indent=2))
