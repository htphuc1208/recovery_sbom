"""Resolve Maven ${properties} and parent-managed versions from a released pom (+ parent chain + imported BOMs)."""
from __future__ import annotations
import re
from xml.etree import ElementTree as ET
from .http import get

NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def _pom(g, a, v):
    if not (g and a and v):
        return None
    x = get(f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom", as_json=False)
    if not x:
        return None
    try:
        return ET.fromstring(x)
    except ET.ParseError:
        return None


def effective_model(g: str, a: str, v: str, depth: int = 0) -> dict:
    """{'properties': {...}, 'managed': {(g,a): version}} merged over the parent chain."""
    root = _pom(g, a, v)
    if root is None or depth > 8:
        return {"properties": {}, "managed": {}}
    props, managed = {}, {}
    parent = root.find("m:parent", NS)
    if parent is not None:
        pg, pa, pv = (parent.findtext(f"m:{t}", namespaces=NS) for t in ("groupId", "artifactId", "version"))
        pm = effective_model(pg, pa, pv, depth + 1)
        props.update(pm["properties"])
        managed.update(pm["managed"])
        props.setdefault("project.parent.version", pv)
        props.setdefault("parent.version", pv)
    my_g = root.findtext("m:groupId", namespaces=NS) or (parent.findtext("m:groupId", namespaces=NS) if parent is not None else g)
    my_v = root.findtext("m:version", namespaces=NS) or (parent.findtext("m:version", namespaces=NS) if parent is not None else v)
    props.update({"project.version": my_v, "pom.version": my_v, "version": my_v, "project.groupId": my_g})
    pe = root.find("m:properties", NS)
    if pe is not None:
        for child in pe:
            tag = child.tag.split("}", 1)[-1]
            props[tag] = (child.text or "").strip()
    dm = root.find("m:dependencyManagement/m:dependencies", NS)
    if dm is not None:
        for d in dm.findall("m:dependency", NS):
            dg, da, dv = (d.findtext(f"m:{t}", namespaces=NS) for t in ("groupId", "artifactId", "version"))
            dg, dv = interp(dg, props), interp(dv, props)
            if (d.findtext("m:scope", namespaces=NS) == "import") and depth < 4:
                bm = effective_model(dg, da, dv, depth + 1)
                for k, val in bm["managed"].items():
                    managed.setdefault(k, val)
            elif dg and da and dv:
                managed[(dg, da)] = dv
    return {"properties": props, "managed": managed}


def interp(s: str | None, props: dict, n: int = 0) -> str | None:
    if not s or "${" not in s or n > 10:
        return s
    out = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), s)
    return out if out == s else interp(out, props, n + 1)


def resolve_version(root_g: str, root_a: str, root_v: str, dep_g: str, dep_a: str, declared: str | None) -> tuple[str | None, str]:
    """Return (version, evidence)."""
    m = effective_model(root_g, root_a, root_v)
    if declared and "${" in declared:
        v = interp(declared, m["properties"])
        if v and "${" not in v:
            return v, f"pom property {declared} = {v} in {root_g}:{root_a}:{root_v} (parent chain)"
    if not declared:
        dg = interp(dep_g, m["properties"])
        v = m["managed"].get((dg, dep_a))
        if v:
            v = interp(v, m["properties"])
            if v and "${" not in v:
                return v, f"dependencyManagement of {root_g}:{root_a}:{root_v} parent chain"
    return None, "unresolved"
