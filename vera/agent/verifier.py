"""Verifier: a proposal is accepted only if every value is backed by registry evidence."""
from __future__ import annotations
from ..evidence import registry
from ..versions import satisfies, looks_like_range
from ..candidates import _parse_ts
from .tools import split_name, ECOS


def verify(prop: dict, toolbox, spec: str | None = None, ts: str | None = None) -> tuple[bool, str]:
    eco = (prop.get("ecosystem") or "").lower()
    name = prop.get("name")
    ver = prop.get("version")
    if eco not in ECOS:
        return False, f"ecosystem '{eco}' unsupported/unknown"
    if not name:
        return False, "name missing"
    ns, n = split_name(eco, name)
    if eco == "maven" and not ns:
        return False, "maven name must be groupId:artifactId"
    vs = registry.package_versions(eco, n, ns)
    if vs is None:
        return False, f"{eco}:{name} does not exist in the registry"
    if ver:
        if looks_like_range(ver):
            return False, "version must be exact, not a range"
        hit = [v for v in vs if v["version"] == ver]
        if not hit:
            return False, f"version {ver} of {name} does not exist"
        if spec and "${" not in spec and not satisfies(ver, spec, {"pypi": "PyPI", "maven": "Maven"}.get(eco, eco)):
            return False, f"version {ver} violates declared range {spec}"
        t = _parse_ts(hit[0].get("published"))
        tsf = _parse_ts(ts)
        if t and tsf and t > tsf + 86400:
            return False, f"version {ver} was published after the SBOM timestamp {ts}"
    cited = [e for e in prop.get("evidence") or [] if e in toolbox.evidence]
    if not cited:
        return False, "no valid evidence id cited; call a tool first and cite its evidence_id"
    return True, "ok"
