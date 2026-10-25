"""Tools exposed to the LLM agent. Every tool result is evidence with an id that a proposal must cite."""
from __future__ import annotations
import json
from ..evidence import registry
from ..evidence.maven_pom import resolve_version
from ..candidates import generate
from .. import vuln

TOOL_SPECS = [
    {"type": "function", "function": {
        "name": "registry_lookup",
        "description": "Check whether a package exists in an ecosystem registry and return its latest versions. "
                       "ecosystem: pypi | npm | maven. For maven, name must be 'groupId:artifactId'. For scoped npm use '@scope/name'.",
        "parameters": {"type": "object", "properties": {"ecosystem": {"type": "string"}, "name": {"type": "string"}},
                       "required": ["ecosystem", "name"]}}},
    {"type": "function", "function": {
        "name": "list_versions",
        "description": "List versions of a package satisfying an optional range spec and published before an optional ISO date, newest first.",
        "parameters": {"type": "object", "properties": {"ecosystem": {"type": "string"}, "name": {"type": "string"},
                                                        "spec": {"type": "string"}, "before": {"type": "string"}},
                       "required": ["ecosystem", "name"]}}},
    {"type": "function", "function": {
        "name": "get_requirements",
        "description": "Declared dependencies (name, range) of a specific package version.",
        "parameters": {"type": "object", "properties": {"ecosystem": {"type": "string"}, "name": {"type": "string"},
                                                        "version": {"type": "string"}}, "required": ["ecosystem", "name", "version"]}}},
    {"type": "function", "function": {
        "name": "maven_resolve",
        "description": "Resolve a Maven dependency version (${property} or parent-managed) from the root artifact's released pom and parent chain.",
        "parameters": {"type": "object", "properties": {"root": {"type": "string", "description": "groupId:artifactId:version of the SBOM subject"},
                                                        "dependency": {"type": "string", "description": "groupId:artifactId"},
                                                        "declared": {"type": "string"}}, "required": ["root", "dependency"]}}},
    {"type": "function", "function": {
        "name": "osv_lookup",
        "description": "Known vulnerabilities (OSV) for ecosystem/name/version.",
        "parameters": {"type": "object", "properties": {"ecosystem": {"type": "string"}, "name": {"type": "string"},
                                                        "version": {"type": "string"}}, "required": ["ecosystem", "name", "version"]}}},
    {"type": "function", "function": {
        "name": "submit_fix",
        "description": "Submit the final repair for the component. Cite evidence ids (E1, E2, ...) returned by earlier tool calls. "
                       "Use null for fields you could not determine. Never invent values.",
        "parameters": {"type": "object", "properties": {
            "ecosystem": {"type": ["string", "null"]}, "name": {"type": ["string", "null"], "description": "registry name (maven: groupId:artifactId)"},
            "version": {"type": ["string", "null"]}, "evidence": {"type": "array", "items": {"type": "string"}},
            "rationale": {"type": "string"}}, "required": ["ecosystem", "name", "version", "evidence"]}}},
]

ECOS = {"pypi", "npm", "maven"}


def split_name(eco: str, name: str):
    if eco == "maven":
        if ":" in name:
            g, a = name.split(":", 1)
            return g, a
        return None, name
    if eco == "npm" and name.startswith("@") and "/" in name:
        s, n = name.split("/", 1)
        return s, n
    return None, name


class ToolBox:
    def __init__(self, ts: str | None = None):
        self.ts = ts
        self.evidence: dict[str, dict] = {}
        self.calls = 0

    def _ev(self, tool, args, result):
        eid = f"E{len(self.evidence) + 1}"
        self.evidence[eid] = {"tool": tool, "args": args, "result": result}
        return eid

    def run(self, name: str, args: dict) -> str:
        self.calls += 1
        try:
            res = getattr(self, "t_" + name)(**{k: v for k, v in args.items() if not k.startswith("_")})
        except TypeError as e:
            res = {"error": f"bad arguments: {e}"}
        except Exception as e:  # tool failure is reported to the model, not raised
            res = {"error": str(e)[:300]}
        eid = self._ev(name, args, res)
        return json.dumps({"evidence_id": eid, **(res if isinstance(res, dict) else {"result": res})})[:4000]

    def t_registry_lookup(self, ecosystem, name):
        eco = ecosystem.lower()
        if eco not in ECOS:
            return {"exists": False, "error": "unsupported ecosystem"}
        ns, n = split_name(eco, name)
        vs = registry.package_versions(eco, n, ns)
        if vs is None:
            return {"exists": False}
        vs = sorted(vs, key=lambda v: v.get("published") or "", reverse=True)
        return {"exists": True, "n_versions": len(vs), "latest": [v["version"] for v in vs[:8]]}

    def t_list_versions(self, ecosystem, name, spec="", before=None):
        eco = ecosystem.lower()
        ns, n = split_name(eco, name)
        cs = generate(eco, n, ns, [spec] if spec else [], before or self.ts)
        if not cs.exists:
            return {"exists": False}
        return {"candidates": [{"version": v, "prior": round(p, 3)} for v, p in list(cs.dist.items())[:10]],
                "constraints": cs.constraints}

    def t_get_requirements(self, ecosystem, name, version):
        eco = ecosystem.lower()
        ns, n = split_name(eco, name)
        return {"requirements": registry.requirements(eco, n, version, ns)[:60]}

    def t_maven_resolve(self, root, dependency, declared=None):
        rg, ra, rv = (root.split(":") + [None, None, None])[:3]
        dg, da = (dependency.split(":") + [None])[:2]
        v, ev = resolve_version(rg, ra, rv, dg, da, declared)
        return {"version": v, "how": ev}

    def t_osv_lookup(self, ecosystem, name, version):
        eco = {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}.get(ecosystem.lower(), ecosystem)
        vs = vuln.vulns_for(eco, name, version)
        return {"vulns": [{"id": c, "severity": s} for c, s, _ in vs][:20]}
