"""B3 - LLM zero-shot: the whole (bad) component list is given to the LLM, which must return exact
purls (with versions) for every component plus missing transitive dependencies. No tools."""
from __future__ import annotations
import json
from packageurl import PackageURL
from ..model import SBOM, Component, Repair
from ..agent.llm_client import chat, extract_json

PROMPT = """You are an SBOM repair expert. The following SBOM (generated {ts}) has defects: missing or range versions,
missing/invalid package URLs, wrong names, and missing transitive dependencies.
For EVERY component return its corrected package URL with the exact version that was most likely installed at the
SBOM timestamp. Then list up to {max_extra} missing transitive dependencies (exact purl with version).
Answer ONLY with JSON: {{"components": [{{"ref": "<ref>", "purl": "pkg:..."}}], "missing": ["pkg:..."]}}

Components (ref | name | group | version field | purl):
{rows}"""


def repair(s: SBOM, model: str, chunk: int = 60, max_extra: int = 80) -> SBOM:
    out = s.copy()
    ts = s.metadata.get("timestamp") or "unknown date"
    by_ref = {c.bom_ref: c for c in out.components}
    extra: list[str] = []
    comps = out.components
    for i in range(0, len(comps), chunk):
        part = comps[i:i + chunk]
        rows = "\n".join(f"{c.bom_ref} | {c.name} | {c.group or ''} | {c.version or ''} | {c.purl or ''}" for c in part)
        r = chat(model, [{"role": "user", "content": PROMPT.format(ts=ts, rows=rows, max_extra=max_extra if i == 0 else 20)}],
                 max_tokens=8000)
        j = extract_json(r["content"]) or {}
        for item in j.get("components", []) if isinstance(j, dict) else []:
            c = by_ref.get(str(item.get("ref")))
            if not c or not item.get("purl"):
                continue
            try:
                p = PackageURL.from_string(item["purl"])
            except Exception:
                continue
            if item["purl"] != c.purl or p.version != c.version:
                c.repairs.append(Repair("purl", c.purl, item["purl"], "llm-zeroshot", [], 0.5))
                c.purl, c.name, c.group, c.version = item["purl"], p.name, p.namespace, p.version or c.version
        extra += [x for x in (j.get("missing", []) if isinstance(j, dict) else []) if isinstance(x, str)]
    have = {c.purl for c in out.components}
    for k, pu in enumerate(dict.fromkeys(extra)):
        if pu in have:
            continue
        try:
            p = PackageURL.from_string(pu)
        except Exception:
            continue
        c = Component(name=p.name, group=p.namespace, version=p.version, purl=pu, bom_ref=f"b3-{k}")
        c.repairs.append(Repair("component", None, pu, "llm-zeroshot", [], 0.5))
        out.components.append(c)
    return out
