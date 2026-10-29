"""B4 - generic ReAct agent over the whole SBOM with the same evidence tools as VERA, but without the
temporal model, VUG prioritisation, graph-completion algorithm or verifier. The agent decides itself
what to look up and submits fixed components."""
from __future__ import annotations
import json
from packageurl import PackageURL
from ..model import SBOM, Component, Repair
from ..agent.llm_client import chat
from ..agent.tools import TOOL_SPECS, ToolBox

SUBMIT = {"type": "function", "function": {
    "name": "submit_components",
    "description": "Submit corrected components (exact purls with versions), including any missing transitive dependencies you identified.",
    "parameters": {"type": "object", "properties": {"components": {"type": "array", "items": {"type": "object", "properties": {
        "ref": {"type": ["string", "null"], "description": "ref of the original component, null for a new one"},
        "purl": {"type": "string"}}, "required": ["purl"]}}}, "required": ["components"]}}}
FINISH = {"type": "function", "function": {"name": "finish", "description": "Finish the repair.",
                                           "parameters": {"type": "object", "properties": {}}}}
TOOLS = [t for t in TOOL_SPECS if t["function"]["name"] != "submit_fix"] + [SUBMIT, FINISH]

SYSTEM = """You are an autonomous agent repairing a defective SBOM (generated {ts}). Defects include missing/range
versions, missing package URLs, wrong names and missing transitive dependencies. Use the tools to investigate,
then call submit_components (you may call it several times) and finally finish. Tool budget: {budget} calls."""


def repair(s: SBOM, model: str, budget: int = 40, max_turns: int = 30) -> tuple[SBOM, dict]:
    out = s.copy()
    ts = s.metadata.get("timestamp")
    tb = ToolBox(ts=ts)
    rows = "\n".join(f"{c.bom_ref} | {c.name} | {c.group or ''} | {c.version or ''} | {c.purl or ''}" for c in out.components[:150])
    msgs = [{"role": "system", "content": SYSTEM.format(ts=ts, budget=budget)},
            {"role": "user", "content": "Components (ref | name | group | version | purl):\n" + rows}]
    by_ref = {c.bom_ref: c for c in out.components}
    added = 0
    turns = 0
    while turns < max_turns:
        turns += 1
        r = chat(model, msgs, tools=TOOLS, max_tokens=6000)
        if not r["tool_calls"]:
            msgs.append({"role": "assistant", "content": r["content"] or ""})
            msgs.append({"role": "user", "content": "Continue: call tools, submit_components, then finish."})
            continue
        msgs.append({"role": "assistant", "content": r["content"] or None, "tool_calls": [
            {"id": tc["id"], "type": "function", "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"])}}
            for tc in r["tool_calls"]]})
        stop = False
        for tc in r["tool_calls"]:
            if tc["name"] == "finish":
                stop = True
                res = "ok"
            elif tc["name"] == "submit_components":
                n = 0
                for item in tc["arguments"].get("components", []) or []:
                    try:
                        p = PackageURL.from_string(item.get("purl", ""))
                    except Exception:
                        continue
                    c = by_ref.get(str(item.get("ref")))
                    if c is None:
                        c = Component(name=p.name, group=p.namespace, version=p.version, purl=item["purl"], bom_ref=f"b4-{added}")
                        added += 1
                        out.components.append(c)
                        by_ref[c.bom_ref] = c
                        c.repairs.append(Repair("component", None, item["purl"], "react-agent", [], 0.5))
                    else:
                        c.repairs.append(Repair("purl", c.purl, item["purl"], "react-agent", [], 0.5))
                        c.purl, c.name, c.group, c.version = item["purl"], p.name, p.namespace, p.version or c.version
                    n += 1
                res = f"accepted {n} components"
            elif tb.calls >= budget:
                res = json.dumps({"error": "tool budget exhausted; submit_components then finish"})
            else:
                res = tb.run(tc["name"], tc["arguments"])
            msgs.append({"role": "tool", "tool_call_id": tc["id"], "content": res if isinstance(res, str) else json.dumps(res)})
        if stop:
            break
    return out, {"turns": turns, "tool_calls": tb.calls}
