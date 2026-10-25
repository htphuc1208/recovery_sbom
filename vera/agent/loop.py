"""ReAct-style agent loop for one ambiguous component, with verifier feedback."""
from __future__ import annotations
import json
from .llm_client import chat
from .tools import TOOL_SPECS, ToolBox
from .verifier import verify

SYSTEM = """You repair one defective component of a Software Bill of Materials (SBOM).
Goal: find the component's true package identity (ecosystem + registry name) and, if requested, its exact version
as it most likely was when the SBOM was generated. Use the tools to gather evidence. Rules:
- Every value you submit must be confirmed by a tool result; cite evidence ids (E1, E2...).
- Prefer versions published before the SBOM timestamp and satisfying any declared range.
- If you cannot confirm a value, submit null for it. Never guess.
- Finish by calling submit_fix exactly once. Be efficient: at most {max_steps} tool calls."""


def run_agent(component: dict, context: dict, model: str, max_steps: int = 8, use_verifier: bool = True,
              toolbox: ToolBox | None = None) -> dict:
    """component: dict describing the broken component; context: SBOM-level hints.
    Returns {'proposal': dict|None, 'accepted': bool, 'reason': str, 'steps': int, 'toolbox': ToolBox}"""
    tb = toolbox or ToolBox(ts=context.get("timestamp"))
    msgs = [{"role": "system", "content": SYSTEM.format(max_steps=max_steps)},
            {"role": "user", "content": "Component:\n" + json.dumps(component, indent=1) +
             "\n\nSBOM context:\n" + json.dumps(context, indent=1)}]
    steps, retries = 0, 0
    final = {"proposal": None, "accepted": False, "reason": "no submission", "steps": 0, "toolbox": tb}
    while steps < max_steps + 2:
        r = chat(model, msgs, tools=TOOL_SPECS, max_tokens=1500)
        steps += 1
        if not r["tool_calls"]:
            # model answered in text; nudge once
            msgs.append({"role": "assistant", "content": r["content"] or ""})
            msgs.append({"role": "user", "content": "Call a tool, or call submit_fix to finish."})
            if steps >= max_steps + 1:
                break
            continue
        msgs.append({"role": "assistant", "content": r["content"] or None,
                     "tool_calls": [{"id": tc["id"], "type": "function",
                                     "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"])}}
                                    for tc in r["tool_calls"]]})
        done = False
        for tc in r["tool_calls"]:
            if tc["name"] == "submit_fix":
                prop = tc["arguments"]
                if use_verifier:
                    ok, why = verify(prop, tb, spec=component.get("declared_range"), ts=context.get("timestamp"))
                else:
                    ok, why = True, "verifier disabled"
                final = {"proposal": prop, "accepted": ok, "reason": why, "steps": steps, "toolbox": tb}
                if ok or retries >= 1:
                    done = True
                    msgs.append({"role": "tool", "tool_call_id": tc["id"], "content": json.dumps({"status": why})})
                else:
                    retries += 1
                    msgs.append({"role": "tool", "tool_call_id": tc["id"],
                                 "content": json.dumps({"status": "REJECTED by verifier", "reason": why})})
            else:
                if tb.calls >= max_steps:
                    out = json.dumps({"error": "tool budget exhausted; call submit_fix now"})
                else:
                    out = tb.run(tc["name"], tc["arguments"])
                msgs.append({"role": "tool", "tool_call_id": tc["id"], "content": out})
        if done:
            break
    final["steps"] = steps
    return final
