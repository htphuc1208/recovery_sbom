"""Run methods over benchmark samples and write per-sample metrics to results/<exp>.csv"""
from __future__ import annotations
import argparse
import hashlib
import json
import time
import traceback
from pathlib import Path
import pandas as pd
from vera import sbom_io, vuln, config
from vera.pipeline import repair as vera_repair, VeraConfig
from vera.baselines import b1_heuristic, b2_regen, b3_llm_zeroshot, b4_react
from vera.agent import llm_client
from vera.evidence import http as vhttp
from bench.common import BENCH
from bench.metrics import evaluate
from bench.degrade import degrade

RUNS = config.RESULTS / "runs"


def samples(sets=("npm", "pypi", "maven"), split="all"):
    out = []
    for e in sets:
        base = BENCH / ("B" if e == "container" else "A") / ("" if e == "container" else e)
        for d in sorted(p for p in base.iterdir() if (p / "truth.json").exists()):
            if e == "container" and not (d / "meta.json").exists():
                continue
            h = int(hashlib.md5(d.name.encode()).hexdigest(), 16) % 4
            if split == "dev" and h != 0 or split == "test" and h == 0:
                continue
            out.append((e, d))
    return out


def method_fn(name: str, model: str | None):
    """returns f(bad_sbom) -> (pred_sbom, extra_stats)"""
    if name == "B0":
        return lambda s: (s, {})
    if name == "B1-latest":
        return lambda s: (b1_heuristic.repair(s, respect_timestamp=False), {})
    if name == "B1-ts":
        return lambda s: (b1_heuristic.repair(s, respect_timestamp=True), {})
    if name == "B2":
        def f(s):
            p, st = b2_regen.repair(s)
            return p, {"status": st}
        return f
    if name == "B3":
        return lambda s: (b3_llm_zeroshot.repair(s, model), {})
    if name == "B4":
        def f(s):
            p, st = b4_react.repair(s, model)
            return p, st
        return f
    if name.startswith("VERA"):
        cfg = VeraConfig(model=model)
        opts = name.split("-")[1:]  # e.g. VERA-noLLM-noTemporal
        for o in opts:
            if o == "noLLM": cfg.use_llm = False
            if o == "noTemporal": cfg.use_temporal = False
            if o == "noAnchor": cfg.use_anchor = False
            if o == "noCo": cfg.use_coconstraints = False
            if o == "noGraph": cfg.use_graph = False
            if o == "noVerifier": cfg.use_verifier = False
            if o == "noVUG": cfg.use_vug = False
            if o.startswith("b") and o[1:].isdigit(): cfg.budget = int(o[1:])
            if o.startswith("mu") and o[2:].isdigit(): cfg.mu_days = float(o[2:])
            if o == "graphAlways": cfg.graph_mode = "always"
        def f(s):
            r = vera_repair(s, cfg)
            return r.sbom, {**r.stats, "agent_traces": r.agent_traces, "log": r.log}
        return f
    raise ValueError(name)


def run(exp: str, methods: list[str], sets, model: str | None, split: str = "all", degrade_level: str | None = None,
        limit: int | None = None, seeds=(0,)):
    rows = []
    todo = samples(sets, split)
    if limit:
        # stratified limit per ecosystem
        by = {}
        for e, d in todo:
            by.setdefault(e, []).append((e, d))
        todo = [x for v in by.values() for x in v[:limit]]
    for eco, d in todo:
        truth = sbom_io.load(d / "truth.json")
        tf = {(f.component, f.vuln): f.severity for f in vuln.scan(truth, probabilistic=False)}
        for seed in (seeds if degrade_level else (0,)):
            if degrade_level:
                bad, dlog = degrade(truth, degrade_level, seed)
                bad.metadata["timestamp"] = truth.metadata.get("timestamp")
            else:
                bad = sbom_io.load(d / "bad_manifest.json")
                dlog = {}
            for m in methods:
                tag = m + (f"@{model}" if model and (m in ("B3", "B4") or (m.startswith("VERA") and "noLLM" not in m)) else "")
                out = RUNS / exp / tag.replace("/", "_") / f"{eco}__{d.name}__{degrade_level or 'natural'}__s{seed}.json"
                if out.exists():
                    rows.append(json.loads(out.read_text()))
                    continue
                llm_client.reset_usage()
                net0 = vhttp.STATS["network"] + vhttp.STATS["cache"]
                t0 = time.time()
                try:
                    pred, extra = method_fn(m, model)(bad)
                    met = evaluate(pred, truth, bad, check_hallucination=True, truth_findings=tf)
                    err = None
                except Exception as e:
                    traceback.print_exc()
                    met, extra, err = {}, {}, str(e)[:300]
                usage = {k: sum(u[k] for u in llm_client.USAGE.values()) for k in ("calls", "prompt", "completion")} if llm_client.USAGE else {}
                row = {"exp": exp, "method": tag, "eco": eco, "sample": d.name, "seed": seed, "degrade": degrade_level,
                       "seconds": time.time() - t0, "evidence_calls": vhttp.STATS["network"] + vhttp.STATS["cache"] - net0,
                       "llm_calls": usage.get("calls", 0), "llm_prompt_tokens": usage.get("prompt", 0),
                       "llm_completion_tokens": usage.get("completion", 0), "error": err,
                       **{k: v for k, v in met.items()},
                       **{f"x_{k}": v for k, v in extra.items() if isinstance(v, (int, float, str))},
                       **{f"d_{k}": v for k, v in dlog.items()}}
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(row))
                if extra.get("agent_traces"):
                    (out.parent / (out.stem + ".traces.json")).write_text(json.dumps(extra["agent_traces"], default=str, indent=1))
                rows.append(row)
                print(f"[{exp}] {tag:28s} {eco:6s} {d.name[:40]:40s} vulnF1={met.get('vuln_f1', float('nan')):.2f} "
                      f"R={met.get('vuln_r', float('nan')):.2f} P={met.get('vuln_p', float('nan')):.2f} "
                      f"exactF1={met.get('exact_f1', float('nan')):.2f} t={row['seconds']:.0f}s", flush=True)
    df = pd.DataFrame(rows)
    path = config.RESULTS / f"{exp}.csv"
    if path.exists():
        old = pd.read_csv(path)
        df = pd.concat([old, df]).drop_duplicates(subset=["method", "eco", "sample", "seed", "degrade"], keep="last")
    df.to_csv(path, index=False)
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("exp")
    ap.add_argument("--methods", required=True)
    ap.add_argument("--sets", default="npm,pypi,maven")
    ap.add_argument("--model", default=None)
    ap.add_argument("--split", default="all")
    ap.add_argument("--degrade", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--seeds", default="0")
    a = ap.parse_args()
    df = run(a.exp, a.methods.split(","), a.sets.split(","), a.model, a.split, a.degrade, a.limit,
             tuple(int(x) for x in a.seeds.split(",")))
    cols = ["comp_f1", "exact_f1", "version_acc", "defective_fixed", "vuln_p", "vuln_r", "vuln_f1", "vuln_r_any", "hallucination", "seconds", "llm_calls"]
    print(df.groupby(["method", "eco"])[[c for c in cols if c in df]].mean().round(3).to_string())
