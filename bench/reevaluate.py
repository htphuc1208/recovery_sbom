"""Re-evaluate every finished run with the current metrics by replaying the method from cache
(VERA_OFFLINE=1: all HTTP + LLM answers come from data/cache; demonstrates reproducibility)."""
from __future__ import annotations
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
import pandas as pd
from vera import config, sbom_io, vuln
from bench.common import BENCH
from bench.degrade import degrade
from bench.metrics import evaluate
from bench.run_experiments import method_fn, RUNS


def one(path: str):
    row = json.loads(Path(path).read_text())
    if row.get("error"):
        return path, None
    tag = row["method"]
    m, model = (tag.split("@", 1) + [None])[:2]
    eco, sample, seed, lv = row["eco"], row["sample"], int(row["seed"]), row.get("degrade")
    lv = None if (lv is None or (isinstance(lv, float))) else lv
    d = BENCH / ("B" if eco == "container" else "A") / ("" if eco == "container" else eco) / sample
    truth = sbom_io.load(d / "truth.json")
    if lv:
        bad, _ = degrade(truth, lv, seed)
        bad.metadata["timestamp"] = truth.metadata.get("timestamp")
    else:
        bad = sbom_io.load(d / "bad_manifest.json")
    try:
        pred, _ = method_fn(m, model)(bad)
    except Exception as e:  # cache miss etc.
        return path, f"replay failed: {e}"[:200]
    met = evaluate(pred, truth, bad, check_hallucination=True)
    changed = {k: (row.get(k), v) for k, v in met.items() if isinstance(v, float) and row.get(k) is not None
               and abs((row.get(k) or 0) - v) > 1e-6}
    row.update(met)
    row["reevaluated"] = True
    Path(path).write_text(json.dumps(row))
    return path, changed


if __name__ == "__main__":
    os.environ.setdefault("VERA_OFFLINE", "1")
    files = sorted(str(p) for p in RUNS.rglob("*.json") if not p.name.endswith(".traces.json"))
    if len(sys.argv) > 1:
        files = [f for f in files if any(s in f for s in sys.argv[1:])]
    n_changed = 0
    with ProcessPoolExecutor(4) as ex:
        for path, ch in ex.map(one, files, chunksize=4):
            if isinstance(ch, str):
                print("!!", path, ch)
            elif ch:
                n_changed += 1
                keys = sorted(ch)
                if set(keys) - {"hallucination"}:
                    print("changed", Path(path).parent.name, Path(path).name, {k: ch[k] for k in keys[:4]})
    print("runs with changed metrics:", n_changed, "/", len(files))
    # rebuild per-experiment CSVs from run files
    rows = {}
    for p in RUNS.rglob("*.json"):
        if p.name.endswith(".traces.json"):
            continue
        r = json.loads(p.read_text())
        rows.setdefault(r["exp"], []).append(r)
    for exp, rs in rows.items():
        pd.DataFrame(rs).to_csv(config.RESULTS / f"{exp}.csv", index=False)
        print("wrote", exp, len(rs))
