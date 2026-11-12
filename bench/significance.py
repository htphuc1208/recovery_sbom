"""Micro-averaged vuln P/R/F1 (pooled TP/pred/truth) and Holm–Bonferroni correction of the paired Wilcoxon tests
cited in the report (both over all comparisons and within each research-question family).

    .venv/bin/python -m bench.significance   ->  results/table_micro.csv, results/table_holm.csv
"""
from __future__ import annotations
import numpy as np
import pandas as pd
from scipy.stats import wilcoxon
from vera import config
from bench.paired_tables import load

R = config.RESULTS
Q, O = "@Qwen3.6-35B", "@Opus5"


def holm(p) -> np.ndarray:
    p = np.asarray(p, float); m = len(p); adj = np.empty(m); run = 0.0
    for rank, i in enumerate(np.argsort(p)):
        run = max(run, min(1.0, (m - rank) * p[i])); adj[i] = run
    return adj


def micro():
    rows = []
    for exp, meths in [("main_natural", ["B0", "B1-latest", "B1-ts", "B2", "VERA-noLLM"]),
                       ("degraded_heavy", ["B0", "B1-ts", "VERA-noLLM"])]:
        df = load(exp)
        df["tp"] = df.n_vuln_truth - df.vuln_fn
        for eco in ["all", "maven", "npm", "pypi"]:
            for m in meths:
                g = df[(df.method == m) & ((df.eco == eco) | (eco == "all"))]
                tp, npred, ntrue = g.tp.sum(), g.n_vuln_pred.sum(), g.n_vuln_truth.sum()
                p, r = tp / npred, tp / ntrue
                rows.append(dict(exp=exp, eco=eco, method=m, n=len(g), macro_f1=g.vuln_f1.mean(), micro_p=p,
                                 micro_r=r, micro_f1=2 * p * r / (p + r), tp=tp, n_pred=npred, n_truth=ntrue))
    t = pd.DataFrame(rows); t.to_csv(R / "table_micro.csv", index=False)
    print(t.round(3).to_string(index=False))


def paired_p(df, a, b, anchor, methods):
    keys = set(df[df.method == anchor].key)
    sub = df[df.key.isin(keys) & df.method.isin(methods)]
    cnt = sub.groupby("key").method.nunique()
    piv = sub[sub.key.isin(cnt[cnt == len(methods)].index)].pivot_table(index="key", columns="method", values="vuln_f1")
    return len(piv), piv[a].mean(), piv[b].mean(), wilcoxon(piv[a], piv[b]).pvalue


def corrected():
    D = {e: load(e) for e in ["main_natural", "degraded_heavy", "degraded_medium", "degraded_light", "containers"]}
    D["containers"] = D["containers"][D["containers"].degrade == "heavy"]
    NQ = ["B0", "B1-ts", "B2", "B3" + Q, "VERA-noLLM", "VERA" + Q]
    NO = ["B2", "B3" + O, "VERA-noLLM", "VERA" + O]
    HQ = ["B0", "B1-ts", "B3" + Q, "VERA-noLLM", "VERA@Qwen3.5-35B", "VERA@Qwen3.5-122B", "VERA" + Q]
    HO = ["B1-ts", "B3" + O, "VERA-noLLM", "VERA" + O, "VERA" + Q]
    CQ = ["B0", "B1-ts", "VERA-noLLM", "VERA" + Q]
    F1, F2, F3, F4, F5 = ("RQ2/3: tự nhiên, ký hiệu", "RQ4: tự nhiên, LLM", "Suy giảm, ký hiệu",
                          "Suy giảm nặng, LLM", "Container mất distro")
    C = [(F1, "main_natural", "VERA-noLLM", "B2", "B2", ["B2", "VERA-noLLM"]),
         (F1, "main_natural", "VERA-noLLM", "B1-ts", "B1-ts", ["B1-ts", "VERA-noLLM"]),
         (F2, "main_natural", "VERA" + Q, "B2", "B3" + Q, NQ),
         (F2, "main_natural", "VERA" + Q, "B3" + Q, "B3" + Q, NQ),
         (F2, "main_natural", "VERA" + O, "B2", "B3" + O, NO),
         (F2, "main_natural", "VERA" + O, "B3" + O, "B3" + O, NO),
         (F2, "main_natural", "VERA" + Q, "B4" + Q, "B4" + Q, ["B2", "B4" + Q, "VERA-noLLM", "VERA" + Q]),
         (F2, "main_natural", "VERA" + O, "B4" + O, "B4" + O, ["B4" + O, "VERA" + O, "VERA-noLLM"]),
         (F3, "degraded_light", "VERA-noLLM", "B1-ts", "B1-ts", ["B1-ts", "VERA-noLLM"]),
         (F3, "degraded_medium", "VERA-noLLM", "B1-ts", "B1-ts", ["B1-ts", "VERA-noLLM"]),
         (F3, "degraded_heavy", "VERA-noLLM", "B1-ts", "B1-ts", ["B1-ts", "VERA-noLLM"]),
         (F4, "degraded_heavy", "VERA" + Q, "VERA-noLLM", "VERA" + Q, HQ),
         (F4, "degraded_heavy", "VERA" + Q, "B3" + Q, "VERA" + Q, HQ),
         (F4, "degraded_heavy", "VERA@Qwen3.5-122B", "VERA-noLLM", "VERA" + Q, HQ),
         (F4, "degraded_heavy", "VERA" + O, "VERA-noLLM", "VERA" + O, HO),
         (F4, "degraded_heavy", "VERA" + O, "B3" + O, "VERA" + O, HO),
         (F5, "containers", "VERA" + Q, "VERA-noLLM", "VERA" + Q, CQ),
         (F5, "containers", "VERA" + Q, "B1-ts", "VERA" + Q, CQ)]
    rows = []
    for fam, exp, a, b, anchor, ms in C:
        n, fa, fb, p = paired_p(D[exp], a, b, anchor, ms)
        rows.append(dict(family=fam, exp=exp, a=a, b=b, n=n, f1_a=fa, f1_b=fb, p=p))
    t = pd.DataFrame(rows)
    t["p_holm_all"] = holm(t.p)
    t["p_holm_family"] = t.groupby("family", sort=False).p.transform(lambda s: holm(s.values))
    t.to_csv(R / "table_holm.csv", index=False)
    print(t.round(4).to_string(index=False))


if __name__ == "__main__":
    pd.set_option("display.width", 250)
    micro()
    corrected()
