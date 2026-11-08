"""Paired comparisons on identical sample subsets (LLM methods ran on stratified subsets) + Wilcoxon tests + figures."""
from __future__ import annotations
import math
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import wilcoxon
from vera import config
from bench.analysis import short, boot_ci, PAL

R, F = config.RESULTS, config.FIGURES
COLS = ["vuln_p", "vuln_r", "vuln_f1", "vuln_r_sev", "vuln_r_high", "vuln_brier", "exact_f1", "comp_f1",
        "defective_fixed", "hallucination", "seconds", "llm_calls", "llm_prompt_tokens", "llm_completion_tokens"]


def load(exp):
    df = pd.read_csv(R / f"{exp}.csv")
    df = df[df["error"].isna()].copy()
    df["method"] = df["method"].map(short)
    df["degrade"] = df["degrade"].fillna("natural")
    df["key"] = df["eco"] + "/" + df["sample"] + "/" + df["seed"].astype(str) + "/" + df["degrade"]
    return df


def paired(df, methods, anchor, ref, name, title):
    """Restrict every method to the samples on which `anchor` ran; test `ref` vs others (paired Wilcoxon on vuln F1)."""
    keys = set(df[df.method == anchor]["key"])
    sub = df[df.key.isin(keys) & df.method.isin(methods)]
    # keep only keys present for every method
    cnt = sub.groupby("key")["method"].nunique()
    full = set(cnt[cnt == len(methods)].index)
    sub = sub[sub.key.isin(full)]
    rows = []
    piv = sub.pivot_table(index="key", columns="method", values="vuln_f1")
    for m in methods:
        g = sub[sub.method == m]
        r = {"method": m, "n": len(g)}
        for c in COLS:
            if c in g:
                r[c] = g[c].mean()
        lo, hi = boot_ci(g["vuln_f1"])
        r["vuln_f1_ci95"] = f"[{lo:.2f}, {hi:.2f}]"
        if m != ref and ref in piv and m in piv:
            d = piv[ref] - piv[m]
            r["p_wilcoxon_vs_" + ref] = wilcoxon(piv[ref], piv[m]).pvalue if (d != 0).sum() >= 5 else float("nan")
        rows.append(r)
    t = pd.DataFrame(rows)
    t.to_csv(R / f"table_{name}.csv", index=False)
    print(f"\n### {title}  (n = {len(full)} cặp mẫu)")
    show = ["method", "n", "vuln_p", "vuln_r", "vuln_f1", "vuln_f1_ci95", "vuln_r_high", "exact_f1", "comp_f1",
            "hallucination", "seconds", "llm_calls"] + [c for c in t.columns if c.startswith("p_wilcoxon")]
    print(t[[c for c in show if c in t]].round(3).to_string(index=False))
    # per-ecosystem vuln F1
    pe = sub.groupby(["method", "eco"])["vuln_f1"].mean().unstack().reindex(methods).round(3)
    pe.to_csv(R / f"table_{name}_by_eco.csv")
    print(pe.to_string())
    return t, pe


def bar(pe: pd.DataFrame, fname: str, title: str):
    ecos = list(pe.columns)
    methods = list(pe.index)
    fig, ax = plt.subplots(figsize=(1.6 + 1.4 * len(ecos), 3.2))
    w = 0.8 / len(methods)
    for i, m in enumerate(methods):
        ax.bar(np.arange(len(ecos)) + i * w, pe.loc[m].values, w, label=m, color=PAL[i % len(PAL)])
    ax.set_xticks(np.arange(len(ecos)) + 0.4 - w / 2, ecos)
    ax.set_ylim(0, 1.05); ax.set_ylabel("vuln F1"); ax.set_title(title, fontsize=9)
    ax.legend(fontsize=6, ncol=2, loc="upper left", bbox_to_anchor=(1.0, 1.0))
    fig.tight_layout(); fig.savefig(F / fname, bbox_inches="tight"); plt.close(fig)


def cost_quality(tables: list[tuple[str, pd.DataFrame]]):
    """RQ4 scatter: quality vs LLM tokens per SBOM."""
    fig, ax = plt.subplots(figsize=(5.4, 3.6))
    seen = set()
    pts = []
    for lab, t in tables:  # first table = main Qwen subset; later tables only add methods not seen yet
        for _, r in t.iterrows():
            if r["method"] in seen:
                continue
            seen.add(r["method"])
            tok = (r.get("llm_prompt_tokens", 0) or 0) + (r.get("llm_completion_tokens", 0) or 0)
            pts.append((r["method"], max(tok, 50), r["vuln_f1"], lab))
    for i, (m, x, y, lab) in enumerate(pts):
        c = PAL[2] if m.startswith("VERA") else PAL[3] if m[:2] in ("B3", "B4") else PAL[0]
        ax.scatter(x, y, color=c, s=36, zorder=3)
        dy = -9 if "Opus" in m else 3
        ax.annotate(f"{m} ({lab})", (x, y), fontsize=6, xytext=(4, dy), textcoords="offset points")
    ax.set_xscale("log"); ax.set_xlabel("token LLM / SBOM (log; 50 = không dùng LLM)"); ax.set_ylabel("vuln F1")
    ax.set_title("RQ4 – Chất lượng vs chi phí LLM", fontsize=9)
    fig.tight_layout(); fig.savefig(F / "rq4_cost_quality.png"); plt.close(fig)


def main():
    nat = load("main_natural")
    Q, O = "@Qwen3.6-35B", "@Opus5"
    t1, pe1 = paired(nat, ["B0", "B1-ts", "B2", "B3" + Q, "VERA-noLLM", "VERA" + Q], "B3" + Q, "VERA" + Q,
                     "paired_natural_qwen", "SBOM lỗi tự nhiên — tập con Qwen")
    bar(pe1, "paired_natural_qwen.png", "SBOM lỗi tự nhiên: vuln F1 (cặp mẫu, Qwen3.6-35B)")
    t2, pe2 = paired(nat, ["B2", "B3" + O, "VERA-noLLM", "VERA" + O], "B3" + O, "VERA" + O,
                     "paired_natural_opus", "SBOM lỗi tự nhiên — tập con Opus 5")
    t3, pe3 = paired(nat, ["B2", "B4" + Q, "VERA-noLLM", "VERA" + Q], "B4" + Q, "VERA" + Q,
                     "paired_natural_b4", "SBOM lỗi tự nhiên — so với ReAct agent tổng quát (B4)")
    t3b, _ = paired(nat, ["B4" + O, "VERA" + O, "VERA-noLLM"], "B4" + O, "VERA" + O,
                    "paired_natural_b4_opus", "B4@Opus5 vs VERA@Opus5")
    t4, _ = paired(nat, ["B2", "VERA-noLLM"], "B2", "VERA-noLLM", "paired_natural_symbolic",
                   "SBOM lỗi tự nhiên — toàn bộ tập test (phương pháp không LLM)")
    hv = load("degraded_heavy")
    t5, pe5 = paired(hv, ["B0", "B1-ts", "B3" + Q, "VERA-noLLM", "VERA@Qwen3.5-35B", "VERA@Qwen3.5-122B", "VERA" + Q],
                     "VERA" + Q, "VERA" + Q, "paired_heavy_qwen", "SBOM suy giảm nặng — tập con Qwen (so sánh model)")
    bar(pe5, "paired_heavy.png", "SBOM suy giảm nặng: vuln F1 (cặp mẫu)")
    t6, _ = paired(hv, ["B1-ts", "B3" + O, "VERA-noLLM", "VERA" + O, "VERA" + Q], "VERA" + O, "VERA" + O,
                   "paired_heavy_opus", "SBOM suy giảm nặng — tập con Opus 5")
    md = load("degraded_medium")
    paired(md, ["B0", "B1-ts", "VERA-noLLM", "VERA" + Q], "VERA" + Q, "VERA" + Q, "paired_medium_qwen",
           "SBOM suy giảm trung bình — tập con Qwen")
    lt = load("degraded_light")
    paired(lt, ["B0", "B1-ts", "VERA-noLLM"], "VERA-noLLM", "VERA-noLLM", "paired_light", "SBOM suy giảm nhẹ — toàn bộ test")
    paired(md, ["B0", "B1-ts", "VERA-noLLM"], "VERA-noLLM", "VERA-noLLM", "paired_medium_all", "SBOM suy giảm trung bình — toàn bộ test")
    paired(hv, ["B0", "B1-ts", "VERA-noLLM"], "VERA-noLLM", "VERA-noLLM", "paired_heavy_all", "SBOM suy giảm nặng — toàn bộ test")
    ct = load("containers")
    for lv in ("medium", "heavy"):
        sub = ct[ct.degrade == lv]
        ms = ["B0", "B1-ts", "VERA-noLLM"] + (["VERA" + Q] if lv == "heavy" else [])
        paired(sub, ms, ms[-1], ms[-1], f"paired_containers_{lv}", f"Container — suy giảm {lv}")
    ab = load("ablation_llm")
    paired(ab, ["VERA" + Q, "VERA-noVerifier" + Q, "VERA-noVUG" + Q], "VERA" + Q, "VERA" + Q, "paired_ablation_llm",
           "Ablation phần LLM (suy giảm nặng)")
    cost_quality([("n=36", t1), ("n=18", t2), ("n=18", t3)])


if __name__ == "__main__":
    main()
