"""Aggregate results -> tables (results/table_*.csv) + figures (figures/*.png) + stats tests."""
from __future__ import annotations
import glob
import json
import math
from collections import Counter
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import wilcoxon
from vera import config, sbom_io, quality, vuln
from bench.common import BENCH

R, F = config.RESULTS, config.FIGURES
plt.rcParams.update({"figure.dpi": 130, "font.size": 9, "axes.spines.top": False, "axes.spines.right": False})
PAL = ["#4C72B0", "#DD8452", "#55A868", "#C44E52", "#8172B3", "#937860", "#DA8BC3", "#8C8C8C", "#CCB974", "#64B5CD"]


def boot_ci(x, n=2000, seed=0):
    x = np.asarray([v for v in x if not (isinstance(v, float) and math.isnan(v))])
    if len(x) == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    m = rng.choice(x, (n, len(x))).mean(1)
    return float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))


def short(m):
    return m.replace("@Qwen/Qwen3.6-35B-A3B-FP8", "@Qwen3.6-35B").replace("@Qwen/Qwen3.5-122B-A10B-FP8", "@Qwen3.5-122B") \
            .replace("@Qwen/Qwen3.5-35B-A3B-FP8", "@Qwen3.5-35B").replace("@claude-opus-5", "@Opus5")


# ------------------------------------------------------------------ RQ1
def rq1_survey():
    rows = []
    for f in glob.glob(str(BENCH / "survey" / "*" / "*.json")):
        lang = Path(f).parent.name
        s = sbom_io.load(json.loads(Path(f).read_text()))
        if not s.components:
            continue
        q = quality.summary(s)
        n = q["components"]
        d = q["defects"]
        rows.append({"source": "GitHub dependency graph", "group": lang, "repo": Path(f).stem, "components": n,
                     "missing_version": d.get("MISSING_VERSION", 0) / n, "range_version": d.get("RANGE_VERSION", 0) / n,
                     "missing_purl": (d.get("MISSING_PURL", 0) + d.get("INVALID_PURL", 0)) / n,
                     "missing_license": d.get("MISSING_LICENSE", 0) / n, "missing_hash": d.get("MISSING_HASH", 0) / n,
                     "missing_supplier": d.get("MISSING_SUPPLIER", 0) / n,
                     "no_transitive": float("SUSPECTED_MISSING_TRANSITIVE" in q["sbom_defects"]),
                     "ntia": q["ntia"]["overall"], "vuln_readiness": q["vuln_readiness"]})
    for eco in ("npm", "pypi", "maven"):
        for d in sorted((BENCH / "A" / eco).iterdir()):
            if not (d / "bad_manifest.json").exists():
                continue
            s = sbom_io.load(d / "bad_manifest.json")
            t = sbom_io.load(d / "truth.json")
            q = quality.summary(s)
            n = max(q["components"], 1)
            dd = q["defects"]
            T = {(f.component, f.vuln) for f in vuln.scan(t, False)}
            B = {(f.component, f.vuln) for f in vuln.scan(s, False)}
            rows.append({"source": "manifest-only (dataset A)", "group": eco, "repo": d.name, "components": q["components"],
                         "truth_components": len(t.components),
                         "missing_version": dd.get("MISSING_VERSION", 0) / n, "range_version": dd.get("RANGE_VERSION", 0) / n,
                         "missing_purl": (dd.get("MISSING_PURL", 0) + dd.get("INVALID_PURL", 0) + dd.get("MISSING_GROUP", 0)) / n,
                         "missing_license": dd.get("MISSING_LICENSE", 0) / n, "missing_hash": dd.get("MISSING_HASH", 0) / n,
                         "missing_supplier": dd.get("MISSING_SUPPLIER", 0) / n,
                         "no_transitive": float("SUSPECTED_MISSING_TRANSITIVE" in q["sbom_defects"]),
                         "ntia": q["ntia"]["overall"], "vuln_readiness": q["vuln_readiness"],
                         "truth_vulns": len(T), "vulns_found_by_bad": len(B & T),
                         "vuln_recall_bad": (len(B & T) / len(T)) if T else float("nan")})
    df = pd.DataFrame(rows)
    df.to_csv(R / "rq1_per_sbom.csv", index=False)
    agg = df.groupby(["source", "group"]).agg(n=("repo", "count"), components=("components", "median"),
                                              missing_version=("missing_version", "mean"), range_version=("range_version", "mean"),
                                              missing_purl=("missing_purl", "mean"), missing_license=("missing_license", "mean"),
                                              missing_hash=("missing_hash", "mean"), no_transitive=("no_transitive", "mean"),
                                              ntia=("ntia", "mean"), vuln_readiness=("vuln_readiness", "mean")).round(3)
    if "truth_vulns" in df:
        a2 = df.groupby(["source", "group"]).agg(truth_vulns=("truth_vulns", "sum"), found_by_bad=("vulns_found_by_bad", "sum"))
        agg = agg.join(a2)
        agg["vuln_recall_bad"] = (agg["found_by_bad"] / agg["truth_vulns"]).round(3)
    agg.reset_index().to_csv(R / "table_rq1_survey.csv", index=False)
    print(agg.to_string())
    # figure
    fig, ax = plt.subplots(figsize=(7, 3))
    cols = ["missing_version", "range_version", "missing_purl", "missing_license", "no_transitive"]
    sub = agg[cols]
    x = np.arange(len(cols))
    w = 0.8 / max(len(sub), 1)
    for i, (idx, r) in enumerate(sub.iterrows()):
        ax.bar(x + i * w, r.values, w, label=f"{idx[0][:18]}·{idx[1]}", color=PAL[i % len(PAL)])
    ax.set_xticks(x + 0.4 - w / 2, ["thiếu version", "version là range", "thiếu/sai PURL", "thiếu license", "thiếu transitive"])
    ax.set_ylabel("tỉ lệ"); ax.legend(fontsize=6, ncol=2); ax.set_title("RQ1 – Tỉ lệ lỗi trong SBOM thực tế")
    fig.tight_layout(); fig.savefig(F / "rq1_defects.png"); plt.close(fig)
    return df


# ------------------------------------------------------------------ main comparison
METRICS = ["vuln_p", "vuln_r", "vuln_f1", "vuln_r_sev", "vuln_r_high", "vuln_r_any", "vuln_brier", "comp_f1", "exact_f1",
           "version_acc", "defective_fixed", "ntia", "vuln_readiness", "hallucination", "seconds", "evidence_calls", "llm_calls",
           "llm_prompt_tokens", "llm_completion_tokens"]


def main_table(exp: str, ref: str | None = None, name: str | None = None):
    p = R / f"{exp}.csv"
    if not p.exists():
        return None
    df = pd.read_csv(p)
    df = df[df["error"].isna()] if "error" in df else df
    df["method"] = df["method"].map(short)
    cols = [c for c in METRICS if c in df]
    rows = []
    for (m, e), g in df.groupby(["method", "eco"]):
        r = {"method": m, "eco": e, "n": len(g)}
        for c in cols:
            r[c] = g[c].mean()
        lo, hi = boot_ci(g["vuln_f1"])
        r["vuln_f1_ci"] = f"[{lo:.2f}, {hi:.2f}]"
        rows.append(r)
    for m, g in df.groupby("method"):
        r = {"method": m, "eco": "ALL", "n": len(g)}
        for c in cols:
            r[c] = g[c].mean()
        lo, hi = boot_ci(g["vuln_f1"])
        r["vuln_f1_ci"] = f"[{lo:.2f}, {hi:.2f}]"
        rows.append(r)
    t = pd.DataFrame(rows)
    # paired Wilcoxon vs reference method
    if ref:
        ref = short(ref)
        piv = df.pivot_table(index=["eco", "sample", "seed"], columns="method", values="vuln_f1")
        pv = {}
        for m in piv.columns:
            if m == ref or ref not in piv:
                continue
            pair = piv[[ref, m]].dropna()
            d = pair[ref] - pair[m]
            if len(pair) >= 5 and (d != 0).any():
                pv[m] = wilcoxon(pair[ref], pair[m]).pvalue
        t["p_vs_ref"] = t["method"].map(pv)
    t = t.round(3)
    t.to_csv(R / f"table_{name or exp}.csv", index=False)
    return t


def bar_figure(t: pd.DataFrame, fname: str, title: str, metric="vuln_f1", order=None):
    if t is None:
        return
    ecos = [e for e in ("npm", "pypi", "maven", "container", "ALL") if e in set(t["eco"])]
    methods = order or list(dict.fromkeys(t["method"]))
    methods = [m for m in methods if m in set(t["method"])]
    fig, ax = plt.subplots(figsize=(max(6, 1.2 * len(ecos) * len(methods) / 3), 3.2))
    w = 0.8 / len(methods)
    for i, m in enumerate(methods):
        vals = [t[(t.method == m) & (t.eco == e)][metric].mean() for e in ecos]
        ax.bar(np.arange(len(ecos)) + i * w, vals, w, label=m, color=PAL[i % len(PAL)])
    ax.set_xticks(np.arange(len(ecos)) + 0.4 - w / 2, ecos)
    ax.set_ylim(0, 1.05); ax.set_ylabel(metric); ax.set_title(title)
    ax.legend(fontsize=6, ncol=3, loc="upper left", bbox_to_anchor=(0, -0.12))
    fig.tight_layout(); fig.savefig(F / fname, bbox_inches="tight"); plt.close(fig)


def budget_curve(exp="rq5_budget"):
    p = R / f"{exp}.csv"
    if not p.exists():
        return
    df = pd.read_csv(p)
    df["method"] = df["method"].map(short)
    df["budget"] = df["method"].str.extract(r"-b(\d+)").astype(float)
    df["order"] = np.where(df["method"].str.contains("noVUG"), "FIFO (không VUG)", "VUG")
    g = df.groupby(["order", "budget"])[["vuln_f1", "vuln_r", "llm_calls"]].mean().reset_index()
    g.to_csv(R / "table_rq5_budget.csv", index=False)
    fig, ax = plt.subplots(figsize=(4.5, 3))
    for i, (o, gg) in enumerate(g.groupby("order")):
        ax.plot(gg["budget"], gg["vuln_f1"], marker="o", label=o, color=PAL[i])
    ax.set_xlabel("ngân sách agent (số task LLM / SBOM)"); ax.set_ylabel("vuln F1"); ax.set_xscale("symlog")
    ax.set_title("RQ5 – Hiệu quả ngân sách"); ax.legend()
    fig.tight_layout(); fig.savefig(F / "rq5_budget_curve.png"); plt.close(fig)


def calibration(exp="main_natural", method_prefix="VERA"):
    """Reliability of probabilistic findings: bin predicted prob vs empirical precision."""
    import glob as _g
    rows = []
    from vera.pipeline import repair, VeraConfig
    # cheap: recompute on dev samples with symbolic VERA
    from bench.run_experiments import samples
    for eco, d in samples(("npm", "pypi"), "test")[:30]:
        t = sbom_io.load(d / "truth.json"); b = sbom_io.load(d / "bad_manifest.json")
        T = {(f.component, f.vuln) for f in vuln.scan(t, False)}
        pred = repair(b, VeraConfig(use_llm=False, fill_licenses=False)).sbom
        for f in vuln.scan(pred):
            rows.append({"p": f.prob, "y": (f.component, f.vuln) in T})
    df = pd.DataFrame(rows)
    if df.empty:
        return
    df["bin"] = pd.cut(df["p"], [0, .2, .4, .6, .8, .95, 1.0001], include_lowest=True)
    g = df.groupby("bin", observed=True).agg(p=("p", "mean"), y=("y", "mean"), n=("y", "size")).reset_index()
    g.to_csv(R / "table_calibration.csv", index=False)
    fig, ax = plt.subplots(figsize=(3.6, 3.2))
    ax.plot([0, 1], [0, 1], "--", color="#999")
    ax.plot(g["p"], g["y"], marker="o", color=PAL[0])
    for _, r in g.iterrows():
        ax.annotate(str(int(r["n"])), (r["p"], r["y"]), fontsize=6, xytext=(3, -8), textcoords="offset points")
    ax.set_xlabel("xác suất dự đoán"); ax.set_ylabel("tỉ lệ đúng thực tế"); ax.set_title("Độ hiệu chỉnh báo cáo lỗ hổng xác suất")
    fig.tight_layout(); fig.savefig(F / "calibration.png"); plt.close(fig)


if __name__ == "__main__":
    import sys
    what = sys.argv[1:] or ["rq1", "main", "degraded", "ablation", "budget", "calibration"]
    if "rq1" in what:
        rq1_survey()
    ORDER = ["B0", "B1-latest", "B1-ts", "B2", "B3@Qwen3.6-35B", "B3@Opus5", "B4@Qwen3.6-35B", "B4@Opus5",
             "VERA-noLLM", "VERA@Qwen3.6-35B", "VERA@Qwen3.5-122B", "VERA@Qwen3.5-35B", "VERA@Opus5"]
    if "main" in what:
        t = main_table("main_natural", ref="VERA@Qwen/Qwen3.6-35B-A3B-FP8", name="main_natural")
        if t is not None:
            print(t[["method", "eco", "n", "vuln_p", "vuln_r", "vuln_f1", "vuln_f1_ci", "exact_f1", "comp_f1", "hallucination", "seconds", "llm_calls"]].to_string())
            bar_figure(t, "rq2_rq3_vuln_f1.png", "RQ3 – F1 phát hiện lỗ hổng sau khôi phục (SBOM lỗi tự nhiên)", order=ORDER)
            bar_figure(t, "rq2_exact_f1.png", "RQ2 – F1 khôi phục component@version", "exact_f1", order=ORDER)
    if "degraded" in what:
        for lv in ("light", "medium", "heavy"):
            t = main_table(f"degraded_{lv}", ref="VERA@Qwen/Qwen3.6-35B-A3B-FP8")
            if t is not None:
                print(lv, "\n", t[["method", "eco", "n", "vuln_f1", "exact_f1", "comp_f1", "hallucination", "llm_calls"]].to_string())
                bar_figure(t, f"degraded_{lv}_vuln_f1.png", f"SBOM suy giảm mức {lv}: vuln F1", order=ORDER)
        t = main_table("containers", ref="VERA@Qwen/Qwen3.6-35B-A3B-FP8")
        if t is not None:
            print("containers\n", t[["method", "eco", "n", "vuln_p", "vuln_r", "vuln_f1", "exact_f1", "llm_calls"]].to_string())
            bar_figure(t, "containers_vuln_f1.png", "Container image (suy giảm medium/heavy): vuln F1", order=ORDER)
    if "ablation" in what:
        t = main_table("ablation", ref="VERA-noLLM")
        if t is not None:
            print(t[["method", "eco", "n", "vuln_p", "vuln_r", "vuln_f1", "vuln_brier", "exact_f1", "comp_f1"]].to_string())
        t = main_table("ablation_llm", ref="VERA@Qwen/Qwen3.6-35B-A3B-FP8")
        if t is not None:
            print(t[["method", "eco", "n", "vuln_p", "vuln_r", "vuln_f1", "exact_f1", "comp_f1", "hallucination", "llm_calls"]].to_string())
    if "budget" in what:
        budget_curve()
    if "calibration" in what:
        calibration()
