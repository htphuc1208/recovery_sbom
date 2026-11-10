"""VERA PoC UI - Khôi phục SBOM lỗi & đánh giá tác động lên phân tích lỗ hổng."""
from __future__ import annotations
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from vera import sbom_io, quality, vuln, config
from vera.graph_viz import build_graph, COLORS
from vera.pipeline import repair, VeraConfig
from vera.model import SBOM
from bench.metrics import evaluate
from bench.degrade import degrade

st.set_page_config(page_title="VERA – Khôi phục SBOM", layout="wide", page_icon="🛡️")
BENCH = config.DATA / "bench"


@st.cache_data(show_spinner=False)
def demo_samples():
    out = {}
    for eco in ("npm", "pypi", "maven"):
        for d in sorted((BENCH / "A" / eco).iterdir()) if (BENCH / "A" / eco).exists() else []:
            if (d / "truth.json").exists():
                out[f"[{eco}] {d.name} (manifest-only, lỗi tự nhiên)"] = ("A", str(d))
    for d in sorted((BENCH / "B").iterdir()) if (BENCH / "B").exists() else []:
        if (d / "truth.json").exists():
            out[f"[container] {d.name} (suy giảm mức medium)"] = ("B", str(d))
    return out


@st.cache_resource(show_spinner=False)
def load_demo(kind, path):
    truth = sbom_io.load(Path(path) / "truth.json")
    if kind == "A":
        bad = sbom_io.load(Path(path) / "bad_manifest.json")
    else:
        bad, _ = degrade(truth, "medium", 0)
        bad.metadata["timestamp"] = truth.metadata.get("timestamp")
    return bad, truth


def findings_df(s: SBOM):
    fs = vuln.scan(s)
    return pd.DataFrame([{"Lỗ hổng": f.vuln, "Component": f.component, "Version": f.version, "CVSS≈": f.severity,
                          "Xác suất": round(f.prob, 2), "Mức": f.tier} for f in fs]).sort_values(
        ["Xác suất", "CVSS≈"], ascending=False) if fs else pd.DataFrame()


# ------------------------------------------------------------------ sidebar
st.sidebar.title("🛡️ VERA")
st.sidebar.caption("Vulnerability-aware Evidence-grounded Repair Agent")
src = st.sidebar.radio("Nguồn SBOM", ["Mẫu demo (dữ liệu thật)", "Tải lên file"])
bad = truth = None
bad_key = None   # stable identity of the current input across Streamlit reruns
if src.startswith("Mẫu"):
    ds = demo_samples()
    if ds:
        key = st.sidebar.selectbox("Chọn mẫu", list(ds))
        bad, truth = load_demo(*ds[key])
        bad_key = f"demo:{key}"
else:
    up = st.sidebar.file_uploader("SBOM (CycloneDX / SPDX JSON)", type=["json"])
    if up:
        try:
            bad = sbom_io.load(up.getvalue())
            import hashlib
            bad_key = "upload:" + hashlib.md5(up.getvalue()).hexdigest()
        except Exception as e:
            st.sidebar.error(f"Không đọc được SBOM: {e}")
    upt = st.sidebar.file_uploader("(Tuỳ chọn) SBOM chuẩn để so sánh", type=["json"])
    if upt:
        truth = sbom_io.load(upt.getvalue())

st.sidebar.subheader("Cấu hình")
use_llm = st.sidebar.toggle("Dùng LLM agent", value=True)
model = st.sidebar.selectbox("Model", config.AGENT_MODELS, index=2, disabled=not use_llm)
budget = st.sidebar.slider("Ngân sách agent (task/SBOM)", 0, 40, 10)
with st.sidebar.expander("Ablation"):
    use_temporal = st.checkbox("Temporal resolver model", True)
    use_anchor = st.checkbox("Temporal anchoring", True)
    use_co = st.checkbox("Co-constraints", True)
    use_graph = st.checkbox("Khôi phục transitive", True)
    use_vug = st.checkbox("Ưu tiên VUG", True)
    use_ver = st.checkbox("Verifier", True)

st.title("Khôi phục SBOM lỗi & tác động tới đánh giá lỗ hổng")
if bad is None:
    st.info("Chọn một mẫu demo hoặc tải lên SBOM ở thanh bên.")
    tab_res = st.tabs(["📊 Kết quả thí nghiệm"])[0]
else:
    t1, t2, t3, tg, t4, tab_res = st.tabs(["🩺 Chẩn đoán", "🔧 Khôi phục", "🐞 Lỗ hổng trước/sau", "🕸️ Đồ thị phụ thuộc",
                                           "🤖 Agent trace", "📊 Kết quả thí nghiệm"])
    with t1:
        q = quality.summary(bad)
        c1, c2, c3 = st.columns(3)
        c1.metric("Số component", q["components"])
        c2.metric("NTIA (tổng)", f"{q['ntia']['overall']:.0%}")
        c3.metric("Quét lỗ hổng được", f"{q['vuln_readiness']:.0%}", help="Tỉ lệ component có version chính xác + định danh hợp lệ")
        a, b = st.columns(2)
        a.bar_chart(pd.Series({k: v for k, v in q["ntia"].items() if k != "overall"}, name="NTIA"))
        b.bar_chart(pd.Series(q["defects"], name="Số lỗi"))
        if q["sbom_defects"]:
            st.warning("Lỗi cấp SBOM: " + ", ".join(q["sbom_defects"]))
        st.dataframe(pd.DataFrame([{"name": c.name, "group": c.group, "version": c.version, "purl": c.purl,
                                    "license": ",".join(c.licenses)} for c in bad.components]), use_container_width=True, height=300)
    run_clicked = st.sidebar.button("▶ Chạy VERA", type="primary")
    if run_clicked or st.session_state.get("rep_key") == bad_key:
        if run_clicked or "rep" not in st.session_state:
            cfg = VeraConfig(model=model, use_llm=use_llm, budget=budget, use_temporal=use_temporal, use_anchor=use_anchor,
                             use_coconstraints=use_co, use_graph=use_graph, use_vug=use_vug, use_verifier=use_ver)
            with st.spinner("Đang khôi phục (tra registry, deps.dev, OSV, LLM agent)..."):
                st.session_state["rep"] = repair(bad, cfg)
                st.session_state["rep_key"] = bad_key
        rep = st.session_state["rep"]
        fixed = rep.sbom
        with t2:
            st.code("\n".join(rep.log))
            q2 = quality.summary(fixed)
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Component", q2["components"], q2["components"] - len(bad.components))
            c2.metric("NTIA", f"{q2['ntia']['overall']:.0%}", f"{q2['ntia']['overall'] - quality.summary(bad)['ntia']['overall']:+.0%}")
            c3.metric("Quét được", f"{q2['vuln_readiness']:.0%}", f"{q2['vuln_readiness'] - quality.summary(bad)['vuln_readiness']:+.0%}")
            c4.metric("Thời gian", f"{rep.stats.get('seconds', 0):.1f}s")
            rows = []
            for c in fixed.components:
                for r in c.repairs:
                    if r.field == "license":
                        continue
                    rows.append({"component": c.name, "trường": r.field, "cũ": str(r.old), "mới": str(r.new),
                                 "phương pháp": r.method, "độ tin cậy": round(r.confidence, 2),
                                 "bằng chứng": " | ".join(r.evidence)[:300]})
            df = pd.DataFrame(rows)
            if not df.empty:
                meth = st.multiselect("Lọc theo phương pháp", sorted(df["phương pháp"].unique()), default=sorted(df["phương pháp"].unique()))
                st.dataframe(df[df["phương pháp"].isin(meth)], use_container_width=True, height=380)
            unc = [c for c in fixed.components if c.candidates]
            if unc:
                sel = st.selectbox("Phân phối xác suất version (temporal resolver model)", [c.purl for c in unc])
                cc = next(c for c in unc if c.purl == sel)
                st.bar_chart(pd.Series(cc.candidates, name="P(version)").sort_values(ascending=False).head(12))
            st.download_button("⬇ Tải SBOM đã khôi phục (CycloneDX 1.6)", json.dumps(sbom_io.to_cyclonedx(fixed), indent=1),
                               "sbom.repaired.cdx.json", "application/json")
        with t3:
            fb, ff = findings_df(bad), findings_df(fixed)
            c1, c2, c3 = st.columns(3)
            c1.metric("Lỗ hổng phát hiện – SBOM lỗi", len(fb))
            c2.metric("Sau khôi phục (p≥0.5)", int((ff["Xác suất"] >= 0.5).sum()) if not ff.empty else 0)
            c3.metric("Cần xem xét (p<0.5)", int((ff["Xác suất"] < 0.5).sum()) if not ff.empty else 0)
            if truth is not None:
                st.subheader("So với SBOM chuẩn (ground truth)")
                mb, mf = evaluate(bad, truth, bad), evaluate(fixed, truth, bad)
                comp = pd.DataFrame({"SBOM lỗi": mb, "VERA": mf}).loc[
                    ["vuln_p", "vuln_r", "vuln_f1", "vuln_r_sev", "vuln_r_any", "vuln_fp", "vuln_fn", "comp_f1", "exact_f1", "version_acc", "ntia"]]
                st.dataframe(comp.style.format("{:.3f}"), use_container_width=True)
                st.bar_chart(comp.loc[["vuln_p", "vuln_r", "vuln_f1", "comp_f1", "exact_f1"]])
            a, b = st.columns(2)
            a.markdown("**SBOM lỗi**"); a.dataframe(fb, use_container_width=True, height=360)
            b.markdown("**Sau khôi phục (báo cáo xác suất)**"); b.dataframe(ff, use_container_width=True, height=360)
            vex = [{"vulnerability": r["Lỗ hổng"], "component": r["Component"], "version": r["Version"],
                    "probability": r["Xác suất"], "tier": r["Mức"]} for r in ff.to_dict("records")] if not ff.empty else []
            st.download_button("⬇ Tải báo cáo lỗ hổng xác suất (JSON)", json.dumps(vex, indent=1), "vuln_report.json")
        with t4:
            if not rep.agent_traces:
                st.info("Không có task nào cần LLM agent (hoặc LLM bị tắt).")
            st.caption(f"Tổng task: {rep.stats.get('tasks_total')} · task có giá trị VUG > 0: {rep.stats.get('tasks_positive_value')} · đã chạy: {rep.stats.get('agent_tasks')}")
            for tr in rep.agent_traces:
                icon = "✅" if tr["accepted"] else "⛔"
                with st.expander(f"{icon} [{tr['kind']}] {tr['component']} · VUG={tr['value']:.1f} · {tr['tool_calls']} tool call"):
                    st.write("Verifier:", tr["reason"])
                    st.json(tr["proposal"] or {})



def render_graph_tab(bad, truth, bad_key):
    rep = st.session_state.get("rep") if st.session_state.get("rep_key") == bad_key else None
    views = {"SBOM lỗi (đầu vào)": bad}
    if rep is not None:
        views["Sau khôi phục (VERA)"] = rep.sbom
    if truth is not None:
        views["SBOM chuẩn (ground truth)"] = truth
    c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
    view = c1.radio("Hiển thị", list(views), index=1 if rep is not None else 0, horizontal=True)
    max_nodes = c2.slider("Số node tối đa", 20, 800, 250, 10)
    only_vuln = c3.checkbox("Chỉ đường dẫn tới lỗ hổng", value=False)
    hier = c4.checkbox("Bố cục phân tầng", value=False)
    min_prob = st.select_slider("Ngưỡng xác suất lỗ hổng để tô đỏ", [0.0, 0.25, 0.5, 0.75, 0.95], value=0.5)
    if rep is None:
        st.caption("Chạy VERA (thanh bên) để xem đồ thị sau khôi phục.")
    sb = views[view]
    with st.spinner("Đang dựng đồ thị..."):
        html, stats = build_graph(sb, max_nodes=max_nodes, only_vuln_paths=only_vuln, min_prob=min_prob, hierarchical=hier)
    if only_vuln and not stats.get("vulnerable"):
        st.info("Không có component nào có lỗ hổng ở ngưỡng xác suất này trong SBOM đang xem.")
    m = st.columns(6)
    m[0].metric("Node hiển thị", f"{stats.get('nodes', 0)}/{stats.get('total_components', 0)}")
    m[1].metric("Cạnh", stats.get("edges", 0))
    m[2].metric("Có lỗ hổng", stats.get("vulnerable", 0))
    m[3].metric("Được sửa", stats.get("repaired", 0))
    m[4].metric("Khôi phục transitive", stats.get("recovered", 0))
    m[5].metric("Chưa quét được", stats.get("broken", 0))
    legend = " ".join(f"<span style='background:{COLORS[k]};padding:2px 8px;border-radius:8px;margin-right:6px'>{v}</span>"
                      for k, v in [("root", "SBOM gốc"), ("original", "giữ nguyên"), ("repaired", "được sửa"),
                                   ("recovered", "khôi phục transitive"), ("broken", "chưa quét được")])
    st.markdown(legend + "<span style='border:3px solid #D63031;padding:1px 8px;border-radius:8px'>viền đỏ = có lỗ hổng "
                "(kích thước ∝ CVSS × xác suất)</span>", unsafe_allow_html=True)
    st.caption("Kéo/zoom để khám phá; di chuột lên node để xem PURL, sửa đổi, bằng chứng, phân phối version và lỗ hổng. "
               "Cạnh nét đứt: component không có thông tin quan hệ, tạm gắn vào gốc.")
    components.html(html, height=700, scrolling=False)


if bad is not None:
    with tg:
        render_graph_tab(bad, truth, bad_key)

with tab_res:
    res, figd = config.RESULTS, config.FIGURES
    SECTIONS = [
        ("RQ1 – SBOM thực tế lỗi đến mức nào?", "table_rq1_survey.csv", "rq1_defects.png",
         "Khảo sát SBOM GitHub dependency graph và SBOM manifest-only; recall lỗ hổng khi quét SBOM lỗi so với lockfile."),
        ("RQ2/RQ3 – SBOM lỗi tự nhiên (cặp mẫu, Qwen3.6-35B)", "table_paired_natural_qwen.csv", "paired_natural_qwen.png",
         "So sánh trên cùng 36 mẫu test; p = Wilcoxon cặp so với VERA."),
        ("RQ2/RQ3 – SBOM lỗi tự nhiên (Claude Opus 5)", "table_paired_natural_opus.csv", None, "18 mẫu test."),
        ("RQ4 – So với ReAct agent tổng quát (B4)", "table_paired_natural_b4.csv", "rq4_cost_quality.png",
         "Chất lượng vs chi phí token LLM."),
        ("SBOM suy giảm nặng – so sánh model", "table_paired_heavy_qwen.csv", "paired_heavy.png", "24 mẫu test."),
        ("Container (suy giảm nặng)", "table_paired_containers_heavy.csv", None, "12 image × 2 seed."),
        ("Ablation (phần ký hiệu)", "table_ablation.csv", None, "Bỏ từng thành phần của VERA-noLLM."),
        ("RQ5 – Hiệu quả ngân sách (VUG vs FIFO)", "table_rq5_budget.csv", "rq5_budget_curve.png", ""),
        ("Độ hiệu chỉnh báo cáo lỗ hổng xác suất", "table_calibration.csv", "calibration.png", ""),
    ]
    if not any((res / t).exists() for _, t, _, _ in SECTIONS):
        st.info("Chưa có kết quả thí nghiệm. Chạy `bench/run_all.sh` rồi `python -m bench.paired_tables`.")
    for title, tbl, fig, note in SECTIONS:
        if not (res / tbl).exists():
            continue
        with st.expander(title, expanded=tbl == "table_paired_natural_qwen.csv"):
            if note:
                st.caption(note)
            df = pd.read_csv(res / tbl)
            num = df.select_dtypes("number").columns
            st.dataframe(df.style.format({c: "{:.3f}" for c in num}), use_container_width=True)
            if fig and (figd / fig).exists():
                st.image(str(figd / fig), use_container_width=False, width=720)
