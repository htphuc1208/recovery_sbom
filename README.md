# VERA — Khôi phục SBOM lỗi có định hướng lỗ hổng

**VERA** (*Vulnerability-aware Evidence-grounded Repair Agent*) khôi phục SBOM "bad" (thiếu/sai version, PURL, tên,
groupId, distro, license, thiếu component transitive) và đo tác động của việc khôi phục lên **đánh giá lỗ hổng**.
Mô tả dự án: [docs/mo_ta_du_an.md](docs/mo_ta_du_an.md) · Báo cáo đầy đủ (tiếng Việt): [docs/bao_cao.md](docs/bao_cao.md) · Outline thuyết trình: [docs/thuyet_trinh_outline.md](docs/thuyet_trinh_outline.md).

**Kết quả chính (tập test, SBOM lỗi tự nhiên, n=78):** vuln F1 0.17 (SBOM gốc) → 0.29 (heuristic) → 0.49 (re‑resolve bằng npm/uv) → **0.63 (VERA)**;
LLM agent tổng quát 0.25–0.30 với 1–14% giá trị bịa; VERA 0% (verifier). Agent có kiểm chứng giúp ở lỗi định danh (container mất distro: 0.47 → 0.66).

## Cài đặt
```bash
python3 -m venv .venv && .venv/bin/pip install -e . && .venv/bin/pip install pytest uv
cp .env.example .env   # điền LLM_BASE_URL / LLM_API_KEY (gateway OpenAI-compatible)
```
Docker chỉ cần khi muốn sinh lại ground truth container (Syft v1.18.1).

## Dữ liệu (dữ liệu thật, tái lập được)
```bash
# 1) Snapshot OSV (PyPI, npm, Maven, Debian, Alpine) + index
for e in PyPI npm Maven Debian Alpine; do curl -o data/osv/$e.zip https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip; done
.venv/bin/python -c "from vera.vuln import build_index; build_index()"
# 2) Tập A: repo GitHub có lockfile (npm, PyPI) + Maven Central SBOM do build tool công bố
.venv/bin/python -m bench.collect_repos --eco npm --target 40
.venv/bin/python -m bench.collect_repos --eco pypi --target 40
.venv/bin/python -m bench.collect_maven
# 3) Tập B: container image (ground truth = Syft)
.venv/bin/python -m bench.collect_images
# 4) RQ1: khảo sát SBOM thật từ GitHub dependency graph
.venv/bin/python -m bench.real_sbom_survey 25
```

## Sử dụng
```bash
.venv/bin/vera diagnose sbom.json
.venv/bin/vera repair sbom.json -o fixed.cdx.json --report report.json   # thêm --no-llm để chạy thuần ký hiệu
.venv/bin/vera scan fixed.cdx.json
.venv/bin/streamlit run app/streamlit_app.py                               # UI demo
```

## Thí nghiệm
```bash
.venv/bin/python -m bench.tune          # tinh chỉnh (mu, w) trên tập dev (25% repo)
bench/run_all.sh                        # toàn bộ thí nghiệm (4 luồng song song)
.venv/bin/python -m bench.reevaluate    # replay mọi run từ cache + chấm lại bằng metric hiện tại
.venv/bin/python -m bench.paired_tables # bảng so sánh cặp + Wilcoxon + hình (figures/*.png)
.venv/bin/python -m bench.analysis rq1 budget calibration
.venv/bin/python -m pytest -q           # unit test (offline)
```
Mọi lời gọi HTTP và LLM được cache trong `data/cache/*.sqlite`; đặt `VERA_OFFLINE=1` để chạy lại hoàn toàn từ cache.

## Dataset & code theo kịch bản trong báo cáo
Mỗi mẫu trong `data/bench/A/<eco>/<repo>/` gồm: `bad_manifest.json` (input – SBOM lỗi), `truth.json` (ground truth từ
lockfile / SBOM do build tool công bố), `meta.json` (commit, timestamp, nguồn). Mỗi run trong `results/runs/<kịch bản>/<phương pháp>/`
gồm SBOM đã sửa + metric (`*.json`) và với phương pháp dùng LLM có thêm `*.traces.json` (lời gọi tool, quyết định verifier).
`Q=Qwen/Qwen3.6-35B-A3B-FP8`, `R=".venv/bin/python -m bench.run_experiments"`.

| Kịch bản (mục báo cáo) | Input | Code chính | Lệnh tái lập | Output |
|---|---|---|---|---|
| RQ1 – mức độ lỗi của SBOM thật (§6.1) | `data/bench/survey/<ngôn ngữ>/*.json` (SBOM GitHub dependency graph), `data/bench/A` | `bench/real_sbom_survey.py`, `bench/analysis.py` | `python -m bench.real_sbom_survey 25`; `python -m bench.analysis rq1` | `results/table_rq1_survey.csv`, `results/rq1_per_sbom.csv`, `figures/rq1_defects.png` |
| Thu thập tập A (§4) | GitHub repo có lockfile, Maven Central | `bench/collect_repos.py`, `bench/collect_maven.py` | `python -m bench.collect_repos --eco npm --target 40` (tương tự `pypi`); `python -m bench.collect_maven` | `data/bench/A/{npm,pypi,maven}/` |
| Thu thập tập B – container (§4) | `data/bench/B/images.txt` (image pin digest) | `bench/collect_images.py` (Syft v1.18.1) | `python -m bench.collect_images` | `data/bench/B/<image>/` |
| Tinh chỉnh `(μ, w)` trên dev (§3.2) | `data/bench/A`, split dev | `bench/tune.py` | `python -m bench.tune` | `results/tuning_dev.csv`, `results/dev_sym.csv` |
| RQ2/RQ3 – SBOM lỗi tự nhiên (§6.2) | `data/bench/A/*/*/bad_manifest.json` (split test, n = 78) | `vera/pipeline.py`, `vera/candidates.py`, `vera/graph_completion.py`, `vera/baselines/b1_heuristic.py`, `b2_regen.py` | `$R main_natural --methods B0,B1-latest,B1-ts,B2,VERA-noLLM --split test` | `results/runs/main_natural/`, `results/main_natural.csv`, `results/table_main_natural.csv` |
| RQ2/RQ4 – cặp có LLM (§6.2, §6.5) | như trên, tập con | `vera/agent/`, `vera/baselines/b3_llm_zeroshot.py`, `b4_react.py` | `$R main_natural --methods VERA,B3 --model $Q --split test --limit 12`; `$R main_natural --methods B4 --model $Q --split test --limit 6` (Opus: `--model claude-opus-5`) | `results/runs/main_natural/{VERA,B3,B4}@*`, `results/table_paired_natural_*.csv`, `figures/paired_natural_qwen.png`, `figures/rq4_cost_quality.png` |
| Ablation ký hiệu (§6.2) | như RQ2 | `vera/pipeline.py` (cờ cấu hình) | `$R ablation --methods VERA-noLLM,VERA-noLLM-noTemporal,VERA-noLLM-noAnchor,VERA-noLLM-noCo,VERA-noLLM-noGraph --split test` | `results/runs/ablation/`, `results/table_ablation.csv` |
| SBOM suy giảm light/medium/heavy (§6.3) | `truth.json` của tập A + 9 toán tử suy giảm (seed cố định) | `bench/degrade.py` | `$R degraded_heavy --methods B0,B1-ts,VERA-noLLM --degrade heavy --split test` (tương tự `light`, `medium`); với LLM thêm `--methods VERA,B3 --model $Q --limit 8` | `results/runs/degraded_*/`, `results/table_degraded_*.csv`, `results/table_paired_heavy_*.csv`, `figures/paired_heavy.png` |
| So sánh model (§6.3) | như suy giảm nặng | `vera/agent/llm_client.py` | `$R degraded_heavy --methods VERA --model <model> --degrade heavy --split test --limit 8` | `results/runs/degraded_heavy/VERA@*`, `results/table_paired_heavy_opus.csv`, `..._qwen.csv` |
| Container Debian/Alpine (§6.4) | `data/bench/B/` | `vera/vuln.py` (dấu vân tay OSV), `bench/degrade.py` | `$R containers --sets container --methods B0,B1-ts,VERA-noLLM,VERA --model $Q --degrade heavy --seeds 0,1` (medium: bỏ `VERA`) | `results/runs/containers/`, `results/table_containers.csv`, `results/table_paired_containers_*.csv` |
| Ablation LLM: verifier, VUG (§6.5) | suy giảm nặng, tập con | `vera/agent/verifier.py`, `vera/prioritizer.py` | `$R ablation_llm --methods VERA,VERA-noVerifier,VERA-noVUG --model $Q --degrade heavy --split test --limit 8` | `results/runs/ablation_llm/`, `results/table_ablation_llm.csv`, `results/table_paired_ablation_llm.csv` |
| RQ5 – ngân sách VUG vs FIFO (§6.6) | suy giảm nặng, tập con | `vera/prioritizer.py` | lệnh `rq5_budget` trong `bench/run_all.sh`; `python -m bench.analysis budget` | `results/runs/rq5_budget/`, `results/table_rq5_budget.csv`, `figures/rq5_budget_curve.png` |
| Hiệu chỉnh xác suất (§6.7) | các run VERA‑noLLM trên test | `vera/vuln.py`, `bench/analysis.py` | `python -m bench.analysis calibration` | `results/table_calibration.csv`, `figures/calibration.png` |
| Bảng cặp + Wilcoxon (toàn §6) | `results/runs/` | `bench/reevaluate.py`, `bench/paired_tables.py` | `python -m bench.reevaluate`; `python -m bench.paired_tables` | `results/table_paired_*.csv`, `figures/*.png` |

Toàn bộ kịch bản: `bench/run_all.sh`. Không có trong repo (vượt giới hạn GitHub): snapshot OSV `data/osv/` (~800 MB, tải lại
theo mục Dữ liệu) và cache HTTP/LLM `data/cache/` (~600 MB, cần để tái lập *chính xác* số liệu khi registry/OSV đã thay đổi).

## Cấu trúc
| Thư mục | Nội dung |
|---|---|
| `vera/` | thư viện: `sbom_io`, `quality`, `versions`, `vuln` (OSV offline + báo cáo xác suất), `candidates` (temporal resolver model), `graph_completion`, `prioritizer` (VUG), `agent/` (LLM tool-use + verifier), `pipeline`, `baselines/` (B1–B4) |
| `bench/` | thu thập dữ liệu, suy giảm có kiểm soát, metric, chạy thí nghiệm, phân tích |
| `app/` | UI Streamlit |
| `results/`, `figures/` | kết quả thí nghiệm |
| `docs/` | báo cáo |
