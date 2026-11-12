# VERA — Khôi phục SBOM lỗi có định hướng lỗ hổng

**VERA** (*Vulnerability-aware Evidence-grounded Repair Agent*) khôi phục SBOM "bad" (thiếu/sai version, PURL, tên,
groupId, distro, license, thiếu component transitive) và đo tác động của việc khôi phục lên **đánh giá lỗ hổng**.
Báo cáo đầy đủ (tiếng Việt): [docs/bao_cao.md](docs/bao_cao.md) · Outline thuyết trình: [docs/thuyet_trinh_outline.md](docs/thuyet_trinh_outline.md).

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

## Cấu trúc
| Thư mục | Nội dung |
|---|---|
| `vera/` | thư viện: `sbom_io`, `quality`, `versions`, `vuln` (OSV offline + báo cáo xác suất), `candidates` (temporal resolver model), `graph_completion`, `prioritizer` (VUG), `agent/` (LLM tool-use + verifier), `pipeline`, `baselines/` (B1–B4) |
| `bench/` | thu thập dữ liệu, suy giảm có kiểm soát, metric, chạy thí nghiệm, phân tích |
| `app/` | UI Streamlit |
| `results/`, `figures/` | kết quả thí nghiệm |
| `docs/` | báo cáo |
