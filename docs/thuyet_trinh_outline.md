# Outline thuyết trình — VERA: Khôi phục SBOM lỗi có định hướng lỗ hổng

> Thời lượng gợi ý: 15–20 phút trình bày + 5 phút demo + hỏi đáp.
> Mọi số liệu dưới đây là **kết quả đã đo trên tập test** (nguồn: `results/table_*.csv`, `figures/*.png`; chi tiết trong `docs/bao_cao.md` §6).

---

## Phần A — Dàn ý slide

### Slide 1 — Tiêu đề
- **VERA: Khôi phục SBOM lỗi bằng suy luận ràng buộc–thời gian và AI Agent có kiểm chứng**
- Phụ đề: *Tác động lên đánh giá lỗ hổng chuỗi cung ứng phần mềm*
- Tên, đơn vị, ngày.

### Slide 2 — Vấn đề trong một câu
- Thông điệp: **"SBOM lỗi ⇒ scanner im lặng, không phải vì hệ thống an toàn mà vì không nhìn thấy gì."**
- Ví dụ thật (repo `psf/requests`, SBOM do GitHub sinh): 29 component, 12 thiếu version, 4 chỉ có range ⇒ chỉ **10%** component quét được lỗ hổng.
- Hình: một dòng SBOM `lodash ^4.17.0` → scanner: *không khớp* (một range không phải một version).
- *Ghi chú người nói*: scanner chỉ khớp được bộ ba (ecosystem, tên, version chính xác).

### Slide 3 — Mức độ nghiêm trọng (RQ1)
- Bảng: tỉ lệ lỗi trong SBOM thực tế (GitHub dependency graph + SBOM manifest‑only).
  - 83 SBOM GitHub thật: version là range 59% (Java), 32% (JS), 30% (TS), 27% (Python, thêm 24% thiếu hẳn version); chỉ 52–80% component quét được; 18–50% SBOM chỉ có phụ thuộc trực tiếp (`results/table_rq1_survey.csv`)
  - Recall lỗ hổng khi quét SBOM manifest‑only so với lockfile: **Maven 11.1%, npm 1.6%, PyPI 0.1%** (432 / 1.504 / 2.693 lỗ hổng thật).
- Hình: `figures/rq1_defects.png`.
- Thông điệp: thiếu transitive + version là range là hai "sát thủ" chính.

### Slide 4 — Bài toán & yêu cầu
- Đầu vào: chỉ có SBOM lỗi (không có mã nguồn, không build lại).
- Đầu ra: SBOM đã sửa + **bằng chứng và độ tin cậy cho từng sửa đổi** + báo cáo lỗ hổng.
- Ràng buộc: không bịa (no hallucination), tái lập được, chi phí chấp nhận được.
- Câu hỏi nghiên cứu RQ1–RQ5 (liệt kê ngắn).

### Slide 5 — Liên quan & khoảng trống
- Khảo sát: Xia (ICSE'23), Stalnaker (ICSE'24) → SBOM thiếu, công cụ yếu.
- Tác động: O'Donoghue (SCORED'24) → cách sinh SBOM thay đổi kết quả quét lỗ hổng; Zhou et al. (2025) → lockfile ⇒ SBOM chính xác.
- Sửa/gộp: sbom‑unifier (2026) → gộp nhiều SBOM theo luật, **không** suy luận version/transitive, **không** LLM.
- **Khoảng trống**: chưa có phương pháp khôi phục *một* SBOM lỗi, tối ưu theo tác động lên lỗ hổng, có AI agent được kiểm chứng.

### Slide 6 — Tổng quan VERA (sơ đồ pipeline)
- Sơ đồ 8 bước (lấy từ báo cáo §3).
- Nhấn mạnh 3 nguyên tắc: *Evidence‑grounded* · *Vulnerability‑aware* · *LLM chỉ ở chỗ ký hiệu bế tắc*.

### Slide 7 — Đóng góp 1: Temporal resolver model
- Trực giác: package manager chọn **version cao nhất thoả range có mặt tại lúc lock**.
- `t_lock` chưa biết ⇒ mô hình `ts − t_lock ~ Exp(μ)` ⇒ **P(version)** tính đúng theo công thức đóng.
- Ví dụ: `express ^4.17.0` @ 2023‑06 → 4.18.2 (p=0.86), 4.18.1 (p=0.10)…
- Hình: biểu đồ phân phối P(version) chụp từ UI (tab Khôi phục).

### Slide 8 — Đóng góp 2: Neo thời gian từ cận dưới khai báo + mô hình hỗn hợp
- `^4.18.2` ⇒ 4.18.2 đã tồn tại lúc lock ⇒ `t_lock ≥ max pub(lower bounds)` (ràng buộc cứng, không cần học).
- Phát hiện thực nghiệm: npm/uv **không nâng version đã lock** ⇒ lockfile là hỗn hợp thời điểm ⇒ dùng hỗn hợp `w·P_anchor + (1−w)·P_prior`.
- Kết quả tinh chỉnh trên dev: npm F1 0.49 → 0.62 với anchor; PyPI tốt nhất khi w=0 (lockfile Python ít khi refresh đồng loạt).
- Trên **test** (trung thực): anchoring tăng precision 0.69 → 0.75 nhưng F1 không đổi (0.63 vs 0.64) → dùng khi muốn ít báo động giả.
- Hình: heatmap `(μ, w)` từ `results/tuning_dev.csv`.

### Slide 9 — Đóng góp 3: Khôi phục transitive + dấu vân tay OS
- Đồ thị deps.dev chỉ lấy **cạnh và requirement**; version được **resolve lại tại thời điểm SBOM**.
- Maven: resolve `${property}`/`dependencyManagement` qua chuỗi parent pom + BOM import.
- Container: suy distro từ `base-files`; Alpine dùng **dấu vân tay từ chính CSDL OSV** (ghost → Alpine 3.17 ✔).

### Slide 10 — Đóng góp 4: VUG + Agent có verifier
- VUG: ưu tiên task theo *khối lượng lỗ hổng có thể thay đổi / chi phí*; task giá trị 0 không đáng tốn LLM.
- Agent tool‑use: `registry_lookup`, `list_versions`, `get_requirements`, `maven_resolve`, `osv_lookup`, `submit_fix`.
- **Verifier** chặn: package/version không tồn tại, vi phạm range, phát hành sau timestamp, không trích dẫn bằng chứng; với distro: mâu thuẫn dấu vân tay OSV.
- Ví dụ trace: agent khôi phục `com.fasterxml.jackson.core:jackson-databind` sau 2 tool call. Verifier đã bác: 39/733 đề xuất định danh (vd. tên npm bịa `@img/sharp_libvips_darwin_x64`), 5/570 version vi phạm range, 3/10 distro mâu thuẫn dấu vân tay OSV (đề xuất Alpine 3.18 cho image 3.17).

### Slide 11 — Đóng góp 5: Báo cáo lỗ hổng xác suất
- `P(vuln) = Σ P(v)·1[v bị ảnh hưởng]` → confirmed / likely / possible.
- Hình: reliability diagram `figures/calibration.png` — bin 0.29/0.49/0.68/0.90 → tỉ lệ đúng 0.42/0.60/0.65/0.88; Brier VERA 0.24 so với 0.52 khi bỏ temporal model.
- Lưu ý khi trình bày: tầng *possible* vẫn chứa 17–42% lỗ hổng thật → không được bỏ qua.
- Thông điệp: thay vì "có/không", cho người phân tích biết **nên tin tới đâu**.

### Slide 12 — Dữ liệu & thiết lập thí nghiệm
- Dữ liệu thật: 40 npm + 40 PyPI repo có lockfile, 32 artifact Maven Central có SBOM do build tool công bố, 12 container image, khảo sát GitHub SBOM.
- CSDL lỗ hổng: snapshot OSV 2026‑11‑12 (~364k bản ghi), match offline.
- Chia dev/test (25/75); tham số chỉ chỉnh trên dev.
- Baseline B0–B4 (bảng nhỏ); model: Claude Opus 5, Qwen3.6‑35B, Qwen3.5‑122B, Qwen3.5‑35B (đều chạy không‑thinking).

### Slide 13 — Kết quả chính (RQ2 + RQ3)
- Bảng: vuln P/R/F1 và exact F1 theo phương pháp × ecosystem.
  - Toàn bộ test (n=78): B0 **0.17** · B1‑ts 0.29 · B2 (npm/uv re‑resolve) 0.49 · **VERA‑noLLM 0.63** [0.56, 0.70]; recall High/Critical 0.04 → **0.66**.
  - Cặp mẫu có LLM: B3@Qwen 0.25 · B3@Opus 0.30 · VERA@Qwen 0.68 (n=36) · VERA@Opus 0.74 (n=18).
  - Theo ecosystem (VERA‑noLLM vs B2): Maven 0.90 vs 0.74 · npm 0.47 vs 0.43 · PyPI 0.55 vs 0.30.
- Hình: `figures/paired_natural_qwen.png`.
- Kiểm định Wilcoxon cặp: VERA‑noLLM vs B2 p = 0.006; VERA@Qwen vs B3 p < 0.001. Nói thẳng: trên SBOM tự nhiên **LLM không thêm điểm** so với phần ký hiệu.

### Slide 14 — AI Agent vs truyền thống (RQ4)
- Bảng so sánh 4 trục: **chính xác · hallucination · chi phí · độ trễ**.
  - B3 (LLM không tool): vuln F1 0.25–0.30 (tự nhiên), hallucination 4.3% (Qwen) / **13.9% (Opus)**.
  - B4 (ReAct agent tổng quát, cùng bộ tool): vuln F1 0.25 (Qwen, n=18) / 0.30 (Opus, n=9) so với 0.74 / 0.73 của VERA trên cùng mẫu (p < 0.001 / 0.008); tốn 60k–115k token/SBOM.
  - VERA: hallucination **0%**; 0 token (noLLM, 2.8 s/SBOM) hoặc 34k–76k token khi bật agent. Hình `figures/rq4_cost_quality.png`.
- Nơi LLM *giúp*: lỗi định danh. Suy giảm nặng: VERA‑noLLM 0.63 → VERA@Qwen3.5‑122B 0.68, VERA@Opus 0.72 (Maven 0.73 → 0.82); container mất distro: 0.47 → **0.66** (p = 0.005); redis: 0 → 53/53 lỗ hổng.
- Nơi LLM *không giúp/hại*: đoán version khi không có công cụ — exact F1 của B3 chỉ 0.15–0.20 trên SBOM tự nhiên; điểm thú vị: trên SBOM suy giảm nặng B3@Opus có recall cao nhất (0.89) nhờ tri thức "release train" nhưng precision 0.56 và bịa 11% giá trị; khi bật chế độ suy luận, Opus còn từ chối đoán vì "không có quyền truy cập registry" — trung thực nhưng không sửa được gì.
- Thông điệp: **agent chỉ tốt khi được neo vào bằng chứng và được kiểm chứng.**

### Slide 15 — Ablation & ngân sách (RQ5)
- Ablation (F1, n=78): đầy đủ 0.63 · −graph **0.39** · −temporal 0.55 (Brier 0.24→0.52) · −anchor 0.64 (precision 0.75→0.69) · −co‑constraint 0.63. Bỏ verifier/VUG ở ngân sách 20: F1 không đổi (0.658) — verifier là chốt an toàn, không phải nguồn tăng điểm.
- RQ5 (`figures/rq5_budget_curve.png`): VUG đạt F1 tối đa 0.658 với 4 task (~11 lời gọi LLM), FIFO cần 8 task (~23 lời gọi); ở 1 task: 0.650 vs 0.628. Lợi ích tuyệt đối nhỏ — nói rõ khi trình bày (trục y phóng to).
- So sánh model (suy giảm nặng): Opus 5 0.72 (n=18) · Qwen3.5‑122B 0.68 · Qwen3.6‑35B 0.66 · Qwen3.5‑35B 0.66 (n=24); Opus nhanh hơn ~2× (39 s vs 75 s/SBOM).

### Slide 16 — Container (Debian/Alpine)
- Suy giảm medium (n=24): B0 0.39 · B1 0.90 · VERA‑noLLM 0.90 (Debian suy ra từ `base-files`).
- Suy giảm heavy (mất toàn bộ distro): B0 0.06 · B1 0.46 · VERA‑noLLM 0.47 · **VERA@Qwen 0.66** (`results/table_paired_containers_heavy.csv`).
- Ví dụ: mất distro ⇒ 0 lỗ hổng; VERA khôi phục distro ⇒ 53/53 lỗ hổng (redis:7.0.12‑alpine).

### Slide 17 — DEMO (UI Streamlit)
Kịch bản 4–5 phút:
1. Chọn mẫu `[npm] ChromeDevTools__chrome-devtools-mcp` → tab **Chẩn đoán**: NTIA, 23% quét được, lỗi cấp SBOM "thiếu transitive".
2. Bấm **Chạy VERA** → tab **Khôi phục**: log pipeline, bảng sửa đổi có bằng chứng, biểu đồ P(version).
3. Tab **Lỗ hổng trước/sau**: 0 → N lỗ hổng, so với ground truth (P/R/F1).
4. Tab **Đồ thị phụ thuộc**: bật "chỉ đường dẫn tới lỗ hổng" + bố cục phân tầng → chỉ ra đường từ gốc tới component có lỗ hổng; di chuột xem bằng chứng.
5. Tab **Agent trace**: thứ tự ưu tiên VUG, verifier chấp nhận/bác.
6. (Tuỳ chọn) chọn mẫu container → task distro.
- *Phương án dự phòng*: chạy với `VERA_OFFLINE=1` (toàn bộ từ cache) nếu mất mạng; có ảnh chụp màn hình sẵn.

### Slide 18 — Hạn chế & hướng phát triển
- Ground truth container = Syft (không hoàn hảo); lockfile ≠ runtime thật.
- Phụ thuộc deps.dev / registry công khai (không hỗ trợ registry nội bộ).
- Chưa xử lý reachability (FP do mã không được gọi — hướng nối tiếp Zhou et al.).
- Ecosystem: mới PyPI/npm/Maven/Debian/Alpine.
- Hướng: học `μ, w` theo từng repo, VEX tự động, tích hợp CI, registry nội bộ.

### Slide 19 — Tổng kết đóng góp
1. **C1 – Benchmark** SBOM‑RepairBench từ dữ liệu thật (cặp lỗi tự nhiên/chuẩn + suy giảm có kiểm soát + snapshot OSV).
2. **C2 – Phương pháp VERA**: temporal resolver + declared‑floor anchoring + fingerprint OSV + VUG + agent có verifier + báo cáo xác suất.
3. **C3 – Nghiên cứu thực nghiệm**: tác động của SBOM lỗi và của khôi phục lên đánh giá lỗ hổng; AI agent vs truyền thống.
4. **C4 – PoC + UI** mã nguồn mở, tái lập được (cache, offline mode).

### Slide 20 — Cảm ơn / Hỏi đáp

---

## Phần B — Nguồn số liệu cho từng slide
- `results/table_rq1_survey.csv` → Slide 3
- `results/table_main_natural.csv`, `figures/rq2_rq3_vuln_f1.png` → Slide 13
- `results/table_degraded_heavy.csv` (VERA‑noLLM vs VERA@LLM, hallucination) → Slide 14
- `results/table_ablation.csv`, `results/table_ablation_llm.csv` → Slide 15
- `results/table_rq5_budget.csv`, `figures/rq5_budget_curve.png` → Slide 15
- `results/table_containers.csv` → Slide 16
- `figures/calibration.png`, `results/table_calibration.csv` → Slide 11
- Số lời gọi LLM / token / thời gian → Slide 14
