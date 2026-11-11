# VERA: Khôi phục SBOM lỗi có định hướng lỗ hổng bằng suy luận ràng buộc–thời gian và AI Agent có kiểm chứng

*Báo cáo dự án — Hoàng Tấn Phúc — 11/2026*

---

## Tóm tắt

SBOM (Software Bill of Materials) là nền tảng của quản lý lỗ hổng chuỗi cung ứng phần mềm, nhưng SBOM thực tế thường
"lỗi": thiếu version hoặc chỉ ghi khoảng version (range), thiếu/sai Package URL (PURL), thiếu groupId Maven, thiếu
distro của gói hệ điều hành, và đặc biệt là **thiếu toàn bộ phụ thuộc bắc cầu (transitive)**. Một scanner lỗ hổng chỉ
khớp được `(ecosystem, tên, version chính xác)`, nên các lỗi trên làm **mất gần như toàn bộ lỗ hổng**.

Dự án đề xuất **VERA** (*Vulnerability-aware Evidence-grounded Repair Agent*), một phương pháp lai ký hiệu–LLM gồm:
(1) **mô hình resolver theo thời gian** (temporal resolver model) biến một range không giải được thành phân phối xác suất
có hiệu chỉnh trên các version; (2) **neo thời gian từ cận dưới khai báo** (declared‑floor anchoring) và ràng buộc
chéo giữa các component; (3) **khôi phục đồ thị transitive**; (4) **dấu vân tay bản phát hành OS từ chính CSDL lỗ hổng**;
(5) **ưu tiên theo bất định lỗ hổng (VUG)** để phân bổ ngân sách cho AI Agent; (6) **agent LLM có verifier** — mọi giá trị
phải được bằng chứng registry xác nhận; và (7) **báo cáo lỗ hổng xác suất** (confirmed / likely / possible).

Đánh giá trên **dữ liệu thật** — 112 cặp (SBOM lỗi tự nhiên, SBOM chuẩn) từ repo GitHub có lockfile (npm, PyPI) và SBOM
do build tool công bố trên Maven Central, 12 container image (Debian/Alpine) và khảo sát SBOM GitHub dependency graph —
với snapshot OSV cố định. Kết quả chính (tập test): trên SBOM lỗi tự nhiên, scanner chạy trên SBOM gốc chỉ đạt
vuln F1 = 0.17; phần ký hiệu của VERA nâng lên **0.63** (so với 0.29 của heuristic và 0.49 của re‑resolve bằng chính
package manager, p = 0.006), recall lỗ hổng High/Critical từ 0.04 lên 0.66; LLM agent tổng quát (zero‑shot hoặc ReAct)
chỉ đạt 0.25–0.30 và sinh 1–14% giá trị không tồn tại. LLM agent có kiểm chứng mang lại lợi ích ở các lỗi **định danh**:
khôi phục distro cho container (F1 0.47 → 0.66, p = 0.005) và groupId Maven (0.73 → 0.82 với Qwen3.5‑122B), với 0% hallucination.

---

## 1. Bối cảnh và vấn đề

* Các văn bản như EO 14028 và NTIA "minimum elements" yêu cầu SBOM có tối thiểu: supplier, tên, version, định danh duy nhất,
  quan hệ phụ thuộc, tác giả, thời điểm.
* Nghiên cứu thực nghiệm cho thấy công cụ sinh SBOM thiếu nhất quán và chất lượng SBOM ảnh hưởng mạnh tới kết quả quét lỗ
  hổng (O'Donoghue et al., SCORED'24). Khi **không có lockfile**, Syft/Trivy chỉ resolve được phụ thuộc trực tiếp có
  version cố định (Zhou et al., arXiv 2511.20313) — thậm chí trả về SBOM rỗng.
* Bài toán: *cho một SBOM lỗi (không có quyền truy cập mã nguồn/artifact), khôi phục các trường và component bị thiếu sao
  cho đánh giá lỗ hổng tiến gần nhất tới đánh giá trên SBOM chuẩn, kèm bằng chứng và độ tin cậy cho từng sửa đổi.*

## 2. Tổng quan nghiên cứu liên quan

| Công trình | Nội dung | Khác biệt với dự án |
|---|---|---|
| Xia et al., ICSE 2023 — *An Empirical Study on SBOM: Where We Stand and the Road Ahead* | Phỏng vấn/khảo sát người dùng SBOM; thách thức về độ đầy đủ, công cụ | Khảo sát định tính, không đề xuất khôi phục |
| Stalnaker et al., ICSE 2024 — *BOMs Away!* | 138 người thực hành, 12 thách thức (thiếu sót công cụ, kiểm chứng, bảo trì SBOM) | Định tính |
| O'Donoghue et al., SCORED 2024 — *Impacts of SBOM Generation on Vulnerability Detection* | Biến thiên lớn của kết quả quét lỗ hổng do công cụ sinh SBOM | Đo tác động, không sửa |
| Zhou, Dacier, Konstantinou, arXiv 2511.20313 — *A Reality Check on SBOM-based Vulnerability Management* | Lockfile + package manager mạnh → SBOM chính xác; 92% FP do mã không reachable | Ủng hộ chọn lockfile làm ground truth |
| Gamage et al., MSR 2025 — *Software Bills of Materials in Maven Central* | 14.071 SBOM công bố trên Maven Central | Nguồn ground truth Maven của dự án |
| Moriwaki, arXiv 2608.30708 — *sbom-unifier* | Gộp nhiều SBOM, bổ sung trường theo luật ưu tiên tất định | Cần nhiều SBOM đầu vào, không suy luận version/transitive, không LLM |
| Các nghiên cứu so sánh công cụ (arXiv 2402.11151, 2409.1214, 2601.05622, 2609.19920) | Công cụ không nhất quán; recall phụ thuộc < 58,5% | Đánh giá công cụ, không khôi phục |

Theo khảo sát của chúng tôi (11/2026), **chưa có công trình nào khôi phục SBOM lỗi bằng AI agent**, và chưa có công trình
nào tối ưu việc khôi phục theo **tác động lên đánh giá lỗ hổng**.

## 3. Phương pháp VERA

```
SBOM lỗi ──► (1) Chẩn đoán lỗi ──► (2) Định danh ký hiệu (PEP 503, registry, groupId, distro, fingerprint OSV)
                                        │
                                        ▼
            (3) Neo thời gian: t_lock ≥ max(ngày phát hành cận dưới của mọi range khai báo)
                                        │
                                        ▼
            (4) Temporal resolver model ─► phân phối P(version) cho mỗi component
            (5) Ràng buộc chéo (requirements của các component khác) ─► thu hẹp phân phối
            (6) Khôi phục transitive (đồ thị deps.dev + resolver thời gian tại timestamp SBOM)
                                        │
                                        ▼
            (7) VUG: xếp hạng task theo khối lượng lỗ hổng có thể thay đổi / chi phí
            (8) LLM agent (tool-use) cho task mơ hồ ─► Verifier (registry, range, thời gian, bằng chứng)
                                        │
                                        ▼
            SBOM CycloneDX 1.6 đã sửa (provenance + confidence) + báo cáo lỗ hổng xác suất
```

### 3.1 Temporal resolver model (đóng góp cốt lõi)
Package manager resolve range thành **version cao nhất thoả mãn và đã phát hành tại thời điểm lock** `t_lock`. `t_lock`
chưa biết nhưng `t_lock ≤ ts` (timestamp SBOM). Đặt `X = ts − t_lock ~ Exponential(μ)`. Sắp các version thoả range theo
ngày phát hành `p_1 < p_2 < …`; trong khoảng `[p_i, p_{i+1})` version được chọn là `r_i = max_{j≤i} v_j`. Khi đó
`P(v) = Σ_{i: r_i = v} [e^{−(ts−p_{i+1})/μ} − e^{−(ts−p_i)/μ}]` (chuẩn hoá). Công thức tính đúng (không lấy mẫu), xử lý
được backport (version cũ phát hành muộn).

### 3.2 Declared‑floor anchoring và mô hình hỗn hợp
Nếu manifest khai báo `^4.18.2`, version 4.18.2 phải tồn tại khi lock được tạo ⇒ `t_lock ≥ max_i pub(min_satisfying(range_i))`.
Vì npm/uv **không nâng version đã lock khi thêm phụ thuộc mới**, lockfile là hỗn hợp nhiều thời điểm; do đó dùng phân phối
hỗn hợp `P = w·P_{anchor} + (1−w)·P_{prior}`. Tham số `(μ, w)` tinh chỉnh **chỉ trên tập dev** (25% repo, theo hash tên):
npm `μ=120 ngày, w=0.5`; PyPI `μ=60, w=0` (lockfile Python hầu như không refresh đồng loạt); Maven không nhạy.

### 3.3 Ràng buộc chéo và khôi phục transitive
Requirements khai báo của các component đã biết version (PyPI `requires_dist`, npm `dependencies`, Maven qua deps.dev) được
giao với range của component đang bất định. Với SBOM có dấu hiệu "chỉ phụ thuộc trực tiếp", VERA lấy cạnh và requirement
của đồ thị phụ thuộc từ deps.dev rồi **tự resolve lại từng node bằng temporal model tại `ts`** (deps.dev resolve tại
thời điểm crawl của nó, không phải thời điểm của SBOM). Maven dùng "nearest‑wins" và resolve `${property}` /
`dependencyManagement` qua chuỗi parent pom và BOM import.

### 3.4 Dấu vân tay bản phát hành OS
Gói `deb`/`apk` thiếu `distro` không thể quét (scanner không chọn được namespace CSDL). VERA chấm điểm mỗi bản phát hành
theo số cặp `(source package, version)` xuất hiện *nguyên văn* trong các sự kiện fixed/introduced của advisory OSV cho bản
đó; chỉ chấp nhận người thắng rõ ràng. Ca không rõ → LLM; đề xuất của LLM bị **bác** nếu mâu thuẫn với dấu vân tay.

### 3.5 VUG — Vulnerability‑Uncertainty‑Guided prioritisation
* Task version: `D(c) = Σ_v P(v)·sev(V(v) Δ V(mode))` — khối lượng mức nghiêm trọng của lỗ hổng sẽ báo sai nếu chọn sai.
* Task định danh: tổng mức nghiêm trọng của mọi advisory OSV từng gắn với tên đó (tên "dễ có lỗ hổng" trước).
* Ưu tiên = giá trị / chi phí; task có giá trị 0 **không thể** thay đổi kết luận lỗ hổng nên đẩy xuống cuối.

### 3.6 Agent LLM có verifier
Agent (ReAct, tool calling) có các tool `registry_lookup`, `list_versions`, `get_requirements`, `maven_resolve`,
`osv_lookup`, `submit_fix`. Mỗi kết quả tool được gán mã bằng chứng `E1, E2…`. **Verifier** chỉ chấp nhận đề xuất khi:
package tồn tại trên registry, version tồn tại, thoả range khai báo, phát hành trước `ts`, và có trích dẫn bằng chứng hợp
lệ; nếu không, trả lý do cho agent sửa một lần.

### 3.7 Báo cáo lỗ hổng xác suất
`P(vuln) = Σ_v P(v)·1[v bị ảnh hưởng]`, phân tầng *confirmed* (≥0.95), *likely* (≥0.5), *possible* (<0.5). Metric chính
dùng ngưỡng 0.5; tầng *possible* là danh sách cần con người xem xét.

## 4. Dữ liệu (SBOM‑RepairBench)

| Tập | Nguồn | Ground truth | SBOM lỗi |
|---|---|---|---|
| A‑npm (40) | Repo GitHub ≥1000★, có `package-lock.json`, commit cố định | Mọi package trong lockfile (version, integrity) | Manifest‑only: phụ thuộc trực tiếp + range (như GitHub dependency graph / Syft khi không có lockfile) |
| A‑PyPI (40) | Repo GitHub có `uv.lock`/`poetry.lock` + `pyproject.toml` | Mọi package trong lockfile | Manifest‑only |
| A‑Maven (32) | 19 artifact Apache/Eclipse trên Maven Central công bố `*-cyclonedx.json` | SBOM do cyclonedx‑maven‑plugin sinh khi build | `pom.xml` đã phát hành: `${property}` chưa resolve, version do parent quản lý bị thiếu |
| B‑container (12) | Image Debian 12 / Alpine 3.17–3.18 phổ biến, pin digest | Syft v1.18.1 (CycloneDX) | Suy giảm có kiểm soát (medium/heavy, 2 seed) |
| C‑degraded | Ground truth tập A | — | 9 toán tử suy giảm mô phỏng lỗi thật (bỏ version, range hoá, bỏ PURL, đổi tên, bỏ groupId, bỏ distro, bỏ component, bỏ license/hash) ở 3 mức |
| Khảo sát RQ1 | SBOM GitHub dependency graph (SPDX 2.3) của repo phổ biến | — | — |

CSDL lỗ hổng: snapshot OSV ngày 2026‑11‑12 (PyPI, npm, Maven, Debian, Alpine; ~364k bản ghi), matcher offline tự viết
(ECOSYSTEM/SEMVER ranges, so sánh version PEP 440 / semver / Maven / dpkg / apk), khử trùng lặp theo alias CVE/GHSA.

## 5. Thiết kế thí nghiệm

* **Baseline**: B0 (giữ nguyên), B1‑latest / B1‑ts (heuristic: chuẩn hoá tên, tra registry, chọn version mới nhất thoả range,
  có/không tôn trọng timestamp), B2 (re‑resolve bằng chính package manager tại timestamp: `npm --before`, `uv --exclude-newer`;
  Maven: đồ thị deps.dev của artifact gốc), B3 (LLM zero‑shot, không tool), B4 (ReAct agent tổng quát, cùng bộ tool, không
  temporal model/VUG/verifier).
* **VERA**: VERA‑noLLM (chỉ phần ký hiệu) và VERA@model; ablation −temporal, −anchor, −co‑constraint, −graph, −verifier, −VUG;
  đường cong ngân sách (RQ5); so sánh model: Claude Opus 5, Qwen3.6‑35B‑A3B, Qwen3.5‑122B‑A10B, Qwen3.5‑35B‑A3B (Qwen chạy
  chế độ không‑thinking để đồng nhất với Claude không bật extended thinking).
* **Chia dữ liệu**: dev (25% theo hash tên repo) chỉ dùng tinh chỉnh `(μ, w)`; mọi kết quả báo cáo trên tập **test**.
  Phương pháp ký hiệu chạy trên toàn bộ test; phương pháp dùng LLM chạy trên tập con phân tầng (giới hạn chi phí), ghi rõ `n`.
* **Metric**: precision/recall/F1 phát hiện lỗ hổng (cặp component–lỗ hổng, ngưỡng P≥0.5), recall có trọng số CVSS,
  recall lỗ hổng High/Critical, Brier score; F1 component (theo định danh) và component@version; độ chính xác version; tỉ lệ
  sửa đúng trên component lỗi; tỉ lệ hallucination (giá trị không tồn tại trên registry); thời gian, số lời gọi LLM, token.
  Kiểm định Wilcoxon cặp và bootstrap 95% CI.


## 6. Kết quả

> Mọi số liệu trên **tập test**; nguồn: `results/table_*.csv`, hình trong `figures/`. "n" = số SBOM. Các phương pháp dùng
> LLM được so sánh **theo cặp trên cùng tập mẫu** (`bench/paired_tables.py`); p = kiểm định Wilcoxon cặp trên vuln F1.

### 6.1 RQ1 — SBOM thực tế lỗi đến mức nào và ảnh hưởng ra sao?

| Nguồn | n | Thiếu version | Version là range | Chỉ có phụ thuộc trực tiếp | Component quét được |
|---|---|---|---|---|---|
| GitHub dependency graph — Java | 22 | 11.9% | 58.7% | 50% SBOM | 53.1% |
| GitHub dependency graph — JavaScript | 19 | 0.2% | 32.2% | 21% SBOM | 78.2% |
| GitHub dependency graph — TypeScript | 22 | 0.0% | 30.4% | 18% SBOM | 79.7% |
| GitHub dependency graph — Python | 20 | 23.7% | 27.2% | 50% SBOM | 52.2% |
| Manifest‑only — Maven (tập A) | 32 | 49.6% | 19.4% | 100% | 31.0% |
| Manifest‑only — npm (tập A) | 40 | 0.0% | 80.1% | 100% | 19.9% |
| Manifest‑only — PyPI (tập A) | 40 | 11.0% | 88.7% | 100% | 0.4% |

Quét lỗ hổng trên SBOM manifest‑only so với SBOM chuẩn từ lockfile: **chỉ tìm thấy 48/432 (11.1%) lỗ hổng Maven,
24/1.504 (1.6%) npm và 2/2.693 (0.1%) PyPI**. Kết luận RQ1: version‑là‑range và thiếu transitive là hai lỗi phổ biến và
nghiêm trọng nhất; một "báo cáo sạch" từ SBOM như vậy gần như không có giá trị. (Hình `rq1_defects.png`.)

### 6.2 RQ2 + RQ3 — Khôi phục SBOM lỗi tự nhiên và tác động lên đánh giá lỗ hổng

**Toàn bộ tập test (n = 78), phương pháp không dùng LLM:**

| Phương pháp | vuln P | vuln R | **vuln F1** [95% CI] | R (High/Crit) | F1 comp@version | F1 component | t/SBOM |
|---|---|---|---|---|---|---|---|
| B0 – SBOM lỗi | 0.32 | 0.15 | 0.17 [0.09, 0.25] | 0.04 | 0.09 | 0.39 | — |
| B1‑latest – heuristic | 0.58 | 0.23 | 0.27 [0.18, 0.35] | — | 0.19 | 0.39 | 0.4 s |
| B1‑ts – heuristic + timestamp | 0.58 | 0.25 | 0.29 [0.20, 0.38] | — | 0.21 | 0.39 | 0.2 s |
| B2 – re‑resolve (npm `--before`, uv `--exclude-newer`, deps.dev) | 0.75 | 0.47 | 0.49 [0.40, 0.58] | 0.39 | 0.60 | 0.84 | 8.8 s |
| **VERA‑noLLM** | **0.75** | **0.69** | **0.63 [0.56, 0.70]** | **0.66** | **0.62** | **0.87** | 2.8 s |

VERA‑noLLM hơn B2 có ý nghĩa thống kê (p = 0.006). Theo ecosystem (vuln F1): Maven **0.90** (B2 0.74, B0 0.44),
npm **0.47** (B2 0.43, B0 0.03), PyPI **0.55** (B2 0.30, B0 0.04). B2 thất bại một phần trên PyPI vì xung đột
extras/nền tảng (phải dùng fallback) và vì giả định lock được tạo đúng lúc timestamp.

**Cặp mẫu với LLM (n = 36, Qwen3.6‑35B; n = 18, Claude Opus 5):**

| Phương pháp | vuln F1 (Qwen‑subset) | vuln F1 (Opus‑subset) | Hallucination | Token LLM/SBOM | t/SBOM |
|---|---|---|---|---|---|
| B2 | 0.46 | 0.39 | 0% | 0 | 10 s |
| B3 – LLM zero‑shot | 0.25 (Qwen) | 0.30 (Opus) | 4.3% / **13.9%** | 7.7k / 4.1k | 78 s / 26 s |
| VERA‑noLLM | 0.68 | 0.74 | 0% | 0 | 2.7 s |
| VERA@LLM | 0.68 (Qwen) | 0.74 (Opus) | 0% | 53k / 34k | 62 s / 22 s |

p (VERA@Qwen vs B2) = 0.018; (VERA@Qwen vs B3) < 0.001; (VERA@Opus vs B3@Opus) < 0.001. **Trên SBOM lỗi tự nhiên,
LLM agent không cải thiện thêm so với phần ký hiệu** (các task là tinh chỉnh version, agent xác nhận lại mode của phân phối
— 310/310 đề xuất được chấp nhận nhưng không đổi kết luận lỗ hổng). Đây là một kết quả quan trọng cho RQ4: với lỗi
version/transitive, phương pháp ký hiệu có nền tảng tốt là đủ và rẻ hơn ~20 lần.

**Ablation (VERA‑noLLM, n = 78):**

| Biến thể | vuln P | vuln R | vuln F1 | Brier ↓ | F1 comp@ver |
|---|---|---|---|---|---|
| VERA‑noLLM đầy đủ | 0.75 | 0.69 | 0.63 | **0.24** | 0.62 |
| − khôi phục transitive | 0.67 | 0.36 | **0.39** | 0.56 | 0.31 |
| − temporal model (chọn version mới nhất thoả) | 0.78 | 0.55 | 0.55 | 0.52 | 0.59 |
| − declared‑floor anchoring | 0.69 | 0.75 | 0.64 | 0.24 | 0.63 |
| − co‑constraints | 0.75 | 0.69 | 0.63 | 0.23 | 0.62 |

Khôi phục transitive là thành phần quan trọng nhất (−0.24 F1), tiếp theo là temporal model (−0.08 F1 và Brier tệ gấp đôi:
nếu luôn chọn version mới nhất, báo cáo "chắc chắn" nhưng sai). Kết quả trung thực: **anchoring tăng precision
(0.69 → 0.75) nhưng giảm recall, F1 không đổi** trên test (trên dev nó tăng F1 npm) — anchoring hữu ích khi ưu tiên ít
báo động giả; **co‑constraints gần như không tác động** (npm/PyPI ít khi có hai phụ thuộc trực tiếp ràng buộc nhau).

### 6.3 SBOM suy giảm có kiểm soát (lỗi định danh)

| Mức suy giảm (n = 78) | B0 | B1‑ts | VERA‑noLLM | p (VERA vs B1) |
|---|---|---|---|---|
| Nhẹ | 0.85 | **0.89** | 0.87 | 0.63 (n.s.) |
| Trung bình | 0.67 | 0.78 | **0.81** | 0.15 |
| Nặng | 0.33 | 0.54 | **0.63** | < 0.001 |

Ở mức nhẹ heuristic đơn giản ngang/nhỉnh hơn (VERA thêm phân phối xác suất làm giảm precision 0.98 → 0.93). Lợi thế
của VERA tăng theo mức độ hư hỏng.

**So sánh model trên SBOM suy giảm nặng (n = 24 cặp):**

| Phương pháp | vuln P | vuln R | vuln F1 | Maven F1 | Hallucination | Token/SBOM |
|---|---|---|---|---|---|---|
| B1‑ts | 0.91 | 0.47 | 0.55 | 0.67 | 0% | 0 |
| B3@Qwen3.6‑35B (zero‑shot) | 0.52 | 0.74 | 0.50 | 0.61 | **8.3%** | 16k |
| VERA‑noLLM | 0.86 | 0.58 | 0.63 | 0.73 | 0% | 0 |
| VERA@Qwen3.5‑35B | 0.84 | 0.60 | 0.66 | 0.77 | 0% | 71k |
| VERA@Qwen3.6‑35B | 0.84 | 0.60 | 0.66 | 0.77 | 0% | 72k |
| VERA@Qwen3.5‑122B | 0.85 | 0.63 | **0.68** | **0.82** | 0.2% | 76k |

Tập con Opus (n = 18): B1‑ts 0.55 · **B3@Opus 0.62 (P 0.56, R 0.89, hallucination 11.3%)** · VERA‑noLLM 0.65 ·
VERA@Qwen3.6 0.70 · **VERA@Opus 0.72**. Agent cải thiện +0.03 đến +0.07 F1 so với phần ký hiệu, rõ nhất ở Maven (khôi phục
groupId), nhưng với n = 18–24 chênh lệch **chưa có ý nghĩa thống kê** (p = 0.08–0.12). Đáng chú ý, B3 có recall cao nhất
(R High/Crit 0.86 với Opus) và sửa đúng 70% version bị xoá (VERA: 58%): LLM tận dụng tri thức "anh em cùng release train"
(vd. `@babel/*`, `org.eclipse.jetty:*`) mà VERA hiện chưa khai thác — đổi lại precision thấp và bịa 1/9 giá trị.

### 6.4 Container (Debian 12 / Alpine 3.17–3.18)

| Suy giảm | B0 | B1‑ts | VERA‑noLLM | VERA@Qwen3.6‑35B |
|---|---|---|---|---|
| Trung bình (n = 24) | 0.39 | **0.90** | **0.90** | — |
| Nặng (mất toàn bộ distro, n = 24) | 0.06 | 0.46 | 0.47 | **0.66** (p = 0.005) |

Khi mất qualifier `distro`, scanner không chọn được namespace CSDL ⇒ gần như không thấy lỗ hổng OS. Debian khôi phục được
bằng ký hiệu (gói `base-files`); Alpine cần dấu vân tay OSV hoặc LLM. Agent đề xuất 10 distro, **3 bị verifier bác do mâu
thuẫn dấu vân tay OSV** (ví dụ đề xuất Alpine 3.18 cho image 3.17). Ví dụ `redis:7.0.12-alpine3.18`: 0 → 53/53 lỗ hổng.

### 6.5 RQ4 — AI Agent so với phương pháp truyền thống

| Tiêu chí | Truyền thống (B1, B2) | LLM tổng quát (B3 zero‑shot, B4 ReAct) | VERA (ký hiệu + agent có verifier) |
|---|---|---|---|
| vuln F1, SBOM tự nhiên | 0.29–0.49 | 0.25–0.30 (B4@Qwen 0.25, B4@Opus 0.30) | **0.63–0.74** |
| vuln F1, suy giảm nặng | 0.54 | 0.50–0.62 | **0.66–0.72** |
| Hallucination | 0% | 1–14% | **0%** (verifier bác 5% đề xuất định danh) |
| Chi phí / SBOM | ~0 token, 0.2–9 s | 4k–115k token, 26–150 s | 0 token (noLLM, 2.8 s); 34k–76k token khi dùng agent |
| Giải thích được | thấp | thấp (B3), trung bình (B4) | **cao** (mỗi sửa đổi có bằng chứng + confidence) |

ReAct agent tổng quát (B4) dùng cùng bộ tool với VERA nhưng chỉ đạt 0.25 (Qwen, n = 18) và 0.30 (Opus, n = 9) so với
0.74/0.73 của VERA trên cùng mẫu (p < 0.001 / p = 0.008) và tốn gấp 2–2.5 lần token: agent không có thuật toán resolve
nên không thể khôi phục hàng trăm phụ thuộc transitive trong ngân sách tool call. **Kết luận RQ4:** AI agent chỉ hữu ích
khi (i) được đặt **sau** một lõi ký hiệu mạnh, (ii) chỉ được giao các task định danh mà ký hiệu bế tắc, và (iii) bị một
verifier dựa trên registry chặn — khi đó nó cải thiện các lỗi định danh (distro, groupId) mà không bịa giá trị.
Hình `rq4_cost_quality.png`.

Thống kê verifier (mọi run): task định danh 694/733 được chấp nhận (bác: ecosystem rỗng 20, thiếu tên 17, package không
tồn tại — vd. `@img/sharp_libvips_darwin_x64` do LLM đổi `-` thành `_`); task version 565/570 (bác: vi phạm range khai báo);
task distro 7/10 (bác: mâu thuẫn dấu vân tay). Ở ngân sách mặc định (20 task), bỏ verifier không làm thay đổi F1 (0.658 cả
hai) vì đề xuất bị bác chủ yếu ở component không có lỗ hổng — verifier là **bảo đảm an toàn**, không phải nguồn tăng điểm.

### 6.6 RQ5 — Hiệu quả ngân sách của VUG (n = 24, suy giảm nặng, Qwen3.6‑35B)

| Ngân sách (task LLM / SBOM) | 0 | 1 | 2 | 4 | 8 | 16 |
|---|---|---|---|---|---|---|
| FIFO – vuln F1 (lời gọi LLM) | 0.626 | 0.628 (3.3) | 0.628 (5.8) | 0.656 (12.1) | **0.658** (22.8) | 0.658 (32.9) |
| VUG – vuln F1 (lời gọi LLM) | 0.626 | **0.650** (3.1) | **0.656** (5.5) | **0.658** (11.0) | 0.658 (20.8) | 0.658 (31.9) |

VUG đạt mức tối đa với **một nửa ngân sách** (4 task ≈ 11 lời gọi LLM so với 8 task ≈ 23 lời gọi). Mức lợi tuyệt đối nhỏ
(+0.02–0.03 F1 ở ngân sách 1–2) vì phần lớn chất lượng đến từ lõi ký hiệu. *Ghi chú quá trình*: phiên bản đầu của hàm giá trị
VUG tra advisory Maven theo `artifactId` trong khi OSV dùng khoá `group:artifact`, khiến task Maven (tác động lớn nhất) bị
xếp cuối và VUG thua FIFO; lỗi được sửa (`vuln.advisories_for_artifact`) và mọi run phụ thuộc VUG được replay từ cache.

### 6.7 Độ hiệu chỉnh của báo cáo lỗ hổng xác suất

| Xác suất dự đoán (trung bình bin) | 0.08 | 0.29 | 0.49 | 0.68 | 0.90 | 1.00 |
|---|---|---|---|---|---|---|
| Tỉ lệ đúng thực tế | 0.17 | 0.42 | 0.60 | 0.65 | 0.88 | 0.84 |
| Số phát hiện | 1.184 | 455 | 129 | 78 | 16 | 516 |

Xác suất khá sát thực tế ở vùng giữa; mô hình hơi **thiếu tự tin** ở xác suất thấp (tầng *possible* vẫn chứa 17–42% lỗ
hổng thật — không nên bỏ qua) và hơi quá tự tin ở tầng *confirmed* (84%: sai chủ yếu do transitive được thêm nhầm phiên bản).

## 7. Thảo luận

* **Tại sao lõi ký hiệu thắng?** Lỗi chiếm ưu thế trong SBOM thực tế là *range* và *thiếu transitive* — đây là bài toán
  resolve có cấu trúc, giải được bằng dữ liệu registry + mô hình thời gian, không cần "hiểu ngôn ngữ".
* **Khi nào LLM có giá trị?** Lỗi định danh cần tri thức thế giới không có API tra cứu: groupId Maven bị mất (Maven Central
  search không truy cập được), release Alpine, tên package bị biến dạng.
* **Báo cáo xác suất thay đổi cách dùng scanner:** thay vì "không có lỗ hổng" (sai) hoặc liệt kê mọi lỗ hổng của mọi
  version trong range (báo động giả), người phân tích nhận được danh sách xếp hạng theo xác suất.

## 8. Hạn chế và các mối đe doạ tính hợp lệ

1. **Ground truth**: lockfile phản ánh trạng thái tại commit, không phải runtime; truth container là Syft (đo khả năng khôi
   phục thông tin bị mất so với Syft, không đo độ đầy đủ tuyệt đối).
2. **Kích thước mẫu cho LLM**: 18–36 SBOM/phương pháp do chi phí; một số chênh lệch (VERA@LLM vs VERA‑noLLM trên suy giảm
   nặng) chưa có ý nghĩa thống kê.
3. **Nhiễm dữ liệu huấn luyện**: LLM có thể đã thấy lockfile của repo nổi tiếng (có lợi cho B3); commit được pin ở 11/2026.
4. **Cấu hình model**: mọi model chạy *không* suy luận mở rộng (thinking) để đồng nhất và giới hạn chi phí; khi bật, prompt
   dài của B3 làm cạn token trước khi trả lời.
5. **Tinh chỉnh**: `(μ, w)` chọn trên dev; anchoring cải thiện F1 trên dev nhưng không trên test (chỉ cải thiện precision).
6. **Chưa khai thác "release train"**: ràng buộc version anh em có trong `candidates.generate` nhưng chưa nối vào pipeline —
   B3 cho thấy đây là nguồn thông tin mạnh (hướng cải tiến trực tiếp).
7. **Phạm vi**: PyPI/npm/Maven/Debian/Alpine; chưa xử lý reachability (FP do mã không được gọi).
8. **Một số chi tiết đo**: 1 run B4@Qwen bị chạy trùng giữa hai luồng nên lần replay gọi lại LLM (kết quả replay được giữ);
   metric hallucination được làm chặt sau khi phát hiện danh sách version của deps.dev cập nhật chậm hơn endpoint chi tiết
   (toàn bộ run được chấm lại bằng metric mới).

## 9. Đóng góp

1. **C1 – SBOM‑RepairBench**: 112 cặp (SBOM lỗi tự nhiên, SBOM chuẩn) thật cho npm/PyPI/Maven + 12 container + khảo sát
   83 SBOM GitHub + 9 toán tử suy giảm + snapshot OSV cố định; toàn bộ HTTP/LLM được cache để tái lập.
2. **C2 – Phương pháp VERA**: temporal resolver model dạng đóng; declared‑floor anchoring với mô hình hỗn hợp; khôi phục
   transitive resolve lại theo thời điểm SBOM; dấu vân tay bản phát hành OS từ CSDL lỗ hổng; VUG; agent có verifier;
   báo cáo lỗ hổng xác suất.
3. **C3 – Bằng chứng thực nghiệm**: SBOM lỗi làm mất 89–99.9% lỗ hổng; VERA nâng vuln F1 từ 0.17 lên 0.63 trên toàn bộ tập
   test (~3.8 lần), hơn re‑resolve bằng package manager (p = 0.006); AI agent tổng quát không hơn heuristic đơn giản (0.25–0.30
   so với 0.29–0.35) và bịa 1–14% giá trị; agent có verifier
   cải thiện lỗi định danh với 0% hallucination; VUG đạt mức tối đa với nửa ngân sách.
4. **C4 – PoC**: thư viện + CLI + UI Streamlit (chẩn đoán, khôi phục có bằng chứng, lỗ hổng trước/sau, đồ thị phụ thuộc tương
   tác, agent trace, kết quả thí nghiệm).

## 10. Tái lập

```bash
bench/run_all.sh                       # thí nghiệm (cache: data/cache/*.sqlite)
python -m bench.reevaluate             # replay + chấm lại mọi run
python -m bench.paired_tables          # bảng so sánh cặp + Wilcoxon + hình
python -m bench.analysis rq1 budget calibration
streamlit run app/streamlit_app.py
```

## Tài liệu tham khảo

1. B. Xia, T. Bi, Z. Xing, Q. Lu, L. Zhu. *An Empirical Study on Software Bill of Materials: Where We Stand and the Road Ahead.* ICSE 2023, pp. 2630–2642. doi:10.1109/ICSE48619.2023.00219
2. T. Stalnaker, N. Wintersgill, O. Chaparro, M. Di Penta, D. M. German, D. Poshyvanyk. *BOMs Away! Inside the Minds of Stakeholders: A Comprehensive Study of Bills of Materials for Software Systems.* ICSE 2024. doi:10.1145/3597503.3623347
3. E. O'Donoghue, B. Boles, C. Izurieta, A. M. Reinhold. *Impacts of Software Bill of Materials (SBOM) Generation on Vulnerability Detection.* ACM SCORED 2024, pp. 67–76.
4. L. Zhou, M. Dacier, C. Konstantinou. *A Reality Check on SBOM-based Vulnerability Management: An Empirical Study and A Path Forward.* arXiv:2511.20313.
5. Y. Gamage, N. Gonzalez Fernandez, M. Monperrus, B. Baudry. *Software Bills of Materials in Maven Central.* MSR 2025. arXiv:2501.13832.
6. Y. Moriwaki. *sbom-unifier: Integration Framework for Heterogeneous SBOMs.* arXiv:2608.30708.
7. *A Landscape Study of Open Source and Proprietary Tools for Software Bill of Materials (SBOM).* arXiv:2402.11151.
8. *SBOM Generation Tools in the Python Ecosystem: an In-Detail Analysis.* arXiv:2409.1214.
9. *A Large Scale Empirical Analysis on the Adherence Gap between Standards and Tools in SBOM.* arXiv:2601.05622.
10. *Mind the Gap: How SBOM Specification Ambiguities Lead to Divergent Software Bills of Materials.* arXiv:2609.19920.
11. OSV — Open Source Vulnerabilities schema & data (osv.dev); deps.dev API; NTIA, *The Minimum Elements For a Software Bill of Materials* (2021).

