# Mô tả dự án — VERA: Khôi phục SBOM lỗi có định hướng lỗ hổng

## 1. Thông tin chung

| Mục | Nội dung |
|---|---|
| Tên đề tài | Khôi phục SBOM lỗi bằng suy luận ràng buộc–thời gian và AI Agent có kiểm chứng: tác động lên đánh giá lỗ hổng chuỗi cung ứng phần mềm |
| Tên tiếng Anh | VERA: Vulnerability‑aware Evidence‑grounded Repair Agent for bad SBOMs |
| Sinh viên thực hiện | Hoàng Tấn Phúc — phuc.ht235189@sis.hust.edu.vn |
| Giảng viên hướng dẫn | *(điền)* |
| Lĩnh vực | An toàn chuỗi cung ứng phần mềm, Software Bill of Materials (SBOM), AI Agent |
| Loại dự án | Nghiên cứu: đề xuất phương pháp + benchmark dữ liệu thật + thực nghiệm + PoC có giao diện |
| Mã nguồn | https://github.com/htphuc1208/recovery_sbom |
| Ngôn ngữ / nền tảng | Python ≥ 3.11, Streamlit (UI), Linux |

## 2. Bối cảnh và vấn đề

SBOM là danh sách các thành phần (thư viện, gói hệ điều hành) cấu thành một phần mềm. Scanner lỗ hổng dựa vào SBOM để đối
chiếu với CSDL lỗ hổng như OSV/NVD. Văn bản như EO 14028 (Mỹ) và NTIA "minimum elements" yêu cầu SBOM có tối thiểu tên,
version, định danh duy nhất và quan hệ phụ thuộc.

Thực tế SBOM thường **lỗi**:
- version bị thiếu hoặc chỉ ghi khoảng (`^4.17.0`);
- thiếu hoặc sai Package URL (PURL), thiếu groupId Maven, thiếu distro của gói OS;
- và nghiêm trọng nhất: **thiếu toàn bộ phụ thuộc bắc cầu (transitive)** khi SBOM được sinh mà không có lockfile.

Scanner chỉ khớp được bộ ba *(ecosystem, tên, version chính xác)*. Vì vậy một SBOM lỗi cho ra báo cáo "sạch" giả: scanner
im lặng không phải vì hệ thống an toàn mà vì không nhìn thấy gì.

**Bài toán:** cho một SBOM lỗi, không có mã nguồn hay artifact, khôi phục các trường và component bị thiếu sao cho kết quả
đánh giá lỗ hổng gần nhất với kết quả trên SBOM chuẩn. Mỗi sửa đổi phải kèm **bằng chứng** và **độ tin cậy**, và **không được bịa** giá trị.

## 3. Mục tiêu

1. Đo mức độ lỗi của SBOM thực tế và ảnh hưởng của nó lên phát hiện lỗ hổng.
2. Đề xuất phương pháp khôi phục SBOM lỗi, tối ưu theo tác động lên đánh giá lỗ hổng, có bằng chứng và độ tin cậy cho từng sửa đổi.
3. So sánh AI Agent (LLM) với phương pháp truyền thống trên 4 trục: độ chính xác, hallucination, chi phí, độ trễ.
4. Xây dựng benchmark từ dữ liệu thật và công cụ PoC có giao diện, tái lập được.

**Câu hỏi nghiên cứu**
- **RQ1:** SBOM thực tế lỗi đến mức nào, và lỗi đó làm mất bao nhiêu lỗ hổng?
- **RQ2:** VERA khôi phục SBOM lỗi chính xác đến đâu so với các giải pháp hiện có?
- **RQ3:** Khôi phục SBOM thay đổi kết quả đánh giá lỗ hổng như thế nào?
- **RQ4:** AI Agent so với phương pháp truyền thống: khi nào có ích, khi nào không?
- **RQ5:** Ưu tiên theo bất định lỗ hổng (VUG) có dùng ngân sách LLM hiệu quả hơn không?

## 4. Phạm vi

| Trong phạm vi | Ngoài phạm vi |
|---|---|
| Ecosystem npm, PyPI, Maven; gói OS Debian 12, Alpine 3.17–3.18 | Go, Rust, NuGet, Ubuntu… (kiến trúc cho phép mở rộng) |
| Đầu vào chỉ có SBOM (CycloneDX / SPDX JSON) | Sinh SBOM từ mã nguồn (đã có Syft/Trivy) |
| Lỗi version, range, PURL, tên, groupId, distro, transitive, license/hash | Phân tích reachability (mã có lỗ hổng có được gọi không) |
| Registry công khai (npm, PyPI, Maven Central) + deps.dev + OSV | Registry nội bộ / package riêng |

## 5. Phương pháp (VERA)

```
SBOM lỗi ─► (1) Chẩn đoán ─► (2) Định danh ký hiệu (chuẩn hoá tên, registry, groupId, distro, dấu vân tay OSV)
        ─► (3) Neo thời gian từ cận dưới khai báo ─► (4) Temporal resolver: phân phối P(version)
        ─► (5) Ràng buộc chéo ─► (6) Khôi phục transitive (deps.dev + resolve lại tại thời điểm SBOM)
        ─► (7) VUG xếp hạng task ─► (8) Agent LLM (tool‑use) cho task mơ hồ ─► Verifier
        ─► SBOM CycloneDX đã sửa (bằng chứng + độ tin cậy) + báo cáo lỗ hổng xác suất
```

| Thành phần | Ý tưởng chính |
|---|---|
| Temporal resolver model | Package manager cài version cao nhất thoả range *tại thời điểm lock*. Thời điểm này không biết, nên được mô hình hoá `ts − t_lock ~ Exp(μ)` ⇒ P(version) dạng đóng |
| Neo thời gian + mô hình hỗn hợp | Cận dưới của range khai báo đã tồn tại lúc lock ⇒ ràng buộc `t_lock`; trộn có/không neo vì lockfile là hỗn hợp nhiều thời điểm |
| Khôi phục transitive | Lấy cạnh và requirement từ deps.dev; version của node con resolve lại tại timestamp SBOM; Maven resolve `${property}`, parent POM, BOM |
| Dấu vân tay OS | Suy distro Debian từ `base-files`, Alpine từ version gói đối chiếu với chính CSDL OSV |
| VUG | Ưu tiên task theo khối lượng lỗ hổng có thể thay đổi kết luận / chi phí; task giá trị 0 không dùng LLM |
| Agent LLM + verifier | LLM chỉ nhận task định danh/distro mà ký hiệu bế tắc; mọi đề xuất phải tồn tại trên registry, thoả range, phát hành trước timestamp, có trích dẫn bằng chứng |
| Báo cáo xác suất | `P(vuln) = Σ P(v)·1[v bị ảnh hưởng]` ⇒ tầng confirmed / likely / possible |

Chi tiết và cơ sở lý thuyết: [bao_cao.md](bao_cao.md) §3, [co_so_phuong_phap.md](co_so_phuong_phap.md).

## 6. Dữ liệu (SBOM‑RepairBench)

| Tập | Quy mô | Ground truth |
|---|---|---|
| A‑npm, A‑PyPI | 40 + 40 repo GitHub có lockfile, commit cố định | Lockfile |
| A‑Maven | 32 bản phát hành (19 artifact) trên Maven Central | SBOM do `cyclonedx-maven-plugin` công bố |
| B‑container | 12 image Debian/Alpine, pin digest | Syft v1.18.1 |
| Suy giảm có kiểm soát | 9 toán tử × 3 mức (nhẹ / trung bình / nặng) trên tập A | SBOM chuẩn của tập A |
| Khảo sát RQ1 | 83 SBOM GitHub dependency graph (Java, JS, TS, Python) | — |
| CSDL lỗ hổng | Snapshot OSV 12/11/2026, ~364k advisory | — |

Chia dev/test cố định theo hash tên (34 dev / 78 test). Tham số chỉ tinh chỉnh trên dev. Mô tả cấu trúc dữ liệu:
[mo_ta_du_lieu.md](mo_ta_du_lieu.md).

## 7. Thực nghiệm

- **Baseline:** B0 (giữ nguyên), B1 (heuristic chọn version mới nhất), B2 (re‑resolve bằng `npm --before` / `uv --exclude-newer`),
  B3 (LLM zero‑shot), B4 (ReAct agent, cùng bộ tool với VERA).
- **Model LLM:** Claude Opus 5, Qwen3.6‑35B, Qwen3.5‑122B, Qwen3.5‑35B (temperature 0, không bật thinking).
- **Metric:** P/R/F1 phát hiện lỗ hổng, recall High/Critical, Brier score, F1 component@version, tỉ lệ hallucination, token, thời gian.
- **Thống kê:** Wilcoxon cặp trên cùng tập mẫu, bootstrap 95% CI, hiệu chỉnh Holm theo từng câu hỏi nghiên cứu.

## 8. Kết quả chính (tập test)

| Kịch bản | Kết quả |
|---|---|
| RQ1 | SBOM manifest‑only chỉ phát hiện 11.1% (Maven), 1.6% (npm), 0.1% (PyPI) lỗ hổng thật |
| RQ2/RQ3, SBOM lỗi tự nhiên (n = 78) | vuln F1: SBOM gốc 0.17 → heuristic 0.29 → re‑resolve 0.49 → **VERA 0.63** (p = 0.006); recall High/Critical 0.04 → 0.66 |
| RQ4, LLM tổng quát | B3/B4 đạt 0.25–0.30 và bịa 1–14% giá trị; VERA 0.68–0.74 trên cùng mẫu, không bịa |
| RQ4, lỗi định danh | Container mất distro: 0.47 → **0.66** (p = 0.005); Maven mất groupId: 0.73 → 0.82 |
| RQ5 | VUG đạt F1 tối đa với ~11 lời gọi LLM; FIFO cần ~23 lời gọi |
| Chi phí | VERA không LLM: 2.8 s/SBOM, 0 token; khi bật agent: 34k–76k token/SBOM |

**Kết luận:** lõi ký hiệu dựa trên ngữ nghĩa package manager giải quyết phần lớn lỗi version và transitive. AI Agent chỉ có
ích khi đứng sau lõi đó, chỉ nhận lỗi định danh, và bị verifier kiểm soát.

## 9. Đóng góp

1. **C1 — Benchmark SBOM‑RepairBench:** 112 cặp SBOM lỗi tự nhiên / SBOM chuẩn từ dữ liệu thật, 12 container, khảo sát 83 SBOM, snapshot OSV cố định.
2. **C2 — Phương pháp VERA:** temporal resolver model, neo thời gian từ cận dưới khai báo, khôi phục transitive, dấu vân tay OS, VUG, agent có verifier, báo cáo lỗ hổng xác suất.
3. **C3 — Bằng chứng thực nghiệm:** tác động của SBOM lỗi và của việc khôi phục lên đánh giá lỗ hổng; điều kiện để AI Agent có ích.
4. **C4 — PoC mã nguồn mở:** CLI + UI Streamlit, tái lập hoàn toàn từ cache (`VERA_OFFLINE=1`).

So sánh với các giải pháp trong tài liệu: [so_sanh_giai_phap.xlsx](so_sanh_giai_phap.xlsx).

## 10. Hạn chế và hướng phát triển

- Mỗi component được suy luận độc lập, chưa dùng chung bằng chứng về thời điểm lock của cả lockfile → hướng: posterior Bayes chung.
- Chưa tìm lại component bị xoá khỏi SBOM đầy đủ; chưa khai thác ràng buộc "release train" → hướng: bao đóng đồ thị, ràng buộc mềm theo namespace.
- Kích thước mẫu cho LLM nhỏ (n = 18–36); lợi ích LLM trên SBOM suy giảm nặng chưa có ý nghĩa thống kê.
- Ground truth container là Syft; chưa đối chiếu matcher lỗ hổng với osv‑scanner; chưa xử lý reachability.

## 11. Công nghệ sử dụng

| Nhóm | Công nghệ |
|---|---|
| Ngôn ngữ | Python 3.11+ |
| Xử lý version / định danh | `packaging` (PEP 440), `semver`, `node-semver`, `packageurl-python`, so sánh dpkg/apk tự viết |
| Nguồn dữ liệu | npm registry, PyPI, Maven Central, deps.dev API v3, GitHub API, OSV |
| LLM | API OpenAI‑compatible (`openai`): Claude Opus 5, Qwen3.x |
| Phân tích | `pandas`, `scipy`, `matplotlib`, `cvss` |
| Giao diện | Streamlit, `pyvis` (đồ thị phụ thuộc) |
| Khác | `httpx`, cache sqlite, Docker + Syft (sinh ground truth container), pytest |

## 12. Cấu trúc mã nguồn

```
vera/                 thư viện chính
  pipeline.py           luồng khôi phục 8 bước, định danh ký hiệu, suy distro OS
  candidates.py         temporal resolver model, sinh ứng viên version
  graph_completion.py   khôi phục transitive
  vuln.py               đối chiếu OSV, danh sách bản phát hành OS, báo cáo xác suất
  prioritizer.py        VUG
  agent/                LLM client, tool, verifier, vòng lặp agent
  baselines/            B1–B4
  evidence/             client registry, deps.dev, Maven POM
  cli.py                lệnh vera diagnose / repair / scan
bench/                thu thập dữ liệu, chạy thí nghiệm, phân tích, kiểm định
app/streamlit_app.py  giao diện demo
data/bench/           benchmark (tập A, B, khảo sát)
results/, figures/    kết quả, bảng, hình
docs/                 báo cáo, cơ sở phương pháp, mô tả dữ liệu, outline thuyết trình
tests/                unit test
```

## 13. Chạy nhanh

```bash
python3 -m venv .venv && .venv/bin/pip install -e . && .venv/bin/pip install pytest uv
cp .env.example .env                                        # điền LLM_BASE_URL, LLM_API_KEY nếu dùng agent
.venv/bin/vera repair sbom.json -o fixed.cdx.json --no-llm  # khôi phục thuần ký hiệu
.venv/bin/streamlit run app/streamlit_app.py                # UI demo
```

Hướng dẫn đầy đủ (dữ liệu, tái lập thí nghiệm): [README.md](../README.md).

## 14. Tài liệu liên quan

| Tài liệu | Nội dung |
|---|---|
| [bao_cao.md](bao_cao.md) | Báo cáo đầy đủ |
| [co_so_phuong_phap.md](co_so_phuong_phap.md) | Cơ sở lý thuyết, công thức |
| [mo_ta_du_lieu.md](mo_ta_du_lieu.md) | Cấu trúc và cách khai thác dữ liệu |
| [so_sanh_giai_phap.xlsx](so_sanh_giai_phap.xlsx) | So sánh với giải pháp trong tài liệu |
| [thuyet_trinh_outline.md](thuyet_trinh_outline.md) | Outline thuyết trình |
