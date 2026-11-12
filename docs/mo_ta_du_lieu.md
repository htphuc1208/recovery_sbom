# Cơ sở dữ liệu VERA — mô tả cấu trúc và cách khai thác

> Đi kèm bộ dữ liệu trên Google Drive và mã nguồn tại https://github.com/htphuc1208/recovery_sbom.
> Mọi dữ liệu được thu thập đến ngày **2026‑11‑12**. Đường dẫn trong tài liệu tính từ thư mục gốc của repo.

## 0. Danh sách gói tải về

| File trên Drive | Giải nén vào | Nội dung | Dung lượng |
|---|---|---|---|
| `VERA_source.zip` | thư mục mới (là repo) | Mã nguồn tại commit được dùng trong báo cáo (giống GitHub) | ~19 MB |
| `VERA_dataset_bench.zip` | `data/bench/` | **Tập A, tập B, tập khảo sát** (input + ground truth) | ~16 MB |
| `VERA_osv_snapshot.zip` | `data/osv/` | Snapshot CSDL lỗ hổng OSV + index đã dựng | ~840 MB |
| `VERA_cache.zip` | `data/cache/` | Cache mọi lời gọi HTTP (registry, deps.dev, GitHub) và LLM | ~100 MB |
| `VERA_results.zip` | `results/`, `figures/` | Output của mọi thí nghiệm (từng SBOM, từng phương pháp) + bảng + hình | ~3 MB |

Có đủ 5 gói thì có thể tái lập **chính xác** mọi số liệu trong báo cáo, kể cả khi không có mạng (`VERA_OFFLINE=1`).

## 1. Tổng quan các tập dữ liệu

| Tập | Thư mục | Số mẫu | Nguồn | Input (SBOM lỗi) | Ground truth | Dùng cho |
|---|---|---|---|---|---|---|
| A‑npm | `data/bench/A/npm/` | 40 repo | GitHub, ≥1000★, có `package-lock.json` | `bad_manifest.json` | `truth.json` (từ lockfile) | RQ2–RQ5, suy giảm |
| A‑PyPI | `data/bench/A/pypi/` | 40 repo | GitHub, có `uv.lock`/`poetry.lock` | `bad_manifest.json` | `truth.json` (từ lockfile) | RQ2–RQ5, suy giảm |
| A‑Maven | `data/bench/A/maven/` | 32 bản phát hành (19 artifact) | Maven Central | `bad_manifest.json` (từ `pom.xml`) | `truth.json` (SBOM do `cyclonedx-maven-plugin` công bố) | RQ2–RQ5, suy giảm |
| B‑container | `data/bench/B/` | 12 image | Docker Hub, pin digest | sinh lúc chạy bằng toán tử suy giảm | `truth.json` (Syft v1.18.1) | §6.4 |
| Khảo sát | `data/bench/survey/<ngôn ngữ>/` | 88 file (83 SBOM phân tích được) | GitHub dependency graph API | — (dữ liệu quan sát) | — | RQ1 |
| OSV | `data/osv/` | 364.040 advisory | osv.dev (PyPI, npm, Maven, Debian, Alpine) | — | — | đối chiếu lỗ hổng |

Tách dev/test (cố định, không ngẫu nhiên): mẫu thuộc **dev** khi `int(md5(tên_thư_mục), 16) % 4 == 0`, còn lại là **test**
(`bench/run_experiments.py`). Tập A: 34 dev / 78 test (Maven 25, npm 29, PyPI 24 mẫu test).

## 2. Cấu trúc chi tiết

### 2.1 Tập A — repo có lockfile và artifact Maven (`data/bench/A/<eco>/<mẫu>/`)

Tên thư mục mẫu: `owner__repo` (npm/PyPI) hoặc `groupId__artifactId__version` (Maven).

```
data/bench/A/npm/ChromeDevTools__chrome-devtools-mcp/
├── meta.json            # thông tin mẫu
├── bad_manifest.json    # INPUT: SBOM lỗi tự nhiên (CycloneDX 1.5)
└── truth.json           # GROUND TRUTH: SBOM chuẩn (CycloneDX 1.5)
```

**`meta.json`**

| Trường | Ý nghĩa | Ví dụ |
|---|---|---|
| `repo` | repo GitHub (hoặc `group:artifact` với Maven) | `ChromeDevTools/chrome-devtools-mcp` |
| `sha` | commit được pin (npm/PyPI) | `83d2ba4d…` |
| `version` | version artifact (Maven) | `5.1.7` |
| `timestamp` | thời điểm commit / phát hành = timestamp của SBOM | `2026-11-12T06:58:55+00:00` |
| `stars` | số sao GitHub lúc thu thập | `55145` |
| `ecosystem` | `npm` / `pypi` / `maven` | |
| `n_truth`, `n_bad` | số component trong truth / trong SBOM lỗi | `471`, `30` |

**`bad_manifest.json`** — mô phỏng SBOM mà công cụ thật sinh ra khi không có lockfile (GitHub dependency graph, Syft/Trivy):
chỉ có phụ thuộc **trực tiếp**, version là **range** như trong manifest.

```json
{"type": "library", "bom-ref": "b0", "group": "@blackwell-systems", "name": "gcf",
 "version": "^2.2.2", "purl": "pkg:npm/%40blackwell-systems/gcf",
 "properties": [{"name": "dev", "value": "true"}]}
```
Với Maven: lấy từ `pom.xml` đã phát hành, nên còn `${property}` chưa resolve và version do parent/BOM quản lý bị bỏ trống.

**`truth.json`** — mọi package trong lockfile (kể cả transitive), version chính xác, PURL đầy đủ, hash, license:

```json
{"type": "library", "bom-ref": "c0", "group": "@babel", "name": "runtime", "version": "7.29.10",
 "purl": "pkg:npm/%40babel/runtime@7.29.10",
 "hashes": [{"alg": "SHA-512", "content": "369ba0…"}], "licenses": [{"license": {"id": "MIT"}}],
 "properties": [{"name": "dev", "value": "true"}]}
```
Hai file đều có `metadata.timestamp` và mảng `dependencies` (đồ thị `ref → dependsOn`).

### 2.2 Tập B — container (`data/bench/B/`)

```
data/bench/B/
├── images.txt                          # danh sách 12 image
└── redis__7.0.12-alpine3.18/           # tên image, ':' và '/' thay bằng '__'
    ├── meta.json   # image, digest (sha256), timestamp, ecosystem="container", n_truth
    └── truth.json  # SBOM CycloneDX do Syft v1.18.1 sinh
```
Component có PURL `pkg:deb/debian/...?distro=debian-12` hoặc `pkg:apk/alpine/...?distro=alpine-3.18.3`, kèm CPE.
Tập này **không có SBOM lỗi sẵn**: input được sinh khi chạy bằng `bench/degrade.py` (mục 2.4), với seed 0 và 1.
Image: Debian 12 (httpd, nginx, node, postgres, python, wordpress, jenkins) và Alpine 3.17–3.18 (ghost, nginx, node, postgres, python, redis).

### 2.3 Tập khảo sát RQ1 (`data/bench/survey/{Java,JavaScript,Python,TypeScript}/owner__repo.json`)

Mỗi file là phản hồi nguyên bản của API `GET /repos/{owner}/{repo}/dependency-graph/sbom`: `{"sbom": {...}}` theo
**SPDX 2.3** (`packages[]` gồm `name`, `versionInfo`, `externalRefs` chứa PURL, `relationships[]`). Dữ liệu giữ nguyên, không
chỉnh sửa. Đây chính là loại SBOM "lỗi tự nhiên" mà người dùng thật nhận được (version là range, thiếu version, chỉ có
phụ thuộc trực tiếp).

### 2.4 Tập suy giảm có kiểm soát (sinh từ truth, không lưu sẵn)

`bench/degrade.py` áp 9 toán tử lên từng component của `truth.json`. Bảng dưới là xác suất áp dụng cho mỗi component:

| Toán tử | light | medium | heavy |
|---|---|---|---|
| `drop_version` (xoá version) | 0.10 | 0.25 | 0.40 |
| `range_version` (thay bằng range) | 0.05 | 0.15 | 0.20 |
| `drop_purl` | 0.05 | 0.15 | 0.30 |
| `mangle_name` (biến dạng tên) | 0.05 | 0.10 | 0.20 |
| `drop_group` (mất groupId / scope) | 0.05 | 0.15 | 0.30 |
| `drop_distro` (mất qualifier distro) | 0.3 | 0.7 | 1.0 |
| `drop_component` (xoá hẳn component) | 0.05 | 0.15 | 0.30 |
| `drop_license`, `drop_hash` | 0.3 | 0.6 | 1.0 |

Kết quả là tất định theo `(mẫu, mức, seed)`, nên cùng tham số luôn sinh lại đúng SBOM lỗi đã dùng.

### 2.5 Snapshot OSV (`data/osv/`)

| File | Nội dung |
|---|---|
| `PyPI.zip`, `npm.zip`, `Maven.zip`, `Debian.zip`, `Alpine.zip` | dump gốc `https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip` |
| `SNAPSHOT_DATE` | ngày tải: `2026-11-12` |
| `osv_index.sqlite` | bảng `adv(eco TEXT, name TEXT, id TEXT, json TEXT)`, 364.040 dòng: một advisory OSV (JSON đầy đủ) cho mỗi `(ecosystem, package)` |

### 2.6 Cache (`data/cache/`)

| File | Bảng | Số bản ghi | Nội dung |
|---|---|---|---|
| `http_cache.sqlite` | `http(url PRIMARY KEY, status, body, ts)` | 56.502 | phản hồi registry npm/PyPI/Maven Central, deps.dev, GitHub |
| `llm_cache.sqlite` | `llm(k PRIMARY KEY, resp, ts)` | 6.532 | phản hồi LLM; `k` = SHA‑256 của (model, messages, tools, max_tokens, temperature, cấu hình thinking) |

### 2.7 Kết quả thí nghiệm (`results/`, `figures/`)

```
results/runs/<kịch bản>/<phương pháp>[@model]/<eco>__<mẫu>__<natural|light|medium|heavy>__s<seed>.json
                                              …/<cùng tên>.traces.json   # chỉ với phương pháp dùng LLM
```
* `<kịch bản>`: `main_natural`, `degraded_{light,medium,heavy}`, `containers`, `ablation`, `ablation_llm`, `rq5_budget`.
* `*.json`: metric của một SBOM. Gồm thời gian, số lời gọi evidence/LLM, token; P/R/F1 component, `exact_*` (component@version),
  `version_acc`, `defective_fixed`; P/R/F1 lỗ hổng (`vuln_*`), `vuln_r_high`, `vuln_brier`, danh sách `vuln_fp`/`vuln_fn`;
  `ntia`, `hallucination`; thống kê task agent (`x_*`).
* `*.traces.json`: danh sách quyết định của agent. Mỗi phần tử có `component`, `kind` (version/identity/distro), `value` (giá trị
  VUG), `proposal` (giá trị đề xuất, bằng chứng, lập luận), `accepted` và `reason` của verifier.
* `results/<kịch bản>.csv`: gộp các run. `results/table_*.csv`: bảng trong báo cáo. `figures/*.png`: hình.

## 3. Cách khai thác

### 3.1 Cài đặt và đặt dữ liệu
```bash
unzip VERA_source.zip -d recovery_sbom && cd recovery_sbom && unzip ../VERA_results.zip
python3 -m venv .venv && .venv/bin/pip install -e . && .venv/bin/pip install pytest uv
mkdir -p data && unzip ../VERA_dataset_bench.zip -d data/ && unzip ../VERA_osv_snapshot.zip -d data/ && unzip ../VERA_cache.zip -d data/
cp .env.example .env    # chỉ cần khi gọi LLM mới (không cần nếu chạy từ cache)
```

### 3.2 Đọc dữ liệu bằng Python
```python
import json, pathlib
from vera.sbom_io import load          # đọc CycloneDX / SPDX thành đối tượng SBOM
for d in sorted(pathlib.Path("data/bench/A/npm").iterdir()):
    meta  = json.load(open(d / "meta.json"))
    bad   = load(d / "bad_manifest.json")     # input
    truth = load(d / "truth.json")            # ground truth
    print(meta["repo"], len(bad.components), "->", len(truth.components))
```
Sinh SBOM suy giảm:
```python
from bench.degrade import degrade
bad, log = degrade(load("data/bench/B/redis__7.0.12-alpine3.18/truth.json"), level="heavy", seed=0)
```
Tra lỗ hổng offline:
```python
import sqlite3, json
db = sqlite3.connect("data/osv/osv_index.sqlite")
for (aid, js) in db.execute("select id, json from adv where eco='npm' and name='lodash'"):
    print(aid, json.loads(js).get("summary"))
```

### 3.3 Dùng công cụ trên một mẫu
```bash
.venv/bin/vera diagnose data/bench/A/npm/ChromeDevTools__chrome-devtools-mcp/bad_manifest.json
.venv/bin/vera repair   data/bench/A/npm/ChromeDevTools__chrome-devtools-mcp/bad_manifest.json -o fixed.cdx.json --report report.json --no-llm
.venv/bin/vera scan     fixed.cdx.json
.venv/bin/streamlit run app/streamlit_app.py      # UI: chọn mẫu bất kỳ trong data/bench
```

### 3.4 Tái lập thí nghiệm
```bash
export VERA_OFFLINE=1                    # mọi HTTP/LLM lấy từ cache, số liệu khớp báo cáo
bash bench/run_all.sh                    # toàn bộ kịch bản (xem README, mục "Dataset & code theo kịch bản")
.venv/bin/python -m bench.paired_tables  # bảng + kiểm định Wilcoxon + hình
.venv/bin/python -m bench.analysis rq1 budget calibration
```
Một kịch bản lẻ: `.venv/bin/python -m bench.run_experiments <kịch bản> --methods <...> [--model M] [--degrade L] [--split test] [--limit N] [--seeds 0,1]`.

### 3.5 Thu thập lại từ đầu (dữ liệu mới, kết quả có thể khác)
```bash
for e in PyPI npm Maven Debian Alpine; do curl -o data/osv/$e.zip https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip; done
.venv/bin/python -c "from vera.vuln import build_index; build_index()"
.venv/bin/python -m bench.collect_repos --eco npm --target 40      # GitHub search API + git clone (không cần token, có giới hạn tốc độ)
.venv/bin/python -m bench.collect_repos --eco pypi --target 40
.venv/bin/python -m bench.collect_maven
.venv/bin/python -m bench.collect_images                           # cần Docker
.venv/bin/python -m bench.real_sbom_survey 25
```

## 4. Giấy phép và lưu ý
* Lockfile, `pom.xml`, SBOM khảo sát được lấy từ repo/artifact công khai và giữ giấy phép của dự án gốc. SBOM GitHub dùng CC0‑1.0. OSV dùng CC‑BY 4.0.
* Cache LLM chỉ chứa prompt/phản hồi về tên và version package, không có dữ liệu cá nhân. File `.env` (khoá API) **không** được đóng gói.
