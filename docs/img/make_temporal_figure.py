"""Hình minh hoạ temporal resolver model trên dữ liệu thật (express ^4.17.0, SBOM ngày 2023-06-01).
Chạy: VERA_OFFLINE=1 .venv/bin/python docs/img/make_temporal_figure.py   (đọc registry từ cache)"""
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from vera.evidence import registry
from vera.versions import satisfies, is_prerelease
from vera.candidates import temporal_distribution, _parse_ts

SPEC, TS, MU = "^4.17.0", "2023-06-01T00:00:00Z", 120.0
FLOOR_DATE = "2022-11-15T00:00:00Z"   # ví dụ: cận dưới khai báo của một phụ thuộc KHÁC được phát hành ngày này

vs = registry.package_versions("npm", "express") or []
ts = _parse_ts(TS)
pool = [v for v in vs if not is_prerelease(v["version"], "npm") and satisfies(v["version"], SPEC, "npm")
        and _parse_ts(v["published"]) <= ts]
pool.sort(key=lambda v: v["published"])
P = temporal_distribution(pool, "npm", ts, MU)
floor = _parse_ts(FLOOR_DATE)
PF = temporal_distribution(pool, "npm", ts, MU, t_floor=floor)
for v in pool:
    print(v["version"], v["published"][:10], round(P.get(v["version"], 0), 3), round(PF.get(v["version"], 0), 3))

d = lambda t: datetime.fromtimestamp(t, timezone.utc)
WIN = 600  # ngày hiển thị trước timestamp
lo = ts - WIN * 86400
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 5.2), sharex=True, gridspec_kw={"height_ratios": [1, 1.4]})
# (a) mật độ thời điểm lock
xs = [ts - k * 86400 for k in range(0, WIN + 1)]
ax1.fill_between([d(x) for x in xs], [math.exp(-(ts - x) / (MU * 86400)) for x in xs], color="#74B9FF", alpha=.6,
                 label=f"prior: t_lock = ts − X,  X ~ Exp(μ = {MU:.0f} ngày)")
ax1.fill_between([d(x) for x in xs if x >= floor], [math.exp(-(ts - x) / (MU * 86400)) for x in xs if x >= floor],
                 color="#6C5CE7", alpha=.35, label="vùng còn lại khi có neo")
ax1.axvline(d(ts), color="#D63031", lw=2)
ax1.text(d(ts - 5 * 86400), 1.05, "timestamp SBOM", color="#D63031", fontsize=8, ha="right")
ax1.axvline(d(floor), color="#6C5CE7", ls="--")
ax1.text(d(floor - 5 * 86400), 1.05, "neo (ví dụ): lock phải sau ngày này", color="#6C5CE7", fontsize=8, ha="right")
ax1.set_yticks([]); ax1.set_ylim(0, 1.2); ax1.legend(fontsize=7, loc="center left")
ax1.set_title("(a) Không biết chính xác lúc tạo lockfile → mô hình hoá bằng phân phối", fontsize=9)
# (b) version phát hành và xác suất được chọn
outside = []
for v in pool:
    t = _parse_ts(v["published"])
    p0, p1 = P.get(v["version"], 0), PF.get(v["version"], 0)
    if t < lo:
        outside.append(f"{v['version']} (P={p0:.2f})")
        continue
    ax2.vlines(d(t), 0, p0, color="#0984E3", lw=7, alpha=.8)
    ax2.vlines(d(t + 3 * 86400), 0, p1, color="#6C5CE7", lw=2.5)
    if max(p0, p1) >= 0.005:
        ax2.text(d(t), max(p0, p1) + .03, f"{v['version']}\n{p0:.2f} → {p1:.2f}", fontsize=7, ha="center", va="bottom")
ax2.plot([], [], color="#0984E3", lw=7, label="P(version) — không neo")
ax2.plot([], [], color="#6C5CE7", lw=2.5, label="P(version) — có neo")
ax2.axvline(d(ts), color="#D63031", lw=2)
ax2.axvline(d(floor), color="#6C5CE7", ls="--")
if outside:
    ax2.text(d(lo + 10 * 86400), 1.05, "ngoài khung (cũ hơn): " + ", ".join(outside), fontsize=7, color="#636e72")
ax2.set_ylim(0, 1.25); ax2.set_ylabel("xác suất được resolve"); ax2.legend(fontsize=7, loc="center left")
ax2.set_title(f"(b) express {SPEC}: các version thoả range theo ngày phát hành", fontsize=9)
ax2.xaxis.set_major_locator(mdates.MonthLocator(interval=3))
ax2.xaxis.set_major_formatter(mdates.DateFormatter("%m/%Y"))
ax2.set_xlim(d(lo), d(ts + 20 * 86400))
fig.tight_layout()
out = Path(__file__).with_name("temporal_model.png")
fig.savefig(out, dpi=150)
print("saved", out)
