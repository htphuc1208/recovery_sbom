"""Offline OSV vulnerability matching + probabilistic vulnerability report.

Index: sqlite table (eco_base, name, id, json) built once from OSV zip dumps (pinned snapshot).
"""
from __future__ import annotations
import json
import sqlite3
import threading
import zipfile
from dataclasses import dataclass, field
from functools import lru_cache
from . import config
from .model import SBOM, Component
from .versions import comparator, satisfies
from .evidence.registry import norm_pypi

INDEX_DB = config.OSV_DIR / "osv_index.sqlite"
SEV_LABEL = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "MEDIUM": 5.0, "LOW": 2.5}
_lock = threading.Lock()


def _norm_name(eco_base: str, name: str) -> str:
    if eco_base == "PyPI":
        return norm_pypi(name)
    if eco_base == "Maven":
        return name.lower()
    return name


def build_index(ecosystems=("PyPI", "npm", "Maven", "Debian", "Alpine")) -> None:
    conn = sqlite3.connect(INDEX_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS adv (eco TEXT, name TEXT, id TEXT, json TEXT)")
    conn.execute("CREATE INDEX IF NOT EXISTS i_adv ON adv(eco, name)")
    for eco in ecosystems:
        z = config.OSV_DIR / f"{eco}.zip"
        if not z.exists():
            print("missing", z)
            continue
        conn.execute("DELETE FROM adv WHERE eco=?", (eco,))
        n = 0
        with zipfile.ZipFile(z) as zf:
            for member in zf.namelist():
                if not member.endswith(".json"):
                    continue
                try:
                    d = json.loads(zf.read(member))
                except Exception:
                    continue
                if d.get("withdrawn"):
                    continue
                slim = {"id": d["id"], "aliases": d.get("aliases", []), "summary": (d.get("summary") or "")[:200],
                        "severity": d.get("severity", []), "dbsev": (d.get("database_specific") or {}).get("severity"),
                        "affected": []}
                names = set()
                for a in d.get("affected", []) or []:
                    p = a.get("package", {}) or {}
                    if not p.get("ecosystem", "").split(":")[0] == eco:
                        continue
                    slim["affected"].append({"eco": p.get("ecosystem"), "name": p.get("name"),
                                             "ranges": a.get("ranges", []), "versions": a.get("versions", []),
                                             "sev": (a.get("ecosystem_specific") or {}).get("severity") or
                                                    (a.get("database_specific") or {}).get("severity")})
                    names.add(_norm_name(eco, p.get("name", "")))
                js = json.dumps(slim)
                for nm in names:
                    conn.execute("INSERT INTO adv VALUES (?,?,?,?)", (eco, nm, d["id"], js))
                    n += 1
        conn.commit()
        print(eco, n, "rows")
    conn.close()


_conn = None


def _db():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(INDEX_DB, check_same_thread=False, timeout=120)
    return _conn


@lru_cache(maxsize=200_000)
def advisories_for(eco_base: str, name: str) -> tuple:
    with _lock:
        rows = _db().execute("SELECT json FROM adv WHERE eco=? AND name=?", (eco_base, _norm_name(eco_base, name))).fetchall()
    return tuple(json.loads(r[0]) for r in rows)


def _severity(adv: dict, aff: dict | None = None) -> float:
    lab = (aff or {}).get("sev") or adv.get("dbsev")
    if isinstance(lab, str) and lab.upper() in SEV_LABEL:
        return SEV_LABEL[lab.upper()]
    for s in adv.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS_V3"):
            try:
                from cvss import CVSS3
                return float(CVSS3(s["score"]).base_score)
            except Exception:
                pass
    if adv["id"].startswith("MAL-"):
        return 10.0
    return 5.0  # unknown -> medium


def canonical_id(adv: dict) -> str:
    ids = [adv["id"]] + list(adv.get("aliases", []) or [])
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    if cves:
        return cves[0]
    ghsa = sorted(i for i in ids if i.startswith("GHSA-"))
    return ghsa[0] if ghsa else adv["id"]


def _affected_version(aff: dict, version: str, eco: str) -> bool:
    if version in (aff.get("versions") or []):
        return True
    cmp = comparator(eco)
    for r in aff.get("ranges", []) or []:
        if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        events = r.get("events", [])
        # walk events in listed order (OSV spec: sorted)
        affected = False
        intro_ok = False
        for ev in events:
            if "introduced" in ev:
                iv = ev["introduced"]
                if iv == "0" or cmp(version, iv) >= 0:
                    intro_ok = True
                    affected = True
            elif "fixed" in ev and intro_ok:
                if cmp(version, ev["fixed"]) >= 0:
                    affected = False
                    intro_ok = False
            elif "last_affected" in ev and intro_ok:
                if cmp(version, ev["last_affected"]) > 0:
                    affected = False
                    intro_ok = False
            elif "limit" in ev and intro_ok:
                if cmp(version, ev["limit"]) >= 0:
                    affected = False
                    intro_ok = False
        if affected:
            return True
    return False


def vulns_for(eco: str, name: str, version: str) -> list[tuple[str, float, str]]:
    """[(canonical_id, severity, osv_id)] affecting (eco,name,version). eco like 'PyPI' or 'Debian:12'."""
    if not eco or not name or not version:
        return []
    base = eco.split(":")[0]
    out = {}
    for adv in advisories_for(base, name):
        for aff in adv["affected"]:
            ae = aff.get("eco") or base
            if ":" in eco and ":" in ae and not ae.startswith(eco.split(":")[0] + ":" + eco.split(":")[1]):
                continue  # distro release mismatch
            if _affected_version(aff, version, ae):
                cid = canonical_id(adv)
                out[cid] = (cid, _severity(adv, aff), adv["id"])
                break
    return list(out.values())


@lru_cache(maxsize=50_000)
def advisories_for_artifact(artifact: str) -> tuple:
    """Maven advisories whose package is '<any group>:<artifact>' (identity task when the groupId is missing)."""
    with _lock:
        rows = _db().execute("SELECT json FROM adv WHERE eco='Maven' AND name LIKE ?", ("%:" + artifact.lower(),)).fetchall()
    return tuple(json.loads(r[0]) for r in rows)


@lru_cache(maxsize=1)
def known_os_releases() -> frozenset:
    with _lock:
        rows = _db().execute("SELECT DISTINCT json_extract(json, '$.affected[0].eco') FROM adv WHERE eco IN ('Debian','Alpine')").fetchall()
    return frozenset(r[0] for r in rows if r[0])


def component_vulns(c: Component) -> list[tuple[str, float, str]]:
    eco = c.osv_ecosystem()
    if not eco or not c.version:
        return []
    from .versions import looks_like_range
    if looks_like_range(c.version):
        return []  # a range is not a version: scanners cannot match it (this is the "bad SBOM" effect)
    return vulns_for(eco, c.osv_name(), c.version)


@dataclass
class Finding:
    component: str          # identity key
    vuln: str               # canonical id
    severity: float
    prob: float = 1.0       # probability (VERA probabilistic report)
    osv_id: str = ""
    version: str = ""

    @property
    def tier(self) -> str:
        return "confirmed" if self.prob >= 0.95 else "likely" if self.prob >= 0.5 else "possible"


def scan(s: SBOM, probabilistic: bool = True) -> list[Finding]:
    """Scan SBOM. If a component carries a candidate distribution (VERA), emit probabilistic findings."""
    out: dict[tuple, Finding] = {}
    for c in s.components:
        key = c.key()
        if probabilistic and c.candidates and len(c.candidates) > 1:
            eco = c.osv_ecosystem()
            agg: dict[str, list] = {}
            for v, p in c.candidates.items():
                for cid, sev, oid in vulns_for(eco, c.osv_name(), v):
                    a = agg.setdefault(cid, [0.0, sev, oid])
                    a[0] += p
            for cid, (p, sev, oid) in agg.items():
                out[(key, cid)] = Finding(key, cid, sev, min(p, 1.0), oid, c.version or "")
        else:
            for cid, sev, oid in component_vulns(c):
                out[(key, cid)] = Finding(key, cid, sev, 1.0, oid, c.version or "")
    return list(out.values())


def release_fingerprint(pkgs: list[tuple[str, str]], family: str) -> list[tuple[str, int]]:
    """Score each OS release of `family` (Alpine|Debian) by how many installed (source-name, version) pairs appear
    verbatim as a fixed/affected version in that release's OSV advisories. -> [(eco, score)] best first."""
    from collections import Counter
    score = Counter()
    for name, ver in pkgs:
        rels = set()
        for adv in advisories_for(family, name):
            for aff in adv["affected"]:
                e = aff.get("eco") or ""
                if ver in (aff.get("versions") or []):
                    rels.add(e)
                for r in aff.get("ranges", []) or []:
                    for ev in r.get("events", []):
                        if ver in (ev.get("fixed"), ev.get("introduced"), ev.get("last_affected")):
                            rels.add(e)
        for e in rels:
            score[e] += 1
    return score.most_common()
