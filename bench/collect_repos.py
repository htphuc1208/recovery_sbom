"""Collect real open-source repos with lockfiles (npm / PyPI) and build
(ground-truth SBOM from lockfile, natural bad SBOM from manifest only) pairs.

Ground truth  : every package resolved in the lockfile (exact version, purl, hash from lock).
Bad SBOM      : what a manifest-only generator emits (GitHub dependency graph without lockfile,
                many CI SBOM tools on source trees): direct deps only, version = declared range.
SBOM timestamp: HEAD commit date (lockfile is valid at that time).
"""
from __future__ import annotations
import argparse
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from vera.evidence.http import get
from vera.evidence.registry import norm_pypi
from bench.common import BENCH, save_json

GH = "https://api.github.com/search/repositories?q={q}&sort=stars&order=desc&per_page=100&page={p}"
RAW = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"


def head_commit(repo: str) -> tuple[str, str] | None:
    with tempfile.TemporaryDirectory() as d:
        r = subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout",
                            f"https://github.com/{repo}.git", d], capture_output=True, timeout=180)
        if r.returncode:
            return None
        out = subprocess.run(["git", "-C", d, "log", "-1", "--format=%H %cI"], capture_output=True, text=True).stdout.split()
        return (out[0], out[1]) if len(out) == 2 else None


# ----------------------------------------------------------------- npm
def npm_truth(lock: dict) -> list[dict]:
    comps = {}
    pk = lock.get("packages")
    if pk:
        for path, meta in pk.items():
            if not path or "node_modules/" not in path or meta.get("link"):
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[1]
            ver = meta.get("version")
            if not ver:
                continue
            comps[(name, ver)] = {"name": name, "version": ver, "dev": bool(meta.get("dev")),
                                  "integrity": meta.get("integrity"), "license": meta.get("license")}
    else:  # lockfileVersion 1
        def walk(deps):
            for name, meta in (deps or {}).items():
                if meta.get("version") and not str(meta["version"]).startswith(("file:", "git")):
                    comps[(name, meta["version"])] = {"name": name, "version": meta["version"], "dev": bool(meta.get("dev")),
                                                      "integrity": meta.get("integrity"), "license": None}
                walk(meta.get("dependencies"))
        walk(lock.get("dependencies"))
    return list(comps.values())


def npm_manifest(pkg: dict) -> list[dict]:
    out = []
    for sec, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
        for n, spec in (pkg.get(sec) or {}).items():
            out.append({"name": n, "spec": spec, "dev": dev})
    return out


# ----------------------------------------------------------------- PyPI
def py_truth(lock_text: str, kind: str) -> list[dict]:
    d = tomllib.loads(lock_text)
    out = []
    for p in d.get("package", []):
        src = p.get("source") or {}
        if isinstance(src, dict) and (src.get("editable") or src.get("virtual") or src.get("path") or src.get("git") or src.get("type") in ("directory", "git", "file")):
            continue
        h = None
        files = p.get("files") or p.get("wheels") or []
        if files and isinstance(files, list) and isinstance(files[0], dict):
            h = files[0].get("hash")
        if p.get("sdist", {}).get("hash") and not h:
            h = p["sdist"]["hash"]
        out.append({"name": norm_pypi(p["name"]), "version": p["version"], "hash": h, "dev": p.get("category") == "dev"})
    return out


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*([^;]*)")


def py_manifest(pyproj: dict) -> list[dict]:
    out = []
    proj = pyproj.get("project", {})
    for r in proj.get("dependencies", []) or []:
        m = _REQ.match(r)
        if m:
            out.append({"name": norm_pypi(m.group(1)), "spec": m.group(3).strip(), "dev": False})
    for grp, reqs in (proj.get("optional-dependencies") or {}).items():
        for r in reqs:
            m = _REQ.match(r)
            if m:
                out.append({"name": norm_pypi(m.group(1)), "spec": m.group(3).strip(), "dev": True})
    for grp, reqs in (pyproj.get("dependency-groups") or {}).items():
        for r in reqs:
            if isinstance(r, str):
                m = _REQ.match(r)
                if m:
                    out.append({"name": norm_pypi(m.group(1)), "spec": m.group(3).strip(), "dev": True})
    poetry = pyproj.get("tool", {}).get("poetry", {})
    def addp(deps, dev):
        for n, spec in (deps or {}).items():
            if n.lower() == "python":
                continue
            if isinstance(spec, dict):
                spec = spec.get("version", "")
            out.append({"name": norm_pypi(n), "spec": str(spec), "dev": dev})
    addp(poetry.get("dependencies"), False)
    addp(poetry.get("dev-dependencies"), True)
    for g in (poetry.get("group") or {}).values():
        addp(g.get("dependencies"), True)
    seen, uniq = set(), []
    for x in out:
        if x["name"] not in seen:
            seen.add(x["name"]); uniq.append(x)
    return uniq


def poetry_spec_to_pep440(spec: str) -> str:
    """^1.2 -> >=1.2,<2.0 ; ~1.2 -> >=1.2,<1.3 (poetry semantics)."""
    s = spec.strip()
    def bump(parts, idx):
        p = [int(x) if x.isdigit() else 0 for x in parts[: idx + 1]]
        p[idx] += 1
        return ".".join(map(str, p))
    m = re.match(r"^\^(\d+(?:\.\d+)*)$", s)
    if m:
        parts = m.group(1).split(".")
        idx = next((i for i, x in enumerate(parts) if x != "0"), len(parts) - 1)
        return f">={m.group(1)},<{bump(parts, idx)}"
    m = re.match(r"^~(\d+(?:\.\d+)*)$", s)
    if m:
        parts = m.group(1).split(".")
        idx = 1 if len(parts) > 1 else 0
        return f">={m.group(1)},<{bump(parts, idx)}"
    if s == "*":
        return ""
    return s


# ----------------------------------------------------------------- build SBOM docs
def cdx(components, ts, root_name, deps=None):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"timestamp": ts, "component": {"type": "application", "name": root_name, "bom-ref": "root"}},
            "components": components, "dependencies": deps or []}


def build_npm(repo, sha, ts, lock, pkg):
    truth = npm_truth(lock)
    comps = []
    for i, t in enumerate(truth):
        ns, nm = (t["name"].split("/", 1) if t["name"].startswith("@") else (None, t["name"]))
        purl = f"pkg:npm/{(ns.replace('@', '%40') + '/') if ns else ''}{nm}@{t['version']}"
        c = {"type": "library", "bom-ref": f"c{i}", "name": nm, "version": t["version"], "purl": purl,
             "properties": [{"name": "dev", "value": str(t["dev"]).lower()}]}
        if ns:
            c["group"] = ns
        if t.get("integrity") and t["integrity"].startswith("sha512-"):
            import base64
            c["hashes"] = [{"alg": "SHA-512", "content": base64.b64decode(t["integrity"][7:]).hex()}]
        if t.get("license"):
            c["licenses"] = [{"license": {"id": t["license"]}}] if isinstance(t["license"], str) else []
        comps.append(c)
    bad = []
    for i, m in enumerate(npm_manifest(pkg)):
        ns, nm = (m["name"].split("/", 1) if m["name"].startswith("@") else (None, m["name"]))
        c = {"type": "library", "bom-ref": f"b{i}", "name": nm, "version": m["spec"],
             "purl": f"pkg:npm/{(ns.replace('@', '%40') + '/') if ns else ''}{nm}",
             "properties": [{"name": "dev", "value": str(m["dev"]).lower()}]}
        if ns:
            c["group"] = ns
        bad.append(c)
    bad_deps = [{"ref": "root", "dependsOn": [c["bom-ref"] for c in bad]}]
    return cdx(comps, ts, repo, [{"ref": "root", "dependsOn": []}]), cdx(bad, ts, repo, bad_deps)


def build_py(repo, sha, ts, lock_text, kind, pyproj):
    truth = py_truth(lock_text, kind)
    comps = []
    for i, t in enumerate(truth):
        c = {"type": "library", "bom-ref": f"c{i}", "name": t["name"], "version": t["version"],
             "purl": f"pkg:pypi/{t['name']}@{t['version']}"}
        if t.get("hash") and ":" in t["hash"]:
            alg, val = t["hash"].split(":", 1)
            c["hashes"] = [{"alg": alg.upper().replace("SHA256", "SHA-256"), "content": val}]
        comps.append(c)
    bad = []
    for i, m in enumerate(py_manifest(pyproj)):
        spec = poetry_spec_to_pep440(m["spec"]) if kind == "poetry" else m["spec"]
        bad.append({"type": "library", "bom-ref": f"b{i}", "name": m["name"], "version": spec,
                    "purl": f"pkg:pypi/{m['name']}", "properties": [{"name": "dev", "value": str(m["dev"]).lower()}]})
    bad_deps = [{"ref": "root", "dependsOn": [c["bom-ref"] for c in bad]}]
    return cdx(comps, ts, repo, [{"ref": "root", "dependsOn": []}]), cdx(bad, ts, repo, bad_deps)


def collect(eco: str, target: int, max_pkgs: int, queries: list[str]):
    outdir = BENCH / "A" / eco
    outdir.mkdir(parents=True, exist_ok=True)
    have = {p.name for p in outdir.iterdir() if (p / "truth.json").exists()}
    n = len(have)
    for q in queries:
        for page in (1, 2, 3):
            res = get(GH.format(q=q, p=page))
            if not res:
                print("search failed", q, page, file=sys.stderr)
                break
            for item in res.get("items", []):
                if n >= target:
                    return
                repo = item["full_name"]
                slug = repo.replace("/", "__")
                if slug in have or item.get("fork") or item.get("archived"):
                    continue
                ref = item.get("default_branch", "HEAD")
                try:
                    if eco == "npm":
                        lock = get(RAW.format(repo=repo, ref=ref, path="package-lock.json"))
                        if not lock:
                            continue
                        pkg = get(RAW.format(repo=repo, ref=ref, path="package.json"))
                        if not pkg or lock.get("lockfileVersion", 1) < 2 and not lock.get("dependencies"):
                            continue
                        tn = len(npm_truth(lock))
                        if not (20 <= tn <= max_pkgs) or len(npm_manifest(pkg)) < 3:
                            continue
                    else:
                        kind, lock_text = None, None
                        for path, k in (("uv.lock", "uv"), ("poetry.lock", "poetry")):
                            t = get(RAW.format(repo=repo, ref=ref, path=path), as_json=False)
                            if t and "[[package]]" in t:
                                kind, lock_text = k, t
                                break
                        if not kind:
                            continue
                        pt = get(RAW.format(repo=repo, ref=ref, path="pyproject.toml"), as_json=False)
                        if not pt:
                            continue
                        pyproj = tomllib.loads(pt)
                        tn = len(py_truth(lock_text, kind))
                        if not (10 <= tn <= max_pkgs) or len(py_manifest(pyproj)) < 3:
                            continue
                    hc = head_commit(repo)
                    if not hc:
                        continue
                    sha, ts = hc
                    # re-fetch at pinned sha for reproducibility
                    if eco == "npm":
                        lock = get(RAW.format(repo=repo, ref=sha, path="package-lock.json")) or lock
                        pkg = get(RAW.format(repo=repo, ref=sha, path="package.json")) or pkg
                        truth, bad = build_npm(repo, sha, ts, lock, pkg)
                    else:
                        lt = get(RAW.format(repo=repo, ref=sha, path=f"{kind}.lock"), as_json=False) or lock_text
                        pt2 = get(RAW.format(repo=repo, ref=sha, path="pyproject.toml"), as_json=False) or pt
                        truth, bad = build_py(repo, sha, ts, lt, kind, tomllib.loads(pt2))
                except Exception as e:  # malformed upstream files
                    print("skip", repo, e, file=sys.stderr)
                    continue
                d = outdir / slug
                save_json(truth, d / "truth.json")
                save_json(bad, d / "bad_manifest.json")
                save_json({"repo": repo, "sha": sha, "timestamp": ts, "stars": item.get("stargazers_count"),
                           "ecosystem": eco, "n_truth": len(truth["components"]), "n_bad": len(bad["components"])},
                          d / "meta.json")
                n += 1
                print(f"[{eco}] {n}/{target} {repo} truth={len(truth['components'])} bad={len(bad['components'])}", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--eco", choices=["npm", "pypi"], required=True)
    ap.add_argument("--target", type=int, default=40)
    ap.add_argument("--max-pkgs", type=int, default=1200)
    a = ap.parse_args()
    if a.eco == "npm":
        qs = ["language:TypeScript+stars:>3000+pushed:>2026-06-01", "language:JavaScript+stars:>3000+pushed:>2026-06-01",
              "language:TypeScript+stars:1000..3000+pushed:>2026-06-01"]
    else:
        qs = ["language:Python+stars:>3000+pushed:>2026-06-01", "language:Python+stars:1000..3000+pushed:>2026-06-01",
              "language:Python+stars:500..1000+pushed:>2026-06-01"]
    collect(a.eco, a.target, a.max_pkgs, qs)
