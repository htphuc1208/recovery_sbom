"""B2 - traditional re-resolution with the real package manager at the SBOM timestamp
(npm --before, uv --exclude-newer). Needs only the (bad) SBOM's direct deps + ranges.
For Maven: resolution of the published root artifact via deps.dev (artifact-level regeneration)."""
from __future__ import annotations
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from packageurl import PackageURL
from ..model import SBOM, Component, Repair
from ..pipeline import _comp_identity, _needs_version, _declared
from ..evidence import registry
from .. import config

UV = shutil.which("uv") or str(config.ROOT / ".venv/bin/uv")


def _components_from(pairs, ptype):
    out = []
    for i, (name, ver) in enumerate(pairs):
        ns, nm = (name.split("/", 1) if ptype == "npm" and name.startswith("@") else (None, name))
        if ptype == "maven":
            ns, nm = name.split(":", 1)
        c = Component(name=nm, group=ns, version=ver, purl=PackageURL(ptype, ns, nm, ver).to_string(), bom_ref=f"b2-{i}")
        c.repairs.append(Repair("component", None, c.purl, "package-manager", ["re-resolution"]))
        out.append(c)
    return out


def repair(s: SBOM, timeout: int = 600) -> tuple[SBOM, str]:
    out = s.copy()
    ts = s.metadata.get("timestamp")
    types = {c.ptype for c in s.components}
    try:
        if "npm" in types:
            deps = {}
            for c in s.components:
                p = c.purl_obj()
                if p and p.type == "npm":
                    full = f"{p.namespace}/{p.name}" if p.namespace else p.name
                    deps[full] = _declared(c) or c.version or "*"
            with tempfile.TemporaryDirectory() as d:
                Path(d, "package.json").write_text(json.dumps({"name": "x", "version": "1.0.0", "dependencies": deps}))
                cmd = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--legacy-peer-deps", "--no-audit", "--no-fund"]
                if ts:
                    cmd.append(f"--before={ts}")
                r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=timeout)
                if r.returncode or not Path(d, "package-lock.json").exists():
                    return out, "npm failed: " + r.stderr[-300:]
                lock = json.loads(Path(d, "package-lock.json").read_text())
            pairs = []
            for path, meta in lock.get("packages", {}).items():
                if "node_modules/" in path and meta.get("version"):
                    pairs.append((meta.get("name") or path.rsplit("node_modules/", 1)[1], meta["version"]))
            out.components = _components_from(sorted(set(pairs)), "npm")
            return out, "ok"
        if "pypi" in types:
            reqs, prod = [], []
            for c in s.components:
                p = c.purl_obj()
                if p and p.type == "pypi":
                    spec = _declared(c) or (f"=={c.version}" if c.version else "")
                    reqs.append(f"{p.name}{spec}")
                    if c.properties.get("dev", "false") != "true":
                        prod.append(f"{p.name}{spec}")
            pairs, status = None, "ok"
            for attempt, rs in (("all", reqs), ("prod-only", prod)):
                pairs = _uv_compile(rs, ts, timeout) if rs else None
                if pairs is not None:
                    status = "ok" if attempt == "all" else "ok (prod-only fallback)"
                    break
            if pairs is None:  # lenient: resolve every requirement on its own and union
                acc = {}
                for r in reqs:
                    for n, v in _uv_compile([r], ts, timeout) or []:
                        acc.setdefault(n, v)
                pairs, status = sorted(acc.items()), "ok (per-requirement fallback)"
            out.components = _components_from(pairs, "pypi")
            return out, status
        if "maven" in types and s.root:
            rp = s.root.purl_obj()
            g, a, v = (rp.namespace, rp.name, rp.version) if rp else (s.root.group, s.root.name, s.root.version)
            graph = registry.resolved_dependencies("maven", a, v, g)
            if not graph:
                return out, "deps.dev has no graph"
            pairs = []
            for n in graph.get("nodes", []):
                if n.get("relation") == "SELF":
                    continue
                vk = n["versionKey"]
                pairs.append((vk["name"], vk["version"]))
            out.components = _components_from(pairs, "maven")
            return out, "ok"
    except subprocess.TimeoutExpired:
        return out, "timeout"
    return out, "unsupported"


def _uv_compile(reqs, ts, timeout):
    with tempfile.TemporaryDirectory() as d:
        Path(d, "requirements.in").write_text("\n".join(reqs))
        cmd = [UV, "pip", "compile", "requirements.in", "-o", "out.txt", "--no-header", "--quiet",
               "--python-version", "3.12", "--python-platform", "linux", "--resolution", "highest"]
        if ts:
            cmd += ["--exclude-newer", ts]
        r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=timeout)
        if r.returncode:
            return None
        lines = Path(d, "out.txt").read_text().splitlines()
    pairs = []
    for ln in lines:
        ln = ln.strip()
        if ln and not ln.startswith("#") and "==" in ln:
            n, v = ln.split("==", 1)
            pairs.append((registry.norm_pypi(n.split("[")[0]), v.split(";")[0].strip()))
    return pairs
