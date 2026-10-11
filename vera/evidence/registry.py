"""Package registry / deps.dev evidence. Unified API across PyPI, npm, Maven."""
from __future__ import annotations
import re
from urllib.parse import quote
from xml.etree import ElementTree as ET
from .http import get

DEPSDEV = "https://api.deps.dev/v3"
SYSTEM = {"pypi": "pypi", "npm": "npm", "maven": "maven"}


def norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def depsdev_name(ptype: str, name: str, namespace: str | None = None) -> str:
    if ptype == "maven":
        return f"{namespace}:{name}" if namespace else name
    if ptype == "npm" and namespace:
        return f"{namespace}/{name}"
    if ptype == "pypi":
        return norm_pypi(name)
    return name


def package_versions(ptype: str, name: str, namespace: str | None = None) -> list[dict] | None:
    """[{version, published (ISO or None), is_default}] or None if package doesn't exist."""
    n = depsdev_name(ptype, name, namespace)
    d = get(f"{DEPSDEV}/systems/{SYSTEM[ptype]}/packages/{quote(n, safe='')}")
    if d and d.get("versions"):
        return [{"version": v["versionKey"]["version"], "published": v.get("publishedAt"),
                 "is_default": v.get("isDefault", False)} for v in d["versions"]]
    # fallbacks (deps.dev sometimes lags)
    if ptype == "pypi":
        j = get(f"https://pypi.org/pypi/{quote(n)}/json")
        if j:
            out = []
            for v, files in j.get("releases", {}).items():
                ts = min((f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")), default=None)
                out.append({"version": v, "published": ts, "is_default": v == j["info"]["version"]})
            return out
    if ptype == "npm":
        j = get(f"https://registry.npmjs.org/{n.replace('/', '%2F')}")
        if j and "versions" in j:
            t = j.get("time", {})
            latest = j.get("dist-tags", {}).get("latest")
            return [{"version": v, "published": t.get(v), "is_default": v == latest} for v in j["versions"]]
    if ptype == "maven" and namespace:
        x = get(f"https://repo1.maven.org/maven2/{namespace.replace('.', '/')}/{name}/maven-metadata.xml", as_json=False)
        if x:
            try:
                root = ET.fromstring(x)
                vs = [v.text for v in root.iter("version")]
                rel = (root.findtext(".//release") or "")
                return [{"version": v, "published": None, "is_default": v == rel} for v in vs]
            except ET.ParseError:
                return None
    return None


def exists(ptype: str, name: str, namespace: str | None = None, version: str | None = None) -> bool:
    vs = package_versions(ptype, name, namespace)
    if vs is None:
        return False
    return version is None or any(v["version"] == version for v in vs)


def version_info(ptype: str, name: str, version: str, namespace: str | None = None) -> dict | None:
    n = depsdev_name(ptype, name, namespace)
    return get(f"{DEPSDEV}/systems/{SYSTEM[ptype]}/packages/{quote(n, safe='')}/versions/{quote(version, safe='')}")


def licenses(ptype: str, name: str, version: str, namespace: str | None = None) -> list[str]:
    d = version_info(ptype, name, version, namespace)
    return [l for l in (d or {}).get("licenses", []) if l and l != "non-standard"]


def resolved_dependencies(ptype: str, name: str, version: str, namespace: str | None = None) -> dict | None:
    """deps.dev resolved dependency graph: {nodes:[{versionKey:{system,name,version}, relation}], edges:[...]}"""
    n = depsdev_name(ptype, name, namespace)
    return get(f"{DEPSDEV}/systems/{SYSTEM[ptype]}/packages/{quote(n, safe='')}/versions/{quote(version, safe='')}:dependencies")


def requirements(ptype: str, name: str, version: str, namespace: str | None = None) -> list[tuple[str, str]]:
    """Declared (unresolved) requirements of a package version -> [(dep_name, range_spec)]."""
    out: list[tuple[str, str]] = []
    if ptype == "pypi":
        j = get(f"https://pypi.org/pypi/{quote(norm_pypi(name))}/{quote(version)}/json")
        for r in ((j or {}).get("info", {}) or {}).get("requires_dist") or []:
            if "extra ==" in r:
                continue
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*\(?([^;)]*)\)?", r)
            if m:
                out.append((norm_pypi(m.group(1)), m.group(2).strip()))
    elif ptype == "npm":
        full = f"{namespace}/{name}" if namespace else name
        j = get(f"https://registry.npmjs.org/{full.replace('/', '%2F')}/{quote(version)}")
        for k, v in ((j or {}).get("dependencies") or {}).items():
            out.append((k, v))
    elif ptype == "maven":
        n = depsdev_name(ptype, name, namespace)
        j = get(f"https://api.deps.dev/v3alpha/systems/maven/packages/{quote(n, safe='')}/versions/{quote(version, safe='')}:requirements")
        for d in ((j or {}).get("maven") or {}).get("dependencies", []) or []:
            if d.get("scope") in (None, "", "compile", "runtime"):
                out.append((d.get("name"), d.get("version", "")))
    return out


def search_by_hash(alg: str, value: str) -> list[dict]:
    """deps.dev hash query -> [{system,name,version}]"""
    alg = {"SHA-1": "SHA1", "SHA1": "SHA1", "SHA-256": "SHA256", "SHA256": "SHA256", "MD5": "MD5", "SHA-512": "SHA512"}.get(alg.upper())
    if not alg:
        return []
    import base64
    try:
        b64 = base64.b64encode(bytes.fromhex(value)).decode()
    except ValueError:
        b64 = value
    j = get(f"{DEPSDEV}/query?hash.type={alg}&hash.value={quote(b64, safe='')}")
    out = []
    for r in (j or {}).get("results", []) or []:
        vk = (r.get("version") or {}).get("versionKey") or {}
        out.append({"system": vk.get("system"), "name": vk.get("name"), "version": vk.get("version")})
    return out


def pypi_search_name(name: str) -> str | None:
    """Return canonical PyPI name if exists."""
    j = get(f"https://pypi.org/pypi/{quote(norm_pypi(name))}/json")
    return j["info"]["name"] if j else None


def maven_search_artifact(artifact: str) -> list[str]:
    """Find groupIds for an artifactId via deps.dev search fallback (maven central search is unreachable)."""
    j = get(f"https://api.deps.dev/v3alpha/purlsearch?q=pkg:maven/*/{quote(artifact)}")  # may not exist
    return [] if not j else [x for x in j]
