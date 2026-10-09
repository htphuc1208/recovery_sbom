"""Ecosystem-aware version comparison and range satisfaction.
Used by the OSV matcher (introduced/fixed events) and by the candidate solver (declared ranges)."""
from __future__ import annotations
import functools
import re
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier
import nodesemver


# ------------------------------------------------------------------ Maven
_MVN_QUAL = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3, "rc": 4, "cr": 4,
             "snapshot": 5, "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7}


def _mvn_tokens(v: str):
    toks = re.findall(r"\d+|[a-zA-Z]+", v.lower())
    out = []
    for t in toks:
        if t.isdigit():
            out.append((1, int(t), ""))
        else:
            out.append((0, _MVN_QUAL.get(t, 5.5), t))
    # strip trailing zero / release-equivalent tokens
    while out and out[-1][0] == 1 and out[-1][1] == 0 and len(out) > 1:
        out.pop()
    return out


def _mvn_cmp(a: str, b: str) -> int:
    ta, tb = _mvn_tokens(a), _mvn_tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else (0, 6, "") if (i < len(tb) and tb[i][0] == 0) else (1, 0, "")
        y = tb[i] if i < len(tb) else (0, 6, "") if (i < len(ta) and ta[i][0] == 0) else (1, 0, "")
        if x[0] != y[0]:
            # number > qualifier (1.0.1 > 1.0-rc)
            return 1 if x[0] > y[0] else -1
        if x[1] != y[1]:
            return 1 if x[1] > y[1] else -1
        if x[2] != y[2]:
            return 1 if x[2] > y[2] else -1
    return 0


# ------------------------------------------------------------------ Debian (dpkg)
def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_cmp_part(a: str, b: str) -> int:
    while a or b:
        na = re.match(r"^[^\d]*", a).group(0)
        nb = re.match(r"^[^\d]*", b).group(0)
        for i in range(max(len(na), len(nb))):
            ca = _dpkg_order(na[i]) if i < len(na) else 0
            cb = _dpkg_order(nb[i]) if i < len(nb) else 0
            if ca != cb:
                return -1 if ca < cb else 1
        a, b = a[len(na):], b[len(nb):]
        da = re.match(r"^\d*", a).group(0)
        db = re.match(r"^\d*", b).group(0)
        ia, ib = int(da or 0), int(db or 0)
        if ia != ib:
            return -1 if ia < ib else 1
        a, b = a[len(da):], b[len(db):]
    return 0


def _dpkg_split(v: str):
    epoch, rest = (v.split(":", 1) if ":" in v else ("0", v))
    if "-" in rest:
        up, rev = rest.rsplit("-", 1)
    else:
        up, rev = rest, ""
    return int(epoch) if epoch.isdigit() else 0, up, rev


def _dpkg_cmp(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_cmp_part(ua, ub) or _dpkg_cmp_part(ra, rb)


# ------------------------------------------------------------------ Alpine (apk) - approximation
def _apk_cmp(a: str, b: str) -> int:
    def split(v):
        m = re.match(r"^(.*?)(?:-r(\d+))?$", v)
        return m.group(1), int(m.group(2) or 0)
    va, ra = split(a)
    vb, rb = split(b)
    return _dpkg_cmp_part(va.replace("_", "~"), vb.replace("_", "~")) or (ra > rb) - (ra < rb)


# ------------------------------------------------------------------ generic
def _pypi_cmp(a: str, b: str) -> int:
    try:
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    except InvalidVersion:
        return _mvn_cmp(a, b)


def _semver_cmp(a: str, b: str) -> int:
    try:
        return nodesemver.compare(a, b, loose=True)
    except Exception:
        return _mvn_cmp(a, b)


def comparator(ecosystem: str):
    e = (ecosystem or "").lower()
    if e.startswith("pypi"):
        return _pypi_cmp
    if e.startswith("npm") or e in ("go", "crates.io", "semver"):
        return _semver_cmp
    if e.startswith("maven"):
        return _mvn_cmp
    if e.startswith("debian") or e.startswith("ubuntu") or e in ("deb",):
        return _dpkg_cmp
    if e.startswith("alpine") or e in ("apk",):
        return _apk_cmp
    return _mvn_cmp


def sort_versions(versions: list[str], ecosystem: str) -> list[str]:
    return sorted(versions, key=functools.cmp_to_key(comparator(ecosystem)))


def is_prerelease(v: str, ecosystem: str) -> bool:
    e = ecosystem.lower()
    if e.startswith("pypi"):
        try:
            return Version(v).is_prerelease or Version(v).is_devrelease
        except InvalidVersion:
            return True
    return bool(re.search(r"(alpha|beta|rc|snapshot|milestone|-m\d|preview|canary|next|dev|nightly|insiders|experimental)", v.lower())) or (
        e.startswith("npm") and "-" in v)


# ------------------------------------------------------------------ ranges (declared constraints)
def looks_like_range(v: str | None) -> bool:
    if not v:
        return False
    return bool(re.search(r"[<>=^~*|,\[\]()]|\bx\b|\.x|\s-\s|latest|\$\{", v)) or v.strip() in ("*", "")


def satisfies(version: str, spec: str, ecosystem: str) -> bool:
    """Does `version` satisfy declared range `spec` in this ecosystem?"""
    spec = (spec or "").strip()
    if spec in ("", "*", "latest", "x"):
        return True
    e = ecosystem.lower()
    if e.startswith("pypi"):
        s = spec.replace(" ", "")
        if re.match(r"^[0-9]", s):
            s = "==" + s
        try:
            return Version(version) in SpecifierSet(s, prereleases=True)
        except (InvalidSpecifier, InvalidVersion):
            return False
    if e.startswith("npm"):
        if spec.startswith(("npm:", "git", "http", "file:", "link:", "workspace:")):
            return False
        try:
            return bool(nodesemver.satisfies(version, spec, loose=True))
        except Exception:
            return False
    if e.startswith("maven"):
        if spec.startswith("${"):
            return True
        m = re.match(r"^([\[(])\s*([^,]*)\s*,\s*([^\])]*)\s*([\])])$", spec)
        if m:
            lo_inc, lo, hi, hi_inc = m.group(1) == "[", m.group(2), m.group(3), m.group(4) == "]"
            if lo:
                c = _mvn_cmp(version, lo)
                if c < 0 or (c == 0 and not lo_inc):
                    return False
            if hi:
                c = _mvn_cmp(version, hi)
                if c > 0 or (c == 0 and not hi_inc):
                    return False
            return True
        if spec.startswith("[") and spec.endswith("]"):
            return _mvn_cmp(version, spec[1:-1]) == 0
        return _mvn_cmp(version, spec) == 0  # soft requirement treated as pin
    return version == spec


def pin_from_spec(spec: str | None, ecosystem: str) -> str | None:
    """If a spec pins exactly one version (==1.2.3, 1.2.3, [1.2.3]) return it."""
    if not spec:
        return None
    s = spec.strip()
    m = re.match(r"^(?:===?|v)?\s*([0-9][0-9A-Za-z.\-+_]*)$", s)
    if m and not looks_like_range(s.lstrip("=")):
        return m.group(1)
    m = re.match(r"^\[([0-9][^,\]]*)\]$", s)
    if m:
        return m.group(1)
    return None
