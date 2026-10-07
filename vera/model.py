"""Internal SBOM model, independent of CycloneDX / SPDX."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any
from packageurl import PackageURL

# purl type -> OSV ecosystem
PURL_TO_OSV = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
               "gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist"}
DISTRO_OSV = {"debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine"}
LANG_TYPES = {"pypi", "npm", "maven"}


@dataclass
class Repair:
    field: str            # version | purl | name | license | component(add) | ...
    old: Any
    new: Any
    method: str           # e.g. "constraint", "llm-agent", "heuristic"
    evidence: list[str] = field(default_factory=list)
    confidence: float = 1.0


@dataclass
class Component:
    name: str
    version: str | None = None
    purl: str | None = None
    group: str | None = None          # maven groupId / npm scope
    type: str = "library"
    licenses: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    bom_ref: str | None = None
    supplier: str | None = None
    properties: dict[str, str] = field(default_factory=dict)
    ecosystem_hint: str | None = None  # e.g. pypi/npm/maven/deb/apk if known w/o purl
    repairs: list[Repair] = field(default_factory=list)
    # candidate distribution after repair: {version: prob}
    candidates: dict[str, float] = field(default_factory=dict)

    # ---- helpers -------------------------------------------------------
    def purl_obj(self) -> PackageURL | None:
        if not self.purl:
            return None
        try:
            return PackageURL.from_string(self.purl)
        except Exception:
            return None

    @property
    def ptype(self) -> str | None:
        p = self.purl_obj()
        if p:
            return p.type
        return self.ecosystem_hint

    def osv_ecosystem(self) -> str | None:
        p = self.purl_obj()
        t = p.type if p else self.ecosystem_hint
        if t in PURL_TO_OSV:
            return PURL_TO_OSV[t]
        if p and t in ("deb", "apk", "rpm"):
            distro = (p.qualifiers or {}).get("distro", "")
            ns = (p.namespace or "").lower()
            for k, v in DISTRO_OSV.items():
                if ns.startswith(k) or distro.startswith(k):
                    ver = distro.split("-", 1)[1] if "-" in distro else ""
                    if v == "Alpine" and ver:
                        ver = "v" + ".".join(ver.split(".")[:2])
                    if v == "Debian" and ver:
                        ver = ver.split(".")[0]
                    if v == "Ubuntu" and ver:
                        # 22.04 -> 22.04 ; OSV uses "Ubuntu:22.04:LTS" too; matcher handles prefix
                        pass
                    return f"{v}:{ver}" if ver else None  # no release -> scanners cannot pick a vuln namespace
        return None

    def osv_name(self) -> str:
        p = self.purl_obj()
        if p and p.type == "maven":
            return f"{p.namespace}:{p.name}"
        if p and p.type == "npm" and p.namespace:
            return f"{p.namespace}/{p.name}"
        if p and p.type == "deb" and (p.qualifiers or {}).get("upstream"):
            # Debian OSV advisories are keyed by source package
            return p.qualifiers["upstream"].split("@")[0]
        if p and p.type == "apk" and (p.qualifiers or {}).get("upstream"):
            return p.qualifiers["upstream"].split("@")[0]
        if p:
            return p.name
        if self.group and self.ptype == "maven":
            return f"{self.group}:{self.name}"
        return self.name

    def key(self) -> str:
        """Identity key (ecosystem + normalized name), version-independent."""
        p = self.purl_obj()
        if p:
            ns = f"{p.namespace}/" if p.namespace else ""
            name = p.name.lower()
            if p.type == "pypi":
                name = name.replace("_", "-").replace(".", "-")
            return f"{p.type}:{ns.lower()}{name}"
        name = self.name.lower()
        if self.group:
            name = f"{self.group.lower()}/{name}"
        return f"{self.ecosystem_hint or '?'}:{name}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SBOM:
    components: list[Component] = field(default_factory=list)
    dependencies: dict[str, list[str]] = field(default_factory=dict)  # bom_ref -> [bom_ref]
    metadata: dict[str, Any] = field(default_factory=dict)  # timestamp, root, tools, source_format
    root: Component | None = None

    def by_ref(self) -> dict[str, Component]:
        return {c.bom_ref: c for c in self.components if c.bom_ref}

    def copy(self) -> "SBOM":
        import copy
        return copy.deepcopy(self)
