"""Maven pairs from Maven Central: truth = CycloneDX SBOM published by the project's own build
(cyclonedx-maven-plugin); natural bad SBOM = dependencies declared in the released pom.xml
(unresolved ${properties}, parent-managed versions missing, no transitive deps)."""
from __future__ import annotations
import re
import sys
from xml.etree import ElementTree as ET
from vera.evidence.http import get, _client
from vera.versions import is_prerelease
from bench.common import BENCH, save_json

ARTS = """org.apache.commons:commons-lang3 org.apache.commons:commons-text org.apache.commons:commons-compress commons-io:commons-io
org.apache.commons:commons-configuration2 org.apache.maven:maven-core org.apache.zookeeper:zookeeper org.apache.avro:avro
org.apache.parquet:parquet-hadoop org.apache.cxf:cxf-core org.apache.commons:commons-csv org.apache.commons:commons-dbcp2
org.apache.commons:commons-vfs2 org.apache.commons:commons-email org.apache.jena:jena-arq org.apache.mina:mina-core
org.apache.santuario:xmlsec org.apache.wss4j:wss4j-ws-security-common io.vertx:vertx-core""".split()
NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def pom_deps(pom: str) -> list[dict]:
    root = ET.fromstring(pom)
    out = []
    deps = root.find("m:dependencies", NS)
    for d in (deps.findall("m:dependency", NS) if deps is not None else []):
        scope = (d.findtext("m:scope", default="", namespaces=NS) or "").strip()
        if scope in ("test", "import"):
            continue
        out.append({"group": d.findtext("m:groupId", namespaces=NS), "name": d.findtext("m:artifactId", namespaces=NS),
                    "version": (d.findtext("m:version", namespaces=NS) or "").strip() or None, "scope": scope or "compile"})
    return out


def main(per_artifact=2):
    outdir = BENCH / "A" / "maven"
    n = 0
    for a in ARTS:
        g, art = a.split(":")
        base = f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{art}"
        meta = get(base + "/maven-metadata.xml", as_json=False)
        vs = [v.text for v in ET.fromstring(meta).iter("version") if not is_prerelease(v.text, "maven")]
        found = []
        for v in vs[-8:]:
            if _client.head(f"{base}/{v}/{art}-{v}-cyclonedx.json").status_code == 200:
                found.append(v)
        pick = [found[0], found[-1]] if len(found) >= 2 else found
        for v in dict.fromkeys(pick):
            truth = get(f"{base}/{v}/{art}-{v}-cyclonedx.json")
            pom = get(f"{base}/{v}/{art}-{v}.pom", as_json=False)
            if not truth or not pom:
                continue
            # truth: keep library components (drop root), keep deps graph
            ts = (truth.get("metadata") or {}).get("timestamp")
            comps = [c for c in truth.get("components", []) if c.get("purl", "").startswith("pkg:maven/")]
            if len(comps) < 1:
                continue
            truth["components"] = comps
            bad_comps = []
            for i, d in enumerate(pom_deps(pom)):
                c = {"type": "library", "bom-ref": f"b{i}", "group": d["group"], "name": d["name"],
                     "properties": [{"name": "scope", "value": d["scope"]}]}
                if d["version"]:
                    c["version"] = d["version"]
                if d["group"] and not (d["group"].startswith("${")):
                    c["purl"] = f"pkg:maven/{d['group']}/{d['name']}" + (f"@{d['version']}" if d["version"] and "${" not in d["version"] else "")
                bad_comps.append(c)
            bad = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                   "metadata": {"timestamp": ts, "component": {"type": "library", "name": art, "group": g, "version": v, "bom-ref": "root"}},
                   "components": bad_comps, "dependencies": [{"ref": "root", "dependsOn": [c["bom-ref"] for c in bad_comps]}]}
            d = outdir / f"{g}__{art}__{v}"
            save_json(truth, d / "truth.json")
            save_json(bad, d / "bad_manifest.json")
            save_json({"repo": f"{g}:{art}", "version": v, "timestamp": ts, "ecosystem": "maven",
                       "n_truth": len(comps), "n_bad": len(bad_comps)}, d / "meta.json")
            n += 1
            print(f"[maven] {n} {a}@{v} truth={len(comps)} bad={len(bad_comps)}", flush=True)


if __name__ == "__main__":
    main()
