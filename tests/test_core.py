import math
import pytest
from vera import versions, sbom_io, candidates, quality
from vera.vuln import _affected_version, canonical_id
from vera.model import Component, SBOM
from vera.agent import verifier
from vera.agent.tools import ToolBox


def test_version_sorting_maven_and_debian():
    assert versions.sort_versions(["1.10.0", "1.2.0", "1.2.0-rc1"], "Maven") == ["1.2.0-rc1", "1.2.0", "1.10.0"]
    assert versions.sort_versions(["1.2-1", "1.2~rc1-1", "1:0.1-1"], "Debian:12") == ["1.2~rc1-1", "1.2-1", "1:0.1-1"]


@pytest.mark.parametrize("v,spec,eco,ok", [
    ("2.31.0", "<3,>=2", "PyPI", True), ("4.17.20", "^4.17.21", "npm", False),
    ("2.15.0", "[2.10,2.16)", "Maven", True), ("2.16", "[2.10,2.16)", "Maven", False),
    ("1.2.3", "~1.2.0", "npm", True), ("1.3.0", "~1.2.0", "npm", False)])
def test_satisfies(v, spec, eco, ok):
    assert versions.satisfies(v, spec, eco) is ok


def test_osv_range_events():
    aff = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}], "versions": []}
    assert _affected_version(aff, "1.9.0", "PyPI")
    assert not _affected_version(aff, "2.0.0", "PyPI")
    aff2 = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}]}]}
    assert _affected_version(aff2, "1.4.0", "npm") and not _affected_version(aff2, "1.4.1", "npm")
    assert canonical_id({"id": "GHSA-x", "aliases": ["CVE-2020-1"]}) == "CVE-2020-1"


def test_temporal_distribution_prefers_recent_max_satisfying():
    vs = [{"version": "1.0.0", "published": "2020-01-01T00:00:00Z"},
          {"version": "1.1.0", "published": "2020-06-01T00:00:00Z"},
          {"version": "1.2.0", "published": "2020-12-01T00:00:00Z"}]
    ts = candidates._parse_ts("2021-01-01T00:00:00Z")
    d = candidates.temporal_distribution(vs, "npm", ts, mu_days=10)   # lock very likely recent
    assert math.isclose(sum(d.values()), 1.0, rel_tol=1e-6)
    assert max(d, key=d.get) == "1.2.0"
    # 1.2.0 is only 31 days old: with mu=60 the lock more likely predates it (P(X>31d)=exp(-31/60)>0.5)
    d60 = candidates.temporal_distribution(vs, "npm", ts, mu_days=60)
    assert max(d60, key=d60.get) == "1.1.0" and math.isclose(d60["1.2.0"], 1 - math.exp(-31 / 60), rel_tol=1e-2)
    # floor after 1.2.0 publication -> certain
    d2 = candidates.temporal_distribution(vs, "npm", ts, 60, t_floor=candidates._parse_ts("2020-12-15T00:00:00Z"))
    assert d2 == {"1.2.0": 1.0}


def test_cyclonedx_roundtrip_and_spdx():
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
           "components": [{"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0",
                           "bom-ref": "a"}], "dependencies": [{"ref": "a", "dependsOn": []}]}
    s = sbom_io.load(cdx)
    assert s.components[0].osv_ecosystem() == "PyPI"
    back = sbom_io.load(sbom_io.to_cyclonedx(s))
    assert back.components[0].purl == "pkg:pypi/requests@2.31.0"
    spdx = {"spdxVersion": "SPDX-2.3", "creationInfo": {"created": "2024-01-01T00:00:00Z"},
            "packages": [{"SPDXID": "SPDXRef-x", "name": "lodash", "versionInfo": "^4.17.0",
                          "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash"}]}]}
    s2 = sbom_io.load(spdx)
    kinds = {d.kind for d in quality.diagnose(s2)["component_defects"]}
    assert "RANGE_VERSION" in kinds and quality.vuln_readiness(s2) == 0.0


def test_debian_ecosystem_from_purl():
    c = Component(name="openssl", version="3.0.9-1", purl="pkg:deb/debian/libssl3@3.0.9-1?distro=debian-12&upstream=openssl")
    assert c.osv_ecosystem() == "Debian:12" and c.osv_name() == "openssl"


def test_verifier_rejects_hallucinations(monkeypatch):
    fake = {("pypi", "requests"): [{"version": "2.31.0", "published": "2023-05-22T00:00:00Z"}]}
    monkeypatch.setattr(verifier.registry, "package_versions", lambda t, n, ns=None: fake.get((t, n)))
    tb = ToolBox()
    tb.evidence["E1"] = {"tool": "registry_lookup", "args": {}, "result": {}}
    ok, _ = verifier.verify({"ecosystem": "pypi", "name": "requests", "version": "2.31.0", "evidence": ["E1"]}, tb)
    assert ok
    assert not verifier.verify({"ecosystem": "pypi", "name": "requestz", "version": "2.31.0", "evidence": ["E1"]}, tb)[0]
    assert not verifier.verify({"ecosystem": "pypi", "name": "requests", "version": "9.9.9", "evidence": ["E1"]}, tb)[0]
    assert not verifier.verify({"ecosystem": "pypi", "name": "requests", "version": "2.31.0", "evidence": []}, tb)[0]
    assert not verifier.verify({"ecosystem": "pypi", "name": "requests", "version": "2.31.0", "evidence": ["E1"]}, tb,
                               ts="2023-01-01T00:00:00Z")[0]


def test_degrade_is_deterministic():
    from bench.degrade import degrade
    s = SBOM(components=[Component(name=f"p{i}", version="1.2.3", purl=f"pkg:pypi/p{i}@1.2.3", bom_ref=str(i)) for i in range(50)])
    a, la = degrade(s, "heavy", 1)
    b, lb = degrade(s, "heavy", 1)
    assert la == lb and [c.purl for c in a.components] == [c.purl for c in b.components]
    assert la["drop_version"] > 0
