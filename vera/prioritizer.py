"""VUG - Vulnerability-Uncertainty-Guided prioritisation of repair tasks.

value(task) = expected severity mass of vulnerability findings that the task could change.
  * version task : D(c) = sum_v P(v) * sev( V(v) symdiff V(mode) )      (risk of reporting wrong vulns)
  * identity task: M(c) = sum of severities of all OSV advisories ever filed under the component name
                    in the candidate ecosystems (vuln-prone names first)   x  P(unresolved)
priority = value / cost. Tasks with value 0 cannot change the vulnerability assessment.
"""
from __future__ import annotations
from functools import lru_cache
from . import vuln

ECO_OSV = {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}


def version_task_value(eco: str, name: str, dist: dict[str, float]) -> float:
    if len(dist) <= 1:
        return 0.0
    mode = max(dist, key=dist.get)
    def vs(v):
        return {cid: sev for cid, sev, _ in vuln.vulns_for(eco, name, v)}
    vm = vs(mode)
    total = 0.0
    for v, p in dist.items():
        if v == mode:
            continue
        vv = vs(v)
        diff = set(vv) ^ set(vm)
        total += p * sum(vv.get(c, vm.get(c, 0)) for c in diff)
    return total


@lru_cache(maxsize=50_000)
def name_vuln_mass(name: str, ecos: tuple = ("PyPI", "npm", "Maven")) -> float:
    seen: set[str] = set()
    total = 0.0
    short = name.split(":")[-1].split("/")[-1]
    for e in ecos:
        for n in {name, short, name.lower(), short.lower()}:
            for adv in vuln.advisories_for(e, n):
                if adv["id"] not in seen:
                    seen.add(adv["id"]); total += vuln._severity(adv)
        if e == "Maven":
            # groupId missing: OSV keys Maven packages as 'group:artifact' -> match on the artifactId suffix
            for adv in vuln.advisories_for_artifact(short):
                if adv["id"] not in seen:
                    seen.add(adv["id"]); total += vuln._severity(adv)
    return total


def identity_task_value(name: str, ecos=("PyPI", "npm", "Maven")) -> float:
    return name_vuln_mass(name, tuple(ecos))


def rank(tasks: list[dict], use_vug: bool = True) -> list[dict]:
    """tasks: [{'kind','value','cost',...}] -> ordered list."""
    if not use_vug:
        return list(tasks)
    return sorted(tasks, key=lambda t: -(t["value"] / max(t.get("cost", 1.0), 1e-9)))
