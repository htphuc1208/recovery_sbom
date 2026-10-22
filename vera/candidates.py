"""Candidate generation + multi-source constraint solving with a *temporal resolver model*.

Key idea: a package manager resolves a range to the highest satisfying version available at lock
time t_lock. t_lock is unknown but bounded by the SBOM timestamp ts (lock is older than or equal to
the SBOM). We model X = ts - t_lock ~ Exponential(mean=mu_days) and compute, exactly, the probability
that each satisfying version was "the max satisfying version" at t_lock. This turns an unresolvable
range into a calibrated distribution over versions instead of a guess.
"""
from __future__ import annotations
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from .evidence import registry
from .versions import satisfies, sort_versions, is_prerelease, pin_from_spec, looks_like_range, comparator
import functools

DEFAULT_MU_DAYS = 120.0


def _parse_ts(s: str | None) -> float | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


@dataclass
class CandidateSet:
    ptype: str
    name: str
    namespace: str | None
    dist: dict[str, float] = field(default_factory=dict)   # version -> prob
    constraints: list[str] = field(default_factory=list)   # human-readable evidence
    exists: bool = True

    @property
    def mode(self) -> str | None:
        return max(self.dist, key=self.dist.get) if self.dist else None

    @property
    def confidence(self) -> float:
        return max(self.dist.values()) if self.dist else 0.0

    def entropy(self) -> float:
        return -sum(p * math.log(p) for p in self.dist.values() if p > 0)


def eco_of(ptype: str) -> str:
    return {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}.get(ptype, ptype)


def temporal_distribution(versions: list[dict], ecosystem: str, ts: float | None, mu_days: float = DEFAULT_MU_DAYS,
                          t_floor: float | None = None) -> dict[str, float]:
    """versions: [{version, published}] already filtered to satisfying ones.
    Returns P(version was resolved) under the temporal resolver model."""
    if not versions:
        return {}
    cmp = comparator(ecosystem)
    now = ts or datetime.now(timezone.utc).timestamp()
    dated = [(v["version"], _parse_ts(v.get("published"))) for v in versions]
    dated = [(v, t) for v, t in dated if t is None or t <= now + 86400]
    if not dated:
        return {}
    if any(t is None for _, t in dated):
        # no publish dates (e.g. maven-metadata fallback): geometric prior over version order, newest first
        order = sort_versions([v for v, _ in dated], ecosystem)[::-1]
        w = [0.6 ** i for i in range(len(order))]
        z = sum(w)
        return {v: x / z for v, x in zip(order, w)}
    lam = 1.0 / (mu_days * 86400.0)
    # breakpoints: publish times (ascending)
    dated.sort(key=lambda x: x[1])
    probs: dict[str, float] = {}
    best = None
    for i, (v, t) in enumerate(dated):
        if best is None or cmp(v, best) > 0:
            best = v
        t_next = dated[i + 1][1] if i + 1 < len(dated) else now
        if t_next <= t:
            continue
        lo = max(t, t_floor) if t_floor and t_floor < now else t
        if t_next <= lo:
            continue
        # t_lock in [lo, t_next) <=> X in (now - t_next, now - lo]
        a, b = max(now - t_next, 0.0), max(now - lo, 0.0)
        mass = math.exp(-lam * a) - math.exp(-lam * b)
        probs[best] = probs.get(best, 0.0) + mass
    # mass for t_lock before first publish -> impossible; renormalize
    z = sum(probs.values())
    if z <= 0:
        probs = {best: 1.0}
        z = 1.0
    out = {v: p / z for v, p in probs.items() if p / z > 1e-4}
    z = sum(out.values())
    return {v: p / z for v, p in sorted(out.items(), key=lambda x: -x[1])}


def generate(ptype: str, name: str, namespace: str | None, specs: list[str], ts: str | None,
             mu_days: float = DEFAULT_MU_DAYS, sibling_versions: list[str] | None = None,
             temporal: bool = True, allow_prerelease: bool = False, t_floor: float | None = None,
             floor_weight: float = 1.0) -> CandidateSet:
    """Build candidate distribution for one component.
    specs: declared ranges from all sources (own range, parents' requirements) -> intersected.
    """
    cs = CandidateSet(ptype, name, namespace)
    eco = eco_of(ptype)
    vs = registry.package_versions(ptype, name, namespace)
    if vs is None:
        cs.exists = False
        cs.constraints.append("package not found in registry")
        return cs
    specs = [s for s in specs if s is not None]
    # exact pin wins
    for s in specs:
        pin = pin_from_spec(s, eco)
        if pin and any(v["version"] == pin for v in vs):
            cs.dist = {pin: 1.0}
            cs.constraints.append(f"pinned by spec '{s}'")
            return cs
    want_pre = allow_prerelease or any(re.search(r"\d-(alpha|beta|rc|next|canary)", s or "") for s in specs)
    pool = [v for v in vs if want_pre or not is_prerelease(v["version"], eco)] or vs
    for s in specs:
        if not s or "${" in s:
            continue
        new = [v for v in pool if satisfies(v["version"], s, eco)]
        if new:
            pool = new
            cs.constraints.append(f"range '{s}' -> {len(pool)} versions")
        else:
            cs.constraints.append(f"range '{s}' unsatisfiable (ignored)")
    tsf = _parse_ts(ts)
    if tsf:
        before = [v for v in pool if (_parse_ts(v.get("published")) or 0) <= tsf + 86400]
        if before:
            if len(before) < len(pool):
                cs.constraints.append(f"published <= SBOM timestamp -> {len(before)} versions")
            pool = before
    if sibling_versions:
        sib = [v for v in pool if v["version"] in sibling_versions]
        if sib:
            cs.constraints.append(f"release-train sibling version {sibling_versions[0]}")
            pool = sib
    if temporal:
        if t_floor and floor_weight < 1.0:
            # mixture: with prob floor_weight the package was (re)resolved after the anchor, otherwise any time
            a = temporal_distribution(pool, eco, tsf, mu_days, t_floor)
            b = temporal_distribution(pool, eco, tsf, mu_days, None)
            mix = {v: floor_weight * a.get(v, 0) + (1 - floor_weight) * b.get(v, 0) for v in set(a) | set(b)}
            cs.dist = dict(sorted(mix.items(), key=lambda x: -x[1]))
        else:
            cs.dist = temporal_distribution(pool, eco, tsf, mu_days, t_floor)
    else:
        # traditional: just the newest satisfying version
        newest = sort_versions([v["version"] for v in pool], eco)[-1]
        cs.dist = {newest: 1.0}
    return cs


import re  # noqa: E402  (used above)
