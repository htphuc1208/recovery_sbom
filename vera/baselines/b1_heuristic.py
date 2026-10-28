"""B1 - traditional heuristic repair (what ad-hoc scripts / many SBOM 'enrichment' tools do):
normalise names, look the name up in the majority ecosystem registry, fill version with the newest
version satisfying the declared range. Variant 'latest' ignores the SBOM timestamp; 'ts' respects it.
No transitive recovery, no LLM."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from ..model import SBOM, Repair
from ..pipeline import symbolic_identity, _majority_type, _distro_hint, _comp_identity, _needs_version, _declared, _set_version
from ..candidates import generate


def repair(s: SBOM, respect_timestamp: bool = True, workers: int = 12) -> SBOM:
    s = s.copy()
    maj, dh = _majority_type(s), _distro_hint(s)
    ts = s.metadata.get("timestamp") if respect_timestamp else None

    def one(c):
        try:
            symbolic_identity(c, maj, dh)
        except Exception:
            return
        idt = _comp_identity(c)
        if idt and _needs_version(c):
            d = _declared(c)
            spec = d if d and "${" not in d else None
            cs = generate(idt[0], idt[2], idt[1], [spec] if spec else [], ts, temporal=False)
            if cs.dist:
                _set_version(c, cs.mode, cs.dist, cs.constraints, 1.0, "heuristic-newest", d)
    with ThreadPoolExecutor(workers) as ex:
        list(ex.map(one, s.components))
    return s
