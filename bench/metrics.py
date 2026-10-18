"""Evaluation metrics: component recovery, version accuracy, vulnerability assessment quality, hallucination."""
from __future__ import annotations
from collections import defaultdict
from vera.model import SBOM, LANG_TYPES
from vera import vuln, quality
from vera.versions import looks_like_range
from vera.evidence import registry


def _kv(s: SBOM):
    d = defaultdict(set)
    for c in s.components:
        d[c.key()].add(c.version if c.version and not looks_like_range(c.version) else None)
    return d


def prf(tp, npred, ntrue):
    p = tp / npred if npred else (1.0 if ntrue == 0 else 0.0)
    r = tp / ntrue if ntrue else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def evaluate(pred: SBOM, truth: SBOM, bad: SBOM | None = None, check_hallucination: bool = False,
             truth_findings=None) -> dict:
    tk, pk = _kv(truth), _kv(pred)
    m: dict = {}
    inter = set(tk) & set(pk)
    m["comp_p"], m["comp_r"], m["comp_f1"] = prf(len(inter), len(pk), len(tk))
    tex = {(k, v) for k, vs in tk.items() for v in vs}
    pex = {(k, v) for k, vs in pk.items() for v in vs if v}
    m["exact_p"], m["exact_r"], m["exact_f1"] = prf(len(tex & pex), len(pex), len(tex))
    m["version_acc"] = (sum(1 for k in inter if tk[k] & pk[k]) / len(inter)) if inter else 0.0
    # repair accuracy on originally-defective components (those in the bad SBOM that a scanner could not use)
    if bad is not None:
        need = [c.key() for c in bad.components if not c.version or looks_like_range(c.version) or not c.purl_obj()
                or (c.purl_obj() and c.purl_obj().type == "maven" and not c.purl_obj().namespace)]
        need = [k for k in need if k in tk]
        # key may have changed (identity repair) -> look up by name too
        m["n_defective"] = len(need)
        m["defective_fixed"] = (sum(1 for k in need if pk.get(k, set()) & tk[k]) / len(need)) if need else float("nan")
    # vulnerabilities
    T = truth_findings if truth_findings is not None else {(f.component, f.vuln): f.severity for f in vuln.scan(truth, probabilistic=False)}
    pf = vuln.scan(pred, probabilistic=True)
    P50 = {(f.component, f.vuln): f.severity for f in pf if f.prob >= 0.5}
    Pany = {(f.component, f.vuln): f.severity for f in pf}
    tp = len(set(P50) & set(T))
    m["n_vuln_truth"], m["n_vuln_pred"] = len(T), len(P50)
    m["vuln_p"], m["vuln_r"], m["vuln_f1"] = prf(tp, len(P50), len(T))
    m["vuln_r_any"] = (len(set(Pany) & set(T)) / len(T)) if T else 1.0
    m["vuln_p_any"] = (len(set(Pany) & set(T)) / len(Pany)) if Pany else 1.0
    tsev = sum(T.values())
    m["vuln_r_sev"] = (sum(T[k] for k in set(P50) & set(T)) / tsev) if tsev else 1.0
    crit = {k for k, v in T.items() if v >= 7.0}
    m["vuln_r_high"] = (len(crit & set(P50)) / len(crit)) if crit else float("nan")
    m["vuln_fp"] = len(set(P50) - set(T))
    m["vuln_fn"] = len(set(T) - set(P50))
    # brier score over union (calibration of probabilistic report)
    keys = set(T) | set(Pany)
    probs = {(f.component, f.vuln): f.prob for f in pf}
    m["vuln_brier"] = (sum((probs.get(k, 0.0) - (1.0 if k in T else 0.0)) ** 2 for k in keys) / len(keys)) if keys else 0.0
    q = quality.summary(pred)
    m["ntia"] = q["ntia"]["overall"]
    m["vuln_readiness"] = q["vuln_readiness"]
    m["n_pred_comps"] = len(pred.components)
    if check_hallucination:
        m["hallucination"] = hallucination_rate(pred)
    return m


def hallucination_rate(s: SBOM) -> float:
    """Share of components whose identity or version was SET/CHANGED by the method (license-only enrichment does not
    count) and whose resulting package or version does not exist in the registry."""
    n = bad = 0
    for c in s.components:
        changed = {r.field for r in c.repairs} & {"version", "purl", "component", "name"}
        if not changed:
            continue
        p = c.purl_obj()
        if not p or p.type not in LANG_TYPES:
            continue
        # a pure PEP 503 / group-field normalisation that kept the given version is not a generated value
        if changed == {"purl"} and all(r.method == "symbolic" for r in c.repairs if r.field == "purl"):
            continue
        n += 1
        v = c.version if c.version and not looks_like_range(c.version) else None
        ok = registry.exists(p.type, p.name, p.namespace, v)
        if not ok and v and registry.exists(p.type, p.name, p.namespace):
            ok = registry.version_info(p.type, p.name, v, p.namespace) is not None  # listing may lag
        if not ok:
            bad += 1
    return bad / n if n else 0.0
