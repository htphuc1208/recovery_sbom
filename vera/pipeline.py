"""VERA end-to-end repair pipeline."""
from __future__ import annotations
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from packageurl import PackageURL
from .model import SBOM, Component, Repair, LANG_TYPES
from . import quality
from .evidence import registry
from .evidence.maven_pom import resolve_version
from .candidates import generate, _parse_ts, eco_of
from .graph_completion import complete
from .versions import looks_like_range, pin_from_spec
from . import prioritizer
from .agent.loop import run_agent
from .agent.tools import ToolBox, split_name


@dataclass
class VeraConfig:
    model: str | None = "Qwen/Qwen3.6-35B-A3B-FP8"
    use_llm: bool = True
    use_temporal: bool = True        # temporal resolver model (else: newest satisfying)
    use_anchor: bool = True          # temporal anchoring from pinned components
    use_coconstraints: bool = True   # sibling requirement constraints
    use_vug: bool = True             # vulnerability-uncertainty-guided ordering
    use_verifier: bool = True
    use_graph: bool = True           # transitive completion
    graph_mode: str = "auto"         # auto | always | never
    budget: int = 20                 # max LLM agent tasks per SBOM
    agent_steps: int = 6
    mu_days: float | None = None     # None -> per-ecosystem default (tuned on dev split)
    floor_weight: float | None = None
    workers: int = 12
    fill_licenses: bool = True


@dataclass
class RepairReport:
    sbom: SBOM
    log: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    agent_traces: list[dict] = field(default_factory=list)


# tuned on the dev split (25% of repos, see bench/tune.py); test split never used for tuning
ECO_DEFAULTS = {"npm": {"mu_days": 120.0, "floor_weight": 0.5}, "pypi": {"mu_days": 60.0, "floor_weight": 0.0},
                "maven": {"mu_days": 120.0, "floor_weight": 0.5}}


def _eco_params(cfg, majority):
    d = ECO_DEFAULTS.get(majority or "", {"mu_days": 120.0, "floor_weight": 0.5})
    return (cfg.mu_days if cfg.mu_days is not None else d["mu_days"],
            cfg.floor_weight if cfg.floor_weight is not None else d["floor_weight"])


def _make_purl(ptype, ns, name, version=None, qualifiers=None):
    return PackageURL(type=ptype, namespace=ns, name=name, version=version, qualifiers=qualifiers).to_string()


def _majority_type(s: SBOM) -> str | None:
    c = Counter(x.ptype for x in s.components if x.ptype)
    return c.most_common(1)[0][0] if c else None


def _comp_identity(c: Component):
    """-> (ptype, namespace, name) if complete & language ecosystem, else None"""
    p = c.purl_obj()
    if p and p.type in LANG_TYPES:
        if p.type == "maven" and not p.namespace:
            return None
        return p.type, p.namespace, p.name
    return None


def _declared(c: Component) -> str | None:
    """the declared range if the 'version' field is a range/property"""
    if c.version and (looks_like_range(c.version) or "${" in c.version):
        return c.version
    p = c.purl_obj()
    if p and p.version and looks_like_range(p.version):
        return p.version
    return None


def _needs_version(c: Component) -> bool:
    return not c.version or looks_like_range(c.version) or "${" in (c.version or "")


# ------------------------------------------------------------------ step 1: identity (symbolic)
def symbolic_identity(c: Component, majority: str | None, distro_hint: dict | None) -> tuple[bool, str]:
    p = c.purl_obj()
    if p:
        if p.type == "pypi":
            canon = registry.norm_pypi(p.name)
            if canon != p.name:
                c.repairs.append(Repair("purl", c.purl, None, "symbolic", [f"PEP 503 normalisation {p.name}->{canon}"]))
                c.purl = _make_purl("pypi", None, canon, p.version, p.qualifiers)
                c.repairs[-1].new = c.purl
                c.name = canon
            return True, "ok"
        if p.type == "maven" and not p.namespace:
            if c.group:
                c.purl = _make_purl("maven", c.group, p.name, p.version)
                c.repairs.append(Repair("purl", None, c.purl, "symbolic", ["group field"]))
                return True, "group field"
            return False, "maven groupId missing"
        if p.type in ("deb", "apk", "rpm") and not (p.qualifiers or {}).get("distro") and distro_hint:
            q = dict(p.qualifiers or {})
            dh = distro_hint.get(p.type)
            if dh:
                q["distro"] = dh
                old = c.purl
                c.purl = _make_purl(p.type, p.namespace, p.name, p.version, q)
                c.repairs.append(Repair("purl", old, c.purl, "symbolic", [f"distro inferred from SBOM: {dh}"], 0.9))
                return True, "distro"
            return False, "distro unknown"
        return True, "ok"
    # no purl
    name = c.name
    if c.group and (majority == "maven" or "." in c.group) and not c.group.startswith("@"):
        if registry.exists("maven", name, c.group):
            c.purl = _make_purl("maven", c.group, name, None if _needs_version(c) else c.version)
            c.repairs.append(Repair("purl", None, c.purl, "symbolic", [f"maven-central has {c.group}:{name}"]))
            return True, "maven"
    if ":" in name and majority in (None, "maven"):
        g, a = name.split(":", 1)
        if registry.exists("maven", a, g):
            c.name, c.group = a, g
            c.purl = _make_purl("maven", g, a, None if _needs_version(c) else c.version)
            c.repairs.append(Repair("purl", None, c.purl, "symbolic", [f"maven-central has {g}:{a}"]))
            return True, "maven"
    if majority in ("deb", "apk", "rpm") and distro_hint and distro_hint.get("_ns", {}).get(majority):
        q = {"distro": distro_hint[majority]} if distro_hint.get(majority) else None
        c.purl = _make_purl(majority, distro_hint["_ns"][majority], name, None if _needs_version(c) else c.version, q)
        c.repairs.append(Repair("purl", None, c.purl, "symbolic", ["OS package; type/namespace/distro from SBOM majority"], 0.7))
        return True, "os"
    order = [majority] + [e for e in ("npm", "pypi", "maven") if e != majority] if majority in LANG_TYPES else ["npm", "pypi"]
    ns = c.group if c.group and c.group.startswith("@") else None
    nm = name
    if name.startswith("@") and "/" in name:
        ns, nm = name.split("/", 1)
    hits = []
    for e in order:
        if e == "maven":
            continue  # needs groupId
        if e == "pypi" and ns:
            continue
        if registry.exists(e, nm if e != "pypi" else registry.norm_pypi(nm), ns if e == "npm" else None):
            hits.append(e)
            if e == majority:
                break
    if hits and (hits[0] == majority or len(hits) == 1):
        e = hits[0]
        nm2 = registry.norm_pypi(nm) if e == "pypi" else nm
        c.purl = _make_purl(e, ns if e == "npm" else None, nm2, None if _needs_version(c) else c.version)
        conf = 0.95 if e == majority else 0.6
        c.repairs.append(Repair("purl", None, c.purl, "symbolic", [f"name exists in {e} registry (SBOM majority={majority})"], conf))
        return True, e
    return False, "no registry match" if not hits else f"ambiguous ecosystems {hits}"


def _distro_hint(s: SBOM) -> dict:
    out: dict = {"_ns": {}}
    for t in ("deb", "apk", "rpm"):
        ds = Counter()
        nss = Counter()
        for c in s.components:
            p = c.purl_obj()
            if p and p.type == t:
                nss[p.namespace] += 1
                if (p.qualifiers or {}).get("distro"):
                    ds[p.qualifiers["distro"]] += 1
                elif t == "deb" and p.version:
                    m = re.search(r"deb(\d+)u", p.version)
                    if m:
                        ds[f"debian-{m.group(1)}"] += 0.5
        # release markers shipped in every base image (artifact-free evidence)
        for c in s.components:
            p = c.purl_obj()
            if not p or p.type != t or not p.version:
                continue
            if t == "apk" and p.name in ("alpine-release", "alpine-base", "alpine-baselayout-data", "alpine-baselayout"):
                m = re.match(r"^(\d+\.\d+)", p.version)
                if m and p.name in ("alpine-release", "alpine-base"):
                    ds[f"alpine-{m.group(1)}"] += 5
            if t == "deb" and p.name == "base-files":
                m = re.match(r"^(\d+)", p.version)
                if m:
                    ds[f"debian-{m.group(1)}"] += 5
        if ds:
            out[t] = ds.most_common(1)[0][0]
        if nss:
            out["_ns"][t] = nss.most_common(1)[0][0]
    return out


# ------------------------------------------------------------------ main
def repair(sbom: SBOM, cfg: VeraConfig | None = None, artifact: dict | None = None) -> RepairReport:
    cfg = cfg or VeraConfig()
    t0 = time.time()
    s = sbom.copy()
    rep = RepairReport(s)
    ts = s.metadata.get("timestamp")
    diag = quality.diagnose(s)
    rep.log.append(f"diagnosed {sum(diag['counts'].values())} component defects, sbom-level: {[d.kind for d in diag['sbom_defects']]}")
    majority = _majority_type(s)
    dh = _distro_hint(s)
    mu, fw = _eco_params(cfg, majority)

    # ---- 1. identity (symbolic) --------------------------------------------------------
    unresolved = []
    def ident(c):
        try:
            return c, symbolic_identity(c, majority, dh)
        except Exception as e:
            return c, (False, f"error {e}")
    with ThreadPoolExecutor(cfg.workers) as ex:
        for c, (ok, why) in ex.map(ident, s.components):
            if not ok:
                unresolved.append((c, why))
    rep.log.append(f"identity: {len(unresolved)} components unresolved symbolically")

    # ---- 2. temporal anchoring --------------------------------------------------------
    t_floor = None
    if cfg.use_anchor and ts:
        pins = []
        for c in s.components:
            idt = _comp_identity(c)
            if idt and c.version and not _needs_version(c):
                pins.append((idt, c.version))
        def pubdate(item):
            (pt, ns, nm), v = item
            vs = registry.package_versions(pt, nm, ns) or []
            return next((_parse_ts(x.get("published")) for x in vs if x["version"] == v), None)
        with ThreadPoolExecutor(cfg.workers) as ex:
            dates = [d for d in ex.map(pubdate, pins[:400]) if d]
        # declared-floor anchoring: the lower bound of every declared range had to exist when the lock was made
        def floor_date(c):
            idt = _comp_identity(c)
            d = _declared(c)
            if not idt or not d or "${" in d:
                return None
            vs = registry.package_versions(idt[0], idt[2], idt[1]) or []
            eco = eco_of(idt[0])
            from .versions import satisfies, is_prerelease
            sat = [x for x in vs if not is_prerelease(x["version"], eco) and satisfies(x["version"], d, eco)
                   and x.get("published")]
            if not sat:
                return None
            from .versions import sort_versions
            lo = sort_versions([x["version"] for x in sat], eco)[0]
            return next((_parse_ts(x["published"]) for x in sat if x["version"] == lo), None)
        with ThreadPoolExecutor(cfg.workers) as ex:
            floors = [d for d in ex.map(floor_date, s.components) if d]
        tsf = _parse_ts(ts)
        cands = []
        if dates:
            dates.sort()
            cands.append(dates[int(0.9 * (len(dates) - 1))])
        if floors:
            cands.append(max(floors))
        if cands and tsf:
            t_floor = min(max(cands), tsf)
            rep.log.append(f"temporal anchor: lock time >= {time.strftime('%Y-%m-%d', time.gmtime(t_floor))} "
                           f"({len(dates)} pinned comps, {len(floors)} declared floors)")
            rep.stats["anchor_gap_days"] = (tsf - t_floor) / 86400

    # ---- 3. version repair (symbolic) -----------------------------------------------
    root = s.root
    root_gav = None
    if root:
        rp = root.purl_obj()
        if rp and rp.type == "maven":
            root_gav = (rp.namespace, rp.name, rp.version)
        elif root.group and root.version:
            root_gav = (root.group, root.name, root.version)

    def fix_version(c: Component):
        idt = _comp_identity(c)
        if not idt or not _needs_version(c):
            return None
        pt, ns, nm = idt
        declared = _declared(c)
        if pt == "maven" and root_gav and (not c.version or "${" in (c.version or "")):
            v, ev = resolve_version(*root_gav, ns, nm, c.version)
            if v and registry.exists("maven", nm, ns, v):
                return c, {v: 1.0}, [ev], 1.0, declared
        cs = generate(pt, nm, ns, [declared] if declared else [], ts, mu, temporal=cfg.use_temporal,
                      t_floor=t_floor, floor_weight=fw)
        if not cs.dist:
            return None
        return c, cs.dist, cs.constraints, cs.confidence, declared

    with ThreadPoolExecutor(cfg.workers) as ex:
        vres = [r for r in ex.map(fix_version, s.components) if r]
    for c, dist, ev, conf, declared in vres:
        mode = max(dist, key=dist.get)
        _set_version(c, mode, dist, ev, conf, "constraint+temporal" if cfg.use_temporal else "newest-satisfying", declared)
    rep.log.append(f"version: repaired {len(vres)} components")

    # ---- 4. co-constraints from siblings' declared requirements -----------------------
    if cfg.use_coconstraints:
        n_ref = _coconstrain(s, ts, cfg, t_floor, mu, fw)
        rep.log.append(f"co-constraints refined {n_ref} components")

    # ---- 5. transitive completion ---------------------------------------------------
    sbom_kinds = [d.kind for d in diag["sbom_defects"]]
    do_graph = cfg.use_graph and (cfg.graph_mode == "always" or (cfg.graph_mode == "auto" and "SUSPECTED_MISSING_TRANSITIVE" in sbom_kinds))
    if do_graph:
        added = _complete_graph(s, ts, cfg, t_floor, mu, fw)
        rep.log.append(f"graph completion: added {added} transitive components")

    # ---- 6. VUG-prioritised agent tasks ------------------------------------------------
    tasks = []
    groups: dict = {}
    for c, why in unresolved:
        groups.setdefault((c.name.lower(), (c.group or "").lower(), why), []).append(c)
    for (_, _, why), cs_ in groups.items():
        c = cs_[0]
        tasks.append({"kind": "identity", "comp": c, "same": cs_[1:], "why": why, "cost": 1.0,
                      "value": prioritizer.identity_task_value(f"{c.group}:{c.name}" if c.group else c.name)})
    for c in s.components:
        if c.candidates and len(c.candidates) > 1:
            idt = _comp_identity(c)
            if idt:
                val = prioritizer.version_task_value(eco_of(idt[0]), c.osv_name(), c.candidates)
                if val > 0:
                    tasks.append({"kind": "version", "comp": c, "why": "uncertain version", "cost": 1.0, "value": val})
    os_missing = [c for c, why in unresolved if why == "distro unknown"]
    if os_missing and symbolic_distro(os_missing, s, rep):
        os_missing = [c for c in os_missing if not (c.purl_obj() and (c.purl_obj().qualifiers or {}).get("distro"))]
    if os_missing:
        tasks = [t for t in tasks if t["comp"] not in os_missing]
        tasks.append({"kind": "distro", "comps": os_missing, "comp": os_missing[0], "why": "OS release unknown", "cost": 1.0,
                      "value": sum(prioritizer.identity_task_value(c.osv_name(), ("Debian", "Alpine")) for c in os_missing[:200]) / 10})
    ordered = prioritizer.rank(tasks, cfg.use_vug)
    if cfg.use_vug:  # tasks that cannot change vulnerability findings are deferred to the end
        ordered = [t for t in ordered if t["value"] > 0] + [t for t in ordered if t["value"] <= 0]
    rep.stats["tasks_total"] = len(tasks)
    rep.stats["tasks_positive_value"] = sum(1 for t in tasks if t["value"] > 0)
    done = 0
    if cfg.use_llm and cfg.model:
        ctx = {"timestamp": ts, "sbom_majority_ecosystem": majority,
               "root": (root.purl or f"{root.group or ''}:{root.name}:{root.version or ''}") if root else None,
               "other_components_sample": [c.purl for c in s.components if c.purl][:15]}
        for t in ordered:
            if done >= cfg.budget:
                break
            c = t["comp"]
            if t["kind"] == "version" and t["value"] < 1.0:
                continue
            done += 1
            if t["kind"] == "distro":
                _distro_task(t["comps"], s, cfg, rep)
                continue
            info = {"name": c.name, "group": c.group, "version_field": c.version, "purl": c.purl,
                    "declared_range": _declared(c) or next((r.old for r in c.repairs if r.field == "version" and r.old), None),
                    "problem": t["why"]}
            if t["kind"] == "version":
                info["current_candidates"] = {v: round(p, 3) for v, p in list(c.candidates.items())[:8]}
                info["task"] = "Determine the most likely exact version; return the same ecosystem/name."
            try:
                res = run_agent(info, ctx, cfg.model, cfg.agent_steps, cfg.use_verifier)
            except Exception as e:
                rep.log.append(f"agent error on {c.name}: {e}")
                continue
            rep.agent_traces.append({"component": c.name, "kind": t["kind"], "value": t["value"], "accepted": res["accepted"],
                                     "reason": res["reason"], "proposal": res["proposal"], "steps": res["steps"],
                                     "tool_calls": res["toolbox"].calls})
            if res["accepted"] and res["proposal"]:
                _apply_agent(c, res, t["kind"], ts, cfg)
                for other in t.get("same", []):
                    _apply_agent(other, res, t["kind"], ts, cfg)
    rep.stats["agent_tasks"] = done

    # ---- 7. licenses -----------------------------------------------------------------
    if cfg.fill_licenses:
        def lic(c):
            idt = _comp_identity(c)
            if not idt or c.licenses or not c.version or _needs_version(c):
                return None
            ls = registry.licenses(idt[0], idt[2], c.version, idt[1])
            return (c, ls) if ls else None
        with ThreadPoolExecutor(cfg.workers) as ex:
            for r in ex.map(lic, s.components):
                if r:
                    r[0].licenses = r[1]
                    r[0].repairs.append(Repair("license", None, r[1], "registry", ["deps.dev version metadata"]))
    rep.stats["seconds"] = time.time() - t0
    rep.stats["repaired_components"] = sum(1 for c in s.components if c.repairs)
    return rep


def _set_version(c: Component, v: str, dist: dict, ev: list[str], conf: float, method: str, declared=None):
    old = c.version
    c.version = v
    c.candidates = dict(dist) if len(dist) > 1 else {}
    p = c.purl_obj()
    if p:
        c.purl = _make_purl(p.type, p.namespace, p.name, v, p.qualifiers)
    c.repairs.append(Repair("version", old if old is not None else declared, v, method, list(ev), conf))


def _coconstrain(s: SBOM, ts, cfg: VeraConfig, t_floor, mu, fw) -> int:
    """Use declared requirements of other components (at their repaired versions) to narrow uncertain ones."""
    by_key = {}
    for c in s.components:
        idt = _comp_identity(c)
        if idt:
            by_key[(idt[0], (f"{idt[1]}/{idt[2]}" if idt[0] == "npm" and idt[1] else f"{idt[1]}:{idt[2]}" if idt[0] == "maven" else idt[2]).lower())] = c
    uncertain = {k: c for k, c in by_key.items() if c.candidates and len(c.candidates) > 1 and k[0] != "maven"}
    if not uncertain:
        return 0
    def reqs(c):
        idt = _comp_identity(c)
        if not idt or not c.version or looks_like_range(c.version):
            return c, []
        return c, registry.requirements(idt[0], idt[2], c.version, idt[1])
    parents = [c for c in by_key.values()]
    with ThreadPoolExecutor(cfg.workers) as ex:
        rr = list(ex.map(reqs, parents))
    extra: dict = {}
    for parent, lst in rr:
        pt = _comp_identity(parent)[0] if _comp_identity(parent) else None
        for dep, spec in lst:
            k = (pt, (dep or "").lower() if pt != "pypi" else registry.norm_pypi(dep or ""))
            if k in uncertain and spec:
                extra.setdefault(k, []).append((spec, parent.name))
    n = 0
    for k, specs in extra.items():
        c = uncertain[k]
        idt = _comp_identity(c)
        declared = _declared(c) or next((r.old for r in c.repairs if r.field == "version"), None)
        allspecs = ([declared] if declared else []) + [sp for sp, _ in specs]
        cs = generate(idt[0], idt[2], idt[1], allspecs, ts, mu, temporal=cfg.use_temporal, t_floor=t_floor, floor_weight=fw)
        if cs.dist and (len(cs.dist) < len(c.candidates) or cs.mode != c.version):
            ev = [f"required '{sp}' by {pn}" for sp, pn in specs[:5]] + cs.constraints
            c.repairs = [r for r in c.repairs if r.field != "version"]
            _set_version(c, cs.mode, cs.dist, ev, cs.confidence, "co-constraint", declared)
            n += 1
    return n


def _complete_graph(s: SBOM, ts, cfg: VeraConfig, t_floor=None, mu=120.0, fw=1.0) -> int:
    direct = []
    for c in s.components:
        idt = _comp_identity(c)
        if idt and c.version and not _needs_version(c):
            direct.append((idt[0], idt[2], idt[1], c.version))
    rec = complete(direct, ts, mu, cfg.workers, temporal=cfg.use_temporal, t_floor=t_floor, floor_weight=fw)
    have = set()
    for c in s.components:
        idt = _comp_identity(c)
        if idt:
            have.add((idt[0], (idt[1] or "").lower(), idt[2].lower(), c.version if idt[0] == "npm" else None))
    added = 0
    links: list = []
    for r in rec:
        cs = r["cands"]
        key = (r["ptype"], (r["namespace"] or "").lower(), r["name"].lower(), cs.mode if r["ptype"] == "npm" else None)
        if key in have:
            continue
        have.add(key)
        comp = Component(name=r["name"], version=cs.mode, group=r["namespace"],
                         purl=_make_purl(r["ptype"], r["namespace"], r["name"], cs.mode),
                         bom_ref=f"vera-{len(s.components)}")
        comp.candidates = dict(cs.dist) if len(cs.dist) > 1 else {}
        comp.repairs.append(Repair("component", None, comp.purl, "graph-completion",
                                   [f"transitive dependency via {r['via']} (deps.dev graph)"] + cs.constraints, cs.confidence))
        s.components.append(comp)
        links.append((comp.bom_ref, r.get("parents") or [r["via"]]))
        added += 1
    # second pass: link every recovered node to all of its parents (parents may be recovered nodes themselves)
    def full(c):
        idt = _comp_identity(c)
        if not idt:
            return c.name.lower()
        pt, ns, nm = idt
        if pt == "maven":
            return f"{ns}:{nm}".lower()
        if pt == "npm" and ns:
            return f"{ns}/{nm}".lower()
        return registry.norm_pypi(nm) if pt == "pypi" else nm.lower()
    by_name: dict[str, list[str]] = {}
    for c in s.components:
        by_name.setdefault(full(c), []).append(c.bom_ref)
    for ref, pars in links:
        for pn in pars:
            prefs = by_name.get(pn.lower()) or by_name.get(registry.norm_pypi(pn)) or []
            for pref in prefs[:1]:
                if pref != ref and ref not in s.dependencies.setdefault(pref, []):
                    s.dependencies[pref].append(ref)
    return added


def _apply_agent(c: Component, res: dict, kind: str, ts, cfg: VeraConfig):
    p = res["proposal"]
    eco = (p.get("ecosystem") or "").lower()
    ns, nm = split_name(eco, p["name"])
    ev = [f"{eid}: {res['toolbox'].evidence[eid]['tool']}({res['toolbox'].evidence[eid]['args']})"
          for eid in p.get("evidence", []) if eid in res["toolbox"].evidence]
    old_purl = c.purl
    try:  # structurally invalid proposals (possible when the verifier is disabled) cannot be applied
        _make_purl(eco, ns, nm, p.get("version"))
    except (ValueError, TypeError):
        return
    if kind == "identity":
        c.name = nm
        c.group = ns
        ver = p.get("version")
        declared = _declared(c)
        if ver:
            c.purl = _make_purl(eco, ns, nm, ver)
            c.repairs.append(Repair("purl", old_purl, c.purl, "llm-agent", ev, 0.8))
            if ver != c.version:
                _set_version(c, ver, {ver: 1.0}, ev, 0.8, "llm-agent", declared)
        else:
            c.purl = _make_purl(eco, ns, nm, None if _needs_version(c) else c.version)
            c.repairs.append(Repair("purl", old_purl, c.purl, "llm-agent", ev, 0.8))
            if _needs_version(c):
                cs = generate(eco, nm, ns, [declared] if declared else [], ts, *_eco_params(cfg, eco)[:1], temporal=cfg.use_temporal)
                if cs.dist:
                    _set_version(c, cs.mode, cs.dist, cs.constraints, cs.confidence, "constraint+temporal", declared)
    else:
        ver = p.get("version")
        if ver and ver != c.version:
            dist = {ver: 0.8}
            for v, q in c.candidates.items():
                if v != ver:
                    dist[v] = dist.get(v, 0) + 0.2 * q
            z = sum(dist.values())
            _set_version(c, ver, {k: v / z for k, v in dist.items()}, ev, 0.8, "llm-agent")


DISTRO_PROMPT = """These OS packages come from one container image whose OS release is unknown.
Identify the distribution release from the package versions (e.g. musl, busybox, alpine-baselayout, libc6, base-files).
Answer ONLY JSON: {{"distro": "<alpine-3.18 | debian-12 | ...>", "evidence": "<which package versions support it>"}}
Packages (type name@version):
{rows}"""


def _fingerprint(s: SBOM):
    from . import vuln as _v
    out = {}
    for t, fam in (("apk", "Alpine"), ("deb", "Debian")):
        pk = []
        for c in s.components:
            p = c.purl_obj()
            if p and p.type == t and p.version:
                pk.append((c.osv_name(), p.version))
        if pk:
            out[t] = _v.release_fingerprint(pk, fam)
    return out


def _eco_to_distro(eco: str) -> str:
    fam, ver = eco.split(":", 1)
    return f"alpine-{ver.lstrip('v')}" if fam == "Alpine" else f"debian-{ver}"


def symbolic_distro(comps, s: SBOM, rep: RepairReport) -> bool:
    """Release fingerprinting from the vulnerability DB itself (no LLM). Accept only a clear winner."""
    fp = _fingerprint(s)
    applied = False
    for t, ranking in fp.items():
        if not ranking:
            continue
        best, sc = ranking[0]
        second = ranking[1][1] if len(ranking) > 1 else 0
        if sc >= 3 and sc >= 2 * second:
            d = _eco_to_distro(best)
            for c in comps:
                p = c.purl_obj()
                if p and p.type == t:
                    q = dict(p.qualifiers or {}); q["distro"] = d
                    old = c.purl
                    c.purl = _make_purl(p.type, p.namespace, p.name, p.version, q)
                    c.repairs.append(Repair("purl", old, c.purl, "fingerprint",
                                            [f"OSV release fingerprint {best}: {sc} exact version matches (next best {second})"], 0.9))
            rep.log.append(f"distro fingerprint ({t}): {best} score={sc} vs {second}")
            applied = True
    return applied


def _distro_task(comps, s: SBOM, cfg: VeraConfig, rep: RepairReport):
    from .agent.llm_client import chat, extract_json
    from . import vuln as _v
    key = [c for c in s.components if c.ptype in ("apk", "deb", "rpm")]
    prio = ("musl", "busybox", "alpine-baselayout", "alpine-keys", "libc6", "base-files", "libssl3", "openssl", "zlib", "apk-tools")
    key.sort(key=lambda c: (c.name not in prio, c.name))
    rows = "\n".join(f"{c.ptype} {c.name}@{c.version}" for c in key[:40])
    r = chat(cfg.model, [{"role": "user", "content": DISTRO_PROMPT.format(rows=rows)}], max_tokens=4000)
    j = extract_json(r["content"]) or {}
    d = str(j.get("distro", "")).lower().strip()
    m = re.match(r"^(alpine|debian)-(\d+(?:\.\d+)?)", d)
    ok, why = False, "unparseable"
    if m:
        fam, ver = m.group(1), m.group(2)
        eco = f"Alpine:v{'.'.join(ver.split('.')[:2])}" if fam == "alpine" else f"Debian:{ver.split('.')[0]}"
        ok = (not cfg.use_verifier) or eco in _v.known_os_releases()
        why = "ok" if ok else f"{eco} not a known release in the vulnerability database"
        if ok and cfg.use_verifier:
            # reject if the OSV fingerprint clearly contradicts the proposal
            fp = _fingerprint(s).get("apk" if fam == "alpine" else "deb") or []
            sc = dict(fp)
            top = fp[0][1] if fp else 0
            if top >= 3 and sc.get(eco, 0) < 0.5 * top:
                ok, why = False, f"contradicted by OSV fingerprint (best {fp[0][0]}={top}, proposed {eco}={sc.get(eco, 0)})"
    rep.agent_traces.append({"component": f"{len(comps)} OS packages", "kind": "distro", "value": 0, "accepted": ok,
                             "reason": why, "proposal": j, "steps": 1, "tool_calls": 0})
    if not ok:
        return
    for c in comps:
        p = c.purl_obj()
        if not p:
            continue
        q = dict(p.qualifiers or {})
        q["distro"] = d
        old = c.purl
        c.purl = _make_purl(p.type, p.namespace, p.name, p.version, q)
        c.repairs.append(Repair("purl", old, c.purl, "llm-agent", [f"OS release inferred from package versions: {j.get('evidence', '')}"[:300]], 0.8))
