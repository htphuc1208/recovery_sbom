"""Tune (mu_days, floor_weight) per ecosystem on the dev split only (symbolic VERA, no LLM)."""
import itertools
import pandas as pd
from vera import sbom_io, vuln, config
from vera.pipeline import repair, VeraConfig
from bench.run_experiments import samples
from bench.metrics import evaluate

S = [(e, d, sbom_io.load(d / "truth.json"), sbom_io.load(d / "bad_manifest.json")) for e, d in samples(("pypi", "npm", "maven"), "dev")]
TF = {d: {(f.component, f.vuln): f.severity for f in vuln.scan(t, False)} for e, d, t, b in S}
rows = []
for mu, fw in itertools.product((30, 60, 120, 240), (0.0, 0.25, 0.5, 0.75, 1.0)):
    for e, d, t, b in S:
        r = repair(b, VeraConfig(use_llm=False, mu_days=mu, floor_weight=fw, fill_licenses=False))
        m = evaluate(r.sbom, t, b, truth_findings=TF[d])
        rows.append({"mu": mu, "fw": fw, "eco": e, **{k: m[k] for k in ("exact_f1", "vuln_f1", "vuln_p", "vuln_r", "vuln_brier")}})
df = pd.DataFrame(rows)
g = df.groupby(["eco", "mu", "fw"])[["exact_f1", "vuln_f1", "vuln_brier"]].mean()
g.to_csv(config.RESULTS / "tuning_dev.csv")
for e in df.eco.unique():
    ge = g.loc[e]
    best = ge.sort_values(["vuln_f1", "exact_f1"], ascending=False).head(3)
    print(e, "\n", best.round(3).to_string())
