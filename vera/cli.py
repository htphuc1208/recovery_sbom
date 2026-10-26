"""vera CLI: diagnose / repair / scan an SBOM."""
from __future__ import annotations
import argparse
import json
from . import sbom_io, quality, vuln
from .pipeline import repair, VeraConfig


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vera")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diagnose"); d.add_argument("sbom")
    s = sub.add_parser("scan"); s.add_argument("sbom")
    r = sub.add_parser("repair"); r.add_argument("sbom"); r.add_argument("-o", "--output", required=True)
    r.add_argument("--model", default="Qwen/Qwen3.6-35B-A3B-FP8"); r.add_argument("--no-llm", action="store_true")
    r.add_argument("--budget", type=int, default=20); r.add_argument("--report", default=None)
    a = ap.parse_args(argv)
    sb = sbom_io.load(a.sbom)
    if a.cmd == "diagnose":
        print(json.dumps(quality.summary(sb), indent=2))
    elif a.cmd == "scan":
        for f in sorted(vuln.scan(sb), key=lambda f: -f.severity):
            print(f"{f.vuln:22s} {f.severity:4.1f} p={f.prob:.2f} {f.tier:9s} {f.component}@{f.version}")
    else:
        rep = repair(sb, VeraConfig(model=a.model, use_llm=not a.no_llm, budget=a.budget))
        sbom_io.dump(rep.sbom, a.output)
        print("\n".join(rep.log))
        if a.report:
            fs = vuln.scan(rep.sbom)
            json.dump({"log": rep.log, "stats": rep.stats, "agent_traces": rep.agent_traces,
                       "vulnerabilities": [f.__dict__ | {"tier": f.tier} for f in fs]}, open(a.report, "w"), indent=1, default=str)
        print(f"written {a.output}")


if __name__ == "__main__":
    main()
