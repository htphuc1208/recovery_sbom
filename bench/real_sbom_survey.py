"""RQ1: how bad are real-world SBOMs? Survey GitHub dependency-graph SBOMs (SPDX 2.3, produced by GitHub
for any public repo) of popular repositories across ecosystems. Unauthenticated API: <=60 req/h -> sleep."""
import json
import time
import sys
from vera.evidence.http import get
from bench.common import BENCH, save_json

GH = "https://api.github.com/search/repositories?q={q}&sort=stars&order=desc&per_page=100&page=1"
QUERIES = {"Python": "language:Python+stars:>3000+pushed:>2026-06-01",
           "JavaScript": "language:JavaScript+stars:>3000+pushed:>2026-06-01",
           "TypeScript": "language:TypeScript+stars:>3000+pushed:>2026-06-01",
           "Java": "language:Java+stars:>3000+pushed:>2026-06-01"}


def main(per_lang=30):
    out = BENCH / "survey"
    for lang, q in QUERIES.items():
        res = get(GH.format(q=q))
        if not res:
            print("search failed", lang); continue
        items = [i for i in res["items"] if not i.get("fork") and not i.get("archived")]
        # take every 3rd repo to spread over the star range
        for item in items[::3][:per_lang]:
            repo = item["full_name"]
            f = out / lang / (repo.replace("/", "__") + ".json")
            if f.exists():
                continue
            url = f"https://api.github.com/repos/{repo}/dependency-graph/sbom"
            d = get(url)
            if d is None:
                print("no sbom", repo, flush=True)
            else:
                save_json(d, f)
                print(lang, repo, len(d.get("sbom", {}).get("packages", [])), flush=True)
            time.sleep(62)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 30)
