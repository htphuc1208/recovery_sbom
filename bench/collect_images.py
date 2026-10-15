"""Container ground truth: Syft (pinned v1.18.1) CycloneDX SBOM of each pinned image (docker-archive input)."""
import json
import subprocess
import tempfile
from pathlib import Path
from bench.common import BENCH, save_json

SYFT = "anchore/syft:v1.18.1"


def main():
    out = BENCH / "B"
    for img in (out / "images.txt").read_text().split():
        slug = img.replace("/", "__").replace(":", "__")
        d = out / slug
        if (d / "truth.json").exists():
            continue
        digest = subprocess.run(["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}|{{.Created}}", img],
                                capture_output=True, text=True).stdout.strip()
        with tempfile.TemporaryDirectory() as tmp:
            tar = Path(tmp) / "img.tar"
            subprocess.run(["docker", "save", img, "-o", str(tar)], check=True)
            r = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{tmp}:/in:ro", SYFT,
                                "docker-archive:/in/img.tar", "-o", "cyclonedx-json", "-q"], capture_output=True, text=True)
        if r.returncode:
            print("fail", img, r.stderr[:300]); continue
        bom = json.loads(r.stdout)
        dg, created = (digest.split("|") + [""])[:2]
        bom.setdefault("metadata", {})["timestamp"] = created  # image build time
        bom["components"] = [c for c in bom.get("components", []) if c.get("purl")]
        save_json(bom, d / "truth.json")
        save_json({"image": img, "digest": dg, "timestamp": created, "ecosystem": "container",
                   "n_truth": len(bom["components"])}, d / "meta.json")
        types = {}
        for c in bom["components"]:
            t = c["purl"].split("/")[0][4:]
            types[t] = types.get(t, 0) + 1
        print(img, len(bom["components"]), types, flush=True)


if __name__ == "__main__":
    main()
