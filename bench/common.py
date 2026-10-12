from __future__ import annotations
import json
from pathlib import Path
from vera import config

BENCH = config.DATA / "bench"
BENCH.mkdir(parents=True, exist_ok=True)


def save_json(obj, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(obj, indent=1))


def load_json(path):
    return json.loads(Path(path).read_text())
