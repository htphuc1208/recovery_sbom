from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA = ROOT / "data"
CACHE_DB = DATA / "cache" / "http_cache.sqlite"
LLM_CACHE_DB = DATA / "cache" / "llm_cache.sqlite"
OSV_DIR = DATA / "osv"
RESULTS = ROOT / "results"
FIGURES = ROOT / "figures"

LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "claude-opus-5")
# Models on the gateway that support tool calling (verified 2026-11-12)
AGENT_MODELS = ["claude-opus-5", "Qwen/Qwen3.5-122B-A10B-FP8", "Qwen/Qwen3.6-35B-A3B-FP8", "Qwen/Qwen3.5-35B-A3B-FP8"]
# Offline mode: only serve HTTP from cache (for reproducible experiments)
OFFLINE = os.environ.get("VERA_OFFLINE", "0") == "1"

for d in (DATA / "cache", OSV_DIR, RESULTS, FIGURES):
    d.mkdir(parents=True, exist_ok=True)
