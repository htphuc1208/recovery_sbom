#!/usr/bin/env bash
# Full experiment suite in 4 parallel streams. Logs -> data/logs/
cd "$(dirname "$0")/.."
PY=.venv/bin/python
Q=Qwen/Qwen3.6-35B-A3B-FP8
mkdir -p data/logs
R="$PY -m bench.run_experiments"
stream1() {  # symbolic methods on full test split + ablations
  $R main_natural --methods B0,B1-latest,B1-ts,B2,VERA-noLLM --split test
  $R ablation --methods VERA-noLLM,VERA-noLLM-noTemporal,VERA-noLLM-noAnchor,VERA-noLLM-noCo,VERA-noLLM-noGraph --split test
  for lv in light medium heavy; do $R degraded_$lv --methods B0,B1-ts,VERA-noLLM --degrade $lv --split test; done
  $R containers --sets container --methods B0,B1-ts,VERA-noLLM --degrade medium --seeds 0,1
  $R containers --sets container --methods B0,B1-ts,VERA-noLLM,VERA --model $Q --degrade heavy --seeds 0,1
}
stream2() {  # LLM methods (Qwen3.6-35B) on natural
  $R main_natural --methods VERA,B3 --model $Q --split test --limit 12
  $R main_natural --methods B4 --model $Q --split test --limit 6
}
stream3() {  # degraded with LLM + ablations + budget curve
  for lv in medium heavy; do $R degraded_$lv --methods VERA --model $Q --degrade $lv --split test --limit 8; done
  $R degraded_heavy --methods B3 --model $Q --degrade heavy --split test --limit 8
  $R ablation_llm --methods VERA,VERA-noVerifier,VERA-noVUG --model $Q --degrade heavy --split test --limit 8
  $R rq5_budget --methods VERA-b0,VERA-b1,VERA-b2,VERA-b4,VERA-b8,VERA-b16,VERA-noVUG-b1,VERA-noVUG-b2,VERA-noVUG-b4,VERA-noVUG-b8,VERA-noVUG-b16 --model $Q --degrade heavy --split test --limit 8
}
stream4() {  # model comparison (Opus 5 vs Qwen family)
  $R main_natural --methods VERA,B3 --model claude-opus-5 --split test --limit 6
  $R degraded_heavy --methods VERA,B3 --model claude-opus-5 --degrade heavy --split test --limit 6
  $R degraded_heavy --methods VERA --model Qwen/Qwen3.5-122B-A10B-FP8 --degrade heavy --split test --limit 8
  $R degraded_heavy --methods VERA --model Qwen/Qwen3.5-35B-A3B-FP8 --degrade heavy --split test --limit 8
  $R main_natural --methods B4 --model claude-opus-5 --split test --limit 3
}
stream1 > data/logs/s1.log 2>&1 &
stream2 > data/logs/s2.log 2>&1 &
stream3 > data/logs/s3.log 2>&1 &
stream4 > data/logs/s4.log 2>&1 &
wait
echo ALL DONE
