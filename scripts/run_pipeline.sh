#!/usr/bin/env bash
# PERSON A - run every Linux step in order. LLM generation is separate (long; see README step 3).
#   bash scripts/run_pipeline.sh            # tracing + baseline + enforcement + analysis
#   bash scripts/run_pipeline.sh --no-trace # skip re-recording traces (keep existing data/)
set -euo pipefail
cd "$(dirname "$0")/.."
make
if [[ "${1:-}" != "--no-trace" ]]; then
  python3 tracing/record_traces.py          # data/<program>/traces/*.strace + summaries
fi
python3 tracing/make_baseline.py            # policies/baseline/*
python3 enforce/run_enforcement.py          # results/enforcement.csv   (real seccomp)
python3 enforce/run_containment.py          # results/containment.csv   (probe validation)
python3 analysis/evaluate_policies.py       # results/policy_metrics.csv
python3 analysis/make_figures.py            # results/figures/*.png + results/summary.md
echo "Done. Open results/summary.md and results/figures/."
