#!/usr/bin/env bash
set -euo pipefail

campaign=${1:?usage: run_afl_matrix_slurm.sh CAMPAIGN_DIR}
runtime=${2:-600}
shard_index=${3:-0}
shard_count=${4:-1}
repo=/home/msai/qinh0007/free5gc-security-lab
cd "$repo"
module load gcc/14.2.0
module load gmp/6.3.0
export GOROOT="$HOME/opt/go"
export PATH="$HOME/opt/afl/bin:$HOME/opt/go/bin:$HOME/.local/bin:$PATH"
export PYTHONPATH="$repo/src${PYTHONPATH:+:$PYTHONPATH}"
# Phase 2.1 determinism lock, documented here for visibility. run-matrix also
# sets these explicitly in its own subprocess environment (authoritative),
# so this is not load-bearing but kept in sync to avoid misleading readers.
export GOMAXPROCS=1
export GOGC=off
export GODEBUG=asyncpreemptoff=1,gctrace=0
exec /home/msai/qinh0007/nwdaf-research/.venv/bin/python scripts/afl_seed_comparison.py run-matrix \
    --campaign "$campaign" \
    --runtime "$runtime" \
    --timeout-ms 1000 \
    --memory-mb 2048 \
    --shard-index "$shard_index" \
    --shard-count "$shard_count"
