#!/usr/bin/env bash
set -euo pipefail

run_root=${USDD_PROOF_RUN_ROOT:-"$HOME/usdd-proof-runs"}
run_dir="$run_root/current"
[[ -d "$run_dir" ]] || { echo "No current proof run at $run_dir" >&2; exit 2; }

echo "run=$(readlink -f "$run_dir")"
if [[ -e "$run_dir/SUCCESS" ]]; then
    echo "status=SUCCESS"
elif [[ -e "$run_dir/FAILED" ]]; then
    echo "status=FAILED exit=$(cat "$run_dir/exit-status" 2>/dev/null || echo unknown)"
else
    pid=$(cat "$run_dir/worker.pid")
    if kill -0 "$pid" 2>/dev/null; then
        echo "status=RUNNING pid=$pid"
    else
        echo "status=PROCESS_MISSING"
    fi
fi
tail -n 5 "$run_dir/health.log" 2>/dev/null || true
find "$run_dir/proof" -maxdepth 1 -type f -printf '%f %s bytes\n' 2>/dev/null || true
df -h "$run_dir" | tail -n 1
