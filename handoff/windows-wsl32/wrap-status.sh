#!/usr/bin/env bash
set -euo pipefail

run_root=${USDD_WRAP_RUN_ROOT:-"$HOME/usdd-wrap-runs"}
run_dir="$run_root/current"
[[ -d "$run_dir" ]] || { echo "No current wrapper run at $run_dir" >&2; exit 2; }

echo "run=$(readlink -f "$run_dir")"
if [[ -e "$run_dir/SUCCESS" ]]; then
    echo "status=SUCCESS"
elif [[ -e "$run_dir/FAILED_VALIDATION" ]]; then
    echo "status=FAILED_VALIDATION"
    cat "$run_dir/verification.log" 2>/dev/null || true
elif [[ -e "$run_dir/FAILED" ]]; then
    echo "status=FAILED exit=$(cat "$run_dir/exit-status" 2>/dev/null || echo unknown)"
    tail -n 30 "$run_dir/wrapper.log" 2>/dev/null || true
else
    pid=$(cat "$run_dir/worker.pid")
    if kill -0 "$pid" 2>/dev/null; then
        echo "status=RUNNING pid=$pid"
    else
        echo "status=PROCESS_MISSING"
    fi
fi
tail -n 5 "$run_dir/health.log" 2>/dev/null || true
find "$run_dir/wrapper" -maxdepth 1 -type f -printf '%f %s bytes\n' 2>/dev/null || true
df -h "$run_dir" | tail -n 1
