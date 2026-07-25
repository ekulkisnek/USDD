#!/usr/bin/env bash
set -uo pipefail

[[ $# -eq 4 ]] || { echo "usage: $0 <run-dir> <runner> <binary> <handoff>" >&2; exit 2; }
run_dir=$1
runner=$2
binary=$3
handoff=$4

python3 "$runner" --binary "$binary" --handoff "$handoff" --run-dir "$run_dir"
status=$?
printf '%s\n' "$status" >"$run_dir/exit-status"
if [[ $status -ne 0 ]]; then
    touch "$run_dir/FAILED"
fi
exit "$status"
