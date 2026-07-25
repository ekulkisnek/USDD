#!/usr/bin/env bash
set -uo pipefail

if [[ $# -ne 5 ]]; then
    echo "usage: $0 <run-dir> <prover> <segment-elf> <fold-elf> <input>" >&2
    exit 2
fi
run_dir=$1
binary=$2
segment_elf=$3
fold_elf=$4
input=$5
output="$run_dir/proof"

"$binary" prove-segment "$segment_elf" "$fold_elf" "$input" "$output" \
    >"$run_dir/prover.log" 2>&1 &
prover_pid=$!
printf '%s\n' "$prover_pid" >"$run_dir/prover.pid"
wait "$prover_pid"
status=$?
printf '%s\n' "$status" >"$run_dir/exit-status"
if [[ $status -eq 0 && -d "$output" ]]; then
    touch "$run_dir/SUCCESS"
else
    touch "$run_dir/FAILED"
fi
exit "$status"
