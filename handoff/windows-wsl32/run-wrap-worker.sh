#!/usr/bin/env bash
set -uo pipefail

if [[ $# -ne 5 ]]; then
    echo "usage: $0 <run-dir> <prover> <segment-elf> <fold-elf> <source-proof>" >&2
    exit 2
fi
run_dir=$1
binary=$2
segment_elf=$3
fold_elf=$4
source_proof=$5
output="$run_dir/wrapper"
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

"$binary" wrap-groth16 "$segment_elf" "$fold_elf" "$source_proof" "$output" \
    >"$run_dir/wrapper.log" 2>&1 &
prover_pid=$!
printf '%s\n' "$prover_pid" >"$run_dir/prover.pid"
wait "$prover_pid"
status=$?
printf '%s\n' "$status" >"$run_dir/exit-status"
if [[ $status -eq 0 && -d "$output" ]]; then
    if python3 "$here/verify-wrap-result.py" "$output" >"$run_dir/verification.log" 2>&1; then
        touch "$run_dir/SUCCESS"
    else
        touch "$run_dir/FAILED_VALIDATION"
        exit 1
    fi
else
    touch "$run_dir/FAILED"
fi
exit "$status"
