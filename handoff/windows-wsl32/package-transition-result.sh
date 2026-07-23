#!/usr/bin/env bash
set -euo pipefail

run_root=${USDD_TRANSITION_RUN_ROOT:-"$HOME/usdd-transition-runs"}
run_dir=$(readlink -f "$run_root/current")
[[ -f "$run_dir/SUCCESS" ]] || { echo "Current transition run is not SUCCESS." >&2; exit 2; }
test -s "$run_dir/groth16-wrapper/wrap-metadata.json"
test -s "$run_dir/groth16-wrapper/groth16-proof.bin"
test -s "$run_dir/groth16-wrapper/relay-proof.bin"
archive="$run_dir.tar.gz"
tar -C "$(dirname "$run_dir")" -czf "$archive" "$(basename "$run_dir")"
(cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")") >"$archive.sha256"
echo "$archive"
echo "$archive.sha256"
