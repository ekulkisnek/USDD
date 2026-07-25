#!/usr/bin/env bash
set -euo pipefail

run_root=${USDD_PROOF_RUN_ROOT:-"$HOME/usdd-proof-runs"}
run_dir=$(readlink -f "$run_root/current")
[[ -f "$run_dir/SUCCESS" ]] || { echo "Current run is not SUCCESS." >&2; exit 2; }

archive="$run_dir.tar.gz"
tar -C "$(dirname "$run_dir")" -czf "$archive" "$(basename "$run_dir")"
(cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")") >"$archive.sha256"
echo "$archive"
echo "$archive.sha256"
