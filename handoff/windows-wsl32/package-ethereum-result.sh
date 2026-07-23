#!/usr/bin/env bash
set -euo pipefail

run_root=${USDD_ETHEREUM_RUN_ROOT:-"$HOME/usdd-ethereum-runs"}
run_dir=$(readlink -f "$run_root/current")
[[ -f "$run_dir/SUCCESS" ]] || { echo "Current Ethereum run is not SUCCESS." >&2; exit 2; }
test -s "$run_dir/result.json"
test -s "$run_dir/proof/proof.raw.bin"
test -s "$run_dir/proof/public-values.bin"
test -s "$run_dir/proof/annex.bin"
test -s "$run_dir/proof/proof-metadata.json"
archive="$run_dir.tar.gz"
tar -C "$(dirname "$run_dir")" -czf "$archive" "$(basename "$run_dir")"
(cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")") >"$archive.sha256"
echo "$archive"
echo "$archive.sha256"
