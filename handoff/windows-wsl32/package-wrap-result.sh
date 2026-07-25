#!/usr/bin/env bash
set -euo pipefail

run_root=${USDD_WRAP_RUN_ROOT:-"$HOME/usdd-wrap-runs"}
run_dir=$(readlink -f "$run_root/current")
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ -f "$run_dir/SUCCESS" ]] || { echo "Current wrapper run is not SUCCESS." >&2; exit 2; }
python3 "$here/verify-wrap-result.py" "$run_dir/wrapper"

archive="$run_dir.tar.gz"
tar -C "$(dirname "$run_dir")" -czf "$archive" "$(basename "$run_dir")"
(cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")") >"$archive.sha256"
echo "$archive"
echo "$archive.sha256"
