#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 <extracted-handoff-directory>" >&2; exit 2; }
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
binary="$repo/scripts/usdd-sp1-prover/target/release/usdd-sp1-prover"
handoff=$(readlink -f "$1")
run_root=${USDD_ETHEREUM_RUN_ROOT:-"$HOME/usdd-ethereum-runs"}
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$run_root/ethereum-v7-$timestamp"

[[ $(uname -s) == Linux ]] || { echo "Run inside Linux/WSL2." >&2; exit 2; }
test -x "$binary" || { echo "Build the pinned release prover first." >&2; exit 2; }
test -f "$handoff/handoff-manifest.json" || { echo "Missing handoff manifest." >&2; exit 2; }
test -f "$handoff/SHA256SUMS" || { echo "Missing handoff checksums." >&2; exit 2; }
(cd "$handoff" && sha256sum --check SHA256SUMS)
python3 "$repo/scripts/usdd-sp1-prover/toolchain/prepare.py" --check-vendor

memory_kib=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
free_kib=$(df -Pk "$HOME" | awk 'NR == 2 {print $4}')
(( memory_kib >= 24 * 1024 * 1024 )) || {
    echo "Need 24 GiB visible RAM; found $((memory_kib / 1024 / 1024)) GiB." >&2
    exit 2
}
(( free_kib >= 120 * 1024 * 1024 )) || {
    echo "Need 120 GiB free disk; found $((free_kib / 1024 / 1024)) GiB." >&2
    exit 2
}

mkdir -p "$run_root"
[[ ! -e "$run_dir" ]] || { echo "Run directory already exists." >&2; exit 2; }
mkdir "$run_dir"
ln -sfn "$run_dir" "$run_root/current"
cat >"$run_dir/run.env" <<EOF
created_utc=$timestamp
repository_commit=$(git -C "$repo" rev-parse HEAD)
handoff=$handoff
handoff_manifest_sha256=$(sha256sum "$handoff/handoff-manifest.json" | awk '{print $1}')
memory_kib=$memory_kib
disk_free_kib=$free_kib
EOF

set -a
source "$here/input.env"
set +a

nohup bash "$here/run-ethereum-worker.sh" "$run_dir" \
    "$here/run-ethereum-handoff.py" "$binary" "$handoff" \
    >"$run_dir/launcher.log" 2>&1 &
worker_pid=$!
printf '%s\n' "$worker_pid" >"$run_dir/worker.pid"
nohup bash "$here/watch-proof.sh" "$run_dir" "$worker_pid" \
    >"$run_dir/watch.log" 2>&1 &
printf '%s\n' "$!" >"$run_dir/watcher.pid"

echo "Started V7 Ethereum proof run: $run_dir"
echo "Worker PID: $worker_pid"
