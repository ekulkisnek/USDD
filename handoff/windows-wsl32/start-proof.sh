#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
binary="$repo/scripts/usdd-ecash-prover/target/release/usdd-ecash-prover"
run_root=${USDD_PROOF_RUN_ROOT:-"$HOME/usdd-proof-runs"}
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$run_root/ecash-segment-$timestamp"

[[ $(uname -s) == Linux ]] || { echo "Run inside Linux/WSL2." >&2; exit 2; }
test -x "$binary" || { echo "Run bootstrap.sh first." >&2; exit 2; }

memory_kib=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
free_kib=$(df -Pk "$HOME" | awk 'NR == 2 {print $4}')
(( memory_kib >= 24 * 1024 * 1024 )) || {
    echo "Need 24 GiB visible RAM; found $((memory_kib / 1024 / 1024)) GiB." >&2
    exit 2
}
(( free_kib >= 60 * 1024 * 1024 )) || {
    echo "Need 60 GiB free disk; found $((free_kib / 1024 / 1024)) GiB." >&2
    exit 2
}

(cd "$here" && sha256sum --check input-sha256.txt)
python3 "$repo/scripts/usdd-sp1-prover/toolchain/prepare.py" --check-vendor

mkdir -p "$run_root"
[[ ! -e "$run_dir" ]] || { echo "Run directory already exists." >&2; exit 2; }
mkdir "$run_dir"
ln -sfn "$run_dir" "$run_root/current"

cat >"$run_dir/run.env" <<EOF
created_utc=$timestamp
repository_commit=$(git -C "$repo" rev-parse HEAD)
segment_elf_sha256=$(sha256sum "$here/artifacts/ecash-segment-v1.elf" | awk '{print $1}')
fold_elf_sha256=$(sha256sum "$here/artifacts/ecash-fold-v1.elf" | awk '{print $1}')
input_sha256=$(sha256sum "$here/artifacts/ecash-genesis-segment-input.bin" | awk '{print $1}')
memory_kib=$memory_kib
disk_free_kib=$free_kib
EOF

set -a
source "$here/input.env"
set +a

nohup bash "$here/run-proof-worker.sh" "$run_dir" "$binary" \
    "$here/artifacts/ecash-segment-v1.elf" \
    "$here/artifacts/ecash-fold-v1.elf" \
    "$here/artifacts/ecash-genesis-segment-input.bin" \
    >"$run_dir/launcher.log" 2>&1 &
worker_pid=$!
printf '%s\n' "$worker_pid" >"$run_dir/worker.pid"

nohup bash "$here/watch-proof.sh" "$run_dir" "$worker_pid" \
    >"$run_dir/watch.log" 2>&1 &
printf '%s\n' "$!" >"$run_dir/watcher.pid"

echo "Started proof run: $run_dir"
echo "Worker PID: $worker_pid"
echo "Monitor with: bash $here/status.sh"
