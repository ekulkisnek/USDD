#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 <extracted-handoff-directory>" >&2; exit 2; }
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
binary="$repo/scripts/usdd-ecash-prover/target/release/usdd-ecash-prover"
handoff=$(readlink -f "$1")
run_root=${USDD_TRANSITION_RUN_ROOT:-"$HOME/usdd-transition-runs"}
circuit_root=${SP1_GROTH16_CIRCUIT_PATH:-"$HOME/usdd-sp1-circuits/groth16"}
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$run_root/ecash-transition-$timestamp"
circuit_dir="$circuit_root/v6.1.0"

[[ $(uname -s) == Linux ]] || { echo "Run inside Linux/WSL2." >&2; exit 2; }
test -x "$binary" || { echo "Run bootstrap.sh first." >&2; exit 2; }
test -f "$handoff/handoff-manifest.json" || { echo "Missing handoff manifest." >&2; exit 2; }
test -f "$handoff/SHA256SUMS" || { echo "Missing handoff checksums." >&2; exit 2; }
(cd "$handoff" && sha256sum --check SHA256SUMS)
git -C "$repo" diff --quiet
git -C "$repo" diff --cached --quiet
expected_commit=$(python3 - "$handoff/handoff-manifest.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["repositoryCommit"])
PY
)
actual_commit=$(git -C "$repo" rev-parse HEAD)
[[ $actual_commit == "$expected_commit" ]] || {
    echo "Handoff requires repository commit $expected_commit; found $actual_commit." >&2
    exit 2
}
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

if [[ -e "$circuit_dir" ]]; then
    for required in constraints.json groth16_witness.json groth16_pk.bin groth16_vk.bin; do
        test -s "$circuit_dir/$required" || {
            echo "Circuit directory is incomplete: $circuit_dir/$required" >&2
            exit 2
        }
    done
    actual_vk=$(sha256sum "$circuit_dir/groth16_vk.bin" | awk '{print $1}')
    expected_vk=4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696
    [[ $actual_vk == "$expected_vk" ]] || {
        echo "Installed Groth16 verifier-key hash mismatch: $actual_vk" >&2
        exit 2
    }
fi

mkdir -p "$run_root"
[[ ! -e "$run_dir" ]] || { echo "Run directory already exists." >&2; exit 2; }
mkdir "$run_dir"
ln -sfn "$run_dir" "$run_root/current"
cat >"$run_dir/run.env" <<EOF
created_utc=$timestamp
repository_commit=$(git -C "$repo" rev-parse HEAD)
handoff=$handoff
handoff_manifest_sha256=$(sha256sum "$handoff/handoff-manifest.json" | awk '{print $1}')
circuit_root=$circuit_root
memory_kib=$memory_kib
disk_free_kib=$free_kib
EOF

set -a
source "$here/input.env"
set +a
export SP1_GROTH16_CIRCUIT_PATH="$circuit_root"

nohup bash "$here/run-transition-worker.sh" "$run_dir" \
    "$here/run-transition-handoff.py" "$binary" "$handoff" \
    >"$run_dir/launcher.log" 2>&1 &
worker_pid=$!
printf '%s\n' "$worker_pid" >"$run_dir/worker.pid"
nohup bash "$here/watch-proof.sh" "$run_dir" "$worker_pid" \
    >"$run_dir/watch.log" 2>&1 &
printf '%s\n' "$!" >"$run_dir/watcher.pid"

echo "Started transition proof run: $run_dir"
echo "Worker PID: $worker_pid"
echo "Monitor with: bash $here/transition-status.sh"
