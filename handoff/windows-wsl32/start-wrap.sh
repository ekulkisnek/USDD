#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
binary="$repo/scripts/usdd-ecash-prover/target/release/usdd-ecash-prover"
source_proof=${1:-"/root/usdd-proof-runs/ecash-segment-20260722T204834Z/proof"}
run_root=${USDD_WRAP_RUN_ROOT:-"$HOME/usdd-wrap-runs"}
circuit_root=${SP1_GROTH16_CIRCUIT_PATH:-"$HOME/usdd-sp1-circuits/groth16"}
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$run_root/ecash-segment-groth16-$timestamp"
circuit_dir="$circuit_root/v6.1.0"

[[ $(uname -s) == Linux ]] || { echo "Run inside Linux/WSL2." >&2; exit 2; }
test -x "$binary" || { echo "Run bootstrap.sh first." >&2; exit 2; }
python3 "$here/verify-segment-result.py" "$source_proof"
python3 "$repo/scripts/usdd-sp1-prover/toolchain/prepare.py" --check-vendor
(cd "$here" && sha256sum --check input-sha256.txt)

memory_kib=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
free_kib=$(df -Pk "$HOME" | awk 'NR == 2 {print $4}')
(( memory_kib >= 24 * 1024 * 1024 )) || {
    echo "Need 24 GiB visible RAM; found $((memory_kib / 1024 / 1024)) GiB." >&2
    exit 2
}
(( free_kib >= 100 * 1024 * 1024 )) || {
    echo "Need 100 GiB free disk before circuit installation and wrapping; found $((free_kib / 1024 / 1024)) GiB." >&2
    exit 2
}

if [[ -e "$circuit_dir" ]]; then
    for required in constraints.json groth16_witness.json groth16_pk.bin groth16_vk.bin; do
        test -s "$circuit_dir/$required" || {
            echo "Circuit directory exists but is incomplete: $circuit_dir/$required" >&2
            echo "Preserve/rename the incomplete v6.1.0 directory before retrying; do not overwrite it blindly." >&2
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
source_proof=$source_proof
source_raw_proof_sha256=$(sha256sum "$source_proof/proof.raw.bin" | awk '{print $1}')
source_public_values_sha256=$(sha256sum "$source_proof/public-values.bin" | awk '{print $1}')
circuit_root=$circuit_root
memory_kib=$memory_kib
disk_free_kib=$free_kib
EOF

set -a
source "$here/input.env"
set +a
export SP1_GROTH16_CIRCUIT_PATH="$circuit_root"

nohup bash "$here/run-wrap-worker.sh" "$run_dir" "$binary" \
    "$here/artifacts/ecash-segment-v1.elf" \
    "$here/artifacts/ecash-fold-v1.elf" "$source_proof" \
    >"$run_dir/launcher.log" 2>&1 &
worker_pid=$!
printf '%s\n' "$worker_pid" >"$run_dir/worker.pid"

nohup bash "$here/watch-proof.sh" "$run_dir" "$worker_pid" \
    >"$run_dir/watch.log" 2>&1 &
printf '%s\n' "$!" >"$run_dir/watcher.pid"

echo "Started Groth16 wrapping: $run_dir"
echo "Worker PID: $worker_pid"
echo "SP1 may first download and extract the official v6.1.0 Groth16 circuit package."
echo "Monitor with: bash $here/wrap-status.sh"
