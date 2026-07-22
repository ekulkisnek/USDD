#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
[[ $(uname -s) == Linux ]] || { echo "Run inside Linux/WSL2." >&2; exit 2; }

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential clang cmake curl git libssl-dev pkg-config protobuf-compiler \
    python3 ca-certificates

if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain 1.88.0 --profile minimal
fi
source "$HOME/.cargo/env"
rustup toolchain install 1.88.0 --profile minimal
rustup override set 1.88.0 --path "$repo/scripts/usdd-ecash-prover"

python3 "$repo/scripts/usdd-sp1-prover/toolchain/prepare.py" --materialize
python3 "$repo/scripts/usdd-sp1-prover/toolchain/prepare.py" --check-vendor
cargo +1.88.0 build --locked --release \
    --manifest-path "$repo/scripts/usdd-ecash-prover/Cargo.toml"

binary="$repo/scripts/usdd-ecash-prover/target/release/usdd-ecash-prover"
test -x "$binary"
"$binary" setup "$here/artifacts/ecash-segment-v1.elf" \
    "$here/artifacts/ecash-fold-v1.elf"
echo "PASS: pinned prover built and guest identities verified"
