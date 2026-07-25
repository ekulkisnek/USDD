#!/bin/sh
set -eu

toolchain_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$toolchain_dir/prepare.py" --materialize >&2

exec cargo "$@"
