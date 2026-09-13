#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output=${1:-"$repo_root/benchmarks/protocol-baseline/results.json"}

cd "$repo_root"
cargo bench -p proxyapi --bench protocol_baseline -- \
    --warmup 2000 \
    --iterations 20000 \
    --output "$output"
