#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
baseline="$repo_root/benchmarks/protocol-baseline/results.json"
final="$repo_root/benchmarks/protocol-baseline/final-results.json"
comparison="$repo_root/benchmarks/protocol-baseline/comparison.json"

cd "$repo_root"
cargo bench -p proxyapi --bench protocol_final -- \
    --warmup 2000 \
    --iterations 20000 \
    --output "$final" \
    --baseline "$baseline" \
    --comparison "$comparison"
