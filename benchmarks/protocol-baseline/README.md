# Protocol baseline

This benchmark captures the Hyper-based protocol path before the native
protocol core is introduced. It exercises persistent HTTP/1.1, HTTP/2
multiplexing, TLS, streaming bodies, concurrency, and duplicate-heavy header
blocks. The client and server run over an in-memory Tokio transport so the
result is protocol-stack CPU and allocation cost rather than kernel or network
noise.

Run the checked-in configuration from the repository root:

```sh
benchmarks/protocol-baseline/run.sh
```

The harness reports throughput, p50/p99 end-to-end latency, allocation count,
and allocated bytes per request. Allocation figures cover both the client and
server protocol paths in the benchmark process. TLS setup and warmup are outside
the measured region.

Raw results include the Git commit, Rust compiler, target triple, scenario
configuration, and schema version. Results are machine-dependent; compare final
results on the same host with background load minimized.
