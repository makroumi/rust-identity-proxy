# Performance

## Benchmarking

The Criterion benchmarks isolate path normalization and YAML policy evaluation;
they do not include TLS handshakes, network I/O, or upstream processing.

```bash
cargo bench -p proxy-server
```

## Interpreting results

Measure on the target hardware and with representative policy sizes and request
paths. The sequential `scripts/load-test.sh` helper measures end-to-end request
throughput for a local mTLS setup, but it is a smoke/load check rather than a
reproducible benchmark. For production capacity planning, use a purpose-built
load generator and record the proxy, upstream, hardware, and workload
configuration.

The current implementation uses a pooled HTTP/1.1 upstream client. HTTPS
upstream connections validate certificates against the native system roots by
default or a configured private CA bundle. Network and TLS costs remain
outside the microbenchmarks and may dominate end-to-end latency. The configured
request rate limit is a process-wide token bucket; it is not coordinated across
replicas.
