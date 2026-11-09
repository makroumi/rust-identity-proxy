# rust-identity-proxy

An identity-aware TLS reverse proxy. It requires mutual TLS (mTLS), extracts
client-certificate identities, evaluates deny-by-default YAML access policies,
and forwards authorized requests to one HTTP or HTTPS upstream. HTTPS upstream
verification is enabled by default.

## Workspace

| Crate | Purpose |
| --- | --- |
| `proxy-core` | Shared identity, policy, audit, and error types |
| `proxy-tls` | TLS configuration and certificate identity extraction |
| `proxy-policy` | YAML policy evaluation and path matching |
| `proxy-trust` | Validated, atomically replaceable client-CA trust store |
| `proxy-server` | Proxy binary and HTTP request handling |

See [docs/architecture.md](docs/architecture.md) for request flow and operating
behavior.

## Build and test

Requirements: Rust 1.89+ and OpenSSL 1.1.1+ for local certificate generation.
Install [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) to run
the local coverage command below.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
cargo llvm-cov --workspace --locked \
  --ignore-filename-regex 'crates/proxy-server/src/main\.rs' \
  --fail-under-lines 65
scripts/e2e-test.sh
```

GitHub Actions runs formatting, Clippy, locked builds and tests on Rust 1.89
(the workspace MSRV) and stable, enforces a 65% workspace line-coverage floor
(excluding the binary entrypoint, which is exercised by end-to-end tests),
compiles benchmarks and the container image, and exercises mTLS, HTTPS upstream
verification, default-deny authorization, and live client-CA reload
end-to-end. Coverage is uploaded as an LCOV artifact. Dependabot checks Rust
dependencies and Actions weekly, and CI audits the locked dependency graph for
known vulnerabilities.

Pushing a `vMAJOR.MINOR.PATCH` tag runs release verification and, on success,
publishes a versioned container image to GHCR with provenance and an SBOM. The
package must be enabled for the repository or organization.

## Local mTLS run

Generate test-only certificates, then start a local HTTP backend:

```bash
./scripts/gen-certs.sh
docker run --rm -p 8080:80 kennethreitz/httpbin
```

In another terminal:

```bash
cargo run -p proxy-server -- --config config/proxy.toml
```

Try a request authorized for the sample agent identity:

```bash
curl --cert config/certs/client.crt \
  --key config/certs/client.key \
  --cacert config/certs/ca.crt \
  https://localhost:8443/api/v1/identity/self
```

The local configuration binds only to loopback and explicitly opts in to a
plain-HTTP upstream for development. Do not copy that setting into production.
The sample policy grants no administrator wildcard access; unmatched identities
and requests are denied. A client certificate is required for every HTTP
request.

## Docker Compose

Generate the local certificates first; they are intentionally not baked into
the image:

```bash
./scripts/gen-certs.sh
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" \
  docker compose -f docker/compose.yaml up --build
```

The Compose configuration points the proxy at the `backend` service on the
Compose network. This development-only Compose configuration explicitly opts
in to HTTP between the containers. The image's default
[`docker/proxy.toml`](docker/proxy.toml) requires HTTPS upstreams. The
non-root container user needs read access to mounted certificates; Compose
uses the invoking host UID/GID so the generated private keys remain
owner-readable only.

## Policies and operations

Policies are in [config/policies.yaml](config/policies.yaml). `*` matches one
path segment, `**` matches zero or more segments, and normalized paths are both
authorized and forwarded to avoid policy/backend path discrepancies.

The server enforces request-body, upstream-timeout, concurrent-request,
connection-count, and process-wide token-bucket rate limits. `SIGTERM`/Ctrl-C
stop new accepts and drain active connections for up to 30 seconds. On Unix,
`SIGHUP` validates the configured client CA bundle and applies it to new TLS
handshakes; existing TLS connections retain their original trust decision.
The container healthcheck uses a separate unauthenticated HTTP listener bound
to `server.health_addr` (loopback only); it does not expose proxy data or check
upstream availability.
See [docs/trust-rotation.md](docs/trust-rotation.md) and
[docs/performance.md](docs/performance.md) for operational details and capacity
planning guidance.

## Production deployment checklist

- Replace the example policy with the deployment's reviewed identity and
  method/path grants. The checked-in policy is a demonstration, not an
  application-specific authorization design.
- Keep `allow_insecure_upstream` unset or `false`. HTTPS is required by default;
  optionally set `tls.upstream_ca` to a PEM bundle containing the upstream
  trust roots. When omitted, the system's native root certificates are used.
- Supply production server/client CA material through a secret manager or
  protected read-only mounts. `scripts/gen-certs.sh` creates test-only
  certificates and must never be used for production credentials.
- Configure limits against measured workload and deploy behind the intended
  network controls. Rate limiting is global per process, so scale-out instances
  each have their own bucket.
- Run the container as its default non-root UID (10001) or map it to the
  secret-owning UID as the Compose example does. Do not make private keys
  world-readable to accommodate a container. Set CPU, memory, process, and
  connection limits appropriate to the deployment.
- Configure GitHub package publishing before pushing a version tag. Review CI
  and release workflow results and the generated SBOM/provenance before
  distribution.

## Benchmarks

```bash
cargo bench -p proxy-server
```

## License

MIT; see [LICENSE](LICENSE).
