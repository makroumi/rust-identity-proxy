# Architecture

## Request flow

1. A client establishes TLS with a client certificate.
2. `rustls` validates the server certificate and requires a trusted client
   certificate before HTTP handling begins.
3. `proxy-tls` extracts the subject, issuer, SANs, serial, and validity window
   from the authenticated certificate.
4. `proxy-policy` evaluates the canonical identity, HTTP method, and normalized
   path against YAML rules. Unmatched requests are denied.
5. `proxy-server` records a structured audit event and forwards allowed
   requests to the configured HTTP(S) upstream over a verified TLS connection
   by default.

## Crate responsibilities

| Crate | Responsibility |
| --- | --- |
| `proxy-core` | Shared identity, policy, audit, and error types |
| `proxy-tls` | mTLS configuration and X.509 identity extraction |
| `proxy-policy` | YAML policy engine and path matcher |
| `proxy-trust` | Validated, atomic client-CA trust store replacement |
| `proxy-server` | TLS listener, middleware, audit, and upstream forwarding |

## TLS and identity boundary

Certificate-chain and validity checks happen during the TLS handshake. Identity
extraction is performed only after the handshake succeeds; authorization is a
separate application-layer policy decision. A certificate's SPIFFE URI SAN is
the preferred canonical identity, with the subject as the fallback.

## Request handling

The server streams request and response bodies and applies the configured
body-size limit (10 MiB by default). Hop-by-hop headers are removed before
forwarding, and proxy-controlled `X-Forwarded-*` headers are added. Normalized
paths are used for both authorization and forwarding. The listener serves
HTTP/1.1 over TLS and forwards to one HTTP/HTTPS upstream. HTTPS certificate
validation uses native system roots unless a dedicated upstream CA bundle is
configured.

## Runtime controls and operations

- Request-body size, upstream response timeout, concurrent request count,
  active connection count, and a process-wide token-bucket rate limit are
  enforced. Rate limiting is per process, not shared across replicas.
- A separate, unauthenticated HTTP liveness listener must bind to loopback.
  It reports process/listener health only and deliberately does not indicate
  upstream availability.
- On Unix, `SIGHUP` reloads the client CA bundle after validating it and swaps
  the verifier used for new handshakes. Existing TLS connections are not
  revalidated. `SIGTERM` and Ctrl-C stop accepts and drain connections for up
  to 30 seconds.
- TLS handshake and HTTP header reads time out after 10 seconds. Automatic
  upstream retries and certificate revocation checks are not implemented.
