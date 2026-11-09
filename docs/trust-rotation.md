# Trust store rotation

## Current behavior

The `proxy-trust` crate wraps a `rustls::RootCertStore` in `ArcSwap` and
validates a replacement bundle before atomically publishing it. Failed or
empty replacements leave the existing in-memory store untouched.

On Unix, send `SIGHUP` after updating the bundle. The server validates the
replacement and atomically installs a new TLS verifier for subsequent
handshakes. Invalid or empty bundles leave the active trust set unchanged.
Existing TLS connections keep the trust decision made when they connected.
On platforms without SIGHUP support, restart the proxy to load the updated
bundle.

## Local bundle update

Generate or obtain a new CA certificate, then append it to the bundle:

```bash
./scripts/rotate-trust.sh config/certs/ca.crt config/certs/new-ca.crt
```

The script validates that the new file is a PEM X.509 certificate and updates
the bundle through a temporary file. Back up the current bundle before changing
trust roots in any non-test environment. Then signal the process:

```bash
kill -HUP <proxy-pid>
```

For a container, send the signal to the container with your runtime's equivalent
(for example `docker kill --signal HUP <container>`). To remove a retired CA,
replace the bundle with the desired roots before reloading; appending only adds
trust.

## Operational cautions

Use an atomic file replacement when rotating a bundle so the process never
reads a partially written file. Reload failure is logged and the previous TLS
verifier remains active. Monitor the structured logs for successful reload
confirmation before assuming a rotation took effect.
