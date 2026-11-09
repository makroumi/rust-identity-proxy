#!/usr/bin/env bash
# Exercise the compiled proxy against a local echo upstream with real mTLS.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

for tool in cargo curl openssl python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Error: required command not found: $tool" >&2
    exit 1
  fi
done

TMP_DIR=$(mktemp -d)
PROXY_PID=""
UPSTREAM_PID=""

cleanup() {
  local status=$?
  if [[ -n "$PROXY_PID" ]]; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [[ -n "$UPSTREAM_PID" ]]; then
    kill "$UPSTREAM_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
  fi
  rm -rf -- "$TMP_DIR"
  exit "$status"
}
trap cleanup EXIT

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

PROXY_PORT=$(free_port)
HEALTH_PORT=$(free_port)
UPSTREAM_PORT=$(free_port)
CERT_DIR="$TMP_DIR/certs"

scripts/gen-certs.sh "$CERT_DIR" >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
  -keyout "$TMP_DIR/untrusted-ca.key" -out "$TMP_DIR/untrusted-ca.crt" \
  -subj "/CN=Untrusted E2E CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$TMP_DIR/untrusted-client.key" -out "$TMP_DIR/untrusted-client.csr" \
  -subj "/CN=agent-42/O=Arkion" >/dev/null 2>&1
openssl x509 -req -in "$TMP_DIR/untrusted-client.csr" \
  -CA "$TMP_DIR/untrusted-ca.crt" -CAkey "$TMP_DIR/untrusted-ca.key" \
  -CAcreateserial -out "$TMP_DIR/untrusted-client.crt" -days 1 -sha256 \
  -extfile <(printf '%s\n' "extendedKeyUsage=clientAuth") >/dev/null 2>&1

python3 -u - "$UPSTREAM_PORT" "$CERT_DIR/server.crt" "$CERT_DIR/server.key" \
  >"$TMP_DIR/upstream.log" 2>&1 <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ssl
import sys

class Handler(BaseHTTPRequestHandler):
    def respond(self):
        body = json.dumps({
            "method": self.command,
            "path": self.path,
            "forwarded_for": self.headers.get("X-Forwarded-For"),
            "forwarded_host": self.headers.get("X-Forwarded-Host"),
            "private_header": self.headers.get("X-Private"),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = respond
    do_POST = respond

    def log_message(self, _format, *_args):
        pass

server = HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
UPSTREAM_PID=$!

upstream_ready=false
for _ in $(seq 1 50); do
  if python3 - "$UPSTREAM_PORT" >/dev/null 2>&1 <<'PY'
import socket
import sys

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
    pass
PY
  then
    upstream_ready=true
    break
  fi
  if ! kill -0 "$UPSTREAM_PID" 2>/dev/null; then
    echo "Error: echo upstream exited before becoming ready" >&2
    cat "$TMP_DIR/upstream.log" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$upstream_ready" != true ]]; then
  echo "Error: echo upstream did not become ready" >&2
  cat "$TMP_DIR/upstream.log" >&2
  exit 1
fi

cat >"$TMP_DIR/proxy.toml" <<EOF
[server]
listen_addr = "127.0.0.1:$PROXY_PORT"
health_addr = "127.0.0.1:$HEALTH_PORT"
upstream_url = "https://localhost:$UPSTREAM_PORT"

[tls]
server_cert = "$CERT_DIR/server.crt"
server_key = "$CERT_DIR/server.key"
upstream_ca = "$CERT_DIR/ca.crt"

[policy]
policy_file = "$ROOT/config/policies.yaml"

[limits]
max_body_bytes = 10485760
request_timeout_secs = 30
max_concurrency = 1000
rate_limit_rps = 5000
rate_limit_burst = 10000
max_connections = 128

[trust]
ca_bundle_path = "$CERT_DIR/ca.crt"
EOF

cargo build --locked -p proxy-server --bin identity-proxy
RUST_LOG=info target/debug/identity-proxy --config "$TMP_DIR/proxy.toml" \
  >"$TMP_DIR/proxy.log" 2>&1 &
PROXY_PID=$!

BASE_URL="https://localhost:$PROXY_PORT"
CURL_COMMON=(--resolve "localhost:$PROXY_PORT:127.0.0.1" --cacert "$CERT_DIR/ca.crt")
AGENT_CERT=(--cert "$CERT_DIR/client.crt" --key "$CERT_DIR/client.key")

ready=false
for _ in $(seq 1 50); do
  if curl --silent "${CURL_COMMON[@]}" "${AGENT_CERT[@]}" "$BASE_URL/health" \
      >/dev/null 2>&1; then
    ready=true
    break
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "Error: proxy exited before becoming ready" >&2
    cat "$TMP_DIR/proxy.log" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  echo "Error: proxy did not become ready" >&2
  cat "$TMP_DIR/proxy.log" >&2
  exit 1
fi
target/debug/identity-proxy --config "$TMP_DIR/proxy.toml" --healthcheck
echo "PASS: standalone loopback healthcheck"

AGENT_RESPONSE=$(curl --fail --silent --show-error "${CURL_COMMON[@]}" \
  "${AGENT_CERT[@]}" -H "Connection: X-Private" \
  -H "X-Private: must-not-forward" "$BASE_URL/api/v1/identity/self?probe=1")
printf '%s' "$AGENT_RESPONSE" | python3 -c '
import json, sys
actual = json.load(sys.stdin)
expected = {
    "method": "GET",
    "path": "/api/v1/identity/self?probe=1",
    "forwarded_for": "127.0.0.1",
    "forwarded_host": "localhost:'"$PROXY_PORT"'",
    "private_header": None,
}
assert actual == expected, (actual, expected)
'
echo "PASS: agent GET is authorized and forwarded with sanitized headers"

NORMALIZED_RESPONSE=$(curl --fail --silent --show-error --path-as-is \
  "${CURL_COMMON[@]}" "${AGENT_CERT[@]}" \
  "$BASE_URL/api/v1//identity/self?probe=normalized")
printf '%s' "$NORMALIZED_RESPONSE" | python3 -c '
import json, sys
actual = json.load(sys.stdin)
assert actual["path"] == "/api/v1/identity/self?probe=normalized", actual
'
echo "PASS: normalized paths are also normalized before upstream forwarding"

POST_RESPONSE=$(curl --fail --silent --show-error "${CURL_COMMON[@]}" \
  "${AGENT_CERT[@]}" -X POST -d '{"ok":true}' \
  "$BASE_URL/api/v1/credentials/short-lived")
printf '%s' "$POST_RESPONSE" | python3 -c \
  'import json, sys; assert json.load(sys.stdin)["method"] == "POST"'
echo "PASS: agent POST is authorized and forwarded"

ADMIN_STATUS=$(curl --path-as-is --silent --output /dev/null \
  --write-out '%{http_code}' "${CURL_COMMON[@]}" \
  --cert "$CERT_DIR/admin.crt" --key "$CERT_DIR/admin.key" \
  "$BASE_URL/admin/users")
if [[ "$ADMIN_STATUS" != 403 ]]; then
  echo "Error: expected 403 for unconfigured admin identity, got $ADMIN_STATUS" >&2
  exit 1
fi
echo "PASS: broad CN=admin access is denied by default"

for denied_path in \
  "/admin/users" \
  "/api/v1/identity/%2e%2e/%2E%2e/admin/secret"; do
  status=$(curl --path-as-is --silent --output /dev/null \
    --write-out '%{http_code}' "${CURL_COMMON[@]}" "${AGENT_CERT[@]}" \
    "$BASE_URL$denied_path")
  if [[ "$status" != 403 ]]; then
    echo "Error: expected 403 for $denied_path, got $status" >&2
    exit 1
  fi
done
echo "PASS: policy and encoded-traversal requests are denied"

HEALTH=$(curl --fail --silent --show-error "${CURL_COMMON[@]}" \
  "${AGENT_CERT[@]}" "$BASE_URL/health")
if [[ "$HEALTH" != "ok" ]]; then
  echo "Error: unexpected health response: $HEALTH" >&2
  exit 1
fi
echo "PASS: health endpoint"

if curl --silent "${CURL_COMMON[@]}" "$BASE_URL/health" >/dev/null 2>&1; then
  echo "Error: server accepted a connection without a client certificate" >&2
  exit 1
fi
if curl --silent "${CURL_COMMON[@]}" \
    --cert "$TMP_DIR/untrusted-client.crt" \
    --key "$TMP_DIR/untrusted-client.key" "$BASE_URL/health" >/dev/null 2>&1; then
  echo "Error: server accepted a client certificate from an untrusted CA" >&2
  exit 1
fi
echo "PASS: mTLS rejects missing and untrusted client certificates"

if ! grep -q 'Deny' "$TMP_DIR/proxy.log"; then
  echo "Error: denied requests were not recorded in audit events" >&2
  exit 1
fi
if ! grep -q 'spiffe://arkion.internal/agent/42' "$TMP_DIR/proxy.log" \
    || ! grep -q 'CN=admin' "$TMP_DIR/proxy.log"; then
  echo "Error: expected agent and admin identities were not audited" >&2
  exit 1
fi
echo "PASS: audit events include identities and policy decisions"

openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
  -keyout "$TMP_DIR/reload-ca.key" -out "$TMP_DIR/reload-ca.crt" \
  -subj "/CN=Reloaded E2E CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$TMP_DIR/reloaded-client.key" -out "$TMP_DIR/reloaded-client.csr" \
  -subj "/CN=agent-reloaded/O=Arkion" >/dev/null 2>&1
openssl x509 -req -in "$TMP_DIR/reloaded-client.csr" \
  -CA "$TMP_DIR/reload-ca.crt" -CAkey "$TMP_DIR/reload-ca.key" \
  -CAcreateserial -out "$TMP_DIR/reloaded-client.crt" -days 1 -sha256 \
  -extfile <(printf '%s\n' \
    "extendedKeyUsage=clientAuth" \
    "subjectAltName=URI:spiffe://arkion.internal/agent/43") >/dev/null 2>&1
cat "$TMP_DIR/reload-ca.crt" >> "$CERT_DIR/ca.crt"
kill -HUP "$PROXY_PID"

reloaded=false
for _ in $(seq 1 50); do
  if grep -q 'client CA trust reloaded for new TLS handshakes' "$TMP_DIR/proxy.log"; then
    reloaded=true
    break
  fi
  sleep 0.1
done
if [[ "$reloaded" != true ]]; then
  echo "Error: proxy did not report successful trust reload" >&2
  cat "$TMP_DIR/proxy.log" >&2
  exit 1
fi
curl --fail --silent --show-error "${CURL_COMMON[@]}" \
  --cert "$TMP_DIR/reloaded-client.crt" --key "$TMP_DIR/reloaded-client.key" \
  "$BASE_URL/api/v1/identity/self" >/dev/null
echo "PASS: SIGHUP reloads client trust for new TLS handshakes"

cp "$CERT_DIR/ca.crt" "$TMP_DIR/curl-ca.crt"
CURL_COMMON=(--resolve "localhost:$PROXY_PORT:127.0.0.1" --cacert "$TMP_DIR/curl-ca.crt")
printf 'invalid trust bundle\n' > "$CERT_DIR/ca.crt"
kill -HUP "$PROXY_PID"

reload_rejected=false
for _ in $(seq 1 50); do
  if grep -q 'client CA trust reload failed' "$TMP_DIR/proxy.log"; then
    reload_rejected=true
    break
  fi
  sleep 0.1
done
if [[ "$reload_rejected" != true ]]; then
  echo "Error: proxy did not report rejection of the invalid trust bundle" >&2
  cat "$TMP_DIR/proxy.log" >&2
  exit 1
fi
curl --fail --silent --show-error "${CURL_COMMON[@]}" \
  "${AGENT_CERT[@]}" "$BASE_URL/api/v1/identity/self" >/dev/null
echo "PASS: invalid trust reload retains the active trust set"

kill -TERM "$PROXY_PID"
wait "$PROXY_PID"
PROXY_PID=""
if ! grep -q 'proxy shut down cleanly' "$TMP_DIR/proxy.log"; then
  echo "Error: proxy did not report a clean SIGTERM shutdown" >&2
  cat "$TMP_DIR/proxy.log" >&2
  exit 1
fi
echo "PASS: SIGTERM stops the listener and drains active connections"
