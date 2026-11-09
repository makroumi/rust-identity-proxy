#!/usr/bin/env bash
# Generate test-only CA, server, and client certificates for local development.
set -euo pipefail
umask 077

OUT="${1:-config/certs}"
mkdir -p "$OUT"

echo "==> Generating test CA..."
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
  -subj "/CN=Arkion Test CA/O=Arkion Identity Systems" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "==> Generating localhost server certificate..."
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$OUT/server.key" -out "$OUT/server.csr" \
  -subj "/CN=localhost/O=Arkion"
openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/server.crt" -days 365 -sha256 \
  -extfile <(printf '%s\n' \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth" \
    "subjectAltName=DNS:localhost,IP:127.0.0.1")

echo "==> Generating agent client certificate..."
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$OUT/client.key" -out "$OUT/client.csr" \
  -subj "/CN=agent-42/O=Arkion"
openssl x509 -req -in "$OUT/client.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/client.crt" -days 365 -sha256 \
  -extfile <(printf '%s\n' \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=clientAuth" \
    "subjectAltName=URI:spiffe://arkion.internal/agent/42")

echo "==> Generating admin client certificate..."
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$OUT/admin.key" -out "$OUT/admin.csr" \
  -subj "/CN=admin/O=Arkion"
openssl x509 -req -in "$OUT/admin.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -CAcreateserial -out "$OUT/admin.crt" -days 365 -sha256 \
  -extfile <(printf '%s\n' \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=clientAuth")

rm -f "$OUT"/*.csr "$OUT"/*.srl
echo "==> Test certificates generated in $OUT/"
echo "==> Do not use these certificates or keys in production."
