#!/usr/bin/env bash
# Send sequential mTLS requests to the proxy and report approximate throughput.
set -euo pipefail

URL="${1:-https://localhost:8443/health}"
CERT="${2:-config/certs/client.crt}"
KEY="${3:-config/certs/client.key}"
CA="${4:-config/certs/ca.crt}"
REQUESTS="${5:-1000}"

if [[ ! "$REQUESTS" =~ ^[1-9][0-9]*$ ]]; then
  echo "Error: request count must be a positive integer" >&2
  exit 2
fi

echo "==> Sending $REQUESTS requests to $URL"
START=$(date +%s%N)
for ((i = 1; i <= REQUESTS; i++)); do
  curl --fail --silent --show-error --output /dev/null \
    --cert "$CERT" --key "$KEY" --cacert "$CA" "$URL"
done
END=$(date +%s%N)
ELAPSED_MS=$(((END - START) / 1000000))
if (( ELAPSED_MS == 0 )); then
  ELAPSED_MS=1
fi
RPS=$(awk -v requests="$REQUESTS" -v elapsed="$ELAPSED_MS" \
  'BEGIN { printf "%.1f", requests * 1000 / elapsed }')
echo "==> Completed $REQUESTS requests in ${ELAPSED_MS}ms (~${RPS} req/s)"
