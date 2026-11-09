#!/usr/bin/env bash
# Add a CA certificate to the configured trust bundle.
set -euo pipefail

BUNDLE="${1:-config/certs/ca.crt}"
NEW_CA="${2:-config/certs/new-ca.crt}"

if [[ ! -f "$BUNDLE" ]]; then
  echo "Error: trust bundle not found at $BUNDLE" >&2
  exit 1
fi
if [[ ! -f "$NEW_CA" ]]; then
  echo "Error: new CA certificate not found at $NEW_CA" >&2
  exit 1
fi
if ! openssl x509 -in "$NEW_CA" -noout >/dev/null 2>&1; then
  echo "Error: invalid PEM certificate at $NEW_CA" >&2
  exit 1
fi

TMP=$(mktemp "${BUNDLE}.XXXXXX")
trap 'rm -f "$TMP"' EXIT
cp "$BUNDLE" "$TMP"
printf '\n' >> "$TMP"
cat "$NEW_CA" >> "$TMP"
chmod --reference="$BUNDLE" "$TMP"
mv "$TMP" "$BUNDLE"
trap - EXIT

echo "Trust bundle updated at $BUNDLE."
echo "The running server currently loads its TLS trust store at startup; restart it to apply the change."
