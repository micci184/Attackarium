#!/usr/bin/env bash
# Generate the per-sensor self-signed certificate for the HTTPS collector (#93 R7).
#
# Run ON THE SENSOR HOST (or in a test with a temp directory). The private key
# never leaves the host: it must not be copied into Git, images, Terraform
# state, or logs. Rotation is regeneration (--force) plus a collector restart.
#
# - ECDSA P-256, SHA-256, 10-year validity (typical for appliance self-signed
#   certificates; scanners that sweep IPs do not validate certificates).
# - Subject and SAN are a generic "localhost", as many real devices ship.
#   Never name Attackarium, OpenCanary, or a honeypot here (#88).
# - Keys are generated per sensor, so sensors cannot be linked by a shared
#   certificate fingerprint in Internet-wide scan indexes.
#
# Usage: generate_tls_cert.sh [--dir DIR] [--owner USER] [--force]
#   defaults: --dir /etc/attackarium/tls --owner attackarium
set -euo pipefail

DIR=/etc/attackarium/tls
OWNER=attackarium
FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) DIR="${2:?--dir needs a value}"; shift 2 ;;
    --owner) OWNER="${2:?--owner needs a value}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

CERT="$DIR/cert.pem"
KEY="$DIR/key.pem"
if [[ $FORCE -eq 0 && ( -e "$CERT" || -e "$KEY" ) ]]; then
  echo "certificate or key already exists in $DIR (use --force to regenerate)" >&2
  exit 1
fi

umask 077
mkdir -p "$DIR"
chmod 0700 "$DIR"
TMP="$(mktemp -d "$DIR/.gen.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

openssl req -x509 -new -sha256 -days 3650 -nodes \
  -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -keyout "$TMP/key.pem" -out "$TMP/cert.pem" 2>/dev/null

chmod 0600 "$TMP/key.pem"
chmod 0644 "$TMP/cert.pem"
if [[ "$(id -u)" -eq 0 ]]; then
  chown "$OWNER:$OWNER" "$DIR" "$TMP/key.pem" "$TMP/cert.pem"
fi
mv -f "$TMP/key.pem" "$KEY"
mv -f "$TMP/cert.pem" "$CERT"

# Print only public, non-secret facts.
openssl x509 -in "$CERT" -noout -subject -enddate -fingerprint -sha256
