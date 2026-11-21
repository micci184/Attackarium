#!/usr/bin/env bash
# Verify layered egress isolation on the Attackarium sensor host.
# Expected result:
#   1. Arbitrary external IPs are blocked (exit non-zero / timeout).
#   2. IMDSv1 (without token) is rejected with HTTP 401.
#   3. Approved Supabase ingest HTTPS endpoint is reachable when INGEST_HEALTH_URL is set.
set -euo pipefail

BLOCKED_TARGETS=(
  "https://1.1.1.1"
  "http://93.184.216.34"
)

echo "[1/3] Checking that arbitrary external egress is blocked..."
for target in "${BLOCKED_TARGETS[@]}"; do
  if curl --silent --show-error --max-time 3 --head "$target" >/dev/null 2>&1; then
    echo "FAIL: unexpected outbound connectivity succeeded to $target" >&2
    exit 1
  fi
  echo "PASS: blocked outbound connection to $target"
done

echo "[2/3] Checking that IMDSv1 is disabled (401 expected)..."
imds_status="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 http://169.254.169.254/latest/meta-data/ || true)"
if [[ "$imds_status" != "401" && "$imds_status" != "000" ]]; then
  echo "FAIL: IMDSv1 returned unexpected HTTP status $imds_status" >&2
  exit 1
fi
echo "PASS: IMDSv1 rejected (status=$imds_status)"

if [[ -n "${INGEST_HEALTH_URL:-}" ]]; then
  echo "[3/3] Checking approved ingest HTTPS reachability..."
  code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 "$INGEST_HEALTH_URL")"
  if [[ "$code" == "000" ]]; then
    echo "FAIL: could not reach approved ingest endpoint $INGEST_HEALTH_URL" >&2
    exit 1
  fi
  echo "PASS: approved ingest endpoint responded (HTTP $code)"
else
  echo "[3/3] Skipped approved ingest check (set INGEST_HEALTH_URL to verify)."
fi

echo "ALL EGRESS ISOLATION CHECKS PASSED"
