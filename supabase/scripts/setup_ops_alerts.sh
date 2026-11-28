#!/usr/bin/env bash
# Configure the pg_cron -> ops-alerts Edge Function -> Slack alerts (#32).
#
# Run by the OPERATOR on their own machine (Supabase CLI logged in). Secrets are
# read from the terminal without echo, written only to a 0600 temp directory
# that is deleted on exit, and never printed or passed on a command line.
#
# Sets:
#   Edge Function secrets: SLACK_WEBHOOK_URL (unless --keep-slack),
#                          OPS_ALERTS_CRON_SECRET (new random value)
#   Vault secrets:         ops_alerts_cron_secret (same value),
#                          ops_alerts_function_url
#
# Running it is the operator's approval: both hosted changes pass --yes (CLI v3
# cannot prompt while output is hidden).
#
# Usage: supabase/scripts/setup_ops_alerts.sh [--project-ref REF] [--keep-slack]
set -euo pipefail

REF=""
KEEP_SLACK=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-ref) REF="${2:?--project-ref needs a value}"; shift 2 ;;
    --keep-slack) KEEP_SLACK=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [[ -z "$REF" && -f "$ROOT/supabase/.temp/project-ref" ]]; then
  REF="$(tr -d '[:space:]' < "$ROOT/supabase/.temp/project-ref")"
fi
[[ "$REF" =~ ^[a-z0-9]{20}$ ]] || { echo "project ref not found; pass --project-ref" >&2; exit 2; }
command -v supabase >/dev/null || { echo "supabase CLI is required" >&2; exit 2; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 2; }

TMP="$(mktemp -d)"
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT
umask 077

{
  if [[ $KEEP_SLACK -eq 0 ]]; then
    read -rsp "Slack incoming webhook URL (input hidden): " SLACK_URL
    echo
    [[ "$SLACK_URL" =~ ^https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+$ ]] \
      || { echo "not a Slack incoming webhook URL" >&2; exit 2; }
    printf 'SLACK_WEBHOOK_URL=%s\n' "$SLACK_URL"
    unset SLACK_URL
  fi
  CRON_SECRET="$(openssl rand -hex 32)"
  printf 'OPS_ALERTS_CRON_SECRET=%s\n' "$CRON_SECRET"
} > "$TMP/functions.env"

FUNCTION_URL="https://${REF}.supabase.co/functions/v1/ops-alerts"
# Values are hex / a fixed URL pattern, so they cannot break the SQL literal.
cat > "$TMP/vault.sql" <<SQL
do \$\$
declare
  v_id uuid;
begin
  select id into v_id from vault.secrets where name = 'ops_alerts_cron_secret';
  if v_id is null then
    perform vault.create_secret('${CRON_SECRET}', 'ops_alerts_cron_secret', 'ops-alerts pg_cron Bearer secret (#32)');
  else
    perform vault.update_secret(v_id, '${CRON_SECRET}');
  end if;
  select id into v_id from vault.secrets where name = 'ops_alerts_function_url';
  if v_id is null then
    perform vault.create_secret('${FUNCTION_URL}', 'ops_alerts_function_url', 'ops-alerts Edge Function URL (#32)');
  else
    perform vault.update_secret(v_id, '${FUNCTION_URL}');
  end if;
end
\$\$;
SQL
unset CRON_SECRET

echo "Setting Edge Function secrets on ${REF} ..."
supabase secrets set --remote="$REF" --env-file "$TMP/functions.env" --yes >/dev/null
echo "Storing the cron secret and function URL in Vault ..."
supabase db query --remote="$REF" -f "$TMP/vault.sql" --yes >/dev/null
echo "Done. Values were not printed. Verify with: supabase secrets list --remote=${REF}"
