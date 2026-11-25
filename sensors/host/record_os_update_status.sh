#!/usr/bin/env bash
# Record a successful automatic OS update run for the operator console (ADR-027).
#
# Runs as ExecStartPost of apt-daily-upgrade.service. It writes
# /var/lib/attackarium-patch/last-success (the same file and format as
# patch_window.sh), which the shipper reports as sensor_status. It writes ONLY
# when the evidence says the host is up to date:
#   - the package lists were refreshed recently (update-success-stamp), and
#   - the latest unattended-upgrades run finished cleanly.
# Otherwise it leaves the file alone, so /admin ages to Due/Overdue and the
# weekly freshness check fails loudly instead of showing a stale "Current".
set -euo pipefail

STATE_DIR="${OS_UPDATE_STATE_DIR:-/var/lib/attackarium-patch}"
STAMP="${OS_UPDATE_LIST_STAMP:-/var/lib/apt/periodic/update-success-stamp}"
UU_LOG="${OS_UPDATE_UU_LOG:-/var/log/unattended-upgrades/unattended-upgrades.log}"
MAX_LIST_AGE_SECONDS="${OS_UPDATE_MAX_LIST_AGE_SECONDS:-93600}" # 26 hours
NOW="${OS_UPDATE_NOW:-$(date -u +%s)}"

log() { printf 'record_os_update_status: %s\n' "$*" >&2; }

file_mtime() {
  stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"
}

if [[ ! -f "$STAMP" ]]; then
  log "no successful package list refresh recorded; not marking success"
  exit 1
fi
list_age=$(( NOW - $(file_mtime "$STAMP") ))
if (( list_age > MAX_LIST_AGE_SECONDS )); then
  log "package lists are stale (${list_age}s old); not marking success"
  exit 1
fi

if [[ ! -f "$UU_LOG" ]]; then
  log "no unattended-upgrades log; not marking success"
  exit 1
fi
# Only the most recent run counts.
last_run="$(awk '/Starting unattended upgrades script/ { buf = "" } { buf = buf $0 "\n" } END { printf "%s", buf }' "$UU_LOG")"
if ! grep -q 'Starting unattended upgrades script' <<<"$last_run"; then
  log "no unattended-upgrades run found; not marking success"
  exit 1
fi
if grep -q -E '(^| )(ERROR|CRITICAL)( |:)|Traceback' <<<"$last_run"; then
  log "last unattended-upgrades run reported errors; not marking success"
  exit 1
fi
if ! grep -q -E 'All upgrades installed|No packages found that can be upgraded unattended' <<<"$last_run"; then
  log "last unattended-upgrades run did not complete; not marking success"
  exit 1
fi

install -d -m 0755 "$STATE_DIR"
tmp="$(mktemp "$STATE_DIR/.last-success.XXXXXX")"
{
  printf 'finished_at=%s\n' "$(date -u -d "@$NOW" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$NOW" +%Y-%m-%dT%H:%M:%SZ)"
  printf 'result=success\n'
  printf 'detail=unattended-upgrades\n'
  if [[ -f /var/run/reboot-required ]]; then
    printf 'reboot_required=yes\n'
  else
    printf 'reboot_required=no\n'
  fi
} >"$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$STATE_DIR/last-success"
log "recorded successful automatic update run"
