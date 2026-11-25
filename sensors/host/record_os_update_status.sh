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
#
# The recorded time is the completion time logged by that unattended-upgrades
# run, not "now": a skipped apt-daily-upgrade invocation re-reads the same old
# run and cannot advance the status. The stamp is trustworthy because
# 52attackarium-unattended-upgrades sets APT::Update::Error-Mode "any".
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
completion="$(grep -E 'All upgrades installed|No packages found that can be upgraded unattended' <<<"$last_run" | tail -n 1)"
if [[ -z "$completion" ]]; then
  log "last unattended-upgrades run did not complete; not marking success"
  exit 1
fi
# Log lines start with "YYYY-MM-DD HH:MM:SS,mmm" in host time (UTC).
if [[ ! "$completion" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2})\ ([0-9]{2}:[0-9]{2}:[0-9]{2}) ]]; then
  log "unexpected unattended-upgrades log format; not marking success"
  exit 1
fi
finished_at="${BASH_REMATCH[1]}T${BASH_REMATCH[2]}Z"

# Serialize with the manual patch window (patch_window.sh holds the same lock
# for its whole run), so the read-compare-replace below cannot overwrite a
# newer manual result. If a window is running, skip: the next daily run
# records again.
install -d -m 0755 "$STATE_DIR"
if command -v flock >/dev/null 2>&1; then
  exec 9>"$STATE_DIR/run.lock"
  if ! flock -w "${OS_UPDATE_LOCK_WAIT_SECONDS:-60}" 9; then
    log "a patch window holds the lock; leaving status unchanged"
    exit 0
  fi
fi

# Never move the status backwards (for example after a newer manual window).
if [[ -f "$STATE_DIR/last-success" ]]; then
  previous="$(sed -n 's/^finished_at=//p' "$STATE_DIR/last-success" | head -n 1)"
  if [[ -n "$previous" && ! "$finished_at" > "$previous" ]]; then
    log "no newer completed run since $previous; leaving status unchanged"
    exit 0
  fi
fi

tmp="$(mktemp "$STATE_DIR/.last-success.XXXXXX")"
{
  printf 'finished_at=%s\n' "$finished_at"
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
