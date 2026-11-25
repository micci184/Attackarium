#!/usr/bin/env bash
# Record a verified automatic OS update for the operator console (ADR-027).
#
# Two phases, both wired into apt-daily-upgrade.service by
# apt-daily-upgrade-attackarium.conf:
#
#   refresh  (ExecStartPre)  Runs `apt-get update` with
#            APT::Update::Error-Mode "any" and records THIS attempt's outcome
#            (ok/failed) and time in $STATE_DIR/refresh-result. The exit status
#            is the evidence: apt's Post-Invoke-Success hooks (and the stamps
#            they touch) run even when some indexes failed, so stamps are not
#            used (verified on Ubuntu 24.04, apt 2.8.4).
#
#   record   (ExecStartPost) Writes $STATE_DIR/last-success (same file and
#            format as patch_window.sh; the shipper reports it) ONLY when:
#              - the latest refresh attempt succeeded,
#              - the latest unattended-upgrades run finished cleanly AFTER that
#                refresh (same invocation, within REFRESH_MAX_LEAD_SECONDS),
#              - and it is newer than the last recorded success.
#            The recorded time is the run's own logged completion time, so a
#            skipped invocation cannot advance the status. Otherwise the file
#            is left alone and /admin ages to Due/Overdue, which the weekly
#            freshness check reports.
set -euo pipefail

STATE_DIR="${OS_UPDATE_STATE_DIR:-/var/lib/attackarium-patch}"
UU_LOG="${OS_UPDATE_UU_LOG:-/var/log/unattended-upgrades/unattended-upgrades.log}"
REFRESH_RESULT="$STATE_DIR/refresh-result"
REFRESH_MAX_LEAD_SECONDS="${OS_UPDATE_REFRESH_MAX_LEAD_SECONDS:-21600}" # 6 hours
now_epoch() { printf '%s\n' "${OS_UPDATE_NOW:-$(date -u +%s)}"; }

log() { printf 'record_os_update_status: %s\n' "$*" >&2; }

# "YYYY-MM-DDTHH:MM:SSZ" -> epoch seconds (GNU date, then BSD date).
iso_to_epoch() {
  date -u -d "$1" +%s 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s
}

write_atomic() {
  local target="$1" tmp
  tmp="$(mktemp "$STATE_DIR/.$(basename "$target").XXXXXX")"
  cat >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$target"
}

cmd_refresh() {
  install -d -m 0755 "$STATE_DIR"
  local result="failed"
  if apt-get -q -o DPkg::Lock::Timeout=300 -o APT::Update::Error-Mode=any update; then
    result="ok"
  fi
  printf 'result=%s\nat=%s\n' "$result" "$(now_epoch)" | write_atomic "$REFRESH_RESULT"
  log "package list refresh: $result"
  # Never block the upgrade itself; the record phase decides.
  return 0
}

cmd_record() {
  if [[ ! -f "$REFRESH_RESULT" ]]; then
    log "no refresh attempt recorded; not marking success"
    return 1
  fi
  local refresh_result refresh_at
  refresh_result="$(sed -n 's/^result=//p' "$REFRESH_RESULT" | head -n 1)"
  refresh_at="$(sed -n 's/^at=//p' "$REFRESH_RESULT" | head -n 1)"
  if [[ "$refresh_result" != "ok" || ! "$refresh_at" =~ ^[0-9]+$ ]]; then
    log "latest package list refresh failed; not marking success"
    return 1
  fi

  if [[ ! -f "$UU_LOG" ]]; then
    log "no unattended-upgrades log; not marking success"
    return 1
  fi
  # Only the most recent run counts.
  local last_run completion finished_at finished_epoch
  last_run="$(awk '/Starting unattended upgrades script/ { buf = "" } { buf = buf $0 "\n" } END { printf "%s", buf }' "$UU_LOG")"
  if ! grep -q 'Starting unattended upgrades script' <<<"$last_run"; then
    log "no unattended-upgrades run found; not marking success"
    return 1
  fi
  if grep -q -E '(^| )(ERROR|CRITICAL)( |:)|Traceback' <<<"$last_run"; then
    log "last unattended-upgrades run reported errors; not marking success"
    return 1
  fi
  # A security update held back because a locally modified conffile needs a
  # prompt is NOT installed, although the run still logs a completion line.
  if grep -q -E 'conffile prompt|needs to be upgraded manually' <<<"$last_run"; then
    log "last unattended-upgrades run held back a package (conffile prompt); not marking success"
    return 1
  fi
  completion="$(grep -E 'All upgrades installed|No packages found that can be upgraded unattended' <<<"$last_run" | tail -n 1)"
  if [[ -z "$completion" ]]; then
    log "last unattended-upgrades run did not complete; not marking success"
    return 1
  fi
  # Log lines start with "YYYY-MM-DD HH:MM:SS,mmm" in host time (UTC).
  if [[ ! "$completion" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2})\ ([0-9]{2}:[0-9]{2}:[0-9]{2}) ]]; then
    log "unexpected unattended-upgrades log format; not marking success"
    return 1
  fi
  finished_at="${BASH_REMATCH[1]}T${BASH_REMATCH[2]}Z"
  finished_epoch="$(iso_to_epoch "$finished_at")"

  # The run must belong to this invocation: after the successful refresh, and
  # not long after it.
  if (( finished_epoch < refresh_at || finished_epoch - refresh_at > REFRESH_MAX_LEAD_SECONDS )); then
    log "latest upgrade run does not follow the latest refresh; not marking success"
    return 1
  fi

  install -d -m 0755 "$STATE_DIR"
  # Serialize with the manual patch window (patch_window.sh holds the same
  # lock for its whole run), so the read-compare-replace below cannot
  # overwrite a newer manual result. If a window is running, skip.
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$STATE_DIR/run.lock"
    if ! flock -w "${OS_UPDATE_LOCK_WAIT_SECONDS:-60}" 9; then
      log "a patch window holds the lock; leaving status unchanged"
      return 0
    fi
  fi

  # Never move the status backwards (for example after a newer manual window).
  if [[ -f "$STATE_DIR/last-success" ]]; then
    local previous
    previous="$(sed -n 's/^finished_at=//p' "$STATE_DIR/last-success" | head -n 1)"
    if [[ -n "$previous" && ! "$finished_at" > "$previous" ]]; then
      log "no newer completed run since $previous; leaving status unchanged"
      return 0
    fi
  fi

  {
    printf 'finished_at=%s\n' "$finished_at"
    printf 'result=success\n'
    printf 'detail=unattended-upgrades\n'
    if [[ -f /var/run/reboot-required ]]; then
      printf 'reboot_required=yes\n'
    else
      printf 'reboot_required=no\n'
    fi
  } | write_atomic "$STATE_DIR/last-success"
  log "recorded successful automatic update run ($finished_at)"
}

case "${1:-record}" in
  refresh) cmd_refresh ;;
  record) cmd_record ;;
  *) echo "usage: $0 {refresh|record}" >&2; exit 2 ;;
esac
