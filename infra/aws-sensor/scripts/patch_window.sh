#!/usr/bin/env bash
# Short, self-reverting OS patch window for the Attackarium sensor host (#94).
#
# The host nftables output policy blocks Ubuntu mirrors, so unattended-upgrades
# cannot refresh its package lists. This script opens HTTP (TCP/80) egress
# only to the IPv4 addresses that the configured apt mirrors resolve to,
# installs security updates, and then restores the on-disk firewall
# (/etc/nftables.conf), which never contains the temporary rule.
#
# Usage (as root, over an EICE operator session):
#   patch_window.sh resolve   # print mirror /32s for terraform patch_egress_cidrs
#   patch_window.sh run       # open, patch, close; detached from the SSH session
#   patch_window.sh install PKG=VERSION...  # same window, install/downgrade pinned packages
#   patch_window.sh cleanup   # force-restore the persisted firewall
#   patch_window.sh status    # show the last recorded result
#
# Safety properties:
#   - The temporary rule allows only TCP/80 to resolved mirror IPv4s, carries a
#     fixed comment tag, and lives only in memory (a reboot also removes it).
#   - Cleanup always runs: on exit, on signals, and from an independent
#     systemd timer if the patch unit is killed or hangs. Cleanup also ends any
#     TCP/80 connection to the window addresses, because the persisted ruleset
#     accepts established flows.
#   - Only one window runs at a time (flock).
#   - The run is a transient systemd unit, so an SSH or EICE tunnel drop
#     cannot interrupt dpkg halfway.
#   - apt verifies the signed InRelease files, so plain HTTP mirrors are fine.
set -euo pipefail

RULE_TAG="attackarium-patch-window"
UNIT_NAME="${PATCH_WINDOW_UNIT:-attackarium-patch-window}"
CLEANUP_UNIT="${UNIT_NAME}-cleanup"
STATE_DIR="${PATCH_WINDOW_STATE_DIR:-/var/lib/attackarium-patch}"
NFT_CONF="${PATCH_WINDOW_NFT_CONF:-/etc/nftables.conf}"
APT_SOURCES_DIR="${PATCH_WINDOW_APT_SOURCES_DIR:-/etc/apt}"
MAX_RUNTIME_SECONDS="${PATCH_WINDOW_MAX_RUNTIME_SECONDS:-2400}"
RESOLVE_ROUNDS="${PATCH_WINDOW_RESOLVE_ROUNDS:-5}"
MAX_MIRROR_ADDRESSES=32
SELF="$(readlink -f "$0")"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

require_root() {
  [[ "$(id -u)" == "0" ]] || die "must run as root"
}

# Hostnames from deb822 (*.sources) and one-line (*.list) apt sources. deb822
# URIs may list several values and continue on indented lines; stanzas with
# "Enabled: no" are skipped.
mirror_hosts() {
  local files=()
  shopt -s nullglob
  files+=("$APT_SOURCES_DIR"/sources.list "$APT_SOURCES_DIR"/sources.list.d/*.sources "$APT_SOURCES_DIR"/sources.list.d/*.list)
  shopt -u nullglob
  local f
  for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    if [[ "$f" == *.sources ]]; then
      awk '
        function flush() { if (enabled) for (i = 1; i <= n; i++) print uris[i]; n = 0; enabled = 1; inuris = 0 }
        BEGIN { enabled = 1; n = 0 }
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { flush(); next }
        /^[Ee]nabled:[[:space:]]*[Nn]o[[:space:]]*$/ { enabled = 0; inuris = 0; next }
        /^URIs:/ { inuris = 1; for (i = 2; i <= NF; i++) uris[++n] = $i; next }
        /^[[:space:]]/ { if (inuris) for (i = 1; i <= NF; i++) uris[++n] = $i; next }
        { inuris = 0 }
        END { flush() }
      ' "$f"
    else
      sed -E -n 's/^[[:space:]]*deb(-src)?[[:space:]]+(\[[^]]*\][[:space:]]+)?([^[:space:]]+).*/\3/p' "$f"
    fi
  done | grep -E '^https?://' | sed -E 's#^https?://##; s#[/:].*$##' | tr '[:upper:]' '[:lower:]' | sort -u
}

is_ipv4() {
  local ip="$1" octet
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for octet in "${BASH_REMATCH[@]:1}"; do
    (( 10#$octet <= 255 )) || return 1
  done
}

# Globally reachable unicast only: never open egress to private, loopback,
# link-local (instance metadata), CGNAT, IETF protocol assignments,
# documentation, benchmarking, multicast, or reserved ranges (IANA IPv4
# special-purpose registry).
is_public_ipv4() {
  local ip="$1"
  is_ipv4 "$ip" || return 1
  local a b c
  IFS=. read -r a b c _ <<<"$ip"
  a=$((10#$a)); b=$((10#$b)); c=$((10#$c))
  (( a == 0 || a == 10 || a == 127 || a >= 224 )) && return 1
  (( a == 169 && b == 254 )) && return 1
  (( a == 172 && b >= 16 && b <= 31 )) && return 1
  (( a == 192 && b == 168 )) && return 1
  (( a == 100 && b >= 64 && b <= 127 )) && return 1
  (( a == 192 && b == 0 && (c == 0 || c == 2) )) && return 1   # 192.0.0.0/24, 192.0.2.0/24
  (( a == 198 && (b == 18 || b == 19) )) && return 1           # 198.18.0.0/15
  (( a == 198 && b == 51 && c == 100 )) && return 1            # 198.51.100.0/24
  (( a == 203 && b == 0 && c == 113 )) && return 1             # 203.0.113.0/24
  return 0
}

# Union of several lookups through the VPC resolver, because mirrors rotate
# their A records.
resolve_mirrors() {
  local hosts host round addr
  hosts="$(mirror_hosts)"
  [[ -n "$hosts" ]] || die "no apt mirror hosts found under $APT_SOURCES_DIR"
  {
    for host in $hosts; do
      for ((round = 0; round < RESOLVE_ROUNDS; round++)); do
        getent ahostsv4 "$host" | awk '{print $1}' || true
      done
    done
  } | sort -u | while read -r addr; do
    if is_public_ipv4 "$addr"; then
      printf '%s\n' "$addr"
    else
      log "skipping non-public mirror address $addr" >&2
    fi
  done
}

patch_rule_present() {
  nft list chain inet attackarium output 2>/dev/null | grep -q "$RULE_TAG"
}

WINDOW_ADDRS_FILE="$STATE_DIR/window-addrs"

# The persisted ruleset accepts established flows, so removing the rule alone
# would let a TCP/80 connection opened during the window keep running.
end_window_flows() {
  [[ -f "$WINDOW_ADDRS_FILE" ]] || return 0
  local addr out leftover=""
  while read -r addr; do
    is_ipv4 "$addr" || continue
    # A failed kill is not fatal by itself; the query below decides.
    ss -K -tn dst "$addr" dport = :80 >/dev/null 2>&1 || true
    # Only a successful, empty query proves the flows are gone.
    if ! out="$(ss -Htn state established state syn-sent dst "$addr" dport = :80)"; then
      leftover+=" $addr(query-failed)"
    elif [[ -n "$out" ]]; then
      leftover+=" $addr"
    fi
  done <"$WINDOW_ADDRS_FILE"
  if [[ -n "$leftover" ]]; then
    log "ERROR: TCP/80 connections still open to:$leftover" >&2
    return 1
  fi
  rm -f "$WINDOW_ADDRS_FILE"
}

restore_firewall() {
  # The persisted ruleset never contains the patch rule; reloading it is the
  # single source of truth and also removes any partially added rule.
  # Returns non-zero instead of exiting, because it also runs inside the EXIT
  # trap, where the caller must still record the failure.
  if ! nft -f "$NFT_CONF"; then
    log "ERROR: nft -f $NFT_CONF failed" >&2
    return 1
  fi
  if patch_rule_present; then
    log "ERROR: temporary patch rule still present after restoring $NFT_CONF" >&2
    return 1
  fi
  end_window_flows || return 1
  log "firewall restored from $NFT_CONF (no temporary egress rule, no window flows)"
}

write_result() {
  local result="$1" detail="$2"
  install -d -m 0755 "$STATE_DIR"
  local tmp
  tmp="$(mktemp "$STATE_DIR/.result.XXXXXX")"
  {
    printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'result=%s\n' "$result"
    printf 'detail=%s\n' "$detail"
    if [[ -f /var/run/reboot-required ]]; then
      printf 'reboot_required=yes\n'
    else
      printf 'reboot_required=no\n'
    fi
  } >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$STATE_DIR/last-result"
  if [[ "$result" == "success" ]]; then
    cp -f "$STATE_DIR/last-result" "$STATE_DIR/last-success"
  fi
}

PACKAGE_PIN_RE='^[a-z0-9][a-z0-9+.-]*=[A-Za-z0-9.+~:-]+$'

inner_run() {
  local mode="$1"
  shift
  require_root
  # The process that changes the firewall and writes the status holds the
  # lock for its whole life (released only when it exits), so the automatic
  # update recorder can never interleave with it, even if the wrapper that
  # started this unit has died.
  install -d -m 0755 "$STATE_DIR"
  if command -v flock >/dev/null 2>&1; then
    exec 8>"$STATE_DIR/run.lock"
    flock -w 120 8 || die "could not acquire $STATE_DIR/run.lock"
  fi
  # Globals, not locals: the EXIT trap also fires after this function returns.
  status="failure"
  detail="started"
  finish() {
    local rc=$?
    trap - EXIT INT TERM HUP
    if ! restore_firewall; then
      # Keep the original reason; append the restore failure.
      status="failure"; detail="$detail; firewall restore failed; run: $SELF cleanup"
      rc=1
    fi
    write_result "$status" "$detail"
    log "patch window finished: result=$status ($detail)"
    exit "$rc"
  }
  trap finish EXIT
  trap 'detail="interrupted"; exit 1' INT TERM HUP

  # A previous window whose flows could not be verified must be cleaned up
  # first; otherwise overwriting window-addrs would stop tracking it.
  # restore_firewall reloads the persisted ruleset first, so a leftover rule
  # cannot re-admit a flow between the drain and the new window.
  if [[ -f "$WINDOW_ADDRS_FILE" ]] || patch_rule_present; then
    log "cleaning up a previous window before opening a new one"
    restore_firewall || { detail="previous window flows not cleaned up; run: $SELF cleanup"; exit 1; }
  fi

  local addrs
  addrs="$(resolve_mirrors)"
  [[ -n "$addrs" ]] || { detail="no public mirror addresses resolved"; exit 1; }
  local count
  count="$(wc -l <<<"$addrs" | tr -d ' ')"
  if (( count > MAX_MIRROR_ADDRESSES )); then
    detail="refusing to open egress to $count addresses (max $MAX_MIRROR_ADDRESSES)"
    exit 1
  fi
  local set_expr
  set_expr="$(paste -sd, - <<<"$addrs" | sed 's/,/, /g')"
  log "opening temporary TCP/80 egress to $count mirror address(es): $set_expr"
  install -d -m 0755 "$STATE_DIR"
  printf '%s\n' "$addrs" >"$WINDOW_ADDRS_FILE"
  nft insert rule inet attackarium output ip daddr "{ $set_expr }" tcp dport 80 accept comment "\"$RULE_TAG\""

  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
  detail="apt-get update failed"
  # Error-Mode=any: a partially failed refresh (for example a mirror address
  # outside the window) must fail instead of silently keeping stale lists.
  apt-get -o DPkg::Lock::Timeout=300 -o Acquire::Retries=3 -o Acquire::http::Timeout=30 \
    -o APT::Update::Error-Mode=any update
  if [[ "$mode" == "install" ]]; then
    detail="apt-get install failed"
    apt-get -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confold \
      -y --allow-downgrades install "$@"
    detail="installed: $*"
  else
    detail="unattended-upgrade failed"
    # Security origins only, with the host's existing unattended-upgrades policy
    # (it keeps modified conffiles such as /etc/nftables.conf).
    unattended-upgrade -v
    detail="security updates applied"
  fi
  status="success"
}

cmd_run() {
  local mode="$1"
  shift
  require_root
  if [[ "$mode" == "install" ]]; then
    (( $# > 0 )) || die "install needs at least one PKG=VERSION"
    local pin
    for pin in "$@"; do
      [[ "$pin" =~ $PACKAGE_PIN_RE ]] || die "invalid package pin: $pin (expected PKG=VERSION)"
    done
  fi
  if [[ "${PATCH_WINDOW_NO_DETACH:-0}" == "1" ]]; then
    inner_run "$mode" "$@"
    return
  fi
  # One window at a time. The patch unit itself holds run.lock (see
  # inner_run); here we only fail fast if a window or the recorder holds it,
  # and the fixed transient unit names make a second concurrent start fail.
  install -d -m 0755 "$STATE_DIR"
  exec 9>"$STATE_DIR/run.lock"
  flock -n 9 || die "another patch window (or the update recorder) holds the lock"
  exec 9>&-
  if systemctl is-active --quiet "$UNIT_NAME"; then
    die "$UNIT_NAME is already running"
  fi
  if systemctl is-active --quiet "$CLEANUP_UNIT.timer"; then
    die "a cleanup timer is still armed (another window, or a wrapper that died); wait for it or run: $SELF cleanup && systemctl stop $CLEANUP_UNIT.timer"
  fi
  # A stale result must never be read as this run's outcome.
  rm -f "$STATE_DIR/last-result"
  # Independent safety net: restore the firewall even if the patch unit is
  # killed or hangs past its runtime limit.
  systemd-run --unit="$CLEANUP_UNIT" --collect \
    --on-active="$((MAX_RUNTIME_SECONDS + 300))s" \
    "$SELF" cleanup >/dev/null
  systemd-run --unit="$UNIT_NAME" --collect --wait \
    --property=RuntimeMaxSec="$MAX_RUNTIME_SECONDS" \
    --setenv=PATCH_WINDOW_NO_DETACH=1 \
    "$SELF" "$mode" "$@" || true
  systemctl stop "$CLEANUP_UNIT.timer" 2>/dev/null || true
  # The unit's journal holds the full apt output.
  journalctl -u "$UNIT_NAME" --since "-$((MAX_RUNTIME_SECONDS / 60 + 5))min" --no-pager -o cat | tail -n 40 || true
  if patch_rule_present || [[ -f "$WINDOW_ADDRS_FILE" ]]; then
    log "temporary rule or window flows still present; restoring now"
    restore_firewall || die "firewall restore failed; run: $SELF cleanup"
  fi
  cmd_status
  grep -qs '^result=success$' "$STATE_DIR/last-result"
}

cmd_status() {
  if [[ -f "$STATE_DIR/last-result" ]]; then
    cat "$STATE_DIR/last-result"
  else
    echo "result=never-run"
  fi
  if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
    printf 'apt_lists_refreshed_at=%s\n' "$(date -u -r /var/lib/apt/periodic/update-success-stamp +%Y-%m-%dT%H:%M:%SZ)"
  fi
  if patch_rule_present; then
    echo "temporary_rule=PRESENT"
  else
    echo "temporary_rule=absent"
  fi
  if [[ -f "$WINDOW_ADDRS_FILE" ]]; then
    echo "window_flows=UNVERIFIED (run cleanup)"
  fi
}

main() {
  case "${1:-}" in
    resolve) resolve_mirrors | sed 's#$#/32#' ;;
    run) cmd_run run ;;
    install) shift; cmd_run install "$@" ;;
    cleanup) require_root; restore_firewall || exit 1 ;;
    status) cmd_status ;;
    *) echo "usage: $0 {resolve|run|install PKG=VERSION...|cleanup|status}" >&2; exit 2 ;;
  esac
}

main "$@"
