#!/usr/bin/env bash
# One-command operator wrapper for the sensor OS patch window (#94).
#
# Runs from the operator's machine (Terraform state, AWS credentials, and the
# operator SSH key). It never runs unattended: every run is an explicit
# operator decision. Steps:
#   1. Preflight: tools, AWS identity, `patch_egress_cidrs` empty, no drift.
#   2. Pre-patch root-volume snapshot (tagged DeleteAfter = today + 7 days).
#   3. Install patch_window.sh and verify_egress.sh on the host over EICE.
#   4. Resolve mirror /32s on the host.
#   5. Open: Terraform apply targeted at the patch_http rules only.
#   6. Patch: `patch_window.sh run` on the host.
#   7. Close: targeted apply with an empty list. This ALWAYS runs once step 5
#      has started, including on errors and Ctrl-C, and is then verified with a
#      full `terraform plan` (no changes).
#   8. Verify the host (no temporary rule, egress lockdown, services active),
#      reboot if the host asks for it, and verify again.
#   9. List expired pre-patch snapshots (delete only with --delete-expired-snapshots).
#
# Usage:
#   infra/aws-sensor/scripts/patch_sensor.sh --key ~/.ssh/<operator-key> [--yes]
#       [--reboot auto|never] [--delete-expired-snapshots]
#
#   --yes    Apply the targeted Terraform open without an interactive prompt.
#            The close step never prompts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TF_DIR="${PATCH_SENSOR_TF_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
TARGET='aws_vpc_security_group_egress_rule.patch_http'
SNAPSHOT_RETENTION_DAYS=7
REBOOT_WAIT_SECONDS="${PATCH_SENSOR_REBOOT_WAIT_SECONDS:-300}"
SLEEP_SECONDS="${PATCH_SENSOR_SLEEP_SECONDS:-5}"

KEY=""
ASSUME_YES=0
REBOOT_MODE="auto"
DELETE_EXPIRED=0

OPENED=0
CLOSED=0
WORK_DIR=""

log() { printf '%s [patch_sensor] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

usage() {
  sed -n '20,25p' "$0" >&2
  exit 2
}

parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      --key) KEY="${2:-}"; shift 2 ;;
      --yes) ASSUME_YES=1; shift ;;
      --reboot)
        REBOOT_MODE="${2:-}"
        [[ "$REBOOT_MODE" == "auto" || "$REBOOT_MODE" == "never" ]] || usage
        shift 2 ;;
      --delete-expired-snapshots) DELETE_EXPIRED=1; shift ;;
      -h|--help) usage ;;
      *) log "unknown argument: $1" >&2; usage ;;
    esac
  done
  [[ -n "$KEY" ]] || { log "--key is required" >&2; usage; }
  [[ -r "$KEY" ]] || die "operator key not readable: $KEY"
}

tf() { terraform -chdir="$TF_DIR" "$@"; }
tf_value() { tf console <<<"$1" | tr -d '"[:space:]'; }

date_plus_days() {
  date -u -d "+$1 days" +%Y-%m-%d 2>/dev/null || date -u -v+"$1"d +%Y-%m-%d
}

remote() { ssh -F "$WORK_DIR/ssh_config" sensor "$@"; }

# Run a remote command, but never past the given wall-clock deadline (in
# bash SECONDS). Portable: macOS has no coreutils `timeout` by default, and
# ssh's own timeouts do not bound the EICE ProxyCommand. Prints stdout.
# ssh is started directly (not through a function), so the background PID is
# ssh itself; SIGTERM makes ssh exit and terminate its ProxyCommand child.
remote_until() {
  local deadline="$1" out pid
  shift
  out="$(mktemp "$WORK_DIR/probe.XXXXXX")"
  ssh -F "$WORK_DIR/ssh_config" sensor "$@" >"$out" 2>/dev/null &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      rm -f "$out"
      return 124
    fi
    sleep 0.2
  done
  local rc=0
  wait "$pid" || rc=$?
  cat "$out"
  rm -f "$out"
  return "$rc"
}

close_egress() {
  (( OPENED == 1 && CLOSED == 0 )) || return 0
  log "closing patch egress (targeted apply with an empty list)"
  if tf apply -input=false -auto-approve -no-color -target="$TARGET" \
      -var 'patch_egress_cidrs=[]' >"$WORK_DIR/close.log" 2>&1; then
    CLOSED=1
    log "patch egress closed"
  else
    tail -n 20 "$WORK_DIR/close.log" >&2 || true
    log "ERROR: CLOSE FAILED. Security Group egress may still be open. Run now:" >&2
    log "  terraform -chdir=$TF_DIR apply -target=$TARGET -var 'patch_egress_cidrs=[]'" >&2
    return 1
  fi
}

on_exit() {
  local rc=$?
  trap - EXIT INT TERM HUP
  close_egress || rc=3
  [[ -n "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
  exit "$rc"
}

preflight() {
  local cmd
  for cmd in terraform aws ssh scp; do
    command -v "$cmd" >/dev/null || die "$cmd is required"
  done
  aws sts get-caller-identity --query Arn --output text >/dev/null \
    || die "AWS credentials are not available (aws login, then retry)"
  [[ "$(tf_value 'length(var.patch_egress_cidrs)')" == "0" ]] \
    || die "patch_egress_cidrs must be [] in terraform.tfvars before a run"
  local rc=0
  tf plan -input=false -lock=false -detailed-exitcode -no-color >"$WORK_DIR/preflight.plan" 2>&1 || rc=$?
  case "$rc" in
    0) ;;
    2) die "terraform plan shows pending changes; resolve drift before patching" ;;
    *) tail -n 20 "$WORK_DIR/preflight.plan" >&2; die "terraform plan failed" ;;
  esac
  REGION="$(tf_value 'var.aws_region')"
  ADMIN_PORT="$(tf_value 'var.admin_ssh_port')"
  INSTANCE_ID="$(tf output -raw instance_id)"
  [[ "$INSTANCE_ID" =~ ^i-[0-9a-f]{8,17}$ ]] || die "unexpected instance id"
  [[ "$ADMIN_PORT" =~ ^[0-9]+$ ]] || die "unexpected admin port"
  cat >"$WORK_DIR/ssh_config" <<EOF
Host sensor
  HostName $INSTANCE_ID
  Port $ADMIN_PORT
  User ubuntu
  IdentityFile $KEY
  IdentitiesOnly yes
  BatchMode yes
  ConnectTimeout 30
  ServerAliveInterval 30
  StrictHostKeyChecking accept-new
  UserKnownHostsFile ${PATCH_SENSOR_KNOWN_HOSTS:-$HOME/.ssh/known_hosts_attackarium}
  ProxyCommand aws ec2-instance-connect open-tunnel --region $REGION --instance-id %h --remote-port %p
EOF
  log "preflight ok (no drift, patch_egress_cidrs empty)"
}

snapshot() {
  local volume delete_after
  # shellcheck disable=SC2016  # JMESPath backticks, not shell expansion
  volume="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName==`/dev/sda1`].Ebs.VolumeId' \
    --output text)"
  [[ "$volume" =~ ^vol-[0-9a-f]+$ ]] || die "could not find the root volume"
  delete_after="$(date_plus_days "$SNAPSHOT_RETENTION_DAYS")"
  SNAPSHOT_ID="$(aws ec2 create-snapshot --region "$REGION" --volume-id "$volume" \
    --description "attackarium pre-patch $(date -u +%Y-%m-%d); delete after $delete_after" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=Project,Value=Attackarium},{Key=Purpose,Value=pre-patch},{Key=DeleteAfter,Value=$delete_after}]" \
    --query SnapshotId --output text)"
  [[ "$SNAPSHOT_ID" =~ ^snap-[0-9a-f]+$ ]] || die "snapshot creation failed"
  log "pre-patch snapshot $SNAPSHOT_ID (DeleteAfter=$delete_after; contains the shipper HMAC secret)"
}

install_scripts() {
  scp -q -F "$WORK_DIR/ssh_config" "$SCRIPT_DIR/patch_window.sh" "$SCRIPT_DIR/verify_egress.sh" sensor:/tmp/ \
    || die "copying scripts to the sensor failed"
  remote 'sudo install -o root -g root -m 0755 /tmp/patch_window.sh /tmp/verify_egress.sh /usr/local/sbin/ && rm -f /tmp/patch_window.sh /tmp/verify_egress.sh' \
    || die "installing scripts on the sensor failed"
  log "installed patch_window.sh and verify_egress.sh on the sensor"
}

resolve_cidrs() {
  local out line
  out="$(remote 'sudo /usr/local/sbin/patch_window.sh resolve')" || die "mirror resolution failed"
  CIDRS=()
  while read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/32$ ]] || die "unexpected resolve output: $line"
    CIDRS+=("$line")
  done <<<"$out"
  (( ${#CIDRS[@]} > 0 && ${#CIDRS[@]} <= 32 )) || die "expected 1-32 mirror /32s, got ${#CIDRS[@]}"
  log "mirror addresses: ${CIDRS[*]}"
}

open_egress() {
  local list
  list="$(printf '"%s",' "${CIDRS[@]}")"
  list="[${list%,}]"
  local mode=(-input=true)
  (( ASSUME_YES == 1 )) && mode=(-input=false -auto-approve)
  # Mark as opened before applying: a partial apply must still be closed.
  OPENED=1
  log "opening patch egress (targeted apply: $TARGET only)"
  tf apply "${mode[@]}" -no-color -target="$TARGET" -var "patch_egress_cidrs=$list" \
    || die "opening patch egress failed or was declined"
}

run_patch() {
  local rc=0
  remote 'sudo /usr/local/sbin/patch_window.sh run' || rc=$?
  PATCH_RC=$rc
  if (( rc != 0 )); then
    log "patch window reported failure (exit $rc); closing egress and verifying anyway" >&2
  fi
}

verify_closed() {
  local rc=0
  tf plan -input=false -lock=false -detailed-exitcode -no-color >"$WORK_DIR/verify.plan" 2>&1 || rc=$?
  (( rc == 0 )) || { tail -n 20 "$WORK_DIR/verify.plan" >&2; die "terraform plan is not clean after closing (exit $rc)"; }
  log "terraform plan: no changes"
}

verify_host() {
  local status
  status="$(remote 'sudo /usr/local/sbin/patch_window.sh status')" || die "status failed"
  printf '%s\n' "$status"
  grep -qx 'temporary_rule=absent' <<<"$status" || die "temporary rule still present on the host"
  ! grep -q '^window_flows=' <<<"$status" || die "window flows not verified; run patch_window.sh cleanup"
  remote 'sudo /usr/local/sbin/verify_egress.sh' >/dev/null || die "verify_egress.sh failed"
  # One unit per call: with several units, is-active succeeds if ANY is active.
  local unit
  for unit in opencanary http-collector attackarium-shipper; do
    remote "systemctl is-active --quiet $unit" || die "sensor service $unit is not active"
  done
  log "host verified: rule absent, egress locked down, services active"
  REBOOT_REQUIRED="$(sed -n 's/^reboot_required=//p' <<<"$status")"
}

maybe_reboot() {
  [[ "$REBOOT_REQUIRED" == "yes" ]] || { log "no reboot required"; return 0; }
  if [[ "$REBOOT_MODE" == "never" ]]; then
    log "reboot required but --reboot never was given; reboot manually soon"
    return 0
  fi
  local before after="" deadline=$((SECONDS + REBOOT_WAIT_SECONDS))
  before="$(remote 'cat /proc/sys/kernel/random/boot_id')" || die "could not read the boot id"
  [[ -n "$before" ]] || die "empty boot id"
  log "rebooting the sensor (reboot required)"
  # The connection usually drops during the reboot, so the exit status is not
  # meaningful; a changed boot id is the proof that the reboot happened.
  remote_until "$deadline" 'sudo systemctl reboot' >/dev/null || true
  while :; do
    sleep "$SLEEP_SECONDS"
    after="$(remote_until "$deadline" 'cat /proc/sys/kernel/random/boot_id' || true)"
    [[ -n "$after" && "$after" != "$before" ]] && break
    (( SECONDS >= deadline )) && die "sensor did not complete a reboot within ${REBOOT_WAIT_SECONDS}s"
  done
  log "sensor is back (new boot id)"
  verify_host
}

expired_snapshots() {
  local today ids
  today="$(date -u +%Y-%m-%d)"
  ids="$(aws ec2 describe-snapshots --region "$REGION" --owner-ids self \
    --filters Name=tag:Project,Values=Attackarium Name=tag:Purpose,Values=pre-patch \
    --query "Snapshots[?Tags[?Key=='DeleteAfter' && Value<'$today']].SnapshotId" --output text)"
  if [[ -z "$ids" || "$ids" == "None" ]]; then
    log "no expired pre-patch snapshots"
    return 0
  fi
  if (( DELETE_EXPIRED == 1 )); then
    local id
    for id in $ids; do
      aws ec2 delete-snapshot --region "$REGION" --snapshot-id "$id"
      log "deleted expired pre-patch snapshot $id"
    done
  else
    log "expired pre-patch snapshots (contain the HMAC secret): $ids"
    log "delete them with --delete-expired-snapshots, or: aws ec2 delete-snapshot --snapshot-id <id>"
  fi
}

main() {
  parse_args "$@"
  WORK_DIR="$(mktemp -d)"
  trap on_exit EXIT
  trap 'exit 130' INT TERM HUP
  preflight
  snapshot
  install_scripts
  resolve_cidrs
  open_egress
  run_patch
  close_egress || exit 3
  verify_closed
  verify_host
  maybe_reboot
  expired_snapshots
  if (( PATCH_RC != 0 )); then
    die "patch window failed (egress closed and verified); see the output above"
  fi
  log "done: patched, egress closed, host verified. Pre-patch snapshot: $SNAPSHOT_ID"
}

PATCH_RC=0
REBOOT_REQUIRED=no
SNAPSHOT_ID=""
main "$@"
