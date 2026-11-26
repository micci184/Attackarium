# Operations runbook

Manual procedures for the single `us-east-1` sensor, Supabase storage, public
Vercel dashboard, Remote MCP server, and operator-only Admin Console. No
automated responder service and no Lambda are part of this runbook. AWS Budgets
email does not stop the instance. Do not create resources from this document.

## Abuse and security mail

Attackarium does not operate a dedicated abuse ticketing system or mailbox in
MVP (ADR-023). AWS security and abuse notifications arrive at the email address
registered on the existing AWS account, and public security inquiries are
directed to the GitHub repository Security page.

Before or during live sensor operation:

1. Confirm the registered AWS account email can receive mail from AWS.
2. Check it promptly whenever AWS sends a security or abuse notice.
3. If the notice names the sensor instance, start the emergency stop below.

## Emergency stop

Stop preserves the volume for investigation. Terminate deletes the instance and
its attached store. During an incident, **stop**. Do not terminate until the
investigation is finished and the owner chooses to destroy the host.

1. **Block traffic.** On the sensor security group, remove inbound decoy rules
   and outbound rules except what is required to keep the management path
   available for the stop itself. The host firewall remains in place.
2. **Stop the EC2 instance.** Use the existing account console or CLI. Do not
   terminate it. Stopping ends capture and keeps the EBS volume.
3. **Revoke secrets if the host or the ingest key may be exposed.** Rotate the
   sensor HMAC secret and, if needed, `IP_HASH_SALT`. Revoking the salt makes
   older `src_ip_hash` values unlinkable to new events. It does not restore
   discarded source addresses.
4. **Read what remains.** Check the AWS Budget mail, the instance stop state,
   CloudTrail or account notifications already in the account, and any
   Supabase ingest errors. EC2 raw logs older than 24 hours are already gone
   by design. The stopped volume can still hold the SQLite spool and logs
   newer than that.
5. **Decide recovery after the cause is known.** Starting the same instance
   resumes the same disk. A new instance is a later, separate decision. Do not
   treat a start as permission to widen the security group.

## Sensor host access & code deployment (ADR-025)

Operator SSH goes through the EC2 Instance Connect Endpoint (EICE) on port 3389
(EICE tunnels only to 22 or 3389; 22 is the decoy). No public admin port and no
instance IAM role are used. Hosts bootstrapped with the current user data disable
cloud-init after first boot (`/etc/cloud/cloud-init.disabled`), because `nftables`
blocks the instance metadata service and cloud-init would otherwise stall every
reboot for about 8 minutes. Terraform ignores `user_data` changes, so a host
created before this change must get the marker manually over an operator
session (`sudo touch /etc/cloud/cloud-init.disabled`) or be replaced. The current
production sensor already has it (2026-11-23).

Changing the management port on an existing sensor (host config is not
re-rendered from user data), in this order:

Keep the existing session open throughout.

1. Over the current path, add the new port to
   `/etc/ssh/sshd_config.d/99-attackarium-hardening.conf` and to the host
   `nftables` admin rule, **keeping the old port** in both. Check with
   `sshd -t` and `nft -c -f /etc/nftables.conf`, then apply with
   `nft -f /etc/nftables.conf` and `systemctl reload ssh`.
2. Host-local check only: the Security Group still allows the old port, so
   EICE cannot reach the new one yet. Confirm `ss -ltn` shows sshd on both
   ports, and `nft list chain inet attackarium input` allows both.
3. Apply the Terraform Security Group change (`admin_ssh_port`).
4. Open a **new** EICE SSH session on the new port and confirm it works.
5. Only then remove the old port from sshd and `nftables` (validate and
   reload as in step 1), and confirm a fresh EICE session still connects.

If access is lost at any point, use the offline root-volume procedure below. You need the operator private key
and an AWS identity allowed to call `ec2-instance-connect:OpenTunnel`
(protect it with MFA).

```bash
cd infra/aws-sensor
terraform output -raw admin_ssh_command   # replace <operator-private-key>
```

Deploying collector/shipper code that needs no new packages (no Terraform
change and no egress opening):

1. Back up the deployed files on the host
   (`/opt/attackarium/http-collector/*.py`, `/opt/attackarium/shipper/*.py`).
2. Copy `sensors/http-collector/collector.py`, `sensors/http-collector/signatures.py`,
   and `sensors/shipper/shipper.py` over an EICE tunnel. `open-tunnel` targets
   port 22 unless told otherwise, so pass the admin port:

   ```bash
   cd infra/aws-sensor
   ADMIN_PORT=$(terraform console <<< 'var.admin_ssh_port')
   command -v nc >/dev/null || { echo "nc is required" >&2; exit 1; }
   # The local port must be free, so a ready listener is this tunnel's own.
   ! nc -z 127.0.0.1 12222 || { echo "port 12222 already in use" >&2; exit 1; }
   aws ec2-instance-connect open-tunnel --region us-east-1 \
     --instance-id "$(terraform output -raw instance_id)" \
     --remote-port "$ADMIN_PORT" --local-port 12222 &
   TUNNEL_PID=$!
   # Always stop the tunnel, including on Ctrl-C or an early failure.
   trap 'kill "$TUNNEL_PID" 2>/dev/null || true' EXIT
   for _ in $(seq 1 30); do   # bounded wait (about 30 s)
     kill -0 "$TUNNEL_PID" 2>/dev/null || { echo "tunnel exited" >&2; exit 1; }
     nc -z 127.0.0.1 12222 && break
     sleep 1
   done
   nc -z 127.0.0.1 12222 || { echo "tunnel not ready" >&2; exit 1; }
   scp -P 12222 -i <operator-private-key> <files> ubuntu@127.0.0.1:/tmp/ \
     || { echo "scp failed" >&2; exit 1; }
   ```

   Install them with the same owner and mode as the files they replace, and
   restart the collector and shipper systemd units.
3. Verify `systemctl is-active`, the journal (no tracebacks), a fresh heartbeat on
   `/sensors`, and that the local spool drains.
4. If the change adds a data-minimization rule, re-run the matching idempotent
   cleanup migration SQL once the spool is empty, so events queued before the
   update are cleaned too.
5. Roll back by restoring the backed-up files and restarting the services.

Changing host firewall rules (`/etc/nftables.conf`):

- cloud-init writes the file only at first boot, and `aws_instance.sensor`
  ignores `user_data` changes. A `terraform apply` therefore never updates the
  running host's firewall, and it does not stop or restart the instance.
- **With access:** edit the file on the host, check it with `nft -c -f`, and
  apply it with `nft -f /etc/nftables.conf`.
- **Ordering:** a Terraform change that removes a public admin SG rule must be
  applied only after the host firewall already allows the EICE subnet on the
  admin port. Otherwise the operator is locked out.
- **Without access (recovery):** do **not** relaunch from an AMI of the current
  root volume. Its `nftables` output policy drops traffic to the instance
  metadata service, and `nftables.service` and `cloud-init-local.service` have
  no boot ordering. cloud-init may fail to fetch the new user data, and the
  replacement would be unreachable too. Edit the volume offline instead:
  1. Snapshot the root volume (rollback point).
  2. Launch a temporary rescue instance (stock Ubuntu 24.04 LTS) in the same AZ,
     with no public IP and a temporary SG that allows SSH only from the EICE SG.
     Add a matching temporary EICE SG egress rule.
  3. Stop the sensor, detach its root volume, and attach it to the rescue
     instance. Over EICE, mount it and make the host match `admin_ssh_port`
     (3389): set `Port 3389` in `etc/ssh/sshd_config.d/99-attackarium-hardening.conf`,
     allow 3389 from the sensor subnet in `etc/nftables.conf` (validate with
     `nft -c -f <mounted>/etc/nftables.conf`), create
     `etc/cloud/cloud-init.disabled`, and deploy any sensor code at the same time.
     If the Security Group still uses another port, apply Terraform with
     `admin_ssh_port = 3389` before starting the sensor again.
  4. On the rescue instance, `umount` the volume. Detach it and wait until it is
     `available`. Reattach it to the sensor as its original root device
     (`/dev/sda1`).
  5. Set `DeleteOnTermination=true` on the reattached root volume and verify it,
     because a reattached volume defaults to `false`:
     `aws ec2 modify-instance-attribute --instance-id <id> --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"DeleteOnTermination":true}}]'`.
     Then start the sensor. The Elastic IP keeps the public address unchanged;
     expect a recorded coverage gap if the stop lasts more than 15 minutes.
  6. Terminate the rescue instance and remove the temporary SG and rules.
  7. After verification and the rollback window, delete the step 1 root-volume
     snapshot, and deregister any AMI **and delete its EBS snapshots**. They
     contain the shipper HMAC secret.

## Automatic OS security updates (ADR-027)

The sensor installs security updates by itself: `unattended-upgrades` runs
daily over permanent TCP/80 egress to the Canonical-owned archive ranges
(`os_update_egress_cidrs`), and reboots at 04:00 UTC when an update requires
it. Each `apt-daily-upgrade` run first refreshes the package lists itself
(`record_os_update_status.sh refresh`, `apt-get update` with
`APT::Update::Error-Mode "any"`) and stores that attempt's outcome from the
exit status; apt's success hooks and stamps are not trusted because they run
even after a partial failure. Afterwards (`record`), success is written only if
that refresh succeeded, the unattended-upgrades run that followed finished
cleanly, and it is newer than the last recorded success. The shipper reports
it to `/admin` (Current within
3 days, Due after 3, Overdue after 7). The `sensor-patch-freshness-weekly`
GitHub Actions workflow fails (and GitHub emails the maintainer) when an
active sensor is not current. Its public logs print counts only.

If it reports a problem:
1. Over EICE, read `/var/log/unattended-upgrades/unattended-upgrades.log` and
   `journalctl -u apt-daily.service -u apt-daily-upgrade.service`.
2. If apt cannot connect, compare `getent ahostsv4 archive.ubuntu.com
   security.ubuntu.com` with `os_update_egress_cidrs`. If Canonical moved the
   archive, confirm the new range in the RIPE database (owner Canonical,
   AS41231) before changing the variable, then update both the Terraform
   variable and the host `nftables` rule. Never widen it to unowned ranges.
3. Patch manually in the meantime with `scripts/patch_sensor.sh` (below).

Enabling it on a host created before ADR-027 (user data is not re-rendered),
over an EICE session, keeping the existing session open. This is a production
change: get explicit owner approval first (`docs/SECURITY.md`, gate 1).
1. **On the operator machine** (not over EICE: the sensor has no AWS
   credentials), from `infra/aws-sensor` after `aws login`, save a plan with
   `terraform plan -out=os-update.tfplan`, then review that
   saved plan with `terraform show os-update.tfplan`. It must contain **only**
   the `aws_vpc_security_group_egress_rule.os_update_http` additions (one per
   CIDR); stop and investigate if anything else changes. Apply exactly that
   file: `terraform apply os-update.tfplan`.
2. Still locally, print the configured ranges with
   `terraform console <<< 'var.os_update_egress_cidrs'`. Then, in the EICE
   session on the host, add exactly those to
   the `output` chain in `/etc/nftables.conf`, for example with the defaults:
   `ip daddr { 91.189.88.0/21, 185.125.188.0/22 } tcp dport 80 accept`.
   Check with `nft -c -f /etc/nftables.conf` and apply with
   `nft -f /etc/nftables.conf`. The Security Group and host rule must list the
   same CIDRs.
3. Install `sensors/host/record_os_update_status.sh` as
   `/usr/local/sbin/record_os_update_status.sh` (`root:root 0755`),
   `sensors/host/52attackarium-unattended-upgrades` in `/etc/apt/apt.conf.d/`
   (`0644`), and `sensors/host/apt-daily-upgrade-attackarium.conf` as
   `/etc/systemd/system/apt-daily-upgrade.service.d/attackarium-status.conf`
   (`0644`); then `systemctl daemon-reload`.
4. Verify: `sudo /usr/local/sbin/verify_egress.sh` still passes (arbitrary
   egress blocked). Then run `sudo systemctl start apt-daily-upgrade.service`
   (its pre-step refreshes the lists). Expected:
   `/var/lib/attackarium-patch/refresh-result` shows `result=ok`, the latest
   run in `/var/log/unattended-upgrades/unattended-upgrades.log` ends with
   "All upgrades installed" or "No packages found ...", and `last-success`
   has a newer `finished_at` (that run's completion time). If not, read
   `journalctl -u apt-daily-upgrade.service` for the
   `record_os_update_status` lines: `refresh failed` means apt could not
   reach the archive (check `nftables`, the Security Group, and
   `getent ahostsv4 archive.ubuntu.com`); `does not follow the latest
   refresh` means unattended-upgrade did not run (check
   `APT::Periodic::Unattended-Upgrade`).

   **If unattended-upgrades already ran in the last 24 hours** (for example
   from the daily timer), `apt.systemd.daily` skips the upgrade on a manual
   start. The pre-step still refreshes the lists, and the recorder correctly
   logs `does not follow the latest refresh` and writes nothing. To verify the
   whole path anyway, run the same three phases by hand, in order:

   ```bash
   sudo /usr/local/sbin/record_os_update_status.sh refresh
   sudo unattended-upgrade -v
   sudo /usr/local/sbin/record_os_update_status.sh record
   ```

   `refresh-result` must show `result=ok`, and `last-success` must then show
   `detail=unattended-upgrades` with that run's completion time. Within a few
   minutes the shipper reports it and `/admin` shows Current.

   **Transient mirror errors:** if unattended-upgrades logs
   `404  Not Found` for a `.deb` (the archive nodes are briefly out of sync)
   or any other download error, the recorder logs `reported errors` and writes
   nothing. Re-run the three phases after a few minutes; on the daily timer it
   recovers on the next day without action. Only a failure lasting three days
   makes `/admin` show Due, and the weekly check fails after that.

## OS security patch window (ADR-026, #94)

Since ADR-027 this is the **manual fallback**: for an urgent fix before the
next daily run, a rollback (`install PKG=VERSION`), or while automatic updates
are broken (for example the archive moved outside `os_update_egress_cidrs`).
Every window needs explicit operator approval.

`infra/aws-sensor/scripts/patch_window.sh` opens TCP/80 only to the IPv4
addresses that the configured apt mirrors resolve to, runs `apt-get update`
and `unattended-upgrade` (security origins, existing conffiles kept), and then
reloads `/etc/nftables.conf`, which never contains the temporary rule. The run
is a transient systemd unit, so an EICE tunnel drop cannot interrupt `dpkg`. A
separate timer restores the firewall if the unit is killed or hangs, and a
reboot also discards the in-memory rule.

**Recommended: one command from the operator machine** (Terraform state, AWS
credentials, and the operator key; after `aws login`):

```bash
eval "$(aws configure export-credentials --format env)"
infra/aws-sensor/scripts/patch_sensor.sh --key ~/.ssh/<operator-key>
```

`patch_sensor.sh` performs the manual steps below in order: preflight (no
Terraform drift, `patch_egress_cidrs` empty), pre-patch snapshot (tagged
`DeleteAfter` = today + 7 days), script install, mirror resolution, a
Terraform apply **targeted at the `patch_http` rules only** (it prompts unless
`--yes`), the patch run, and the close. **The close always runs** once the open
has started, including on errors and Ctrl-C, and is verified with a full
`terraform plan`. It then verifies the host, reboots if the host requires it
(`--reboot never` to skip), and lists expired pre-patch snapshots
(`--delete-expired-snapshots` deletes them). If it prints `CLOSE FAILED`, run
the printed Terraform command immediately.

Patch freshness is visible on `/admin` ("Sensor OS patch freshness"): the
sensor reports its last successful window with every signed batch and
heartbeat. Patch when it shows **Due** (30 days); **Overdue** (35 days) is the
alert threshold.

Manual procedure (what the script does, and the fallback):

1. Copy `infra/aws-sensor/scripts/patch_window.sh` and
   `infra/aws-sensor/scripts/verify_egress.sh` to the host (see the code
   deployment procedure above) and install both as `root:root 0755` in
   `/usr/local/sbin/`.
   Then take a **pre-patch snapshot** of the sensor root volume and record its
   ID: `aws ec2 create-snapshot --region us-east-1 --volume-id <root-volume-id>
   --description "attackarium pre-patch <date>"`. It is the rollback path for a
   package that cannot be downgraded. It contains the shipper HMAC secret, so
   delete it after the rollback window (7 days), with any AMI made from it.
2. On the host, print the mirror addresses:
   `sudo /usr/local/sbin/patch_window.sh resolve`.
3. Locally, set `patch_egress_cidrs` in `terraform.tfvars` to exactly those
   `/32` entries. Review `terraform plan` (only `patch_http` rules are added),
   then apply. The variable rejects anything other than up to 32 `/32` entries.
4. On the host: `sudo /usr/local/sbin/patch_window.sh run`. It prints the apt
   output and the result (`/var/lib/attackarium-patch/last-result`).
   - If the result is `failure` with `apt-get update failed`, mirrors probably
     rotated. Repeat from step 2 once; do not widen the CIDRs.
   - The Ubuntu mirrors currently sit behind shared Cloudflare addresses, so the
     window allows plain HTTP to anything on those IPs, not only Ubuntu (ADR-026).
     Keep the window short.
5. Immediately set `patch_egress_cidrs = []` and apply again. Confirm with
   `terraform plan` (no changes).
6. On the host: `sudo /usr/local/sbin/patch_window.sh status` must show
   `temporary_rule=absent` and no `window_flows` line. Run
   `sudo /usr/local/sbin/verify_egress.sh` (all checks pass),
   then check `systemctl is-active opencanary http-collector attackarium-shipper`
   and a fresh heartbeat on `/sensors`.
7. If `reboot_required=yes`, reboot over EICE (`sudo systemctl reboot`), and
   repeat the step 6 checks after it comes back. A normal reboot takes under a
   minute; a stop longer than 15 minutes is recorded as a coverage gap.
8. Record the date, result, and whether a reboot happened in the drills record
   below.

Rollback: if a service fails after the upgrade, check its journal first.
Package downgrades need the mirrors again, so repeat steps 2–6 with
`sudo /usr/local/sbin/patch_window.sh install <package>=<previous-version> ...`
instead of `run`. It opens the same mirror-only host rule, installs only the
pinned versions (`--allow-downgrades`), and cleans up the same way. If a
package cannot be downgraded, restore from the step 1 pre-patch snapshot
(create a volume from it and swap it in as the root device with the steps of
the offline procedure above). The offline procedure by itself only restores
access; it does not restore packages.

Cleanup also ends any TCP/80 connection to the window addresses, because the
persisted ruleset accepts established flows. `status` reports
`window_flows=UNVERIFIED` if that step did not complete; run
`sudo /usr/local/sbin/patch_window.sh cleanup` until it succeeds. Only one
window can run at a time.

## Retention policy & storage pressure (ADR-022 / ADR-023)

Active retention boundaries (no raw source IPs or raw payloads in Supabase):

- **EC2 raw logs:** Deleted within 24 hours on the sensor host.
- **Sanitized events (`attack_events`):** Retained at least **30 days**
  (configurable via `public.run_scheduled_observation_maintenance(p_event_retention_days)`,
  default `30`, minimum enforced at `30`).
- **Daily aggregates (`event_aggregates`, `daily_stats`, `observed_patterns`,
  `pattern_daily_counts`):** Retained at least **1 year** (not deleted by
  scheduled maintenance).
- **Transient replay/rate-limit tables (`ingest_receipts`,
  `mcp_rate_limit_windows`):** Expired rows pruned automatically on every
  15-minute `pg_cron` run.

Storage pressure checks (no extra monitoring service; sensor has no DB password):

1. **Local spool (> 70% alert):** The shipper writes
   `/var/lib/attackarium/shipper-metrics.json`. `spool_alert` becomes `true` at
   70% of the local cap, and the same warning is logged to
   `journalctl -u attackarium-shipper` at most every five minutes.
2. **Database budget (> 70% / 350 MB alert):** From an operator machine with
   Supabase CLI access, check database size:

   ```sql
   select pg_size_pretty(pg_database_size(current_database())) as database_size;
   ```

   The MVP budget is the Supabase Free 500 MB quota. Above 70% (350 MB), verify
   that `observation-maintenance` is running, confirm `attack_events` retention
   is set to 30 days, and prune `attack_events` before ever touching daily
   aggregates. Never reduce sanitized event retention below 30 days without a
   new ADR.

## Operational alerts checklist (`docs/SECURITY.md`)

Check these five operational conditions regularly (no mandatory third-party
SIEM or Lambda required in MVP):

1. **Sensor heartbeat loss (> 15 min):** Automatically recorded as a coverage
   gap in `sensor_status_events` by `sync_sensor_coverage_gaps()` and surfaced
   as `stale` / `inactive` on `/sensors` and in `get_observation_summary`.
2. **Local spool > 70%:** `spool_alert: true` in shipper metrics and
   `journalctl -u attackarium-shipper`.
3. **Database quota > 70% (350 MB of 500 MB):** Verified via
   `pg_database_size(current_database())` and Supabase Dashboard → Database
   usage.
4. **Unexpected egress from sensor:** Guarded by both EC2 Security Group
   outbound rules and host `nftables` firewall; verify via VPC/host logs if
   anomalous billing or AWS abuse mail occurs.
5. **Sustained ingest 401 / 429 / schema rejections:** Review Supabase Edge
   Function (`ingest-events`) logs in Supabase Dashboard → Edge Functions →
   Logs and shipper retry metrics.

## Backup risk & deferral policy (ADR-023)

Independent offsite backups (such as AWS S3 exports or automated `pg_dump` to
external object storage) are **intentionally deferred in MVP** to keep monthly
cost near zero and avoid duplicating operational infrastructure before the
30-day value evaluation completes.

- **Accepted risk:** Supabase Free does not include Point-in-Time Recovery
  (PITR) or guaranteed daily backups. A catastrophic Supabase project failure
  or accidental destructive query could cause permanent loss of historical
  aggregates and sanitized events.
- **Mitigation during MVP:** All schema changes are checked into Git under
  `supabase/migrations`, `admin_audit_logs` is append-only, and destructive DB
  operations require explicit operator approval.
- **Future adoption criteria:** Enable scheduled offsite backups (e.g.,
  encrypted `pg_dump` of aggregate tables or Supabase Pro PITR) if any of the
  following occur:
  1. The 30-day MVP evaluation (`#34`) succeeds and Attackarium transitions to
     long-term public service.
  2. Historical aggregates represent > 90 days of irreplaceable longitudinal
     trend data or > 100 MB of unique observations.

## Remote MCP OAuth 2.1 & Operator Admin setup (Phase 2)

1. **Supabase Auth providers:** Enable GitHub (and optionally Google) OAuth
   providers and add `<SITE_URL>/auth/callback` to Redirect URLs.
2. **Supabase Auth OAuth 2.1 Server:** Enable the OAuth 2.1 Server
   (Authorization Code + PKCE) with:
   - Authorization Path: `/oauth/consent`
   - Allow Dynamic OAuth Apps (DCR): ON (for MCP clients such as Cursor/Claude)
   - Asymmetric JWT signing keys (`ES256` / `RS256`, verified via JWKS)
   - Minimal standard OIDC scope `openid` (Supabase OAuth 2.1 Server does not
     support custom scopes; read-only access is enforced server-side across the
     3 read-only tools).
3. **Vercel Environment Variables (Production only for secrets):**
   - `NEXT_PUBLIC_SITE_URL` (Config)
   - `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` (Config)
   - `SUPABASE_AUTH_ISSUER` (`https://<project-ref>.supabase.co/auth/v1`)
   - `SUPABASE_SERVICE_ROLE_KEY` (Secret, server-only — never in `NEXT_PUBLIC_*`)
   - `ADMIN_ALLOWED_USER_IDS` (Secret, comma-separated operator Supabase Auth UUIDs)
   - Optional: `MCP_REQUIRED_TERMS_VERSION`, `MCP_RATE_LIMIT_PER_MINUTE`
4. **Entitlements & Operator MFA (`aal2`):**
   - Signing in does not grant MCP access. Grant or revoke
     `user_mcp_entitlements.mcp_enabled` (and `is_suspended`) via `/admin` or
     explicit operator SQL.
   - Operators access `/admin` (linked privately inside `/mcp` for allowlisted
     operators only), complete TOTP MFA enrollment/verification on `/admin/mfa`
     to reach `aal2`, and review aggregate MCP usage on `/admin/mcp-usage`.

## Pre-public verification & drills record

| Verification / Drill | Status | Evidence / Notes |
|---|---|---|
| PostgreSQL RLS & default-deny (`anon`/`authenticated`) | Verified | `supabase/tests/rls_test.sql` tested on CI Postgres 16; private tables, `user_mcp_entitlements`, `mcp_usage_buckets`, `mcp_rate_limit_windows`, `admin_audit_logs` verified |
| Secret & PII hygiene | Verified | No `service_role` in `NEXT_PUBLIC_*` or Git; no raw IPs, credentials, payloads, or MCP prompts/tokens stored or logged |
| Log redaction & hostile-input safety | Verified | Sensor/ingest unit tests + `apps/web` unit tests (38/38 passing) covering control-char stripping, URL sanitization, and CSP `form-action 'self'` |
| Ingest outage recovery (local SQLite spool) | Verified | Shipper unit tests cover bounded SQLite spooling, 70% cap warning, backoff, and idempotent replay via `ingest_receipts` |
| Remote MCP OAuth 2.1 + 5-gate authz E2E | Verified | Live Cursor OAuth 2.1 + PKCE consent flow on `https://attackarium.vercel.app/api/mcp` and live `get_observation_summary` execution verified |
| Operator Admin Console + MFA (`aal2`) | Verified | Live TOTP enrollment on `/admin/mfa`, `aal2` access to `/admin` and `/admin/mcp-usage`, and `401`/`403` denial for unauthenticated/non-allowlisted callers |
| Sensor OS patch window (ADR-026) | Verified 2026-11-25 | First production window: 59 s, Security Group egress open about 2 minutes, no reboot, `verify_egress.sh` passed afterwards |
| Automatic OS security updates (ADR-027) | Verified 2026-11-26 | Rolled out per this runbook. A manual `apt-daily-upgrade` start was skipped (already ran within 24 h) and correctly not recorded; a first manual run hit a transient mirror `404` and was correctly not recorded; the retry installed 13 security updates and recorded `2026-11-26T08:42:02Z`, which reached `/admin`. `verify_egress.sh` passed, and the weekly check passed on a manual run. Pending: confirm that killing a patch-window wrapper keeps `run.lock` held by the unit, during the next approved window (PR #99 review) |
| Live EC2 sensor emergency stop drill | Deferred (requires explicit approval) | Intentionally not executed during active 30-day observation collection (`#32`); run only with explicit operator authorization |

## What this runbook does not add

- A second AWS account, a dedicated abuse product, or a status page.
- Automatic shutdown, AWS Lambda, or an extra monitoring service.
- Mandatory S3 export of logs or disk images in MVP.
