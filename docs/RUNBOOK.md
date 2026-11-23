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
instance IAM role are used. cloud-init is disabled after first boot
(`/etc/cloud/cloud-init.disabled`) because `nftables` blocks the instance metadata
service and cloud-init would otherwise stall every reboot for about 8 minutes. You need the operator private key
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
     instance. Over EICE, mount it, edit `etc/nftables.conf` (and deploy any
     sensor code at the same time), and validate with `nft -c -f`.
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
| Live EC2 sensor emergency stop drill | Deferred (requires explicit approval) | Intentionally not executed during active 30-day observation collection (`#32`); run only with explicit operator authorization |

## What this runbook does not add

- A second AWS account, a dedicated abuse product, or a status page.
- Automatic shutdown, AWS Lambda, or an extra monitoring service.
- Mandatory S3 export of logs or disk images in MVP.
