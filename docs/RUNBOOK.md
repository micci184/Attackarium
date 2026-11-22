# Operations runbook

Manual procedures for the single `us-east-1` sensor. No responder service and
no Lambda are part of this runbook. AWS Budgets email does not stop the
instance. Do not create resources from this document.

## Abuse and security mail

Attackarium does not have its own abuse mailbox. AWS notifications arrive at
the email address already registered on the existing AWS account.

Before the sensor is exposed:

1. Confirm that address can receive mail from AWS.
2. Check it when AWS sends a security or abuse notice.
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

## Storage pressure

These checks do not add a monitoring service, and the sensor does not receive a
database password.

1. **Local spool.** The shipper writes `/var/lib/attackarium/shipper-metrics.json`.
   `spool_alert` is true at 70% of the local cap. The same warning is written to
   the shipper service journal and repeats at most every five minutes.
   `journalctl -u attackarium-shipper` shows `spool utilization`.
2. **Database budget.** From an operator machine that already has the Supabase
   database URL, run:

   ```sql
   select pg_size_pretty(pg_database_size(current_database())) as database_size;
   ```

   The Phase 1 budget is the Supabase Free database quota, 500 MB. Above 70%
   (350 MB), shorten detailed-event retention before daily aggregates. Do not
   keep sanitized events for less than 30 days without a new decision.

## What this runbook does not add

- A second AWS account, a dedicated abuse product, or a status page.
- Automatic shutdown, AWS Lambda, or an extra monitoring service.
- S3 export of logs or disk images.
