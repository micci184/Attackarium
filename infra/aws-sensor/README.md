# AWS Sensor Infrastructure (`infra/aws-sensor`)

Terraform configuration for the single isolated Attackarium honeypot sensor host in **US East (N. Virginia), `us-east-1`** (`ADR-006`, `ADR-018`–`ADR-021`).

## What this provisions

- Dedicated isolated VPC (`10.42.0.0/24`) with one public subnet, no VPC peering, and a locked-down default Security Group (empty rules).
- Layer 1 firewall (VPC Security Group):
  - Inbound: decoy ports (`21`, `22`, `23`, `80`, `3306`, `6379`, optional `443`) + operator SSH on `var.admin_ssh_port` **only from the EC2 Instance Connect Endpoint Security Group** (ADR-025). `var.admin_ssh_cidrs` is an optional break-glass list and is empty by default.
  - Outbound: strictly `443/TCP` to `var.ingest_egress_cidrs`, `80/TCP` to the Canonical-owned Ubuntu archive ranges in `var.os_update_egress_cidrs` for automatic security updates (ADR-027), DNS to VPC resolver, and NTP to Amazon Time Sync. No `0.0.0.0/0` egress during normal operation.
- Layer 2 firewall (host `nftables` via cloud-init): mirrors the Security Group rules, applies per-source new-connection rate limiting (`30/s`, burst `60`) and a per-source concurrent-connection cap (`var.decoy_max_conns_per_source`, default `8`, #95) on decoy ports, and disables Ubuntu 24.04 `ssh.socket` so `sshd` listens strictly on `var.admin_ssh_port`.
- EC2 Instance Connect Endpoint in the sensor subnet for IAM-authenticated operator SSH (no public admin port, no instance IAM role, no extra cost). Connect with `terraform output -raw admin_ssh_command`; see `docs/RUNBOOK.md`.
- Elastic IP associated with the sensor, so stop/start keeps the same public IPv4 (observation continuity). It costs the same as an auto-assigned address while associated. `terraform output public_ip` is marked sensitive; never publish the address.
- Single EC2 instance: `t3a.small`, `cpu_credits = "standard"`, latest Ubuntu Server LTS AMI, encrypted `gp3` 20 GiB root volume, 1 public IPv4, **no IAM role**, IMDSv2 required (`hop_limit = 1`), and termination protection enabled by default.
- Single AWS Budget (`40` USD/month, scoped to `Project=Attackarium` tag, email alerts at 50% / 80% / 100%, notification only — does not stop the instance).

## Notes on `ingest_egress_cidrs` and initial bootstrap

- Hosted Supabase Edge Functions (`https://<project>.supabase.co`) sit behind Cloudflare anycast IPs rather than a single static IP. Set `ingest_egress_cidrs` to the published Cloudflare IPv4 CIDRs (or a narrower proxy CIDR if used later) so outbound traffic stays restricted to TCP/443 on approved ranges while surviving DNS rotation.
- For initial OS/package installation (`apt` / `pip`), `/etc/nftables.conf` always stays locked down so temporary egress can never be persisted on disk. Temporarily set `enable_bootstrap_egress = true` and apply (opens SG Layer 1), add an ephemeral in-memory rule on the host (`sudo nft add rule inet attackarium output tcp dport '{ 80, 443 }' accept`), install packages, immediately restore host rules with `sudo nft -f /etc/nftables.conf`, then set `enable_bootstrap_egress = false` and re-apply. Verify lockdown with `scripts/verify_egress.sh`.
- Routine OS security updates do **not** use bootstrap egress. Use the patch window (`scripts/patch_window.sh` and `patch_egress_cidrs`, TCP/80 to resolved Ubuntu mirror `/32`s only); see "OS security patch window" in `docs/RUNBOOK.md`.

## Usage (manual apply only)

```bash
cd infra/aws-sensor
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your real operator CIDR, SSH public key, approved ingest CIDRs, and alert email.
# Never commit terraform.tfvars.

terraform init
terraform plan
# Review the plan carefully before applying:
terraform apply
```

After provisioning:

1. Activate the `Project` (plus `Component`, `Environment`) user-defined Cost Allocation Tags in AWS Billing so the `Project=Attackarium` Budget filter tracks spend (`ADR-020`).
2. Confirm the AWS account contact email can receive abuse/security notifications (`docs/RUNBOOK.md`).
3. Ensure `enable_bootstrap_egress = false` is applied and run `scripts/verify_egress.sh` on the host to verify arbitrary external egress is blocked and IMDSv1 is rejected.
4. For incidents, follow `docs/RUNBOOK.md` (**stop**, do not terminate, until investigation is complete).
