# AWS Sensor Infrastructure (`infra/aws-sensor`)

Terraform configuration for the single isolated Attackarium honeypot sensor host in **US East (N. Virginia), `us-east-1`** (`ADR-006`, `ADR-018`–`ADR-021`).

## What this provisions

- Dedicated isolated VPC (`10.42.0.0/24`) with one public subnet and no VPC peering.
- Layer 1 firewall (VPC Security Group):
  - Inbound: decoy ports (`21`, `22`, `23`, `80`, `3306`, `6379`, optional `443`) + restricted operator SSH (`var.admin_ssh_port` from `var.admin_ssh_cidrs` only).
  - Outbound: strictly `443/TCP` to `var.ingest_egress_cidrs`, DNS to VPC resolver, and NTP to Amazon Time Sync. No `0.0.0.0/0` egress.
- Layer 2 firewall (host `nftables` via cloud-init): mirrors the Security Group rules and drops all other outbound traffic.
- Single EC2 instance: `t3a.small`, `cpu_credits = "standard"`, latest Ubuntu Server LTS AMI, encrypted `gp3` 20 GiB root volume, 1 public IPv4, **no IAM role**, IMDSv2 required (`hop_limit = 1`).
- Single AWS Budget (`40` USD/month, email alerts at 50% / 80% / 100%, notification only — does not stop the instance).

## Usage (manual apply only)

```bash
cd infra/aws-sensor
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your real operator CIDR, SSH public key, Supabase ingest CIDRs, and alert email.
# Never commit terraform.tfvars.

terraform init
terraform plan
# Review the plan carefully before applying:
terraform apply
```

After provisioning:

1. Activate the cost allocation tags (`Project`, `Component`, `Environment`) in AWS Billing if not already active (`ADR-020`).
2. Confirm the AWS account contact email can receive abuse/security notifications (`docs/RUNBOOK.md`).
3. Run `scripts/verify_egress.sh` on the host to verify arbitrary external egress is blocked and IMDSv1 is rejected.
4. For incidents, follow `docs/RUNBOOK.md` (**stop**, do not terminate, until investigation is complete).
