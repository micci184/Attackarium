variable "aws_region" {
  description = "AWS region locked by ADR-018 (US East N. Virginia)."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "ADR-018 locks the initial sensor region to us-east-1."
  }
}

variable "vpc_cidr" {
  description = "Isolated VPC CIDR for the single Attackarium sensor (no peering)."
  type        = string
  default     = "10.42.0.0/24"
}

variable "subnet_cidr" {
  description = "Public subnet CIDR inside the isolated sensor VPC."
  type        = string
  default     = "10.42.0.0/25"
}

variable "admin_ssh_port" {
  description = "Dedicated management SSH port, separate from the decoy port 22. EC2 Instance Connect Endpoint tunnels only to port 22 or 3389, and 22 is the OpenCanary decoy, so management SSH uses 3389 (ADR-025). The Security Group exposes it only to the EICE Security Group."
  type        = number
  default     = 3389

  validation {
    condition     = var.admin_ssh_port == 3389
    error_message = "admin_ssh_port must be 3389: EC2 Instance Connect Endpoint only tunnels to 22 or 3389, and 22 is the decoy SSH port."
  }
}

variable "admin_ssh_cidrs" {
  description = "Optional break-glass public source CIDRs for the management SSH port. Normal access uses the EC2 Instance Connect Endpoint, so keep this empty. Never use 0.0.0.0/0. Note: the host nftables copy is written by cloud-init at first boot only."
  type        = list(string)
  default     = []

  validation {
    condition     = !contains(var.admin_ssh_cidrs, "0.0.0.0/0") && alltrue([for c in var.admin_ssh_cidrs : can(cidrhost(c, 0))])
    error_message = "admin_ssh_cidrs must contain only valid IPv4 CIDRs and must never include 0.0.0.0/0."
  }
}

variable "sensor_ami_id" {
  description = "Optional AMI to launch a deliberately replaced sensor from. Use a fresh/stock image whose firewall does not block the instance metadata service. Never use an image of the current root volume: its nftables output policy blocks IMDS, so cloud-init may not apply the new user data (see docs/RUNBOOK.md). Null uses the latest Ubuntu 24.04 LTS image."
  type        = string
  default     = null

  validation {
    condition     = var.sensor_ami_id == null || can(regex("^ami-[0-9a-f]{8,17}$", var.sensor_ami_id))
    error_message = "sensor_ami_id must be null or an AMI ID such as ami-0123456789abcdef0."
  }
}

variable "ssh_public_key" {
  description = "Operator SSH public key for key-only management access."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) ", var.ssh_public_key))
    error_message = "ssh_public_key must be a valid OpenSSH public key string."
  }
}

variable "ingest_egress_cidrs" {
  description = "Explicit HTTPS (443) destination CIDRs allowed for outbound shipping to Supabase ingest. Never use 0.0.0.0/0."
  type        = list(string)

  validation {
    condition     = length(var.ingest_egress_cidrs) > 0 && !contains(var.ingest_egress_cidrs, "0.0.0.0/0") && alltrue([for c in var.ingest_egress_cidrs : can(cidrhost(c, 0))])
    error_message = "ingest_egress_cidrs must list valid explicit IPv4 CIDRs and must never allow 0.0.0.0/0."
  }
}

variable "enable_https_decoy" {
  description = "Expose TCP/443 for the HTTPS collector (ADR-028). Opens the Security Group and the rendered host nftables rule only; an existing host needs the runbook steps, and enabling it requires explicit operator approval."
  type        = bool
  default     = false
}

variable "enable_bootstrap_egress" {
  description = "Temporarily allow outbound 80/443 during initial OS/package bootstrap only. Must be false during normal operation."
  type        = bool
  default     = false
}

variable "decoy_max_conns_per_source" {
  description = "Maximum concurrent decoy connections per source IPv4 (host nftables ct count, #95). Keeps one source from filling the HTTP collector's connection slots."
  type        = number
  default     = 8

  validation {
    condition     = var.decoy_max_conns_per_source >= 2 && var.decoy_max_conns_per_source <= 64 && floor(var.decoy_max_conns_per_source) == var.decoy_max_conns_per_source
    error_message = "decoy_max_conns_per_source must be an integer between 2 and 64."
  }
}

variable "os_update_egress_cidrs" {
  description = "Permanent plain-HTTP (TCP/80) egress for automatic OS security updates (ADR-027): Canonical-owned Ubuntu archive ranges only (AS41231). apt verifies signed InRelease files."
  type        = list(string)
  default     = ["91.189.88.0/21", "185.125.188.0/22"]

  validation {
    condition = length(var.os_update_egress_cidrs) <= 8 && alltrue([
      # cidrnetmask accepts IPv4 only (cidrhost would also accept IPv6).
      for c in var.os_update_egress_cidrs : try(can(cidrnetmask(c)) && tonumber(split("/", c)[1]) >= 16, false)
    ])
    error_message = "os_update_egress_cidrs must be at most 8 explicit IPv4 CIDRs of /16 or narrower (no IPv6, never 0.0.0.0/0)."
  }
}

variable "patch_egress_cidrs" {
  description = "TEMPORARY patch-window egress (#94): Ubuntu mirror /32s printed by `scripts/patch_window.sh resolve`, allowed on TCP/80 only. Keep empty outside a patch window."
  type        = list(string)
  default     = []

  validation {
    condition = length(var.patch_egress_cidrs) <= 32 && alltrue([
      for c in var.patch_egress_cidrs : can(cidrhost(c, 0)) && endswith(c, "/32")
    ])
    error_message = "patch_egress_cidrs must be at most 32 single-host IPv4 /32 entries (never a range such as 0.0.0.0/0)."
  }
}

variable "enable_termination_protection" {
  description = "Protect the EC2 instance against accidental termination so incident evidence is preserved (ADR-021: stop, do not terminate)."
  type        = bool
  default     = true
}

variable "monthly_budget_usd" {
  description = "Monthly AWS Budget threshold in USD (ADR-020: 40 USD target)."
  type        = number
  default     = 40

  validation {
    condition     = var.monthly_budget_usd > 0 && var.monthly_budget_usd <= 100
    error_message = "monthly_budget_usd must be between 1 and 100 USD."
  }
}

variable "budget_alert_emails" {
  description = "Email addresses for 50%/80%/100% AWS Budget alerts (notification only; does not stop instances)."
  type        = list(string)

  validation {
    condition     = length(var.budget_alert_emails) > 0
    error_message = "At least one budget alert email address is required."
  }
}
