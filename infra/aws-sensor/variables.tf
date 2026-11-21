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
  description = "Dedicated management SSH port separated from decoy port 22."
  type        = number
  default     = 2222

  validation {
    condition     = var.admin_ssh_port >= 1024 && var.admin_ssh_port <= 65535 && !contains([3306, 6379], var.admin_ssh_port)
    error_message = "admin_ssh_port must be an unprivileged port (1024-65535) that does not collide with decoy ports."
  }
}

variable "admin_ssh_cidrs" {
  description = "Operator source CIDRs allowed to reach the dedicated management SSH port. Never use 0.0.0.0/0."
  type        = list(string)

  validation {
    condition     = length(var.admin_ssh_cidrs) > 0 && !contains(var.admin_ssh_cidrs, "0.0.0.0/0")
    error_message = "admin_ssh_cidrs must contain at least one explicit operator CIDR and must never include 0.0.0.0/0."
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
    condition     = length(var.ingest_egress_cidrs) > 0 && !contains(var.ingest_egress_cidrs, "0.0.0.0/0")
    error_message = "ingest_egress_cidrs must list explicit destination CIDRs and must never allow 0.0.0.0/0."
  }
}

variable "enable_https_decoy" {
  description = "Expose TCP/443 on the HTTP collector once TLS/DNS is configured."
  type        = bool
  default     = false
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
