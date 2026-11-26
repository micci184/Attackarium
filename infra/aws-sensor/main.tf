locals {
  name_prefix = "attackarium-sensor-mvp"

  # VPC DNS resolver is always VPC base + 2 (10.42.0.2 for 10.42.0.0/24).
  vpc_dns_ip       = cidrhost(var.vpc_cidr, 2)
  aws_time_sync_ip = "169.254.169.123"

  # OpenCanary decoys (21, 22, 23, 3306, 6379) + dedicated HTTP collector (80, optional 443).
  decoy_tcp_ports = concat(
    [21, 22, 23, 80, 3306, 6379],
    var.enable_https_decoy ? [443] : []
  )
}

# Resolve the latest official Canonical Ubuntu Server 24.04 LTS AMI (ADR-019).
# EC2 name filters support only the * and ? wildcards (no [...] classes), so
# the LTS release is named explicitly. Bump it deliberately for the next LTS.
data "aws_ami" "ubuntu_lts" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# -----------------------------------------------------------------------------
# Isolated VPC (single public subnet, no VPC peering to other workloads)
# -----------------------------------------------------------------------------
resource "aws_vpc" "sensor" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "sensor" {
  vpc_id = aws_vpc.sensor.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

resource "aws_subnet" "sensor_public" {
  vpc_id                  = aws_vpc.sensor.id
  cidr_block              = var.subnet_cidr
  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name_prefix}-public-subnet"
  }
}

resource "aws_route_table" "sensor_public" {
  vpc_id = aws_vpc.sensor.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sensor.id
  }

  tags = {
    Name = "${local.name_prefix}-public-rt"
  }
}

resource "aws_route_table_association" "sensor_public" {
  subnet_id      = aws_subnet.sensor_public.id
  route_table_id = aws_route_table.sensor_public.id
}

# -----------------------------------------------------------------------------
# Layer 1 Firewall: Lock down VPC default SG + dedicated sensor SG
# -----------------------------------------------------------------------------
resource "aws_default_security_group" "lockdown" {
  vpc_id = aws_vpc.sensor.id

  # Intentionally empty ingress/egress blocks to revoke AWS's default allow-all egress.
  tags = {
    Name = "${local.name_prefix}-default-sg-locked"
  }
}

resource "aws_security_group" "sensor" {
  name        = "${local.name_prefix}-sg"
  description = "Attackarium isolated sensor SG: decoy ports + restricted admin SSH + explicit egress allowlist"
  vpc_id      = aws_vpc.sensor.id

  tags = {
    Name = "${local.name_prefix}-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "decoy_tcp" {
  for_each = toset([for p in local.decoy_tcp_ports : tostring(p)])

  security_group_id = aws_security_group.sensor.id
  description       = "Inbound decoy TCP/${each.value}"
  ip_protocol       = "tcp"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
  cidr_ipv4         = "0.0.0.0/0"
}

# Optional break-glass only. Normal administration goes through the EC2
# Instance Connect Endpoint below, so this is empty by default.
resource "aws_vpc_security_group_ingress_rule" "admin_ssh" {
  for_each = toset(var.admin_ssh_cidrs)

  security_group_id = aws_security_group.sensor.id
  description       = "Restricted operator management SSH (${each.value})"
  ip_protocol       = "tcp"
  from_port         = var.admin_ssh_port
  to_port           = var.admin_ssh_port
  cidr_ipv4         = each.value
}

# -----------------------------------------------------------------------------
# Operator access: EC2 Instance Connect Endpoint (no public admin port, no
# instance IAM role). The operator opens an IAM-authenticated tunnel; the
# instance still requires the operator SSH key. Each tunnel is logged in
# CloudTrail and limited to 1 hour by the service.
# -----------------------------------------------------------------------------
resource "aws_security_group" "eice" {
  name        = "${local.name_prefix}-eice-sg"
  description = "EC2 Instance Connect Endpoint: egress only to the sensor admin SSH port"
  vpc_id      = aws_vpc.sensor.id

  tags = {
    Name = "${local.name_prefix}-eice-sg"
  }
}

resource "aws_vpc_security_group_egress_rule" "eice_to_sensor_admin" {
  security_group_id            = aws_security_group.eice.id
  description                  = "EICE to sensor management SSH only"
  ip_protocol                  = "tcp"
  from_port                    = var.admin_ssh_port
  to_port                      = var.admin_ssh_port
  referenced_security_group_id = aws_security_group.sensor.id
}

resource "aws_vpc_security_group_ingress_rule" "admin_ssh_from_eice" {
  security_group_id            = aws_security_group.sensor.id
  description                  = "Operator management SSH via EC2 Instance Connect Endpoint only"
  ip_protocol                  = "tcp"
  from_port                    = var.admin_ssh_port
  to_port                      = var.admin_ssh_port
  referenced_security_group_id = aws_security_group.eice.id
}

resource "aws_ec2_instance_connect_endpoint" "admin" {
  subnet_id          = aws_subnet.sensor_public.id
  security_group_ids = [aws_security_group.eice.id]
  preserve_client_ip = false

  tags = {
    Name = "${local.name_prefix}-eice"
  }
}

resource "aws_vpc_security_group_egress_rule" "ingest_https" {
  for_each = toset(var.ingest_egress_cidrs)

  security_group_id = aws_security_group.sensor.id
  description       = "Outbound HTTPS to approved Supabase ingest CIDR (${each.value})"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "vpc_dns_udp" {
  security_group_id = aws_security_group.sensor.id
  description       = "Outbound DNS UDP to VPC resolver only"
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
  cidr_ipv4         = "${local.vpc_dns_ip}/32"
}

resource "aws_vpc_security_group_egress_rule" "vpc_dns_tcp" {
  security_group_id = aws_security_group.sensor.id
  description       = "Outbound DNS TCP to VPC resolver only"
  ip_protocol       = "tcp"
  from_port         = 53
  to_port           = 53
  cidr_ipv4         = "${local.vpc_dns_ip}/32"
}

resource "aws_vpc_security_group_egress_rule" "aws_ntp" {
  security_group_id = aws_security_group.sensor.id
  description       = "Outbound NTP to Amazon Time Sync Service only"
  ip_protocol       = "udp"
  from_port         = 123
  to_port           = 123
  cidr_ipv4         = "${local.aws_time_sync_ip}/32"
}

resource "aws_vpc_security_group_egress_rule" "bootstrap_https" {
  count = var.enable_bootstrap_egress ? 1 : 0

  security_group_id = aws_security_group.sensor.id
  description       = "TEMPORARY bootstrap-only HTTPS egress for apt/pip (set enable_bootstrap_egress=false after setup)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "bootstrap_http" {
  count = var.enable_bootstrap_egress ? 1 : 0

  security_group_id = aws_security_group.sensor.id
  description       = "TEMPORARY bootstrap-only HTTP egress for Ubuntu apt mirrors (set enable_bootstrap_egress=false after setup)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

# Automatic OS security updates (ADR-027): Canonical-owned archive ranges
# only, plain HTTP (apt verifies signed InRelease files). The host nftables
# allows the same ranges, so unattended-upgrades can refresh its lists daily.
resource "aws_vpc_security_group_egress_rule" "os_update_http" {
  for_each = toset(var.os_update_egress_cidrs)

  security_group_id = aws_security_group.sensor.id
  description       = "OS security updates: Canonical Ubuntu archive (HTTP, signed)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = each.value
}

# Patch window (#94): Ubuntu mirrors only, plain HTTP (apt verifies signed
# InRelease files). The host nftables rule is added in memory by
# scripts/patch_window.sh and is never persisted. Empty list = no rules.
resource "aws_vpc_security_group_egress_rule" "patch_http" {
  for_each = toset(var.patch_egress_cidrs)

  security_group_id = aws_security_group.sensor.id
  description       = "TEMPORARY patch-window HTTP egress to an Ubuntu mirror (clear patch_egress_cidrs after the window)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = each.value
}

# -----------------------------------------------------------------------------
# EC2 Sensor Host (ADR-019: t3a.small, standard credits, gp3 20 GiB encrypted, no IAM role)
# -----------------------------------------------------------------------------
resource "aws_key_pair" "operator" {
  key_name   = "${local.name_prefix}-operator"
  public_key = var.ssh_public_key
}

resource "aws_instance" "sensor" {
  ami                         = coalesce(var.sensor_ami_id, data.aws_ami.ubuntu_lts.id)
  instance_type               = "t3a.small"
  subnet_id                   = aws_subnet.sensor_public.id
  vpc_security_group_ids      = [aws_security_group.sensor.id]
  key_name                    = aws_key_pair.operator.key_name
  associate_public_ip_address = true
  disable_api_termination     = var.enable_termination_protection

  # Explicitly attach NO IAM instance profile so the sensor holds zero AWS credentials.
  iam_instance_profile = null

  # ADR-019: throttle on credit exhaustion rather than incurring unlimited surplus charges.
  credit_specification {
    cpu_credits = "standard"
  }

  # Enforce IMDSv2 only and hop limit 1.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    admin_ssh_port      = var.admin_ssh_port
    admin_ssh_cidrs     = var.admin_ssh_cidrs
    eice_source_cidr    = var.subnet_cidr
    decoy_tcp_ports     = local.decoy_tcp_ports
    ingest_egress_cidrs = var.ingest_egress_cidrs
    os_update_cidrs     = var.os_update_egress_cidrs
    # Single source of truth for host files shipped by cloud-init (ADR-027).
    record_os_update_script = file("${path.module}/../../sensors/host/record_os_update_status.sh")
    unattended_upgrades_cfg = file("${path.module}/../../sensors/host/52attackarium-unattended-upgrades")
    apt_upgrade_dropin      = file("${path.module}/../../sensors/host/apt-daily-upgrade-attackarium.conf")
    vpc_dns_ip              = local.vpc_dns_ip
    aws_time_sync_ip        = local.aws_time_sync_ip
  })
  user_data_replace_on_change = false

  # Prevent daily Ubuntu AMI updates from forcing instance replacement on later SG/budget applies.
  # user_data is ignored too: in the AWS provider, a user_data change stops and
  # starts the instance even with user_data_replace_on_change = false (an
  # outage and a new public IP), and cloud-init would not re-apply it anyway.
  # A deliberately replaced instance still receives the current user_data.
  lifecycle {
    ignore_changes = [ami, user_data]
  }

  tags = {
    Name = local.name_prefix
  }
}

# -----------------------------------------------------------------------------
# Stable public IPv4 (Elastic IP). Without it, every stop/start assigns a new
# address, and a fresh address receives little traffic until scanners find it,
# which breaks observation continuity. While associated, an Elastic IP costs the
# same as an auto-assigned public IPv4. Never publish this address.
# -----------------------------------------------------------------------------
resource "aws_eip" "sensor" {
  domain = "vpc"

  # AWS recommends an explicit IGW dependency for EIPs in a freshly built VPC.
  depends_on = [aws_internet_gateway.sensor]

  tags = {
    Name = "${local.name_prefix}-eip"
  }
}

resource "aws_eip_association" "sensor" {
  instance_id   = aws_instance.sensor.id
  allocation_id = aws_eip.sensor.id
}

# -----------------------------------------------------------------------------
# Cost Guardrail: Single AWS Budget scoped to Project=Attackarium tag (ADR-020)
# Requires activating the "Project" user-defined Cost Allocation Tag in AWS Billing.
# -----------------------------------------------------------------------------
resource "aws_budgets_budget" "monthly_cost" {
  name         = "${local.name_prefix}-monthly-usd"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Project$Attackarium"]
  }

  dynamic "notification" {
    for_each = toset(["50", "80", "100"])

    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = tonumber(notification.value)
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = var.budget_alert_emails
    }
  }
}
