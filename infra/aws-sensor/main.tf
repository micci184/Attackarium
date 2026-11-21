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

# Resolve the latest official Canonical Ubuntu Server LTS AMI without pinning a version number (ADR-019).
data "aws_ami" "ubuntu_lts" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-*-amd64-server-*"]
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
# Layer 1 Firewall: VPC Security Group (strict ingress + strict egress allowlist)
# -----------------------------------------------------------------------------
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

resource "aws_vpc_security_group_ingress_rule" "admin_ssh" {
  for_each = toset(var.admin_ssh_cidrs)

  security_group_id = aws_security_group.sensor.id
  description       = "Restricted operator management SSH (${each.value})"
  ip_protocol       = "tcp"
  from_port         = var.admin_ssh_port
  to_port           = var.admin_ssh_port
  cidr_ipv4         = each.value
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

# -----------------------------------------------------------------------------
# EC2 Sensor Host (ADR-019: t3a.small, standard credits, gp3 20 GiB encrypted, no IAM role)
# -----------------------------------------------------------------------------
resource "aws_key_pair" "operator" {
  key_name   = "${local.name_prefix}-operator"
  public_key = var.ssh_public_key
}

resource "aws_instance" "sensor" {
  ami                         = data.aws_ami.ubuntu_lts.id
  instance_type               = "t3a.small"
  subnet_id                   = aws_subnet.sensor_public.id
  vpc_security_group_ids      = [aws_security_group.sensor.id]
  key_name                    = aws_key_pair.operator.key_name
  associate_public_ip_address = true

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
    decoy_tcp_ports     = local.decoy_tcp_ports
    ingest_egress_cidrs = var.ingest_egress_cidrs
    vpc_dns_ip          = local.vpc_dns_ip
    aws_time_sync_ip    = local.aws_time_sync_ip
  })
  user_data_replace_on_change = false

  tags = {
    Name = local.name_prefix
  }
}

# -----------------------------------------------------------------------------
# Cost Guardrail: Single AWS Budget (ADR-020: 40 USD, email at 50/80/100%, no auto-stop)
# -----------------------------------------------------------------------------
resource "aws_budgets_budget" "monthly_cost" {
  name         = "${local.name_prefix}-monthly-usd"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

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
