output "instance_id" {
  description = "EC2 instance ID of the isolated sensor host."
  value       = aws_instance.sensor.id
}

output "public_ip" {
  description = "Public IPv4 address of the isolated sensor host."
  value       = aws_instance.sensor.public_ip
}

output "security_group_id" {
  description = "Security Group ID enforcing Layer 1 ingress/egress isolation."
  value       = aws_security_group.sensor.id
}

output "vpc_id" {
  description = "Isolated sensor VPC ID."
  value       = aws_vpc.sensor.id
}

output "budget_name" {
  description = "AWS Budget name for monthly cost email alerts (notification only)."
  value       = aws_budgets_budget.monthly_cost.name
}

output "instance_connect_endpoint_id" {
  description = "EC2 Instance Connect Endpoint used for operator SSH (no public admin port)."
  value       = aws_ec2_instance_connect_endpoint.admin.id
}

output "admin_ssh_command" {
  description = "Operator SSH via EC2 Instance Connect Endpoint (requires ec2-instance-connect:OpenTunnel and the operator private key)."
  value       = "aws ec2-instance-connect ssh --region ${var.aws_region} --instance-id ${aws_instance.sensor.id} --connection-type eice --ssh-port ${var.admin_ssh_port} --os-user ubuntu --private-key-file <operator-private-key>"
}
