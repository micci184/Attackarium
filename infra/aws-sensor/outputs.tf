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
