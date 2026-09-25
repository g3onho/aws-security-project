output "vpc_id" { value = aws_vpc.this.id }

output "public_web_subnet_id" { value = aws_subnet.public_web.id }
output "public_subnet_ids" { value = [aws_subnet.public_web.id, aws_subnet.public_web_b.id] }
output "private_app_subnet_id" { value = aws_subnet.private_app.id }
output "private_db_subnet_id" { value = aws_subnet.private_db.id }

output "sg_alb_id" { value = aws_security_group.alb.id }
output "sg_docker_host_id" { value = aws_security_group.docker_host.id }
output "sg_dashboard_id" { value = aws_security_group.dashboard.id }
output "sg_web_dvwa_id" { value = aws_security_group.web_dvwa.id }
output "sg_db_auto_id" { value = aws_security_group.db_auto.id }
output "sg_db_manual_id" { value = aws_security_group.db_manual.id }

output "sg_attacker_id" {
  value = var.enable_attacker_instance ? aws_security_group.attacker[0].id : ""
}

output "private_nacl_id" { value = aws_network_acl.private.id }

