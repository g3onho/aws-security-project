

output "dashboard_instance_id" { value = aws_instance.dashboard.id }

output "web_dvwa_public_ip" {
  value = var.enable_dvwa_instance ? aws_instance.web_dvwa[0].public_ip : ""
}

# CloudWatch 알람이 붙을 인스턴스 목록 (soar 모듈이 사용)
output "monitored_instances" {
  description = "알람 대상 인스턴스 { 이름 => 인스턴스 ID }"
  value = merge(
    {
      "docker-host" = aws_instance.docker_host.id
      "db"          = aws_instance.db.id
      "dashboard"   = aws_instance.dashboard.id
    },
    var.enable_dvwa_instance ? { "web-dvwa" = aws_instance.web_dvwa[0].id } : {},
    var.enable_attacker_instance ? { "attacker" = aws_instance.attacker[0].id } : {},
  )
}

output "honeypot_demo_attackers" {
  description = "허니팟 AI 시연용 공격자 fleet [{ case, instance_id, private_ip }]"
  value = [
    for i, inst in aws_instance.honeypot_demo_attacker : {
      case        = i + 1
      instance_id = inst.id
      private_ip  = inst.private_ip
    }
  ]
}

output "alb_dns_name" {
  value = var.enable_alb ? aws_lb.main[0].dns_name : ""
}

# WAF 차단 -> Security Hub finding 경로(soar 모듈)가 쓴다. 꺼져 있으면 빈 문자열.
output "waf_web_acl_name" {
  value = var.enable_alb && var.enable_waf ? aws_wafv2_web_acl.main[0].name : ""
}

output "waf_web_acl_arn" {
  value = var.enable_alb && var.enable_waf ? aws_wafv2_web_acl.main[0].arn : ""
}

output "ecr_repository_url" { value = aws_ecr_repository.app.repository_url }

output "db_secret_name" { value = aws_secretsmanager_secret.db.name }

