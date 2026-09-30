############################################
# 접속 정보
############################################

output "region" {
  value = var.region
}

output "detected_admin_cidr" {
  description = "SG 에 적용된 관리자 CIDR (미지정 시 실행 PC 공인 IP)"
  value       = local.admin_cidr
}

output "web_url" {
  description = "서비스 접속 주소 (ALB 사용 시 ALB, 아니면 DVWA 웹서버)"
  value = var.enable_alb ? "http://${module.compute.alb_dns_name}" : (
    var.enable_dvwa_instance ? "http://${module.compute.web_dvwa_public_ip}" : "ALB/DVWA 비활성"
  )
}

# apply 출력은 이름순이라 website_urls 가 맨 마지막 줄에 뜬다.
output "website_urls" {
  description = "접속 주소 모음 — 대시보드 / DVWA"
  value = {
    dashboard = var.enable_alb ? "http://${module.compute.alb_dns_name}:8080" : "ALB 미사용 — dashboard_ssm_port_forward 로 접속"
    dvwa = var.enable_dvwa_instance ? (
      var.enable_alb ? "http://${module.compute.alb_dns_name}:8081" : "http://${module.compute.web_dvwa_public_ip}"
    ) : "DVWA 비활성"
  }
}

output "alb_dns_name" {
  value = module.compute.alb_dns_name
}

output "dashboard_url" {
  description = "보안 대시보드 접속 주소. ALB 가 꺼져 있으면 SSM 포트포워딩만 가능하다."
  value = var.enable_alb ? "http://${module.compute.alb_dns_name}:8080" : (
    "ALB 미사용 — dashboard_ssm_port_forward 명령으로 접속하세요"
  )
}

output "dashboard_ssm_port_forward" {
  description = "보안 대시보드 접속용 SSM 포트포워딩 명령"
  value       = "aws ssm start-session --target ${module.compute.dashboard_instance_id} --document-name AWS-StartPortForwardingSession --parameters '{\"portNumber\":[\"5000\"],\"localPortNumber\":[\"5000\"]}' --region ${var.region}"
}

output "ssh_commands" {
  description = "SSM Session Manager 접속 명령 (SSH 22 미개방 — 세션 매니저 사용)"
  value = {
    for name, id in module.compute.monitored_instances :
    name => "aws ssm start-session --target ${id} --region ${var.region}"
  }
}

output "instance_ids" {
  value = module.compute.monitored_instances
}

############################################
# 대시보드가 읽어야 하는 리소스
############################################

output "correlated_findings_table" { value = module.soar.correlated_findings_table_name }
output "remediation_actions_table" { value = module.soar.remediation_actions_table_name }
output "scan_results_bucket" { value = module.soar.scan_results_bucket }
output "sns_topic_arn" { value = module.soar.sns_topic_arn }
output "ecr_repository_url" { value = module.compute.ecr_repository_url }
output "db_secret_name" { value = module.compute.db_secret_name }
output "cloudwatch_dashboard" { value = module.soar.cloudwatch_dashboard_name }
output "asr_trigger_function_name" { value = module.soar.asr_trigger_function_name }
output "correlator_function_name" { value = module.soar.correlator_function_name }

############################################
# 자동/수동 조치 플레이북 (기획서 성공기준 매핑)
############################################

output "ssm_playbooks" {
  description = "자동개선 3 / 수동개선 2 SSM 문서"
  value       = module.soar.ssm_playbooks
}

output "honeypot_demo_attackers" {
  description = "허니팟 AI 시연용 공격자 fleet [{ case, instance_id, private_ip }] (honeypot_demo_attacker_count > 0 일 때)"
  value       = module.compute.honeypot_demo_attackers
}

output "manual_scan_documents" {
  description = "수동 모니터링 2 SSM Run Command 문서"
  value       = module.soar.manual_scan_document
}

output "target_security_groups" {
  description = "SEC-03 시연 대상 — 같은 위반, 태그로 결과가 갈립니다"
  value = {
    auto_remediated = module.network.sg_db_auto_id
    manual_only     = module.network.sg_db_manual_id
    override_demo   = var.enable_override_demo_sg ? aws_security_group.override_demo[0].id : ""
    private_nacl_id = module.network.private_nacl_id
  }
}

############################################
# 비용 경고
############################################

output "cost_warning" {
  description = "현재 켜져 있는 유료 리소스"
  value = join("\n", compact([
    var.enable_nat_gateway ? "NAT Gateway — 시간당+데이터 처리 과금. (끄면 대시보드 설치 실패)" : "",
    var.enable_vpc_endpoints ? "VPC 인터페이스 엔드포인트 3개 — 엔드포인트당 시간당 과금(NAT 보다 저렴)." : "",
    var.enable_alb ? "ALB — 시간당+LCU 과금." : "",
    var.enable_waf ? "WAFv2 Web ACL — Web ACL/룰/요청 과금." : "",
    var.enable_guardduty ? "GuardDuty — 무료 체험 종료 후 사용량 과금." : "",
    var.enable_guardduty_ai_protection ? "GuardDuty AI Protection — 별도 과금." : "",
    var.enable_inspector2 ? "Inspector2 — 스캔 대상당 과금." : "",
    var.enable_config ? "AWS Config — 기록 항목당 과금(7개 타입만 기록)." : "",
    var.enable_security_hub ? "Security Hub — 체크/finding 건당 과금." : "",
    var.enable_cloudtrail ? "CloudTrail — 관리 이벤트 1개는 무료, S3 저장 비용 발생." : "",
    "EC2 ${3 + (var.enable_dvwa_instance ? 1 : 0) + (var.enable_attacker_instance ? 1 : 0)}대 — 상시 과금. 실습 종료 시 중지/종료.",
  ]))
}

output "cleanup_checklist" {
  value = <<-EOT
    1) demo/cleanup.sh 실행 — SG 룰 원복, 테스트 액세스 키 삭제
    2) terraform destroy
    3) 콘솔에서 GuardDuty / Security Hub / Inspector2 / Config 비활성화 확인
    4) CloudTrail S3 버킷과 KMS 키는 보존 목적상 수동 삭제
  EOT
}
