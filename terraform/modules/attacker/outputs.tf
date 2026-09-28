output "instance_id" {
  value       = var.enabled ? aws_instance.this[0].id : null
  description = "SSM으로 공격 명령을 보낼 대상 인스턴스 ID"
}

output "public_ip" {
  value       = var.enabled ? aws_instance.this[0].public_ip : null
  description = "공격 출발지 공인 IP. GuardDuty finding에 이 IP의 지역이 찍힌다."
}

output "region_label" {
  value = var.region_label
}
