output "alarm_name" {
  value       = aws_cloudwatch_metric_alarm.honeypot.alarm_name
  description = "asr_trigger EventBridge 규칙이 참조할 알람 이름."
}
output "log_group_name" {
  value       = aws_cloudwatch_log_group.honeypot.name
  description = "asr_trigger 가 출발지 IP 를 읽을 로그 그룹."
}
output "instance_id" { value = aws_instance.honeypot.id }
output "instance_private_ip" { value = aws_instance.honeypot.private_ip }
output "security_group_id" { value = aws_security_group.honeypot.id }
