output "correlated_findings_table_name" { value = aws_dynamodb_table.correlated.name }
output "remediation_actions_table_name" { value = aws_dynamodb_table.actions.name }
output "findings_table_name" { value = aws_dynamodb_table.findings.name }
output "vulnerabilities_table_name" { value = aws_dynamodb_table.vulnerabilities.name }
output "finding_sync_function_name" { value = aws_lambda_function.finding_sync.function_name }
output "finding_sync_dlq_url" { value = aws_sqs_queue.finding_sync_dlq.url }
output "scan_results_bucket" { value = aws_s3_bucket.scan.id }
output "sns_topic_arn" { value = aws_sns_topic.alerts.arn }

output "correlator_function_name" { value = aws_lambda_function.correlator.function_name }
output "asr_trigger_function_name" { value = aws_lambda_function.asr_trigger.function_name }

output "ssm_playbooks" {
  description = "SSM Automation 문서 (자동개선/수동개선)"
  value = {
    auto_revoke_sg       = aws_ssm_document.automation["ASR-RevokeSecurityGroupIngress"].name
    auto_disable_key     = aws_ssm_document.automation["ASR-DisableExposedAccessKey"].name
    manual_block_ip      = aws_ssm_document.automation["ASR-BlockIpWithNacl"].name
    manual_rotate_secret = aws_ssm_document.automation["ASR-RotateDbSecret"].name
    auto_harden_nginx    = aws_ssm_document.command["ASR-HardenNginx"].name
  }
}

output "manual_scan_document" {
  description = "수동 모니터링 실행용 SSM Run Command 문서"
  value = {
    port_and_web    = aws_ssm_document.command["SCAN-PortAndWeb"].name
    container_image = aws_ssm_document.command["SCAN-ContainerImage"].name
    secrets         = aws_ssm_document.command["SCAN-Secrets"].name
    load_stress     = aws_ssm_document.command["LOAD-Stress"].name
  }
}

output "cloudwatch_dashboard_name" { value = aws_cloudwatch_dashboard.main.dashboard_name }
