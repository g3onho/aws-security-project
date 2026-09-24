variable "name_prefix" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "partition" { type = string }

variable "log_group_nginx" { type = string }
variable "log_group_mysql" { type = string }
variable "log_retention_days" { type = number }

variable "correlated_findings_table" { type = string }
variable "remediation_actions_table" { type = string }
variable "scan_results_bucket" { type = string }

variable "enable_auto_remediation" { type = bool }

# 조치 이력 보존 일수. 지나면 DynamoDB TTL 로 자동 삭제된다(루트에서 넘기지 않으면 30일).
variable "action_history_ttl_days" {
  type    = number
  default = 30
}
variable "auto_remediable_patterns" { type = list(string) }
variable "alert_email" { type = string }

variable "enable_guardduty" { type = bool }
variable "enable_security_hub" { type = bool }

variable "cpu_alarm_threshold" { type = number }
variable "memory_alarm_threshold" { type = number }
variable "mysql_auth_fail_threshold" { type = number }

variable "monitored_instances" { type = map(string) }

variable "enable_waf_finding" { type = bool }
variable "waf_web_acl_name" { type = string }
variable "waf_web_acl_arn" { type = string }
variable "waf_block_alarm_threshold" { type = number }

variable "tags" {
  type    = map(string)
  default = {}
}
