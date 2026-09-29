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

# 탐지·취약점 적재 (v21, PR-4). 이름은 루트 locals 에서 정해 compute(대시보드 권한·env)와 공유한다.
variable "findings_table" { type = string }
variable "vulnerabilities_table" { type = string }

# 원본 전체 대조 주기. 이벤트로 못 받은 변경(Inspector 재탐지 등)을 이 주기 안에 맞춘다.
variable "finding_sync_schedule" {
  type    = string
  default = "rate(10 minutes)"
}

# 해결·보관된 탐지/취약점 보존 일수(DynamoDB TTL).
variable "finding_ttl_days" {
  type    = number
  default = 30
}

variable "enable_auto_remediation" { type = bool }

# 조치 이력 보존 일수. 지나면 DynamoDB TTL 로 자동 삭제된다(루트에서 넘기지 않으면 30일).
variable "action_history_ttl_days" {
  type    = number
  default = 30
}
variable "auto_remediable_patterns" { type = list(string) }
# 규칙 ID 정확 일치 자동 조치 목록(DEC-017)과 "SEC-06A"(DEC-018). 루트 variables.tf 설명 참고.
variable "auto_remediable_controls" { type = list(string) }
variable "alert_email" { type = string }

# SEC-06A·06B NACL 자동 차단 대상(Private NACL)과 차단을 허용할 주소 범위(VPC CIDR). DEC-018·DEC-019.
variable "private_nacl_id" { type = string }
variable "vpc_cidr" { type = string }

# EC2.2 기본 보안그룹 자동 조치는 이 VPC 의 것만 한다(계정 기본 VPC 등은 수동). DEC-017.
variable "vpc_id" { type = string }

# SEC-06B — VPC Flow Logs 로그 그룹(network 모듈 출력)과 22번 거부 알람 임계치. DEC-019.
variable "enable_flow_logs" { type = bool }
variable "log_group_flowlogs" { type = string }
variable "ssh_reject_alarm_threshold" { type = number }

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

# --- A6 허니팟 접속 → 공격 IP NACL 자동 차단 (HONEYPOT) ---
variable "honeypot_alarm_name" {
  description = "허니팟 접속 알람 이름. 비어 있으면(허니팟 미배포) 관련 규칙을 만들지 않는다."
  type        = string
  default     = null
}
variable "honeypot_log_group" {
  description = "허니팟 접속 로그 그룹. asr_trigger 가 여기서 출발지 IP 를 읽는다."
  type        = string
  default     = null
}

# --- IP 차단 목록·만료 (v25, DEC-021) ---
variable "ip_blocklist_table" { type = string }
variable "ip_block_default_ttl_hours" {
  description = "자동 차단(NACL Deny)의 기본 차단 기간(시간). 0 이면 영구(수동 해제 전까지)."
  type        = number
  default     = 24
}
variable "enable_block_expiry" {
  description = "만료된 차단을 5분마다 자동 해제하는 block_expiry Lambda 사용 여부."
  type        = bool
  default     = true
}
