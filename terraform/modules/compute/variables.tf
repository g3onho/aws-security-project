variable "name_prefix" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "partition" { type = string }

variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "public_web_subnet_id" { type = string }
variable "private_app_subnet_id" { type = string }
variable "private_db_subnet_id" { type = string }

variable "sg_alb_id" { type = string }
variable "sg_docker_host_id" { type = string }
variable "sg_dashboard_id" { type = string }
variable "sg_web_dvwa_id" { type = string }
variable "sg_db_auto_id" { type = string }
variable "sg_db_manual_id" { type = string }
variable "sg_attacker_id" { type = string }

variable "instance_type" { type = string }
variable "docker_host_instance_type" { type = string }
variable "db_instance_type" { type = string }

variable "db_name" { type = string }
variable "db_app_user" { type = string }
variable "mysql_root_password" {
  type      = string
  sensitive = true
}
variable "mysql_app_password" {
  type      = string
  sensitive = true
}

variable "enable_alb" { type = bool }
variable "enable_waf" { type = bool }
variable "enable_dvwa_instance" { type = bool }
variable "enable_attacker_instance" { type = bool }

variable "acm_certificate_arn" {
  description = "ALB HTTPS 리스너용 인증서 ARN. 비우면 HTTP 리스너만 만듭니다(SEC-02 탐지 대상)."
  type        = string
  default     = ""
}

variable "log_group_nginx" { type = string }
variable "log_group_mysql" { type = string }

variable "correlated_findings_table" { type = string }
variable "remediation_actions_table" { type = string }

# 탐지·취약점 적재 테이블(v21, modules/soar finding_sync). 대시보드 읽기 권한·env 에 쓴다.
variable "findings_table" { type = string }
variable "vulnerabilities_table" { type = string }

# 대시보드가 탐지·취약점을 어디서 읽을지. 문제가 생기면 securityhub / inspector 로 되돌린다.
variable "dashboard_event_source" {
  type    = string
  default = "dynamodb"
  validation {
    condition     = contains(["securityhub", "dynamodb"], var.dashboard_event_source)
    error_message = "dashboard_event_source 는 securityhub 또는 dynamodb 입니다."
  }
}

variable "dashboard_vulnerability_source" {
  type    = string
  default = "dynamodb"
  validation {
    condition     = contains(["inspector", "dynamodb"], var.dashboard_vulnerability_source)
    error_message = "dashboard_vulnerability_source 는 inspector 또는 dynamodb 입니다."
  }
}
variable "scan_results_bucket" { type = string }

variable "tags" {
  type    = map(string)
  default = {}
}

variable "ssm_automation_role_name" {
  description = "SOAR 모듈이 만드는 SSM Automation 실행 역할 이름. 대시보드 역할의 PassRole 범위를 좁히는 데 씁니다."
  type        = string
}

variable "sns_topic_arn" {
  description = "알림 토픽 ARN (대시보드가 수동 조치 알림을 재발행할 때 사용)"
  type        = string
  default     = ""
}

# 대시보드가 탐지마다 "자동 조치 대상인지" 표시할 때 asr_trigger 와 같은 목록을 쓴다(DEC-015·DEC-017).
variable "auto_remediable_patterns" {
  type    = list(string)
  default = []
}

variable "auto_remediable_controls" {
  type    = list(string)
  default = []
}

variable "enable_auto_remediation" {
  type    = bool
  default = false
}

# 대시보드 코드를 S3 로 배포하고 인스턴스가 자동 기동할지 여부.
# false 면 호스트만 준비되고 서비스는 뜨지 않는다(기존 동작).
variable "enable_dashboard_deploy" {
  type    = bool
  default = true
}
