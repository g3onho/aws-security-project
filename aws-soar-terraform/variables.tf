############################################
# 기본 식별자
############################################

variable "project" {
  description = "리소스 이름 접두사"
  type        = string
  default     = "soar-sec"
}

variable "env" {
  description = "환경 구분"
  type        = string
  default     = "dev"
}

variable "team_name" {
  description = "태그에 들어갈 팀 이름"
  type        = string
  default     = "team2"
}

variable "owner" {
  description = "자원 담당자. 학생가이드 7.3의 필수 태그(Owner)."
  type        = string
  default     = "student-name"
}

variable "region" {
  description = "배포 리전"
  type        = string
  default     = "ap-northeast-2"
}

############################################
# 네트워크 — 기본기획서 아키텍처 시트 기준
############################################

variable "vpc_cidr" {
  description = "VPC CIDR (기획서: 10.0.0.0/16)"
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_primary" {
  description = "주 가용영역. 모든 자원이 여기 배치됩니다."
  type        = string
  default     = "ap-northeast-2a"
}

variable "az_secondary" {
  description = "보조 가용영역. ALB 2 AZ 요건을 위해서만 사용합니다."
  type        = string
  default     = "ap-northeast-2c"
}

variable "subnet_cidrs" {
  description = "서브넷 CIDR (기획서: Public-Web 10.0.0.0/24 · Private-DB 10.0.1.0/24 · Private-App 10.0.2.0/24)"
  type = object({
    public_web   = string
    private_db   = string
    private_app  = string
    public_web_b = string
  })
  default = {
    public_web   = "10.0.0.0/24"
    private_db   = "10.0.1.0/24"
    private_app  = "10.0.2.0/24"
    public_web_b = "10.0.3.0/24"
  }
}

variable "admin_cidr" {
  description = <<-EOT
    관리자 접속 허용 CIDR.
    비워두면 terraform 실행 PC의 현재 공인 IP/32 를 자동으로 사용합니다(가이드 방식).
    IP 가 바뀌면 다시 apply 하면 됩니다.

    CI(GitHub Actions)에서 실행할 때는 반드시 값을 지정하세요.
    비워두면 GitHub 러너의 IP가 잡혀서, 실행할 때마다 SG가 바뀌고
    본인은 접속하지 못하게 됩니다.
  EOT
  type        = string
  default     = ""
}

############################################
# 비용 토글 — 기본값은 전부 '끔'
############################################

variable "enable_nat_gateway" {
  description = "NAT Gateway. Private EC2 부트스트랩이 끝나면 false 로 되돌려 apply 하세요."
  type        = bool
  default     = false
}

variable "enable_vpc_endpoints" {
  description = "SSM 접속용 VPC 인터페이스 엔드포인트(ssm/ssmmessages/ec2messages). NAT 대신 사용합니다."
  type        = bool
  default     = true
}

variable "enable_alb" {
  description = "ALB 생성 여부. true 면 Public 서브넷 2 AZ 가 사용됩니다."
  type        = bool
  default     = false
}

variable "enable_waf" {
  description = "WAFv2 Web ACL 및 ALB 연결. enable_alb = true 일 때만 의미가 있습니다. (SEC-08)"
  type        = bool
  default     = false
}

variable "enable_dvwa_instance" {
  description = "웹 공격 시연용 DVWA EC2 생성 여부 (SEC-08)"
  type        = bool
  default     = true
}

variable "enable_attacker_instance" {
  description = "VPC 내부 공격용 EC2 생성 여부 (nmap / hydra / sqlmap / ZAP)"
  type        = bool
  default     = false
}

############################################
# 탐지 서비스 토글 — 기본값은 전부 '켬'
############################################

variable "enable_guardduty" {
  type    = bool
  default = true
}

variable "enable_inspector2" {
  type    = bool
  default = true
}

variable "enable_config" {
  type    = bool
  default = true
}

variable "enable_security_hub" {
  type    = bool
  default = true
}

variable "enable_access_analyzer" {
  type    = bool
  default = true
}

variable "enable_cloudtrail" {
  type    = bool
  default = true
}

variable "enable_flow_logs" {
  type    = bool
  default = true
}


variable "enable_guardduty_ai_protection" {
  description = "GuardDuty AI Protection / AI Analyst. 별도 과금이라 기본 off."
  type        = bool
  default     = false
}

############################################
# 자동조치 (SOAR)
############################################

variable "enable_auto_remediation" {
  description = "false 면 Lambda 가 판단만 하고 SSM 을 실행하지 않습니다 (전체 dry-run)."
  type        = bool
  default     = true
}

variable "auto_remediable_patterns" {
  description = <<-EOT
    자동조치를 허용할 finding 유형 화이트리스트. 1차 판단 기준입니다.
    여기 없는 finding 은 SNS 알림만 가고 대시보드에서 승인해야 실행됩니다.
  EOT
  type        = list(string)
  default = [
    "restricted-ssh",
    "restricted-common-ports",
    "vpc-sg-open-only-to-authorized-ports",
    "EC2.13",
    "EC2.14",
    "EC2.19",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
    "CredentialAccess:IAMUser/AnomalousBehavior",
    "Discovery:IAMUser/AnomalousBehavior",
  ]
}

variable "alert_email" {
  description = "SNS 구독 이메일. 비우면 구독을 만들지 않습니다(콘솔에서 수동 추가)."
  type        = string
  default     = ""
}

############################################
# 컴퓨팅
############################################

variable "instance_type" {
  description = "웹·대시보드 EC2 인스턴스 타입"
  type        = string
  default     = "t3.micro"
}

variable "docker_host_instance_type" {
  description = "Docker Host EC2 (Nginx+Flask+MySQL 컨테이너) 인스턴스 타입"
  type        = string
  default     = "t3.small"
}

variable "db_instance_type" {
  description = "MySQL EC2 인스턴스 타입"
  type        = string
  default     = "t3.small"
}

variable "db_name" {
  description = "애플리케이션 DB 이름"
  type        = string
  default     = "appdb"
}

variable "db_app_user" {
  description = "애플리케이션용 MySQL 계정 (root 와 분리 — Docker 체크리스트 #18)"
  type        = string
  default     = "appuser"
}

variable "mysql_root_password" {
  description = "MySQL root 비밀번호. 비우면 Secrets Manager 에 랜덤 생성해 저장합니다."
  type        = string
  default     = ""
  sensitive   = true
}

variable "mysql_app_password" {
  description = "MySQL 앱 계정 비밀번호. 비우면 Secrets Manager 에 랜덤 생성해 저장합니다."
  type        = string
  default     = ""
  sensitive   = true
}

############################################
# 모니터링 임계치 — 기획서 프로젝트 목표 3)
############################################

variable "cpu_alarm_threshold" {
  description = "CPU 사용률 알람 임계치(%) — 기획서 80%"
  type        = number
  default     = 80
}

variable "memory_alarm_threshold" {
  description = "메모리 사용률 알람 임계치(%) — CloudWatch Agent 필요"
  type        = number
  default     = 80
}

variable "mysql_auth_fail_threshold" {
  description = "5분간 MySQL 인증 실패 횟수 임계치 (SEC-06 Hydra 무차별 대입 탐지)"
  type        = number
  default     = 10
}

variable "log_retention_days" {
  description = "CloudWatch Logs 보존 기간"
  type        = number
  default     = 14
}
