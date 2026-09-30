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
  default     = "eu-west-3" # 2026-09-30 서울(ap-northeast-2)→파리 이전. 데이터는 migration-backup/ 에 백업됨.
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
  default     = "eu-west-3a"
}

variable "az_secondary" {
  description = "보조 가용영역. ALB 2 AZ 요건을 위해서만 사용합니다."
  type        = string
  default     = "eu-west-3b"
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
# 비용 토글 — NAT/ALB 는 기본 '켬' (끄면 대시보드가 설치·접속되지 않음)
############################################

variable "enable_nat_gateway" {
  description = "NAT Gateway. 끄면 Private EC2(대시보드·DB)의 user_data 가 apt/pip 에서 멈춰 대시보드가 설치되지 않습니다."
  type        = bool
  default     = true
}

variable "enable_vpc_endpoints" {
  description = "SSM 접속용 VPC 인터페이스 엔드포인트(ssm/ssmmessages/ec2messages). NAT 대신 사용합니다."
  type        = bool
  default     = true
}

variable "enable_alb" {
  description = "ALB 생성 여부. true 면 Public 서브넷 2 AZ 가 사용되고, 대시보드가 ALB :8080 으로 열립니다."
  type        = bool
  default     = true
}

variable "enable_waf" {
  description = "WAFv2 Web ACL 및 ALB 연결. enable_alb = true 일 때만 의미가 있습니다. (SEC-08)"
  type        = bool
  default     = true
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

variable "enable_override_demo_sg" {
  description = "대시보드 '위험 확인 후 조치' 시연용 SG. 태그 없이 3389 를 전체 공개하고 어디에도 붙이지 않는다 — 회수해도 서비스에 영향이 없다."
  type        = bool
  default     = false
}

variable "enable_sec01_demo_sg" {
  description = "SEC-01([전부 실행]) 시연용 SG. AutoRemediation=enabled 태그를 붙이고 어디에도 붙이지 않는다 — 실행할 때 22 를 전체 공개해 위반을 재현하고 즉시 자동 회수한다."
  type        = bool
  default     = false
}

variable "enable_geo_attackers" {
  description = <<-EOT
    지리별 공격 시연 fleet(미국·싱가포르·시드니·뭄바이·도쿄 5개 리전에 공인
    공격자 EC2 1대씩) 생성 여부. enable_dvwa_instance = true 여야 대상이 생긴다.
    리전당 t3.micro 상시 과금 → 시연 후 false 로 되돌려 제거.
  EOT
  type        = bool
  default     = false
}

variable "honeypot_demo_attacker_count" {
  description = "허니팟 AI 시연용 내부 공격자 EC2 개수(사례 1~4당 1대). 0 이면 만들지 않는다. 시연 후 0 으로 되돌려 제거."
  type        = number
  default     = 0

  validation {
    condition     = var.honeypot_demo_attacker_count >= 0 && var.honeypot_demo_attacker_count <= 4 && floor(var.honeypot_demo_attacker_count) == var.honeypot_demo_attacker_count
    error_message = "honeypot_demo_attacker_count 는 0~4 사이의 정수여야 합니다."
  }
}

variable "attacker_instance_type" {
  description = "지리별 공격자 노드 인스턴스 타입. ATK-WebAttack이 nmap·hydra×2·ZAP·sqlmap 5개를 전부 동시 실행하므로 t3.micro(1GB)는 부족하다(2026-09-29 자원고갈로 SSM 에이전트 다운 사고). t3.medium(4GB)으로 5-way 동시 실행 여유를 둔다."
  type        = string
  default     = "t3.medium"
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

variable "auto_remediable_controls" {
  description = <<-EOT
    Security Hub 규칙 ID 정확 일치 자동 조치 목록(project-management/decisions.md DEC-017)과 SEC-06A(DEC-018).
    규칙 ID 는 부분 일치하지 않는다(EC2.2 가 EC2.21 을 잡지 않음). 재부팅이 없고 Terraform 이 관리하지 않는
    계정·리전 설정만 넣는다. "SEC-06A" 는 MySQL 무차별 대입 알람 → 공격 IP NACL 자동 차단,
    "SEC-06B" 는 VPC 내부 출발지의 SSH(22) 거부 급증(Flow Logs) → 같은 NACL 자동 차단이다(DEC-019).
    "HONEYPOT" 은 미끼서버 접속 알람 → 같은 NACL 자동 차단이다(DEC-020, enable_honeypot = true 일 때만 의미).
    v26 부터 기본값에 들어 있다(enable_honeypot = false 면 알람이 없어 아무 일도 일어나지 않는다).
    tfvars 에서 이 변수를 직접 지정하면 기본값을 대체하므로 목록 전체를 쓴다(["HONEYPOT"] 만 쓰면 나머지 9개가 꺼진다).
    항목을 빼면 그 finding 은 기존 패턴 화이트리스트 규칙대로 판정된다(대부분 수동 알림).
  EOT
  type        = list(string)
  default     = ["EC2.2", "EC2.7", "EC2.182", "S3.1", "IAM.7", "SSM.6", "SSM.7", "SEC-06A", "SEC-06B", "HONEYPOT"]
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
  description = "웹·대시보드 EC2 인스턴스 타입. 2026-09-29 t3.micro(1GB)→t3.small(2GB, 대시보드 여유)."
  type        = string
  default     = "t3.small"
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

variable "ssh_reject_alarm_threshold" {
  description = "5분간 VPC 내부 출발지의 SSH(22) 거부 흐름 수 임계치 (SEC-06B, DEC-019). MySQL 알람 기본값과 맞춘 값이며 승인된 운영 기준은 아니다."
  type        = number
  default     = 10
}

variable "waf_block_alarm_threshold" {
  description = "WAF 규칙별 1분간 차단 요청 수 임계치 (SEC-08). ALB 80 은 인터넷에 열려 있어 봇 차단도 섞이므로 오탐이 많으면 올린다."
  type        = number
  default     = 10
}

variable "log_retention_days" {
  description = "CloudWatch Logs 보존 기간"
  type        = number
  default     = 14
}

variable "dashboard_ingress_cidr" {
  description = <<-EOT
    보안 대시보드(ALB 8080) 공개 범위.
    실제 취약점 목록이 보이는 화면이다. 팀이 한 네트워크에 있으면 그 대역으로 좁히세요.
  EOT
  type        = string
  default     = "0.0.0.0/0"
}

# --- A6 AI 미끼서버(허니팟) ---
variable "enable_honeypot" {
  description = "AI 미끼서버(허니팟) 생성 여부. private-db 서브넷에 미끼 1대."
  type        = bool
  default     = false
}

variable "honeypot_alarm_period" {
  description = "허니팟 접속 알람 집계 주기(초). 기본 300. 시연에서 사례를 빠르게 넘기려면 60, 끝나면 300 으로 되돌린다."
  type        = number
  default     = 300

  validation {
    condition     = var.honeypot_alarm_period >= 60 && var.honeypot_alarm_period % 60 == 0
    error_message = "honeypot_alarm_period 는 60 이상의 60 배수여야 합니다."
  }
}

variable "honeypot_instance_type" {
  description = "미끼 서버 인스턴스 타입."
  type        = string
  default     = "t3.micro"
}

variable "enable_honeypot_ai" {
  description = "미끼서버가 Bedrock 으로 가짜 셸 응답·세션 분석·위험도 판정을 생성할지 여부. false 면 로깅·탐지·차단만."
  type        = bool
  default     = true
}

variable "honeypot_ai_model_id" {
  description = "미끼서버 AI 응답에 쓸 Bedrock 모델 ID. 기본값 Amazon Nova Lite(파리 eu 추론 프로파일, converse 호출). 이 계정은 Claude 를 쓰려면 Marketplace 구독 권한이 필요해 Nova 를 쓴다. 2026-09-30 서울(apac)→파리(eu) 이전 — 프로파일 리전 접두어를 반드시 같이 바꿔야 한다(apac 프로파일은 파리에서 호출 불가)."
  type        = string
  default     = "eu.amazon.nova-lite-v1:0"
}

# --- 대시보드 도우미(챗봇, v27) ---
variable "enable_dashboard_assistant" {
  description = "대시보드 AI 도우미(챗봇, 조회 전용)를 켠다. 대시보드 역할에 bedrock:InvokeModel 을 주고 ASSISTANT_ENABLED=true 로 배포한다. 질문·조회 결과가 Bedrock 으로 전송된다."
  type        = bool
  default     = true
}

variable "dashboard_assistant_model_id" {
  description = "대시보드 도우미·AI 요약 보고서가 쓸 Bedrock 모델 ID. 기본값 Amazon Nova Pro(파리 eu 추론 프로파일, converse 호출). 이 계정은 Claude 를 쓰려면 Marketplace 구독 권한이 필요해 Nova 를 쓴다. 미끼서버 AI(honeypot_ai_model_id)는 6초 제한 때문에 Nova Lite 를 유지한다. 2026-09-30 서울(apac)→파리(eu) 이전."
  type        = string
  default     = "eu.amazon.nova-pro-v1:0"
}

# --- IP 차단 기간·만료 (v25, DEC-021) ---
variable "ip_block_default_ttl_hours" {
  description = "자동 차단(NACL 1~99 Deny)의 기본 차단 기간(시간). 0 이면 영구. 대시보드 허니팟 화면에서 행마다 바꿀 수 있다. 시연이면 1 권장."
  type        = number
  default     = 24

  validation {
    condition     = var.ip_block_default_ttl_hours >= 0 && var.ip_block_default_ttl_hours <= 720
    error_message = "ip_block_default_ttl_hours 는 0(영구) ~ 720 이어야 합니다."
  }
}

variable "ip_block_ttl_minutes_override" {
  description = "시연용 차단 기간(분). 0 이면 쓰지 않고 ip_block_default_ttl_hours(시간)를 따른다. 0 보다 크면 우선한다. 시연 후 0 으로 되돌린다."
  type        = number
  default     = 0

  validation {
    condition     = var.ip_block_ttl_minutes_override >= 0 && var.ip_block_ttl_minutes_override <= 1440 && floor(var.ip_block_ttl_minutes_override) == var.ip_block_ttl_minutes_override
    error_message = "ip_block_ttl_minutes_override 는 0(미사용) ~ 1440 사이의 정수여야 합니다."
  }
}

variable "block_expiry_rate_minutes" {
  description = "만료된 IP 차단을 확인·해제하는 block_expiry Lambda 의 실행 주기(분). 기본 5. 시연에서 빠른 해제가 필요하면 1, 끝나면 5 로 되돌린다."
  type        = number
  default     = 5

  validation {
    condition     = var.block_expiry_rate_minutes >= 1 && var.block_expiry_rate_minutes <= 60 && floor(var.block_expiry_rate_minutes) == var.block_expiry_rate_minutes
    error_message = "block_expiry_rate_minutes 는 1~60 사이의 정수여야 합니다."
  }
}

variable "enable_block_expiry" {
  description = "만료된 IP 차단을 자동 해제(block_expiry Lambda, 5분 주기). 끄면 만료 시각이 지나도 차단이 유지되고 대시보드에서만 해제할 수 있다."
  type        = bool
  default     = true
}

variable "enable_tier_check" {
  description = "docker-host 의 3계층(Nginx·Flask·MySQL) 상태를 주기적으로 점검해 저장(tier_check Lambda). 끄면 대시보드는 3계층을 확인 불가로 표시한다."
  type        = bool
  default     = true
}

variable "tier_check_rate_minutes" {
  description = "3계층 점검 주기(분). 임시 기본값 5 — 근거가 확정되지 않았다(decisions.md 미결정 항목)."
  type        = number
  default     = 5

  validation {
    condition     = var.tier_check_rate_minutes >= 1 && var.tier_check_rate_minutes <= 60 && floor(var.tier_check_rate_minutes) == var.tier_check_rate_minutes
    error_message = "tier_check_rate_minutes 는 1~60 사이의 정수여야 합니다."
  }
}

variable "tier_stale_after_minutes" {
  description = "이 시간(분)보다 오래된 3계층 점검 결과는 확인 불가로 표시한다. 임시 기본값 15 — 근거가 확정되지 않았다. 점검 주기보다 충분히 크게 둔다."
  type        = number
  default     = 15

  validation {
    condition     = var.tier_stale_after_minutes >= 1 && floor(var.tier_stale_after_minutes) == var.tier_stale_after_minutes
    error_message = "tier_stale_after_minutes 는 1 이상의 정수여야 합니다."
  }
}
