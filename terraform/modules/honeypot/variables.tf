variable "name_prefix" { type = string }
variable "region" { type = string }
variable "partition" {
  type    = string
  default = "aws"
}
variable "tags" {
  type    = map(string)
  default = {}
}

variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }
variable "subnet_id" {
  type        = string
  description = "미끼 서버를 둘 서브넷(권장: private-db). 정상 트래픽이 닿지 않는 곳."
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

# --- AI (Amazon Bedrock, 외부 API 키 없음) ---
variable "enable_ai" {
  type        = bool
  default     = true
  description = "true 면 Bedrock 으로 가짜 셸 응답·세션 분석·위험도 판정을 생성한다. false 면 로깅·탐지·차단만."
}
variable "ai_model_id" {
  type        = string
  default     = "apac.amazon.nova-lite-v1:0"
  description = "Bedrock 모델 ID. 기본값 Amazon Nova Lite(apac 추론 프로파일). 허니팟은 converse 로 호출하므로 Nova·Claude 어느 쪽 ID 든 요청 형식은 같다."
}
variable "listen_port" {
  type    = number
  default = 22
}

variable "log_retention_days" {
  type    = number
  default = 30
}

# --- 탐지 알람(접속 = 신호) ---
variable "hit_threshold" {
  type    = number
  default = 1
}
variable "alarm_period" {
  type    = number
  default = 300
}
variable "alarm_evaluation_periods" {
  type    = number
  default = 1
}
variable "sns_topic_arn" {
  type        = string
  default     = ""
  description = "알람 알림용 SNS(선택). 자동 차단은 EventBridge→asr_trigger 로 별도 연결된다."
}
