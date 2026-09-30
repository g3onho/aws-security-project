variable "name_prefix" {
  type        = string
  description = "리소스 이름 접두어 (예: soar-sec-dev)"
}

variable "region_label" {
  type        = string
  description = "발표용 지역 표기 (예: us-virginia). 태그·리소스명에 사용."
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "target_ip" {
  type        = string
  description = "공격 대상 DVWA 공인 IP. 인터넷 경유해야 GuardDuty 지리탐지가 잡힌다."
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "enabled" {
  type        = bool
  default     = true
  description = "false면 이 리전 노드를 만들지 않는다(count=0)."
}

variable "attack_document_name" {
  type        = string
  description = "이 리전에 등록할 공격 SSM Command 문서 이름 (예: soar-sec-dev-ATK-WebAttack)."
}

variable "attack_document_content" {
  type        = string
  description = "공격 SSM 문서 YAML 내용. 루트에서 file()로 읽어 넘긴다(단일 원본)."
}

variable "scan_results_bucket" {
  type        = string
  default     = ""
  description = "공격 결과(.txt/.json)를 올릴 스캔 결과 버킷 이름(홈 리전). 비우면 업로드 권한을 만들지 않는다."
}
