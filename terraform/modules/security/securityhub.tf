############################################
# Security Hub — finding 집계 (자동 모니터링)
# GuardDuty / Inspector2 / Config / Access Analyzer 의 finding 을 한곳에 모읍니다.
############################################

resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0

  enable_default_standards = false # 필요한 표준만 아래에서 명시적으로 켭니다.
}

# AWS Foundational Security Best Practices — EC2.13(22), EC2.14(3389),
# EC2.19(공통 포트) 등이 asr_trigger 화이트리스트와 연결됩니다.
resource "aws_securityhub_standards_subscription" "fsbp" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:${var.partition}:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.this]
}

# GuardDuty / Inspector -> Security Hub 통합은 기본 자동 활성화됩니다.
# Config 관리형 규칙 결과도 Security Hub 로 자동 유입됩니다.
