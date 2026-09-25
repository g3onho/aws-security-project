############################################
# GuardDuty — ML 기반 이상탐지 (자동 모니터링)
# provider 6.x: datasources 인라인 블록은 deprecated.
# 개별 기능은 aws_guardduty_detector_feature 로 켭니다.
############################################

resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = var.tags
}

locals {
  gd_features = var.enable_guardduty ? merge(
    {
      "S3_DATA_EVENTS"         = "ENABLED"
      "EBS_MALWARE_PROTECTION" = "ENABLED"
      "RDS_LOGIN_EVENTS"       = "ENABLED"
    },
    var.enable_guardduty_ai_protection ? { "AI_PROTECTION" = "ENABLED" } : {}
  ) : {}
}

resource "aws_guardduty_detector_feature" "features" {
  for_each = local.gd_features

  detector_id = aws_guardduty_detector.this[0].id
  name        = each.key
  status      = each.value
}
