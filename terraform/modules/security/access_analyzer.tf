############################################
# IAM Access Analyzer — 외부 공개 권한 분석 (SEC-05). 외부 접근 분석기는 무료.
############################################

resource "aws_accessanalyzer_analyzer" "this" {
  count = var.enable_access_analyzer ? 1 : 0

  analyzer_name = "${var.name_prefix}-analyzer"
  type          = "ACCOUNT"

  tags = merge(var.tags, { Scenario = "SEC-05" })
}
