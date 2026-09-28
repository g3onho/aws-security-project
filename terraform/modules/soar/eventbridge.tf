############################################
# EventBridge — finding 을 Lambda 로 라우팅
#  ① GuardDuty finding      -> correlator  (상관분석)
#  ② GuardDuty finding      -> asr_trigger (IAM 키 노출 등 자동조치 판단)
#  ③ Security Hub finding    -> asr_trigger (SG 노출 등 자동조치 판단)
#  ④ WAF 차단 알람(ALARM)    -> waf_finding (Security Hub 로 가져오기, SEC-08)
#  ⑤ 무차별 대입 알람(MySQL·SSH) -> asr_trigger (공격 IP NACL 자동 차단, SEC-06A·06B)
############################################

# ① GuardDuty -> correlator
resource "aws_cloudwatch_event_rule" "gd_to_correlator" {
  count = var.enable_guardduty ? 1 : 0

  name        = "${var.name_prefix}-gd-correlator"
  description = "GuardDuty findings to correlator Lambda"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "gd_to_correlator" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.gd_to_correlator[0].name
  target_id = "correlator"
  arn       = aws_lambda_function.correlator.arn
}

resource "aws_lambda_permission" "gd_to_correlator" {
  count = var.enable_guardduty ? 1 : 0

  statement_id  = "AllowGuardDutyCorrelator"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.correlator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.gd_to_correlator[0].arn
}

# ② GuardDuty -> asr_trigger (IAM 키 노출 계열)
resource "aws_cloudwatch_event_rule" "gd_to_asr" {
  count = var.enable_guardduty ? 1 : 0

  name        = "${var.name_prefix}-gd-asr"
  description = "GuardDuty credential/unauthorized findings to asr_trigger"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "UnauthorizedAccess:IAMUser" }, { prefix = "CredentialAccess:IAMUser" }, { prefix = "Discovery:IAMUser" }]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "gd_to_asr" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.gd_to_asr[0].name
  target_id = "asr-trigger"
  arn       = aws_lambda_function.asr_trigger.arn
}

resource "aws_lambda_permission" "gd_to_asr" {
  count = var.enable_guardduty ? 1 : 0

  statement_id  = "AllowGuardDutyAsr"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.asr_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.gd_to_asr[0].arn
}

# ③ Security Hub -> asr_trigger (SG 노출 등 설정 위반)
resource "aws_cloudwatch_event_rule" "sh_to_asr" {
  count = var.enable_security_hub ? 1 : 0

  name        = "${var.name_prefix}-sh-asr"
  description = "Security Hub findings to asr_trigger"

  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Compliance  = { Status = ["FAILED", "WARNING"] }
        RecordState = ["ACTIVE"]
      }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "sh_to_asr" {
  count = var.enable_security_hub ? 1 : 0

  rule      = aws_cloudwatch_event_rule.sh_to_asr[0].name
  target_id = "asr-trigger"
  arn       = aws_lambda_function.asr_trigger.arn
}

resource "aws_lambda_permission" "sh_to_asr" {
  count = var.enable_security_hub ? 1 : 0

  statement_id  = "AllowSecurityHubAsr"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.asr_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sh_to_asr[0].arn
}

# ④ WAF 차단 알람 -> waf_finding
# ALARM 으로 "바뀌는 순간" 한 번만 온다. 공격이 이어지는 동안은 ALARM 에 머무르므로
# 사고 1건 = finding 1건.
resource "aws_cloudwatch_event_rule" "waf_alarm_to_finding" {
  count = var.enable_waf_finding ? 1 : 0

  name        = "${var.name_prefix}-waf-finding"
  description = "WAF block alarms to waf_finding Lambda"

  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    detail = {
      alarmName = [{ prefix = "${var.name_prefix}-waf-" }]
      state     = { value = ["ALARM"] }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "waf_alarm_to_finding" {
  count = var.enable_waf_finding ? 1 : 0

  rule      = aws_cloudwatch_event_rule.waf_alarm_to_finding[0].name
  target_id = "waf-finding"
  arn       = aws_lambda_function.waf_finding[0].arn
}

resource "aws_lambda_permission" "waf_alarm_to_finding" {
  count = var.enable_waf_finding ? 1 : 0

  statement_id  = "AllowWafAlarmFinding"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.waf_finding[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.waf_alarm_to_finding[0].arn
}

############################################
# SSM Automation(ASR-*) 종료 → asr_trigger
# 자동조치 실행 결과(성공·실패·시간초과·취소)를 조치 이력의 같은 행(action_id = ssm-<실행 ID>)에
# 기록한다. 실행 결과일 뿐 재검증(동일 조건 재점검)은 아니다 — 대시보드는 '해결'로 표시하지 않는다.
############################################

resource "aws_cloudwatch_event_rule" "ssm_result_to_asr" {
  name        = "${var.name_prefix}-ssm-result"
  description = "ASR automation terminal status to asr_trigger (action history result)"

  event_pattern = jsonencode({
    source        = ["aws.ssm"]
    "detail-type" = ["EC2 Automation Execution Status-change Notification"]
    detail = {
      Definition = [{ prefix = "ASR-" }]
      Status     = ["Success", "Failed", "TimedOut", "Cancelled", "CompletedWithSuccess", "CompletedWithFailure"]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "ssm_result_to_asr" {
  rule      = aws_cloudwatch_event_rule.ssm_result_to_asr.name
  target_id = "asr-trigger"
  arn       = aws_lambda_function.asr_trigger.arn
}

resource "aws_lambda_permission" "ssm_result_to_asr" {
  statement_id  = "AllowSsmResultAsr"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.asr_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ssm_result_to_asr.arn
}

############################################
# ⑤ 무차별 대입 알람(ALARM) → asr_trigger (SEC-06A MySQL · DEC-018 / SEC-06B SSH 22 거부 · DEC-019)
# ALARM 으로 "바뀌는 순간" 한 번 온다. asr_trigger 가 알람 구간 로그(MySQL 오류 로그 / VPC Flow Logs)에서
# 최다 출발지를 찾아 Private NACL 1~99 번대 Deny 로 막는다. 목록(auto_remediable_controls)에서 빼면 알람만 남는다.
############################################

locals {
  bruteforce_alarm_names = compact([
    contains(var.auto_remediable_controls, "SEC-06A") ? aws_cloudwatch_metric_alarm.mysql_bruteforce.alarm_name : "",
    local.enable_ssh_reject ? aws_cloudwatch_metric_alarm.ssh_reject[0].alarm_name : "",
  ])
  enable_bruteforce_block = contains(var.auto_remediable_controls, "SEC-06A") || local.enable_ssh_reject
}

resource "aws_cloudwatch_event_rule" "bruteforce_alarm_to_asr" {
  count = local.enable_bruteforce_block ? 1 : 0

  name        = "${var.name_prefix}-bruteforce-asr"
  description = "MySQL / SSH brute-force alarms (ALARM) to asr_trigger (SEC-06 NACL block)"

  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    detail = {
      alarmName = local.bruteforce_alarm_names
      state     = { value = ["ALARM"] }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "bruteforce_alarm_to_asr" {
  count = local.enable_bruteforce_block ? 1 : 0

  rule      = aws_cloudwatch_event_rule.bruteforce_alarm_to_asr[0].name
  target_id = "asr-trigger"
  arn       = aws_lambda_function.asr_trigger.arn
}

resource "aws_lambda_permission" "bruteforce_alarm_to_asr" {
  count = local.enable_bruteforce_block ? 1 : 0

  statement_id  = "AllowBruteforceAlarmAsr"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.asr_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.bruteforce_alarm_to_asr[0].arn
}
